package desiredpolicy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// Standard in-cluster ServiceAccount mount paths (Kubernetes well-known
	// filesystem locations). The string contains "token" but is a path, not a
	// credential value — same as agent pod_watch.rs SA_TOKEN_PATH.
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNSPath    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// Watcher polls/watches a single ConfigMap (agent pod_watch.rs conventions:
// in-cluster SA + raw HTTPS; optional NEUROMESH_K8S_* overrides for lab).
// Verbs required: get + watch on that ConfigMap only (no write).
type Watcher struct {
	http      *http.Client
	baseURL   string
	token     string
	namespace string
	name      string
}

// StartWatchFromEnv builds a Watcher when Enabled() and runs it until ctx cancel.
// Safe no-op when the dual env gate is off.
func StartWatchFromEnv(ctx context.Context) error {
	if !Enabled() {
		log.Printf("desired_policy_watch disabled (%s unset or false — Issue #137 PR-1 safety rail)", EnvDesiredPolicyEnable)
		return nil
	}
	w, err := newWatcherFromEnv()
	if err != nil {
		return err
	}
	go w.Run(ctx)
	return nil
}

func newWatcherFromEnv() (*Watcher, error) {
	name := ConfigMapName()
	if name == "" {
		return nil, fmt.Errorf("%s required when desired policy enabled", EnvDesiredPolicyConfigMap)
	}
	ns := strings.TrimSpace(os.Getenv(EnvDesiredPolicyNamespace))
	if ns == "" {
		b, err := os.ReadFile(saNSPath)
		if err != nil {
			return nil, fmt.Errorf("read serviceaccount namespace: %w", err)
		}
		ns = strings.TrimSpace(string(b))
	}
	if ns == "" {
		return nil, fmt.Errorf("desired policy namespace empty")
	}

	baseURL, token, client, err := k8sHTTPClient()
	if err != nil {
		return nil, err
	}
	return &Watcher{
		http:      client,
		baseURL:   strings.TrimRight(baseURL, "/"),
		token:     token,
		namespace: ns,
		name:      name,
	}, nil
}

func k8sHTTPClient() (baseURL, token string, client *http.Client, err error) {
	if u := strings.TrimSpace(os.Getenv("NEUROMESH_K8S_API_URL")); u != "" {
		tok := strings.TrimSpace(os.Getenv("NEUROMESH_K8S_BEARER_TOKEN"))
		if tok == "" {
			return "", "", nil, fmt.Errorf("NEUROMESH_K8S_BEARER_TOKEN required with NEUROMESH_K8S_API_URL")
		}
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if caPath := strings.TrimSpace(os.Getenv("NEUROMESH_K8S_CA_FILE")); caPath != "" {
			// Operator/lab deployment env only (same NEUROMESH_K8S_* class as
			// agent pod_watch.rs) — never derived from request or watch payload.
			pem, rerr := os.ReadFile(caPath) // #nosec G304
			if rerr != nil {
				return "", "", nil, fmt.Errorf("read NEUROMESH_K8S_CA_FILE: %w", rerr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return "", "", nil, fmt.Errorf("parse NEUROMESH_K8S_CA_FILE PEM")
			}
			tlsCfg.RootCAs = pool
		}
		return strings.TrimRight(u, "/"), tok, &http.Client{
			Timeout: 0, // watch streams
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}, nil
	}

	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return "", "", nil, fmt.Errorf("KUBERNETES_SERVICE_HOST unset (not in-cluster?)")
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	tokBytes, err := os.ReadFile(saTokenPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("read SA token: %w", err)
	}
	tok := strings.TrimSpace(string(tokBytes))
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("read SA CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return "", "", nil, fmt.Errorf("parse SA CA PEM")
	}
	return fmt.Sprintf("https://%s:%s", host, port), tok, &http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}, nil
}

// Run GETs the ConfigMap then watches it until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	log.Printf(
		"desired_policy_watch starting configmap=%s/%s (Issue #137 PR-1; Rego still static until PR-2)",
		w.namespace, w.name,
	)
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		rv, err := w.fetchAndApply(ctx)
		if err != nil {
			log.Printf("desired_policy_watch initial get: %v (retry)", err)
			sleepCtx(ctx, backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if err := w.watchLoop(ctx, rv); err != nil && ctx.Err() == nil {
			log.Printf("desired_policy_watch stream ended: %v (reconnect)", err)
			sleepCtx(ctx, backoff)
		}
	}
}

func (w *Watcher) objectURL() string {
	return fmt.Sprintf(
		"%s/api/v1/namespaces/%s/configmaps/%s",
		w.baseURL, w.namespace, w.name,
	)
}

func (w *Watcher) fetchAndApply(ctx context.Context) (resourceVersion string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.objectURL(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Accept", "application/json")
	resp, err := w.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET configmap HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}
	var meta struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(body, &meta)
	if err := ApplyConfigMapJSON(body); err != nil {
		// Invalid content: retain LKG (bootstrap if never applied). Still return
		// resourceVersion so watch can resume from this object version.
		return meta.Metadata.ResourceVersion, nil
	}
	return meta.Metadata.ResourceVersion, nil
}

type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

func (w *Watcher) watchLoop(ctx context.Context, resourceVersion string) error {
	url := w.objectURL() + "?watch=true&resourceVersion=" + resourceVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Accept", "application/json")
	// Long-lived watch: use a client without short Timeout (already Timeout:0).
	resp, err := w.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("watch HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev watchEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Printf("desired_policy_watch bad event: %v", err)
			continue
		}
		switch ev.Type {
		case "ADDED", "MODIFIED", "BOOKMARK":
			if len(ev.Object) == 0 {
				continue
			}
			if err := ApplyConfigMapJSON(ev.Object); err != nil {
				// rejected → LKG retained; continue watching
				continue
			}
		case "DELETED":
			log.Printf(
				"desired_policy_watch configmap deleted name=%s — retaining last-known-good (fail-closed)",
				w.name,
			)
		case "ERROR":
			return fmt.Errorf("watch ERROR event: %s", truncate(ev.Object, 200))
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return ctx.Err()
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}