package desiredpolicy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRBACManifestWatchOnlyNoWrites(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path, err := findRepoFile(filepath.Dir(thisFile), filepath.Join("deploy", "kubernetes", "neuromesh-desired-policy.yaml"))
	if err != nil {
		t.Skipf("manifest not available in this checkout layout: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)
	if !strings.Contains(text, "verbs: [\"get\", \"watch\"]") {
		t.Fatal("expected get+watch only on desired-policy Role")
	}
	for _, banned := range []string{
		`"create"`, `"update"`, `"patch"`, `"delete"`,
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("RBAC must not grant %s", banned)
		}
	}
	if strings.Contains(text, `"list"`) {
		t.Fatal("RBAC must not grant list (use get+watch on named ConfigMap)")
	}
	if !strings.Contains(text, "NEUROMESH_DESIRED_POLICY_ENABLE") {
		t.Fatal("manifest must document enable safety rail")
	}
	if !strings.Contains(text, ConfigMapDataKey) {
		t.Fatalf("manifest must include data key %q", ConfigMapDataKey)
	}
}

func findRepoFile(startDir, rel string) (string, error) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, rel)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
