package desiredpolicy

import (
	"os"
	"strings"
)

// EnvDesiredPolicyEnable must be true/1/yes for the ConfigMap watch to start.
// Default unset = hardcoded bootstrap only (safe to merge PR-1 alone).
const EnvDesiredPolicyEnable = "NEUROMESH_DESIRED_POLICY_ENABLE"

// EnvDesiredPolicyConfigMap is the ConfigMap name to watch (required when enabled).
const EnvDesiredPolicyConfigMap = "NEUROMESH_DESIRED_POLICY_CONFIGMAP"

// EnvDesiredPolicyNamespace overrides the in-cluster ServiceAccount namespace.
// When unset, the watch reads /var/run/secrets/kubernetes.io/serviceaccount/namespace.
const EnvDesiredPolicyNamespace = "NEUROMESH_DESIRED_POLICY_NAMESPACE"

// Enabled reports whether both the explicit enable flag and ConfigMap name are set.
// Production Deployment must leave these unset until Issue #137 PR-2 (Rego) lands.
func Enabled() bool {
	if !truthy(os.Getenv(EnvDesiredPolicyEnable)) {
		return false
	}
	return strings.TrimSpace(os.Getenv(EnvDesiredPolicyConfigMap)) != ""
}

// ConfigMapName returns the configured ConfigMap name (empty when disabled).
func ConfigMapName() string {
	return strings.TrimSpace(os.Getenv(EnvDesiredPolicyConfigMap))
}

func truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
