package desiredpolicy

import (
	"log"
	"sort"
	"strings"
)

// AuditAccepted logs a structured line for every accepted DesiredPolicy apply.
func AuditAccepted(resourceVersion, oldVersion, newVersion string, oldSnap, newSnap *Snapshot) {
	var oldPrefixes, newPrefixes, oldIDs, newIDs []string
	if oldSnap != nil {
		oldPrefixes = oldSnap.DenyPathPrefixes
		oldIDs = oldSnap.SpiffeIDs
	}
	if newSnap != nil {
		newPrefixes = newSnap.DenyPathPrefixes
		newIDs = newSnap.SpiffeIDs
	}
	log.Printf(
		"desired_policy_accepted resource_version=%q old_content_version=%q new_content_version=%q prefixes_added=%q prefixes_removed=%q spiffe_ids_added=%q spiffe_ids_removed=%q",
		resourceVersion,
		oldVersion,
		newVersion,
		joinDiff(added(oldPrefixes, newPrefixes)),
		joinDiff(removed(oldPrefixes, newPrefixes)),
		joinDiff(added(oldIDs, newIDs)),
		joinDiff(removed(oldIDs, newIDs)),
	)
}

// AuditRejected logs a structured line when ConfigMap content fails validation.
// LKG is retained (caller must not ApplyValidated).
func AuditRejected(resourceVersion, reason string) {
	log.Printf(
		"desired_policy_rejected resource_version=%q reason=%q action=retain_last_known_good",
		resourceVersion,
		reason,
	)
}

func joinDiff(items []string) string {
	if len(items) == 0 {
		return ""
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

func setOf(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, s := range items {
		m[s] = struct{}{}
	}
	return m
}

func added(oldItems, newItems []string) []string {
	old := setOf(oldItems)
	var out []string
	for _, s := range newItems {
		if _, ok := old[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

func removed(oldItems, newItems []string) []string {
	neu := setOf(newItems)
	var out []string
	for _, s := range oldItems {
		if _, ok := neu[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
