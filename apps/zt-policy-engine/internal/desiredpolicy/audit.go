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

// AuditSafetyRailOverride emits a SEPARATE, higher-severity line when an
// accepted DesiredPolicy actually omits one or more floor deny prefixes under
// allow_floor_prefix_removal=true. Distinct from desired_policy_accepted so
// SIEM/alerting can page on this tag alone.
func AuditSafetyRailOverride(resourceVersion, oldVersion, newVersion string, floorPrefixesRemoved []string) {
	log.Printf(
		"desired_policy_SAFETY_RAIL_OVERRIDE severity=WARNING allow_floor_prefix_removal=true resource_version=%q old_content_version=%q new_content_version=%q floor_prefixes_removed=%q action=security_floor_weakened",
		resourceVersion,
		oldVersion,
		newVersion,
		joinDiff(floorPrefixesRemoved),
	)
}

// FloorPrefixesRemovedInDiff returns floor prefixes that disappear in this
// apply: present in the prior deny set (or the compile-time floor when there
// is no prior DesiredPolicy LKG), absent from newPrefixes.
func FloorPrefixesRemovedInDiff(oldPrefixes, newPrefixes []string) []string {
	baseline := oldPrefixes
	if len(baseline) == 0 {
		baseline = FloorDenyPathPrefixes
	}
	dropped := setOf(removed(baseline, newPrefixes))
	var out []string
	for _, floor := range FloorDenyPathPrefixes {
		if _, ok := dropped[floor]; ok {
			out = append(out, floor)
		}
	}
	return out
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
