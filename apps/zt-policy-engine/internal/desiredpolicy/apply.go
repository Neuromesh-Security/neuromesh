package desiredpolicy

import (
	"encoding/json"
	"fmt"
)

// configMapObject is the subset of a core/v1 ConfigMap we need.
type configMapObject struct {
	Metadata struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

// ApplyConfigMapJSON parses a ConfigMap object JSON, validates policy.json, and
// on success updates LKG + policybundle override. On failure retains LKG and
// returns an error (already audit-logged as rejected).
func ApplyConfigMapJSON(raw []byte) error {
	var cm configMapObject
	if err := json.Unmarshal(raw, &cm); err != nil {
		AuditRejected("", fmt.Sprintf("configmap decode: %v", err))
		return fmt.Errorf("configmap decode: %w", err)
	}
	rv := cm.Metadata.ResourceVersion
	body, ok := cm.Data[ConfigMapDataKey]
	if !ok || body == "" {
		reason := fmt.Sprintf("missing data[%q]", ConfigMapDataKey)
		AuditRejected(rv, reason)
		return fmt.Errorf("%s", reason)
	}
	doc, err := ParseDocument([]byte(body))
	if err != nil {
		AuditRejected(rv, err.Error())
		return err
	}
	snap, err := Validate(doc)
	if err != nil {
		AuditRejected(rv, err.Error())
		return err
	}
	snap.ResourceVersion = rv

	old := Active()
	oldVersion := ""
	var oldPrefixes []string
	if old != nil {
		oldVersion = old.ContentVersion
		oldPrefixes = old.DenyPathPrefixes
	}
	if err := ApplyValidated(snap); err != nil {
		AuditRejected(rv, err.Error())
		return err
	}
	AuditAccepted(rv, oldVersion, snap.ContentVersion, old, &snap)
	// Loud signal only when the override flag was exercised to drop a floor.
	if snap.AllowFloorPrefixRemoval {
		if floors := FloorPrefixesRemovedInDiff(oldPrefixes, snap.DenyPathPrefixes); len(floors) > 0 {
			AuditSafetyRailOverride(rv, oldVersion, snap.ContentVersion, floors)
		}
	}
	return nil
}
