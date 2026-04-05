package collector

import (
	"encoding/json"
	"fmt"
	"time"
)

// CollectorMeta is embedded in the collector-data output file under the
// reserved key "_meta". It carries provenance information that downstream
// commands (e.g. "kvirtbp scan") can use to avoid re-fetching the bundle.
type CollectorMeta struct {
	// BundlePaths are the local filesystem paths where bundles were saved by
	// "kvirtbp collect --save-bundle". One entry per --bundle flag.
	// Empty when --save-bundle was not used.
	BundlePaths []string `json:"bundlePaths,omitempty"`

	// CollectedAt is the RFC3339 UTC timestamp of the collection run.
	CollectedAt string `json:"collectedAt"`
}

// CollectorResult is the top-level structure written to the collector-data
// output file. It serialises as a flat JSON object: "_meta" holds provenance
// and every other key is a collector name from Data.
//
// The flat layout preserves backwards compatibility — existing files that
// lack "_meta" are still valid CollectorResult values (Meta will be zero).
type CollectorResult struct {
	Meta CollectorMeta
	Data map[string]any
}

// NewCollectorResult creates a CollectorResult stamped with the current time.
func NewCollectorResult(data map[string]any, meta CollectorMeta) CollectorResult {
	if meta.CollectedAt == "" {
		meta.CollectedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return CollectorResult{Meta: meta, Data: data}
}

// MarshalJSON emits "_meta" (if non-zero) followed by all Data keys at the
// top level of the JSON object.
func (r CollectorResult) MarshalJSON() ([]byte, error) {
	flat := make(map[string]any, len(r.Data)+1)
	for k, v := range r.Data {
		flat[k] = v
	}
	// Only include _meta when there is something meaningful to surface.
	if len(r.Meta.BundlePaths) > 0 || r.Meta.CollectedAt != "" {
		flat["_meta"] = r.Meta
	}
	return json.Marshal(flat)
}

// UnmarshalJSON parses the flat collector-data format back into a
// CollectorResult, extracting "_meta" into Meta and everything else into Data.
func (r *CollectorResult) UnmarshalJSON(b []byte) error {
	var flat map[string]json.RawMessage
	if err := json.Unmarshal(b, &flat); err != nil {
		return err
	}

	r.Data = make(map[string]any, len(flat))
	for k, raw := range flat {
		if k == "_meta" {
			if err := json.Unmarshal(raw, &r.Meta); err != nil {
				return fmt.Errorf("decode _meta: %w", err)
			}
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("decode collector %q: %w", k, err)
		}
		r.Data[k] = v
	}
	return nil
}
