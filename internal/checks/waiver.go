package checks

import (
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

// WaiverFile is the top-level structure for a waiver YAML file.
type WaiverFile struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Waivers    []Waiver `json:"waivers"`
}

// Waiver represents a single check waiver with mandatory justification metadata.
// Expires is an optional date in "YYYY-MM-DD" format; an empty value means no expiry.
// ResourceRef optionally scopes the waiver to a specific finding resource reference.
type Waiver struct {
	CheckID       string `json:"checkId"`
	Justification string `json:"justification"`
	Owner         string `json:"owner"`
	Expires       string `json:"expires,omitempty"`
	ResourceRef   string `json:"resourceRef,omitempty"`
}

// LoadWaivers reads and validates a waiver YAML file from path.
// Every waiver entry must have a non-empty checkId, justification, and owner.
func LoadWaivers(path string) ([]Waiver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading waiver file %q: %w", path, err)
	}

	var wf WaiverFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parsing waiver file %q: %w", path, err)
	}

	for i, w := range wf.Waivers {
		if w.CheckID == "" {
			return nil, fmt.Errorf("waiver at index %d is missing checkId", i)
		}
		if w.Justification == "" {
			return nil, fmt.Errorf("waiver for %q (index %d) is missing justification", w.CheckID, i)
		}
		if w.Owner == "" {
			return nil, fmt.Errorf("waiver for %q (index %d) is missing owner", w.CheckID, i)
		}
		if w.Expires != "" {
			if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
				return nil, fmt.Errorf("waiver for %q has invalid expires date %q (expected YYYY-MM-DD)", w.CheckID, w.Expires)
			}
		}
	}

	return wf.Waivers, nil
}

// ApplyWaivers marks findings as waived when a matching, non-expired Waiver exists.
// A waiver matches when CheckID matches and, if the waiver has a ResourceRef, it also
// matches the finding's ResourceRef. Expired waivers (Expires in the past) are skipped.
// Waived findings remain visible in reports but are excluded from failure exit-code logic.
func ApplyWaivers(findings []Finding, waivers []Waiver) []Finding {
	if len(waivers) == 0 {
		return findings
	}

	now := time.Now()

	for i := range findings {
		for _, w := range waivers {
			if w.CheckID != findings[i].CheckID {
				continue
			}
			if w.ResourceRef != "" && w.ResourceRef != findings[i].ResourceRef {
				continue
			}
			if w.Expires != "" {
				exp, err := time.Parse("2006-01-02", w.Expires)
				if err == nil && now.After(exp) {
					continue // expired waiver; do not apply
				}
			}

			findings[i].Waived = true
			findings[i].WaiverJustification = w.Justification
			findings[i].WaiverOwner = w.Owner
			findings[i].WaiverExpires = w.Expires
			break
		}
	}

	return findings
}
