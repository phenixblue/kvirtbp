package eval

import (
	"sort"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

type ComparableFinding struct {
	CheckID  string
	Title    string
	Category string
	Severity checks.Severity
	Pass     bool
}

func NormalizeForComparison(result checks.RunResult) []ComparableFinding {
	out := make([]ComparableFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		out = append(out, ComparableFinding{
			CheckID:  f.CheckID,
			Title:    f.Title,
			Category: f.Category,
			Severity: f.Severity,
			Pass:     f.Pass,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CheckID != out[j].CheckID {
			return out[i].CheckID < out[j].CheckID
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		if out[i].Severity != out[j].Severity {
			return out[i].Severity < out[j].Severity
		}
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		if out[i].Pass == out[j].Pass {
			return false
		}
		return !out[i].Pass && out[j].Pass
	})

	return out
}

func Equivalent(left checks.RunResult, right checks.RunResult) bool {
	a := NormalizeForComparison(left)
	b := NormalizeForComparison(right)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
