package report

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

func WriteTable(out io.Writer, result checks.RunResult) error {
	w := tabwriter.NewWriter(out, 2, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "CHECK ID\tCATEGORY\tSEVERITY\tPASS\tMESSAGE"); err != nil {
		return err
	}

	reasonCounts := map[string]int{}
	remediationSet := map[string]struct{}{}

	for _, f := range result.Findings {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\n", f.CheckID, f.Category, f.Severity, f.Pass, f.Message); err != nil {
			return err
		}
		if f.Pass {
			continue
		}
		if f.ReasonCode != "" {
			reasonCounts[f.ReasonCode]++
		}
		if f.RemediationID != "" {
			remediationSet[f.RemediationID] = struct{}{}
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(out, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Summary: total=%d passed=%d failed=%d info=%d warning=%d error=%d\n", result.Summary.Total, result.Summary.Passed, result.Summary.Failed, result.Summary.Info, result.Summary.Warning, result.Summary.Error); err != nil {
		return err
	}

	if len(reasonCounts) > 0 {
		if _, err := fmt.Fprintln(out, "Failing reason codes:"); err != nil {
			return err
		}
		reasonKeys := make([]string, 0, len(reasonCounts))
		for k := range reasonCounts {
			reasonKeys = append(reasonKeys, k)
		}
		sort.Strings(reasonKeys)
		for _, k := range reasonKeys {
			if _, err := fmt.Fprintf(out, "- %s: %d\n", k, reasonCounts[k]); err != nil {
				return err
			}
		}
	}

	if len(remediationSet) > 0 {
		if _, err := fmt.Fprintln(out, "Remediation IDs:"); err != nil {
			return err
		}
		ids := make([]string, 0, len(remediationSet))
		for id := range remediationSet {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if _, err := fmt.Fprintf(out, "- %s\n", id); err != nil {
				return err
			}
		}
	}

	return nil
}
