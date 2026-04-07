package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	ltable "github.com/charmbracelet/lipgloss/table"
	"github.com/phenixblue/kvirtbp/internal/checks"
)

const msgWrapWidth = 120

func wrapText(s string, width int) string {
	if len(s) <= width {
		return s
	}
	var lines []string
	for len(s) > width {
		idx := strings.LastIndex(s[:width+1], " ")
		if idx <= 0 {
			idx = width
		}
		lines = append(lines, s[:idx])
		s = strings.TrimLeft(s[idx:], " ")
	}
	if s != "" {
		lines = append(lines, s)
	}
	return strings.Join(lines, "\n")
}

func WriteTable(out io.Writer, result checks.RunResult) error {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("24")).Padding(0, 1).Align(lipgloss.Center)
	passStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true).Padding(0, 1)
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true).Padding(0, 1)
	waivedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true).Padding(0, 1)
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	baseCellStyle := lipgloss.NewStyle().Padding(0, 1)
	borderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	severityStyles := map[checks.Severity]lipgloss.Style{
		checks.SeverityInfo:    lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Padding(0, 1),
		checks.SeverityWarning: lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true).Padding(0, 1),
		checks.SeverityError:   lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true).Padding(0, 1),
	}

	if _, err := fmt.Fprintln(out, titleStyle.Render("KubeVirt Best Practice Results")); err != nil {
		return err
	}

	tbl := ltable.New().
		Headers("CHECK ID", "CATEGORY", "SEVERITY", "PASS", "MESSAGE").
		Border(lipgloss.RoundedBorder()).
		BorderStyle(borderStyle).
		BorderHeader(true).
		BorderColumn(true).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == ltable.HeaderRow {
				return headerStyle
			}
			if row < 0 || row >= len(result.Findings) {
				return baseCellStyle
			}

			f := result.Findings[row]
			switch col {
			case 2:
				if s, ok := severityStyles[f.Severity]; ok {
					return s.Align(lipgloss.Center)
				}
				return mutedStyle.Padding(0, 1).Align(lipgloss.Center)
			case 3:
				if f.Waived {
					return waivedStyle.Align(lipgloss.Center)
				}
				if f.Pass {
					return passStyle.Align(lipgloss.Center)
				}
				return failStyle.Align(lipgloss.Center)
			default:
				if f.Waived {
					return baseCellStyle.Foreground(lipgloss.Color("11"))
				}
				if f.Pass {
					return baseCellStyle.Foreground(lipgloss.Color("7"))
				}
				return baseCellStyle.Foreground(lipgloss.Color("9"))
			}
		})

	reasonCounts := map[string]int{}
	remediationSet := map[string]struct{}{}

	for _, f := range result.Findings {
		passText := "FAIL"
		if f.Waived {
			passText = "WAIVED"
		} else if f.Pass {
			passText = "PASS"
		}

		msg := f.Message
		if f.Waived && f.WaiverJustification != "" {
			if f.WaiverExpires != "" {
				msg = fmt.Sprintf("%s [waived by %s until %s: %s]", f.Message, f.WaiverOwner, f.WaiverExpires, f.WaiverJustification)
			} else {
				msg = fmt.Sprintf("%s [waived by %s: %s]", f.Message, f.WaiverOwner, f.WaiverJustification)
			}
		}

		tbl.Row(
			f.CheckID,
			f.Category,
			strings.ToUpper(string(f.Severity)),
			passText,
			wrapText(msg, msgWrapWidth),
		)

		if f.Pass || f.Waived {
			continue
		}
		if f.ReasonCode != "" {
			reasonCounts[f.ReasonCode]++
		}
		if f.RemediationID != "" {
			remediationSet[f.RemediationID] = struct{}{}
		}
	}

	if _, err := fmt.Fprintln(out, tbl.Render()); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, ""); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "%s\n", titleStyle.Render(fmt.Sprintf("Summary: total=%d passed=%d failed=%d waived=%d info=%d warning=%d error=%d", result.Summary.Total, result.Summary.Passed, result.Summary.Failed, result.Summary.Waived, result.Summary.Info, result.Summary.Warning, result.Summary.Error))); err != nil {
		return err
	}

	if len(reasonCounts) > 0 {
		if _, err := fmt.Fprintln(out, headerStyle.Render("Failing reason codes:")); err != nil {
			return err
		}
		reasonKeys := make([]string, 0, len(reasonCounts))
		for k := range reasonCounts {
			reasonKeys = append(reasonKeys, k)
		}
		sort.Strings(reasonKeys)
		for _, k := range reasonKeys {
			if _, err := fmt.Fprintf(out, "%s\n", failStyle.Render(fmt.Sprintf("- %s: %d", k, reasonCounts[k]))); err != nil {
				return err
			}
		}
	}

	if len(remediationSet) > 0 {
		if _, err := fmt.Fprintln(out, headerStyle.Render("Remediation IDs:")); err != nil {
			return err
		}
		ids := make([]string, 0, len(remediationSet))
		for id := range remediationSet {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if _, err := fmt.Fprintf(out, "%s\n", mutedStyle.Render(fmt.Sprintf("- %s", id))); err != nil {
				return err
			}
		}
	}

	return nil
}
