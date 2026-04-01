package cli

import (
	"fmt"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/spf13/cobra"
)

func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List available checks",
		Run: func(cmd *cobra.Command, args []string) {
			for _, c := range checks.DefaultChecks() {
				m := c.Metadata()
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", m.ID, m.Category, m.Severity, m.Title)
			}
		},
	}
	return cmd
}
