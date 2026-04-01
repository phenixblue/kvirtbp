package cli

import (
	"fmt"

	"github.com/phenixblue/kvirtbp/internal/runbook"
	"github.com/spf13/cobra"
)

func newRunbookCmd() *cobra.Command {
	var remediationID string

	cmd := &cobra.Command{
		Use:   "runbook",
		Short: "Show remediation runbook details",
		RunE: func(cmd *cobra.Command, args []string) error {
			if remediationID == "" {
				for _, id := range runbook.SortedIDs() {
					fmt.Fprintln(cmd.OutOrStdout(), id)
				}
				return nil
			}

			e, ok := runbook.Lookup(remediationID)
			if !ok {
				return fmt.Errorf("unknown remediation ID: %s", remediationID)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "ID: %s\n", e.ID)
			fmt.Fprintf(cmd.OutOrStdout(), "Title: %s\n", e.Title)
			fmt.Fprintf(cmd.OutOrStdout(), "Description: %s\n", e.Description)
			fmt.Fprintln(cmd.OutOrStdout(), "Steps:")
			for i, s := range e.Steps {
				fmt.Fprintf(cmd.OutOrStdout(), "%d. %s\n", i+1, s)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&remediationID, "id", "", "Remediation ID (for example RUNBOOK-SEC-RBAC-001)")
	return cmd
}
