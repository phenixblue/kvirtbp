package cli

import (
	"errors"
	"fmt"

	"github.com/phenixblue/kvirtbp/internal/config"
	"github.com/phenixblue/kvirtbp/internal/version"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	var cfgFile string
	var outputFlag string
	var kubeconfigPath string
	var kubeContext string

	root := &cobra.Command{
		Use:   "kvirtbp",
		Short: "KubeVirt best-practices scanner",
		Long:  "kvirtbp scans Kubernetes clusters with KubeVirt for production-readiness, security, and availability best practices.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if outputFlag != "" && outputFlag != "table" && outputFlag != "json" {
				return errors.New("--output must be one of: table, json")
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "Path to config file")
	root.PersistentFlags().StringVar(&outputFlag, "output", "", "Output format: table|json")
	root.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to kubeconfig file")
	root.PersistentFlags().StringVar(&kubeContext, "context", "", "Kubernetes context override")

	root.AddCommand(newScanCmd(&outputFlag, &kubeconfigPath, &kubeContext, &cfgFile))
	root.AddCommand(newCollectCmd(&kubeconfigPath, &kubeContext))
	root.AddCommand(newChecksCmd())
	root.AddCommand(newRunbookCmd())
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "version=%s commit=%s date=%s\n", version.Version, version.Commit, version.Date)
		},
	})

	root.SilenceUsage = true
	return root
}

func loadConfigWithOverride(outputOverride, configPath string) (config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, err
	}
	if outputOverride != "" {
		cfg.Output = outputOverride
	}
	return cfg, nil
}
