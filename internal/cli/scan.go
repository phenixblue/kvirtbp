package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/eval"
	"github.com/phenixblue/kvirtbp/internal/eval/goeval"
	regoengine "github.com/phenixblue/kvirtbp/internal/eval/rego"
	"github.com/phenixblue/kvirtbp/internal/kube"
	"github.com/phenixblue/kvirtbp/internal/report"
	"github.com/phenixblue/kvirtbp/internal/runbook"
	"github.com/spf13/cobra"
)

const clusterContextHashVersion = "v1"

type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("scan failed with exit code %d", e.Code)
}

func newScanCmd(outputFlag *string, kubeconfigPath *string, kubeContext *string) *cobra.Command {
	var includeChecks []string
	var excludeChecks []string
	var categories []string
	var severities []string
	var includeNamespaces []string
	var excludeNamespaces []string
	var engineName string
	var policyFile string
	var policyBundle string
	var showRunbook bool
	var waiverFile string
	var resourceTypes []string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run best-practice checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			cfg, err := loadConfigWithOverride(*outputFlag)
			if err != nil {
				return err
			}

			parsedSeverities, err := checks.ParseSeverities(severities)
			if err != nil {
				return err
			}

			filter := checks.Filter{
				IncludeIDs: includeChecks,
				ExcludeIDs: excludeChecks,
				Categories: categories,
				Severities: parsedSeverities,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Timeout)
			defer cancel()

			evaluator, err := getEvaluator(engineName)
			if err != nil {
				return err
			}

			// Merge resource types from --resource flag and bundle metadata.
			mergedResourceTypes := append([]string(nil), resourceTypes...)
			if policyBundle != "" {
				bundleResources, err := regoengine.ResourceTypesFromBundle(policyBundle)
				if err != nil {
					return fmt.Errorf("reading bundle resource types: %w", err)
				}
				mergedResourceTypes = mergeResourceTypes(mergedResourceTypes, bundleResources)
			}

			preflightOpts := kube.PreflightOptions{
				IncludeNamespaces: includeNamespaces,
				ExcludeNamespaces: excludeNamespaces,
				ResourceTypes:     mergedResourceTypes,
			}

			clients, kubeErr := kube.NewClients(kube.Options{
				KubeconfigPath: *kubeconfigPath,
				Context:        *kubeContext,
			})

			var snap kube.ClusterSnapshot
			if kubeErr != nil {
				snap = kube.DegradedSnapshot(preflightOpts)
			} else {
				snap = kube.BuildClusterSnapshot(ctx, clients, preflightOpts)
			}

			result, err := evaluator.Evaluate(ctx, eval.RunRequest{
				Registry:        checks.DefaultChecks(),
				Filter:          filter,
				PolicyFile:      policyFile,
				PolicyBundle:    policyBundle,
				ClusterSnapshot: &snap,
			})
			if err != nil {
				return err
			}

			// The Go engine produces cluster findings via BuildPreflightFindingsFromSnapshot.
			// The Rego engine is self-contained: it receives input.cluster and handles
			// all checks (catalog + cluster) entirely within its policy.
			if engineName != "rego" {
				result.Findings = append(result.Findings, kube.BuildPreflightFindingsFromSnapshot(snap)...)
			}
			result.Findings = checks.ApplyBaselineAssessments(result.Findings)

			if waiverFile != "" {
				waivers, waiverErr := checks.LoadWaivers(waiverFile)
				if waiverErr != nil {
					return fmt.Errorf("loading waivers: %w", waiverErr)
				}
				result.Findings = checks.ApplyWaivers(result.Findings, waivers)
			}

			result.Findings = checks.FilterFindings(result.Findings, filter)
			if showRunbook {
				result.Findings = annotateRunbookHints(result.Findings)
			}
			result.Metadata = buildRunMetadata(runMetadataInput{
				Engine:                    evaluator.Name(),
				NamespaceInclude:          includeNamespaces,
				NamespaceExclude:          excludeNamespaces,
				ClusterContextHash:        clusterContextHash(*kubeContext, *kubeconfigPath != ""),
				ClusterContextHashVersion: clusterContextHashVersion,
				DurationMillis:            time.Since(start).Milliseconds(),
				PolicyFile:                policyFile,
				PolicyBundle:              policyBundle,
				WaiverFile:                waiverFile,
				KubeContext:               *kubeContext,
				KubeconfigProvided:        *kubeconfigPath != "",
			})
			result.Summary = checks.Summarize(result.Findings)

			switch cfg.Output {
			case "json":
				if err := report.WriteJSON(os.Stdout, result); err != nil {
					return err
				}
			case "table":
				if err := report.WriteTable(os.Stdout, result); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported output: %s", cfg.Output)
			}

			exitCode := checks.ExitCode(result)
			if exitCode != checks.ExitCodeSuccess {
				return &ExitCodeError{
					Code: exitCode,
					Err:  fmt.Errorf("scan completed with %d failing checks", result.Summary.Failed),
				}
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVar(&includeChecks, "check", nil, "Include only specific check IDs")
	cmd.Flags().StringSliceVar(&excludeChecks, "exclude-check", nil, "Exclude specific check IDs")
	cmd.Flags().StringSliceVar(&categories, "category", nil, "Include only specific categories")
	cmd.Flags().StringSliceVar(&severities, "severity", nil, "Include only specific severities: info|warning|error")
	cmd.Flags().StringSliceVar(&includeNamespaces, "namespace", nil, "Limit namespace-scoped coverage checks to matching namespaces (supports glob patterns like tenant-*)")
	cmd.Flags().StringSliceVar(&excludeNamespaces, "exclude-namespace", nil, "Exclude matching namespaces from namespace-scoped coverage checks (supports glob patterns)")
	cmd.Flags().StringVar(&engineName, "engine", "go", "Evaluator engine: go|rego")
	cmd.Flags().StringVar(&policyFile, "policy-file", "", "Path to Rego policy file (used with --engine rego)")
	cmd.Flags().StringVar(&policyBundle, "policy-bundle", "", "Path to Rego policy bundle directory (used with --engine rego)")
	cmd.Flags().BoolVar(&showRunbook, "show-runbook", false, "Append runbook hint for failing findings with remediation IDs")
	cmd.Flags().StringVar(&waiverFile, "waiver-file", "", "Path to waiver YAML file (checks matching a waiver are skipped from failure counting)")
	cmd.Flags().StringSliceVar(&resourceTypes, "resource", nil, "Additional Kubernetes resource types to fetch and expose to Rego as input.cluster.resources (format: VERSION/RESOURCE or GROUP/VERSION/RESOURCE, e.g. v1/configmaps,apps/v1/deployments)")

	return cmd
}

func annotateRunbookHints(findings []checks.Finding) []checks.Finding {
	out := make([]checks.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Pass || f.RemediationID == "" {
			out = append(out, f)
			continue
		}

		e, ok := runbook.Lookup(f.RemediationID)
		if !ok {
			f.Message = fmt.Sprintf("%s [Runbook: %s]", f.Message, f.RemediationID)
			out = append(out, f)
			continue
		}

		if len(e.Steps) > 0 {
			f.Message = fmt.Sprintf("%s [Runbook: %s | First step: %s]", f.Message, e.ID, e.Steps[0])
		} else {
			f.Message = fmt.Sprintf("%s [Runbook: %s]", f.Message, e.ID)
		}
		out = append(out, f)
	}

	return out
}

func getEvaluator(name string) (eval.Evaluator, error) {
	switch name {
	case "", "go":
		return goeval.New(), nil
	case "rego":
		return regoengine.New(), nil
	default:
		return nil, fmt.Errorf("unsupported evaluator engine: %s", name)
	}
}

// mergeResourceTypes returns a deduplicated union of a and b.
func mergeResourceTypes(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, rt := range append(a, b...) {
		if _, ok := seen[rt]; !ok {
			seen[rt] = struct{}{}
			out = append(out, rt)
		}
	}
	return out
}

type runMetadataInput struct {
	Engine                    string
	NamespaceInclude          []string
	NamespaceExclude          []string
	ClusterContextHash        string
	ClusterContextHashVersion string
	DurationMillis            int64
	PolicyFile                string
	PolicyBundle              string
	WaiverFile                string
	KubeContext               string
	KubeconfigProvided        bool
}

func buildRunMetadata(in runMetadataInput) *checks.MetadataRun {
	meta := &checks.MetadataRun{
		Engine:                    in.Engine,
		NamespaceInclude:          append([]string(nil), in.NamespaceInclude...),
		NamespaceExclude:          append([]string(nil), in.NamespaceExclude...),
		ClusterContextHash:        in.ClusterContextHash,
		ClusterContextHashVersion: in.ClusterContextHashVersion,
		DurationMillis:            in.DurationMillis,
		PolicyFile:                in.PolicyFile,
		PolicyBundle:              in.PolicyBundle,
		WaiverFile:                in.WaiverFile,
		EvaluationMode:            "hybrid",
		KubeContext:               in.KubeContext,
		KubeconfigProvided:        in.KubeconfigProvided,
	}
	return meta
}

func clusterContextHash(kubeContext string, kubeconfigProvided bool) string {
	seed := fmt.Sprintf("context=%s|kubeconfigProvided=%t", kubeContext, kubeconfigProvided)
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:])[:12]
}
