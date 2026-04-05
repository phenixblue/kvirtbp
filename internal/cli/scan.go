package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/phenixblue/kvirtbp/internal/bundle"
	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/collector"
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
	var collectorDataFiles []string
	var bundleSubdir string
	var collectorBundles []string
	var collectorConfigFiles []string
	var collectorNamespace string
	var collectorTimeout time.Duration
	var noCollectorCleanup bool
	var noAutoBundle bool

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run best-practice checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			cfg, err := loadConfigWithOverride(*outputFlag)
			if err != nil {
				return err
			}

			// Load collector-data files first so we can extract _meta.bundlePath
			// for auto-bundle discovery before resolving --policy-bundle.
			var collectorData map[string]any
			var collectorMeta collector.CollectorMeta
			if len(collectorDataFiles) > 0 {
				cd, meta, loadErr := loadAndMergeCollectorData(collectorDataFiles)
				if loadErr != nil {
					return loadErr
				}
				collectorData = cd
				collectorMeta = meta
			}

			// resolvedBundles is the list of local bundle directories to evaluate.
			// Populated from --policy-bundle (resolved then sub-bundle detected) or
			// from _meta.bundlePaths in the collector-data file(s).
			var resolvedBundles []string
			if policyBundle != "" {
				dir, cleanup, resolveErr := bundle.Resolve(cmd.Context(), policyBundle, bundleSubdir)
				if resolveErr != nil {
					return fmt.Errorf("resolve policy bundle: %w", resolveErr)
				}
				defer cleanup()
				subs, splitErr := bundle.SubBundles(dir)
				if splitErr != nil {
					return fmt.Errorf("detect sub-bundles in %q: %w", dir, splitErr)
				}
				resolvedBundles = subs
			} else if !noAutoBundle && len(collectorMeta.BundlePaths) > 0 {
				for _, p := range collectorMeta.BundlePaths {
					subs, splitErr := bundle.SubBundles(p)
					if splitErr != nil {
						return fmt.Errorf("detect sub-bundles in %q: %w", p, splitErr)
					}
					resolvedBundles = append(resolvedBundles, subs...)
				}
				if len(resolvedBundles) > 0 {
					fmt.Fprintf(cmd.ErrOrStderr(), "info: using %d bundle(s) from collector data\n", len(resolvedBundles))
				}
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

			// Merge resource types from --resource flag and all bundle metadata.
			mergedResourceTypes := append([]string(nil), resourceTypes...)
			for _, bp := range resolvedBundles {
				bundleResources, err := regoengine.ResourceTypesFromBundle(bp)
				if err != nil {
					return fmt.Errorf("reading bundle resource types from %q: %w", bp, err)
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

			// Seed snap.Collectors from pre-collected data files.
			if collectorData != nil {
				snap.Collectors = collectorData
			}

			// Run inline custom collectors (--collector-bundle / --collector-config)
			// and merge their results on top, overwriting any stale file data.
			inlineConfigs, err := resolveCollectorConfigs(collectorBundles, collectorConfigFiles)
			if err != nil {
				return fmt.Errorf("resolve inline collector configs: %w", err)
			}
			if len(inlineConfigs) > 0 {
				if clients == nil {
					return fmt.Errorf("inline collectors require a live cluster connection")
				}
				if snap.Collectors == nil {
					snap.Collectors = make(map[string]any)
				}
				inlineOpts := collector.RunOptions{
					Namespace:     collectorNamespace,
					GlobalTimeout: collectorTimeout,
					SkipCleanup:   noCollectorCleanup,
				}
				inlineData, inlineErr := runCollectors(ctx, clients, inlineConfigs, inlineOpts)
				if inlineErr != nil {
					return fmt.Errorf("inline collectors: %w", inlineErr)
				}
				for k, v := range inlineData {
					snap.Collectors[k] = v
				}
			}

			// Evaluate each bundle independently and merge findings.
			// When no bundles are present (go engine or --policy-file) a single
			// evaluation runs with an empty PolicyBundle.
			evalBundles := resolvedBundles
			if len(evalBundles) == 0 {
				evalBundles = []string{""}
			}
			var result checks.RunResult
			for _, bp := range evalBundles {
				r, evalErr := evaluator.Evaluate(ctx, eval.RunRequest{
					Registry:        checks.DefaultChecks(),
					Filter:          filter,
					PolicyFile:      policyFile,
					PolicyBundle:    bp,
					ClusterSnapshot: &snap,
				})
				if evalErr != nil {
					return evalErr
				}
				result.Findings = append(result.Findings, r.Findings...)
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
	cmd.Flags().StringVar(&policyBundle, "policy-bundle", "", "Path or HTTPS URL to a Rego policy bundle directory or .tar.gz archive (used with --engine rego)")
	cmd.Flags().StringVar(&bundleSubdir, "bundle-subdir", "", "Subdirectory within the bundle archive that contains metadata.json (for monorepo layouts)")
	cmd.Flags().BoolVar(&showRunbook, "show-runbook", false, "Append runbook hint for failing findings with remediation IDs")
	cmd.Flags().StringVar(&waiverFile, "waiver-file", "", "Path to waiver YAML file (checks matching a waiver are skipped from failure counting)")
	cmd.Flags().StringSliceVar(&resourceTypes, "resource", nil, "Additional Kubernetes resource types to fetch and expose to Rego as input.cluster.resources (format: VERSION/RESOURCE or GROUP/VERSION/RESOURCE, e.g. v1/configmaps,apps/v1/deployments)")
	cmd.Flags().StringArrayVar(&collectorDataFiles, "collector-data", nil, "Path to a collector-data JSON file produced by 'kvirtbp collect' (repeatable; later files win on name collision). The _meta.bundlePath from the first file is used to auto-discover --policy-bundle.")
	cmd.Flags().StringArrayVar(&collectorBundles, "collector-bundle", nil, "Path or HTTPS URL to a bundle whose metadata.json declares collectors to run inline during scan (repeatable)")
	cmd.Flags().StringArrayVar(&collectorConfigFiles, "collector-config", nil, "Path to a JSON file containing []CollectorConfig to run inline during scan (repeatable)")
	cmd.Flags().StringVar(&collectorNamespace, "collector-namespace", "kvirtbp-collectors", "Kubernetes namespace for inline collector Jobs")
	cmd.Flags().DurationVar(&collectorTimeout, "collector-timeout", 5*time.Minute, "Timeout for inline collector Jobs")
	cmd.Flags().BoolVar(&noCollectorCleanup, "no-collector-cleanup", false, "Keep inline collector Jobs after scan (useful for debugging)")
	cmd.Flags().BoolVar(&noAutoBundle, "no-auto-bundle", false, "Disable automatic policy bundle discovery from _meta.bundlePath in collector-data files")

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

// loadAndMergeCollectorData reads one or more collector-data files, merges
// them left-to-right at the collector-name level (later files win on
// collision), and returns the merged data map plus the CollectorMeta from the
// first file (which holds the authoritative _meta.bundlePath).
func loadAndMergeCollectorData(files []string) (map[string]any, collector.CollectorMeta, error) {
	var merged map[string]any
	var firstMeta collector.CollectorMeta
	for i, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, firstMeta, fmt.Errorf("read collector data %q: %w", f, err)
		}
		var result collector.CollectorResult
		if err := json.Unmarshal(b, &result); err != nil {
			return nil, firstMeta, fmt.Errorf("decode collector data %q: %w", f, err)
		}
		if i == 0 {
			firstMeta = result.Meta
			merged = result.Data
		} else {
			if merged == nil {
				merged = make(map[string]any)
			}
			for k, v := range result.Data {
				merged[k] = v
			}
		}
	}
	return merged, firstMeta, nil
}
