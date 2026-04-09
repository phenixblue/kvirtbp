package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phenixblue/kvirtbp/internal/bundle"
	"github.com/phenixblue/kvirtbp/internal/collector"
	regoengine "github.com/phenixblue/kvirtbp/internal/eval/rego"
	"github.com/phenixblue/kvirtbp/internal/kube"
	"github.com/spf13/cobra"
)

func newCollectCmd(kubeconfigPath *string, kubeContext *string) *cobra.Command {
	var policyBundles []string
	var collectorConfigFiles []string
	var collectorNamespace string
	var collectorTimeout time.Duration
	var noCleanup bool
	var outputFile string
	var bundleSubdir string
	var saveBundle string

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Run collector Jobs on the cluster and write collector data to a file",
		Long: `collect deploys short-lived Kubernetes Jobs to gather node or cluster-scope
data that Rego policies can reference via input.cluster.collectors.

The collected data is written to a JSON file (default: collector-data.json)
that can be passed to 'kvirtbp scan --collector-data <file>'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), collectorTimeout)
			defer cancel()

			// Resolve each --bundle (download + unpack if URL). Track the single
			// resolved path used for --save-bundle: when there is exactly one
			// bundle we save that directory; multiple bundles are not merged into
			// a single directory (use --collector-config for that).
			resolvedBundles := make([]string, 0, len(policyBundles))
			for _, rawBundle := range policyBundles {
				dir, cleanup, resolveErr := bundle.Resolve(ctx, rawBundle, bundleSubdir)
				if resolveErr != nil {
					return fmt.Errorf("resolve bundle %q: %w", rawBundle, resolveErr)
				}
				defer cleanup() //nolint:gocritic // intentional: each cleanup deferred
				resolvedBundles = append(resolvedBundles, dir)
			}

			// Persist bundle(s) before temp-dir cleanup runs when --save-bundle is set.
			// Single bundle: save directly to saveBundle.
			// Multiple bundles: save each to saveBundle/bundle-0/, bundle-1/, …
			var persistedBundlePaths []string
			if saveBundle != "" {
				for i, resolved := range resolvedBundles {
					dest := saveBundle
					if len(resolvedBundles) > 1 {
						dest = filepath.Join(saveBundle, fmt.Sprintf("bundle-%d", i))
					}
					if err := bundle.SaveDir(resolved, dest); err != nil {
						return fmt.Errorf("save bundle %d to %q: %w", i, dest, err)
					}
					persistedBundlePaths = append(persistedBundlePaths, dest)
				}
			} else {
				// No --save-bundle: record local paths so scan can reuse them.
				// Remote URLs are skipped — they can't be referenced without saving.
				for _, raw := range policyBundles {
					if !isRemoteURL(raw) {
						persistedBundlePaths = append(persistedBundlePaths, raw)
					}
				}
			}

			configs, err := resolveCollectorConfigs(resolvedBundles, collectorConfigFiles)
			if err != nil {
				return err
			}
			if len(configs) == 0 {
				return fmt.Errorf("no collector configs found; provide --bundle or --collector-config")
			}

			clients, err := kube.NewClients(kube.Options{
				KubeconfigPath: *kubeconfigPath,
				Context:        *kubeContext,
			})
			if err != nil {
				return fmt.Errorf("connect to cluster: %w", err)
			}

			nsCreated, err := ensureNamespace(ctx, clients, collectorNamespace)
			if err != nil {
				return fmt.Errorf("ensure namespace %q: %w", collectorNamespace, err)
			}
			if !noCleanup && nsCreated {
				defer func() {
					_ = clients.Core.CoreV1().Namespaces().Delete(
						context.Background(), collectorNamespace, metav1.DeleteOptions{})
				}()
			}

			opts := collector.RunOptions{
				Namespace:     collectorNamespace,
				GlobalTimeout: collectorTimeout,
				SkipCleanup:   noCleanup,
			}

			data, err := runCollectors(ctx, clients, configs, opts)
			if err != nil {
				return err
			}

			meta := collector.CollectorMeta{BundlePaths: persistedBundlePaths}
			result := collector.NewCollectorResult(data, meta)
			return writeCollectorResult(outputFile, result)
		},
	}

	cmd.Flags().StringArrayVar(&policyBundles, "bundle", nil, "Path or HTTPS URL to a policy bundle (repeatable); collector configs from each bundle's metadata.json are merged")
	cmd.Flags().StringVar(&bundleSubdir, "bundle-subdir", "", "Subdirectory within the bundle archive that contains metadata.json (for monorepo layouts)")
	cmd.Flags().StringVar(&saveBundle, "save-bundle", "", "Persist resolved bundle(s) to this path. Single bundle: saved directly. Multiple bundles: saved to <path>/bundle-0/, bundle-1/, …")
	cmd.Flags().StringArrayVar(&collectorConfigFiles, "collector-config", nil, "Path to a JSON file containing []CollectorConfig (repeatable); merged after bundle configs, later files win")
	cmd.Flags().StringVar(&collectorNamespace, "collector-namespace", "kvirtbp-collectors", "Kubernetes namespace for collector Jobs")
	cmd.Flags().DurationVar(&collectorTimeout, "collector-timeout", 5*time.Minute, "Maximum time to wait for all collectors to finish")
	cmd.Flags().BoolVar(&noCleanup, "no-collector-cleanup", false, "Keep collector Jobs after completion (useful for debugging)")
	cmd.Flags().StringVar(&outputFile, "output", "collector-data.json", "Path to write the collector data JSON file")

	return cmd
}

// resolveCollectorConfigs loads collectors from one or more bundles and/or
// standalone config files and returns the merged list.
// Bundle configs are merged left-to-right (later bundle wins on collision).
// Config-file configs are then merged on top (config files always win).
func resolveCollectorConfigs(bundlePaths, configFiles []string) ([]collector.CollectorConfig, error) {
	bundleSlices := make([][]collector.CollectorConfig, 0, len(bundlePaths))
	for _, bp := range bundlePaths {
		configs, err := regoengine.CollectorsFromBundle(bp)
		if err != nil {
			return nil, fmt.Errorf("load bundle collectors from %q: %w", bp, err)
		}
		bundleSlices = append(bundleSlices, configs)
	}
	mergedBundles := collector.MergeAll(bundleSlices...)

	fileSlices := make([][]collector.CollectorConfig, 0, len(configFiles))
	for _, cf := range configFiles {
		b, err := os.ReadFile(cf)
		if err != nil {
			return nil, fmt.Errorf("read collector config %q: %w", cf, err)
		}
		var cfgList []collector.CollectorConfig
		if err := json.Unmarshal(b, &cfgList); err != nil {
			return nil, fmt.Errorf("decode collector config %q: %w", cf, err)
		}
		fileSlices = append(fileSlices, cfgList)
	}
	mergedFiles := collector.MergeAll(fileSlices...)

	return collector.MergeCollectorConfigs(mergedBundles, mergedFiles), nil
}

// isRemoteURL returns true when s is an http/https URL.
func isRemoteURL(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || (len(s) > 8 && s[:8] == "https://"))
}

// ensureNamespace creates ns if it does not already exist.
// It returns (true, nil) when ns was created, (false, nil) when it already existed.
func ensureNamespace(ctx context.Context, clients *kube.Clients, ns string) (bool, error) {
	_, err := clients.Core.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err == nil {
		return false, nil // already exists
	}
	if !errors.IsNotFound(err) {
		return false, fmt.Errorf("get namespace %q: %w", ns, err)
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kvirtbp",
			},
		},
	}
	_, createErr := clients.Core.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if createErr != nil && !errors.IsAlreadyExists(createErr) {
		return false, fmt.Errorf("create namespace %q: %w", ns, createErr)
	}
	return true, nil
}

// runCollectors executes all collectors concurrently and aggregates results.
// The returned map is map[collectorName]map[nodeNameOrCluster]map[string]any.
func runCollectors(ctx context.Context, clients *kube.Clients, configs []collector.CollectorConfig, opts collector.RunOptions) (map[string]any, error) {
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		result = make(map[string]any, len(configs))
		runErr error
	)

	for _, cfg := range configs {
		c := collector.NewJobCollector(cfg)
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := c.Collect(ctx, clients, opts)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if runErr == nil {
					runErr = fmt.Errorf("collector %q: %w", c.Name(), err)
				}
				return
			}
			result[c.Name()] = data
		}()
	}
	wg.Wait()
	return result, runErr
}

// writeCollectorResult encodes a CollectorResult as indented JSON and writes
// it to filePath.
func writeCollectorResult(filePath string, result collector.CollectorResult) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode collector data: %w", err)
	}
	if err := os.WriteFile(filePath, b, 0o600); err != nil {
		return fmt.Errorf("write collector data to %q: %w", filePath, err)
	}
	return nil
}
