package rego

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/phenixblue/kvirtbp/internal/checks"
	"github.com/phenixblue/kvirtbp/internal/collector"
	"github.com/phenixblue/kvirtbp/internal/eval"
	"github.com/phenixblue/kvirtbp/internal/kube"
	"github.com/phenixblue/kvirtbp/internal/version"
	"golang.org/x/mod/semver"
)

type Engine struct{}

type bundleMetadata struct {
	SchemaVersion    string                      `json:"schemaVersion"`
	PolicyVersion    string                      `json:"policyVersion"`
	MinBinaryVersion string                      `json:"minBinaryVersion"`
	Resources        []string                    `json:"resources"`
	Collectors       []collector.CollectorConfig `json:"collectors,omitempty"`
}

const policySchemaVersion = "v1alpha1"

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Name() string {
	return "rego"
}

func (e *Engine) Evaluate(ctx context.Context, req eval.RunRequest) (checks.RunResult, error) {
	regoArgs, _, err := buildPolicyArgs(req)
	if err != nil {
		return checks.RunResult{}, err
	}

	input := makeInput(req.Registry, req.ClusterSnapshot)
	regoArgs = append(regoArgs,
		rego.Query("data.kvirtbp.findings"),
		rego.Input(input),
	)
	r := rego.New(regoArgs...)

	rs, err := r.Eval(ctx)
	if err != nil {
		return checks.RunResult{}, fmt.Errorf("evaluate rego policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return checks.RunResult{}, fmt.Errorf("rego query returned no results")
	}

	findings, err := decodeFindings(rs[0].Expressions[0].Value)
	if err != nil {
		return checks.RunResult{}, err
	}
	if err := validateFindings(findings); err != nil {
		return checks.RunResult{}, err
	}
	findings = checks.FilterFindings(findings, req.Filter)

	result := checks.RunResult{
		SchemaVersion: checks.ReportSchemaVersion,
		Findings:      findings,
	}
	result.Summary = checks.Summarize(result.Findings)

	return result, nil
}

func buildPolicyArgs(req eval.RunRequest) ([]func(*rego.Rego), []string, error) {
	if req.PolicyBundle != "" {
		return loadBundle(req.PolicyBundle)
	}

	policyText, err := loadPolicy(req.PolicyFile)
	if err != nil {
		return nil, nil, err
	}
	return []func(*rego.Rego){rego.Module("kvirtbp.rego", policyText)}, nil, nil
}

func loadPolicy(path string) (string, error) {
	if path == "" {
		return embeddedBaselinePolicy, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read policy file %q: %w", path, err)
	}
	return string(b), nil
}

func loadBundle(bundlePath string) ([]func(*rego.Rego), []string, error) {
	md, err := readBundleMetadata(bundlePath)
	if err != nil {
		return nil, nil, err
	}
	if err := validateMetadata(md); err != nil {
		return nil, nil, err
	}

	regoFiles, err := filepath.Glob(filepath.Join(bundlePath, "*.rego"))
	if err != nil {
		return nil, nil, fmt.Errorf("read bundle rego files: %w", err)
	}
	if len(regoFiles) == 0 {
		return nil, nil, fmt.Errorf("policy bundle %q has no .rego files", bundlePath)
	}

	args := make([]func(*rego.Rego), 0, len(regoFiles))
	for _, file := range regoFiles {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, fmt.Errorf("read policy file %q: %w", file, err)
		}
		args = append(args, rego.Module(filepath.Base(file), string(b)))
	}

	return args, md.Resources, nil
}

func readBundleMetadata(bundlePath string) (bundleMetadata, error) {
	path := filepath.Join(bundlePath, "metadata.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return bundleMetadata{}, nil
		}
		return bundleMetadata{}, fmt.Errorf("read bundle metadata %q: %w", path, err)
	}

	var md bundleMetadata
	if err := json.Unmarshal(b, &md); err != nil {
		return bundleMetadata{}, fmt.Errorf("decode bundle metadata %q: %w", path, err)
	}
	return md, nil
}

func validateMetadata(md bundleMetadata) error {
	if md.SchemaVersion != "" && md.SchemaVersion != policySchemaVersion {
		return fmt.Errorf("unsupported policy schema version %q (expected %q)", md.SchemaVersion, policySchemaVersion)
	}
	if md.MinBinaryVersion == "" {
		return nil
	}

	binaryVersion := normalizeVersion(version.Version)
	requiredVersion := normalizeVersion(md.MinBinaryVersion)
	if binaryVersion == "" || requiredVersion == "" {
		return nil
	}

	if semver.Compare(binaryVersion, requiredVersion) < 0 {
		return fmt.Errorf("policy bundle requires binary version >= %s, current is %s", requiredVersion, binaryVersion)
	}
	return nil
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" || v == "none" || v == "unknown" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

// ResourceTypesFromBundle reads the metadata.json of a policy bundle and
// returns the list of Kubernetes resource types it declares it needs.
// Returns nil (no error) when the bundle has no metadata or no resources field.
func ResourceTypesFromBundle(bundlePath string) ([]string, error) {
	md, err := readBundleMetadata(bundlePath)
	if err != nil {
		return nil, err
	}
	return md.Resources, nil
}

// CollectorsFromBundle reads the metadata.json of a policy bundle and returns
// the collector configurations declared by the bundle. Script files referenced
// by scripts[].file are read from the bundle directory and their content is
// embedded into the returned configs so the framework can create the
// corresponding ConfigMaps without needing the bundle path at runtime.
// Returns nil (no error) when the bundle has no metadata or no collectors declared.
func CollectorsFromBundle(bundlePath string) ([]collector.CollectorConfig, error) {
	md, err := readBundleMetadata(bundlePath)
	if err != nil {
		return nil, err
	}

	// Resolve script file contents relative to the bundle directory.
	for i := range md.Collectors {
		for j := range md.Collectors[i].Scripts {
			s := &md.Collectors[i].Scripts[j]
			if s.File == "" || s.Content != "" {
				continue
			}
			content, readErr := os.ReadFile(filepath.Join(bundlePath, s.File))
			if readErr != nil {
				return nil, fmt.Errorf("read script %q for collector %q: %w", s.File, md.Collectors[i].Name, readErr)
			}
			s.Content = string(content)
		}
	}

	return md.Collectors, nil
}

func makeInput(registry []checks.Check, snapshot *kube.ClusterSnapshot) map[string]any {
	out := make([]map[string]string, 0, len(registry))
	for _, c := range registry {
		m := c.Metadata()
		out = append(out, map[string]string{
			"id":       m.ID,
			"title":    m.Title,
			"category": m.Category,
			"severity": string(m.Severity),
		})
	}
	input := map[string]any{"checks": out}
	if snapshot != nil {
		input["cluster"] = clusterSnapshotToMap(snapshot)
	}
	return input
}

func clusterSnapshotToMap(snap *kube.ClusterSnapshot) map[string]any {
	// Serialise via JSON round-trip to produce the map[string]any that OPA
	// expects, ensuring field names match the JSON tags on ClusterSnapshot.
	b, err := json.Marshal(snap)
	if err != nil {
		return map[string]any{"marshalError": err.Error()}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{"marshalError": err.Error()}
	}
	return m
}

func decodeFindings(value any) ([]checks.Finding, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal rego result: %w", err)
	}
	var findings []checks.Finding
	if err := json.Unmarshal(b, &findings); err != nil {
		return nil, fmt.Errorf("decode rego findings: %w", err)
	}
	return findings, nil
}

func validateFindings(findings []checks.Finding) error {
	for i, f := range findings {
		if strings.TrimSpace(f.CheckID) == "" {
			return fmt.Errorf("rego finding at index %d is missing checkId", i)
		}
		if strings.TrimSpace(f.Title) == "" {
			return fmt.Errorf("rego finding %q is missing title", f.CheckID)
		}
		if strings.TrimSpace(f.Category) == "" {
			return fmt.Errorf("rego finding %q is missing category", f.CheckID)
		}
		if strings.TrimSpace(f.Message) == "" {
			return fmt.Errorf("rego finding %q is missing message", f.CheckID)
		}

		s, err := checks.ParseSeverity(string(f.Severity))
		if err != nil {
			return fmt.Errorf("rego finding %q has invalid severity %q: %w", f.CheckID, f.Severity, err)
		}
		findings[i].Severity = s
	}
	return nil
}

//go:embed policy/baseline.rego
var embeddedBaselinePolicy string
