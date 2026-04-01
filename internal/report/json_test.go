package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/checks"
)

func TestWriteJSONIncludesMetadataSnapshot(t *testing.T) {
	result := checks.RunResult{
		SchemaVersion: checks.ReportSchemaVersion,
		Metadata: &checks.MetadataRun{
			Engine:                    "rego",
			NamespaceInclude:          []string{"tenant-*"},
			NamespaceExclude:          []string{"tenant-b"},
			ClusterContextHash:        "abc123def456",
			ClusterContextHashVersion: "v1",
			DurationMillis:            37,
			PolicyBundle:              "./policy/bundle",
			EvaluationMode:            "hybrid",
			KubeContext:               "dev",
			KubeconfigProvided:        true,
		},
		Summary: checks.Summary{Total: 1, Passed: 1, Failed: 0, Info: 1, Warning: 0, Error: 0},
		Findings: []checks.Finding{
			{
				CheckID:  "kubevirt-api-availability",
				Title:    "KubeVirt API Availability",
				Category: "production-readiness",
				Severity: checks.SeverityInfo,
				Pass:     true,
				Message:  "Detected kubevirt.io API group.",
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"\"metadata\": {",
		"\"engine\": \"rego\"",
		"\"namespaceInclude\": [",
		"\"namespaceExclude\": [",
		"\"clusterContextHash\": \"abc123def456\"",
		"\"clusterContextHashVersion\": \"v1\"",
		"\"durationMillis\": 37",
		"\"evaluationMode\": \"hybrid\"",
		"\"kubeContext\": \"dev\"",
		"\"kubeconfigProvided\": true",
		"\"schemaVersion\": \"v1alpha1\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected JSON snapshot to contain %q\nOutput:\n%s", want, out)
		}
	}
}

func TestWriteJSONOmitsEmptyMetadataFields(t *testing.T) {
	result := checks.RunResult{
		SchemaVersion: checks.ReportSchemaVersion,
		Metadata: &checks.MetadataRun{
			Engine: "go",
		},
		Summary: checks.Summary{Total: 0, Passed: 0, Failed: 0, Info: 0, Warning: 0, Error: 0},
		Findings: []checks.Finding{},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output failed: %v", err)
	}

	metaAny, ok := payload["metadata"]
	if !ok {
		t.Fatal("expected metadata object")
	}
	meta, ok := metaAny.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata to be object, got %T", metaAny)
	}

	if got, ok := meta["engine"]; !ok || got != "go" {
		t.Fatalf("expected metadata.engine=go, got %v", got)
	}

	for _, key := range []string{
		"namespaceInclude",
		"namespaceExclude",
		"clusterContextHash",
		"clusterContextHashVersion",
		"durationMillis",
		"policyFile",
		"policyBundle",
		"kubeContext",
		"kubeconfigProvided",
	} {
		if _, exists := meta[key]; exists {
			t.Fatalf("expected metadata.%s to be omitted when empty", key)
		}
	}
}

func TestWriteJSONGoldenShape(t *testing.T) {
	result := checks.RunResult{
		SchemaVersion: checks.ReportSchemaVersion,
		Metadata: &checks.MetadataRun{
			Engine:                    "rego",
			ClusterContextHash:        "1234567890ab",
			ClusterContextHashVersion: "v1",
			EvaluationMode:            "hybrid",
		},
		Summary: checks.Summary{Total: 1, Passed: 1, Failed: 0, Info: 1, Warning: 0, Error: 0},
		Findings: []checks.Finding{{
			CheckID:  "id-1",
			Title:    "Title 1",
			Category: "security",
			Severity: checks.SeverityInfo,
			Pass:     true,
			Message:  "ok",
		}},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"{",
		"\"schemaVersion\": \"v1alpha1\"",
		"\"metadata\": {",
		"\"clusterContextHashVersion\": \"v1\"",
		"\"summary\": {",
		"\"findings\": [",
		"\"checkId\": \"id-1\"",
		"}",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected golden JSON shape to contain %q\nOutput:\n%s", want, out)
		}
	}
}
