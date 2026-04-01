package kube

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type namespacePSAFixture struct {
	Namespaces []struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"namespaces"`
}

type namespacePDBFixture struct {
	Namespaces []struct {
		Name string `yaml:"name"`
	} `yaml:"namespaces"`
	PDBNamespaces []string `yaml:"pdbNamespaces"`
}

func TestNamespacePSAFixtureCases(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		expectPass bool
	}{
		{name: "pass", fixture: "pass.yaml", expectPass: true},
		{name: "fail", fixture: "fail.yaml", expectPass: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := loadNamespacePSAFixture(t, tc.fixture)
			ns := make([]corev1.Namespace, 0, len(fx.Namespaces))
			for _, n := range fx.Namespaces {
				ns = append(ns, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n.Name, Labels: n.Labels}})
			}

			finding := buildNamespacePSAEnforceFinding(ns, nil, PreflightOptions{})
			if finding.Pass != tc.expectPass {
				t.Fatalf("expected pass=%t, got pass=%t reason=%s", tc.expectPass, finding.Pass, finding.ReasonCode)
			}
		})
	}
}

func TestNamespacePDBFixtureCases(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		expectPass bool
	}{
		{name: "pass", fixture: "pass.yaml", expectPass: true},
		{name: "fail", fixture: "fail.yaml", expectPass: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := loadNamespacePDBFixture(t, tc.fixture)
			ns := make([]corev1.Namespace, 0, len(fx.Namespaces))
			for _, n := range fx.Namespaces {
				ns = append(ns, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n.Name}})
			}

			pdbs := make([]policyv1.PodDisruptionBudget, 0, len(fx.PDBNamespaces))
			for i, name := range fx.PDBNamespaces {
				pdbs = append(pdbs, policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pdb-%d", i+1), Namespace: name}})
			}

			finding := buildNamespacePDBCoverageFinding(ns, pdbs, nil, PreflightOptions{})
			if finding.Pass != tc.expectPass {
				t.Fatalf("expected pass=%t, got pass=%t reason=%s", tc.expectPass, finding.Pass, finding.ReasonCode)
			}
		})
	}
}

func loadNamespacePSAFixture(t *testing.T, file string) namespacePSAFixture {
	t.Helper()
	path := filepath.Join("..", "..", "test", "fixtures", "preflight", "namespace_psa", file)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx namespacePSAFixture
	if err := yaml.Unmarshal(b, &fx); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	return fx
}

func loadNamespacePDBFixture(t *testing.T, file string) namespacePDBFixture {
	t.Helper()
	path := filepath.Join("..", "..", "test", "fixtures", "preflight", "namespace_pdb", file)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx namespacePDBFixture
	if err := yaml.Unmarshal(b, &fx); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	return fx
}
