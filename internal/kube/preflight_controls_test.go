package kube

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestControlPlaneNodeCount(t *testing.T) {
	nodes := []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
		{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/master": ""}}},
		{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/worker": ""}}},
	}
	if got := controlPlaneNodeCount(nodes...); got != 2 {
		t.Fatalf("expected 2 control-plane nodes, got %d", got)
	}
}

func TestBuildControlPlaneHAFinding(t *testing.T) {
	pass := buildControlPlaneHAFinding(
		corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
		corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
		corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
	)
	if !pass.Pass {
		t.Fatal("expected HA finding to pass with 3 control-plane nodes")
	}

	fail := buildControlPlaneHAFinding(
		corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
	)
	if fail.Pass {
		t.Fatal("expected HA finding to fail with insufficient control-plane nodes")
	}
}

func TestBuildNodeInventoryFinding(t *testing.T) {
	ok := buildNodeInventoryFinding(corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}})
	if !ok.Pass {
		t.Fatal("expected node inventory finding to pass when nodes are present")
	}

	none := buildNodeInventoryFinding()
	if none.Pass {
		t.Fatal("expected node inventory finding to fail when no nodes are present")
	}
}

func TestBuildNetworkPolicyCoverageFinding(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
	}

	pass := buildNetworkPolicyCoverageFinding(
		namespaces,
		[]networkingv1.NetworkPolicy{
			{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "tenant-a"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "tenant-b"}},
		},
		nil,
		PreflightOptions{},
	)
	if !pass.Pass {
		t.Fatalf("expected network policy coverage to pass, got reason=%s", pass.ReasonCode)
	}
	if pass.Evidence["targetNamespaces"] == "" {
		t.Fatal("expected network policy evidence to include targetNamespaces")
	}

	filtered := buildNetworkPolicyCoverageFinding(
		namespaces,
		[]networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "tenant-a"}}},
		nil,
		PreflightOptions{ExcludeNamespaces: []string{"tenant-b"}},
	)
	if !filtered.Pass {
		t.Fatalf("expected filtered network policy coverage to pass, got reason=%s", filtered.ReasonCode)
	}
	if filtered.Evidence["namespaceExcludeFilter"] != "tenant-b" {
		t.Fatalf("expected network policy evidence to include namespace exclude filter, got %+v", filtered.Evidence)
	}
}

func TestBuildNamespaceGuardrailsCoverageFinding(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
	}

	pass := buildNamespaceGuardrailsCoverageFinding(
		namespaces,
		[]corev1.ResourceQuota{{ObjectMeta: metav1.ObjectMeta{Name: "rq", Namespace: "tenant-a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "rq", Namespace: "tenant-b"}}},
		[]corev1.LimitRange{{ObjectMeta: metav1.ObjectMeta{Name: "lr", Namespace: "tenant-a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "lr", Namespace: "tenant-b"}}},
		nil,
		PreflightOptions{IncludeNamespaces: []string{"tenant-*"}},
	)
	if !pass.Pass {
		t.Fatalf("expected namespace guardrails coverage to pass, got reason=%s", pass.ReasonCode)
	}
	if pass.Evidence["namespaceIncludeFilter"] != "tenant-*" {
		t.Fatalf("expected guardrails evidence to include namespace include filter, got %+v", pass.Evidence)
	}

	fail := buildNamespaceGuardrailsCoverageFinding(
		namespaces,
		[]corev1.ResourceQuota{{ObjectMeta: metav1.ObjectMeta{Name: "rq", Namespace: "tenant-a"}}},
		nil,
		nil,
		PreflightOptions{},
	)
	if fail.Pass {
		t.Fatalf("expected namespace guardrails coverage to fail, got reason=%s", fail.ReasonCode)
	}
}

func TestTargetNamespacesIncludeExclude(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-c"}},
	}

	got := targetNamespaces(namespaces, PreflightOptions{
		IncludeNamespaces: []string{"tenant-a", "tenant-b"},
		ExcludeNamespaces: []string{"tenant-b"},
	})

	if len(got) != 1 || got[0] != "tenant-a" {
		t.Fatalf("unexpected namespace target result: %+v", got)
	}
}

func TestTargetNamespacesWildcardExclude(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "platform-monitoring"}},
	}

	got := targetNamespaces(namespaces, PreflightOptions{
		ExcludeNamespaces: []string{"platform-*", "tenant-b"},
	})

	if len(got) != 1 || got[0] != "tenant-a" {
		t.Fatalf("unexpected namespace wildcard exclude result: %+v", got)
	}
}

func TestTargetNamespacesWildcardIncludeThenExclude(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "ops-a"}},
	}

	got := targetNamespaces(namespaces, PreflightOptions{
		IncludeNamespaces: []string{"tenant-*", "ops-*"},
		ExcludeNamespaces: []string{"tenant-b", "ops-*"},
	})

	if len(got) != 1 || got[0] != "tenant-a" {
		t.Fatalf("unexpected namespace wildcard include/exclude result: %+v", got)
	}
}

func TestBuildNamespacePSAEnforceFinding(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
	}

	fail := buildNamespacePSAEnforceFinding(namespaces, nil, PreflightOptions{})
	if fail.Pass {
		t.Fatalf("expected psa enforce finding to fail, got reason=%s", fail.ReasonCode)
	}

	pass := buildNamespacePSAEnforceFinding([]corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
	}, nil, PreflightOptions{})
	if !pass.Pass {
		t.Fatalf("expected psa enforce finding to pass, got reason=%s", pass.ReasonCode)
	}
}

func TestBuildNamespacePDBCoverageFinding(t *testing.T) {
	namespaces := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tenant-b"}},
	}

	fail := buildNamespacePDBCoverageFinding(namespaces, []policyv1.PodDisruptionBudget{{ObjectMeta: metav1.ObjectMeta{Name: "pdb", Namespace: "tenant-a"}}}, nil, PreflightOptions{})
	if fail.Pass {
		t.Fatalf("expected pdb coverage finding to fail, got reason=%s", fail.ReasonCode)
	}

	pass := buildNamespacePDBCoverageFinding(namespaces, []policyv1.PodDisruptionBudget{{ObjectMeta: metav1.ObjectMeta{Name: "pdb-a", Namespace: "tenant-a"}}, {ObjectMeta: metav1.ObjectMeta{Name: "pdb-b", Namespace: "tenant-b"}}}, nil, PreflightOptions{})
	if !pass.Pass {
		t.Fatalf("expected pdb coverage finding to pass, got reason=%s", pass.ReasonCode)
	}
}

func TestBuildKubeVirtOperatorHealthFinding(t *testing.T) {
	pass := buildKubeVirtOperatorHealthFinding([]appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "virt-operator"}, Status: appsv1.DeploymentStatus{AvailableReplicas: 1}}}, nil)
	if !pass.Pass {
		t.Fatalf("expected kubevirt operator health to pass, got reason=%s", pass.ReasonCode)
	}

	fail := buildKubeVirtOperatorHealthFinding([]appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "virt-operator"}, Status: appsv1.DeploymentStatus{AvailableReplicas: 0}}}, nil)
	if fail.Pass {
		t.Fatalf("expected kubevirt operator health to fail, got reason=%s", fail.ReasonCode)
	}
}

func TestParseResourceType_CoreGroup(t *testing.T) {
	gvr, err := parseResourceType("v1/ConfigMap")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvr.Group != "" || gvr.Version != "v1" || gvr.Resource != "configmap" {
		t.Errorf("unexpected gvr: %+v", gvr)
	}
}

func TestParseResourceType_NamedGroup(t *testing.T) {
	gvr, err := parseResourceType("apps/v1/Deployment")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvr.Group != "apps" || gvr.Version != "v1" || gvr.Resource != "deployment" {
		t.Errorf("unexpected gvr: %+v", gvr)
	}
}

func TestParseResourceType_CRD(t *testing.T) {
	gvr, err := parseResourceType("kubevirt.io/v1/VirtualMachine")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gvr.Group != "kubevirt.io" || gvr.Version != "v1" || gvr.Resource != "virtualmachine" {
		t.Errorf("unexpected gvr: %+v", gvr)
	}
}

func TestParseResourceType_Invalid(t *testing.T) {
	cases := []string{"", "noSlash", "a/b/c/d"}
	for _, c := range cases {
		if _, err := parseResourceType(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}
