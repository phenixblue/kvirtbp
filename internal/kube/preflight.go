package kube

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/phenixblue/kvirtbp/internal/checks"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type permissionProbe struct {
	ID       string
	Resource string
	Group    string
	Verb     string
}

type PreflightOptions struct {
	IncludeNamespaces []string
	ExcludeNamespaces []string
}

func BuildPreflightFindings(ctx context.Context, clients *Clients) []checks.Finding {
	return BuildPreflightFindingsWithOptions(ctx, clients, PreflightOptions{})
}

func BuildPreflightFindingsWithOptions(ctx context.Context, clients *Clients, opts PreflightOptions) []checks.Finding {
	findings := make([]checks.Finding, 0)

	if clients == nil {
		return append(findings, checks.Finding{
			CheckID:  "cluster-connectivity",
			Title:    "Cluster Connectivity",
			Category: "production-readiness",
			Severity: checks.SeverityWarning,
			Pass:     false,
			Message:  "Kubernetes client is unavailable; scan is running in degraded mode.",
		})
	}

	cap, err := DiscoverCapabilities(ctx, clients.Discovery)
	if err != nil {
		findings = append(findings, checks.Finding{
			CheckID:  "cluster-discovery",
			Title:    "Cluster API Discovery",
			Category: "production-readiness",
			Severity: checks.SeverityWarning,
			Pass:     false,
			Message:  fmt.Sprintf("API discovery failed: %v", err),
		})
		return findings
	}

	if cap.KubeVirtInstalled {
		findings = append(findings, checks.Finding{
			CheckID:  "kubevirt-api-availability",
			Title:    "KubeVirt API Availability",
			Category: "production-readiness",
			Severity: checks.SeverityInfo,
			Pass:     true,
			Message:  "Detected kubevirt.io API group.",
		})
	} else {
		findings = append(findings, checks.Finding{
			CheckID:  "kubevirt-api-availability",
			Title:    "KubeVirt API Availability",
			Category: "production-readiness",
			Severity: checks.SeverityWarning,
			Pass:     false,
			Message:  "kubevirt.io API group was not discovered; KubeVirt-specific checks may be skipped.",
		})
	}

	findings = append(findings, buildNetworkingAPIFinding(cap))

	deployments, depErr := clients.Core.AppsV1().Deployments("kubevirt").List(ctx, metav1.ListOptions{})
	if depErr != nil {
		findings = append(findings, buildKubeVirtOperatorHealthFinding(nil, depErr))
	} else {
		findings = append(findings, buildKubeVirtOperatorHealthFinding(deployments.Items, nil))
	}

	nodes, err := clients.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		findings = append(findings, checks.Finding{
			CheckID:       "prod-node-inventory",
			Title:         "Production Node Inventory",
			Category:      "production-readiness",
			Severity:      checks.SeverityWarning,
			Impact:        checks.ImpactMedium,
			Confidence:    checks.ConfidenceHigh,
			Pass:          false,
			ReasonCode:    "prod.nodes.list.error",
			Message:       fmt.Sprintf("unable to list nodes: %v", err),
			RemediationID: "RUNBOOK-PROD-BASELINE-001",
			Remediation:   "Grant node list permissions and verify API server connectivity.",
		})
	} else {
		findings = append(findings, buildNodeInventoryFinding(nodes.Items...))
		findings = append(findings, buildControlPlaneHAFinding(nodes.Items...))
	}

	namespaces, err := clients.Core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		findings = append(findings,
			buildNamespacePSAEnforceFinding(nil, fmt.Errorf("unable to list namespaces: %w", err), opts),
			buildNetworkPolicyCoverageFinding(nil, nil, fmt.Errorf("unable to list namespaces: %w", err), opts),
			buildNamespaceGuardrailsCoverageFinding(nil, nil, nil, fmt.Errorf("unable to list namespaces: %w", err), opts),
			buildNamespacePDBCoverageFinding(nil, nil, fmt.Errorf("unable to list namespaces: %w", err), opts),
		)
	} else {
		findings = append(findings, buildNamespacePSAEnforceFinding(namespaces.Items, nil, opts))

		networkPolicies, npErr := clients.Core.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		findings = append(findings, buildNetworkPolicyCoverageFinding(namespaces.Items, networkPolicies.Items, npErr, opts))

		resourceQuotas, rqErr := clients.Core.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
		limitRanges, lrErr := clients.Core.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
		findings = append(findings, buildNamespaceGuardrailsCoverageFinding(namespaces.Items, resourceQuotas.Items, limitRanges.Items, joinErrs(rqErr, lrErr), opts))

		pdbs, pdbErr := clients.Core.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
		findings = append(findings, buildNamespacePDBCoverageFinding(namespaces.Items, pdbs.Items, pdbErr, opts))
	}

	findings = append(findings, permissionFindings(ctx, clients)...)
	return findings
}

func buildNetworkPolicyCoverageFinding(namespaces []corev1.Namespace, policies []networkingv1.NetworkPolicy, err error, opts PreflightOptions) checks.Finding {
	if err != nil {
		return checks.Finding{
			CheckID:       "sec-networkpolicy-coverage",
			Title:         "Security Namespace NetworkPolicy Coverage",
			Category:      "security",
			Severity:      checks.SeverityWarning,
			Impact:        checks.ImpactHigh,
			Confidence:    checks.ConfidenceHigh,
			Pass:          false,
			ReasonCode:    "sec.networkpolicy.enumeration.error",
			Message:       fmt.Sprintf("unable to evaluate NetworkPolicy coverage: %v", err),
			RemediationID: "RUNBOOK-SEC-NETPOL-001",
			Remediation:   "Grant namespace and networkpolicy read permissions to the scanning identity.",
		}
	}

	targets := targetNamespaces(namespaces, opts)
	if len(targets) == 0 {
		evidence := withNamespaceFilterEvidence(map[string]string{}, opts)
		return checks.Finding{
			CheckID:    "sec-networkpolicy-coverage",
			Title:      "Security Namespace NetworkPolicy Coverage",
			Category:   "security",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactMedium,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "sec.networkpolicy.target.none",
			Message:    "No non-system namespaces detected for NetworkPolicy coverage checks.",
			Evidence:   evidence,
		}
	}

	protected := make(map[string]struct{}, len(policies))
	for _, p := range policies {
		protected[p.Namespace] = struct{}{}
	}

	covered := 0
	missing := make([]string, 0)
	for _, ns := range targets {
		if _, ok := protected[ns]; ok {
			covered++
			continue
		}
		missing = append(missing, ns)
	}

	coverage := percentage(covered, len(targets))
	evidence := map[string]string{
		"targetNamespaces":  fmt.Sprintf("%d", len(targets)),
		"coveredNamespaces": fmt.Sprintf("%d", covered),
		"coveragePercent":   fmt.Sprintf("%.1f", coverage),
	}
	evidence = withNamespaceFilterEvidence(evidence, opts)
	if len(missing) > 0 {
		evidence["missingNamespaces"] = strings.Join(missing, ",")
	}

	if covered == len(targets) {
		return checks.Finding{
			CheckID:    "sec-networkpolicy-coverage",
			Title:      "Security Namespace NetworkPolicy Coverage",
			Category:   "security",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactHigh,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "sec.networkpolicy.coverage.pass",
			Message:    fmt.Sprintf("NetworkPolicy coverage is complete across %d non-system namespaces.", len(targets)),
			Evidence:   evidence,
		}
	}

	return checks.Finding{
		CheckID:       "sec-networkpolicy-coverage",
		Title:         "Security Namespace NetworkPolicy Coverage",
		Category:      "security",
		Severity:      checks.SeverityWarning,
		Impact:        checks.ImpactHigh,
		Confidence:    checks.ConfidenceMedium,
		Pass:          false,
		ReasonCode:    "sec.networkpolicy.coverage.partial",
		Message:       fmt.Sprintf("NetworkPolicy coverage is %.1f%% across non-system namespaces.", coverage),
		Evidence:      evidence,
		RemediationID: "RUNBOOK-SEC-NETPOL-001",
		Remediation:   "Add baseline default-deny plus required allow-list NetworkPolicy rules for uncovered namespaces.",
	}
}

func buildNamespacePSAEnforceFinding(namespaces []corev1.Namespace, err error, opts PreflightOptions) checks.Finding {
	if err != nil {
		return checks.Finding{
			CheckID:       "sec-namespace-psa-enforce",
			Title:         "Security Namespace Pod Security Admission Enforce",
			Category:      "security",
			Severity:      checks.SeverityWarning,
			Impact:        checks.ImpactHigh,
			Confidence:    checks.ConfidenceHigh,
			Pass:          false,
			ReasonCode:    "sec.psa.enumeration.error",
			Message:       fmt.Sprintf("unable to evaluate namespace PSA labels: %v", err),
			RemediationID: "RUNBOOK-SEC-RBAC-001",
			Remediation:   "Grant namespace read permissions so PSA enforce labels can be evaluated.",
		}
	}

	targets := targetNamespaces(namespaces, opts)
	if len(targets) == 0 {
		return checks.Finding{
			CheckID:    "sec-namespace-psa-enforce",
			Title:      "Security Namespace Pod Security Admission Enforce",
			Category:   "security",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactMedium,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "sec.psa.target.none",
			Message:    "No non-system namespaces detected for PSA enforcement checks.",
			Evidence:   withNamespaceFilterEvidence(map[string]string{}, opts),
		}
	}

	nsMap := make(map[string]corev1.Namespace, len(namespaces))
	for _, ns := range namespaces {
		nsMap[ns.Name] = ns
	}

	missing := make([]string, 0)
	compliant := 0
	for _, name := range targets {
		enforce := strings.TrimSpace(nsMap[name].Labels["pod-security.kubernetes.io/enforce"])
		if enforce == "baseline" || enforce == "restricted" {
			compliant++
			continue
		}
		missing = append(missing, name)
	}

	coverage := percentage(compliant, len(targets))
	evidence := map[string]string{
		"targetNamespaces":    fmt.Sprintf("%d", len(targets)),
		"compliantNamespaces": fmt.Sprintf("%d", compliant),
		"coveragePercent":     fmt.Sprintf("%.1f", coverage),
	}
	evidence = withNamespaceFilterEvidence(evidence, opts)
	if len(missing) > 0 {
		evidence["missingPSAEnforce"] = strings.Join(missing, ",")
	}

	if compliant == len(targets) {
		return checks.Finding{
			CheckID:    "sec-namespace-psa-enforce",
			Title:      "Security Namespace Pod Security Admission Enforce",
			Category:   "security",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactHigh,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "sec.psa.enforce.pass",
			Message:    "PSA enforce labels are configured across targeted namespaces.",
			Evidence:   evidence,
		}
	}

	return checks.Finding{
		CheckID:       "sec-namespace-psa-enforce",
		Title:         "Security Namespace Pod Security Admission Enforce",
		Category:      "security",
		Severity:      checks.SeverityWarning,
		Impact:        checks.ImpactHigh,
		Confidence:    checks.ConfidenceMedium,
		Pass:          false,
		ReasonCode:    "sec.psa.enforce.missing",
		Message:       fmt.Sprintf("PSA enforce coverage is %.1f%% across targeted namespaces.", coverage),
		Evidence:      evidence,
		RemediationID: "RUNBOOK-SEC-RBAC-001",
		Remediation:   "Set pod-security.kubernetes.io/enforce to baseline or restricted on uncovered namespaces.",
	}
}

func buildNamespacePDBCoverageFinding(namespaces []corev1.Namespace, pdbs []policyv1.PodDisruptionBudget, err error, opts PreflightOptions) checks.Finding {
	if err != nil {
		return checks.Finding{
			CheckID:       "avail-namespace-pdb-coverage",
			Title:         "Availability Namespace PDB Coverage",
			Category:      "availability",
			Severity:      checks.SeverityWarning,
			Impact:        checks.ImpactMedium,
			Confidence:    checks.ConfidenceHigh,
			Pass:          false,
			ReasonCode:    "avail.pdb.enumeration.error",
			Message:       fmt.Sprintf("unable to evaluate PodDisruptionBudget coverage: %v", err),
			RemediationID: "RUNBOOK-AVAIL-BASELINE-001",
			Remediation:   "Grant PodDisruptionBudget read permissions to the scanning identity.",
		}
	}

	targets := targetNamespaces(namespaces, opts)
	if len(targets) == 0 {
		return checks.Finding{
			CheckID:    "avail-namespace-pdb-coverage",
			Title:      "Availability Namespace PDB Coverage",
			Category:   "availability",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactLow,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "avail.pdb.target.none",
			Message:    "No non-system namespaces detected for PDB coverage checks.",
			Evidence:   withNamespaceFilterEvidence(map[string]string{}, opts),
		}
	}

	pdbNamespaces := make(map[string]struct{}, len(pdbs))
	for _, p := range pdbs {
		pdbNamespaces[p.Namespace] = struct{}{}
	}

	covered := 0
	missing := make([]string, 0)
	for _, name := range targets {
		if _, ok := pdbNamespaces[name]; ok {
			covered++
			continue
		}
		missing = append(missing, name)
	}

	coverage := percentage(covered, len(targets))
	evidence := map[string]string{
		"targetNamespaces":  fmt.Sprintf("%d", len(targets)),
		"coveredNamespaces": fmt.Sprintf("%d", covered),
		"coveragePercent":   fmt.Sprintf("%.1f", coverage),
	}
	evidence = withNamespaceFilterEvidence(evidence, opts)
	if len(missing) > 0 {
		evidence["missingPDBNamespaces"] = strings.Join(missing, ",")
	}

	if covered == len(targets) {
		return checks.Finding{
			CheckID:    "avail-namespace-pdb-coverage",
			Title:      "Availability Namespace PDB Coverage",
			Category:   "availability",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactMedium,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "avail.pdb.coverage.pass",
			Message:    "PodDisruptionBudget coverage is complete across targeted namespaces.",
			Evidence:   evidence,
		}
	}

	return checks.Finding{
		CheckID:       "avail-namespace-pdb-coverage",
		Title:         "Availability Namespace PDB Coverage",
		Category:      "availability",
		Severity:      checks.SeverityWarning,
		Impact:        checks.ImpactMedium,
		Confidence:    checks.ConfidenceMedium,
		Pass:          false,
		ReasonCode:    "avail.pdb.coverage.partial",
		Message:       fmt.Sprintf("PodDisruptionBudget coverage is %.1f%% across targeted namespaces.", coverage),
		Evidence:      evidence,
		RemediationID: "RUNBOOK-AVAIL-BASELINE-001",
		Remediation:   "Add PodDisruptionBudget resources to uncovered workload namespaces.",
	}
}

func buildKubeVirtOperatorHealthFinding(deployments []appsv1.Deployment, err error) checks.Finding {
	if err != nil {
		return checks.Finding{
			CheckID:       "prod-kubevirt-operator-health",
			Title:         "Production KubeVirt Operator Health",
			Category:      "production-readiness",
			Severity:      checks.SeverityWarning,
			Impact:        checks.ImpactHigh,
			Confidence:    checks.ConfidenceHigh,
			Pass:          false,
			ReasonCode:    "prod.kubevirt.operator.enumeration.error",
			Message:       fmt.Sprintf("unable to evaluate kubevirt operator deployment health: %v", err),
			RemediationID: "RUNBOOK-PROD-BASELINE-001",
			Remediation:   "Grant deployment read access in kubevirt namespace and verify operator installation.",
		}
	}

	for _, d := range deployments {
		if d.Name != "virt-operator" && d.Name != "kubevirt-operator" {
			continue
		}
		if d.Status.AvailableReplicas > 0 {
			return checks.Finding{
				CheckID:    "prod-kubevirt-operator-health",
				Title:      "Production KubeVirt Operator Health",
				Category:   "production-readiness",
				Severity:   checks.SeverityInfo,
				Impact:     checks.ImpactHigh,
				Confidence: checks.ConfidenceMedium,
				Pass:       true,
				ReasonCode: "prod.kubevirt.operator.healthy",
				Message:    fmt.Sprintf("KubeVirt operator deployment %s is healthy with %d available replicas.", d.Name, d.Status.AvailableReplicas),
				Evidence: map[string]string{
					"deployment":        d.Name,
					"availableReplicas": fmt.Sprintf("%d", d.Status.AvailableReplicas),
				},
			}
		}

		return checks.Finding{
			CheckID:    "prod-kubevirt-operator-health",
			Title:      "Production KubeVirt Operator Health",
			Category:   "production-readiness",
			Severity:   checks.SeverityWarning,
			Impact:     checks.ImpactHigh,
			Confidence: checks.ConfidenceMedium,
			Pass:       false,
			ReasonCode: "prod.kubevirt.operator.unavailable",
			Message:    fmt.Sprintf("KubeVirt operator deployment %s has no available replicas.", d.Name),
			Evidence: map[string]string{
				"deployment":        d.Name,
				"availableReplicas": fmt.Sprintf("%d", d.Status.AvailableReplicas),
			},
			RemediationID: "RUNBOOK-PROD-BASELINE-001",
			Remediation:   "Investigate virt-operator rollout and reconcile kubevirt control-plane components.",
		}
	}

	return checks.Finding{
		CheckID:       "prod-kubevirt-operator-health",
		Title:         "Production KubeVirt Operator Health",
		Category:      "production-readiness",
		Severity:      checks.SeverityWarning,
		Impact:        checks.ImpactHigh,
		Confidence:    checks.ConfidenceMedium,
		Pass:          false,
		ReasonCode:    "prod.kubevirt.operator.missing",
		Message:       "KubeVirt operator deployment was not found in kubevirt namespace.",
		RemediationID: "RUNBOOK-PROD-BASELINE-001",
		Remediation:   "Install KubeVirt operator and ensure deployment is running in kubevirt namespace.",
	}
}

func buildNamespaceGuardrailsCoverageFinding(namespaces []corev1.Namespace, quotas []corev1.ResourceQuota, limits []corev1.LimitRange, err error, opts PreflightOptions) checks.Finding {
	if err != nil {
		return checks.Finding{
			CheckID:       "prod-namespace-guardrails-coverage",
			Title:         "Production Namespace Guardrails Coverage",
			Category:      "production-readiness",
			Severity:      checks.SeverityWarning,
			Impact:        checks.ImpactMedium,
			Confidence:    checks.ConfidenceHigh,
			Pass:          false,
			ReasonCode:    "prod.guardrails.enumeration.error",
			Message:       fmt.Sprintf("unable to evaluate namespace guardrails: %v", err),
			RemediationID: "RUNBOOK-PROD-GUARDRAILS-001",
			Remediation:   "Grant read permissions for namespaces, resourcequotas, and limitranges.",
		}
	}

	targets := targetNamespaces(namespaces, opts)
	if len(targets) == 0 {
		evidence := withNamespaceFilterEvidence(map[string]string{}, opts)
		return checks.Finding{
			CheckID:    "prod-namespace-guardrails-coverage",
			Title:      "Production Namespace Guardrails Coverage",
			Category:   "production-readiness",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactLow,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "prod.guardrails.target.none",
			Message:    "No non-system namespaces detected for quota/limit guardrail checks.",
			Evidence:   evidence,
		}
	}

	quotaNS := make(map[string]struct{}, len(quotas))
	for _, rq := range quotas {
		quotaNS[rq.Namespace] = struct{}{}
	}
	limitNS := make(map[string]struct{}, len(limits))
	for _, lr := range limits {
		limitNS[lr.Namespace] = struct{}{}
	}

	compliant := 0
	missing := make([]string, 0)
	for _, ns := range targets {
		_, hasQuota := quotaNS[ns]
		_, hasLimit := limitNS[ns]
		if hasQuota && hasLimit {
			compliant++
			continue
		}
		missing = append(missing, ns)
	}

	coverage := percentage(compliant, len(targets))
	evidence := map[string]string{
		"targetNamespaces":    fmt.Sprintf("%d", len(targets)),
		"compliantNamespaces": fmt.Sprintf("%d", compliant),
		"coveragePercent":     fmt.Sprintf("%.1f", coverage),
	}
	evidence = withNamespaceFilterEvidence(evidence, opts)
	if len(missing) > 0 {
		evidence["missingGuardrails"] = strings.Join(missing, ",")
	}

	if coverage >= 80.0 {
		return checks.Finding{
			CheckID:    "prod-namespace-guardrails-coverage",
			Title:      "Production Namespace Guardrails Coverage",
			Category:   "production-readiness",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactMedium,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "prod.guardrails.coverage.pass",
			Message:    fmt.Sprintf("Namespace guardrails coverage is %.1f%% across non-system namespaces.", coverage),
			Evidence:   evidence,
		}
	}

	return checks.Finding{
		CheckID:       "prod-namespace-guardrails-coverage",
		Title:         "Production Namespace Guardrails Coverage",
		Category:      "production-readiness",
		Severity:      checks.SeverityWarning,
		Impact:        checks.ImpactMedium,
		Confidence:    checks.ConfidenceMedium,
		Pass:          false,
		ReasonCode:    "prod.guardrails.coverage.partial",
		Message:       fmt.Sprintf("Namespace guardrails coverage is %.1f%% and below recommended threshold.", coverage),
		Evidence:      evidence,
		RemediationID: "RUNBOOK-PROD-GUARDRAILS-001",
		Remediation:   "Add ResourceQuota and LimitRange defaults to uncovered namespaces.",
	}
}

func targetNamespaces(namespaces []corev1.Namespace, opts PreflightOptions) []string {
	const (
		nsSystem    = "kube-system"
		nsPublic    = "kube-public"
		nsNodeLease = "kube-node-lease"
	)

	includeMatcher := newNamespaceMatcher(opts.IncludeNamespaces)
	excludeMatcher := newNamespaceMatcher(opts.ExcludeNamespaces)

	out := make([]string, 0, len(namespaces))
	for _, ns := range namespaces {
		name := strings.TrimSpace(ns.Name)
		if name == "" {
			continue
		}

		if ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		switch name {
		case nsSystem, nsPublic, nsNodeLease:
			continue
		}

		if includeMatcher.Enabled() {
			if !includeMatcher.Matches(name) {
				continue
			}
		}
		if excludeMatcher.Matches(name) {
			continue
		}

		out = append(out, name)
	}
	return out
}

type namespaceMatcher struct {
	exact    map[string]struct{}
	patterns []string
}

func newNamespaceMatcher(values []string) namespaceMatcher {
	m := namespaceMatcher{exact: map[string]struct{}{}, patterns: []string{}}
	for _, v := range values {
		n := strings.TrimSpace(v)
		if n == "" {
			continue
		}
		if strings.ContainsAny(n, "*?[") {
			m.patterns = append(m.patterns, n)
			continue
		}
		m.exact[n] = struct{}{}
	}
	return m
}

func (m namespaceMatcher) Enabled() bool {
	return len(m.exact) > 0 || len(m.patterns) > 0
}

func (m namespaceMatcher) Matches(name string) bool {
	if len(m.exact) == 0 && len(m.patterns) == 0 {
		return false
	}
	if _, ok := m.exact[name]; ok {
		return true
	}
	for _, p := range m.patterns {
		ok, err := path.Match(p, name)
		if err != nil {
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

func percentage(part int, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func withNamespaceFilterEvidence(evidence map[string]string, opts PreflightOptions) map[string]string {
	if len(opts.IncludeNamespaces) > 0 {
		evidence["namespaceIncludeFilter"] = strings.Join(opts.IncludeNamespaces, ",")
	}
	if len(opts.ExcludeNamespaces) > 0 {
		evidence["namespaceExcludeFilter"] = strings.Join(opts.ExcludeNamespaces, ",")
	}
	return evidence
}

func joinErrs(errs ...error) error {
	parts := make([]string, 0)
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return errors.New(strings.Join(parts, "; "))
}

func buildNetworkingAPIFinding(cap Capabilities) checks.Finding {
	if cap.HasNetworkingV1 {
		return checks.Finding{
			CheckID:    "sec-networking-api-availability",
			Title:      "Security Networking API Availability",
			Category:   "security",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactMedium,
			Confidence: checks.ConfidenceHigh,
			Pass:       true,
			ReasonCode: "sec.networking.api.present",
			Message:    "networking.k8s.io/v1 API is available for NetworkPolicy checks.",
		}
	}

	return checks.Finding{
		CheckID:       "sec-networking-api-availability",
		Title:         "Security Networking API Availability",
		Category:      "security",
		Severity:      checks.SeverityWarning,
		Impact:        checks.ImpactMedium,
		Confidence:    checks.ConfidenceHigh,
		Pass:          false,
		ReasonCode:    "sec.networking.api.missing",
		Message:       "networking.k8s.io/v1 API is unavailable; NetworkPolicy security checks are degraded.",
		RemediationID: "RUNBOOK-SEC-RBAC-001",
		Remediation:   "Ensure networking.k8s.io/v1 is enabled and cluster networking supports NetworkPolicy.",
	}
}

func buildNodeInventoryFinding(nodes ...corev1.Node) checks.Finding {
	if len(nodes) > 0 {
		return checks.Finding{
			CheckID:    "prod-node-inventory",
			Title:      "Production Node Inventory",
			Category:   "production-readiness",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactMedium,
			Confidence: checks.ConfidenceHigh,
			Pass:       true,
			ReasonCode: "prod.nodes.present",
			Message:    fmt.Sprintf("cluster node inventory detected: %d nodes", len(nodes)),
			Evidence: map[string]string{
				"nodeCount": fmt.Sprintf("%d", len(nodes)),
			},
		}
	}

	return checks.Finding{
		CheckID:       "prod-node-inventory",
		Title:         "Production Node Inventory",
		Category:      "production-readiness",
		Severity:      checks.SeverityError,
		Impact:        checks.ImpactHigh,
		Confidence:    checks.ConfidenceHigh,
		Pass:          false,
		ReasonCode:    "prod.nodes.none",
		Message:       "no nodes were returned by the cluster API.",
		RemediationID: "RUNBOOK-PROD-BASELINE-001",
		Remediation:   "Verify cluster health and API permissions for node visibility.",
	}
}

func buildControlPlaneHAFinding(nodes ...corev1.Node) checks.Finding {
	count := controlPlaneNodeCount(nodes...)
	if count >= 3 {
		return checks.Finding{
			CheckID:    "avail-control-plane-ha",
			Title:      "Availability Control Plane HA",
			Category:   "availability",
			Severity:   checks.SeverityInfo,
			Impact:     checks.ImpactHigh,
			Confidence: checks.ConfidenceMedium,
			Pass:       true,
			ReasonCode: "avail.controlplane.ha.pass",
			Message:    fmt.Sprintf("control-plane high availability looks healthy: %d control-plane nodes", count),
			Evidence: map[string]string{
				"controlPlaneNodes": fmt.Sprintf("%d", count),
			},
		}
	}

	return checks.Finding{
		CheckID:    "avail-control-plane-ha",
		Title:      "Availability Control Plane HA",
		Category:   "availability",
		Severity:   checks.SeverityWarning,
		Impact:     checks.ImpactHigh,
		Confidence: checks.ConfidenceMedium,
		Pass:       false,
		ReasonCode: "avail.controlplane.ha.insufficient",
		Message:    fmt.Sprintf("control-plane HA below recommended threshold: %d control-plane nodes", count),
		Evidence: map[string]string{
			"controlPlaneNodes": fmt.Sprintf("%d", count),
		},
		RemediationID: "RUNBOOK-AVAIL-BASELINE-001",
		Remediation:   "Scale control-plane nodes toward a highly available quorum where supported.",
	}
}

func controlPlaneNodeCount(nodes ...corev1.Node) int {
	count := 0
	for _, n := range nodes {
		if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
			count++
			continue
		}
		if _, ok := n.Labels["node-role.kubernetes.io/master"]; ok {
			count++
		}
	}
	return count
}

func permissionFindings(ctx context.Context, clients *Clients) []checks.Finding {
	probes := []permissionProbe{
		{ID: "perm-list-nodes", Group: "", Resource: "nodes", Verb: "list"},
		{ID: "perm-list-namespaces", Group: "", Resource: "namespaces", Verb: "list"},
		{ID: "perm-list-vms", Group: "kubevirt.io", Resource: "virtualmachines", Verb: "list"},
	}

	findings := make([]checks.Finding, 0, len(probes))
	for _, p := range probes {
		allowed, reason, err := canI(ctx, clients, p)
		if err != nil {
			findings = append(findings, checks.Finding{
				CheckID:  p.ID,
				Title:    "RBAC Preflight",
				Category: "security",
				Severity: checks.SeverityWarning,
				Pass:     false,
				Message:  fmt.Sprintf("permission probe failed for %s.%s: %v", p.Resource, p.Group, err),
			})
			continue
		}

		if allowed {
			findings = append(findings, checks.Finding{
				CheckID:  p.ID,
				Title:    "RBAC Preflight",
				Category: "security",
				Severity: checks.SeverityInfo,
				Pass:     true,
				Message:  fmt.Sprintf("allowed to %s %s.%s", p.Verb, p.Resource, p.Group),
			})
			continue
		}

		findings = append(findings, checks.Finding{
			CheckID:  p.ID,
			Title:    "RBAC Preflight",
			Category: "security",
			Severity: checks.SeverityWarning,
			Pass:     false,
			Message:  fmt.Sprintf("not allowed to %s %s.%s (%s)", p.Verb, p.Resource, p.Group, reason),
		})
	}

	return findings
}

func canI(ctx context.Context, clients *Clients, p permissionProbe) (bool, string, error) {
	review, err := clients.Core.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     p.Verb,
				Group:    p.Group,
				Resource: p.Resource,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, "", err
	}

	return review.Status.Allowed, review.Status.Reason, nil
}
