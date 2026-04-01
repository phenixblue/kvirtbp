package checks

func DefaultControlCatalog() []Metadata {
	return []Metadata{
		{
			ID:       "prod-baseline-kubevirt-readiness",
			Title:    "Production Baseline: KubeVirt Readiness",
			Category: "production-readiness",
			Severity: SeverityInfo,
		},
		{
			ID:       "sec-baseline-rbac-safety",
			Title:    "Security Baseline: RBAC Safety",
			Category: "security",
			Severity: SeverityInfo,
		},
		{
			ID:       "avail-baseline-workload-resilience",
			Title:    "Availability Baseline: Workload Resilience",
			Category: "availability",
			Severity: SeverityInfo,
		},
	}
}
