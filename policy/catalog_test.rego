package kvirtbp

# ---------------------------------------------------------------------------
# catalog_test.rego — OPA unit tests for catalog.rego
# Run with: opa test ./policy/ -v
# ---------------------------------------------------------------------------

# Valid security check (sec- prefix + security category) → pass finding.
test_catalog_valid_security_check {
	f := catalog_findings with input as {
		"checks": [{"id": "sec-baseline-rbac", "title": "RBAC Safety", "category": "security", "severity": "info"}],
	}
	count(f) == 1
	f[0].pass == true
	f[0].checkId == "sec-baseline-rbac"
}

# Valid production-readiness check (prod- prefix) → pass finding.
test_catalog_valid_prod_check {
	f := catalog_findings with input as {
		"checks": [{"id": "prod-operator-health", "title": "Operator Health", "category": "production-readiness", "severity": "info"}],
	}
	count(f) == 1
	f[0].pass == true
}

# Valid availability check (avail- prefix) → pass finding.
test_catalog_valid_avail_check {
	f := catalog_findings with input as {
		"checks": [{"id": "avail-pdb-coverage", "title": "PDB Coverage", "category": "availability", "severity": "info"}],
	}
	count(f) == 1
	f[0].pass == true
}

# Unsupported category → fail with rego.category.unsupported reason code.
test_catalog_unsupported_category {
	f := catalog_findings with input as {
		"checks": [{"id": "xyz-custom-check", "title": "Custom", "category": "compliance", "severity": "warning"}],
	}
	count(f) == 1
	f[0].pass == false
	f[0].reasonCode == "rego.category.unsupported"
}

# Correct category but wrong ID prefix → fail with rego.id.category.mismatch.
test_catalog_id_category_mismatch {
	f := catalog_findings with input as {
		"checks": [{"id": "prod-wrong-for-security", "title": "Mismatch", "category": "security", "severity": "info"}],
	}
	count(f) == 1
	f[0].pass == false
	f[0].reasonCode == "rego.id.category.mismatch"
}

# Empty checks array → no findings.
test_catalog_empty_checks {
	f := catalog_findings with input as {"checks": []}
	f == []
}

# Two checks: one passes, one has mismatched ID prefix → two findings.
test_catalog_multiple_checks_mixed {
	f := catalog_findings with input as {
		"checks": [
			{"id": "sec-baseline", "title": "Sec Baseline", "category": "security", "severity": "info"},
			{"id": "prod-wrong", "title": "Wrong Prefix", "category": "security", "severity": "info"},
		],
	}
	count(f) == 2
	# pass_findings comes before id_mismatch_findings in the concat order
	f[0].pass == true
	f[1].pass == false
	f[1].reasonCode == "rego.id.category.mismatch"
}

# All three valid categories produce pass findings in a single evaluation.
test_catalog_all_valid_categories {
	f := catalog_findings with input as {
		"checks": [
			{"id": "sec-check", "title": "sec", "category": "security", "severity": "info"},
			{"id": "prod-check", "title": "prod", "category": "production-readiness", "severity": "info"},
			{"id": "avail-check", "title": "avail", "category": "availability", "severity": "info"},
		],
	}
	count(f) == 3
	count([x | x := f[_]; x.pass == true]) == 3
}
