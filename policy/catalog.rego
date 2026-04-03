package kvirtbp

allowed_categories := {
	"production-readiness",
	"security",
	"availability",
}

pass_findings := [finding |
	check := input.checks[_]
	allowed_categories[check.category]
	valid_id_for_category(check)
	finding := {
		"checkId": check.id,
		"title": check.title,
		"category": check.category,
		"severity": check.severity,
		"pass": true,
		"message": sprintf("rego baseline validated check metadata for %s", [check.id]),
	}
]

fail_findings := [finding |
	check := input.checks[_]
	not allowed_categories[check.category]
	finding := {
		"checkId": check.id,
		"title": check.title,
		"category": check.category,
		"severity": "warning",
		"pass": false,
		"reasonCode": "rego.category.unsupported",
		"message": sprintf("rego baseline rejected unsupported category %s for %s", [check.category, check.id]),
		"remediation": "Use one of: production-readiness, security, availability.",
	}
]

id_mismatch_findings := [finding |
	check := input.checks[_]
	allowed_categories[check.category]
	not valid_id_for_category(check)
	finding := {
		"checkId": check.id,
		"title": check.title,
		"category": check.category,
		"severity": "warning",
		"pass": false,
		"reasonCode": "rego.id.category.mismatch",
		"message": sprintf("rego baseline rejected check ID %s for category %s", [check.id, check.category]),
		"remediation": "Use ID prefixes prod-, sec-, or avail- that match category taxonomy.",
	}
]

valid_id_for_category(check) {
	check.category == "production-readiness"
	startswith(check.id, "prod-")
}

valid_id_for_category(check) {
	check.category == "security"
	startswith(check.id, "sec-")
}

valid_id_for_category(check) {
	check.category == "availability"
	startswith(check.id, "avail-")
}

catalog_findings := array.concat(array.concat(pass_findings, fail_findings), id_mismatch_findings)
