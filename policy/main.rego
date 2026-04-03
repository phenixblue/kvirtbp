package kvirtbp

# Combine catalog checks (input.checks) and cluster checks (input.cluster)
# into the single required entrypoint: data.kvirtbp.findings.
findings := array.concat(catalog_findings, cluster_findings)
