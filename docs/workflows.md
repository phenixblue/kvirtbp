# Example Workflows

This page provides practical local and CI usage patterns for `kvirtbp`.

## Local operator workflow

```bash
make build
./bin/kvirtbp scan --output table
./bin/kvirtbp scan --output json > report.json
```

## Namespace-scoped security review

```bash
./bin/kvirtbp scan \
  --category security \
  --namespace tenant-a \
  --exclude-namespace tenant-a-shared \
  --output table
```

## Rego policy bundle validation

```bash
./bin/kvirtbp scan \
  --engine rego \
  --policy-bundle ./policy/baseline \
  --output json
```

## CI gating workflow (shell)

```bash
set -euo pipefail

./bin/kvirtbp scan --output json > report.json

# Exit code handling:
# 0 = pass, 2 = violations, 3 = partial/degraded
# Gate strictly on 0 in protected environments.
```

## CI gating workflow (GitHub Actions snippet)

```yaml
- name: Build scanner
  run: make build

- name: Run scan
  run: ./bin/kvirtbp scan --output json > report.json

- name: Upload report artifact
  uses: actions/upload-artifact@v4
  with:
    name: kvirtbp-report
    path: report.json
```

## Exception-managed workflow with waivers

```bash
./bin/kvirtbp scan \
  --output json \
  --waiver-file ./waivers.yaml > report.json
```

Use this mode when temporary exceptions are approved and tracked with owner + expiry metadata.
