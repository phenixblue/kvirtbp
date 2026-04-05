# Collectors Guide

Collectors are short-lived Kubernetes Jobs deployed by `kvirtbp collect` to gather node or cluster-scope data that Rego policies can reference at scan time via `input.cluster.collectors`.

## How it works

```
kvirtbp collect                  kvirtbp scan --collector-data ...
      │                                       │
      ▼                                       ▼
Deploy Jobs on cluster          Load collector-data.json
      │                                       │
      ▼                                       ▼
Wait for completion             Inject into ClusterSnapshot.Collectors
      │                                       │
      ▼                                       ▼
Read pod logs (JSON)            Available as input.cluster.collectors
      │
      ▼
Write collector-data.json
```

`scan` is read-only. All cluster writes happen exclusively in `collect`.

## Quick start

```bash
# Run collectors declared in a local policy bundle
./bin/kvirtbp collect --bundle ./policy/baseline --output collector-data.json

# Run collectors from a remote bundle (HTTPS .tar.gz)
./bin/kvirtbp collect \
    --bundle https://github.com/myorg/policies/archive/refs/tags/v1.2.0.tar.gz \
    --output collector-data.json

# Monorepo: bundle lives under a subdirectory of the archive
./bin/kvirtbp collect \
    --bundle https://github.com/myorg/policies/archive/refs/tags/v1.2.0.tar.gz \
    --bundle-subdir policy/kubevirt \
    --output collector-data.json

# Or from a standalone collector config file
./bin/kvirtbp collect --collector-config ./my-collectors.json --output collector-data.json

# Then scan with the collected data
./bin/kvirtbp scan --engine rego --policy-bundle ./policy/baseline \
    --collector-data collector-data.json
```

## CollectorConfig schema

Collectors are declared as JSON objects. The schema maps to `collector.CollectorConfig` in the Go package.

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique identifier; used as the key in `input.cluster.collectors` |
| `image` | string | yes | Container image to run |
| `commands` | []string | yes | Shell commands to execute inside the container |
| `scope` | string | no | `"once"` (default) or `"per-node"` |
| `outputPath` | string | no | In-pod path where commands write JSON output (default: `/kvirtbp/output.json`) |
| `timeoutSeconds` | int | no | Per-collector deadline in seconds; `0` means use the global `--collector-timeout` cap |
| `privileged` | bool | no | Run container with `SecurityContext.Privileged = true` |
| `hostPID` | bool | no | Mount host PID namespace |
| `hostNetwork` | bool | no | Attach to host network namespace |
| `env` | object | no | Environment variables injected into the container |
| `tolerations` | []object | no | Pod tolerations applied to the Job pod. Each object supports `key`, `operator` (`Exists`/`Equal`), `value`, and `effect` fields. Use `{"operator": "Exists"}` to tolerate all taints (e.g. to run `per-node` on control-plane nodes). |

### Scope values

| Value | Behaviour |
|---|---|
| `once` | A single Job is deployed. Output is stored under the sentinel key `_cluster`. |
| `per-node` | One Job per node (via `nodeName` selector). Output is stored keyed by node name. |

## Output format

`kvirtbp collect` writes a JSON file with the structure:

```json
{
  "<collector-name>": {
    "<node-name-or-_cluster>": {
      "<key>": "<value>"
    }
  }
}
```

Example with a `sysctl` collector using `scope: once`:

```json
{
  "sysctl": {
    "_cluster": {
      "net.ipv4.ip_forward": "0",
      "net.bridge.bridge-nf-call-iptables": "1"
    }
  }
}
```

Example with a `sysctl` collector using `scope: per-node`:

```json
{
  "sysctl": {
    "worker-1": { "net.ipv4.ip_forward": "0" },
    "worker-2": { "net.ipv4.ip_forward": "1" }
  }
}
```

If a collector (or individual node) fails, an `_error` key is stored in place of the normal output and collection continues:

```json
{
  "sysctl": {
    "worker-1": { "_error": "job kvirtbp-sysctl-worker-1 failed: BackoffLimitExceeded" }
  }
}
```

## Writing collector output

Commands must write valid JSON to `outputPath` (default `/kvirtbp/output.json`). The CLI appends `cat <outputPath>` as the last command in the Job spec — this is what appears as pod logs and is parsed as JSON.

Intermediate commands may freely write to stdout/stderr without corrupting the output payload since they run before the final `cat`.

Example pattern for a sysctl collector:

```bash
# write JSON to the output path, then let the CLI's appended "cat" emit it
commands:
  - "sysctl -a --pattern '^(net\\.ipv4\\.ip_forward|net\\.bridge\\.bridge-nf-call-iptables)' | awk 'BEGIN{printf \"{\"} {printf \"%s\\\"%s\\\": \\\"%s\\\"%s\", NR>1?\",\":\" \", $1, $3} END{print \"}\"}' > /kvirtbp/output.json"
```

Or with a helper image that already produces JSON:

```bash
commands:
  - "my-tool dump-json > /kvirtbp/output.json"
```

## Declaring collectors in a bundle

Add a `collectors` array to the bundle's `metadata.json`:

```json
{
  "schemaVersion": "v1alpha1",
  "policyVersion": "1.0.0",
  "resources": ["v1/nodes"],
  "collectors": [
    {
      "name": "sysctl",
      "image": "alpine:3.21",
      "commands": [
        "apk add -q procps",
        "sysctl -a --pattern '^net\\.ipv4\\.ip_forward' | awk 'BEGIN{printf \"{\"}{printf \"\\\"%s\\\":\\\"%s\\\"\", $1,$3}END{print \"}\"}' > /kvirtbp/output.json"
      ],
      "scope": "per-node",
      "privileged": true,
      "hostNetwork": true
    }
  ]
}
```

Running `kvirtbp collect --bundle ./policy/baseline` will execute these collectors automatically.

## Merging collector configs

When both `--bundle` and `--collector-config` are provided, the two sets are merged. `--collector-config` wins on name collision:

```bash
./bin/kvirtbp collect \
    --bundle ./policy/baseline \
    --collector-config ./overrides.json \
    --output collector-data.json
```

`overrides.json` can be a partial list — only the names that need to differ from the bundle's defaults need to be included.

## RBAC requirements

The identity running `kvirtbp collect` needs:

```yaml
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "create"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["list"]          # needed for per-node scope
```

If `--collector-namespace` already exists, the `namespaces` create verb is not required.

## Debugging

Use `--no-collector-cleanup` to prevent Job deletion after completion:

```bash
./bin/kvirtbp collect --bundle ./policy/baseline \
    --no-collector-cleanup --output collector-data.json
```

Then inspect failed Jobs directly:

```bash
kubectl get jobs -n kvirtbp-collectors
kubectl logs -n kvirtbp-collectors -l collector-name=sysctl
```

## Security considerations

- `privileged`, `hostPID`, and `hostNetwork` must be explicitly opted into per collector; they are never defaulted.
- The collector namespace (`kvirtbp-collectors` by default) should have a restrictive PSA policy. Consider `enforce: privileged` only if your collectors require host access, and scope the namespace RBAC tightly.
- Collector `env` values are stored in plain text in the Job spec. Do not use them for secrets; use a Kubernetes Secret volume mount instead.
- The output file (`collector-data.json`) may contain sensitive node data. Treat it with appropriate access controls.
