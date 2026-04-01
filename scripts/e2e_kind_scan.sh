#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
if [[ "$MODE" != "pass" && "$MODE" != "fail" ]]; then
  echo "usage: $0 <pass|fail>"
  exit 64
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 127
  fi
}

require_cmd kind
require_cmd kubectl
require_cmd make

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KUBEVIRT_VERSION="${KUBEVIRT_VERSION:-v1.2.2}"
SCAN_ENGINE="${SCAN_ENGINE:-go}"
RECREATE_CLUSTER="${RECREATE_CLUSTER:-true}"
VM_COUNT="${VM_COUNT:-3}"
WAIT_FOR_VMIS="${WAIT_FOR_VMIS:-true}"
VMI_WAIT_TIMEOUT_SECONDS="${VMI_WAIT_TIMEOUT_SECONDS:-180}"
VMI_WAIT_INTERVAL_SECONDS="${VMI_WAIT_INTERVAL_SECONDS:-5}"
UNTAINT_CONTROL_PLANE_NODES="${UNTAINT_CONTROL_PLANE_NODES:-true}"
KUBEVIRT_WAIT_TIMEOUT="${KUBEVIRT_WAIT_TIMEOUT:-20m}"
VM_CONTAINERDISK_IMAGE="${VM_CONTAINERDISK_IMAGE:-quay.io/kubevirt/cirros-container-disk-demo:latest}"

if [[ "$MODE" == "pass" ]]; then
  CLUSTER_NAME="${CLUSTER_NAME:-kvirtbp-pass}"
  KIND_CONFIG="$ROOT_DIR/scripts/kind/pass.yaml"
  TARGET_NAMESPACE="${TARGET_NAMESPACE:-kvirtbp-pass-ns}"
else
  CLUSTER_NAME="${CLUSTER_NAME:-kvirtbp-fail}"
  KIND_CONFIG="$ROOT_DIR/scripts/kind/fail.yaml"
  TARGET_NAMESPACE="${TARGET_NAMESPACE:-kvirtbp-fail-ns}"
fi

KUBE_CONTEXT="kind-${CLUSTER_NAME}"

log() {
  echo "[kvirtbp-e2e] $*"
}

if [[ "$RECREATE_CLUSTER" == "true" ]]; then
  log "Deleting existing kind cluster (if present): $CLUSTER_NAME"
  kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
fi

if ! kind get clusters | grep -qx "$CLUSTER_NAME"; then
  log "Creating kind cluster: $CLUSTER_NAME"
  kind create cluster --name "$CLUSTER_NAME" --config "$KIND_CONFIG" --wait 120s
else
  log "Reusing existing cluster: $CLUSTER_NAME"
fi

if [[ "$UNTAINT_CONTROL_PLANE_NODES" == "true" ]]; then
  log "Removing control-plane taints to allow scheduling in kind e2e clusters"
  control_plane_nodes="$(kubectl --context "$KUBE_CONTEXT" get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
  if [[ -n "$control_plane_nodes" ]]; then
    while IFS= read -r node; do
      [[ -z "$node" ]] && continue
      kubectl --context "$KUBE_CONTEXT" taint node "$node" node-role.kubernetes.io/control-plane- --overwrite >/dev/null 2>&1 || true
      kubectl --context "$KUBE_CONTEXT" taint node "$node" node-role.kubernetes.io/master- --overwrite >/dev/null 2>&1 || true
    done <<< "$control_plane_nodes"
  fi
fi

log "Installing KubeVirt operator: $KUBEVIRT_VERSION"
kubectl --context "$KUBE_CONTEXT" apply -f "https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-operator.yaml"

log "Creating KubeVirt custom resource"
cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: kubevirt.io/v1
kind: KubeVirt
metadata:
  name: kubevirt
  namespace: kubevirt
spec:
  configuration:
    developerConfiguration:
      useEmulation: true
EOF

log "Waiting for KubeVirt to become available (timeout: ${KUBEVIRT_WAIT_TIMEOUT})"
if ! kubectl --context "$KUBE_CONTEXT" wait -n kubevirt kubevirt/kubevirt --for=condition=Available --timeout="$KUBEVIRT_WAIT_TIMEOUT"; then
  log "ERROR: KubeVirt did not become Available in time; dumping diagnostics"
  kubectl --context "$KUBE_CONTEXT" -n kubevirt get pods -o wide || true
  kubectl --context "$KUBE_CONTEXT" -n kubevirt get kubevirt kubevirt -o yaml || true
  exit 1
fi

log "Preparing target namespace: $TARGET_NAMESPACE"
kubectl --context "$KUBE_CONTEXT" create namespace "$TARGET_NAMESPACE" --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -

if ! [[ "$VM_COUNT" =~ ^[0-9]+$ ]] || [[ "$VM_COUNT" -lt 1 ]]; then
  log "ERROR: VM_COUNT must be a positive integer (got: $VM_COUNT)"
  exit 64
fi

log "Deploying ${VM_COUNT} minimal test VMs in namespace ${TARGET_NAMESPACE}"
log "Using VM containerDisk image: ${VM_CONTAINERDISK_IMAGE}"
for i in $(seq 1 "$VM_COUNT"); do
  VM_NAME="testvm-${i}"
  cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: ${VM_NAME}
  namespace: ${TARGET_NAMESPACE}
spec:
  runStrategy: Always
  template:
    metadata:
      labels:
        kubevirt.io/domain: ${VM_NAME}
    spec:
      domain:
        resources:
          requests:
            memory: 128Mi
        devices:
          disks:
          - name: containerdisk
            disk:
              bus: virtio
          - name: cloudinitdisk
            disk:
              bus: virtio
          interfaces:
          - name: default
            masquerade: {}
      networks:
      - name: default
        pod: {}
      volumes:
      - name: containerdisk
        containerDisk:
          image: ${VM_CONTAINERDISK_IMAGE}
      - name: cloudinitdisk
        cloudInitNoCloud:
          userData: |
            #cloud-config
            password: kuber
            chpasswd: { expire: False }
EOF
done

if [[ "$WAIT_FOR_VMIS" == "true" ]]; then
  if ! [[ "$VMI_WAIT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || [[ "$VMI_WAIT_TIMEOUT_SECONDS" -lt 1 ]]; then
    log "ERROR: VMI_WAIT_TIMEOUT_SECONDS must be a positive integer (got: $VMI_WAIT_TIMEOUT_SECONDS)"
    exit 64
  fi
  if ! [[ "$VMI_WAIT_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || [[ "$VMI_WAIT_INTERVAL_SECONDS" -lt 1 ]]; then
    log "ERROR: VMI_WAIT_INTERVAL_SECONDS must be a positive integer (got: $VMI_WAIT_INTERVAL_SECONDS)"
    exit 64
  fi

  log "Waiting up to ${VMI_WAIT_TIMEOUT_SECONDS}s for VMIs to report Running (best effort)"
  start_ts="$(date +%s)"
  while true; do
    running="$(kubectl --context "$KUBE_CONTEXT" -n "$TARGET_NAMESPACE" get vmis -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}' 2>/dev/null | grep -c '^Running$' || true)"
    if [[ "$running" -ge "$VM_COUNT" ]]; then
      log "All VMIs are Running (${running}/${VM_COUNT})"
      break
    fi

    now_ts="$(date +%s)"
    elapsed="$((now_ts - start_ts))"
    if [[ "$elapsed" -ge "$VMI_WAIT_TIMEOUT_SECONDS" ]]; then
      log "WARN: timed out waiting for VMIs (${running}/${VM_COUNT} Running); continuing with scan"
      kubectl --context "$KUBE_CONTEXT" -n "$TARGET_NAMESPACE" get vmis || true
      break
    fi

    sleep "$VMI_WAIT_INTERVAL_SECONDS"
  done
else
  log "Skipping VMI readiness wait (WAIT_FOR_VMIS=${WAIT_FOR_VMIS})"
fi

if [[ "$MODE" == "pass" ]]; then
  log "Applying pass profile controls (PSA + NetworkPolicy + ResourceQuota + LimitRange + PDB)"
  kubectl --context "$KUBE_CONTEXT" label namespace "$TARGET_NAMESPACE" \
    pod-security.kubernetes.io/enforce=baseline \
    pod-security.kubernetes.io/audit=baseline \
    pod-security.kubernetes.io/warn=baseline \
    --overwrite

  cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: ${TARGET_NAMESPACE}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: ${TARGET_NAMESPACE}
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 4Gi
    limits.cpu: "4"
    limits.memory: 8Gi
---
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: ${TARGET_NAMESPACE}
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: 512Mi
    defaultRequest:
      cpu: "100m"
      memory: 128Mi
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: vm-workload-pdb
  namespace: ${TARGET_NAMESPACE}
spec:
  minAvailable: 1
  selector:
    matchLabels:
      kubevirt.io/domain: testvm-1
EOF
else
  log "Fail profile: leaving namespace without PSA labels, NetworkPolicy, ResourceQuota, LimitRange, or PDB"
fi

log "Building scanner"
(
  cd "$ROOT_DIR"
  make build
)

log "Running scan (${SCAN_ENGINE}) against context ${KUBE_CONTEXT}"
set +e
(
  cd "$ROOT_DIR"
  ./bin/kvirtbp scan \
    --engine "$SCAN_ENGINE" \
    --output table \
    --context "$KUBE_CONTEXT" \
    --namespace "$TARGET_NAMESPACE"
)
SCAN_EXIT=$?
set -e

if [[ "$MODE" == "pass" ]]; then
  if [[ $SCAN_EXIT -ne 0 ]]; then
    log "ERROR: pass profile expected exit code 0, got $SCAN_EXIT"
    exit 1
  fi
  log "PASS profile validated successfully"
else
  if [[ $SCAN_EXIT -eq 0 ]]; then
    log "ERROR: fail profile expected non-zero exit code, got 0"
    exit 1
  fi
  log "FAIL profile validated successfully (scan exit code: $SCAN_EXIT)"
fi
