#!/usr/bin/env bash
set -euo pipefail

# e2e_kind_px_kubevirt.sh — stand up a kind cluster with:
#   • Portworx Enterprise (30-day trial activates automatically on first boot;
#     no extra license file is needed for initial testing)
#   • KubeVirt (software CPU emulation enabled for kind)
#   • Two test VMs each backed by a dedicated Portworx ReadWriteMany volume
#
# The resulting cluster can be used to run the portworx-kubevirt collector:
#
#   kvirtbp collect \
#     --bundle ./examples/collectors/portworx-kubevirt \
#     --namespace kvirtbp-collectors \
#     --output px-data.json
#
#   kvirtbp scan --engine rego \
#     --policy-bundle ./examples/collectors/portworx-kubevirt \
#     --collector-data px-data.json
#
# Prerequisites
# -------------
#   kind      https://kind.sigs.k8s.io/
#   kubectl   https://kubernetes.io/docs/tasks/tools/
#   docker    https://docs.docker.com/get-docker/
#
# ARCHITECTURE REQUIREMENT — x86_64 (amd64) only
# -----------------------------------------------
# Portworx Enterprise ships x86_64 binaries only. The px-runc OCI runtime that
# oci-monitor installs on each storage node is an x86_64 ELF executable.
# Running under Rosetta 2 on Apple Silicon (M1/M2/M3/M4) fails at the nsenter
# step with: "rosetta error: failed to open elf at /lib64/ld-linux-x86-64.so.2"
# There is no workaround — this script must run on an x86_64 Linux host or an
# x86_64 VM (e.g. a cloud instance or a Linux VM with nested virtualisation).
#
# Tunable environment variables (all have defaults)
# -------------------------------------------------
#   CLUSTER_NAME            kind cluster name           (kvirtbp-px-kubevirt)
#   KIND_CONFIG             path to kind cluster YAML   (scripts/kind/px-kubevirt.yaml)
#   PX_VERSION              Portworx version            (3.1.3)
#   PX_NAMESPACE            namespace for Portworx      (kube-system)
#   PX_TIMEOUT              readiness poll deadline     (30m)
#   KUBEVIRT_VERSION        KubeVirt release tag        (v1.2.2)
#   KUBEVIRT_TIMEOUT        KubeVirt readiness deadline (20m)
#   RECREATE_CLUSTER        delete+recreate if present  (true)
#   DISK_SIZE_GB            loop-disk size per worker   (20)
#   VM_NAMESPACE            namespace for test VMs      (kvirtbp-px-vms)
#   UNTAINT_CONTROL_PLANE   remove control-plane taint  (true)

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[kvirtbp-px-lab] missing required command: $1"
    exit 127
  fi
}

require_cmd kind
require_cmd kubectl
require_cmd docker

# ── Architecture preflight ─────────────────────────────────────────────────────
# Portworx px-runc is x86_64 only. Rosetta 2 on Apple Silicon cannot execute
# it in the nsenter/host-namespace context that oci-monitor uses. Fail fast
# with a clear message rather than spending 10+ minutes pulling images before
# hitting an opaque Rosetta ELF error.
HOST_ARCH="$(uname -m)"
if [[ "$HOST_ARCH" != "x86_64" ]]; then
  echo "[kvirtbp-px-lab] ERROR: Portworx Enterprise requires an x86_64 host."
  echo "[kvirtbp-px-lab]   Detected architecture: ${HOST_ARCH}"
  echo "[kvirtbp-px-lab]   On Apple Silicon (M-series) there is no Rosetta workaround"
  echo "[kvirtbp-px-lab]   because px-runc is executed via nsenter outside the"
  echo "[kvirtbp-px-lab]   Docker emulation context."
  echo "[kvirtbp-px-lab]   Run this script on an x86_64 Linux host or cloud VM."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-kvirtbp-px-kubevirt}"
KIND_CONFIG="${KIND_CONFIG:-$ROOT_DIR/scripts/kind/px-kubevirt.yaml}"
PX_VERSION="${PX_VERSION:-3.1.3}"
# PX_OPERATOR_TAG is the libopenstorage/operator GitHub release tag used to
# fetch CRDs.  The tag is decoupled from PX_VERSION because the operator
# release cadence differs from Portworx itself.  portworx-24.1.0 is the
# latest tag and its CRDs are compatible with the px-operator:25.x image
# that install.portworx.com serves for PX 3.x.
PX_OPERATOR_TAG="${PX_OPERATOR_TAG:-portworx-24.1.0}"
PX_NAMESPACE="${PX_NAMESPACE:-kube-system}"
PX_TIMEOUT="${PX_TIMEOUT:-30m}"
KUBEVIRT_VERSION="${KUBEVIRT_VERSION:-v1.2.2}"
KUBEVIRT_TIMEOUT="${KUBEVIRT_TIMEOUT:-20m}"
RECREATE_CLUSTER="${RECREATE_CLUSTER:-true}"
DISK_SIZE_GB="${DISK_SIZE_GB:-20}"
VM_NAMESPACE="${VM_NAMESPACE:-kvirtbp-px-vms}"
UNTAINT_CONTROL_PLANE="${UNTAINT_CONTROL_PLANE:-true}"

KUBE_CONTEXT="kind-${CLUSTER_NAME}"

log() {
  echo "[kvirtbp-px-lab] $*"
}

# deadline_seconds converts a duration string like "30m" or "20m" into seconds.
deadline_seconds() {
  local s="${1:-30m}"
  case "$s" in
    *m) echo $(( ${s%m} * 60 )) ;;
    *s) echo "${s%s}" ;;
    *)  echo "$s" ;;
  esac
}

# ── 1. Kind cluster ────────────────────────────────────────────────────────────

if [[ "$RECREATE_CLUSTER" == "true" ]]; then
  log "Deleting existing kind cluster (if present): $CLUSTER_NAME"
  kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
fi

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  log "Creating kind cluster: $CLUSTER_NAME"
  kind create cluster --name "$CLUSTER_NAME" --config "$KIND_CONFIG" --wait 120s
else
  log "Reusing existing cluster: $CLUSTER_NAME"
fi

# ── 2. Control-plane taint removal ────────────────────────────────────────────

if [[ "$UNTAINT_CONTROL_PLANE" == "true" ]]; then
  log "Removing control-plane taints to allow scheduling"
  cp_nodes="$(kubectl --context "$KUBE_CONTEXT" get nodes \
    -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
  if [[ -n "$cp_nodes" ]]; then
    while IFS= read -r node; do
      [[ -z "$node" ]] && continue
      kubectl --context "$KUBE_CONTEXT" taint node "$node" \
        node-role.kubernetes.io/control-plane- --overwrite >/dev/null 2>&1 || true
      kubectl --context "$KUBE_CONTEXT" taint node "$node" \
        node-role.kubernetes.io/master- --overwrite >/dev/null 2>&1 || true
    done <<< "$cp_nodes"
  fi
fi

# ── 3. Privileged pod security for Portworx + KubeVirt namespaces ─────────────
# Portworx DaemonSet pods and KubeVirt virt-handler/virt-launcher require
# privileged SecurityContext. Label their namespaces accordingly before
# installing either operator so that the admission controller does not reject
# the pods.

for ns in "$PX_NAMESPACE" kubevirt; do
  log "Labelling namespace $ns with privileged pod-security enforcement"
  kubectl --context "$KUBE_CONTEXT" label namespace "$ns" \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/warn=privileged \
    --overwrite 2>/dev/null || \
  (
    # Namespace may not exist yet (e.g. kubevirt); create it first
    kubectl --context "$KUBE_CONTEXT" create namespace "$ns" \
      --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -
    kubectl --context "$KUBE_CONTEXT" label namespace "$ns" \
      pod-security.kubernetes.io/enforce=privileged \
      pod-security.kubernetes.io/warn=privileged \
      --overwrite
  )
done

# ── 4. Loop-disk creation on worker nodes ─────────────────────────────────────
# Portworx needs at least one raw, unformatted block device per storage node.
# Inside the Docker containers that serve as kind worker nodes we create a
# sparse file backed loop device.  Each worker gets a dedicated ${DISK_SIZE_GB}G
# file at /var/lib/px-disk.img associated with the next available loop device.
#
# Notes:
#   • modprobe loop will silently no-op when loop is compiled in or already
#     loaded (typical on Docker Desktop / Linux).
#   • mknod creates /dev/loop* entries if the container's /dev does not
#     already have them.
#   • losetup -f --show returns the chosen loop device path.

log "Obtaining worker node list from kind"
mapfile -t WORKER_NODES < <(kind get nodes --name "$CLUSTER_NAME" 2>/dev/null | grep -v 'control-plane')

if [[ "${#WORKER_NODES[@]}" -eq 0 ]]; then
  log "ERROR: no worker nodes found in cluster $CLUSTER_NAME"
  exit 1
fi

for node in "${WORKER_NODES[@]}"; do
  log "Preparing worker node: $node (loop disk + cgroup/sysfs fix)"
  docker exec "$node" bash -c "
    set -euo pipefail

    # ── Loop disk ──────────────────────────────────────────────────────────────
    modprobe loop 2>/dev/null || true
    for i in \$(seq 0 15); do
      [[ -e /dev/loop\$i ]] || mknod -m 660 /dev/loop\$i b 7 \$i 2>/dev/null || true
    done
    if [[ ! -f /var/lib/px-disk.img ]]; then
      fallocate -l ${DISK_SIZE_GB}G /var/lib/px-disk.img
      LOOP_DEV=\$(losetup -f --show /var/lib/px-disk.img)
      echo \"Attached /var/lib/px-disk.img → \${LOOP_DEV} on node ${node}\"
    else
      echo 'Loop disk already exists on ${node}; skipping'
    fi

    # ── cgroup / sysfs fix for Portworx oci-monitor ────────────────────────────
    # oci-monitor verifies a service controller via two checks:
    #   1. 'systemctl show-environment' (executes in PID 1 mount ns via nsenter)
    #   2. Mounts check: /proc/1/mounts must show a cgroup entry named 'systemd'
    #
    # On kind (Docker containers) running on macOS (Docker Desktop + cgroup v2):
    #   • /sys is mounted read-only by the container runtime → mounts check fails
    #   • The cgroup v1 'systemd' subhierarchy does not exist → mounts check fails
    #   • systemd may be PID 1 in the kind node but its D-Bus socket is not
    #     reachable from inside the portworx container → systemctl probe returns
    #     non-zero → oci-monitor sees 'No suitable service controller'
    #
    # Fixes applied:
    #   a) Remount /sys and /sys/fs/cgroup read-write (kind nodes have CAP_SYS_ADMIN)
    #   b) Mount the cgroup v1 systemd subhierarchy so the mounts check passes
    #   c) Create all runtime dirs oci-monitor expects to exist
    #   d) Replace systemctl with a shim that returns a valid 'show-environment'
    #      response — oci-monitor parses the output, so an empty response is not
    #      sufficient; it must look like real systemd environment output

    echo 'Remounting /sys and /sys/fs/cgroup read-write'
    mount -o remount,rw /sys             2>/dev/null || true
    mount -o remount,rw /sys/fs/cgroup   2>/dev/null || true

    echo 'Ensuring cgroup v1 systemd subhierarchy'
    mkdir -p /sys/fs/cgroup/systemd
    if ! mountpoint -q /sys/fs/cgroup/systemd 2>/dev/null; then
      mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd 2>/dev/null || \
        mount --bind /sys/fs/cgroup /sys/fs/cgroup/systemd 2>/dev/null || true
    fi

    echo 'Creating systemd runtime directories'
    mkdir -p /run/systemd/system /etc/systemd/system /usr/lib/systemd/system || true
    mkdir -p /run/systemd/private 2>/dev/null || true

    echo 'Installing systemctl shim for oci-monitor service controller probe'
    cat > /usr/local/bin/systemctl << 'SHIM'
#!/bin/sh
# kind systemctl shim for Portworx oci-monitor.
# oci-monitor runs: nsenter -t 1 -m -- /bin/sh -c 'systemctl show-environment'
# It parses the KEY=VALUE output; an empty or missing response fails the check.
case \"\$1\" in
  show-environment)
    echo 'LANG=C.UTF-8'
    echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    exit 0 ;;
  start|stop|restart|enable|disable|daemon-reload|reset-failed)
    exit 0 ;;
  is-active|is-enabled|is-failed)
    echo 'active'; exit 0 ;;
  show|cat|status|list-units|list-unit-files)
    exit 0 ;;
  *)
    exit 0 ;;
esac
SHIM
    chmod +x /usr/local/bin/systemctl
    # Replace /usr/bin/systemctl so nsenter'd processes find the shim regardless
    # of which path is used to invoke it
    ln -sf /usr/local/bin/systemctl /usr/bin/systemctl
    ln -sf /usr/local/bin/systemctl /bin/systemctl 2>/dev/null || true

    echo 'Worker node prep complete'
  "
done

# ── 5. Portworx CRDs + operator ───────────────────────────────────────────────
# install.portworx.com?comp=pxoperator only installs the SA/ClusterRole/
# ClusterRoleBinding/Deployment — it does NOT include the StorageCluster and
# StorageNode CRDs.  Those must be applied first from the operator GitHub repo.
PX_CRD_BASE="https://raw.githubusercontent.com/libopenstorage/operator/${PX_OPERATOR_TAG}/deploy/crds"

log "Installing Portworx CRDs from operator tag ${PX_OPERATOR_TAG}"
kubectl --context "$KUBE_CONTEXT" apply -f "${PX_CRD_BASE}/core_v1_storagecluster_crd.yaml"
kubectl --context "$KUBE_CONTEXT" apply -f "${PX_CRD_BASE}/core_v1_storagenode_crd.yaml"

log "Installing Portworx operator for PX ${PX_VERSION}"
kubectl --context "$KUBE_CONTEXT" apply -f "https://install.portworx.com/${PX_VERSION}?comp=pxoperator"

log "Waiting for Portworx operator deployment to be ready"
kubectl --context "$KUBE_CONTEXT" -n "$PX_NAMESPACE" \
  rollout status deployment/portworx-operator --timeout=5m

# ── 6. StorageCluster ─────────────────────────────────────────────────────────
# Configuration choices for kind:
#   kvdb.internal=true  — no external etcd required
#   storage.useAll=true — auto-discover the loop devices created above
#   stork.enabled=false — skip Stork scheduler extender to reduce resource usage
#   csi.enabled=true    — required for dynamic PVC provisioning

log "Applying Portworx StorageCluster CR (portworx image: ${PX_VERSION})"
cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: core.libopenstorage.org/v1
kind: StorageCluster
metadata:
  name: portworx
  namespace: ${PX_NAMESPACE}
  annotations:
    portworx.io/misc-args: "--keep-px-up"
spec:
  image: portworx/oci-monitor:${PX_VERSION}
  imagePullPolicy: Always
  kvdb:
    internal: true
  storage:
    useAll: true
    journalDevice: auto
  network:
    dataInterface: eth0
    mgmtInterface: eth0
  secretsProvider: k8s
  stork:
    enabled: false
  autopilot:
    enabled: false
  csi:
    enabled: true
  monitoring:
    prometheus:
      enabled: false
      exportMetrics: false
  userInterface:
    enabled: false
EOF

# ── 7. Wait for Portworx to come online ───────────────────────────────────────

log "Waiting for Portworx StorageCluster to reach Online status (timeout: ${PX_TIMEOUT})"
px_deadline="$(deadline_seconds "$PX_TIMEOUT")"
px_start="$(date +%s)"
px_poll_interval=30

while true; do
  phase="$(kubectl --context "$KUBE_CONTEXT" -n "$PX_NAMESPACE" \
    get storagecluster portworx \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo '')"
  if [[ "$phase" == "Online" ]]; then
    log "Portworx StorageCluster is Online"
    break
  fi

  elapsed=$(( $(date +%s) - px_start ))
  if [[ "$elapsed" -ge "$px_deadline" ]]; then
    log "ERROR: Portworx did not reach Online within ${PX_TIMEOUT}; dumping diagnostics"
    kubectl --context "$KUBE_CONTEXT" -n "$PX_NAMESPACE" get storagecluster portworx -o yaml || true
    kubectl --context "$KUBE_CONTEXT" -n "$PX_NAMESPACE" get pods -l name=portworx -o wide || true
    kubectl --context "$KUBE_CONTEXT" -n "$PX_NAMESPACE" get storagenodes -o wide || true
    exit 1
  fi

  log "  StorageCluster phase=${phase:-Pending} (${elapsed}s elapsed); retrying in ${px_poll_interval}s"
  sleep "$px_poll_interval"
done

# ── 8. KubeVirt operator ──────────────────────────────────────────────────────

log "Installing KubeVirt operator: ${KUBEVIRT_VERSION}"
kubectl --context "$KUBE_CONTEXT" apply -f \
  "https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-operator.yaml"

log "Creating KubeVirt custom resource (software CPU emulation enabled for kind)"
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

log "Waiting for KubeVirt to become available (timeout: ${KUBEVIRT_TIMEOUT})"
if ! kubectl --context "$KUBE_CONTEXT" wait \
    -n kubevirt kubevirt/kubevirt \
    --for=condition=Available \
    --timeout="$KUBEVIRT_TIMEOUT"; then
  log "ERROR: KubeVirt did not become Available in time; dumping diagnostics"
  kubectl --context "$KUBE_CONTEXT" -n kubevirt get pods -o wide || true
  kubectl --context "$KUBE_CONTEXT" -n kubevirt get kubevirt kubevirt -o yaml || true
  exit 1
fi

# ── 9. VM namespace + Portworx StorageClass ───────────────────────────────────

log "Preparing VM namespace: ${VM_NAMESPACE}"
kubectl --context "$KUBE_CONTEXT" create namespace "$VM_NAMESPACE" \
  --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -

kubectl --context "$KUBE_CONTEXT" label namespace "$VM_NAMESPACE" \
  pod-security.kubernetes.io/enforce=privileged \
  --overwrite

log "Creating Portworx RWX StorageClass: px-rwx-kubevirt"
cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: px-rwx-kubevirt
  annotations:
    storageclass.kubernetes.io/is-default-virt-storage-class: "true"
provisioner: pxd.portworx.com
parameters:
  repl: "2"
  sharedv4: "true"
  nodiscard: "true"
  io_profile: "db_remote"
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
EOF

# ── 10. PersistentVolumeClaims ────────────────────────────────────────────────
# One RWX PVC per VM.  Both carry the portworx.io/app=kubevirt label so the
# portworx-kubevirt collector query matches them.

for i in 1 2; do
  log "Creating PVC: px-rwx-vm${i}-data"
  cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: px-rwx-vm${i}-data
  namespace: ${VM_NAMESPACE}
  labels:
    portworx.io/app: kubevirt
spec:
  accessModes:
    - ReadWriteMany
  volumeMode: Block
  resources:
    requests:
      storage: 1Gi
  storageClassName: px-rwx-kubevirt
EOF
done

# ── 11. VirtualMachines ───────────────────────────────────────────────────────
# Each VM boots from a containerDisk (ephemeral cirros OS) and attaches the
# corresponding Portworx RWX block PVC as a secondary virtio disk.
# The portworx.io/app=kubevirt label flows through from PVC to VM metadata so
# the collector and scan results are associated correctly.

VM_IMAGE="${VM_IMAGE:-quay.io/kubevirt/cirros-container-disk-demo:latest}"

for i in 1 2; do
  log "Creating VirtualMachine: kvirtbp-vm-${i}"
  cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: kvirtbp-vm-${i}
  namespace: ${VM_NAMESPACE}
  labels:
    portworx.io/app: kubevirt
spec:
  runStrategy: Always
  template:
    metadata:
      labels:
        kubevirt.io/domain: kvirtbp-vm-${i}
        portworx.io/app: kubevirt
    spec:
      domain:
        resources:
          requests:
            memory: 256Mi
        devices:
          disks:
            - name: rootdisk
              disk:
                bus: virtio
            - name: datadisk
              disk:
                bus: virtio
          interfaces:
            - name: default
              masquerade: {}
      networks:
        - name: default
          pod: {}
      volumes:
        - name: rootdisk
          containerDisk:
            image: ${VM_IMAGE}
        - name: datadisk
          persistentVolumeClaim:
            claimName: px-rwx-vm${i}-data
EOF
done

# ── 12. Wait for VMIs ─────────────────────────────────────────────────────────

VMI_WAIT_TIMEOUT_SECONDS="${VMI_WAIT_TIMEOUT_SECONDS:-300}"
VMI_WAIT_INTERVAL_SECONDS="${VMI_WAIT_INTERVAL_SECONDS:-10}"
VM_COUNT=2

log "Waiting up to ${VMI_WAIT_TIMEOUT_SECONDS}s for ${VM_COUNT} VMIs to reach Running"
vmi_start="$(date +%s)"
while true; do
  running="$(kubectl --context "$KUBE_CONTEXT" -n "$VM_NAMESPACE" \
    get vmis -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}' 2>/dev/null \
    | grep -c '^Running$' || true)"

  if [[ "$running" -ge "$VM_COUNT" ]]; then
    log "All VMIs are Running (${running}/${VM_COUNT})"
    break
  fi

  elapsed=$(( $(date +%s) - vmi_start ))
  if [[ "$elapsed" -ge "$VMI_WAIT_TIMEOUT_SECONDS" ]]; then
    log "WARN: timed out waiting for VMIs (${running}/${VM_COUNT} Running); continuing"
    kubectl --context "$KUBE_CONTEXT" -n "$VM_NAMESPACE" get vmis -o wide || true
    break
  fi

  log "  VMIs Running: ${running}/${VM_COUNT} (${elapsed}s elapsed); retrying in ${VMI_WAIT_INTERVAL_SECONDS}s"
  sleep "$VMI_WAIT_INTERVAL_SECONDS"
done

# ── Summary ───────────────────────────────────────────────────────────────────

log "Lab environment ready"
log ""
log "  Cluster context : ${KUBE_CONTEXT}"
log "  PX namespace    : ${PX_NAMESPACE}"
log "  VM namespace    : ${VM_NAMESPACE}"
log "  StorageClass    : px-rwx-kubevirt (pxd.portworx.com, sharedv4, repl=2)"
log ""
log "  VirtualMachines:"
kubectl --context "$KUBE_CONTEXT" -n "$VM_NAMESPACE" get vms -o wide 2>/dev/null || true
log ""
log "  PersistentVolumeClaims:"
kubectl --context "$KUBE_CONTEXT" -n "$VM_NAMESPACE" get pvc -o wide 2>/dev/null || true
log ""
log "  Portworx nodes:"
kubectl --context "$KUBE_CONTEXT" -n "$PX_NAMESPACE" get storagenodes -o wide 2>/dev/null || true
log ""
log "To run the portworx-kubevirt collector against this cluster:"
log "  export KUBECONFIG=\$(kind get kubeconfig-path --name ${CLUSTER_NAME} 2>/dev/null || echo \$HOME/.kube/config)"
log "  kvirtbp collect \\"
log "    --bundle ./examples/collectors/portworx-kubevirt \\"
log "    --namespace kvirtbp-collectors \\"
log "    --context ${KUBE_CONTEXT} \\"
log "    --output px-data.json"
log ""
log "To tear down: make lab-px-kubevirt-teardown"
