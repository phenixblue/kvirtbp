#!/usr/bin/env bash
# e2e_kind_custom_bundle.sh — end-to-end test for a custom Rego policy bundle
# that fetches a non-default k8s resource type (v1/configmaps).
#
# Usage: $0 <pass|fail>
#   pass  — creates the required ConfigMap; expects scan to exit 0
#   fail  — omits the ConfigMap;             expects scan to exit non-zero
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
CLUSTER_NAME="${CLUSTER_NAME:-kvirtbp-custom-bundle}"
RECREATE_CLUSTER="${RECREATE_CLUSTER:-true}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
TARGET_NAMESPACE="${TARGET_NAMESPACE:-kvirtbp-custom-ns}"
BUNDLE_PATH="./test/fixtures/custom-bundle"

log() {
  echo "[kvirtbp-e2e-custom-bundle] $*"
}

# --------------------------------------------------------------------------
# Cluster lifecycle
# --------------------------------------------------------------------------

if [[ "$RECREATE_CLUSTER" == "true" ]]; then
  log "Deleting existing kind cluster (if present): $CLUSTER_NAME"
  kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
fi

if ! kind get clusters | grep -qx "$CLUSTER_NAME"; then
  log "Creating single-node kind cluster: $CLUSTER_NAME"
  kind create cluster --name "$CLUSTER_NAME" --wait 120s
else
  log "Reusing existing cluster: $CLUSTER_NAME"
fi

# --------------------------------------------------------------------------
# Namespace + test fixture
# --------------------------------------------------------------------------

log "Preparing namespace: $TARGET_NAMESPACE"
kubectl --context "$KUBE_CONTEXT" create namespace "$TARGET_NAMESPACE" \
  --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -

if [[ "$MODE" == "pass" ]]; then
  log "Pass mode: creating ConfigMap 'kvirtbp-e2e-marker' in $TARGET_NAMESPACE"
  kubectl --context "$KUBE_CONTEXT" create configmap kvirtbp-e2e-marker \
    --namespace "$TARGET_NAMESPACE" \
    --from-literal=marker=kvirtbp-e2e \
    --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT" apply -f -
else
  log "Fail mode: ensuring ConfigMap 'kvirtbp-e2e-marker' is absent"
  kubectl --context "$KUBE_CONTEXT" delete configmap kvirtbp-e2e-marker \
    --namespace "$TARGET_NAMESPACE" --ignore-not-found
fi

# --------------------------------------------------------------------------
# Build + scan
# --------------------------------------------------------------------------

log "Building scanner"
(
  cd "$ROOT_DIR"
  make build
)

log "Running scan (rego + custom bundle) against context ${KUBE_CONTEXT}"
set +e
(
  cd "$ROOT_DIR"
  ./bin/kvirtbp scan \
    --engine rego \
    --bundle "$BUNDLE_PATH" \
    --output table \
    --context "$KUBE_CONTEXT" \
    --namespace "$TARGET_NAMESPACE"
)
SCAN_EXIT=$?
set -e

# --------------------------------------------------------------------------
# Validate result
# --------------------------------------------------------------------------

if [[ "$MODE" == "pass" ]]; then
  if [[ $SCAN_EXIT -ne 0 ]]; then
    log "ERROR: pass mode expected exit code 0, got $SCAN_EXIT"
    exit 1
  fi
  log "PASS mode validated successfully (ConfigMap present → scan passed)"
else
  if [[ $SCAN_EXIT -eq 0 ]]; then
    log "ERROR: fail mode expected non-zero exit code, got 0"
    exit 1
  fi
  log "FAIL mode validated successfully (ConfigMap absent → scan exit code: $SCAN_EXIT)"
fi
