# ============================================================================
# portworx-kubevirt collector bundle
# ============================================================================
#
# Collector: "portworx-kubevirt" (scope: once)
#   Runs a single cluster-wide Job using python:3.12-alpine. The pod uses its
#   in-cluster service account token to query the Kubernetes API and gather
#   Portworx-specific KubeVirt configuration data.
#
#   RBAC: apply rbac.yaml before running the collector. Pass the namespace
#   to kvirtbp collect via --namespace kvirtbp-collectors.
#
#   Collected data shape (input.cluster.collectors["portworx-kubevirt"]["_cluster"]):
#   {
#     "storageClasses": [
#       {
#         "name":                     "px-rwx-block-kubevirt",
#         "repl":                     "3",
#         "nodiscard":                "true",
#         "io_profile":               "db_remote",
#         "sharedv4":                 "true",
#         "volumeBindingMode":        "WaitForFirstConsumer",
#         "allowVolumeExpansion":     true,
#         "isDefaultVirtStorageClass": true,
#         "isDefaultStorageClass":    false
#       }
#     ],
#     "storageProfiles": [
#       {
#         "name": "px-rwx-block-kubevirt",
#         "claimPropertySets": [
#           { "accessModes": ["ReadWriteMany"], "volumeMode": "Block" }
#         ]
#       }
#     ],
#     "storageClusters": [
#       { "name": "portworx", "namespace": "portworx", "version": "3.3.0", "operatorVersion": "25.2.1" }
#     ],
#     "pvcs": [
#       {
#         "name": "vm-root-disk", "namespace": "vms",
#         "storageClassName": "px-rwx-block-kubevirt",
#         "accessModes": ["ReadWriteMany"], "volumeMode": "Block"
#       }
#     ]
#   }
#
# Checks:
#   prod-px-kubevirt-collector-present  — gates all other checks; warns when absent
#   prod-px-kubevirt-storageclasses-exist — at least one PX StorageClass found
#   prod-px-kubevirt-replication        — all PX SCs have repl >= 3
#   prod-px-kubevirt-binding-mode       — all PX SCs use WaitForFirstConsumer
#   prod-px-kubevirt-volume-expansion   — all PX SCs have allowVolumeExpansion=true
#   prod-px-kubevirt-nodiscard          — all RWX PX SCs have nodiscard=true
#   prod-px-kubevirt-storageprofile-block — all PX StorageProfiles include Block+RWX
#   prod-px-kubevirt-pvc-rwx            — KubeVirt PVCs use ReadWriteMany
#   prod-px-kubevirt-pvc-block          — KubeVirt PVCs use volumeMode Block
#   prod-px-kubevirt-px-version         — Portworx Enterprise >= 3.3.0
#   prod-px-kubevirt-operator-version   — Portworx Operator >= 25.2.1
#   prod-px-kubevirt-stork-version      — Portworx Stork >= 25.2.0
#   prod-px-kubevirt-cluster-status     — Portworx cluster operational (STATUS_OK)
#   prod-px-kubevirt-license-expiry     — license expires in > 30 days
#   prod-px-kubevirt-global-pool-free   — global storage pool >= 20% free
#   prod-px-kubevirt-local-pool-free    — each local storage pool >= 20% free
#   prod-px-kubevirt-storev2-metadata   — storev2 nodes have metadata device >= 64 GiB
#   prod-px-kubevirt-node-health        — all storage nodes online with storage status Up
#
# References:
#   https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/
#       manage-kubevirt-vms-rwx-block/openshift
#
# Usage:
#   # Ensure RBAC is applied and SA is bound:
#   kubectl apply -f examples/collectors/portworx-kubevirt/rbac.yaml
#
#   # Step 1: collect
#   kvirtbp collect \
#       --bundle ./examples/collectors/portworx-kubevirt \
#       --namespace kvirtbp-collectors \
#       --output portworx-kubevirt-data.json
#
#   # Step 2: scan
#   kvirtbp scan --engine rego \
#       --policy-bundle ./examples/collectors/portworx-kubevirt \
#       --collector-data portworx-kubevirt-data.json
# ============================================================================

package kvirtbp

import rego.v1

# ---------------------------------------------------------------------------
# Short-circuit: no cluster snapshot present (unit tests / dry-run).
# ---------------------------------------------------------------------------

findings := [] if { not input.cluster }
findings := cluster_findings if { input.cluster }

# ---------------------------------------------------------------------------
# Safe data accessor.
# ---------------------------------------------------------------------------

# For scope:once collectors the framework stores output under the "_cluster"
# sentinel key inside the named collector entry.
px_data := object.get(
	object.get(
		object.get(input.cluster, "collectors", {}),
		"portworx-kubevirt",
		{},
	),
	"_cluster",
	{},
)

collector_present if {
	count(object.keys(px_data)) > 0
	not px_data._error
}

px_storage_classes := object.get(px_data, "storageClasses", [])
px_storage_profiles := object.get(px_data, "storageProfiles", [])
px_storage_clusters := object.get(px_data, "storageClusters", [])
px_pvcs := object.get(px_data, "pvcs", [])

# ---------------------------------------------------------------------------
# Check 1: collector data is present
# ---------------------------------------------------------------------------

collector_findings := [{
	"checkId":    "prod-px-kubevirt-collector-present",
	"title":      "Portworx KubeVirt Collector Data Present",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.collector.present",
	"message":    "portworx-kubevirt collector data present",
}] if {
	collector_present
}

collector_findings := [{
	"checkId":     "prod-px-kubevirt-collector-present",
	"title":       "Portworx KubeVirt Collector Data Present",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.collector.absent",
	"message":     "portworx-kubevirt collector data is absent; run 'kvirtbp collect' before scanning",
	"remediation": "kubectl apply -f examples/collectors/portworx-kubevirt/rbac.yaml && kvirtbp collect --bundle ./examples/collectors/portworx-kubevirt --namespace kvirtbp-collectors --output portworx-kubevirt-data.json",
}] if {
	not collector_present
}

# ---------------------------------------------------------------------------
# Check 2: at least one Portworx StorageClass exists
# ---------------------------------------------------------------------------

sc_exists_findings := [{
	"checkId":    "prod-px-kubevirt-storageclasses-exist",
	"title":      "Portworx StorageClasses Present",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.storageclasses.present",
	"message":    sprintf("found %d Portworx StorageClass(es)", [count(px_storage_classes)]),
	"evidence":   {"count": sprintf("%d", [count(px_storage_classes)])},
}] if {
	collector_present
	count(px_storage_classes) > 0
}

sc_exists_findings := [{
	"checkId":     "prod-px-kubevirt-storageclasses-exist",
	"title":       "Portworx StorageClasses Present",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.storageclasses.absent",
	"message":     "no Portworx StorageClasses found (provisioner=pxd.portworx.com)",
	"remediation": "Create or enable the default Portworx KubeVirt StorageClasses. See StorageCluster spec.csi.kubeVirtStorageClasses.",
}] if {
	collector_present
	count(px_storage_classes) == 0
}

sc_exists_findings := [] if { not collector_present }

# ---------------------------------------------------------------------------
# Check 3: replication factor >= 3 on all PX StorageClasses
#
# A replication factor of 3 ensures the volume can survive two simultaneous
# node failures. For KubeVirt VMs this is critical for live migration and
# availability during node maintenance.
# ---------------------------------------------------------------------------

# StorageClasses that lack repl>=3.
sc_low_repl := {sc.name |
	some sc in px_storage_classes
	to_number(object.get(sc, "repl", "0")) < 3
}

repl_findings := [{
	"checkId":    "prod-px-kubevirt-replication",
	"title":      "Portworx StorageClass Replication Factor",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.replication.ok",
	"message":    "all Portworx StorageClasses have repl >= 3",
}] if {
	collector_present
	count(px_storage_classes) > 0
	count(sc_low_repl) == 0
}

repl_findings := [{
	"checkId":     "prod-px-kubevirt-replication",
	"title":       "Portworx StorageClass Replication Factor",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.replication.low",
	"message":     sprintf("%d StorageClass(es) have repl < 3: %v", [count(sc_low_repl), sc_low_repl]),
	"evidence":    {"violating": sprintf("%v", [sc_low_repl])},
	"remediation": "Set parameters.repl=3 on Portworx StorageClasses used with KubeVirt VMs to ensure 3-way HA replication.",
}] if {
	collector_present
	count(px_storage_classes) > 0
	count(sc_low_repl) > 0
}

repl_findings := [] if {
	not collector_present
}

repl_findings := [] if {
	collector_present
	count(px_storage_classes) == 0
}

# ---------------------------------------------------------------------------
# Check 4: volumeBindingMode = WaitForFirstConsumer
#
# WaitForFirstConsumer delays PVC binding until a Pod is scheduled, enabling
# Portworx to intelligently co-locate volume replicas with the VM. Without
# this, replicas may land on different nodes than the VM, reducing I/O
# performance and defeating hyperconvergence.
# ---------------------------------------------------------------------------

sc_wrong_binding := {sc.name |
	some sc in px_storage_classes
	object.get(sc, "volumeBindingMode", "Immediate") != "WaitForFirstConsumer"
}

binding_findings := [{
	"checkId":    "prod-px-kubevirt-binding-mode",
	"title":      "Portworx StorageClass VolumeBindingMode",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.binding_mode.ok",
	"message":    "all Portworx StorageClasses use WaitForFirstConsumer",
}] if {
	collector_present
	count(px_storage_classes) > 0
	count(sc_wrong_binding) == 0
}

binding_findings := [{
	"checkId":     "prod-px-kubevirt-binding-mode",
	"title":       "Portworx StorageClass VolumeBindingMode",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.binding_mode.immediate",
	"message":     sprintf("%d StorageClass(es) do not use WaitForFirstConsumer: %v", [count(sc_wrong_binding), sc_wrong_binding]),
	"evidence":    {"violating": sprintf("%v", [sc_wrong_binding])},
	"remediation": "Set volumeBindingMode: WaitForFirstConsumer on Portworx StorageClasses. This enables Portworx to co-locate VM volumes with the scheduling node for hyperconvergence.",
}] if {
	collector_present
	count(px_storage_classes) > 0
	count(sc_wrong_binding) > 0
}

binding_findings := [] if {
	not collector_present
}

binding_findings := [] if {
	collector_present
	count(px_storage_classes) == 0
}

# ---------------------------------------------------------------------------
# Check 5: allowVolumeExpansion = true
#
# VMs require dynamic disk growth. Without this flag, PVC resize operations
# fail at the Kubernetes level before reaching Portworx.
# ---------------------------------------------------------------------------

sc_no_expansion := {sc.name |
	some sc in px_storage_classes
	object.get(sc, "allowVolumeExpansion", false) == false
}

expansion_findings := [{
	"checkId":    "prod-px-kubevirt-volume-expansion",
	"title":      "Portworx StorageClass Volume Expansion",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.volume_expansion.ok",
	"message":    "all Portworx StorageClasses have allowVolumeExpansion=true",
}] if {
	collector_present
	count(px_storage_classes) > 0
	count(sc_no_expansion) == 0
}

expansion_findings := [{
	"checkId":     "prod-px-kubevirt-volume-expansion",
	"title":       "Portworx StorageClass Volume Expansion",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.volume_expansion.disabled",
	"message":     sprintf("%d StorageClass(es) do not allow volume expansion: %v", [count(sc_no_expansion), sc_no_expansion]),
	"evidence":    {"violating": sprintf("%v", [sc_no_expansion])},
	"remediation": "Set allowVolumeExpansion: true on Portworx StorageClasses to enable online PVC resize for KubeVirt VMs.",
}] if {
	collector_present
	count(px_storage_classes) > 0
	count(sc_no_expansion) > 0
}

expansion_findings := [] if {
	not collector_present
}

expansion_findings := [] if {
	collector_present
	count(px_storage_classes) == 0
}

# ---------------------------------------------------------------------------
# Check 6: nodiscard=true on RWX/sharedv4 StorageClasses
#
# Portworx RWX block volumes (sharedv4=true) have a known issue with
# discard/TRIM operations on OpenShift Virtualization <= 4.18.4 that can
# cause data corruption or performance degradation. Setting nodiscard=true
# disables discard pass-through on the volume until the OS bug is resolved.
# ---------------------------------------------------------------------------

# Only applies to sharedv4 (RWX block) StorageClasses.
sc_rwx_missing_nodiscard := {sc.name |
	some sc in px_storage_classes
	object.get(sc, "sharedv4", "false") == "true"
	object.get(sc, "nodiscard", "false") != "true"
}

nodiscard_findings := [{
	"checkId":    "prod-px-kubevirt-nodiscard",
	"title":      "Portworx RWX StorageClass nodiscard",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.nodiscard.ok",
	"message":    "all Portworx RWX StorageClasses have nodiscard=true",
}] if {
	collector_present
	rwx_scs := {sc.name | some sc in px_storage_classes; object.get(sc, "sharedv4", "false") == "true"}
	count(rwx_scs) > 0
	count(sc_rwx_missing_nodiscard) == 0
}

nodiscard_findings := [{
	"checkId":     "prod-px-kubevirt-nodiscard",
	"title":       "Portworx RWX StorageClass nodiscard",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.nodiscard.missing",
	"message":     sprintf("%d RWX StorageClass(es) missing nodiscard=true: %v", [count(sc_rwx_missing_nodiscard), sc_rwx_missing_nodiscard]),
	"evidence":    {"violating": sprintf("%v", [sc_rwx_missing_nodiscard])},
	"remediation": "Set parameters.nodiscard=true on Portworx RWX block StorageClasses (sharedv4=true). Required for OpenShift Virtualization <= 4.18.4 to prevent discard-related issues.",
}] if {
	collector_present
	count(sc_rwx_missing_nodiscard) > 0
}

nodiscard_findings := [] if {
	not collector_present
}

nodiscard_findings := [] if {
	collector_present
	rwx_scs := {sc.name | some sc in px_storage_classes; object.get(sc, "sharedv4", "false") == "true"}
	count(rwx_scs) == 0
	count(sc_rwx_missing_nodiscard) == 0
}

# ---------------------------------------------------------------------------
# Check 7: StorageProfile claimPropertySets include Block+ReadWriteMany
#
# CDI uses StorageProfiles to determine default access mode and volume mode
# when cloning or importing VM images. If the profile does not advertise
# Block+ReadWriteMany, CDI may fall back to Filesystem or ReadWriteOnce,
# breaking live migration. On OCP >= 4.17 this is set automatically for PX.
# ---------------------------------------------------------------------------

# A profile "has block+rwx" when at least one claimPropertySet satisfies both.
profile_has_block_rwx(profile) if {
	some cps in object.get(profile, "claimPropertySets", [])
	object.get(cps, "volumeMode", "") == "Block"
	"ReadWriteMany" in object.get(cps, "accessModes", [])
}

profiles_missing_block_rwx := {p.name |
	some p in px_storage_profiles
	not profile_has_block_rwx(p)
}

storageprofile_findings := [{
	"checkId":    "prod-px-kubevirt-storageprofile-block",
	"title":      "Portworx StorageProfile Block+RWX Mode",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.storageprofile.block_rwx.ok",
	"message":    sprintf("all %d Portworx StorageProfile(s) advertise Block+ReadWriteMany", [count(px_storage_profiles)]),
}] if {
	collector_present
	count(px_storage_profiles) > 0
	count(profiles_missing_block_rwx) == 0
}

storageprofile_findings := [{
	"checkId":     "prod-px-kubevirt-storageprofile-block",
	"title":       "Portworx StorageProfile Block+RWX Mode",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.storageprofile.block_rwx.missing",
	"message":     sprintf("%d StorageProfile(s) do not advertise Block+ReadWriteMany: %v", [count(profiles_missing_block_rwx), profiles_missing_block_rwx]),
	"evidence":    {"violating": sprintf("%v", [profiles_missing_block_rwx])},
	"remediation": "Patch the CDI StorageProfile to include claimPropertySets with volumeMode=Block and accessModes=[ReadWriteMany]. On OCP >= 4.17 this is set automatically for Portworx StorageClasses.",
}] if {
	collector_present
	count(profiles_missing_block_rwx) > 0
}

storageprofile_findings := [{
	"checkId":    "prod-px-kubevirt-storageprofile-block",
	"title":      "Portworx StorageProfile Block+RWX Mode",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.storageprofile.none_found",
	"message":    "no CDI StorageProfiles found for Portworx StorageClasses (CDI may not be installed)",
}] if {
	collector_present
	count(px_storage_profiles) == 0
	count(profiles_missing_block_rwx) == 0
}

storageprofile_findings := [] if { not collector_present }

# ---------------------------------------------------------------------------
# Check 8: KubeVirt PVCs use ReadWriteMany access mode
#
# RWX enables live migration of VMs between nodes without requiring a data
# copy. PVCs with ReadWriteOnce will prevent live migration.
# ---------------------------------------------------------------------------

pvcs_not_rwx := {sprintf("%s/%s", [pvc.namespace, pvc.name]) |
	some pvc in px_pvcs
	not "ReadWriteMany" in object.get(pvc, "accessModes", [])
}

pvc_rwx_findings := [{
	"checkId":    "prod-px-kubevirt-pvc-rwx",
	"title":      "KubeVirt PVC ReadWriteMany Access Mode",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.pvc.rwx.ok",
	"message":    sprintf("all %d KubeVirt PVC(s) use ReadWriteMany", [count(px_pvcs)]),
}] if {
	collector_present
	count(px_pvcs) > 0
	count(pvcs_not_rwx) == 0
}

pvc_rwx_findings := [{
	"checkId":     "prod-px-kubevirt-pvc-rwx",
	"title":       "KubeVirt PVC ReadWriteMany Access Mode",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.pvc.rwx.missing",
	"message":     sprintf("%d KubeVirt PVC(s) do not use ReadWriteMany: %v", [count(pvcs_not_rwx), pvcs_not_rwx]),
	"evidence":    {"violating": sprintf("%v", [pvcs_not_rwx])},
	"remediation": "Set accessModes: [ReadWriteMany] on PVCs used with KubeVirt VMs backed by Portworx. RWX is required for live migration.",
}] if {
	collector_present
	count(pvcs_not_rwx) > 0
}

pvc_rwx_findings := [] if {
	not collector_present
}

pvc_rwx_findings := [] if {
	collector_present
	count(px_pvcs) == 0
}

# ---------------------------------------------------------------------------
# Check 9: KubeVirt PVCs use Block volume mode
#
# Block volumeMode gives VMs direct block-device access with 4k/512e block
# size control and avoids double-buffering through a filesystem layer.
# Filesystem mode is significantly slower for VM disk I/O workloads.
# ---------------------------------------------------------------------------

pvcs_not_block := {sprintf("%s/%s", [pvc.namespace, pvc.name]) |
	some pvc in px_pvcs
	object.get(pvc, "volumeMode", "Filesystem") != "Block"
}

pvc_block_findings := [{
	"checkId":    "prod-px-kubevirt-pvc-block",
	"title":      "KubeVirt PVC Block Volume Mode",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.pvc.block.ok",
	"message":    sprintf("all %d KubeVirt PVC(s) use Block volume mode", [count(px_pvcs)]),
}] if {
	collector_present
	count(px_pvcs) > 0
	count(pvcs_not_block) == 0
}

pvc_block_findings := [{
	"checkId":     "prod-px-kubevirt-pvc-block",
	"title":       "KubeVirt PVC Block Volume Mode",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.pvc.block.missing",
	"message":     sprintf("%d KubeVirt PVC(s) do not use Block volume mode: %v", [count(pvcs_not_block), pvcs_not_block]),
	"evidence":    {"violating": sprintf("%v", [pvcs_not_block])},
	"remediation": "Set volumeMode: Block on PVCs used with KubeVirt VMs backed by Portworx RWX block volumes for best I/O performance.",
}] if {
	collector_present
	count(pvcs_not_block) > 0
}

pvc_block_findings := [] if {
	not collector_present
}

pvc_block_findings := [] if {
	collector_present
	count(px_pvcs) == 0
}

# ---------------------------------------------------------------------------
# Version comparison helper
#
# Portworx version strings are "MAJOR.MINOR.PATCH" (digits only, no leading
# "v"). Compare by zero-padding each numeric component to 6 chars so that
# string ordering matches numeric ordering (e.g. "3.10.0" > "3.9.0").
# ---------------------------------------------------------------------------

# version_gte(actual, minimum) is true when actual >= minimum.
# Pre-release suffixes (e.g. "-rc1", "-beta") are stripped from each
# component before numeric comparison so that "3.6.0-rc1" >= "3.3.0".
version_gte(actual, minimum) if {
	ap := split(actual, ".")
	mp := split(minimum, ".")
	count(ap) == 3
	count(mp) == 3
	# Strip any pre-release tag from each component (e.g. "0-rc1" -> "0").
	a0 := split(ap[0], "-")[0]
	a1 := split(ap[1], "-")[0]
	a2 := split(ap[2], "-")[0]
	m0 := split(mp[0], "-")[0]
	m1 := split(mp[1], "-")[0]
	m2 := split(mp[2], "-")[0]
	[to_number(a0), to_number(a1), to_number(a2)] >=
		[to_number(m0), to_number(m1), to_number(m2)]
}

# ---------------------------------------------------------------------------
# Check 10: Portworx Enterprise version >= 3.3.0
#
# Prerequisite from:
#   https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/
#       manage-kubevirt-vms-rwx-block/openshift#prerequisites
# ---------------------------------------------------------------------------

px_min_version := "3.3.0"

# Clusters that do not meet the minimum PX version.
clusters_px_version_fail := {sprintf("%s/%s (found: %s, required: >= %s)", [c.namespace, c.name, c.version, px_min_version]) |
	some c in px_storage_clusters
	c.version != ""
	not version_gte(c.version, px_min_version)
}

# Clusters with unparseable or missing version string.
clusters_px_version_unknown := {sprintf("%s/%s", [c.namespace, c.name]) |
	some c in px_storage_clusters
	c.version == ""
}

px_version_findings := [{
	"checkId":    "prod-px-kubevirt-px-version",
	"title":      "Portworx Enterprise Minimum Version",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.px_version.ok",
	"message":    sprintf("all StorageCluster(s) meet minimum Portworx Enterprise version %s", [px_min_version]),
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_px_version_fail) == 0
	count(clusters_px_version_unknown) == 0
}

px_version_findings := [{
	"checkId":     "prod-px-kubevirt-px-version",
	"title":       "Portworx Enterprise Minimum Version",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.px_version.too_old",
	"message":     sprintf("%d StorageCluster(s) below minimum Portworx Enterprise version %s: %v", [count(clusters_px_version_fail), px_min_version, clusters_px_version_fail]),
	"evidence":    {"violating": sprintf("%v", [clusters_px_version_fail])},
	"remediation": sprintf("Upgrade Portworx Enterprise to %s or later. See https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/manage-kubevirt-vms-rwx-block/openshift#prerequisites", [px_min_version]),
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_px_version_fail) > 0
}

px_version_findings := [{
	"checkId":    "prod-px-kubevirt-px-version",
	"title":      "Portworx Enterprise Minimum Version",
	"category":   "production-readiness",
	"severity":   "warning",
	"pass":        false,
	"reasonCode": "prod.px.kubevirt.px_version.unknown",
	"message":    sprintf("Portworx Enterprise version unknown for %d StorageCluster(s): %v", [count(clusters_px_version_unknown), clusters_px_version_unknown]),
	"evidence":   {"unknown": sprintf("%v", [clusters_px_version_unknown])},
	"remediation": "Ensure the StorageCluster status.version field is populated. The cluster may still be initialising.",
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_px_version_fail) == 0
	count(clusters_px_version_unknown) > 0
}

px_version_findings := [] if { not collector_present }
px_version_findings := [] if {
	collector_present
	count(px_storage_clusters) == 0
}

# ---------------------------------------------------------------------------
# Check 11: Portworx Operator version >= 25.2.1
#
# Prerequisite from:
#   https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/
#       manage-kubevirt-vms-rwx-block/openshift#prerequisites
# ---------------------------------------------------------------------------

operator_min_version := "25.2.1"

clusters_operator_version_fail := {sprintf("%s/%s (found: %s, required: >= %s)", [c.namespace, c.name, c.operatorVersion, operator_min_version]) |
	some c in px_storage_clusters
	c.operatorVersion != ""
	not version_gte(c.operatorVersion, operator_min_version)
}

clusters_operator_version_unknown := {sprintf("%s/%s", [c.namespace, c.name]) |
	some c in px_storage_clusters
	c.operatorVersion == ""
}

operator_version_findings := [{
	"checkId":    "prod-px-kubevirt-operator-version",
	"title":      "Portworx Operator Minimum Version",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.operator_version.ok",
	"message":    sprintf("all StorageCluster(s) meet minimum Portworx Operator version %s", [operator_min_version]),
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_operator_version_fail) == 0
	count(clusters_operator_version_unknown) == 0
}

operator_version_findings := [{
	"checkId":     "prod-px-kubevirt-operator-version",
	"title":       "Portworx Operator Minimum Version",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.operator_version.too_old",
	"message":     sprintf("%d StorageCluster(s) below minimum Portworx Operator version %s: %v", [count(clusters_operator_version_fail), operator_min_version, clusters_operator_version_fail]),
	"evidence":    {"violating": sprintf("%v", [clusters_operator_version_fail])},
	"remediation": sprintf("Upgrade the Portworx Operator to %s or later. See https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/manage-kubevirt-vms-rwx-block/openshift#prerequisites", [operator_min_version]),
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_operator_version_fail) > 0
}

operator_version_findings := [{
	"checkId":    "prod-px-kubevirt-operator-version",
	"title":      "Portworx Operator Minimum Version",
	"category":   "production-readiness",
	"severity":   "warning",
	"pass":        false,
	"reasonCode": "prod.px.kubevirt.operator_version.unknown",
	"message":    sprintf("Portworx Operator version unknown for %d StorageCluster(s): %v", [count(clusters_operator_version_unknown), clusters_operator_version_unknown]),
	"evidence":   {"unknown": sprintf("%v", [clusters_operator_version_unknown])},
	"remediation": "Ensure the StorageCluster status.operatorVersion field is populated. The cluster may still be initialising.",
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_operator_version_fail) == 0
	count(clusters_operator_version_unknown) > 0
}

operator_version_findings := [] if { not collector_present }
operator_version_findings := [] if {
	collector_present
	count(px_storage_clusters) == 0
}

# ---------------------------------------------------------------------------
# Check 12: Portworx Stork version >= 25.2.0
#
# Prerequisite from:
#   https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/
#       manage-kubevirt-vms-rwx-block/openshift#prerequisites
#
# Stork is optional (spec.stork.enabled may be false). If no cluster has a
# storkVersion populated this check is skipped (info, not a failure).
# ---------------------------------------------------------------------------

stork_min_version := "25.2.0"

clusters_stork_version_fail := {sprintf("%s/%s (found: %s, required: >= %s)", [c.namespace, c.name, c.storkVersion, stork_min_version]) |
	some c in px_storage_clusters
	c.storkVersion != ""
	not version_gte(c.storkVersion, stork_min_version)
}

stork_version_findings := [{
	"checkId":    "prod-px-kubevirt-stork-version",
	"title":      "Portworx Stork Minimum Version",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.stork_version.ok",
	"message":    sprintf("all StorageCluster(s) with Stork enabled meet minimum Stork version %s", [stork_min_version]),
}] if {
	collector_present
	count(px_storage_clusters) > 0
	# At least one cluster has stork configured.
	count({c | some c in px_storage_clusters; c.storkVersion != ""}) > 0
	count(clusters_stork_version_fail) == 0
}

stork_version_findings := [{
	"checkId":     "prod-px-kubevirt-stork-version",
	"title":       "Portworx Stork Minimum Version",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.stork_version.too_old",
	"message":     sprintf("%d StorageCluster(s) below minimum Stork version %s: %v", [count(clusters_stork_version_fail), stork_min_version, clusters_stork_version_fail]),
	"evidence":    {"violating": sprintf("%v", [clusters_stork_version_fail])},
	"remediation": sprintf("Upgrade Portworx Stork to %s or later. See https://docs.portworx.com/portworx-enterprise/provision-storage/kubevirt-vms/manage-kubevirt-vms-rwx-block/openshift#prerequisites", [stork_min_version]),
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count(clusters_stork_version_fail) > 0
}

stork_version_findings := [{
	"checkId":    "prod-px-kubevirt-stork-version",
	"title":      "Portworx Stork Minimum Version",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.stork_version.not_configured",
	"message":    "no StorageCluster(s) have a Stork version configured; Stork is optional in this deployment",
}] if {
	collector_present
	count(px_storage_clusters) > 0
	count({c | some c in px_storage_clusters; c.storkVersion != ""}) == 0
	count(clusters_stork_version_fail) == 0
}

stork_version_findings := [] if { not collector_present }
stork_version_findings := [] if {
	collector_present
	count(px_storage_clusters) == 0
}

# ---------------------------------------------------------------------------
# pxctl status accessor
#
# pxctl status --json is collected by running the binary inside a portworx
# pod via the K8s exec API. The parsed result is stored under pxctlStatus in
# the collector output. If the exec failed (pod not found, RBAC missing, etc.)
# the dict will contain only the "_error" key and pxctl_present will be false.
# ---------------------------------------------------------------------------

px_pxctl := object.get(px_data, "pxctlStatus", {})

pxctl_present if {
	count(object.keys(px_pxctl)) > 0
	not object.get(px_pxctl, "_error", false)
}

# ---------------------------------------------------------------------------
# Check 13: Portworx cluster is operational (status == STATUS_OK)
# ---------------------------------------------------------------------------

cluster_status_findings := [{
	"checkId":    "prod-px-kubevirt-cluster-status",
	"title":      "Portworx Cluster Operational Status",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.cluster_status.ok",
	"message":    "Portworx cluster is operational (STATUS_OK)",
}] if {
	pxctl_present
	px_pxctl.clusterStatus == "STATUS_OK"
}

cluster_status_findings := [{
	"checkId":     "prod-px-kubevirt-cluster-status",
	"title":       "Portworx Cluster Operational Status",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.cluster_status.degraded",
	"message":     sprintf("Portworx cluster status is not operational: %v", [px_pxctl.clusterStatus]),
	"evidence":    {"clusterStatus": sprintf("%v", [px_pxctl.clusterStatus])},
	"remediation": "Investigate the Portworx cluster status with 'pxctl status'. All storage nodes must be reachable and quorum must be met.",
}] if {
	pxctl_present
	px_pxctl.clusterStatus != "STATUS_OK"
}

cluster_status_findings := [{
	"checkId":     "prod-px-kubevirt-cluster-status",
	"title":       "Portworx Cluster Operational Status",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.cluster_status.unavailable",
	"message":     sprintf("pxctl status data unavailable (%v); cannot verify cluster status", [object.get(px_pxctl, "_error", "collector not run")]),
	"remediation": "Ensure the RBAC rules in rbac.yaml grant pods (get, list) and pods/exec (create). Re-run the collector.",
}] if {
	collector_present
	not pxctl_present
}

cluster_status_findings := [] if { not collector_present }

# ---------------------------------------------------------------------------
# Check 14: Portworx license expires in > 30 days
# ---------------------------------------------------------------------------

license_findings := [{
	"checkId":    "prod-px-kubevirt-license-expiry",
	"title":      "Portworx License Expiry",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.license.permanent",
	"message":    sprintf("Portworx license is permanent/perpetual: %v", [px_pxctl.license]),
}] if {
	pxctl_present
	px_pxctl.licenseDaysRemaining >= 9999
}

license_findings := [{
	"checkId":    "prod-px-kubevirt-license-expiry",
	"title":      "Portworx License Expiry",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.license.ok",
	"message":    sprintf("Portworx license expires in %d days", [px_pxctl.licenseDaysRemaining]),
}] if {
	pxctl_present
	px_pxctl.licenseDaysRemaining < 9999
	px_pxctl.licenseDaysRemaining > 30
}

license_findings := [{
	"checkId":     "prod-px-kubevirt-license-expiry",
	"title":       "Portworx License Expiry",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.license.expiring_soon",
	"message":     sprintf("Portworx license expires in %d day(s); renew immediately to prevent service disruption", [px_pxctl.licenseDaysRemaining]),
	"evidence":    {"daysRemaining": sprintf("%d", [px_pxctl.licenseDaysRemaining])},
	"remediation": "Renew the Portworx license before it expires. Contact your Portworx account team or see https://docs.portworx.com/portworx-enterprise/operations/licensing/",
}] if {
	pxctl_present
	px_pxctl.licenseDaysRemaining < 9999
	px_pxctl.licenseDaysRemaining > 0
	px_pxctl.licenseDaysRemaining <= 30
}

license_findings := [{
	"checkId":     "prod-px-kubevirt-license-expiry",
	"title":       "Portworx License Expiry",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.license.expired",
	"message":     sprintf("Portworx license has expired or could not be parsed: %v", [px_pxctl.license]),
	"evidence":    {"license": sprintf("%v", [px_pxctl.license])},
	"remediation": "Renew the Portworx license immediately. Service degradation or data unavailability may already be occurring.",
}] if {
	pxctl_present
	px_pxctl.licenseDaysRemaining < 9999
	px_pxctl.licenseDaysRemaining == 0
}

license_findings := [{
	"checkId":     "prod-px-kubevirt-license-expiry",
	"title":       "Portworx License Expiry",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.license.unavailable",
	"message":     "pxctl status data unavailable; cannot verify license expiry",
	"remediation": "Re-run the collector with the required RBAC permissions (pods get/list, pods/exec create).",
}] if {
	collector_present
	not pxctl_present
}

license_findings := [] if { not collector_present }

# ---------------------------------------------------------------------------
# Check 15: Global storage pools have at least 20% free space
#
# Portworx volume provisioning will fail when the global pool is near full.
# 20% headroom is the recommended operational minimum.
# ---------------------------------------------------------------------------

_pool_min_free_pct := 20

global_pool_free_pct := (px_pxctl.globalTotalBytes - px_pxctl.globalUsedBytes) * 100 / px_pxctl.globalTotalBytes if {
	px_pxctl.globalTotalBytes > 0
}

global_pool_findings := [{
	"checkId":    "prod-px-kubevirt-global-pool-free",
	"title":      "Portworx Global Storage Pool Free Space",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.global_pool.ok",
	"message":    sprintf("global storage pool has %d%% free space (minimum %d%%)", [global_pool_free_pct, _pool_min_free_pct]),
}] if {
	pxctl_present
	px_pxctl.globalTotalBytes > 0
	global_pool_free_pct >= _pool_min_free_pct
}

global_pool_findings := [{
	"checkId":     "prod-px-kubevirt-global-pool-free",
	"title":       "Portworx Global Storage Pool Free Space",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.global_pool.low",
	"message":     sprintf("global storage pool has only %d%% free space (minimum %d%%)", [global_pool_free_pct, _pool_min_free_pct]),
	"evidence":    {"freePercent": sprintf("%d", [global_pool_free_pct])},
	"remediation": "Add storage capacity to the Portworx cluster or reduce usage. Below 20% free space may cause volume provisioning failures.",
}] if {
	pxctl_present
	px_pxctl.globalTotalBytes > 0
	global_pool_free_pct < _pool_min_free_pct
}

global_pool_findings := [{
	"checkId":    "prod-px-kubevirt-global-pool-free",
	"title":      "Portworx Global Storage Pool Free Space",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.global_pool.no_storage",
	"message":    "no storage pools reported; cluster may have no storage nodes",
}] if {
	pxctl_present
	px_pxctl.globalTotalBytes == 0
}

global_pool_findings := [{
	"checkId":     "prod-px-kubevirt-global-pool-free",
	"title":       "Portworx Global Storage Pool Free Space",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.global_pool.unavailable",
	"message":     "pxctl status data unavailable; cannot verify global pool free space",
	"remediation": "Re-run the collector with the required RBAC permissions.",
}] if {
	collector_present
	not pxctl_present
}

global_pool_findings := [] if { not collector_present }

# ---------------------------------------------------------------------------
# Check 16: Each local storage pool has at least 20% free space
#
# An individual pool that is nearly full can block volume creation on that
# node even when global capacity is available.
# ---------------------------------------------------------------------------

local_pool_violations := [msg |
	some n in px_pxctl.nodes
	some i, pool in n.pools
	pool.totalSize > 0
	free_pct := (pool.totalSize - pool.used) * 100 / pool.totalSize
	free_pct < _pool_min_free_pct
	msg := sprintf("%s pool-%d: %d%% free", [n.name, i, free_pct])
]

local_pool_findings := [{
	"checkId":    "prod-px-kubevirt-local-pool-free",
	"title":      "Portworx Local Storage Pool Free Space",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.local_pool.ok",
	"message":    "all local storage pools have >= 20% free space",
}] if {
	pxctl_present
	count(px_pxctl.nodes) > 0
	count(local_pool_violations) == 0
}

local_pool_findings := [{
	"checkId":     "prod-px-kubevirt-local-pool-free",
	"title":       "Portworx Local Storage Pool Free Space",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.local_pool.low",
	"message":     sprintf("%d pool(s) below %d%% free space: %v", [count(local_pool_violations), _pool_min_free_pct, local_pool_violations]),
	"evidence":    {"violating": sprintf("%v", [local_pool_violations])},
	"remediation": "Expand capacity of the affected pools (pxctl pool expand) or migrate data to other nodes.",
}] if {
	pxctl_present
	count(local_pool_violations) > 0
}

local_pool_findings := [{
	"checkId":     "prod-px-kubevirt-local-pool-free",
	"title":       "Portworx Local Storage Pool Free Space",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.local_pool.unavailable",
	"message":     "pxctl status data unavailable; cannot verify local pool free space",
	"remediation": "Re-run the collector with the required RBAC permissions.",
}] if {
	collector_present
	not pxctl_present
}

local_pool_findings := [] if { not collector_present }
local_pool_findings := [] if {
	pxctl_present
	count(px_pxctl.nodes) == 0
}

# ---------------------------------------------------------------------------
# Check 17: storev2 nodes have a metadata device of at least 64 GiB
#
# Portworx storev2 (StorageVol == /var/.px) requires a dedicated metadata
# device. The recommended minimum size is 64 GiB. An undersized metadata
# device causes metadata I/O saturation under heavy VM workloads.
# ---------------------------------------------------------------------------

_64_gib := 68719476736

storev2_in_use if {
	px_pxctl.storev2 == true
}

# Nodes where metadataDeviceSizeBytes < 64 GiB (includes absent metadata device).
storev2_metadata_violations := [msg |
	some n in px_pxctl.nodes
	n.metadataDeviceSizeBytes < _64_gib
	msg := sprintf("%s (metadata device: %v bytes, need >= %v bytes)",
		[n.name, n.metadataDeviceSizeBytes, _64_gib])
]

storev2_metadata_findings := [{
	"checkId":    "prod-px-kubevirt-storev2-metadata",
	"title":      "Portworx storev2 Metadata Device Size",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.storev2_metadata.ok",
	"message":    sprintf("storev2 in use; all %d node(s) have metadata device >= 64 GiB", [count(px_pxctl.nodes)]),
}] if {
	pxctl_present
	storev2_in_use
	count(storev2_metadata_violations) == 0
}

storev2_metadata_findings := [{
	"checkId":     "prod-px-kubevirt-storev2-metadata",
	"title":       "Portworx storev2 Metadata Device Size",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.storev2_metadata.undersized",
	"message":     sprintf("%d node(s) have metadata device below 64 GiB: %v", [count(storev2_metadata_violations), storev2_metadata_violations]),
	"evidence":    {"violating": sprintf("%v", [storev2_metadata_violations])},
	"remediation": "Resize or replace the metadata device on the affected nodes to at least 64 GiB. See 'pxctl service drive add' documentation.",
}] if {
	pxctl_present
	storev2_in_use
	count(storev2_metadata_violations) > 0
}

storev2_metadata_findings := [{
	"checkId":    "prod-px-kubevirt-storev2-metadata",
	"title":      "Portworx storev2 Metadata Device Size",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.storev2_metadata.not_applicable",
	"message":    "storev2 not detected; metadata device size check not applicable",
}] if {
	pxctl_present
	not storev2_in_use
}

storev2_metadata_findings := [{
	"checkId":     "prod-px-kubevirt-storev2-metadata",
	"title":       "Portworx storev2 Metadata Device Size",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.storev2_metadata.unavailable",
	"message":     "pxctl status data unavailable; cannot verify storev2 metadata device size",
	"remediation": "Re-run the collector with the required RBAC permissions.",
}] if {
	collector_present
	not pxctl_present
}

storev2_metadata_findings := [] if { not collector_present }

# ---------------------------------------------------------------------------
# Check 18: All storage nodes are online with storage status Up
# ---------------------------------------------------------------------------

# node.status == 2 means the node is online in the Portworx gossip protocol.
node_not_ok(n) if { n.status != 2 }
node_not_ok(n) if { n.storageStatus != "Up" }

nodes_not_ok_msgs := [msg |
	some n in px_pxctl.nodes
	node_not_ok(n)
	msg := sprintf("%s (nodeStatus=%v, storageStatus=%v)", [n.name, n.status, n.storageStatus])
]

node_health_findings := [{
	"checkId":    "prod-px-kubevirt-node-health",
	"title":      "Portworx Storage Node Health",
	"category":   "production-readiness",
	"severity":   "info",
	"pass":        true,
	"reasonCode": "prod.px.kubevirt.node_health.ok",
	"message":    sprintf("all %d storage node(s) are online with storage status Up", [count(px_pxctl.nodes)]),
}] if {
	pxctl_present
	count(px_pxctl.nodes) > 0
	count(nodes_not_ok_msgs) == 0
}

node_health_findings := [{
	"checkId":     "prod-px-kubevirt-node-health",
	"title":       "Portworx Storage Node Health",
	"category":    "production-readiness",
	"severity":    "error",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.node_health.degraded",
	"message":     sprintf("%d storage node(s) not online or storage not Up: %v", [count(nodes_not_ok_msgs), nodes_not_ok_msgs]),
	"evidence":    {"violating": sprintf("%v", [nodes_not_ok_msgs])},
	"remediation": "Investigate the affected nodes with 'pxctl status' and 'pxctl service diags'. Ensure all storage nodes are reachable and quorum is met.",
}] if {
	pxctl_present
	count(nodes_not_ok_msgs) > 0
}

node_health_findings := [{
	"checkId":     "prod-px-kubevirt-node-health",
	"title":       "Portworx Storage Node Health",
	"category":    "production-readiness",
	"severity":    "warning",
	"pass":         false,
	"reasonCode":  "prod.px.kubevirt.node_health.unavailable",
	"message":     "pxctl status data unavailable; cannot verify storage node health",
	"remediation": "Re-run the collector with the required RBAC permissions.",
}] if {
	collector_present
	not pxctl_present
}

node_health_findings := [] if { not collector_present }
node_health_findings := [] if {
	pxctl_present
	count(px_pxctl.nodes) == 0
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

cluster_findings := array.concat(
	array.concat(
		array.concat(
			array.concat(
				array.concat(
					array.concat(
						array.concat(
							array.concat(
								array.concat(
									array.concat(
										array.concat(
											array.concat(
												array.concat(
													array.concat(
														array.concat(
															array.concat(
																       array.concat(collector_findings, sc_exists_findings),
																       repl_findings,
															),
															binding_findings,
														),
														expansion_findings,
													),
													nodiscard_findings,
												),
												storageprofile_findings,
											),
											pvc_rwx_findings,
										),
										pvc_block_findings,
									),
									px_version_findings,
								),
								operator_version_findings,
							),
							stork_version_findings,
						),
						cluster_status_findings,
					),
					license_findings,
				),
				global_pool_findings,
			),
			local_pool_findings,
		),
		storev2_metadata_findings,
	),
	node_health_findings,
)
