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
version_gte(actual, minimum) if {
	ap := split(actual, ".")
	mp := split(minimum, ".")
	count(ap) == 3
	count(mp) == 3
	# Convert each component to an integer tuple for numeric comparison.
	[to_number(ap[0]), to_number(ap[1]), to_number(ap[2])] >=
		[to_number(mp[0]), to_number(mp[1]), to_number(mp[2])]
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
)
