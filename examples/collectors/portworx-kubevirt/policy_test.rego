package kvirtbp_test

import rego.v1

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

# Fully compliant cluster: ideal Portworx KubeVirt configuration.
input_compliant := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [
						{
							"name":                      "px-rwx-block-kubevirt",
							"repl":                      "3",
							"nodiscard":                 "true",
							"io_profile":                "db_remote",
							"sharedv4":                  "true",
							"volumeBindingMode":         "WaitForFirstConsumer",
							"allowVolumeExpansion":      true,
							"isDefaultVirtStorageClass": true,
							"isDefaultStorageClass":     false,
						},
						{
							"name":                      "px-rwx-file-kubevirt",
							"repl":                      "3",
							"nodiscard":                 "false",
							"io_profile":                "",
							"sharedv4":                  "false",
							"volumeBindingMode":         "WaitForFirstConsumer",
							"allowVolumeExpansion":      true,
							"isDefaultVirtStorageClass": false,
							"isDefaultStorageClass":     false,
						},
					],
					"storageProfiles": [
						{
							"name": "px-rwx-block-kubevirt",
							"claimPropertySets": [
								{"accessModes": ["ReadWriteMany"], "volumeMode": "Block"},
							],
						},
					],
					"storageClusters": [
						{
							"name":            "portworx",
							"namespace":       "portworx",
							"version":         "3.5.2",
							"operatorVersion": "25.5.2",
							"storkVersion":    "26.1.0",
						},
					],
					"pvcs": [
						{
							"name":             "vm-root-disk",
							"namespace":        "vms",
							"storageClassName": "px-rwx-block-kubevirt",
							"accessModes":      ["ReadWriteMany"],
							"volumeMode":       "Block",
						},
						{
							"name":             "vm-data-disk",
							"namespace":        "vms",
							"storageClassName": "px-rwx-block-kubevirt",
							"accessModes":      ["ReadWriteMany"],
							"volumeMode":       "Block",
						},
					],
					"pxctlStatus": {
						"clusterStatus":        "STATUS_OK",
						"license":              "PX-Enterprise (expires in 354 days)",
						"licenseDaysRemaining": 354,
						"storev2":              true,
						"globalTotalBytes":     1000000,
						"globalUsedBytes":      100000,
						"nodes": [
							{
								"name":                    "node1",
								"status":                  2,
								"storageStatus":            "Up",
								"pools":                   [{"totalSize": 1000000, "used": 100000}],
								"metadataDevicePresent":   true,
								"metadataDeviceSizeBytes": 68719476736,
							},
						],
					},
					"componentVersions": {
						"ocpVersion":     "4.18.33",
						"osvVersion":     "4.18.5",
						"mtvVersion":     "2.10.5",
						"virtV2VVersion": "2.7.1",
						"pxBackupVersion": "2.10.2",
					},
				},
			},
		},
	},
}

# No collector data at all.
input_no_collector := {
	"cluster": {
		"collectors": {},
	},
}

# No cluster (dry-run / unit-test short-circuit).
input_no_cluster := {}

# Low replication factor (repl=1).
input_low_repl := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [
						{
							"name":                 "px-test-sc",
							"repl":                 "1",
							"nodiscard":            "false",
							"sharedv4":             "false",
							"volumeBindingMode":    "WaitForFirstConsumer",
							"allowVolumeExpansion": true,
						},
					],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs":            [],
				},
			},
		},
	},
}

# Wrong binding mode (Immediate).
input_wrong_binding := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [
						{
							"name":                 "px-immediate-sc",
							"repl":                 "3",
							"nodiscard":            "false",
							"sharedv4":             "false",
							"volumeBindingMode":    "Immediate",
							"allowVolumeExpansion": true,
						},
					],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs":            [],
				},
			},
		},
	},
}

# Volume expansion disabled.
input_no_expansion := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [
						{
							"name":                 "px-no-expand-sc",
							"repl":                 "3",
							"nodiscard":            "false",
							"sharedv4":             "false",
							"volumeBindingMode":    "WaitForFirstConsumer",
							"allowVolumeExpansion": false,
						},
					],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs":            [],
				},
			},
		},
	},
}

# RWX StorageClass missing nodiscard.
input_missing_nodiscard := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [
						{
							"name":                 "px-rwx-no-discard",
							"repl":                 "3",
							"nodiscard":            "false",
							"sharedv4":             "true",
							"volumeBindingMode":    "WaitForFirstConsumer",
							"allowVolumeExpansion": true,
						},
					],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs":            [],
				},
			},
		},
	},
}

# StorageProfile missing Block+RWX claim property set.
input_bad_storageprofile := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [
						{
							"name":                 "px-rwx-block-kubevirt",
							"repl":                 "3",
							"nodiscard":            "true",
							"sharedv4":             "true",
							"volumeBindingMode":    "WaitForFirstConsumer",
							"allowVolumeExpansion": true,
						},
					],
					"storageProfiles": [
						{
							"name": "px-rwx-block-kubevirt",
							# Only Filesystem+RWO — missing Block+RWX
							"claimPropertySets": [
								{"accessModes": ["ReadWriteOnce"], "volumeMode": "Filesystem"},
							],
						},
					],
					"storageClusters": [],
					"pvcs":            [],
				},
			},
		},
	},
}

# KubeVirt PVCs using ReadWriteOnce (wrong access mode).
input_pvc_rwo := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs": [
						{
							"name":             "vm-disk",
							"namespace":        "vms",
							"storageClassName": "px-rwx-block-kubevirt",
							"accessModes":      ["ReadWriteOnce"],
							"volumeMode":       "Block",
						},
					],
				},
			},
		},
	},
}

# KubeVirt PVCs using Filesystem volume mode (wrong mode).
input_pvc_filesystem := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses": [],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs": [
						{
							"name":             "vm-disk",
							"namespace":        "vms",
							"storageClassName": "px-rwx-block-kubevirt",
							"accessModes":      ["ReadWriteMany"],
							"volumeMode":       "Filesystem",
						},
					],
				},
			},
		},
	},
}

# ---------------------------------------------------------------------------
# Baseline: no cluster → findings is empty
# ---------------------------------------------------------------------------

test_no_cluster_findings_empty if {
	findings := data.kvirtbp.findings with input as input_no_cluster
	count(findings) == 0
}

# ---------------------------------------------------------------------------
# Check 1: collector present / absent
# ---------------------------------------------------------------------------

test_collector_present_pass if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-collector-present"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.collector.present"
}

test_collector_absent_fail if {
	findings := data.kvirtbp.findings with input as input_no_collector
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-collector-present"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.collector.absent"
}

# ---------------------------------------------------------------------------
# Check 2: StorageClasses exist
# ---------------------------------------------------------------------------

test_storageclasses_exist_pass if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storageclasses-exist"]
	count(fs) == 1
	fs[0].pass == true
}

test_storageclasses_exist_fail if {
	inp := {
		"cluster": {
			"collectors": {
				"portworx-kubevirt": {
					"_cluster": {
						"storageClasses":   [],
						"storageProfiles":  [],
						"storageClusters":  [],
						"pvcs":             [],
					},
				},
			},
		},
	}
	findings := data.kvirtbp.findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storageclasses-exist"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.storageclasses.absent"
}

# ---------------------------------------------------------------------------
# Check 3: replication factor
# ---------------------------------------------------------------------------

test_replication_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-replication"]
	count(fs) == 1
	fs[0].pass == true
}

test_replication_low_fail if {
	findings := data.kvirtbp.findings with input as input_low_repl
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-replication"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.replication.low"
}

# ---------------------------------------------------------------------------
# Check 4: volumeBindingMode
# ---------------------------------------------------------------------------

test_binding_mode_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-binding-mode"]
	count(fs) == 1
	fs[0].pass == true
}

test_binding_mode_immediate_fail if {
	findings := data.kvirtbp.findings with input as input_wrong_binding
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-binding-mode"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.binding_mode.immediate"
}

# ---------------------------------------------------------------------------
# Check 5: allowVolumeExpansion
# ---------------------------------------------------------------------------

test_volume_expansion_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-volume-expansion"]
	count(fs) == 1
	fs[0].pass == true
}

test_volume_expansion_disabled_fail if {
	findings := data.kvirtbp.findings with input as input_no_expansion
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-volume-expansion"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.volume_expansion.disabled"
}

# ---------------------------------------------------------------------------
# Check 6: nodiscard on RWX StorageClasses
# ---------------------------------------------------------------------------

test_nodiscard_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-nodiscard"]
	count(fs) == 1
	fs[0].pass == true
}

test_nodiscard_missing_fail if {
	findings := data.kvirtbp.findings with input as input_missing_nodiscard
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-nodiscard"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.nodiscard.missing"
}

# Non-RWX StorageClasses do not trigger the nodiscard check.
test_nodiscard_not_applicable if {
	# input_low_repl has sharedv4=false — no nodiscard findings expected.
	findings := data.kvirtbp.findings with input as input_low_repl
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-nodiscard"]
	count(fs) == 0
}

# ---------------------------------------------------------------------------
# Check 7: StorageProfile block+RWX
# ---------------------------------------------------------------------------

test_storageprofile_block_rwx_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storageprofile-block"]
	count(fs) == 1
	fs[0].pass == true
}

test_storageprofile_block_rwx_fail if {
	findings := data.kvirtbp.findings with input as input_bad_storageprofile
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storageprofile-block"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.storageprofile.block_rwx.missing"
}

# ---------------------------------------------------------------------------
# Check 8: PVC ReadWriteMany
# ---------------------------------------------------------------------------

test_pvc_rwx_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pvc-rwx"]
	count(fs) == 1
	fs[0].pass == true
}

test_pvc_rwo_fail if {
	findings := data.kvirtbp.findings with input as input_pvc_rwo
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pvc-rwx"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.pvc.rwx.missing"
}

# ---------------------------------------------------------------------------
# Check 9: PVC Block mode
# ---------------------------------------------------------------------------

test_pvc_block_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pvc-block"]
	count(fs) == 1
	fs[0].pass == true
}

test_pvc_filesystem_fail if {
	findings := data.kvirtbp.findings with input as input_pvc_filesystem
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pvc-block"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.pvc.block.missing"
}

# ---------------------------------------------------------------------------
# Acceptance: compliant cluster produces only pass findings
# ---------------------------------------------------------------------------

test_compliant_all_pass if {
	findings := data.kvirtbp.findings with input as input_compliant
	every f in findings {
		f.pass == true
	}
}

# ---------------------------------------------------------------------------
# Check 10: Portworx Enterprise version
# ---------------------------------------------------------------------------

# Old PX version (2.9.0 < 3.5.2)
input_old_px_version := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [
						{
							"name":            "portworx",
							"namespace":       "portworx",
							"version":         "2.9.0",
							"operatorVersion": "25.5.2",
							"storkVersion":    "26.1.0",
						},
					],
					"pvcs": [],
				},
			},
		},
	},
}

# Missing PX version (empty string)
input_unknown_px_version := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [
						{
							"name":            "portworx",
							"namespace":       "portworx",
							"version":         "",
							"operatorVersion": "25.5.2",
							"storkVersion":    "26.1.0",
						},
					],
					"pvcs": [],
				},
			},
		},
	},
}

test_px_version_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-px-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.px_version.ok"
}

test_px_version_too_old_fail if {
	findings := data.kvirtbp.findings with input as input_old_px_version
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-px-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.px_version.too_old"
}

test_px_version_unknown_fail if {
	findings := data.kvirtbp.findings with input as input_unknown_px_version
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-px-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.px_version.unknown"
}

# ---------------------------------------------------------------------------
# Check 11: Portworx Operator version
# ---------------------------------------------------------------------------

input_old_operator_version := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [
						{
							"name":            "portworx",
							"namespace":       "portworx",
							"version":         "3.5.2",
							"operatorVersion": "24.1.0",
							"storkVersion":    "26.1.0",
						},
					],
					"pvcs": [],
				},
			},
		},
	},
}

test_operator_version_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-operator-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.operator_version.ok"
}

test_operator_version_too_old_fail if {
	findings := data.kvirtbp.findings with input as input_old_operator_version
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-operator-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.operator_version.too_old"
}

# ---------------------------------------------------------------------------
# Check 12: Portworx Stork version
# ---------------------------------------------------------------------------

input_old_stork_version := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [
						{
							"name":            "portworx",
							"namespace":       "portworx",
							"version":         "3.5.2",
							"operatorVersion": "25.5.2",
							"storkVersion":    "25.1.0",
						},
					],
					"pvcs": [],
				},
			},
		},
	},
}

input_stork_not_configured := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [
						{
							"name":            "portworx",
							"namespace":       "portworx",
							"version":         "3.5.2",
							"operatorVersion": "25.5.2",
							"storkVersion":    "",
						},
					],
					"pvcs": [],
				},
			},
		},
	},
}

test_stork_version_ok if {
	findings := data.kvirtbp.findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-stork-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.stork_version.ok"
}

test_stork_version_too_old_fail if {
	findings := data.kvirtbp.findings with input as input_old_stork_version
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-stork-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].reasonCode == "prod.px.kubevirt.stork_version.too_old"
}

test_stork_not_configured_pass if {
	findings := data.kvirtbp.findings with input as input_stork_not_configured
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-stork-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.stork_version.not_configured"
}

# ---------------------------------------------------------------------------
# Version comparison helper: edge cases
# ---------------------------------------------------------------------------

# Exact minimum boundary — should pass
test_version_exact_minimum if {
	data.kvirtbp.version_gte("3.3.0", "3.3.0")
}

# Minor version bump — should pass
test_version_minor_bump if {
	data.kvirtbp.version_gte("3.10.0", "3.3.0")
}

# Patch version below — should fail
test_version_patch_below if {
	not data.kvirtbp.version_gte("3.3.0", "3.3.1")
}

# Major version below — should fail
test_version_major_below if {
	not data.kvirtbp.version_gte("2.9.9", "3.0.0")
}

# Pre-release suffix (e.g. -rc1) must not cause the check to fail when the
# numeric version satisfies the minimum.
test_version_prerelease_pass if {
	data.kvirtbp.version_gte("3.6.0-rc1", "3.3.0")
}

# Pre-release patch that is numerically below minimum should still fail.
test_version_prerelease_fail if {
	not data.kvirtbp.version_gte("3.2.9-rc1", "3.3.0")
}

# ===========================================================================
# Checks 13-18: pxctl status checks
# ===========================================================================

# ---------------------------------------------------------------------------
# Helper: build a minimal collector input with a given pxctlStatus object.
# ---------------------------------------------------------------------------

_pxctl_only(ps) := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs":            [],
					"pxctlStatus":     ps,
				},
			},
		},
	},
}

_vm_only(vms) := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":  [],
					"storageProfiles": [],
					"storageClusters": [],
					"pvcs":            [],
					"virtualMachines": vms,
					"pxctlStatus":     {},
				},
			},
		},
	},
}

_good_pxctl := {
	"clusterStatus":        "STATUS_OK",
	"license":              "PX-Enterprise (expires in 100 days)",
	"licenseDaysRemaining": 100,
	"storev2":              true,
	"globalTotalBytes":     1000000,
	"globalUsedBytes":      100000,
	"nodes": [
		{
			"name":                    "node1",
			"status":                  2,
			"storageStatus":            "Up",
			"pools":                   [{"totalSize": 1000000, "used": 100000}],
			"metadataDevicePresent":   true,
			"metadataDeviceSizeBytes": 68719476736,
		},
	],
}

# ---------------------------------------------------------------------------
# Check 13: cluster status
# ---------------------------------------------------------------------------

test_cluster_status_ok if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-cluster-status"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.cluster_status.ok"
}

test_cluster_status_fail if {
	inp := _pxctl_only(object.union(_good_pxctl, {"clusterStatus": "STATUS_NOT_OK"}))
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-cluster-status"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.cluster_status.degraded"
}

test_cluster_status_pxctl_unavailable if {
	inp := _pxctl_only({"_error": "pod_not_found"})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-cluster-status"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "warning"
	fs[0].reasonCode == "prod.px.kubevirt.cluster_status.unavailable"
}

# ---------------------------------------------------------------------------
# Check 14: license expiry
# ---------------------------------------------------------------------------

test_license_ok if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-license-expiry"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.license.ok"
}

test_license_permanent if {
	inp := _pxctl_only(object.union(_good_pxctl, {
		"license":              "PX-Enterprise permanent",
		"licenseDaysRemaining": 99999,
	}))
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-license-expiry"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.license.permanent"
}

test_license_expiring_soon_fail if {
	inp := _pxctl_only(object.union(_good_pxctl, {
		"license":              "PX-Enterprise (expires in 15 days)",
		"licenseDaysRemaining": 15,
	}))
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-license-expiry"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "warning"
	fs[0].reasonCode == "prod.px.kubevirt.license.expiring_soon"
}

test_license_expired_fail if {
	inp := _pxctl_only(object.union(_good_pxctl, {
		"license":              "PX-Enterprise (expired)",
		"licenseDaysRemaining": 0,
	}))
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-license-expiry"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.license.expired"
}

# ---------------------------------------------------------------------------
# Check 15: global pool free space
# ---------------------------------------------------------------------------

test_global_pool_ok if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-global-pool-free"]
	count(fs) == 1
	fs[0].pass == true
}

# 85% used → 15% free < 20% — fail
test_global_pool_low_fail if {
	inp := _pxctl_only(object.union(_good_pxctl, {
		"globalTotalBytes": 1000,
		"globalUsedBytes":  850,
	}))
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-global-pool-free"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "warning"
	fs[0].reasonCode == "prod.px.kubevirt.global_pool.low"
}

# Exactly 20% free — pass
test_global_pool_boundary_pass if {
	inp := _pxctl_only(object.union(_good_pxctl, {
		"globalTotalBytes": 100,
		"globalUsedBytes":  80,
	}))
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-global-pool-free"]
	count(fs) == 1
	fs[0].pass == true
}

# ---------------------------------------------------------------------------
# Check 16: local pool free space
# ---------------------------------------------------------------------------

test_local_pool_ok if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-local-pool-free"]
	count(fs) == 1
	fs[0].pass == true
}

# One node with 85% used pool — fail
test_local_pool_low_fail if {
	ps := object.union(_good_pxctl, {"nodes": [
		{
			"name":                    "node1",
			"status":                  2,
			"storageStatus":            "Up",
			"pools":                   [{"totalSize": 1000, "used": 850}],
			"metadataDevicePresent":   true,
			"metadataDeviceSizeBytes": 68719476736,
		},
	]})
	inp := _pxctl_only(ps)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-local-pool-free"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "warning"
}

# ---------------------------------------------------------------------------
# Check 17: storev2 metadata device size
# ---------------------------------------------------------------------------

test_storev2_metadata_ok if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storev2-metadata"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.storev2_metadata.ok"
}

# storev2=true, node has metadata device below 64 GiB (8 GiB)
test_storev2_metadata_undersized_fail if {
	ps := object.union(_good_pxctl, {"nodes": [
		{
			"name":                    "node1",
			"status":                  2,
			"storageStatus":            "Up",
			"pools":                   [{"totalSize": 1000000, "used": 100000}],
			"metadataDevicePresent":   true,
			"metadataDeviceSizeBytes": 8589934592,
		},
	]})
	inp := _pxctl_only(ps)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storev2-metadata"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.storev2_metadata.undersized"
}

# storev2=false — not applicable, should pass
test_storev2_not_in_use_skip if {
	ps := object.union(_good_pxctl, {"storev2": false})
	inp := _pxctl_only(ps)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storev2-metadata"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.storev2_metadata.not_applicable"
}

# storev2=true, node with no metadata device (size 0) — fail
test_storev2_metadata_absent_fail if {
	ps := object.union(_good_pxctl, {"nodes": [
		{
			"name":                    "node1",
			"status":                  2,
			"storageStatus":            "Up",
			"pools":                   [{"totalSize": 1000000, "used": 100000}],
			"metadataDevicePresent":   false,
			"metadataDeviceSizeBytes": 0,
		},
	]})
	inp := _pxctl_only(ps)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-storev2-metadata"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
}

# ---------------------------------------------------------------------------
# Check 18: storage node health
# ---------------------------------------------------------------------------

test_node_health_ok if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-node-health"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].reasonCode == "prod.px.kubevirt.node_health.ok"
}

# Node with status != 2 (offline)
test_node_health_offline_fail if {
	ps := object.union(_good_pxctl, {"nodes": [
		{
			"name":                    "node1",
			"status":                  0,
			"storageStatus":            "Up",
			"pools":                   [{"totalSize": 1000000, "used": 100000}],
			"metadataDevicePresent":   true,
			"metadataDeviceSizeBytes": 68719476736,
		},
	]})
	inp := _pxctl_only(ps)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-node-health"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.node_health.degraded"
}

# Node with storageStatus != "Up"
test_node_health_storage_down_fail if {
	ps := object.union(_good_pxctl, {"nodes": [
		{
			"name":                    "node1",
			"status":                  2,
			"storageStatus":            "Down",
			"pools":                   [{"totalSize": 1000000, "used": 100000}],
			"metadataDevicePresent":   true,
			"metadataDeviceSizeBytes": 68719476736,
		},
	]})
	inp := _pxctl_only(ps)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-node-health"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
}

# ---------------------------------------------------------------------------
# Check 20-24: Component version checks (OCP, OSV, MTV, virt-v2v, PX-Backup)
# ---------------------------------------------------------------------------

# Helper: minimal input with only componentVersions set (no VMs, no StorageClusters etc.)
_components_only(cv) := {
	"cluster": {
		"collectors": {
			"portworx-kubevirt": {
				"_cluster": {
					"storageClasses":    [],
					"storageProfiles":   [],
					"storageClusters":   [],
					"pvcs":              [],
					"virtualMachines":   [],
					"componentVersions": cv,
				},
			},
		},
	},
}

# ── Check 20: OCP version ──────────────────────────────────────────────────

# Compliant OCP version → pass info.
test_ocp_version_ok if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-ocp-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].severity == "info"
	fs[0].reasonCode == "prod.px.kubevirt.ocp_version.ok"
}

# OCP version newer than minimum → pass.
test_ocp_version_newer_ok if {
	inp := _components_only({"ocpVersion": "4.19.0", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-ocp-version"]
	count(fs) == 1
	fs[0].pass == true
}

# OCP version too old → error.
test_ocp_version_too_old_fail if {
	inp := _components_only({"ocpVersion": "4.18.10", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-ocp-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.ocp_version.too_old"
}

# OCP version empty (non-OCP cluster or CRD unavailable) → check skipped.
test_ocp_version_not_ocp_skip if {
	inp := _components_only({"ocpVersion": "", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-ocp-version"]
	count(fs) == 0
}

# No collector data → OCP check skipped.
test_ocp_version_no_collector_skip if {
	findings := data.kvirtbp.cluster_findings with input as input_no_collector
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-ocp-version"]
	count(fs) == 0
}

# ── Check 21: OSV version ──────────────────────────────────────────────────

# Compliant OSV version (exactly 4.18.5, the minimum) → pass.
test_osv_version_ok if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "4.18.5", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-osv-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].severity == "info"
	fs[0].reasonCode == "prod.px.kubevirt.osv_version.ok"
}

# OSV version 4.18.4 (not strictly > 4.18.4) → error.
test_osv_version_too_old_fail if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "4.18.4", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-osv-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.osv_version.too_old"
}

# OSV not installed (empty version) → check skipped.
test_osv_version_not_installed_skip if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-osv-version"]
	count(fs) == 0
}

# ── Check 22: MTV/Forklift version ────────────────────────────────────────

# Compliant MTV version → pass.
test_mtv_version_ok if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "2.10.5", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-mtv-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].severity == "info"
	fs[0].reasonCode == "prod.px.kubevirt.mtv_version.ok"
}

# MTV version too old → error.
test_mtv_version_too_old_fail if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "2.9.0", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-mtv-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.mtv_version.too_old"
}

# MTV not installed → skip.
test_mtv_version_not_installed_skip if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-mtv-version"]
	count(fs) == 0
}

# ── Check 23: virt-v2v version ────────────────────────────────────────────

# Compliant virt-v2v version → pass.
test_virtv2v_version_ok if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "2.10.5", "virtV2VVersion": "2.7.1", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-virtv2v-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].severity == "info"
	fs[0].reasonCode == "prod.px.kubevirt.virtv2v_version.ok"
}

# virt-v2v version too old → error.
test_virtv2v_version_too_old_fail if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "2.10.5", "virtV2VVersion": "2.6.0", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-virtv2v-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.virtv2v_version.too_old"
}

# virt-v2v version not set (MTV not installed / env var absent) → skip.
test_virtv2v_version_not_installed_skip if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-virtv2v-version"]
	count(fs) == 0
}

# ── Check 24: PX-Backup version ───────────────────────────────────────────

# Compliant PX-Backup version → pass.
test_pxbackup_version_ok if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": "2.10.2"})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pxbackup-version"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].severity == "info"
	fs[0].reasonCode == "prod.px.kubevirt.pxbackup_version.ok"
}

# PX-Backup version too old → error.
test_pxbackup_version_too_old_fail if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": "2.9.0"})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pxbackup-version"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "error"
	fs[0].reasonCode == "prod.px.kubevirt.pxbackup_version.too_old"
}

# PX-Backup not installed → skip.
test_pxbackup_version_not_installed_skip if {
	inp := _components_only({"ocpVersion": "4.18.33", "osvVersion": "", "mtvVersion": "", "virtV2VVersion": "", "pxBackupVersion": ""})
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-pxbackup-version"]
	count(fs) == 0
}

# Compliant fixture: all component checks pass.
test_compliant_component_versions_all_pass if {
	findings := data.kvirtbp.cluster_findings with input as input_compliant
	component_check_ids := {
		"prod-px-kubevirt-ocp-version",
		"prod-px-kubevirt-osv-version",
		"prod-px-kubevirt-mtv-version",
		"prod-px-kubevirt-virtv2v-version",
		"prod-px-kubevirt-pxbackup-version",
	}
	fs := [f | f := findings[_]; f.checkId in component_check_ids]
	count(fs) == 5
	count([f | f := fs[_]; f.pass == true]) == 5
}

# ---------------------------------------------------------------------------
# Check 19: VM disk block sizes
# ---------------------------------------------------------------------------

# One root disk (exempt) + one correctly configured data disk → pass.
test_vm_disk_blocksize_ok if {
	vms := [{
		"name": "my-vm", "namespace": "vms",
		"disks": [
			{"name": "rootdisk",    "isRootDisk": true,  "blockSizeLogical": 512,  "blockSizePhysical": 4096},
			{"name": "data-disk-1", "isRootDisk": false, "blockSizeLogical": 4096, "blockSizePhysical": 4096},
		],
	}]
	inp := _vm_only(vms)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-vm-disk-blocksize"]
	count(fs) == 1
	fs[0].pass == true
	fs[0].severity == "info"
	fs[0].reasonCode == "prod.px.kubevirt.vm_disk_blocksize.ok"
}

# No VMs at all → check is skipped (no finding emitted).
test_vm_disk_blocksize_no_vms_skip if {
	inp := _vm_only([])
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-vm-disk-blocksize"]
	count(fs) == 0
}

# Only root disks present (no data disks) → check is skipped.
test_vm_disk_blocksize_only_root_skip if {
	vms := [{
		"name": "my-vm", "namespace": "vms",
		"disks": [
			{"name": "rootdisk", "isRootDisk": true, "blockSizeLogical": 512, "blockSizePhysical": 4096},
		],
	}]
	inp := _vm_only(vms)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-vm-disk-blocksize"]
	count(fs) == 0
}

# Data disk with physical=512 (supported but not recommended) → warning.
test_vm_disk_blocksize_physical_512_fail if {
	vms := [{
		"name": "my-vm", "namespace": "vms",
		"disks": [
			{"name": "data-disk-1", "isRootDisk": false, "blockSizeLogical": 4096, "blockSizePhysical": 512},
		],
	}]
	inp := _vm_only(vms)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-vm-disk-blocksize"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "warning"
	fs[0].reasonCode == "prod.px.kubevirt.vm_disk_blocksize.not_4k"
}

# Data disk with neither size set (both 0) → warning.
test_vm_disk_blocksize_unset_fail if {
	vms := [{
		"name": "my-vm", "namespace": "vms",
		"disks": [
			{"name": "data-disk-1", "isRootDisk": false, "blockSizeLogical": 0, "blockSizePhysical": 0},
		],
	}]
	inp := _vm_only(vms)
	findings := data.kvirtbp.cluster_findings with input as inp
	fs := [f | f := findings[_]; f.checkId == "prod-px-kubevirt-vm-disk-blocksize"]
	count(fs) == 1
	fs[0].pass == false
	fs[0].severity == "warning"
}
