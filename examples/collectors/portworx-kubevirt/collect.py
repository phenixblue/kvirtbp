"""
portworx-kubevirt collector script
===================================
Queries the Kubernetes API from inside the collector pod using the in-cluster
service account token. Writes a JSON snapshot to /tmp/kvirtbp/output.json.

This file is the human-readable source for the base64-encoded command embedded
in metadata.json. To regenerate the base64 payload:

    base64 -w0 collect.py        # Linux
    base64 -i collect.py         # macOS (then strip trailing newline)

Data collected
--------------
storageClasses   — all StorageClasses with provisioner=pxd.portworx.com
storageProfiles  — CDI StorageProfiles matching any of those StorageClasses
storageClusters  — StorageCluster CRs (Portworx operator CRD)
pvcs             — PVCs labelled portworx.io/app=kubevirt (all namespaces)

RBAC required
-------------
See rbac.yaml — ClusterRole needs get/list on:
  storageclasses (storage.k8s.io/v1)
  persistentvolumeclaims (v1)
  storageclusters (core.libopenstorage.org/v1)
  storageprofiles (cdi.kubevirt.io/v1beta1)
"""

import json, os, ssl, urllib.request as u

SAR = '/var/run/secrets/kubernetes.io/serviceaccount'
tok = open(SAR + '/token').read().strip()
h = os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc')
p = os.environ.get('KUBERNETES_SERVICE_PORT', '443')
BASE = 'https://' + h + ':' + p
ctx = ssl.create_default_context(cafile=SAR + '/ca.crt')


def get(path):
    try:
        req = u.Request(BASE + path, headers={'Authorization': 'Bearer ' + tok})
        with u.urlopen(req, context=ctx) as r:
            return json.loads(r.read())
    except:
        return {'items': []}


# ── StorageClasses ─────────────────────────────────────────────────────────────
sc_list = get('/apis/storage.k8s.io/v1/storageclasses')
px_scs = []
for sc in sc_list.get('items', []):
    if sc.get('provisioner') != 'pxd.portworx.com':
        continue
    p2 = sc.get('parameters', {})
    ann = sc.get('metadata', {}).get('annotations', {})
    px_scs.append({
        'name':                     sc['metadata']['name'],
        'repl':                     p2.get('repl', ''),
        'nodiscard':                p2.get('nodiscard', 'false'),
        'io_profile':               p2.get('io_profile', ''),
        'sharedv4':                 p2.get('sharedv4', 'false'),
        'volumeBindingMode':        sc.get('volumeBindingMode', 'Immediate'),
        'allowVolumeExpansion':     sc.get('allowVolumeExpansion', False),
        'isDefaultVirtStorageClass': ann.get('storageclass.kubevirt.io/is-default-virt-storageclass') == 'true',
        'isDefaultStorageClass':    ann.get('storageclass.kubernetes.io/is-default-class') == 'true',
    })

px_names = {s['name'] for s in px_scs}

# ── StorageProfiles ────────────────────────────────────────────────────────────
sp_list = get('/apis/cdi.kubevirt.io/v1beta1/storageprofiles')
profiles = []
for sp in sp_list.get('items', []):
    if sp['metadata']['name'] not in px_names:
        continue
    cps = sp.get('status', {}).get('claimPropertySets', [])
    profiles.append({'name': sp['metadata']['name'], 'claimPropertySets': cps})

# ── StorageClusters ────────────────────────────────────────────────────────────
stc_list = get('/apis/core.libopenstorage.org/v1/storageclusters')
clusters = [
    {
        'name':            s['metadata']['name'],
        'namespace':       s['metadata']['namespace'],
        'version':         s.get('status', {}).get('version', ''),
        'operatorVersion': s.get('status', {}).get('operatorVersion', ''),
    }
    for s in stc_list.get('items', [])
]

# ── PVCs ───────────────────────────────────────────────────────────────────────
pvc_list = get('/api/v1/persistentvolumeclaims?labelSelector=portworx.io%2Fapp%3Dkubevirt')
pvcs = [
    {
        'name':             pvc['metadata']['name'],
        'namespace':        pvc['metadata']['namespace'],
        'storageClassName': pvc.get('spec', {}).get('storageClassName', ''),
        'accessModes':      pvc.get('spec', {}).get('accessModes', []),
        'volumeMode':       pvc.get('spec', {}).get('volumeMode', 'Filesystem'),
    }
    for pvc in pvc_list.get('items', [])
]

# ── Output ─────────────────────────────────────────────────────────────────────
import os as _os
_os.makedirs('/tmp/kvirtbp', exist_ok=True)
json.dump(
    {
        'storageClasses':   px_scs,
        'storageProfiles':  profiles,
        'storageClusters':  clusters,
        'pvcs':             pvcs,
    },
    open('/tmp/kvirtbp/output.json', 'w'),
)
