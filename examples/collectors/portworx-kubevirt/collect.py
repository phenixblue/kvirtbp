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

import base64, json, os, re as _re, socket, ssl, struct, urllib.parse as _up, urllib.request as u

SAR = '/var/run/secrets/kubernetes.io/serviceaccount'
tok = open(SAR + '/token').read().strip()
h = os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc')
p = os.environ.get('KUBERNETES_SERVICE_PORT', '443')
BASE = 'https://' + h + ':' + p
ctx = ssl.create_default_context(cafile=SAR + '/ca.crt')


def _ws_exec(ns, pod_name, cmd):
    """Run cmd in pod_name via K8s WebSocket exec API. Returns stdout bytes."""
    qs = '&'.join(
        ['command=' + _up.quote(c) for c in cmd] +
        ['stdout=true', 'stderr=true', 'stdin=false', 'tty=false']
    )
    path = '/api/v1/namespaces/{}/pods/{}/exec?{}'.format(ns, pod_name, qs)
    ctx2 = ssl.create_default_context(cafile=SAR + '/ca.crt')
    try:
        sock = ctx2.wrap_socket(
            socket.create_connection((h, int(p)), timeout=30),
            server_hostname=h,
        )
    except Exception:
        return b''
    sock.settimeout(60)
    try:
        ws_key = base64.b64encode(os.urandom(16)).decode()
        req = (
            'GET {path} HTTP/1.1\r\n'
            'Host: {h}:{p}\r\n'
            'Authorization: Bearer {tok}\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            'Sec-WebSocket-Key: {key}\r\n'
            'Sec-WebSocket-Version: 13\r\n'
            'Sec-WebSocket-Protocol: channel.k8s.io\r\n'
            '\r\n'
        ).format(path=path, h=h, p=p, tok=tok, key=ws_key).encode()
        sock.sendall(req)
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return b''
            buf += chunk
        head, buf = buf.split(b'\r\n\r\n', 1)
        if b' 101 ' not in head.split(b'\r\n')[0]:
            return b''
        stdout = b''
        while True:
            while len(buf) < 2:
                c = sock.recv(4096)
                if not c:
                    return stdout
                buf += c
            opcode = buf[0] & 0x0f
            if opcode == 8:   # WebSocket close frame
                return stdout
            plen = buf[1] & 0x7f
            hlen = 2
            if plen == 126:
                while len(buf) < 4:
                    c = sock.recv(4096)
                    if not c:
                        return stdout
                    buf += c
                plen = struct.unpack('>H', buf[2:4])[0]
                hlen = 4
            elif plen == 127:
                while len(buf) < 10:
                    c = sock.recv(4096)
                    if not c:
                        return stdout
                    buf += c
                plen = struct.unpack('>Q', buf[2:10])[0]
                hlen = 10
            total_frame = hlen + plen
            while len(buf) < total_frame:
                c = sock.recv(4096)
                if not c:
                    return stdout
                buf += c
            payload = buf[hlen:total_frame]
            buf = buf[total_frame:]
            if payload:
                ch = payload[0]
                if ch == 1:       # stdout channel
                    stdout += payload[1:]
                elif ch == 3:     # error/EOF signal
                    return stdout
    except Exception:
        return stdout
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _find_px_pod():
    """Return (namespace, pod_name) of a running portworx pod, or (None, None)."""
    for ns in ('kube-system', 'portworx'):
        for sel in ('name=portworx', 'app=portworx'):
            resp = get('/api/v1/namespaces/{}/pods?labelSelector={}'.format(
                ns, _up.quote(sel)))
            for pod in resp.get('items', []):
                if pod.get('status', {}).get('phase') == 'Running':
                    return ns, pod['metadata']['name']
    return None, None


def _license_days(lic_str):
    m = _re.search(r'expires in (\d+) days', str(lic_str))
    if m:
        return int(m.group(1))
    if any(w in str(lic_str).lower() for w in ('permanent', 'never', 'no expiry')):
        return 99999
    return 0


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
def _stork_version(sc):
    # Stork version is embedded in spec.stork.spec.image, e.g.
    #   openstorage/stork:25.2.0
    # Fall back to status.desiredImages.stork when the spec image is absent
    # (operator may replace the field with the resolved digest reference).
    img = (
        sc.get('spec', {})
          .get('stork', {})
          .get('spec', {})
          .get('image', '')
    )
    if not img:
        img = (
            sc.get('status', {})
              .get('desiredImages', {})
              .get('stork', '')
        )
    # Extract the tag after the last colon; strip leading 'v' for uniform comparison.
    if ':' in img:
        tag = img.rsplit(':', 1)[-1]
        return tag.lstrip('v')
    return ''

stc_list = get('/apis/core.libopenstorage.org/v1/storageclusters')
clusters = [
    {
        'name':            s['metadata']['name'],
        'namespace':       s['metadata']['namespace'],
        'version':         s.get('status', {}).get('version', '').lstrip('v'),
        'operatorVersion': s.get('status', {}).get('operatorVersion', '').lstrip('v'),
        'storkVersion':    _stork_version(s),
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

# ── pxctl status ───────────────────────────────────────────────────────────────
pxctl_status = {}
_px_ns, _px_pod = _find_px_pod()
if _px_ns and _px_pod:
    _raw = _ws_exec(_px_ns, _px_pod, ['/opt/pwx/bin/pxctl', 'status', '--json'])
    if _raw:
        try:
            _d = json.loads(_raw)
            _nodes = []
            for _n in _d.get('cluster', {}).get('Nodes', []):
                _si = _n.get('NodeData', {}).get('STORAGE-INFO', {})
                _rsm = _si.get('ResourceSystemMetadata', {})
                _pools = [
                    {'totalSize': _pl.get('TotalSize', 0), 'used': _pl.get('Used', 0)}
                    for _pl in _n.get('Pools', [])
                ]
                _nodes.append({
                    'name':                    _n.get('SchedulerNodeName') or _n.get('Id', ''),
                    'status':                  _n.get('Status', 0),
                    'storageStatus':           _si.get('Status', ''),
                    'pools':                   _pools,
                    'metadataDevicePresent':   bool(_rsm.get('metadata', False)),
                    'metadataDeviceSizeBytes': _rsm.get('size', 0),
                })
            _lic = _d.get('license', '')
            _sv = (_d.get('daemoninfo', {}).get('StorageSpec', {})
                     .get('StorageVol', '') == '/var/.px')
            pxctl_status = {
                'clusterStatus':        _d.get('status', ''),
                'license':              _lic,
                'licenseDaysRemaining': _license_days(_lic),
                'storev2':              _sv,
                'globalTotalBytes':     sum(_pl['totalSize'] for _nd in _nodes for _pl in _nd['pools']),
                'globalUsedBytes':      sum(_pl['used']      for _nd in _nodes for _pl in _nd['pools']),
                'nodes':                _nodes,
            }
        except Exception as _exc:
            pxctl_status = {'_error': 'parse_failed: ' + str(_exc)}
    else:
        pxctl_status = {'_error': 'exec_failed: no output from pxctl status --json'}
else:
    pxctl_status = {'_error': 'pod_not_found: no running portworx pod found in kube-system or portworx namespace'}

# ── Output ─────────────────────────────────────────────────────────────────────
import os as _os
_os.makedirs('/tmp/kvirtbp', exist_ok=True)
json.dump(
    {
        'storageClasses':   px_scs,
        'storageProfiles':  profiles,
        'storageClusters':  clusters,
        'pvcs':             pvcs,
        'pxctlStatus':      pxctl_status,
    },
    open('/tmp/kvirtbp/output.json', 'w'),
)
