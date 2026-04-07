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

import base64, http.client as _hc, json, os, re as _re, socket, ssl, struct, urllib.parse as _up, urllib.request as u

SAR = '/var/run/secrets/kubernetes.io/serviceaccount'
tok = open(SAR + '/token').read().strip()
h = os.environ.get('KUBERNETES_SERVICE_HOST', 'kubernetes.default.svc')
p = os.environ.get('KUBERNETES_SERVICE_PORT', '443')
BASE = 'https://' + h + ':' + p
ctx = ssl.create_default_context(cafile=SAR + '/ca.crt')


def _ws_exec(ns, pod_name, cmd):
    """Run cmd in pod_name via K8s WebSocket exec API.

    Returns (stdout_bytes, stderr_bytes, diag_str).

    Uses http.client for the HTTP upgrade so that any bytes the HTTP parser
    buffered during header reading are correctly available via resp.fp.read1()
    rather than being silently lost if we switched to raw sock.recv().

    Both stdout (ch 1) and stderr (ch 2) are accumulated; callers can use
    whichever is non-empty. Process-exit status (ch 3) is ignored; we keep
    reading until the WebSocket close frame (opcode 8) or EOF.
    """
    qs = '&'.join(
        ['command=' + _up.quote(c) for c in cmd] +
        ['stdout=true', 'stderr=true', 'stdin=false', 'tty=false']
    )
    path = '/api/v1/namespaces/{}/pods/{}/exec?{}'.format(ns, pod_name, qs)
    ws_key = base64.b64encode(os.urandom(16)).decode()
    stdout = b''
    stderr = b''
    diag = ''
    conn = None
    try:
        ctx2 = ssl.create_default_context(cafile=SAR + '/ca.crt')
        conn = _hc.HTTPSConnection(h, int(p), context=ctx2, timeout=30)
        conn.connect()
        conn.request('GET', path, headers={
            'Authorization': 'Bearer ' + tok,
            'Connection':    'Upgrade',
            'Upgrade':       'websocket',
            'Sec-WebSocket-Key':      ws_key,
            'Sec-WebSocket-Version':  '13',
            # Offer both protocol variants so clusters that only support one
            # variant will still agree on a subprotocol.
            'Sec-WebSocket-Protocol': 'channel.k8s.io, v4.channel.k8s.io',
        })
        resp = conn.getresponse()
        if resp.status != 101:
            body = resp.read(256)
            diag = 'upgrade_rejected: HTTP {} {}: {}'.format(
                resp.status, resp.reason,
                body.decode(errors='replace').strip()[:150])
            return b'', b'', diag

        # 101 Switching Protocols — WebSocket is active.
        # CRITICAL: read frames via resp.fp (an io.BufferedReader backed by
        # the SSL socket) rather than conn.sock.recv(). http.client may have
        # read ahead during header parsing; those bytes live in resp.fp's
        # internal buffer and would be silently lost by raw sock.recv().
        conn.sock.settimeout(90)
        fp = resp.fp

        buf = b''

        def _fill(n):
            nonlocal buf
            while len(buf) < n:
                try:
                    chunk = fp.read1(65536)
                except Exception:
                    chunk = b''
                if not chunk:
                    break
                buf += chunk

        while True:
            _fill(2)
            if len(buf) < 2:
                break
            opcode = buf[0] & 0x0f
            if opcode == 8:          # WebSocket close frame
                break
            plen = buf[1] & 0x7f
            hlen = 2
            if plen == 126:
                _fill(4)
                if len(buf) < 4:
                    break
                plen = struct.unpack('>H', buf[2:4])[0]
                hlen = 4
            elif plen == 127:
                _fill(10)
                if len(buf) < 10:
                    break
                plen = struct.unpack('>Q', buf[2:10])[0]
                hlen = 10
            total_frame = hlen + plen
            _fill(total_frame)
            if len(buf) < total_frame:
                break
            payload = buf[hlen:total_frame]
            buf = buf[total_frame:]
            # K8s channels: 1=stdout, 2=stderr, 3=process-exit-status
            if payload and opcode in (0x0, 0x1, 0x2):
                ch = payload[0]
                if ch == 1:
                    stdout += payload[1:]
                elif ch == 2:
                    stderr += payload[1:]
                # ch==3: exit-status message — keep looping until close frame
    except Exception as exc:
        diag = 'exc: {}'.format(exc)
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
    return stdout, stderr, diag


def _find_px_pod():
    """Return (namespace, pod_name) of a running portworx storage pod, or (None, None)."""
    # Search order: most common namespaces first. Skip portworx-api pods since
    # those don't have the pxctl binary or full cluster visibility.
    for ns in ('kube-system', 'portworx', 'px', 'openshift-storage', 'portworx-operator'):
        for sel in ('name=portworx', 'app=portworx', 'name=portworx-nss'):
            resp = get('/api/v1/namespaces/{}/pods?labelSelector={}'.format(
                ns, _up.quote(sel)))
            for pod in resp.get('items', []):
                if pod.get('status', {}).get('phase') != 'Running':
                    continue
                # Skip the portworx-api helper pods — they don't have pxctl
                name = pod['metadata']['name']
                if 'api' in name and 'portworx' in name and not name.startswith('portworx-') or name.endswith('-api'):
                    continue
                return ns, name
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
    _raw_out, _raw_err, _exec_diag = _ws_exec(_px_ns, _px_pod, ['/opt/pwx/bin/pxctl', 'status', '--json'])
    # Use stdout if it has content, else fall back to stderr —
    # some pxctl versions write the JSON blob to stderr instead of stdout.
    _raw = _raw_out or _raw_err
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
        pxctl_status = {'_error': 'exec_failed: no output on stdout or stderr from pxctl status --json'
                        + ('; diag: ' + _exec_diag if _exec_diag else '')}
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
