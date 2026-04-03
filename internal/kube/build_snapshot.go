package kube

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// BuildClusterSnapshot fetches all cluster resources needed for preflight
// checks and returns them as a serializable ClusterSnapshot.
// Errors fetching individual resource types are recorded in the snapshot
// rather than returned, so callers always receive a partial snapshot.
func BuildClusterSnapshot(ctx context.Context, clients *Clients, opts PreflightOptions) ClusterSnapshot {
	snap := ClusterSnapshot{
		NamespaceInclude: append([]string(nil), opts.IncludeNamespaces...),
		NamespaceExclude: append([]string(nil), opts.ExcludeNamespaces...),
	}

	// API discovery
	cap, err := DiscoverCapabilities(ctx, clients.Discovery)
	if err != nil {
		snap.DiscoveryError = err.Error()
		return snap
	}
	snap.KubeVirtInstalled = cap.KubeVirtInstalled
	snap.HasNetworkingV1 = cap.HasNetworkingV1
	snap.HasPolicyV1 = cap.HasPolicyV1
	snap.ServerVersion = cap.ServerVersion

	// Deployments in kubevirt namespace
	deps, err := clients.Core.AppsV1().Deployments("kubevirt").List(ctx, metav1.ListOptions{})
	if err != nil {
		snap.DeploymentsError = err.Error()
	} else {
		snap.KubeVirtDeployments = make([]DeploymentSnapshot, 0, len(deps.Items))
		for _, d := range deps.Items {
			snap.KubeVirtDeployments = append(snap.KubeVirtDeployments, DeploymentSnapshot{
				Name:              d.Name,
				Namespace:         d.Namespace,
				AvailableReplicas: d.Status.AvailableReplicas,
			})
		}
	}

	// Nodes
	nodes, err := clients.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		snap.NodesError = err.Error()
	} else {
		snap.Nodes = make([]NodeSnapshot, 0, len(nodes.Items))
		for _, n := range nodes.Items {
			_, isCP := n.Labels["node-role.kubernetes.io/control-plane"]
			if !isCP {
				_, isCP = n.Labels["node-role.kubernetes.io/master"]
			}
			ready := false
			for _, c := range n.Status.Conditions {
				if string(c.Type) == "Ready" && string(c.Status) == "True" {
					ready = true
					break
				}
			}
			snap.Nodes = append(snap.Nodes, NodeSnapshot{
				Name:         n.Name,
				ControlPlane: isCP,
				Ready:        ready,
			})
		}
	}

	// Namespaces
	namespaces, err := clients.Core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		snap.NamespacesError = err.Error()
	} else {
		snap.Namespaces = make([]NamespaceSnapshot, 0, len(namespaces.Items))
		for _, ns := range namespaces.Items {
			labels := make(map[string]string, len(ns.Labels))
			for k, v := range ns.Labels {
				labels[k] = v
			}
			snap.Namespaces = append(snap.Namespaces, NamespaceSnapshot{
				Name:   ns.Name,
				Phase:  string(ns.Status.Phase),
				Labels: labels,
			})
		}

		// NetworkPolicies
		nps, err := clients.Core.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			snap.NetworkPoliciesError = err.Error()
		} else {
			snap.NetworkPolicies = make([]NetworkPolicySnapshot, 0, len(nps.Items))
			for _, np := range nps.Items {
				snap.NetworkPolicies = append(snap.NetworkPolicies, NetworkPolicySnapshot{
					Name:      np.Name,
					Namespace: np.Namespace,
				})
			}
		}

		// ResourceQuotas
		rqs, err := clients.Core.CoreV1().ResourceQuotas("").List(ctx, metav1.ListOptions{})
		if err != nil {
			snap.ResourceQuotasError = err.Error()
		} else {
			snap.ResourceQuotas = make([]ResourceQuotaSnapshot, 0, len(rqs.Items))
			for _, rq := range rqs.Items {
				snap.ResourceQuotas = append(snap.ResourceQuotas, ResourceQuotaSnapshot{
					Name:      rq.Name,
					Namespace: rq.Namespace,
				})
			}
		}

		// LimitRanges
		lrs, err := clients.Core.CoreV1().LimitRanges("").List(ctx, metav1.ListOptions{})
		if err != nil {
			snap.LimitRangesError = err.Error()
		} else {
			snap.LimitRanges = make([]LimitRangeSnapshot, 0, len(lrs.Items))
			for _, lr := range lrs.Items {
				snap.LimitRanges = append(snap.LimitRanges, LimitRangeSnapshot{
					Name:      lr.Name,
					Namespace: lr.Namespace,
				})
			}
		}

		// PodDisruptionBudgets
		pdbs, err := clients.Core.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			snap.PodDisruptionBudgetsError = err.Error()
		} else {
			snap.PodDisruptionBudgets = make([]PDBSnapshot, 0, len(pdbs.Items))
			for _, pdb := range pdbs.Items {
				snap.PodDisruptionBudgets = append(snap.PodDisruptionBudgets, PDBSnapshot{
					Name:      pdb.Name,
					Namespace: pdb.Namespace,
				})
			}
		}
	}

	// Permission probes
	probes := defaultPermissionProbes()
	snap.Permissions = make([]PermissionSnapshot, 0, len(probes))
	for _, p := range probes {
		allowed, reason, err := canI(ctx, clients, p)
		ps := PermissionSnapshot{
			ID:       p.ID,
			Resource: p.Resource,
			Group:    p.Group,
			Verb:     p.Verb,
			Allowed:  allowed,
		}
		if err != nil {
			ps.Error = err.Error()
		} else {
			ps.Reason = reason
		}
		snap.Permissions = append(snap.Permissions, ps)
	}

	// Dynamic resource types requested via bundle metadata or --resource flag.
	if len(opts.ResourceTypes) > 0 {
		snap.Resources = fetchResources(ctx, clients, opts.ResourceTypes)
	}

	return snap
}

// DegradedSnapshot returns a minimal snapshot representing a cluster that
// could not be reached (no Kubernetes clients available).
func DegradedSnapshot(opts PreflightOptions) ClusterSnapshot {
	return ClusterSnapshot{
		Degraded:         true,
		DiscoveryError:   "Kubernetes client is unavailable; scan is running in degraded mode.",
		NamespaceInclude: append([]string(nil), opts.IncludeNamespaces...),
		NamespaceExclude: append([]string(nil), opts.ExcludeNamespaces...),
	}
}

// fetchResources fetches the requested resource types using the dynamic client
// and returns them as a map keyed by the canonical type string.
// Fetch errors for individual types are stored as a single sentinel entry
// {name: "<error>", namespace: "<error>"} so Rego policies can detect failure
// without the whole snapshot being invalidated.
func fetchResources(ctx context.Context, clients *Clients, resourceTypes []string) map[string][]ResourceSnapshot {
	result := make(map[string][]ResourceSnapshot, len(resourceTypes))
	for _, rt := range resourceTypes {
		gvr, err := parseResourceType(rt)
		if err != nil {
			result[rt] = []ResourceSnapshot{{Name: fmt.Sprintf("<error: %s>", err.Error())}}
			continue
		}
		list, err := clients.Dynamic.Resource(gvr).Namespace("").List(ctx, metav1.ListOptions{})
		if err != nil {
			result[rt] = []ResourceSnapshot{{Name: fmt.Sprintf("<error: %s>", err.Error())}}
			continue
		}
		snaps := make([]ResourceSnapshot, 0, len(list.Items))
		for _, obj := range list.Items {
			rs := ResourceSnapshot{
				Name:      obj.GetName(),
				Namespace: obj.GetNamespace(),
			}
			if l := obj.GetLabels(); len(l) > 0 {
				rs.Labels = l
			}
			if a := obj.GetAnnotations(); len(a) > 0 {
				rs.Annotations = a
			}
			snaps = append(snaps, rs)
		}
		result[rt] = snaps
	}
	return result
}

// parseResourceType parses a resource type string in one of these forms:
//   - "VERSION/RESOURCE"                  (core, e.g. "v1/configmaps")
//   - "GROUP/VERSION/RESOURCE"       (grouped, e.g. "apps/v1/deployments", "kubevirt.io/v1/virtualmachines")
//
// RESOURCE must be the plural API resource path name (as used in Kubernetes REST URLs),
// e.g. "configmaps" not "ConfigMap", "deployments" not "Deployment".
func parseResourceType(rt string) (schema.GroupVersionResource, error) {
	parts := strings.Split(rt, "/")
	switch len(parts) {
	case 2:
		// "VERSION/RESOURCE" — core API (empty group)
		return schema.GroupVersionResource{Group: "", Version: parts[0], Resource: strings.ToLower(parts[1])}, nil
	case 3:
		// "GROUP/VERSION/RESOURCE"
		return schema.GroupVersionResource{Group: parts[0], Version: parts[1], Resource: strings.ToLower(parts[2])}, nil
	default:
		return schema.GroupVersionResource{}, fmt.Errorf("invalid resource type %q: expected \"VERSION/RESOURCE\" or \"GROUP/VERSION/RESOURCE\"", rt)
	}
}

func defaultPermissionProbes() []permissionProbe {
	return []permissionProbe{
		{ID: "perm-list-nodes", Group: "", Resource: "nodes", Verb: "list"},
		{ID: "perm-list-namespaces", Group: "", Resource: "namespaces", Verb: "list"},
		{ID: "perm-list-vms", Group: "kubevirt.io", Resource: "virtualmachines", Verb: "list"},
	}
}


