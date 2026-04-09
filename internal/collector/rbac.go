package collector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phenixblue/kvirtbp/internal/kube"
)

// rbacResourceName returns the shared name for the ServiceAccount, ClusterRole,
// and ClusterRoleBinding that the framework creates for a collector.
func rbacResourceName(collectorName string) string {
	return "kvirtbp-" + sanitizeName(collectorName)
}

// ensureCollectorRBAC creates (or no-ops when already present) the
// ServiceAccount, ClusterRole, and ClusterRoleBinding for the collector.
// It returns the ServiceAccount name to wire into the Job pod spec.
func ensureCollectorRBAC(ctx context.Context, clients *kube.Clients, collectorName, namespace string, rbac CollectorRBAC) (string, error) {
	name := rbacResourceName(collectorName)
	labels := map[string]string{
		jobLabelKey:      jobLabelVal,
		"collector-name": collectorName,
	}

	// ServiceAccount — namespaced, created in the collector namespace.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
	}
	if _, err := clients.Core.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create service account %q: %w", name, err)
	}

	// ClusterRole — cluster-scoped; holds the policy rules from the config.
	// If the role already exists (e.g. from a previous run), update its rules
	// so that any newly-added permissions take effect immediately.
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Rules: toK8sPolicyRules(rbac.Rules),
	}
	_, err := clients.Core.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		_, err = clients.Core.RbacV1().ClusterRoles().Update(ctx, cr, metav1.UpdateOptions{})
	}
	if err != nil {
		return "", fmt.Errorf("ensure cluster role %q: %w", name, err)
	}

	// ClusterRoleBinding — binds the SA to the ClusterRole.
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: namespace,
			},
		},
	}
	if _, err := clients.Core.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create cluster role binding %q: %w", name, err)
	}

	return name, nil
}

// cleanupCollectorRBAC deletes the ServiceAccount, ClusterRole, and
// ClusterRoleBinding created by ensureCollectorRBAC. Errors are silently
// ignored — resources may already be gone or may never have existed.
func cleanupCollectorRBAC(ctx context.Context, clients *kube.Clients, collectorName, namespace string) {
	name := rbacResourceName(collectorName)
	_ = clients.Core.CoreV1().ServiceAccounts(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	_ = clients.Core.RbacV1().ClusterRoles().Delete(ctx, name, metav1.DeleteOptions{})
	_ = clients.Core.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
}

// toK8sPolicyRules converts CollectorPolicyRule slice to rbacv1.PolicyRule.
func toK8sPolicyRules(in []CollectorPolicyRule) []rbacv1.PolicyRule {
	out := make([]rbacv1.PolicyRule, len(in))
	for i, r := range in {
		out[i] = rbacv1.PolicyRule{
			APIGroups: r.APIGroups,
			Resources: r.Resources,
			Verbs:     r.Verbs,
		}
	}
	return out
}
