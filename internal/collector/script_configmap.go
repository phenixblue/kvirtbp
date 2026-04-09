package collector

import (
	"context"
	"fmt"
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phenixblue/kvirtbp/internal/kube"
)

// scriptConfigMapName returns the name of the ConfigMap that holds the
// script files for a collector.
func scriptConfigMapName(collectorName string) string {
	return "kvirtbp-" + sanitizeName(collectorName) + "-scripts"
}

// scriptDataKey converts a script mount path to a valid ConfigMap data key.
// e.g. "/scripts/collect.py" → "scripts_collect.py"
func scriptDataKey(mountPath string) string {
	// Replace path separators with underscores; preserve the file extension.
	base := path.Base(mountPath)
	dir := path.Dir(mountPath)
	if dir == "." || dir == "/" {
		return base
	}
	prefix := strings.ReplaceAll(strings.Trim(dir, "/"), "/", "_")
	return prefix + "_" + base
}

// ensureScriptConfigMap creates (or silently accepts when already present) a
// ConfigMap containing the content of all scripts in the slice. It returns the
// ConfigMap name to wire into the Job pod spec as a volume source.
//
// Only scripts with non-empty Content are included; scripts without content
// are skipped (e.g. when the config was loaded from a --collector-config file
// that does not embed script text).
func ensureScriptConfigMap(ctx context.Context, clients *kube.Clients, collectorName, namespace string, scripts []CollectorScript) (string, error) {
	name := scriptConfigMapName(collectorName)
	data := make(map[string]string, len(scripts))
	for _, s := range scripts {
		if s.Content == "" {
			continue
		}
		data[scriptDataKey(s.MountPath)] = s.Content
	}
	if len(data) == 0 {
		return "", nil
	}

	labels := map[string]string{
		jobLabelKey:      jobLabelVal,
		"collector-name": collectorName,
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Data: data,
	}

	if _, err := clients.Core.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create script configmap %q: %w", name, err)
	}

	return name, nil
}

// cleanupScriptConfigMap deletes the ConfigMap created by ensureScriptConfigMap.
// Errors are silently ignored.
func cleanupScriptConfigMap(ctx context.Context, clients *kube.Clients, collectorName, namespace string) {
	name := scriptConfigMapName(collectorName)
	_ = clients.Core.CoreV1().ConfigMaps(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}
