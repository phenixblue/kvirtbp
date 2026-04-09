package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/phenixblue/kvirtbp/internal/kube"
)

const (
	jobPollInterval = 5 * time.Second

	// jobLabelKey is applied to every Job and its Pod template so they can be
	// listed/cleaned up as a group.
	jobLabelKey = "app.kubernetes.io/managed-by"
	jobLabelVal = "kvirtbp-collector"
)

// jobCollector is the default Collector implementation. It creates batch/v1
// Jobs on the target cluster to gather node or cluster-scoped data.
type jobCollector struct {
	cfg CollectorConfig
}

// NewJobCollector returns a Collector that executes cfg via Kubernetes Jobs.
func NewJobCollector(cfg CollectorConfig) Collector {
	return &jobCollector{cfg: cfg}
}

func (c *jobCollector) Name() string { return c.cfg.Name }

// Collect executes the collector. For ScopeOnce a single Job is deployed.
// For ScopePerNode one Job per node is deployed concurrently. Results are
// merged under the returned map keyed by node name or CollectorDataScope.
func (c *jobCollector) Collect(ctx context.Context, clients *kube.Clients, opts RunOptions) (map[string]any, error) {
	timeout := opts.GlobalTimeout
	if c.cfg.TimeoutSeconds > 0 {
		perCollector := time.Duration(c.cfg.TimeoutSeconds) * time.Second
		if timeout == 0 || perCollector < timeout {
			timeout = perCollector
		}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// If the collector declares RBAC rules, create the ServiceAccount,
	// ClusterRole, and ClusterRoleBinding before launching Jobs, and clean
	// them up afterwards (unless SkipCleanup is set).
	var saName string
	if c.cfg.RBAC != nil {
		name, err := ensureCollectorRBAC(ctx, clients, c.cfg.Name, opts.Namespace, *c.cfg.RBAC)
		if err != nil {
			return nil, fmt.Errorf("ensure RBAC for collector %q: %w", c.cfg.Name, err)
		}
		saName = name
		if !opts.SkipCleanup {
			defer cleanupCollectorRBAC(context.Background(), clients, c.cfg.Name, opts.Namespace)
		}
	}

	// If the collector declares scripts, create a ConfigMap from their
	// content and mount it into the Job pod. Clean up afterwards unless
	// SkipCleanup is set.
	var cmName string
	if len(c.cfg.Scripts) > 0 {
		name, err := ensureScriptConfigMap(ctx, clients, c.cfg.Name, opts.Namespace, c.cfg.Scripts)
		if err != nil {
			return nil, fmt.Errorf("ensure script configmap for collector %q: %w", c.cfg.Name, err)
		}
		if name != "" {
			cmName = name
			if !opts.SkipCleanup {
				defer cleanupScriptConfigMap(context.Background(), clients, c.cfg.Name, opts.Namespace)
			}
		}
	}

	switch c.cfg.Scope {
	case ScopePerNode:
		return c.collectPerNode(ctx, clients, opts, saName, cmName)
	default: // ScopeOnce and empty string both go here
		return c.collectOnce(ctx, clients, opts, saName, cmName)
	}
}

// collectOnce deploys a single Job and stores the result under "_cluster".
func (c *jobCollector) collectOnce(ctx context.Context, clients *kube.Clients, opts RunOptions, saName, cmName string) (map[string]any, error) {
	jobName := safeJobName(c.cfg.Name, "")

	data, err := c.runJob(ctx, clients, opts, jobName, "", saName, cmName)
	if err != nil {
		return map[string]any{CollectorDataScope: map[string]any{"_error": err.Error()}}, nil
	}
	return map[string]any{CollectorDataScope: data}, nil
}

// collectPerNode lists all schedulable nodes and deploys one Job per node
// concurrently. Results are keyed by node name.
func (c *jobCollector) collectPerNode(ctx context.Context, clients *kube.Clients, opts RunOptions, saName, cmName string) (map[string]any, error) {
	nodeList, err := clients.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		result = make(map[string]any, len(nodeList.Items))
	)

	for _, node := range nodeList.Items {
		nodeName := node.Name
		wg.Add(1)
		go func() {
			defer wg.Done()
			jobName := safeJobName(c.cfg.Name, nodeName)
			data, err := c.runJob(ctx, clients, opts, jobName, nodeName, saName, cmName)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				result[nodeName] = map[string]any{"_error": err.Error()}
			} else {
				result[nodeName] = data
			}
		}()
	}
	wg.Wait()
	return result, nil
}

// runJob creates a Job, waits for it to complete, reads its logs, optionally
// deletes it, and returns the parsed JSON output.
func (c *jobCollector) runJob(ctx context.Context, clients *kube.Clients, opts RunOptions, jobName, nodeName, saName, cmName string) (map[string]any, error) {
	job := c.buildJob(jobName, nodeName, opts.Namespace, saName, cmName)

	if _, err := clients.Core.BatchV1().Jobs(opts.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("create job %q: %w", jobName, err)
	}

	if !opts.SkipCleanup {
		defer func() {
			bg := context.Background()
			prop := metav1.DeletePropagationForeground
			_ = clients.Core.BatchV1().Jobs(opts.Namespace).Delete(bg, jobName, metav1.DeleteOptions{
				PropagationPolicy: &prop,
			})
		}()
	}

	if err := waitForJobComplete(ctx, clients, opts.Namespace, jobName); err != nil {
		return nil, fmt.Errorf("wait for job %q: %w", jobName, err)
	}

	output, err := readJobLogs(ctx, clients, opts.Namespace, jobName)
	if err != nil {
		return nil, fmt.Errorf("read logs for job %q: %w", jobName, err)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("parse JSON output from job %q: %w", jobName, err)
	}
	return result, nil
}

// buildJob constructs the batch/v1 Job spec for the collector config.
// saName is the ServiceAccount name to assign to the pod; empty string leaves
// the pod using the namespace default ServiceAccount.
// cmName is the name of the ConfigMap holding script files; empty string means
// no scripts are mounted.
func (c *jobCollector) buildJob(jobName, nodeName, namespace, saName, cmName string) *batchv1.Job {
	outputPath := c.cfg.ResolvedOutputPath()

	// Build the command list: mkdir for the output dir, user commands, then
	// "cat <outputPath>".  The mkdir ensures the output directory exists even
	// in minimal images (e.g. alpine) that don't ship /kvirtbp/.
	// The cat output is the only thing that appears as pod logs; user commands
	// may write freely to stdout/stderr without polluting the JSON payload.
	outputDir := path.Dir(outputPath)
	commands := make([]string, 0, len(c.cfg.Commands)+2)
	commands = append(commands, "mkdir -p "+outputDir)
	commands = append(commands, c.cfg.Commands...)
	commands = append(commands, "cat "+outputPath)

	// Join with && so the cat only runs if all prior commands succeed.
	shellCmd := strings.Join(commands, " && ")

	var ttlSeconds int32 = 300 // clean up completed jobs after 5 min even if SkipCleanup=false
	var backoffLimit int32 = 0 // never retry; surface failures immediately

	env := make([]corev1.EnvVar, 0, len(c.cfg.Env))
	for k, v := range c.cfg.Env {
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}

	privileged := c.cfg.Privileged

	// If scripts are declared and a ConfigMap was created, mount each script
	// into the container at its declared MountPath via a subPath volume mount.
	var volumeMounts []corev1.VolumeMount
	var volumes []corev1.Volume
	if cmName != "" && len(c.cfg.Scripts) > 0 {
		volumes = append(volumes, corev1.Volume{
			Name: "collector-scripts",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: cmName},
				},
			},
		})
		for _, s := range c.cfg.Scripts {
			if s.Content == "" {
				continue
			}
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      "collector-scripts",
				MountPath: s.MountPath,
				SubPath:   scriptDataKey(s.MountPath),
				ReadOnly:  true,
			})
		}
	}

	container := corev1.Container{
		Name:         "collector",
		Image:        c.cfg.Image,
		Command:      []string{"/bin/sh", "-c", shellCmd},
		Env:          env,
		VolumeMounts: volumeMounts,
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
		},
	}

	podSpec := corev1.PodSpec{
		Volumes:            volumes,
		Containers:         []corev1.Container{container},
		RestartPolicy:      corev1.RestartPolicyNever,
		HostPID:            c.cfg.HostPID,
		HostNetwork:        c.cfg.HostNetwork,
		Tolerations:        toK8sTolerations(c.cfg.Tolerations),
		ServiceAccountName: saName,
	}

	if nodeName != "" {
		podSpec.NodeName = nodeName
	}

	labels := map[string]string{
		jobLabelKey:      jobLabelVal,
		"collector-name": c.cfg.Name,
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoffLimit,
			TTLSecondsAfterFinished: &ttlSeconds,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       podSpec,
			},
		},
	}
	return job
}

// waitForJobComplete polls the Job until it has a Complete or Failed condition.
func waitForJobComplete(ctx context.Context, clients *kube.Clients, namespace, jobName string) error {
	return wait.PollUntilContextCancel(ctx, jobPollInterval, true, func(ctx context.Context) (bool, error) {
		job, err := clients.Core.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("get job %q: %w", jobName, err)
		}
		for _, cond := range job.Status.Conditions {
			if cond.Type == batchv1.JobComplete && cond.Status == corev1.ConditionTrue {
				return true, nil
			}
			if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
				return false, fmt.Errorf("job %q failed: %s", jobName, cond.Message)
			}
		}
		return false, nil
	})
}

// readJobLogs fetches the stdout logs from the first (and only) Pod of the Job.
// The last line of stdout is expected to be the JSON output produced by
// "cat <outputPath>".
func readJobLogs(ctx context.Context, clients *kube.Clients, namespace, jobName string) (string, error) {
	podList, err := clients.Core.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	})
	if err != nil {
		return "", fmt.Errorf("list pods for job %q: %w", jobName, err)
	}
	if len(podList.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %q", jobName)
	}

	podName := podList.Items[0].Name
	req := clients.Core.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{})
	rc, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs for pod %q: %w", podName, err)
	}
	defer rc.Close()

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := rc.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}

	// The last non-empty line is the cat output (our JSON).
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("pod %q produced no output", podName)
}

// safeJobName builds a Kubernetes-safe Job name from the collector name and an
// optional node name. Names are truncated to 63 characters if necessary.
func safeJobName(collectorName, nodeName string) string {
	base := "kvirtbp-" + sanitizeName(collectorName)
	if nodeName != "" {
		base = base + "-" + sanitizeName(nodeName)
	}
	if len(base) > 63 {
		base = base[:63]
	}
	return strings.TrimRight(base, "-")
}

// toK8sTolerations converts the config-level CollectorToleration slice to
// the corev1.Toleration type expected by the pod spec.
func toK8sTolerations(in []CollectorToleration) []corev1.Toleration {
	if len(in) == 0 {
		return nil
	}
	out := make([]corev1.Toleration, len(in))
	for i, t := range in {
		out[i] = corev1.Toleration{
			Key:      t.Key,
			Operator: corev1.TolerationOperator(t.Operator),
			Value:    t.Value,
			Effect:   corev1.TaintEffect(t.Effect),
		}
	}
	return out
}

// sanitizeName replaces characters that are not valid in Kubernetes names with
// hyphens and lower-cases the result.
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
