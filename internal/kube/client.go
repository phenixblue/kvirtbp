package kube

import (
	"fmt"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Options struct {
	KubeconfigPath string
	Context        string
}

type Clients struct {
	Config    *rest.Config
	Discovery discovery.DiscoveryInterface
	Core      kubernetes.Interface
}

func NewClients(opts Options) (*Clients, error) {
	cfg, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}

	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return &Clients{
		Config:    cfg,
		Discovery: core.Discovery(),
		Core:      core,
	}, nil
}

func buildConfig(opts Options) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.KubeconfigPath != "" {
		loadingRules.ExplicitPath = opts.KubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}

	clientCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	cfg, err := clientCfg.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	return cfg, nil
}
