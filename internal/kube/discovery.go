package kube

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
)

type Capabilities struct {
	KubeVirtInstalled bool
	HasPolicyV1       bool
	HasNetworkingV1   bool
	ServerVersion     string
}

func DiscoverCapabilities(ctx context.Context, dc discovery.DiscoveryInterface) (Capabilities, error) {
	groups, err := dc.ServerGroups()
	if err != nil {
		return Capabilities{}, fmt.Errorf("discover server groups: %w", err)
	}

	cap := Capabilities{}
	for _, g := range groups.Groups {
		switch g.Name {
		case "kubevirt.io":
			cap.KubeVirtInstalled = true
		case "policy":
			cap.HasPolicyV1 = hasVersion(g.Versions, "v1")
		case "networking.k8s.io":
			cap.HasNetworkingV1 = hasVersion(g.Versions, "v1")
		}
	}

	if v, err := dc.ServerVersion(); err == nil && v != nil {
		cap.ServerVersion = v.String()
	}

	_ = ctx
	return cap, nil
}

func hasVersion(versions []metav1.GroupVersionForDiscovery, expected string) bool {
	for _, v := range versions {
		if v.Version == expected {
			return true
		}
	}
	return false
}
