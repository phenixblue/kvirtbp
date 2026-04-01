package kube

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHasVersion(t *testing.T) {
	versions := []metav1.GroupVersionForDiscovery{
		{Version: "v1beta1"},
		{Version: "v1"},
	}

	if !hasVersion(versions, "v1") {
		t.Fatal("expected v1 to be detected")
	}
	if hasVersion(versions, "v2") {
		t.Fatal("did not expect v2 to be detected")
	}
}
