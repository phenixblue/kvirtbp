package bundle_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/phenixblue/kvirtbp/internal/bundle"
)

// buildTarGz writes a minimal .tar.gz archive containing the given files
// (path → content) into a temp file and returns the file path.
func buildTarGz(t *testing.T, topDir string, files map[string]string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "bundle-*.tar.gz")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Top-level wrapper directory (GitHub-style).
	if topDir != "" {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     topDir + "/",
			Mode:     0o750,
		}); err != nil {
			t.Fatalf("write dir header: %v", err)
		}
	}

	for name, content := range files {
		fullName := name
		if topDir != "" {
			fullName = topDir + "/" + name
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     fullName,
			Size:     int64(len(content)),
			Mode:     0o640,
		}); err != nil {
			t.Fatalf("write file header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write file %q: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	return f.Name()
}

// serveFile returns a test HTTP server that serves the file at path.
func serveFile(t *testing.T, path string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	}))
}

// ---- Tests for local paths ----

func TestResolve_LocalPath_NoSubdir(t *testing.T) {
	dir := t.TempDir()
	got, cleanup, err := bundle.Resolve(context.Background(), dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()
	if got != dir {
		t.Errorf("want %q, got %q", dir, got)
	}
}

func TestResolve_LocalPath_WithSubdir(t *testing.T) {
	parent := t.TempDir()
	sub := filepath.Join(parent, "policy", "baseline")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	got, cleanup, err := bundle.Resolve(context.Background(), parent, "policy/baseline")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()
	want := filepath.Join(parent, "policy", "baseline")
	if got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// ---- Tests for remote tarball ----

func TestResolve_RemoteTarball_FlatRoot(t *testing.T) {
	archivePath := buildTarGz(t, "", map[string]string{
		"metadata.json": `{"schemaVersion":"v1alpha1"}`,
		"policy.rego":   `package kvirtbp`,
	})
	srv := serveFile(t, archivePath)
	defer srv.Close()

	dir, cleanup, err := bundle.Resolve(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	if _, statErr := os.Stat(filepath.Join(dir, "metadata.json")); statErr != nil {
		t.Errorf("expected metadata.json in resolved dir %q: %v", dir, statErr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "policy.rego")); statErr != nil {
		t.Errorf("expected policy.rego in resolved dir %q: %v", dir, statErr)
	}
}

func TestResolve_RemoteTarball_GitHubStyleTopDir(t *testing.T) {
	archivePath := buildTarGz(t, "my-repo-v1.0.0", map[string]string{
		"metadata.json": `{"schemaVersion":"v1alpha1"}`,
		"policy.rego":   `package kvirtbp`,
	})
	srv := serveFile(t, archivePath)
	defer srv.Close()

	dir, cleanup, err := bundle.Resolve(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	// The wrapper dir should have been stripped.
	if _, statErr := os.Stat(filepath.Join(dir, "metadata.json")); statErr != nil {
		t.Errorf("expected metadata.json after top-dir strip in %q: %v", dir, statErr)
	}
}

func TestResolve_RemoteTarball_WithSubdir(t *testing.T) {
	archivePath := buildTarGz(t, "my-repo-v1.0.0", map[string]string{
		"policy/baseline/metadata.json": `{"schemaVersion":"v1alpha1"}`,
		"policy/baseline/policy.rego":   `package kvirtbp`,
	})
	srv := serveFile(t, archivePath)
	defer srv.Close()

	dir, cleanup, err := bundle.Resolve(context.Background(), srv.URL, "policy/baseline")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	if _, statErr := os.Stat(filepath.Join(dir, "metadata.json")); statErr != nil {
		t.Errorf("expected metadata.json in subdir %q: %v", dir, statErr)
	}
}

func TestResolve_RemoteTarball_MissingSubdir(t *testing.T) {
	archivePath := buildTarGz(t, "", map[string]string{
		"metadata.json": `{"schemaVersion":"v1alpha1"}`,
	})
	srv := serveFile(t, archivePath)
	defer srv.Close()

	_, cleanup, err := bundle.Resolve(context.Background(), srv.URL, "does/not/exist")
	cleanup() // always call even on error
	if err == nil {
		t.Fatal("expected error for missing subdir, got nil")
	}
}

func TestResolve_RemoteTarball_HTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, cleanup, err := bundle.Resolve(context.Background(), srv.URL, "")
	cleanup()
	if err == nil {
		t.Fatal("expected error for HTTP 404, got nil")
	}
}

func TestResolve_RemoteTarball_ContextCancelled(t *testing.T) {
	// Server that blocks until it is shut down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, cleanup, err := bundle.Resolve(ctx, srv.URL, "")
	cleanup()
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestResolve_CleanupDeletesTempDir(t *testing.T) {
	archivePath := buildTarGz(t, "", map[string]string{
		"metadata.json": `{}`,
	})
	srv := serveFile(t, archivePath)
	defer srv.Close()

	dir, cleanup, err := bundle.Resolve(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify temp dir exists before cleanup.
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("expected temp dir %q to exist before cleanup: %v", dir, statErr)
	}

	cleanup()

	// After cleanup the directory (or its parent temp container) should be gone.
	// The actual resolved dir may be a subdirectory; check the parent temp root.
	parent := filepath.Dir(dir)
	if _, statErr := os.Stat(parent); statErr == nil {
		// parent may legitimately still exist if it is the OS temp dir itself;
		// check that the specific kvirtbp-bundle-* dir is gone.
		if _, statErr2 := os.Stat(dir); statErr2 == nil {
			t.Errorf("expected temp dir %q to be deleted after cleanup", dir)
		}
	}
}
