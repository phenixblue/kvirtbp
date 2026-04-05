// Package bundle resolves a policy bundle path to a local directory.
// Paths that start with "http://" or "https://" are treated as remote tarballs
// (gzip-compressed tar archives) and are downloaded to a temporary directory.
// Local paths are returned unchanged.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Resolve returns the local directory path for the bundle at rawPath.
//
// If rawPath is a local filesystem path it is returned as-is and cleanup is a
// no-op. If rawPath starts with "http://" or "https://" the tarball is
// downloaded, unpacked into a temporary directory, and cleanup deletes that
// directory. The caller must always call cleanup() when done.
//
// subdir is an optional subdirectory within the archive root that contains the
// bundle's metadata.json (useful for monorepos where the bundle lives under
// e.g. "policy/baseline"). When empty the archive root is used.
func Resolve(ctx context.Context, rawPath, subdir string) (dir string, cleanup func(), err error) {
	noop := func() {}

	if !isURL(rawPath) {
		if subdir != "" {
			return filepath.Join(rawPath, subdir), noop, nil
		}
		return rawPath, noop, nil
	}

	tmpDir, err := os.MkdirTemp("", "kvirtbp-bundle-*")
	if err != nil {
		return "", noop, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmpDir) }

	if err := fetchAndUnpack(ctx, rawPath, tmpDir); err != nil {
		cleanup()
		return "", noop, fmt.Errorf("fetch bundle %q: %w", rawPath, err)
	}

	// GitHub and most Git hosting platforms wrap the archive contents in a
	// single top-level directory (e.g. "repo-v1.2.0/"). Strip it so that
	// tmpDir itself — or tmpDir/subdir — contains the bundle files.
	stripped, err := stripTopDir(tmpDir)
	if err != nil {
		cleanup()
		return "", noop, err
	}

	if subdir != "" {
		stripped = filepath.Join(stripped, subdir)
	}

	// Verify the resolved directory exists in the unpacked archive.
	if _, statErr := os.Stat(stripped); statErr != nil {
		cleanup()
		return "", noop, fmt.Errorf("bundle subdir %q not found in archive", stripped)
	}

	return stripped, cleanup, nil
}

// isURL returns true when s looks like an http or https URL.
func isURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// fetchAndUnpack downloads a .tar.gz archive from rawURL and extracts it into
// destDir. Only regular files and directories are extracted; symlinks,
// hard-links, and device files are skipped for security.
func fetchAndUnpack(ctx context.Context, rawURL, destDir string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "kvirtbp")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		// Security: reject any path that would escape destDir.
		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") {
			return fmt.Errorf("archive contains unsafe path %q", hdr.Name)
		}

		target := filepath.Join(destDir, cleanName)

		// Ensure the resolved path is still inside destDir.
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("archive path %q escapes destination", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return fmt.Errorf("create dir %q: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return fmt.Errorf("create parent dir for %q: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("create file %q: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil { //nolint:gosec // size bounded by server
				f.Close()
				return fmt.Errorf("write file %q: %w", target, err)
			}
			f.Close()
			// Intentionally skip symlinks, hard-links, and special files.
		}
	}

	return nil
}

// stripTopDir checks whether all entries inside dir share a single common
// top-level subdirectory (the GitHub-style wrapper directory). If they do it
// returns that subdirectory path. If the bundle is already flat it returns dir
// unchanged.
func stripTopDir(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read temp dir: %w", err)
	}

	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(dir, entries[0].Name()), nil
	}
	return dir, nil
}

// SubBundles returns the bundle directory paths within dir.
//
// If dir itself contains a metadata.json it is considered a single bundle and
// returned as a one-element slice. Otherwise every immediate subdirectory of
// dir that contains a metadata.json is returned in sorted (alphabetical) order.
// Returns nil (no error) when no bundles are found.
func SubBundles(dir string) ([]string, error) {
	// Check whether dir itself is a bundle.
	if _, err := os.Stat(filepath.Join(dir, "metadata.json")); err == nil {
		return []string{dir}, nil
	}

	// Otherwise scan for bundle subdirectories.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read bundle directory %q: %w", dir, err)
	}
	var bundles []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		if _, statErr := os.Stat(filepath.Join(sub, "metadata.json")); statErr == nil {
			bundles = append(bundles, sub)
		}
	}
	sort.Strings(bundles)
	return bundles, nil
}

// SaveDir copies the bundle directory at src to dst, creating dst if needed.
// It performs a recursive copy of all regular files and directories; symlinks
// and special files are skipped. dst must not already exist.
func SaveDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}

		if !info.Mode().IsRegular() {
			return nil // skip symlinks, device files, etc.
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()

		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode()&0o777)
		if err != nil {
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, in)
		return err
	})
}
