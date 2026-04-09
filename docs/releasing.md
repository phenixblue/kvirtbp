# Release Process

This document describes how to cut a versioned release of `kvirtbp`.

Releases are fully automated via [GoReleaser](https://goreleaser.com/) and GitHub Actions. The only manual steps are preparing the changelog, tagging the commit, and pushing the tag.

---

## Prerequisites

- Write access to the `phenixblue/kvirtbp` repository (push tags).
- `git` and `gh` (GitHub CLI) installed locally.
- Optionally `goreleaser` installed locally for dry-run validation.

---

## Versioning scheme

`kvirtbp` uses [Semantic Versioning](https://semver.org/):

```
vMAJOR.MINOR.PATCH[-rcN]
```

- Pre-releases use a `-rcN` suffix (e.g. `v0.2.0-rc1`). GoReleaser marks these as pre-releases automatically.
- A tag without a suffix (e.g. `v0.2.0`) is a stable release.

---

## Step-by-step

### 1. Choose the next version

Check the most recent tag:

```bash
git fetch --tags
git tag --sort=-v:refname | head -5
```

Decide the next version following semver — bump `PATCH` for bug fixes, `MINOR` for new features/checks, `MAJOR` for breaking changes.

### 2. Prepare the release branch (optional for RCs)

For a minor or major release it is good practice to branch off `main` and do any final cleanup there first. Skip this step for a patch-only or RC release directly off `main`.

```bash
git checkout main && git pull
git checkout -b release/v0.2.0
# ... any final fixes ...
git push -u origin release/v0.2.0
# open a PR → merge to main before tagging
```

### 3. Verify the build locally

```bash
# Full test suite
make test
opa test examples/collectors/portworx-kubevirt/ -v

# Dry-run the GoReleaser pipeline (no publish, no sign)
make release-local
```

`make release-local` produces archives under `dist/` so you can inspect the binaries before tagging.

### 4. Tag the release

```bash
git checkout main && git pull

# Replace with the actual version
VERSION=v0.2.0

git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"
```

Pushing the tag triggers the `release` GitHub Actions workflow, which:

1. Runs `go test ./...` and the OPA test suite.
2. Builds cross-platform binaries (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`).
3. Creates `tar.gz`/`zip` archives and a `checksums.txt`.
4. Generates an SBOM for each archive.
5. Signs `checksums.txt` with `cosign`.
6. Creates a GitHub Release (draft: false; pre-release: auto for `-rcN` tags).
7. Updates the [homebrew-tap](https://github.com/phenixblue/homebrew-tap) formula for stable releases.

### 5. Verify the GitHub Release

Once the workflow completes:

1. Open the [Releases page](https://github.com/phenixblue/kvirtbp/releases) and confirm all assets are attached.
2. Check that `checksums.txt` and its `.sig`/`.pem` files are present.
3. For a stable release, confirm the homebrew-tap PR was opened (or merged automatically).

### 6. Announce (stable releases only)

Update any external documentation or changelog entries as needed.

---

## Rolling back a bad tag

If the tag was pushed but the release workflow has not completed (or produced bad artifacts), delete the tag and re-tag after fixing the issue:

```bash
# Delete locally and remotely
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
```

If the GitHub Release was already published, delete it in the GitHub UI before re-pushing the tag.

---

## Makefile reference

| Target | Description |
|---|---|
| `make release-snapshot` | GoReleaser snapshot — builds all platforms, skips publish and signing |
| `make release-local` | GoReleaser snapshot — skips publish and signing (alias for local use) |
| `make test` | `go test ./...` |
| `make rego-test` | OPA unit tests for built-in policies |
