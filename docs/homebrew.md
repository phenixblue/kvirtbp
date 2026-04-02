# Homebrew Usage

`kvirtbp` is distributed via a Homebrew tap for macOS and Linux users.

## Install

Add the tap and install:

```bash
brew tap phenixblue/tap
brew install kvirtbp
```

Verify:

```bash
kvirtbp version
```

## Upgrade

```bash
brew update
brew upgrade kvirtbp
```

Or upgrade only the tap formulae:

```bash
brew upgrade phenixblue/tap/kvirtbp
```

## Uninstall

```bash
brew uninstall kvirtbp
```

To also remove the tap:

```bash
brew untap phenixblue/tap
```

## Pin a specific version

Prevent a release from being upgraded automatically:

```bash
brew pin kvirtbp
```

To unpin later:

```bash
brew unpin kvirtbp
```

## Install a specific release

Homebrew formulae track the latest release in the tap. To install a specific version, download the archive directly from the [GitHub Releases](https://github.com/phenixblue/kvirtbp/releases) page and use `go install` or extract the binary manually.

## Verify release integrity

Each release ships a `checksums.txt` and per-archive SBOM. To verify a downloaded archive:

```bash
# Download the archive and checksum file from the GitHub release
curl -LO https://github.com/phenixblue/kvirtbp/releases/download/v0.1.0/kvirtbp_Darwin_arm64.tar.gz
curl -LO https://github.com/phenixblue/kvirtbp/releases/download/v0.1.0/checksums.txt

# Verify the archive against the checksum
sha256sum --check --ignore-missing checksums.txt
```

Cosign is used to sign `checksums.txt` in CI. To verify the signature:

```bash
cosign verify-blob \
  --certificate-identity-regexp "https://github.com/phenixblue/kvirtbp/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig \
  checksums.txt
```

## Tap maintenance

### Formula location

The Homebrew formula is automatically published to [`phenixblue/homebrew-tap`](https://github.com/phenixblue/homebrew-tap) by GoReleaser when a `v*` tag is pushed to this repository. No manual formula updates are required.

### Prerequisites for publishing

- The tap repository (`phenixblue/homebrew-tap`) must exist and be accessible.
- The GitHub Actions secret `HOMEBREW_TAP_GITHUB_TOKEN` must be set in this repository with write access to the tap repo.

### Test formula generation locally

Generate the Homebrew formula without publishing:

```bash
make release-local
```

The generated formula appears in `dist/homebrew/`. Inspect it before tagging a release.

### Troubleshooting a failed tap publish

If GoReleaser fails to push the formula:

1. Check that `HOMEBREW_TAP_GITHUB_TOKEN` is set and has `repo` scope on `phenixblue/homebrew-tap`.
2. Confirm the tap repository exists and the default branch is `main`.
3. Re-run `make release-local` and inspect `dist/homebrew/<formula>.rb` for template errors.
4. Review the GoReleaser `brews:` stanza in `.goreleaser.yaml` for owner/name mismatches.
