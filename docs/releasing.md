# Releasing

For maintainers. A release is a git tag on `main`; the Release workflow
builds and publishes everything else.

## Versioning

Aegis follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, a minor version (0.2.0) can change behaviour and config, and
a patch version (0.1.1) only fixes things.

Every `v0.*` release is published as a GitHub pre-release.

## The version lives in three places

They must agree, or the release fails before anything is built:

1. `version` under `[workspace.package]` in `Cargo.toml`. The binaries
   and the RPM take their version from here.
2. The first `%changelog` entry in `packaging/aegis-v2.spec`, which ends
   in `- <version>-<release>`.
3. A `## [<version>] - <date>` section in `CHANGELOG.md`. Its text
   becomes the release notes.

## Steps

1. On a branch, bump the version in `Cargo.toml` and run `cargo update
   -w` so `Cargo.lock` follows.
2. Add the spec `%changelog` entry, newest first.
3. Move the `[Unreleased]` notes in `CHANGELOG.md` into a new
   `## [x.y.z] - YYYY-MM-DD` section.
4. Open a pull request, wait for CI, and squash-merge it.
5. Dry-run the release from `main`:

   ```sh
   gh workflow run release.yml --ref main
   ```

   That runs every check and builds both RPMs, without publishing.
6. Tag the merge commit with an annotated tag and push it:

   ```sh
   git switch main && git pull
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

## What the Release workflow does

On a `v*.*.*` tag:

1. **check:** confirms `Cargo.toml`, the spec's `%changelog` and the tag
   agree, that the tagged commit is on `main`, and that `CHANGELOG.md`
   has a section for the version. It extracts that section as the
   release notes.
2. **rpm:** builds the x86_64 RPMs on an x86_64 runner and the aarch64
   RPM on an arm64 runner, each in the Rocky 10 build container.
3. **publish:** writes SPDX and CycloneDX SBOMs from `Cargo.lock`,
   then `SHA256SUMS` over the RPMs and SBOMs. It attests build
   provenance for every file listed in `SHA256SUMS`, signs
   `SHA256SUMS` keylessly with cosign, and creates a **draft** release
   with the notes, marked as a pre-release for `v0.*` tags.

The release carries:

- `aegis-v2-<version>-1.el10.x86_64.rpm`
- `aegis-v2-<version>-1.el10.aarch64.rpm`
- `aegis-v2-selinux-<version>-1.el10.noarch.rpm`
- `aegis-v2-v<version>.spdx.json` and `aegis-v2-v<version>.cdx.json`
- `SHA256SUMS` and `SHA256SUMS.sigstore.json`

## Publishing the draft

Releases are immutable once published: the files and the tag can't
change after that. So the workflow stops at a draft. Download it, check
the files and the signature the way
[installation](installation.md#install-the-rpms) describes, read the
notes, then publish:

```sh
gh release edit v0.2.0 --draft=false
```

## After publishing

Publishing the release also runs the Wiki workflow, which copies
`docs/` into the [wiki](https://github.com/jamesconwaydev/aegis-v2/wiki)
as of the new tag. The wiki is a copy: edit `docs/`, never the wiki,
or the next release overwrites the change.

Install the released x86_64 RPM on a freshly rebuilt test host and run
the end-to-end scenarios against it. See
[development](development.md#end-to-end-tests).

## If something goes wrong

A failure in any job publishes nothing, and a bad draft can be deleted.
Fix it on a branch, merge, delete the tag locally and on GitHub, and tag
again:

```sh
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
```

Tags matching `v*` are protected by a ruleset, so deleting one means
turning that ruleset off for the moment, in **Settings → Rules →
Rulesets → protect-tags**. Once a release is published, its tag can't
move at all. Fix forward with a patch release instead.
