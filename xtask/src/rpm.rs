// SPDX-License-Identifier: MIT OR Apache-2.0
//! `cargo xtask rpm`: release binaries, then rpmbuild, both in the
//! container. Leaves aegis-v2-<ver>.<arch>.rpm and the noarch
//! aegis-v2-selinux RPM in dist/rpm/.

use anyhow::Result;

use crate::{build, in_container, Arch};

pub fn rpm(engine: &str, arch: Arch) -> Result<()> {
    build(engine, arch, true)?;
    // The licence texts of every crate in the binaries, for %license.
    // --frozen keeps cargo-about to the crate sources already fetched,
    // so the file depends on Cargo.lock alone and not on what a crate's
    // git repo says today.
    // rpmbuild's own tree stays in the container; only the RPMs come out.
    let script = format!(
        "cargo fetch --locked \
         && cargo about generate --frozen --fail --workspace \
            -c packaging/about.toml -o dist/{arch}/THIRD-PARTY-LICENSES \
            packaging/about.hbs \
         && rpmbuild -bb --target {arch} \
         --define '_topdir /tmp/rpmbuild' \
         --define '_sourcedir /src' \
         --define 'aegis_bindir /src/dist/{arch}' \
         --define '_rpmdir /src/dist/rpm' \
         --define '_build_name_fmt %%{{NAME}}-%%{{VERSION}}-%%{{RELEASE}}.%%{{ARCH}}.rpm' \
         packaging/aegis-v2.spec"
    );
    in_container(engine, arch, &script)?;
    println!("built dist/rpm/");
    Ok(())
}
