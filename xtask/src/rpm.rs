// SPDX-License-Identifier: MIT OR Apache-2.0
//! `cargo xtask rpm`: release binaries, then rpmbuild, both in the
//! container. Leaves aegis-v2-<ver>.<arch>.rpm and the noarch
//! aegis-v2-selinux RPM in dist/rpm/.

use anyhow::Result;

use crate::{build, in_container, Arch};

pub fn rpm(engine: &str, arch: Arch) -> Result<()> {
    build(engine, arch, true)?;
    // rpmbuild's own tree stays in the container; only the RPMs come out.
    let script = format!(
        "rpmbuild -bb --target {arch} \
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
