// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::{anyhow, Context as _};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // The pinned nightly for the eBPF crate; build/Containerfile sets it.
    println!("cargo:rerun-if-env-changed=AEGIS_EBPF_TOOLCHAIN");
    let toolchain = std::env::var("AEGIS_EBPF_TOOLCHAIN")
        .context("AEGIS_EBPF_TOOLCHAIN is unset; build with `cargo xtask build`")?;
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "aegis-ebpf")
        .ok_or_else(|| anyhow!("aegis-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::Custom(&toolchain))
}
