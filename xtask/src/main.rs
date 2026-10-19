// SPDX-License-Identifier: MIT OR Apache-2.0
//! Build tasks. Every compile runs inside the Rocky Linux 10 container
//! from `build/Containerfile`, so the host only needs Rust and podman or
//! docker.

use std::{env, path::PathBuf, process::Command};

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand, ValueEnum};

mod rpm;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build aegisd and aegisctl into dist/<arch>/.
    Build {
        #[arg(long, value_enum, default_value_t = Arch::host())]
        arch: Arch,
        #[arg(long)]
        release: bool,
    },
    /// Build release binaries, then the aegis-v2 and aegis-v2-selinux
    /// RPMs into dist/rpm/.
    Rpm {
        #[arg(long, value_enum, default_value_t = Arch::host())]
        arch: Arch,
    },
    /// Build or refresh the aegis-build:rocky10-<arch> image.
    Container {
        #[arg(long, value_enum, default_value_t = Arch::host())]
        arch: Arch,
    },
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    fn host() -> Self {
        if env::consts::ARCH == "x86_64" {
            Self::X86_64
        } else {
            Self::Aarch64
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn platform(self) -> &'static str {
        match self {
            Self::X86_64 => "linux/amd64",
            Self::Aarch64 => "linux/arm64",
        }
    }

    fn image(self) -> String {
        format!("aegis-build:rocky10-{}", self.name())
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Container { arch } => container(&engine(arch)?, arch),
        Cmd::Build { arch, release } => build(&engine(arch)?, arch, release),
        Cmd::Rpm { arch } => rpm::rpm(&engine(arch)?, arch),
    }
}

/// `AEGIS_CONTAINER_ENGINE` if set, otherwise podman, then docker. The
/// exception is a cross-arch build on macOS: podman's qemu crashes rustc
/// there, so docker (Rosetta) goes first.
fn engine(arch: Arch) -> Result<String> {
    let cross_on_mac = cfg!(target_os = "macos") && arch != Arch::host();
    let engine = match env::var("AEGIS_CONTAINER_ENGINE") {
        Ok(engine) => engine,
        Err(_) => {
            let order = if cross_on_mac {
                ["docker", "podman"]
            } else {
                ["podman", "docker"]
            };
            order
                .into_iter()
                .find(|e| Command::new(e).arg("--version").output().is_ok())
                .context("neither podman nor docker found; set AEGIS_CONTAINER_ENGINE")?
                .into()
        }
    };
    if cross_on_mac && engine == "podman" {
        eprintln!(
            "warning: podman on macOS crashes rustc under emulation; \
             use AEGIS_CONTAINER_ENGINE=docker for {arch}"
        );
    }
    Ok(engine)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("running {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed: {status}");
    }
    Ok(())
}

/// A hash of build/Containerfile, stamped on the image as a label so a
/// changed Containerfile means a rebuild. DefaultHasher is only stable
/// within one Rust release, and the toolchain is pinned; a new one at
/// worst costs one extra rebuild.
fn containerfile_hash() -> Result<String> {
    use std::hash::{DefaultHasher, Hasher};
    let body = std::fs::read(root().join("build/Containerfile"))?;
    let mut h = DefaultHasher::new();
    h.write(&body);
    Ok(format!("{:016x}", h.finish()))
}

const LABEL: &str = "aegis.containerfile";

fn container(engine: &str, arch: Arch) -> Result<()> {
    let dir = root().join("build");
    run(Command::new(engine)
        .args(["build", "--platform", arch.platform(), "-t", &arch.image()])
        .args(["--label", &format!("{LABEL}={}", containerfile_hash()?)])
        .arg("-f")
        .arg(dir.join("Containerfile"))
        .arg(dir))
}

fn build(engine: &str, arch: Arch, release: bool) -> Result<()> {
    let (flag, profile) = if release {
        ("--release", "release")
    } else {
        ("", "debug")
    };
    in_container(
        engine,
        arch,
        &format!(
            "cargo build --locked -p aegisd -p aegisctl {flag} \
             && mkdir -p dist/{arch} \
             && cp /target/{profile}/aegisd /target/{profile}/aegisctl dist/{arch}/"
        ),
    )?;
    println!("built dist/{arch}/aegisd and dist/{arch}/aegisctl");
    Ok(())
}

/// Runs `script` in the build image with the repo at /src, building the
/// image first if it's missing or older than build/Containerfile.
fn in_container(engine: &str, arch: Arch, script: &str) -> Result<()> {
    let label = Command::new(engine)
        .args(["image", "inspect", "-f"])
        .arg(format!("{{{{index .Config.Labels \"{LABEL}\"}}}}"))
        .arg(arch.image())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    if label.as_deref() != Some(containerfile_hash()?.as_str()) {
        eprintln!("{} is missing or stale; building it", arch.image());
        container(engine, arch)?;
    }
    // The target dir lives in a named volume rather than the bind-mounted
    // repo: faster on macOS, and it keeps Linux artifacts out of ./target.
    run(Command::new(engine)
        .args(["run", "--rm", "--platform", arch.platform()])
        .arg("-v")
        .arg(format!("{}:/src:z", root().display()))
        .args([
            "-v",
            &format!("aegis-cargo-{arch}:/usr/local/cargo/registry"),
        ])
        .args(["-v", &format!("aegis-target-{arch}:/target")])
        .args(["-e", "CARGO_TARGET_DIR=/target", "-w", "/src"])
        .args([&arch.image(), "sh", "-c", script]))
}
