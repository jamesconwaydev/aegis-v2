// SPDX-License-Identifier: MIT OR Apache-2.0
//! Build tasks. Every compile runs inside the Rocky Linux 10 container
//! from `build/Containerfile`, so the host only needs Rust and podman or
//! docker.

use std::{env, path::PathBuf, process::Command};

use anyhow::{bail, Context as _, Result};
use clap::{Parser, Subcommand, ValueEnum};

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
    /// Build or refresh the aegis-build:rocky10-<arch> image.
    Container {
        #[arg(long, value_enum, default_value_t = Arch::host())]
        arch: Arch,
    },
}

#[derive(Clone, Copy, ValueEnum)]
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
    let engine = engine()?;
    match Cli::parse().command {
        Cmd::Container { arch } => container(&engine, arch),
        Cmd::Build { arch, release } => build(&engine, arch, release),
    }
}

/// `AEGIS_CONTAINER_ENGINE` if set, otherwise podman, then docker.
fn engine() -> Result<String> {
    if let Ok(engine) = env::var("AEGIS_CONTAINER_ENGINE") {
        return Ok(engine);
    }
    for engine in ["podman", "docker"] {
        if Command::new(engine).arg("--version").output().is_ok() {
            return Ok(engine.into());
        }
    }
    bail!("neither podman nor docker found; set AEGIS_CONTAINER_ENGINE")
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

fn container(engine: &str, arch: Arch) -> Result<()> {
    let dir = root().join("build");
    run(Command::new(engine)
        .args(["build", "--platform", arch.platform(), "-t", &arch.image()])
        .arg("-f")
        .arg(dir.join("Containerfile"))
        .arg(dir))
}

fn build(engine: &str, arch: Arch, release: bool) -> Result<()> {
    let image_exists = Command::new(engine)
        .args(["image", "inspect", &arch.image()])
        .output()
        .is_ok_and(|o| o.status.success());
    if !image_exists {
        container(engine, arch)?;
    }

    let (flag, profile) = if release {
        ("--release", "release")
    } else {
        ("", "debug")
    };
    // The target dir lives in a named volume rather than the bind-mounted
    // repo: faster on macOS, and it keeps Linux artifacts out of ./target.
    let script = format!(
        "cargo build --locked -p aegisd -p aegisctl {flag} \
         && mkdir -p dist/{arch} \
         && cp /target/{profile}/aegisd /target/{profile}/aegisctl dist/{arch}/"
    );
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
        .args([&arch.image(), "sh", "-c", &script]))?;
    println!("built dist/{arch}/aegisd and dist/{arch}/aegisctl");
    Ok(())
}
