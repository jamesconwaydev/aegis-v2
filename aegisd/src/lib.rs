// SPDX-License-Identifier: MIT OR Apache-2.0
//! The daemon's modules, as a library so the fuzz targets in `fuzz/`
//! can reach the parsers. `main.rs` is the only real user; nothing here
//! is a stable API, which is also why `new` needs no `Default` twin.
#![allow(clippy::new_without_default)]

pub mod config;
pub mod ebpf;
pub mod enforce;
pub mod incident;
pub mod ipc;
pub mod pipeline;
pub mod proctable;
pub mod scoring;
pub mod telemetry;
pub mod verify;
