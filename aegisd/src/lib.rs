// SPDX-License-Identifier: MIT OR Apache-2.0
//! The daemon's modules as a library, for the fuzz targets in `fuzz/`
//! only. cargo fuzz builds with `--cfg fuzzing`; every other build gets an
//! empty library, and the binary declares the same modules itself, so it
//! keeps its dead-code warnings. Not an API, so `new` needs no `Default`.
#![cfg(fuzzing)]
#![allow(clippy::new_without_default)]

pub mod config;
pub mod ebpf;
pub mod enforce;
pub mod filed;
pub mod incident;
pub mod ipc;
pub mod pipeline;
pub mod proctable;
pub mod scoring;
pub mod spool;
pub mod stix;
pub mod telemetry;
pub mod verify;
