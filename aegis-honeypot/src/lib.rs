// SPDX-License-Identifier: MIT OR Apache-2.0
//! The parsers of client bytes as a library, for the fuzz targets in
//! `fuzz/` only. cargo fuzz builds with `--cfg fuzzing`; every other build
//! gets an empty library, and the binary declares the same modules
//! itself, so it keeps its dead-code warnings.
#![cfg(fuzzing)]

pub mod dispatch;
pub mod dns;
pub mod hello;
pub mod http;
pub mod shell;
pub mod upload;
