// SPDX-License-Identifier: MIT OR Apache-2.0
//! Thin wrappers over systemd and nftables for enforce mode. They shell
//! out, argument by argument and never through a shell, so incident ids
//! and paths can't inject anything.
#![allow(dead_code)] // wired up by the enforcer

pub mod nft;
pub mod systemd;
