// SPDX-License-Identifier: MIT OR Apache-2.0
//! Enforce mode: thin wrappers over systemd and nftables, and the
//! enforcer thread that drives them. The wrappers shell out, argument by
//! argument and never through a shell, so incident ids and paths can't
//! inject anything.

pub mod enforcer;
pub mod nft;
pub mod systemd;
