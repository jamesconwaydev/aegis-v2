// SPDX-License-Identifier: MIT OR Apache-2.0
use clap::Parser;

#[derive(Parser)]
#[command(version)]
struct Cli {}

fn main() {
    Cli::parse();
}
