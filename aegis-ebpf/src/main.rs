// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

// Placeholder that proves the build pipeline. Real probes replace it.
#[tracepoint]
pub fn aegis(_ctx: TracePointContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
