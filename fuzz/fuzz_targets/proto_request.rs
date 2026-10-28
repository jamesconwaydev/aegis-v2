// SPDX-License-Identifier: MIT OR Apache-2.0
//! One control-socket request line, as aegisd's connection task decodes
//! it, then what the daemon does with an id before using it.
#![no_main]

use aegis_proto::{clean, is_incident_id, Request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|line: &[u8]| {
    let Ok(req) = serde_json::from_slice::<Request>(line) else {
        return;
    };
    // Whatever decoded must encode and decode back to itself.
    let again: Request = serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
    assert_eq!(again, req);
    if let Request::IncidentShow { id }
    | Request::IncidentTimeline { id }
    | Request::IncidentRelease { id }
    | Request::IncidentKill { id } = req
    {
        is_incident_id(&id);
        clean(&id);
    }
});
