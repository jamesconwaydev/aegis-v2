# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Use GitHub's private
vulnerability reporting instead:

<https://github.com/jamesconwaydev/aegis-v2/security/advisories/new>

Tell me what you found, which version and Rocky release you saw it on, and how
to reproduce it. A proof of concept helps, but a clear description is enough to
start.

I'll acknowledge your report within 5 business days. After that I'll work
with you on a fix and we'll agree a disclosure date together. I maintain Aegis
on my own, so I can't promise a fix timeline up front, but you'll hear from me
as things move.

## Supported versions

Aegis is pre-1.0. Only the latest release gets security fixes.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Anything older | No        |

## What counts

Anything that lets an attacker blind or disable Aegis, slip past detection or
quarantine by attacking Aegis itself, escalate privileges through it, or tamper
with its logs and incident records. A false positive or a missed detection is
not a vulnerability on its own; use the matching issue form for those.
