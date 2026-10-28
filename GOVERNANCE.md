# Governance

Aegis is maintained by one person, so its governance is short. This page
says who decides, how, and who does what.

## How decisions are made

I decide. Most decisions happen in the open, in an issue, a Discussion or a
pull request, and anyone can argue for or against a change there. I weigh
that, decide, and say why in the thread.

Some things are settled up front in [CONTRIBUTING.md](CONTRIBUTING.md) and
the [roadmap](docs/roadmap.md), so you don't have to guess: Aegis targets
Rocky Linux 10 and its stock kernel, every build runs in the pinned Rocky 10
container, and nothing lands without tests and green CI.

A decision can be reopened with new evidence. A reproducible example
carries the most weight.

## Roles

| Role | Who | Responsibilities |
| --- | --- | --- |
| Maintainer | James Conway ([@jamesconwaydev](https://github.com/jamesconwaydev)) | Triages issues and Discussions; reviews and merges pull requests; keeps CI, dependencies and the end-to-end suite green; cuts releases and publishes the RPMs; handles vulnerability reports as described in [SECURITY.md](SECURITY.md); enforces the [Code of Conduct](CODE_OF_CONDUCT.md); keeps the [roadmap](docs/roadmap.md) current. |
| Contributor | Anyone who opens an issue, a Discussion or a pull request | Follows [CONTRIBUTING.md](CONTRIBUTING.md) and the Code of Conduct. |

[CODEOWNERS](.github/CODEOWNERS) routes every review to me.

## Changes to this document

Changes to governance go through a pull request like any other change, and
are announced in the release notes of the next release.
