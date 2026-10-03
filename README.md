# Amanirenas

> **Offline mobile app security assessment framework.**
> A terminal-first console and CLI for app profile / IPA snapshot analysis:
> metadata, static posture, configuration, API and secrets risk — with no
> runtime execution.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Amanirenas is QYVORA's mobile application security assessment framework
for **offline app profiles and IPA snapshots**. It runs as a shared
terminal-first console **and** a one-shot CLI with identical commands, is
deterministic and offline-first with `--sim`, and produces evidence-backed
findings with transparent risk scoring. Runtime assessment and live
device acquisition are **not implemented and are refused honestly**;
nothing here executes app code.

- **One workflow, two surfaces** — the console commands equal the CLI
  commands.
- **Deterministic `--sim`** — fixed dataset exercises every rule, no device
  or Xcode required, CI-ready.
- **Offline only** — analyzes only the app profiles / snapshots you
  explicitly provide.
- **Evidence over opinion** — every finding carries the observations that
  produced it; secret values are redacted.
- **Status** — shipped at v0.1.0 (Go 1.26+, MIT).

## Installation

```sh
git clone https://github.com/QYVORA/qyvora-amanirenas.git
cd qyvora-amanirenas
make build
sudo make install          # /usr/local layout (root)
make install-user          # ~/.local layout (no root)
```

Or build the single static binary directly with the Go toolchain:

```sh
go build ./cmd/amanirenas
```

No release assets are published yet; `amanirenas updates` installs release
builds once the first verifiable release exists.

## Quickstart

Full assessment, no input required, deterministic:

```sh
amanirenas assess --sim       # 14 findings, risk 100/100 (critical)
```

Generate a sample app profile and assess it:

```sh
amanirenas profile --sim
amanirenas assess profile.sim.json
```

Interactive console (REPL on a real terminal; stdin piping uses a plain line reader):

```sh
amanirenas
assess --sim
findings
evidence
exit
```

Machine-readable output:

```sh
amanirenas capabilities -o json
amanirenas assess -o json
amanirenas report -o json
```

## Commands

```
assess        run the analysis pipeline against an app profile or simulation
capabilities  print the machine-readable capability contract
console       start the interactive assessment console
evidence      inspect the latest assessment evidence
findings      inspect the latest assessment findings
profile       generate a deterministic sample app profile
report        render the latest assessment report from disk
rules         list the registered analysis rules
sources       list supported mobile sources and their status
target        manage assessment targets (profile files and simulation)
updates       check for and install verified releases
version       print version and build metadata
```

Global flags: `-o/--output`, `-q/--quiet`, `--no-color`.

## Analysis rules

```
AMN-001  Hardcoded secret in app                        critical
AMN-002  Insecure transport                             critical
AMN-003  Missing certificate pinning                     medium
AMN-004  Legacy WebView usage                            medium
AMN-005  Weak cryptography                              medium
AMN-006  Insecure local data storage                      high
AMN-007  Sensitive data copied to clipboard              medium
AMN-008  Sensitive data in logs                           low
AMN-009  Excessive permissions                           medium
AMN-010  Outdated minimum OS version                      low
AMN-011  Ad-hoc signing without verified distribution    medium
AMN-012  No jailbreak or tamper detection                medium
```

## Capabilities

`amanirenas capabilities` prints the machine-readable contract. The
deliberate boundary: `mobile.runtime` (dynamic runtime assessment) and
live device acquisition are disabled — **offline IPA/profile analysis only,
nothing executes app code**.

## Documentation

- **[`docs/README.md`](docs/README.md) — the documentation index.** It lists what is
  actually written, and names every zero-byte placeholder file explicitly so
  nothing empty is cited as documentation.
- Pipeline stages, analysis rules and risk scoring: the tool's own
  `capabilities` output, `docs/README.md`, and the QYVORA product overview.
- Cross-project contracts: the QYVORA tool output spec and ecosystem doc.

> **Documentation gap.** This repository still has zero-byte placeholder
> files (including `LICENSE` and `NOTICE`). `docs/README.md` names them all.

## Support

See [SUPPORT.md](SUPPORT.md). Report issues on GitHub.

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Analyze app profiles you are authorized to
evaluate; no code is executed and live devices are never acquired.