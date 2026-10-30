# amanirenas — Security Capability Audit

Framework: `qyvora-amanirenas` · Domain: offline iOS app / IPA snapshot assessment
Audit date: 2026-10-21 · Audit mode: read-only (no feature implementation)
Status vocabulary: IMPLEMENTED / PARTIALLY IMPLEMENTED / STUBBED / PLANNED / MISSING / UNVERIFIED / NOT APPLICABLE

---

## 1. Framework identity and intended domain

- **Name:** amanirenas (`internal/version/version.go:24`, `Framework = "amanirenas"`).
- **Module:** `github.com/QYVORA/qyvora-amanirenas` (`go.mod`), Go 1.25.5.
- **Intended domain (README.md, `docs/README.md`):** offline assessment of iOS app
  snapshots / IPA-derived app profiles through a deterministic staged pipeline:
  `INTAKE → METADATA → STATIC → CONFIG → API → SECRETS → EVIDENCE → RISK`
  (`internal/analysis/analyst.go`, `internal/pipeline/`), with 12 built-in rules
  `AMN-001…AMN-012` (`internal/rules/builtin/builtin.go`).
- **Self-described boundaries:** offline and read-only; live device/live source
  operations are refused by design (`internal/cli/cli.go:519-534` `refuseLive`;
  `internal/capabilities/capabilities.go` marks `mobile.runtime: false`).
- **Ecosystem position:** fleet framework #2 of 14 (`PROMPT.md:34`); implements the
  QYVORA tool-output contract natively (JSONL envelope, capability manifest, semver
  version) — does **not** import `qyvora-common` (by design).

## 2. Audit scope and evidence sources

Evidence gathered (all read-only):

- **Governing spec:** `PROMPT.md` (§3 rules, §6 classification, §13 deliverable),
  `knowledge/.../QYVORA-TOOL-OUTPUT-SPEC.md`,
  `knowledge/.../QYVORA-SECURITY-FRAMEWORK-ECOSYSTEM.md`,
  `shared/qyvora-common/contract/contract.go`, `shared/qyvora-common/conformance/runner.go`.
- **Source:** `internal/cli/cli.go` (~990 lines: command surface, tier grammar,
  evidence/findings/report commands), `internal/capabilities/capabilities.go`,
  `internal/analysis/analyst.go`, `internal/rules/rules.go` + `rules/builtin/`,
  `internal/mobile/` (`mobile.go`, `detect.go`), `internal/risk/risk.go`,
  `internal/events/events.go`, `internal/evidence/`, `internal/safety/safety.go`,
  `internal/version/version.go`, `go.mod`, `Makefile`, `.github/workflows/`,
  `README.md`, `docs/`, `examples/`.
- **Help captures:** `docs/audit/help/amanirenas.txt`; fleet
  `docs/audit/HELP-AUDIT-REPORT.md:16,35` (banner yes; tier-grammar text in root
  help **No**).
- **Live binary probes** (`bin/amanirenas`, built from this tree):
  - `version -o json` → `{"framework":"amanirenas","version":"v0.1.0","commit":"cf8d100",
    "date":"2026-10-21T01:20:52Z",...}` exit 0 (commit matches HEAD).
  - `capabilities -o json` → exit 0; 8 capabilities, `mobile.runtime: false` honest.
  - Unknown flag → exit **2**; unknown command → exit **2**; bare invocation → exit **0**.
  - `recon assess --sim -o json --events off --no-report` → exit **0**, 14 findings,
    7 assets, score `100`, level `"critical"` (see §6 anomaly).
  - `recon assess --sim -o json --events stdout` → JSONL stream conforming to
    schema 1.0, 7-field envelope (`scan.started`, `stage.started`, `app.identified`, …);
    `--events /path` file mode also verified.
  - `sources -o json` → device/live `implemented:false` with recorded refusals.
- **Tests:** `go test ./... -count=1 -timeout 180s` → **PASS** (all packages; several
  `[no test files]` incl. capabilities, rules-builtin, safety, version).
- **Git state:** working tree **clean**, HEAD `cf8d100`. Preserved.

## 3. Existing capability inventory

| Capability | Evidence | Status |
|---|---|---|
| Tier grammar `recon/exploit/report` + hidden flat aliases | `internal/cli/cli.go:207-273`, `commandTarget` at 606+ | IMPLEMENTED (root help text omits grammar — §12) |
| Exit codes 0/1/2/130 | `internal/exitcode` via `internal/errors`; verified live (2/2/0) | IMPLEMENTED — no `3` usage observed (§10) |
| `version -o json` (framework, version, commit, date, go, arch, contact) | `version.go:45-84`; verified live | IMPLEMENTED |
| `capabilities` command | `internal/cli/cli.go` + `capabilities.go`; verified live | IMPLEMENTED (content honest incl. `mobile.runtime:false`) |
| `recon assess` — staged pipeline (identification→risk) | `cli.go` assess cmd, `internal/analysis/analyst.go`, `internal/pipeline/`; verified live | IMPLEMENTED |
| Simulation mode (`--sim`) with deterministic sample app | `cli.go` (target `simulation:simulation` in events); verified live | IMPLEMENTED |
| App profile intake (JSON profile, 64 MiB cap, strict decode) | `internal/mobile/mobile.go:139-174` (`Load`) | PARTIALLY IMPLEMENTED — parses *profile JSON*, not `.ipa` archives (§6) |
| Source detection (ipa/store-catalog/config-profile) | `internal/mobile/detect.go`; `sources` command verified | IMPLEMENTED |
| 12 built-in rules AMN-001…012 | `internal/rules/builtin/builtin.go`; `rules` command lists them | IMPLEMENTED |
| Deterministic rules registry (order-preserving, duplicate-ID guard) | `internal/rules/rules.go:127-184` (`RegisterAll`, `Metas` in order) | IMPLEMENTED |
| Findings sink with stable IDs + merge | `internal/rules/rules.go:36-126` (`stableFindingID`, `mergeInto`) | IMPLEMENTED |
| Risk scoring `sev × conf × (exposure/5) × 40`, capped 100 | `internal/risk/risk.go:76-96`; matches output spec formula | IMPLEMENTED |
| Evidence store with hashing + secret redaction at render/persist | `internal/evidence/`; redaction `cli.go:519-534, 896-911` | IMPLEMENTED |
| JSONL event stream (schema 1.0) | `internal/events/events.go:22-52`; verified live | IMPLEMENTED |
| 5 output formats (terminal/json/yaml/markdown/html) | `capabilities.go` manifest; `internal/reporting/` | IMPLEMENTED |
| `findings` / `evidence` / `report` commands (JSONL + JSON artifacts) | `cli.go:896-911` | IMPLEMENTED |
| `profile` command (deterministic sample profile generator) | `cli.go` utility list | IMPLEMENTED |
| `target` management (profile files + simulation) | `cli.go` (`commandTarget`) | IMPLEMENTED |
| Safety / authorization model (`safety.OperationMetadata`) | `internal/safety/safety.go` | IMPLEMENTED (used by CLI; per-op risk metadata exists) |
| Script engine (`script run/build`) | `internal/cli/script.go`; dep `qyvora-script v0.1.0` | IMPLEMENTED |
| Self-update (`updates`) | `internal/selfupdate/` (via `qyvora-updates`) | IMPLEMENTED |
| Config (viper) | `internal/config/` loaded in cli | IMPLEMENTED (no `-c/--config` flag — §10) |
| TUI | `internal/cli/tui.go` behind `//go:build ignore` | NOT APPLICABLE (retired fleet-wide; `docs/CLI.md` still lists it — §12) |
| Live device / live source assessment | `refuseLive` (`cli.go`), manifest `mobile.runtime:false` | MISSING — honest refusal with recorded refusal note |
| Real `.ipa` zip/Info.plist/Mach-O intake | no archive/plist/macho packages in `internal/` | MISSING (P0 candidate, §8) |
| Android profile support | absent; ecosystem doc conflicts (§15 Q1) | UNVERIFIED / PLANNED (needs ecosystem decision) |

## 4. Capability status matrix

| Capability area | Status | V/S | Notes |
|---|---|---|---|
| Profile intake (JSON) | IMPLEMENTED | V | `sources`, `assess` verified live |
| Real IPA archive parsing | MISSING | S | no `archive/zip`, no Info.plist, no Mach-O reader |
| Metadata extraction | IMPLEMENTED | V | `metadata.extracted` events; asset inventory 7 |
| Static/config/API/secrets analysis | IMPLEMENTED | V/S | runs in live `assess`; rules AMN-001…012 |
| Risk scoring + levels | IMPLEMENTED | V | formula matches spec; level mapping anomaly (§6) |
| Evidence + redaction | IMPLEMENTED | S | `findings`/`evidence` commands; redaction paths reviewed |
| Reporting (5 formats) | IMPLEMENTED | S | `reporting.Write`; manifest lists all five |
| Events (JSONL) | IMPLEMENTED | V | stdout + file modes verified |
| Simulation target | IMPLEMENTED | V | deterministic, offline |
| Live device acquisition | MISSING (deferred) | S | honest refusal, exit 2 (see §9/§14 G1) |
| Runtime/dynamic assessment (simulator/dylib injection) | MISSING (deferred) | S | manifest `mobile.runtime:false` |
| Console REPL | NOT APPLICABLE | S | retired fleet-wide; README still references it (§12) |
| Android domain | UNVERIFIED | S | ecosystem doc internally inconsistent (§15 Q1) |
| Schema documentation for profile JSON | MISSING | S | schema is implicit in `mobile.Load` |

## 5. Reconnaissance and discovery findings

- `sources` — supported mobile sources with implemented/refusal status; verified
  live: device/live `implemented:false`, refusals recorded (IMPLEMENTED).
- `target` — manage profile files and the simulation target; used by `assess` as
  `target=simulation:simulation` (verified in events) (IMPLEMENTED).
- `profile` — deterministic sample app profile generator (IMPLEMENTED).
- `rules` — lists registered analysis rules in deterministic order
  (`rules.Metas()`, `rules.go:172-184`) (IMPLEMENTED).
- `recon assess` identification stage emits `app.identified` with
  `app_id/bundle_id/version/build/source` (verified live) — the reconnaissance
  product of an offline snapshot.
- No live reconnaissance (device enumeration, network discovery) — by design;
  refused with recorded refusal.

## 6. Analysis and assessment findings

- **Pipeline:** `assess` runs identification → IPA intake → metadata → static →
  config → API → secrets → evidence → risk; live `--sim` run produced 14 findings,
  7 assets, exit 0, and stage events for every phase (verified live).
- **Rules:** 12 built-ins (`builtin.go`), registered via `RegisterAll` with
  all-or-nothing duplicate handling (`rules.go:145-147`); profiles gate severity
  (`severityAllows`, `rules.go:280`).
- **Risk formula:** `ScoreFor = sev × conf × (exposure/5) × 40` capped at 100
  (`risk.go:84-86`), category-best aggregation (`risk.go:128`) — matches
  `QYVORA-TOOL-OUTPUT-SPEC.md` exactly.
- **Anomaly (P1):** a clean simulated app returns `score: 100` with
  `level: "critical"` (live probe). Score 100 should be *maximal risk* yet the
  findings are low-severity profile observations — either the level mapping is
  inverted relative to the score, or the clean-app score should be near 0. Either
  reading is a correctness bug for orchestrators consuming `risk.level`.
  (`risk.go:31` `Level` maps score→label; needs a live mapping check — recorded as
  UNVERIFIED correctness issue, not fixed: audit only.)
- **IPA intake honesty:** `mobile.Load` (`mobile.go:139-174`) strictly decodes a
  JSON *profile document* (64 MiB cap, `DisallowUnknownFields`). There is no
  `archive/zip`, no `Info.plist` decoder, no Mach-O inspection anywhere in
  `internal/`. The manifest's `mobile.ipa: true` therefore means "intake of
  IPA-derived profiles", not "parses .ipa files" — overstated relative to the
  ecosystem doc's "IPA snapshots" language (§14 G2).

## 7. Exploitation-related capability findings

- The `exploit` tier exists in the grammar (`cli.go` tier commands) but has **no
  exploit modules** — `docs/CLI.md` exploit section is empty; no exploitation code
  in `internal/`.
- Runtime exploitation-adjacent techniques (dylib injection, jailbreak detection
  bypass, pinning bypass) are all live/runtime and refused or absent (§9).
- Verdict: **NOT APPLICABLE** — amanirenas contributes risk evidence
  (findings + exposure + risk levels) consumed by fleet exploit frameworks.

## 8. High-level implementation candidates

Feasible in-tree with existing Go stdlib/third-party dependencies, no hardware:

1. **P0 — Risk score/level correctness** (§6 anomaly): verify `risk.Level` mapping
   and the clean-app baseline; a correct mapping is a prerequisite for orchestrator
   trust in `risk.level`.
2. **P0 — Real `.ipa` intake**: stdlib `archive/zip` + `Info.plist` decoding +
   Mach-O header/entitlement reading; feed the existing pipeline directly from an
   `.ipa`. The PE-style precedent exists fleet-side in aksum's `internal/formats/pe`.
   This closes the gap between the domain claim ("IPA snapshots") and reality
   (JSON profiles).
3. **P1 — Profile schema + documentation**: document `mobile.Load`'s accepted JSON
   (fields, units, enums) so external producers can generate profiles; add a golden
   fixture (`examples/basic.json` is currently zero-byte — §12).
4. **P1 — Fix capability manifest exit-code documentation**: manifest omits
   `unsupported: 3` (fleet contract defines it); amanirenas never returns 3 (§10/§14 G1).
5. **P2 — Entitlements/privacy-manifest (PrivacyInfo.xcprivacy) analysis rule**:
   pure static analysis on top of candidate 2's plist reader.
6. **P2 — Android profile support**: only after ecosystem settles the domain
   question (§15 Q1); profile-driven design makes it mostly additive rules work.
7. **P2 — Conformance runner wiring**: `conformance/runner.go` checks (version-semver,
   usage-exit-2, unknown-cmd-exit-2, tui-retired) are not run in this repo's CI.

## 9. Low-level deferred technique inventory

All items below are **DEFERRED — SPECIALISED PREREQUISITES** (require physical
devices, macOS/Xcode lab infrastructure, or network attack equipment — not
implementable in this repository):

| Technique | Why deferred | Priority |
|---|---|---|
| Live iOS device acquisition (usbmux/libimobiledevice-class access, device pairing, app bundle pull) | Requires a physical paired device + device-side access | DEFERRED — SPECIALISED PREREQUISITES (manifest already reserves `mobile.runtime`) |
| Simulator/hosted runtime assessment (XCTest, dylib injection, runtime hooking) | Requires macOS + Xcode + iOS Simulator runtime | DEFERRED — SPECIALISED PREREQUISITES (P3) |
| Certificate-pinning / TLS interception assessment (MITM lab, provisioning profiles) | Requires controlled network lab + signed profiles | DEFERRED — SPECIALISED PREREQUISITES |
| Jailbreak/environment tamper detection *validation* (real jailbroken device) | Requires jailbroken hardware | DEFERRED — SPECIALISED PREREQUISITES |
| Baseband/NFC/Secure-Enclave interaction analysis | Requires specialized hardware access | NOT APPLICABLE to offline snapshot analysis |
| Fault injection / voltage glitching / hardware side-channels | Requires lab hardware | NOT APPLICABLE |
| Firmware extraction (chip-off, DFU-level imaging) | Requires device disassembly; belongs to device-domain frameworks | DEFERRED — SPECIALISED PREREQUISITES |

## 10. Common-layer conformance

| Item | Decision | Evidence |
|---|---|---|
| Exit-code contract 0/1/2/130 | SHARED (native, contract-conformant) | live probes 2/2/0; `internal/errors` |
| Exit code `3` (unsupported/declined) | MISSING / INCONSISTENT | fleet contract `contract.ExitUnsupported=3`; amanirenas refuses live ops with **usage (2)** via `refuseLive` (`cli.go`) and never declares `3`; aksum/sekhmet use 3 for the same situation |
| JSONL event envelope (7 fields, schema 1.0) | SHARED | `events.go:22-52`; live stdout + file streams conform |
| Capability manifest command | SHARED | honest content; shape matches peers |
| Semver `version -o json` | SHARED (minor INCONSISTENT: `v` prefix) | emits `v0.1.0`; aksum emits `0.1.0`; both pass `IsSemverVersion` (`v?` prefix allowed) |
| `qyvora-tui` banner helpers | SHARED | dep present; session engine correctly not linked (`tui.go` ignored) |
| `qyvora-script` engine | SHARED | `qyvora-script v0.1.0`; `script.go` |
| capabilities/exitcode/events/selfupdate/output packages | DUPLICATED | near-identical copies of aksum's packages; consolidation is the ecosystem's documented future shared-model layer |
| Output formats (5 vs aksum's 2) | FRAMEWORK-SPECIFIC / INCONSISTENT across fleet | spec permits either; peers differ |
| `-o` only (no `-f` alias), no `-c/--config` flag, no `--dry-run`, no `--authorized` | FRAMEWORK-SPECIFIC, partially INCONSISTENT with fleet flag conventions | `cli.go` persistent flags; viper config loaded without a flag selector |
| Risk model (finding fields, levels) | FRAMEWORK-SPECIFIC (shared shape per output spec) | `risk.go`; spec §20 shape matches |
| Shared Target/Finding/Evidence/Risk model layer | MISSING (by ecosystem plan) | no `qyvora-common` import; contract-only coupling |

## 11. AI orchestration readiness

| Requirement | Status | Evidence |
|---|---|---|
| Identity reporting (framework + semver version, JSON) | CONFORMANT | `version -o json` verified live (`v0.1.0`, commit matches HEAD) |
| Capability discovery (`capabilities -o json`) | CONFORMANT | verified live; honest false entries (`mobile.runtime`) |
| Exit-code contract (incl. `3` unsupported) | PARTIALLY CONFORMANT | 0/1/2/130 verified; refused live operations return **2** instead of **3**, and `3` is undeclared (G1) |
| Structured results (JSON) | CONFORMANT | `assess -o json` verified; risk/findings/assets keys match shared shape |
| Structured events (JSONL) | CONFORMANT | stdout + file modes verified, schema 1.0 envelope |
| Cancellation / interrupt (130) | CONFORMANT (source) | `signal.NotifyContext`; exit 130 defined |
| Timeouts | PARTIALLY CONFORMANT | no per-operation timeout flags on assess/report |
| Prerequisite declarations | CONFORMANT | manifest documents implemented flags and unimplemented sources honestly |
| Risk classification of operations | CONFORMANT | `safety.OperationMetadata` exists and is surfaced by the CLI; refusal notes recorded per operation |
| Safe defaults | CONFORMANT | offline, read-only, simulation default target; bare invocation prints help (exit 0) |
| Root help tier-grammar text | PARTIALLY CONFORMANT | grammar implemented in commands but absent from root help Long (`HELP-AUDIT-REPORT.md:35` — "No") |

**Orchestration verdict:** ready for orchestration now for offline snapshot
assessment; two advisories for orchestrators: treat `risk.level` as UNVERIFIED until
§6 is resolved, and map "unsupported" refusals to exit 2 (not 3) when consuming
amanirenas today.

## 12. CLI, repository-layout, and documentation findings

- **CLI:** tier grammar implemented with hidden flat aliases; unknown command/flag →
  2; bare → 0 with canonical banner (`HELP-AUDIT-REPORT.md:16`).
- **Documentation health (P1/P2):**
  - **20 zero-byte placeholder files in `docs/`** (verified `wc -c`), plus zero-byte
    root `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`,
    `SUPPORT.md`. `docs/README.md` honestly indexes the placeholders but the state
    itself is a repo-quality gap. Note: `LICENSE`/`NOTICE` are populated (1070/1069
    bytes) though `docs/README.md` still claims they are zero-byte — that claim is
    stale in the *good* direction.
  - `README.md` still describes the interactive console REPL and console-era command
    layout; the per-tool session/TUI is retired (`internal/cli/tui.go` `//go:build
    ignore`).
  - `docs/CLI.md` is stale: "No recon-tier modules" (false — assess/profile/sources/
    rules/target are recon-tier utilities), references retired `amanirenas tui`, and
    a garbled `docs script <file>` row.
  - Root help `Long` omits the tier-grammar sentence (fleet inconsistency).
- **Layout:** clean `internal/` structure; `examples/` contains `assess.qs` (935 B,
  runnable) but **`examples/basic.json` and `examples/basic.yaml` are zero-byte**;
  `tests/` directory exists but is **empty**; local gitignored artifacts present
  (`bin/`, `amanirenas-report/`, `reports/*.json`).
- **.gitignore:** contains a stray `/imhotep` entry (copy-paste from another
  framework) — cosmetic P3.
- **Build/CI:** Makefile targets mirror aksum (`all/lint/vet/test/test-race/verify/…`);
  `.github/workflows/{ci,release}.yml` present; `install.sh`, `.goreleaser.yaml`.

## 13. Testing and verification findings

- `go test ./... -count=1 -timeout 180s` → **PASS** across all packages.
  `[no test files]` observed for: capabilities, errors, exitcode, reporting,
  rules-builtin, safety, version — including the packages most relevant to contract
  conformance (exitcode, capabilities) and to the §6 risk anomaly (no risk package
  tests observed).
- Live CLI probes (§2) provided effective smoke coverage of assess, events
  (stdout + file), sources, version, capabilities, and exit codes.
- **Missing validation (documented, not implemented):**
  - Unit/golden tests for `risk.Level` mapping and the clean-app score baseline
    (would have caught or pre-empted §6).
  - Fixture tests exercising each built-in rule `AMN-001…012` (rules-builtin package
    has no test files).
  - Golden tests for evidence redaction paths.
  - Conformance runner (`shared/qyvora-common/conformance/runner.go`) not wired into
    this repo's CI (checks available: version-semver, usage-exit-2,
    unknown-cmd-exit-2, tui-retired, capabilities-present).
- `tests/` directory is empty — no integration test harness.

## 14. Prioritized gaps and recommendations

| # | Priority | Gap | Recommendation |
|---|---|---|---|
| G1 | **P0** | Refused/unsupported live operations exit **2** (usage) instead of contract **3**; manifest doesn't declare `unsupported:3` | Adopt `contract.ExitUnsupported` for `refuseLive`-class refusals (matches aksum/sekhmet); declare code 3 in the manifest; add conformance check |
| G2 | **P0** | Real `.ipa` intake missing — `mobile.Load` parses JSON profiles only, while domain claims IPA snapshots | Implement stdlib zip + Info.plist + Mach-O header intake feeding the existing pipeline; update manifest wording meanwhile |
| G3 | **P0** | Risk `score:100` + `level:"critical"` returned for a clean simulated app (correctness anomaly) | Audit `risk.Level` mapping and clean-app baseline; add unit tests; treat `risk.level` as UNVERIFIED until fixed |
| G4 | P1 | 20 zero-byte `docs/*.md` + 5 zero-byte root governance docs; `tests/` empty; zero-byte example fixtures | Populate or prune placeholders; add real fixtures; stand up an integration harness |
| G5 | P1 | README console REPL + `docs/CLI.md` tui rows/"no recon modules" stale; root help lacks tier-grammar text | Documentation pass; add the grammar sentence to root `Long` for fleet consistency |
| G6 | P2 | No profile-schema documentation (schema implicit in `mobile.Load`) | Publish schema doc + golden fixture (`examples/basic.json`) |
| G7 | P2 | Rule coverage untested (no AMN-0xx tests), redaction untested | Golden tests per rule; redaction fixtures |
| G8 | P2 | Conformance runner not in CI | Wire `conformance.Run` into `ci.yml` |
| G9 | P3 | Stray `/imhotep` in `.gitignore`; `-f`/`-c`/`--dry-run` flag conventions diverge from fleet | Cosmetic + convention alignment pass |

## 15. Dependencies, prerequisites, and unresolved questions

- **Runtime deps:** cobra, viper, go-version, qyvora-cli-brand, qyvora-script v0.1.0,
  qyvora-tui v0.11.0 (banner helpers), qyvora-updates, testify (dev). Offline: no
  network required.
- **Build prerequisites:** Go 1.25.5, `make` (optional), `goreleaser` (releases).
- **Prerequisites for deferred capabilities (§9):** paired physical iOS device;
  macOS + Xcode + Simulator runtime; MITM/provisioning lab.
- **Unresolved questions:**
  1. **Domain boundary:** is amanirenas iOS-only or iOS+Android? Ecosystem doc §2
     table says "iOS only" while §31 says "iOS and Android app profiles" —
     needs an ecosystem decision before G2-adjacent Android work.
  2. **Risk semantics:** should a clean app be `score≈0, level≈informational`, or is
     `level` inverted? Blocks orchestrator trust (§6/G3).
  3. **Exit-3 adoption:** confirm with the ecosystem whether refusing (unimplemented
     live source) is "unsupported" (3) or "usage error" (2) — aksum/sekhmet use 3.
  4. **Profile producer:** who generates profile JSON in production — a separate
     intake tool, or does G2 (real IPA parsing) make the producer obsolete?
  5. **`v`-prefixed version:** cosmetic divergence from aksum (`v0.1.0` vs `0.1.0`);
     both pass semver validation — normalize or leave as framework-specific?

## 16. Implementation statement

No feature implementation was performed during this audit. No source files, tests,
configuration, or documentation were modified; no destructive commands were run; no
git state was changed (working tree remains clean at HEAD `cf8d100`). The only file
created is this `AUDIT.md`.
