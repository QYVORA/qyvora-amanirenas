# CLI Reference

`amanirenas` follows the shared QYVORA tier grammar:

```
amanirenas <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

_No recon-tier modules._

## exploit

_No exploit-tier modules._

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `amanirenas assess` | run the analysis pipeline against an app profile or simulation |
| `amanirenas evidence` | inspect the latest assessment evidence |
| `amanirenas findings` | inspect the latest assessment findings |
| `amanirenas profile` | generate a deterministic sample app profile |
| `amanirenas rules` | list the registered analysis rules |
| `amanirenas sources` | list supported mobile sources and their status |
| `amanirenas target` | manage assessment targets (profile files and simulation) |
| `amanirenas tui` | start the interactive terminal application |

