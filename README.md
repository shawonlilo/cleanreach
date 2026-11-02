# CleanReach — Free Email Verifier & Contact Hygiene Studio | Bulk Email List Cleaner, Disposable Email Checker, Phone Validator

![CleanReach banner](assets/banner.webp)

[![License: MIT](https://img.shields.io/badge/License-MIT-3ED598.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20·%20macOS%20·%20Linux%20·%20Debian%20·%20Android-F2B33D.svg)](#-download)
[![Built with Rust + Tauri](https://img.shields.io/badge/Built%20with-Rust%20%2B%20Tauri%202-0B1210.svg)](#)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20offline%20·%20your%20list%20never%20leaves%20your%20device-3ED598.svg)](#-honest-by-design)

**CleanReach is a free, open-source contact hygiene studio** ✨ — a bulk email verifier and email list cleaner that takes your messy CSV, text file or pasted list and returns **honest, lane-separated clean data**:

- 🧽 **Extracts** emails & phones from CSVs, messy text, mixed files
- 🚫 **Removes disposable / temp emails from the clean export by default**
- 🏷️ **Classifies every address** — clean-personal, clean-corporate, role accounts, free-provider-risky, disposable, invalid, **unknown (never faked as invalid or valid)**
- 📱 **Validates phone numbers** (GB / US / CA) and normalizes to E.164
- 🤝 **Exports a consented-phones lane** — only rows with `consent=true` — ready for opt-in messaging
- 🌐 **Checks domain health** — MX, SPF, DMARC
- 🔒 **Runs 100% on your device** — no uploads, no accounts, no per-email credits, forever free

> Built for list owners, marketers, founders and data cleaners who are tired of paying per-email for black-box verdicts. **Use it on lists you own or are authorized to use.**

---

## ✨ Features

| | |
|---|---|
| 🧽 Full pipeline | Import → extract → split/merge → dedupe → verify → classify → export |
| 🚫 Disposable remover | Built-in starter list (296 domains) + drop in the full community list — temp mail never reaches `clean.csv` |
| 🏷️ Honest lanes | 7 lanes with a plain-English *reason* on every single row |
| 📧 Email checks | Syntax, disposable, role detection, free-provider flagging, optional MX checks |
| 📱 Phone validator | GB/US/CA format + E.164, honest "line type: unknown" |
| 🧰 File toolkit | Split huge lists, merge many files, extract emails from anything |
| 🤝 Consent bridge | `consented_phones.csv` — the only export that feeds Opt-in Messaging, consent-gated by construction |
| 🌐 Domain health | A / MX / SPF / DMARC over raw DNS |
| 💻 CLI + Docker | Script it, schedule it, pipe it |
| 📱 Android app | Same studio in your pocket |

## 🔄 How it works

```
Messy list (CSV / TXT / paste)
        │
        ▼
  Extract emails + phones ──► Dedupe ──► Verify (syntax · disposable · MX)
        │
        ▼
  Classify into lanes ──► clean-personal · clean-corporate · role ·
                          free-provider-risky · disposable · invalid · unknown
        │
        ▼
  Exports: clean.csv · disposable.csv · role.csv · invalid.csv ·
           risky.csv · consented_phones.csv · results.json · summary.md
```

## 🏷️ The lanes

| Lane | Meaning | In `clean.csv`? |
|---|---|---|
| `clean-personal` | Well-formed, not disposable/role/free-provider | ✅ |
| `clean-corporate` | Well-formed on a domain with MX | ✅ |
| `free-provider-risky` | Gmail/Yahoo/Outlook… real inbox possible, ownership unverifiable | ✅ (flagged) |
| `role` | support@, info@, postmaster@… function mailboxes, exported separately | ❌ separate file |
| `disposable` | Temp/disposable domain — **removed by default** | ❌ separate file |
| `invalid` | Not a well-formed address | ❌ separate file |
| `unknown` | Couldn't verify (e.g. domain has no MX) — **unknown ≠ invalid** | ❌ separate file |

## ⚖️ CleanReach vs paid verifiers

| | CleanReach | Typical paid verifier |
|---|---|---|
| Price | **Free forever (MIT)** | Per-email credits, subscriptions |
| Privacy | **Your list never leaves your device** | Upload your whole list to their cloud |
| Works offline | ✅ | ❌ |
| Verdicts | Deterministic, every row explains *why* | Black-box scores |
| Disposable removal | ✅ default | Usually an upsell |
| Source code | ✅ open | ❌ closed |

## 📥 Download

Grab the latest release for your platform:

| Platform | File |
|---|---|
| Windows | `CleanReach_0.1.0_x64-setup.exe` or `.msi` |
| macOS (Apple Silicon) | `CleanReach_0.1.0_aarch64.dmg` |
| macOS (Intel) | `CleanReach_0.1.0_x64.dmg` |
| Linux | `CleanReach_0.1.0_amd64.AppImage` or `.deb` (Debian/Ubuntu) |
| Android | `cleanreach-android.apk` (CI-signed, sideload) |
| CLI only | `cleanreach-windows-x64.exe` · `cleanreach-macos-arm64` · `cleanreach-linux-x64` |
| Docker | `docker build -t cleanreach .` |

iOS is planned (companion mode), not yet released — we only list platforms you can actually download.

## 💻 CLI usage

```bash
# Clean a list (writes cleanreach-out/ with all lane exports)
cleanreach clean list.csv --out clean-out

# With MX checks + a bigger disposable list
cleanreach clean list.csv --mx --disposable-list disposable-domains.txt

# File toolkit
cleanreach extract messy-notes.txt
cleanreach merge part1.csv part2.csv > merged.txt
cleanreach split big.csv 5000

# One-off checks
cleanreach phone "07700 900123" --region GB
cleanreach domain example.com
```

Input with columns `email,phone,consent` is understood automatically; plain lists and messy text work too.

## 🔒 Honest by design

- **Syntax/MX/SPF checks are evidence, not inbox proof.** No tool can honestly guarantee a mailbox exists without sending mail — anyone who claims otherwise is selling you a score.
- **`unknown` is a real lane.** Greylisting, blocked probes and missing MX make some addresses unverifiable. We say so instead of guessing.
- **Free providers are "risky", not "valid".** A Gmail address is probably a real inbox; it is also unverifiable as *your* contact. Both things are true and the export shows it.
- **SMTP probing is off by default** and CLI-only — it's intrusive, so it is always an explicit choice for lists you own.
- **No credentials in this repo, ever.** Optional sidecar engines (see [ENGINES.md](ENGINES.md)) use *your own* keys (BYOK), configured on your own services.
- **No AI calls with your lists.** Verdicts are deterministic and reproducible.

## 🛠️ Build from source

```bash
cargo test                      # 15 core tests
cargo build --release --bin cleanreach
# App: cargo tauri build (in app/src-tauri) — installers via CI, see .github/workflows/release.yml
```

## 🙏 Thanks

Huge thanks to the projects and creators in [THANKS.md](THANKS.md) — AfterShip/email-verifier, BillionVerify/disposable, the owner's Reachers engine lineage, and the design-pattern creators (taste-skill, hallmark, no-ai-slop, anti-slop, aislop, getdesign.md).

## 📜 License

MIT — free for everyone, forever. Part of an open-source tools family alongside [Network Diagnostics](https://github.com/shawonlilo/network-diagnostics).

---
*Keywords: free email verifier · bulk email verifier · email list cleaner · disposable email checker · temp mail detector · email validation · contact hygiene · phone validator · csv cleaner · lead cleaning · deliverability · open source email verifier · offline email checker*
