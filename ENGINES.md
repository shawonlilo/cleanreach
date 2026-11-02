# CleanReach engines

CleanReach is built around one rule: **the default engine must work
fully offline, deterministically, on the user's own device.**

## 1. Native engine — `cr-core` (default, built-in)

Pure-Rust, zero external crates. It does:

- Extraction of emails/phones from CSV, TSV, plain lists and messy text
- Email syntax validation (strict RFC-5322 subset)
- Disposable/temp detection (built-in starter list of 296 domains in
  `core/src/disposable.txt`, parent-domain matching, plus any list the
  user adds)
- Optional domain MX checks and MX/SPF/DMARC domain health (raw DNS)
- Deterministic lane classification (see README "Lanes")
- GB/US/CA phone validation + E.164 normalization
- File toolkit: split / merge / dedupe / extract
- Optional SMTP probe — **off by default**, CLI-only
  (`cleanreach clean list.csv --smtp-probe`), for lists you own

No AI calls. No telemetry. The same input always gives the same output.

## 2. Optional sidecar engines (BYOK, your machine, your keys)

Two Go verifier projects from the same open-tools family can run as
independent local HTTP services and be used as a *second opinion*
alongside the native verdicts. They are **not bundled** and CleanReach
never sends your list anywhere unless *you* run a sidecar and point
CleanReach at it:

| Sidecar | Origin | Shape |
|---|---|---|
| TrueMail Go verifier | TrueMail-style Go verifier service | HTTP JSON API: POST an address, get a verdict object (syntax, MX, SMTP, disposable flags) |
| AfterShip email-verifier | [AfterShip/email-verifier](https://github.com/AfterShip/email-verifier) (MIT) Go library/service | HTTP JSON API around the `email-verifier` Go package |

Expected sidecar contract (either engine):

```http
POST /verify  {"email": "jane@example.com"}
200 OK        {"syntax_ok": true, "mx_ok": true, "disposable": false,
               "role": false, "free_provider": false, "verdict": "deliverable"}
```

Sidecar verdicts are advisory: where a sidecar disagrees with the
native engine, CleanReach reports the address as `unknown` with both
opinions attached — never silently "valid".

**Credentials:** sidecars that call third-party APIs use **your own
keys** (BYOK), configured on the sidecar service itself via its own
environment — never in this repository, never in the CleanReach app.
This repository contains no credentials of any kind.

## 3. What is deliberately NOT an engine

- No copied Reacher / check-if-email-exists code (AGPL) — it is a
  design reference only.
- No cloud verification APIs by default — your list stays on your disk.
- No AI/LLM classification — verdicts must be reproducible and auditable.
