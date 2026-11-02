# Changelog

## v0.2.0 — 2026-11-02 🤍 Essential Light edition

- 🤍 **New V1 Essential Light design** — the Stitch design-program winner,
  now the app's official look: warm off-white paper surfaces, white cards
  with soft tinted borders and gentle shadows, strong mint + amber brand
  accents, colored lane pills and stat chips. Premium light, never plain
  stark white.
- 🎨 Visual rebuild only — every feature, command and export from v0.1.0
  works exactly as before (clean pipeline, honest lanes, phone validator,
  domain health, file toolkit, consented-phones bridge).


## v0.1.0 — 2026-11-02 🎉 First release

CleanReach — Contact Hygiene Studio is born (beta).

- 🧽 **Full pipeline:** import CSV/TSV/plain text/messy text → extract
  emails + phones → dedupe → verify → classify → export
- 🏷️ **Honest lanes:** clean-personal, clean-corporate, role,
  free-provider-risky, disposable, invalid, unknown (unknown ≠ invalid)
- 🚫 **Disposable/temp addresses removed from clean.csv by default**
  (built-in starter list of 296 domains + user-importable lists)
- 📱 **Phone module:** GB/US/CA validation + E.164, honest
  "line type: unknown"
- 🤝 **Consented-phones bridge:** `consented_phones.csv` exports ONLY
  consent=true + valid-phone rows, for the separate Opt-in Messaging
  product
- 🌐 **Domain health:** A / MX / SPF / DMARC over raw DNS
- 🧰 **File toolkit:** split, merge, extract in app and CLI
- 💻 **CLI** (`cleanreach`) for Windows, macOS and Linux + Docker image
- 📱 **Android APK** (CI-signed, sideloadable)
- 🔒 **Private by architecture:** everything runs on your device, no
  credentials in the repo (BYOK sidecars), deterministic verdicts,
  optional SMTP probe off by default (CLI-only)
- ✅ 15 core unit tests + verified end-to-end fixture (every lane)
