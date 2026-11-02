# Sources & data provenance

CleanReach fetches **nothing at runtime** and bundles **no third-party
lists verbatim**. What ships in the box:

| What | Where | Provenance |
|---|---|---|
| Disposable starter list (296 domains) | `core/src/disposable.txt` | Curated in-repo from universally-known disposable providers (Mailinator, Guerrilla Mail, YOPmail, 10MinuteMail, …). Domain names are facts, not copyrighted expression. |
| Free-provider list (~40 domains) | `core/src/lib.rs` (`FREE_PROVIDERS`) | Curated in-repo (Gmail, Yahoo, Outlook, …). |
| Role local-parts list | `core/src/lib.rs` (`ROLE_LOCALS`) | Curated in-repo (support@, info@, postmaster@, …). |

## Growing the disposable list

The built-in list is a starter, by design. For production list work,
drop in the community-maintained list and pass it to the CLI or paste
it in Settings:

- **BillionVerify/disposable** (MIT) — a large community disposable
  domain list merged from many public sources:
  https://github.com/BillionVerify/disposable

```bash
cleanreach clean list.csv --disposable-list disposable-domains.txt
```

## Pattern & design sources

See [THANKS.md](THANKS.md) for the full credits table — engine
inspirations, verifier libraries, and the design-pattern projects
(taste-skill, hallmark, no-ai-slop, anti-slop, aislop, getdesign.md)
that shaped this build. No code from AGPL projects is included;
AfterShip/email-verifier (MIT) is credited as a sidecar pattern, not
vendored.
