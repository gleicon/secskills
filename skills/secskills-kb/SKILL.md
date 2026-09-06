---
name: secskills-kb
description: "OWASP knowledge base lookup. Returns on-disk OWASP Cheat Sheet Series and Top 10 guidance for a security class — controls, checks, and remediation — with provenance. Fully offline; no network at invoke. Grounds the other secskills modes and answers reference questions on their own."
---

Serve OWASP guidance from `kb/` for a given class or free-text intent. Read-only,
offline (NFR-3). No target is touched — no authorization gate.

## Layout

```
kb/
  top10/                     OWASP Top 10 2021 index → class + cheat sheets
  injection/                 A03 — SQLi, XSS, command, SSTI, LDAP
  access-control/            A01 / A04 — authz, IDOR, CSRF
  auth-session/              A07 — authN, password storage, session, JWT, MFA
  crypto-secrets/            A02 — crypto storage, TLS, secrets, key management
  config-exposure/           A05 / A08 — misconfig, headers, CORS, exposure
  components-supply-chain/   A06 — dependencies, CVE, SRI
  ssrf-xxe/                  A10 — SSRF, XXE
  files-deserialization/     file upload, path traversal, deserialization
  logging-monitoring/        A09 — security logging, monitoring
```

Each `<class>/` holds one or more markdown entries. Every entry opens with a
provenance block (source cheat sheet, URL, snapshot ref, CC BY-SA 4.0).

## Procedure

1. Map the request to a class via `kb/top10/README.md` (the Top 10 → class →
   cheat-sheet index) or the intent table in `skills/secskills/SKILL.md`.
2. Read only that class's file(s) — each skill loads its own content (NFR-2).
3. Return the relevant controls/checks/remediation. Preserve the provenance and
   attribution when reproducing content (CC BY-SA ShareAlike).

## Refresh

Content is a vendored snapshot (D-8). To update against upstream, run
`tools/ingest.sh` — it fetches the OWASP Cheat Sheet Series source, normalizes
entries with provenance front-matter, and reports which `kb/` files changed.
Offline until then.
