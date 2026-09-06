---
name: secskills-intake
description: "Pre-engagement interview for a security assessment. Researches the target with passive OSINT to inform, then grills the operator one question at a time — authorization, exact scope, target class, credentials, rules of engagement, deliverable — until nothing is loose. Produces a locked engagement brief (ENGAGEMENT.md) and scope file (.secskills-scope.yml) that discover/test honor without re-prompting."
disable-model-invocation: true
---

Run the intake **before** any discover/test. Goal: reach a complete, unambiguous
engagement definition so the assessment has nothing loose. Style: relentless,
one question at a time, always recommend an answer, and **research instead of
asking** whenever the answer is discoverable.

## Step 1 — Research first (do not ask what you can find)

Run passive OSINT to pre-fill the brief (no traffic to the target):

```bash
secskills profile <target> --output ENGAGEMENT-profile.md
```

This yields: subdomain count, environment tiers (preprod/staging/…), service/infra
signals (sso/iam/api/vault/registry/…), DNS edge/CDN, mail/NS provider, and — if a
Shodan key is set — IP blocks, ASN/org, and third-party SaaS. Read it. Use it to
make specific, informed recommendations, not generic ones.

## Step 2 — Grill, one question at a time

Ask **one** question, give your **recommended answer**, wait, then the next.
Resolve every branch. Stress-test boundaries with concrete edge cases. Pin down
vague terms. Cover, in order:

1. **Authorization (blocking).** Is there written authorization from the target
   owner? Who approved it (name/role)? Testing window (start/end)? — *Recommend:
   do not proceed without it; capture approver + expiry.*
2. **Engagement type.** black-box / grey-box / white-box? — *Recommend based on
   whether creds/docs will be provided.*
3. **Exact scope.** Which apex domains? Which subdomains are **in** scope — all
   discovered, or a named subset? Any hosts explicitly **out** of scope
   (shared/third-party/production-critical)? — *Use the profile's subdomain list;
   confirm the preprod/sandbox hosts should be tested.* Stress-test: "the profile
   shows `sso-corp` and `iam-*preprod` — are the identity systems in scope, or
   excluded as sensitive?"
4. **Network layer.** Any IP ranges / ASN in scope for network testing, or web/app
   only? — *Recommend web/app only unless the profile's IP blocks are owned by the
   client and explicitly authorized.*
5. **Target class (drives the framework).** Web app / API / mobile app / LLM-or-agent
   system? — *Web/API → OWASP Web Top 10; mobile → `kb/mobile` (MASTG); LLM/agent →
   `kb/llm-agents`.* Ask if a mobile binary or LLM endpoint is in scope.
6. **Credentials.** Are credentials provided for authenticated testing (token /
   cookie / test account)? — *If yes, capture how to supply them
   (`--auth-token`/`--cookie`); if no, authenticated testing is marked **not
   available** and the authenticated surface (IDOR, priv-esc, business logic) is
   out of this pass.*
7. **Rules of engagement.** Intrusive tests allowed (write-probes, credential
   stuffing)? Rate limit / concurrency ceiling? Production or staging? Maintenance
   window required? — *Recommend non-destructive default; intrusive only with a
   second explicit confirmation.* DoS / mass third-party scanning are always excluded.
8. **Deliverable.** Output location? Formats (Markdown, HTML, **PDF** for a
   CISO/SOC 2 evidence)? PII handling (scrub before reporting)? — *Recommend PDF +
   Markdown; always scrub PII into the report.*

If the operator asserts a fact you can check (e.g. "we don't run preprod publicly"),
check it against the profile and surface the conflict.

## Step 3 — Lock the brief

Write two artifacts in the working directory (never `.project/`):

- **`.secskills-scope.yml`** — the machine-readable scope the gate honors. Seed it:
  ```bash
  secskills scope --init          # writes the template
  ```
  Then fill: `authorized: true` (only with written auth), `engagement_type`,
  `confirmed_by`, `expires`, `intrusive`, `targets:`, `out_of_scope:`. Validate:
  ```bash
  secskills scope --validate
  ```
  Once `authorized: true` and the target is listed, `discover`/`test` pass the gate
  without `--confirm` — the engagement is fully scoped, nothing loose.

- **`ENGAGEMENT.md`** — the human brief: all resolved answers, the profile summary,
  the framework(s) selected, credentials status, RoE, and the exact commands to run:
  ```bash
  secskills discover <target>
  secskills test <target> --deep [--auth-token <t>]
  secskills report --pdf <target> --output <deliverable>.pdf
  ```

## Step 4 — Confirm and hand off

Summarize the locked engagement. Confirm nothing is unresolved:
authorization ✓, scope in/out ✓, target class ✓, credentials ✓/not-available,
RoE ✓, deliverable ✓. Then hand to `/secskills-discover` → `/secskills-test` →
`/secskills-report`. Do not start testing from this skill.
