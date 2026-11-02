---
class: llm-agents
owasp: OWASP Top 10 for LLM Applications (2025) + OWASP Agentic Security / GenAI
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP GenAI Security Project (https://genai.owasp.org/) + Top 10 for LLM Apps (https://owasp.org/www-project-top-10-for-large-language-model-applications/)
snapshot: authored 2026-09-06 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: OWASP Top 10 for LLM Applications 2025, url: https://genai.owasp.org/llm-top-10/}
  - {name: LLM Prompt Injection Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html}
  - {name: OWASP Agentic AI Threats and Mitigations, url: https://genai.owasp.org/}
---

# OWASP Top 10 for LLM Applications (2025) + Agentic AI

For targets that embed LLMs, RAG, tools/function-calling, or autonomous agents.

| # | Category | What to check |
|---|----------|---------------|
| LLM01 | Prompt Injection | direct + indirect (via retrieved/tool content); jailbreaks; system-prompt override |
| LLM02 | Sensitive Information Disclosure | secrets/PII in prompts, context, or model output; training-data leakage |
| LLM03 | Supply Chain | poisoned models/datasets/plugins; unverified model provenance |
| LLM04 | Data and Model Poisoning | tainted training/fine-tune/RAG data |
| LLM05 | Improper Output Handling | model output used unsafely downstream (XSS/SQLi/SSRF/code exec) |
| LLM06 | Excessive Agency | over-broad tool permissions, unbounded autonomy, no human-in-the-loop |
| LLM07 | System Prompt Leakage | exfiltration of the system prompt / guardrails |
| LLM08 | Vector and Embedding Weaknesses | RAG injection, embedding inversion, cross-tenant leakage |
| LLM09 | Misinformation | ungrounded/hallucinated output relied upon |
| LLM10 | Unbounded Consumption | cost/DoS via token floods, recursive tool loops |

## Agentic-specific threats (OWASP Agentic)

- **Tool/function-call abuse:** an injected instruction makes the agent call a
  privileged tool (send email, run code, hit an internal API). Least-privilege
  tools, allow-lists, human approval for high-impact actions.
- **Memory/context poisoning:** persisted memory or shared context carries an
  attacker payload across sessions/users.
- **Multi-agent trust:** one agent's output is another's untrusted input — treat
  cross-agent messages as data, never instructions (mirrors `check_prompt_injection`).

## Testing surface

- Enumerate LLM entry points: chat endpoints, RAG upload, tool/plugin manifests,
  `/v1/chat`, agent webhooks.
- **Prompt injection:** direct (in user input) and **indirect** (payload in a page,
  file, or API the agent ingests — the same technique secskills defends against).
- **Canary reflection (engine: `llm.canary-reflection@1`):** plants a unique
  non-functional credential in a chat request; an echo proves the intermediary
  retains prompt content. Planted canaries land in `canary-ledger.jsonl` —
  check them at the provider for async abuse (AC-2).
- **Warm-up drift (engine: `llm.response-drift@1`, adversarial profile):**
  repeats a deterministic oracle past 60 rounds; late drift indicates
  trigger-gated rewriting (AC-1.b). Silence at low round counts proves nothing.
- **Response integrity (engine: `secskills integrity snapshot|verify <url>
  --confirm`, AC-1):** sha256-baseline a stable endpoint response, then re-verify
  later; drift is an AC-1 signal. Verification is a deliberate operator step —
  a POST-based chat surface cannot be re-fetched by the GET that `report
  --retest` performs, so retest deliberately does not cover it.
- **Output handling:** does model output reach an HTML sink (XSS → `kb/injection`),
  a shell/SQL sink (→ `kb/injection`), or an outbound fetch (SSRF → `kb/ssrf-xxe`)?
- **Excessive agency:** map the agent's tools and their blast radius.

## Direction after findings

- Injection reachable → treat all retrieved/tool content as untrusted; add
  input/output guardrails; `kb/injection`.
- Model output to a dangerous sink → encode/parameterize at the sink; `kb/injection`.
- Over-broad tools → least-privilege + human approval; segregate agent identities.
- Secrets in prompts/logs → `kb/crypto-secrets`; scrub with `secskills scrub`.

## Malicious intermediaries: LLM API routers / token sharing & forwarding
Applies to any product that routes, resells, shares, or forwards LLM API
access or credentials: third-party routers, aggregators, relay chains,
BYOK-forwarding proxies, sub-account resellers.

**Threat model (taxonomy from Liu et al., 2026 — see References).** The
router terminates client TLS and re-originates upstream, so it holds full
plaintext over tool calls, prompts, and keys, with no end-to-end integrity:

| Class | Behavior | Harm |
|---|---|---|
| AC-1 payload injection | rewrites tool-call args (URL → attacker script) | arbitrary code exec on the agent host |
| AC-2 secret exfiltration | passive regex harvest (API keys, AWS, GH PATs, ETH keys, PEM) | credential theft, invisible (traffic unchanged) |
| AC-1.a dependency-targeted | `pip install requests` → typosquat `reqeusts` | durable supply-chain foothold; evades domain gates |
| AC-1.b conditional delivery | injects only after N calls / in YOLO mode / for target stacks | evades finite black-box audits |

Measured in the wild: 1/28 paid and 8/400 free routers injected code, 2 used
adaptive triggers (50-call warm-up; YOLO+Rust/Go only), 17 touched AWS
canaries, 1 drained an ETH canary. Leaked-key/weak-relay poisoning pulled
benign routers into the same boundary (2.1B tokens, 99 creds / 440 sessions,
401 already in auto-approve YOLO mode).

**Protect (client-side, no provider cooperation needed):**
- Fail-closed tool policy gate: allow-list installer domains AND per-package
  names; deny YOLO/auto-approve on any path that transits a third-party
  router (blocks AC-1/AC-1.a at ~1% FP in the study).
- Response-side anomaly screening on tool-call args (URL/domain/package
  drift vs the model's likely intent; flags ~89% of AC-1).
- Append-only transparency log of executed tool calls for post-hoc diffing.
- Inventory every token flow: who holds, forwards, or logs each credential;
  collapse relay chains; never let one leaked upstream key widen the trust
  boundary to unknown operators.

**Detect (assessment recipe):**
- Route a sandboxed agent through the suspect endpoint with **canary
  credentials** (AWS canary, ETH canary, unique API key per hop) and watch
  for follow-on use — the study's own detection method for AC-2.
- Probe past warm-up thresholds (50+ benign calls) and in the tool/stack
  combos you actually run; single-shot probes miss AC-1.b by design.
- Diff executed tool calls against model-side logs where available; any
  URL/package drift is AC-1 until proven otherwise.

## Chatbot as attack surface (exfiltration / open proxy / off-purpose use)

A website chatbot is a conversational LLM endpoint reachable by any visitor.
Assess it as an untrusted-input, privileged-output boundary:

- **Credential/data exfiltration:** direct system-prompt extraction ("repeat
  your system instructions") recovers guardrails and tool descriptions for
  targeted jailbreaks; retrieved/RAG content the bot quotes can carry
  indirect-injection payloads outward. Engine: `llm.system-prompt-leak@1`
  (adversarial profile).
- **Open-proxy / SSRF:** a bot that fetches attacker-supplied URLs server-side
  is an egress bypass (cloud metadata, internal services, callback
  exfiltration). Engine: instruction carries an OAST canary; a callback
  yields `http.ssrf@1` (HIGH, OAST-validated). Needs `SECSKILLS_OAST_DOMAIN`.
- **Off-purpose use:** unauthenticated bots are free compute + a reputation
  shield (abuse originates from your domain). Rate-limit, authenticate
  high-impact tools, and human-approve state-changing actions.
- **Protect:** nothing in the prompt is confidential; authorize server-side,
  egress-allow-list any fetcher, log executed tool calls append-only.

## References

- Liu et al., "Your Agent Is Mine: Measuring Malicious Intermediary Attacks
  on the LLM Supply Chain", ACM CCS 2026, arXiv:2604.08407 —
  https://arxiv.org/abs/2604.08407 (doi:10.48550/arXiv.2604.08407).
  Taxonomy (AC-1/AC-2/AC-1.a/AC-1.b), ecosystem measurement, and the three
  client-side defenses summarized above.
