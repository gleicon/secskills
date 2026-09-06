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
- **Output handling:** does model output reach an HTML sink (XSS → `kb/injection`),
  a shell/SQL sink (→ `kb/injection`), or an outbound fetch (SSRF → `kb/ssrf-xxe`)?
- **Excessive agency:** map the agent's tools and their blast radius.

## Direction after findings

- Injection reachable → treat all retrieved/tool content as untrusted; add
  input/output guardrails; `kb/injection`.
- Model output to a dangerous sink → encode/parameterize at the sink; `kb/injection`.
- Over-broad tools → least-privilege + human approval; segregate agent identities.
- Secrets in prompts/logs → `kb/crypto-secrets`; scrub with `secskills scrub`.
