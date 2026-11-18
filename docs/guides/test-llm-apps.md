# Testing LLM apps, chatbots, and LLM gateways

Checks for applications that put a model behind an HTTP endpoint, and for API
gateways or proxies that sit between clients and a model provider. Grounded in
the OWASP Top 10 for LLM Applications (`secskills kb llm-agents`).

## What is probed

`test` looks for chat surfaces on each live host: an OpenAI-compatible
`/v1/chat/completions` and an Ollama-style `/api/chat`.

| Check | Profile | Finding when |
|---|---|---|
| Canary reflection | every profile | a planted, non-functional canary comes back in a later answer — the intermediary keeps or reflects prompt content |
| System-prompt leak | `adversarial-readonly` | the bot discloses its instructions on direct request |
| Response drift | `adversarial-readonly` | a deterministic question gets different answers across warm-up rounds (conditional behaviour) |
| Server-side fetch | `adversarial-readonly` + OAST | the bot fetches a URL it was given, confirmed by a callback |

Each probe is a single benign request per round, rate-gated, and never asks the
model to act on real data. A request can still create a session on the target;
run it only where the owner agreed.

## Run

```bash
secskills test chat.example.com --confirm
secskills test chat.example.com --confirm --profile adversarial-readonly
```

For the server-side fetch check, run an OAST collaborator and point secskills at it:

```bash
secskills oast-server --listen :8080 --store oast.jsonl
export SECSKILLS_OAST_DOMAIN=oast.example SECSKILLS_OAST_POLL_URL=https://oast.example/poll
```

## Detect a gateway that rewrites responses

If clients reach the model through a proxy you don't control, record a hash of a
stable endpoint's answer now and compare later:

```bash
secskills integrity snapshot https://gateway.example.com/v1/models --confirm
secskills integrity verify   https://gateway.example.com/v1/models --confirm
```

A changed hash on an unchanged endpoint indicates the intermediary is altering
traffic. Baselines go to `integrity-baselines.jsonl` (override with `--store`).

## Treat model output as untrusted

Bot answers can carry instructions aimed at whoever reads them, including an
agent. Run saved transcripts through `secskills scan <file>` before analysis;
target strings in findings and reports are already neutralized.

## Going deeper

`secskills kb llm-agents` covers prompt injection, insecure output handling,
excessive agency, and agent-to-agent risks, with what to test by hand next.
