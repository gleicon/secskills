---
class: ssrf-xxe
owasp_top10: A10:2021 — Server-Side Request Forgery (+ XXE)
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Server-Side Request Forgery Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html}
  - {name: XML External Entity Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html}
---

# SSRF (A10) & XXE

## SSRF — detection
- URL/redirect/webhook/image-fetch parameters that make the server request a URL.
- Probe cloud metadata and internal hosts (non-destructive read):
  `?url=http://169.254.169.254/latest/meta-data/`, `?to=http://internal-host/`.
- Watch for internal responses, differential timing, or DNS callbacks.

## SSRF — remediation
- **Allow-list** destination hosts/schemes/ports; deny by default. Prefer a fixed set of known endpoints.
- Block private/link-local/loopback ranges (RFC 1918, 169.254.0.0/16, ::1, fc00::/7) **after DNS resolution** — resolve, validate the resolved IP, then connect to that IP (defeats DNS-rebinding and redirect bypass).
- Disable unneeeded URL schemes (`file:`, `gopher:`, `ftp:`); disable following redirects to new hosts.
- No raw error/response passthrough to the client.
- Network-layer egress controls; block the metadata endpoint / require IMDSv2.
- Smell: `vibe-py-ssrf-requests-user-url`.

## XXE — detection
- XML parsers accepting user-supplied documents (SOAP, SAML, SVG, DOCX, config uploads).
- Test external-entity and parameter-entity payloads (file read, SSRF via entity) — carefully, non-destructive.

## XXE — remediation
- **Disable DTDs / external entities** in the parser — the single most effective fix.
  - Java: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
  - libxml2: do not set `NOENT`; disable network access.
  - .NET: `XmlReaderSettings.DtdProcessing = Prohibit`.
- Prefer JSON or a hardened parser; validate against a schema.

## Verify the fix
Re-send the SSRF payload → expect rejection/allow-list block, no internal
response. Re-send the XXE payload → external entity not resolved.
