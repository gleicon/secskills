---
class: files-deserialization
owasp_top10: A08:2021 — Software & Data Integrity (deserialization) + file handling
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: File Upload, url: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html}
  - {name: Deserialization, url: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html}
  - {name: Input Validation, url: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html}
  - {name: Mass Assignment, url: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html}
---

# File Upload, Path Traversal & Deserialization

## File upload — remediation
- **Allow-list** extensions **and** validate content type by magic bytes, not the client `Content-Type`.
- Store outside the web root; generate a new random filename; never use the user-supplied name in the path.
- Cap size; scan for malware; serve with `Content-Disposition: attachment` and a fixed content type.
- Block double extensions, null bytes, and path separators. Never let an upload land in an executable path.

## Path traversal — remediation
- Canonicalize the resolved path and confirm it stays within an intended base directory; reject `..`, absolute paths, and encoded variants.
- Use safe file APIs with a fixed base; never concatenate user input into a path. Smells: `php-lfi-include`, TOCTOU (`*-toctou-*`) — check-then-open races.

## Deserialization — remediation
- **Never deserialize untrusted data** with native object deserializers:
  `pickle`, `yaml.load` (unsafe), Java `ObjectInputStream`, Ruby `Marshal.load`, PHP `unserialize`. Smells: `py-injection-pickle-loads`, `*-yaml-load-unsafe`, `rb-deserialization-marshal-load`, `vibe-ts-langchain-dangerous-deserialization`.
- Prefer a **data-only** format (JSON) with a schema; use `yaml.safe_load`.
- If native deserialization is unavoidable: sign+verify the payload (HMAC), restrict allowed types (allow-list), and run isolated.

## Mass assignment — remediation
- Bind only an explicit allow-list of fields (strong params / DTOs); never bind the whole request body to a model.
- Protect sensitive attributes (`is_admin`, `role`, `price`) from client control. Smell: `vibe-rb-mass-assignment-permit-all`.

## Input validation (cross-cutting)
- Validate on the server: type, length, range, format — allow-list over deny-list.
- Validation is not a substitute for output encoding (XSS) or parameterization (SQLi) — do both.

## Verify the fix
Re-upload a disallowed/spoofed-type file → rejected. Re-send a `..` path → blocked.
Re-send a crafted serialized object → not instantiated.
