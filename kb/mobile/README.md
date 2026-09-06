---
class: mobile
owasp: OWASP Mobile Top 10 (2024) + OWASP MASVS / MASTG
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Mobile Application Security (https://mas.owasp.org/) + OWASP Mobile Top 10 (https://owasp.org/www-project-mobile-top-10/)
snapshot: authored 2026-09-06 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Mobile Application Security (MASVS/MASTG), url: https://mas.owasp.org/}
  - {name: OWASP Mobile Top 10 2024, url: https://owasp.org/www-project-mobile-top-10/}
  - {name: iOS/Android Security Testing, url: https://mas.owasp.org/MASTG/}
---

# OWASP Mobile Top 10 (2024)

For mobile app targets (APK/IPA, mobile backends). Verify against MASVS controls;
test with MASTG procedures.

| # | Category | What to check |
|---|----------|---------------|
| M1 | Improper Credential Usage | hardcoded/API keys in the binary, insecure credential storage, credential reuse |
| M2 | Inadequate Supply Chain Security | vulnerable SDKs/libraries, unsigned/tampered third-party components |
| M3 | Insecure Authentication/Authorization | weak/absent auth, client-side auth decisions, missing server-side authZ |
| M4 | Insufficient Input/Output Validation | injection via IPC/deeplinks, WebView, unsafe deserialization |
| M5 | Insecure Communication | missing TLS/cert pinning, cleartext traffic, weak ciphers |
| M6 | Inadequate Privacy Controls | PII over-collection, leakage via logs/analytics/backups |
| M7 | Insufficient Binary Protections | no obfuscation, debuggable builds, missing anti-tamper/root-jailbreak checks |
| M8 | Security Misconfiguration | debug flags, exported components, permissive `network_security_config` |
| M9 | Insecure Data Storage | secrets/PII in SharedPreferences/plist/SQLite/keychain misuse |
| M10 | Insufficient Cryptography | hardcoded keys, weak algorithms, custom crypto |

## Testing surface (MASTG)

- **Static (APK/IPA):** decompile (`jadx`, `apktool`, `class-dump`); scan for
  secrets (trufflehog/gitleaks), hardcoded endpoints, `android:debuggable`,
  exported activities/services/receivers, `usesCleartextTraffic`, insecure
  `WebView` (`setJavaScriptEnabled` + `addJavascriptInterface`).
- **Storage:** inspect app sandbox — SharedPreferences, SQLite, Keychain/Keystore,
  external storage, backups.
- **Network:** intercept with a proxy; test TLS + **certificate pinning** bypass;
  check for cleartext, weak ciphers (see `kb/crypto-secrets`).
- **Auth/IPC:** deeplink/intent fuzzing, auth-token handling, server-side authZ
  (the mobile backend is a web API — also apply `kb/access-control`, `kb/auth-session`).

## Direction after findings

- Hardcoded secret in binary → rotate + move to server; `kb/crypto-secrets`.
- Missing pinning / cleartext → enforce TLS + pinning; `kb/crypto-secrets`.
- Exported component / injection → `kb/injection`, `kb/access-control`.
- The mobile **backend API** is tested as a web app — cross-apply the Web Top 10.
