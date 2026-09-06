# Recipes — Cryptography & Secrets (A02), per stack

Pair with `kb/crypto-secrets/`. Stacks: Node.js, Python, Go.

## CSPRNG — never Math.random / rand()

**Node**
```js
const { randomBytes, randomUUID } = require('node:crypto');
const token = randomBytes(32).toString('hex');   // not Math.random()
```
**Python**
```python
import secrets
token = secrets.token_hex(32)                     # not random.random()
```
**Go**
```go
import "crypto/rand"                               // not math/rand
b := make([]byte, 32); rand.Read(b)
```

## Authenticated encryption at rest (AES-256-GCM)

**Node**
```js
const { createCipheriv, randomBytes } = require('node:crypto');
const iv = randomBytes(12);
const c = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(pt), c.final()]); const tag = c.getAuthTag();
```
**Python (cryptography)**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ct = AESGCM(key).encrypt(nonce, plaintext, aad)   # never ECB
```
**Go**
```go
block, _ := aes.NewCipher(key); gcm, _ := cipher.NewGCM(block)
ct := gcm.Seal(nil, nonce, plaintext, aad)
```

## Secrets — out of code, from env/secret manager

**All stacks**
```
# VULN: const API_KEY = "sk_live_abc123"; SECRET = "hardcoded"
API_KEY = os.environ["API_KEY"]        # python
const key = process.env.API_KEY;       // node
key := os.Getenv("API_KEY")            // go
```
- No secrets in source, config committed to VCS, logs, or images.
- Store in Vault / cloud KMS / Secrets Manager; inject at runtime; rotate on exposure.
- Never log tokens/passwords. secskills `scrub` redacts them from any evidence blob before reporting.

## TLS — 1.2+ only, HSTS
- Server config: disable TLS 1.0/1.1/SSLv3, weak ciphers (RC4/3DES/EXPORT/NULL); prefer TLS 1.3, ECDHE.
- Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`; redirect HTTP→HTTPS.
- Go server hardening:
```go
srv := &http.Server{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
```

Verify: re-scan TLS (weak protocols/ciphers gone), confirm HSTS, confirm rotated secret no longer valid.
