# Recipes — Authentication & Session (A07), per stack

Pair with `kb/auth-session/`. Stacks: Node.js, Python, Go.

## Password hashing — memory-hard, salted

**Node (argon2)**
```js
const argon2 = require('argon2');
const hash = await argon2.hash(password, { type: argon2.argon2id });
const ok = await argon2.verify(hash, password);   // never MD5/SHA-1/plain SHA-256
```
**Python (argon2-cffi, or passlib bcrypt)**
```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
ph.verify(hash, password)
```
**Go (golang.org/x/crypto/bcrypt or argon2)**
```go
hash, _ := bcrypt.GenerateFromPassword([]byte(pw), 12)      // cost >= 10
err := bcrypt.CompareHashAndPassword(hash, []byte(pw))
```

## Session cookies — Secure, HttpOnly, SameSite

**Node (express-session)**
```js
app.use(session({ secret: process.env.SESSION_SECRET, resave:false, saveUninitialized:false,
  cookie: { secure:true, httpOnly:true, sameSite:'lax', maxAge: 3600_000 } }));
```
**Python (Flask)**
```python
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=3600)
```
**Go (net/http)**
```go
http.SetCookie(w, &http.Cookie{Name:"sid", Value:id, Secure:true, HttpOnly:true,
  SameSite: http.SameSiteLaxMode, MaxAge: 3600, Path:"/"})
```

## Regenerate session on privilege change (anti-fixation)
- Node: `req.session.regenerate(cb)` after login.
- Flask: `session.clear()` + set a fresh id on login.
- Go: issue a new session id server-side; invalidate the pre-login one.

## JWT — pin algorithm, reject `none`
**Node (jsonwebtoken)**
```js
jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });   // never allow 'none'/HS-confusion
```
**Python (PyJWT)**
```python
jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"], options={"require":["exp","iss","aud"]})
```
**Go (golang-jwt)**
```go
jwt.Parse(tok, func(t *jwt.Token) (any, error) {
  if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok { return nil, errors.New("alg") }
  return pub, nil
})
```

## Lockout / enumeration
- Uniform "invalid username or password"; rate-limit + progressive delay; MFA for sensitive/admin.

Verify: re-run enumeration/lockout/fixation probes → uniform responses, enforced lockout, rotated session id, correct cookie flags.
