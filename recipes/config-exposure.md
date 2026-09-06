# Recipes — Security Misconfiguration & Exposure (A05/A08), per stack

Pair with `kb/config-exposure/`. Stacks: Node.js, Python, Go.

## Security headers

**Node (helmet)**
```js
const helmet = require('helmet');
app.use(helmet());                              // HSTS, X-Frame-Options, nosniff, etc.
app.use(helmet.contentSecurityPolicy({ directives: {
  defaultSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"] }}));
```
**Python (Flask after_request)**
```python
@app.after_request
def secure(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
    return resp
```
**Go (middleware)**
```go
func secure(h http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
    h.ServeHTTP(w, r)
  })
}
```

## CORS — allow-list, never reflect Origin with credentials

**Node (cors)**
```js
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));  // not origin:true / '*'
```
**Python (flask-cors)**
```python
CORS(app, origins=["https://app.example.com"], supports_credentials=True)   # explicit list
```
**Go**
```go
if slices.Contains(allowed, r.Header.Get("Origin")) {
  w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))   // exact match only
}
```

## Don't expose internals
- Gate/firewall `/metrics`, `/actuator/*`, admin consoles, `/debug/pprof` — never unauthenticated.
- Disable directory listing, default accounts, verbose stack traces in prod (generic error pages).
- SRI (`integrity=`) on CDN scripts (A08); pin/lock third-party JS.

Verify: re-request headers present+correct; CORS rejects a foreign origin; the exposed endpoint now requires auth.
