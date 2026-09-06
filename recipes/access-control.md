# Recipes — Access Control (A01), per stack

Pair with `kb/access-control/`. Stacks: Node.js, Python, Go.

## Deny-by-default authorization middleware

**Node (Express)**
```js
function requireRole(role) {
  return (req, res, next) =>
    req.user && req.user.roles.includes(role) ? next() : res.status(403).end();
}
app.get('/admin', requireAuth, requireRole('admin'), handler);   // enforced server-side
```
**Python (FastAPI dependency)**
```python
def require_role(role: str):
    def dep(user=Depends(current_user)):
        if role not in user.roles: raise HTTPException(403)
        return user
    return dep

@app.get("/admin")
def admin(_=Depends(require_role("admin"))): ...
```
**Go (net/http middleware)**
```go
func RequireRole(role string, h http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    u := userFrom(r.Context())
    if u == nil || !u.Has(role) { http.Error(w, "forbidden", 403); return }
    h(w, r)
  }
}
```

## IDOR — verify ownership, don't trust the ID

**Node**
```js
// VULN: const doc = await Doc.findById(req.params.id)
const doc = await Doc.findOne({ _id: req.params.id, ownerId: req.user.id });
if (!doc) return res.status(404).end();     // ownership bound to the session subject
```
**Python (SQLAlchemy)**
```python
# VULN: db.query(Doc).get(doc_id)
doc = db.query(Doc).filter_by(id=doc_id, owner_id=current_user.id).first()
if not doc: abort(404)
```
**Go**
```go
// VULN: db.Get(&doc, "SELECT * FROM docs WHERE id=$1", id)
err := db.Get(&doc, "SELECT * FROM docs WHERE id=$1 AND owner_id=$2", id, uid)
```

## CSRF — token or SameSite
**Node (csurf / modern)**
```js
app.use(csrf());                              // synchronizer token, verified server-side
// or: require a custom header on JSON state-changing routes + SameSite=Lax cookie
```
**Python (Flask-WTF)**
```python
csrf = CSRFProtect(app)                        # per-session token on all POST/PUT/DELETE
```
**Go**
```go
// gorilla/csrf: CSRF := csrf.Protect(key); http.ListenAndServe(addr, CSRF(mux))
```

Verify: repeat the bypass/IDOR/CSRF request → 401/403 or redirect, no cross-user data, forged request rejected.
