# Recipes — Injection (A03), per stack

Secure vs vulnerable snippets for the injection class. Pair with `kb/injection/`.
Stacks: Node.js, Python, Go.

## SQL — parameterize, never concatenate

**Node (pg / mysql2)**
```js
// VULN: `SELECT * FROM users WHERE id = ${req.query.id}`
const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
```
**Python (psycopg / sqlite3)**
```python
# VULN: cur.execute(f"SELECT * FROM users WHERE id = {uid}")
cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
```
**Go (database/sql)**
```go
// VULN: db.Query("SELECT * FROM users WHERE id = " + id)
rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)
```

## OS command — no shell, pass args as array

**Node**
```js
// VULN: exec(`ping -c1 ${host}`)
const { execFile } = require('node:child_process');
execFile('ping', ['-c1', host], cb);        // host never hits a shell
```
**Python**
```python
# VULN: os.system("ping -c1 " + host); subprocess.run(cmd, shell=True)
subprocess.run(["ping", "-c1", host], shell=False, check=True)
```
**Go**
```go
// VULN: exec.Command("sh", "-c", "ping -c1 "+host)
exec.Command("ping", "-c1", host)           // args passed directly
```

## XSS — context-aware output encoding

**Node (Express + a template engine)**
```js
// VULN: res.send(`<div>${req.query.q}</div>`)
res.render('page', { q: req.query.q });      // auto-escaping template (EJS <%= %>, Handlebars {{ }})
```
**Python (Flask/Jinja2)**
```python
# VULN: return "<div>" + q + "</div>"
return render_template("page.html", q=q)     # Jinja2 autoescape on by default
```
**Go (html/template — auto context-escapes)**
```go
// VULN: fmt.Fprintf(w, "<div>%s</div>", q)   // or text/template
tmpl := template.Must(template.New("p").Parse(`<div>{{.}}</div>`)) // html/template
tmpl.Execute(w, q)
```

## Template / deserialization
- Never render user input as a template (SSTI): pass it as *data*, not template text.
- Python: `yaml.safe_load`, never `yaml.load`/`pickle.loads` on untrusted input.
- Node: avoid `eval`, `Function()`, `vm` on user input.

Verify: re-send the payload → returned inert/encoded or rejected, no interpreter error.
