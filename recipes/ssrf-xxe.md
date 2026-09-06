# Recipes — SSRF & XXE (A10), per stack

Pair with `kb/ssrf-xxe/`. Stacks: Node.js, Python, Go.

## SSRF — allow-list host, validate resolved IP

**Node**
```js
const dns = require('node:dns/promises');
const net = require('node:net');
async function safeFetch(url) {
  const u = new URL(url);
  if (!['http:','https:'].includes(u.protocol)) throw new Error('scheme');
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error('host');
  const { address } = (await dns.lookup(u.hostname));
  if (isPrivate(address)) throw new Error('private ip');   // block RFC1918/169.254/::1
  return fetch(url, { redirect: 'error' });                // no redirect to new host
}
```
**Python (requests)**
```python
import ipaddress, socket
from urllib.parse import urlparse
def safe_get(url):
    u = urlparse(url)
    if u.scheme not in ("http","https") or u.hostname not in ALLOWED: raise ValueError
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    if ip.is_private or ip.is_loopback or ip.is_link_local: raise ValueError
    return requests.get(url, allow_redirects=False, timeout=5)
```
**Go**
```go
// resolve, reject private, then dial the validated IP (defeats DNS rebinding)
ips, _ := net.LookupIP(host)
for _, ip := range ips { if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() { return errBlocked } }
client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
```

- Block the cloud metadata endpoint (169.254.169.254) / require IMDSv2.
- Disable unused schemes (`file:`, `gopher:`, `ftp:`). Never echo raw upstream response to the client.

## XXE — disable DTDs / external entities

**Node (fast-xml-parser / libxmljs)**
```js
// fast-xml-parser does not resolve external entities by default — keep it that way.
// libxmljs: parseXml(xml, { noent: false, dtdload: false, dtdvalid: false })
```
**Python (defusedxml)**
```python
# VULN: xml.etree.ElementTree.fromstring(untrusted)
from defusedxml.ElementTree import fromstring
root = fromstring(untrusted)                 # entities/DTD disabled
```
**Go (encoding/xml)**
```go
// encoding/xml does NOT resolve external entities — safe by default.
// If using a libxml2 binding, set NOENT off and disable network.
```

Verify: re-send SSRF payload → allow-list block, no internal response. Re-send XXE payload → external entity not resolved.
