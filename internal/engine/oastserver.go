package engine

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gleicon/secskills/internal/jsonl"
)

// M7 — Self-hostable OAST collaborator.
// Run this on a public host with a wildcard DNS record (*.oast.example -> this
// host). The SSRF/webhook probes embed a unique token as a subdomain/path; when
// the target performs a server-side fetch, this server logs the interaction and
// the engine confirms it via /poll?token=<id>. HTTP-based (DNS-based OAST needs a
// DNS server library and is tracked as future work).
//
//   secskills oast-server --listen :8080 --store ~/.secskills-oast.jsonl
//
// Then point the engine at it:
//   SECSKILLS_OAST_DOMAIN=oast.example
//   SECSKILLS_OAST_POLL_URL=https://oast.example/poll   (this server's /poll)

// OASTInteraction is one callback received by the OAST server.
type OASTInteraction struct {
	Token     string `json:"token"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	RemoteIP  string `json:"remote_ip"`
	UA        string `json:"user_agent"`
	Timestamp string `json:"timestamp"`
}

// OASTCollab records callbacks by token for /poll.
type OASTCollab struct {
	Mu    sync.Mutex      `json:"-"`
	Seen  map[string]bool `json:"-"`
	Store string          `json:"-"`
}

// Record marks a token as seen and appends the interaction to the store.
func (c *OASTCollab) Record(i OASTInteraction) {
	c.Mu.Lock()
	c.Seen[i.Token] = true
	c.Mu.Unlock()
	if c.Store != "" {
		_ = jsonl.AppendJSONL(c.Store, i)
	}
}

// TokenFromRequest extracts the canary token from the leftmost DNS label of the
// Host, or the first path segment (fallbacks for different injection shapes).
func TokenFromRequest(r *http.Request) string {
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i]
	}
	seg := strings.Trim(r.URL.Path, "/")
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	return seg
}

// PollHint is the listen address to show in the poll URL hint ("" for :80).
func PollHint(listen string) string {
	if strings.HasPrefix(listen, ":80") && listen == ":80" {
		return ""
	}
	return listen
}
