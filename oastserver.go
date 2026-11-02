package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
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

type oastInteraction struct {
	Token     string `json:"token"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	RemoteIP  string `json:"remote_ip"`
	UA        string `json:"user_agent"`
	Timestamp string `json:"timestamp"`
}

type oastCollab struct {
	mu    sync.Mutex
	seen  map[string]bool
	store string
}

func (c *oastCollab) record(i oastInteraction) {
	c.mu.Lock()
	c.seen[i.Token] = true
	c.mu.Unlock()
	if c.store != "" {
		_ = appendJSONL(c.store, i)
	}
}

// tokenFromRequest extracts the canary token from the leftmost DNS label of the
// Host, or the first path segment (fallbacks for different injection shapes).
func tokenFromRequest(r *http.Request) string {
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

func cmdOASTServer(args []string) error {
	fs := flag.NewFlagSet("oast-server", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	store := fs.String("store", "", "append interactions as JSONL to this file (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := &oastCollab{seen: map[string]bool{}, store: *store}

	mux := http.NewServeMux()
	// /poll?token=<id> — the engine's confirmation channel (200 = interaction seen).
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("token")
		c.mu.Lock()
		ok := c.seen[tok]
		c.mu.Unlock()
		if ok {
			w.WriteHeader(200)
			fmt.Fprintln(w, "interaction observed")
			return
		}
		w.WriteHeader(404)
		fmt.Fprintln(w, "no interaction")
	})
	// everything else is a candidate canary hit — log it.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tok := tokenFromRequest(r)
		ip := r.RemoteAddr
		if i := strings.LastIndexByte(ip, ':'); i >= 0 {
			ip = ip[:i]
		}
		c.record(oastInteraction{
			Token: tok, Method: r.Method, Host: r.Host, Path: r.URL.String(),
			RemoteIP: ip, UA: r.UserAgent(), Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		// bland response — do not reflect anything useful to the target
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "ok")
	})

	fmt.Printf("secskills OAST collaborator listening on %s\n", *listen)
	fmt.Println("Point a wildcard DNS record (*.your-oast-domain) at this host, then set:")
	fmt.Println("  SECSKILLS_OAST_DOMAIN=your-oast-domain")
	fmt.Printf("  SECSKILLS_OAST_POLL_URL=http(s)://your-oast-domain%s/poll\n", pollHint(*listen))
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

func pollHint(listen string) string {
	if strings.HasPrefix(listen, ":80") && listen == ":80" {
		return ""
	}
	return listen
}
