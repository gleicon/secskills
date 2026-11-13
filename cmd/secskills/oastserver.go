package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/engine"
)

func cmdOASTServer(args []string) error {
	fs := flag.NewFlagSet("oast-server", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "HTTP listen address")
	store := fs.String("store", "", "append interactions as JSONL to this file (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := &engine.OASTCollab{Seen: map[string]bool{}, Store: *store}

	mux := http.NewServeMux()
	// /poll?token=<id> — the engine's confirmation channel (200 = interaction seen).
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("token")
		c.Mu.Lock()
		ok := c.Seen[tok]
		c.Mu.Unlock()
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
		tok := engine.TokenFromRequest(r)
		ip := r.RemoteAddr
		if i := strings.LastIndexByte(ip, ':'); i >= 0 {
			ip = ip[:i]
		}
		c.Record(engine.OASTInteraction{
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
	fmt.Printf("  SECSKILLS_OAST_POLL_URL=http(s)://your-oast-domain%s/poll\n", engine.PollHint(*listen))
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}
