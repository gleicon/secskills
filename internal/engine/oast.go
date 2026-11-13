package engine

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"
)

// OAST (out-of-band application security testing) framework.
// A controlled collaborator domain (SECSKILLS_OAST_DOMAIN) plus unique per-test
// tokens lets us validate blind SSRF/XXE/webhook behaviors by observing an
// interaction with our canary, without extracting any target data. If no
// collaborator is configured, OAST-dependent checks report "not available"
// honestly rather than guessing.
type OAST struct {
	Domain  string // e.g. abcd.oast.example — interactions to <token>.<domain>
	PollURL string // optional: GET <PollURL>?token=<t> -> 200 if interaction seen
}

// NewOAST returns the OAST collaborator from SECSKILLS_OAST_DOMAIN, or nil.
func NewOAST() *OAST {
	d := strings.TrimSpace(os.Getenv("SECSKILLS_OAST_DOMAIN"))
	if d == "" {
		return nil
	}
	return &OAST{Domain: d, PollURL: strings.TrimSpace(os.Getenv("SECSKILLS_OAST_POLL_URL"))}
}

func (o *OAST) available() bool { return o != nil && o.Domain != "" }

// token returns a fresh canary hostname to embed in a payload.
func (o *OAST) token() (host, id string) {
	b := make([]byte, 8)
	rand.Read(b)
	id = hex.EncodeToString(b)
	return id + "." + o.Domain, id
}

// interacted polls the collaborator (if a poll URL is configured) to confirm the
// canary was hit. Without a poll URL, callbacks are issued but confirmation is
// left to the operator's collaborator dashboard (reported as issued-not-confirmed).
func (o *OAST) interacted(id string) bool {
	if o.PollURL == "" {
		return false
	}
	c := &http.Client{Timeout: 6 * time.Second}
	resp, err := c.Get(o.PollURL + "?token=" + id)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}
