// Command embed proves internal/probe is usable as a library in under 40 lines
// (spec N-2 acceptance): guard the request path, probe a target, store the
// observation. No import of the secskills CLI.
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/gleicon/secskills/internal/probe"
)

func main() {
	guard := func(u string) error { return probe.SafeURL(u, false) }
	client := probe.NewClient(guard, "secskills-embed/1 (+authorized-security-assessment)", false)

	const target = "https://example.com"
	code, hdr, _, ok := client.GetWithBody(target, 64<<10)
	if !ok {
		log.Fatalf("probe blocked or failed for %s", target)
	}

	obs := probe.Observation{
		IP:         probe.HostOf(target),
		Port:       443,
		Service:    "https",
		Product:    strings.TrimSpace(hdr.Get("Server")),
		Source:     "embed-example",
		Confidence: "low",
	}.Normalize()

	store := probe.Store{Path: "observations.jsonl"}
	if err := store.Append(obs); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s -> HTTP %d, server=%q, id=%s\n", target, code, obs.Product, obs.Fingerprint[:12])
}
