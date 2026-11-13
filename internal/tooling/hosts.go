package tooling

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/textutil"
)

// dnsResolvable reports whether a hostname resolves.
func dnsResolvable(h string) bool { _, err := net.LookupHost(h); return err == nil }

// goProbe is the native fallback when pd httpx is unavailable: rate-limited Go
// HTTP probe (https then http) of each host.
func goProbe(hosts []string, workers int) []LiveHost {
	tick := fetch.RateGate()
	defer tick.Stop()
	var mu sync.Mutex
	var out []LiveHost
	RunPool(hosts, workers, func(name string) {
		for _, scheme := range []string{"https://", "http://"} {
			<-tick.C
			u := scheme + name
			c := fetch.NonDestructiveClient()
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("User-Agent", fetch.UserAgent)
			resp, err := c.Do(req)
			if err != nil {
				continue
			}
			srv := resp.Header.Get("Server")
			resp.Body.Close()
			mu.Lock()
			out = append(out, LiveHost{URL: u, Status: resp.StatusCode, Server: textutil.SafeField(srv)})
			mu.Unlock()
			return
		}
	})
	return out
}

// LiveHosts reads the workdir's live_hosts.json.
func LiveHosts(wd string) []LiveHost {
	b, err := os.ReadFile(filepath.Join(wd, "live_hosts.json"))
	if err != nil {
		return nil
	}
	var lives []LiveHost
	json.Unmarshal(b, &lives)
	return lives
}

// concurrentFilter keeps items for which keep() is true, bounded concurrency.
func concurrentFilter(items []string, workers int, keep func(string) bool) []string {
	in := make(chan string)
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range in {
				if keep(it) {
					mu.Lock()
					out = append(out, it)
					mu.Unlock()
				}
			}
		}()
	}
	for _, it := range items {
		in <- it
	}
	close(in)
	wg.Wait()
	return out
}

// RunPool runs fn over items with bounded concurrency.
func RunPool(items []string, workers int, fn func(string)) {
	in := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range in {
				fn(it)
			}
		}()
	}
	for _, it := range items {
		in <- it
	}
	close(in)
	wg.Wait()
}
