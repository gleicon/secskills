package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// userAgent identifies secskills as an authorized-assessment client.
const userAgent = "secskills/" + version + " (+authorized-security-assessment)"

// sourceInterval returns the conservative minimum time between calls to a free
// data source, mirroring lib/throttle.sh so both implementations behave alike.
func sourceInterval(source string) time.Duration {
	switch source {
	case "crtsh", "wayback", "urlscan", "github":
		return 2 * time.Second
	case "virustotal":
		return 4 * time.Second
	case "osv":
		return 200 * time.Millisecond
	default: // commoncrawl, otx, shodan, fofa, chaos, censys, default
		return time.Second
	}
}

// lastCall tracks the last request time per source for interval enforcement.
var lastCall = map[string]time.Time{}

func throttle(source string) {
	iv := sourceInterval(source)
	if last, ok := lastCall[source]; ok {
		if wait := iv - time.Since(last); wait > 0 {
			time.Sleep(wait)
		}
	}
	lastCall[source] = time.Now()
}

// httpDo performs a throttled request with exponential backoff that honors
// Retry-After on 429/503. Returns the body on 2xx.
func httpDo(source, method, url, body string, retries int) ([]byte, error) {
	client := &http.Client{Timeout: 25 * time.Second}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		throttle(source)
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, url, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			backoff(source, url, "err", attempt)
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return data, nil
		case resp.StatusCode == 429 || resp.StatusCode == 503:
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, e := strconv.Atoi(strings.TrimSpace(ra)); e == nil {
					fmt.Fprintf(os.Stderr, "[throttle] %s %s -> %d, honoring Retry-After %ds\n", source, url, resp.StatusCode, secs)
					time.Sleep(time.Duration(secs) * time.Second)
					continue
				}
			}
			backoff(source, url, fmt.Sprint(resp.StatusCode), attempt)
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		case resp.StatusCode >= 500:
			backoff(source, url, fmt.Sprint(resp.StatusCode), attempt)
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		default:
			return nil, fmt.Errorf("%s %s -> %d", source, url, resp.StatusCode)
		}
	}
	return nil, fmt.Errorf("giving up on %s: %v", url, lastErr)
}

func backoff(source, url, code string, attempt int) {
	d := 1 << uint(attempt+1) // 2^(attempt+1)
	if d > 60 {
		d = 60
	}
	fmt.Fprintf(os.Stderr, "[throttle] %s %s -> %s, backoff %ds (attempt %d)\n", source, url, code, d, attempt+1)
	time.Sleep(time.Duration(d) * time.Second)
}

func cmdFetch(args []string, post bool) error {
	name := "fetch"
	if post {
		name = "post"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	retries := fs.Int("retries", 4, "max retries on 429/503/timeout")
	// Flags must precede positionals (Go flag semantics); tolerate leading flags.
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	method := "GET"
	minArgs := 2
	if post {
		method = "POST"
		minArgs = 3
	}
	if len(rest) < minArgs {
		if post {
			return fmt.Errorf("usage: secskills post <source> <url> <json-body>")
		}
		return fmt.Errorf("usage: secskills fetch <source> <url>")
	}
	source, url := rest[0], rest[1]
	body := ""
	if post {
		body = rest[2]
	}
	out, err := httpDo(source, method, url, body, *retries)
	if err != nil {
		return err
	}
	os.Stdout.Write(out)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		fmt.Println()
	}
	return nil
}
