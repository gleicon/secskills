package exposure

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/probe"
	"github.com/gleicon/secskills/internal/textutil"
)

// leakcheck is a read-only, unauthenticated exposure pass over a stored
// observation set. It looks for data-leak opportunities that need NO
// credentials: exposed VCS/dotenv files, directory listings, open server-status,
// an unauthenticated Elasticsearch index list, and an unauthenticated Redis.
//
// It never sends a password, never tries default credentials, never writes or
// deletes (D-4). Every check is a bounded GET or a single read-only command,
// and the body is read capped. Secret-looking values are redacted before they
// reach the terminal; full evidence stays in the workdir.

const leakMaxBytes = 64 << 10

// LeakFinding is one unauthenticated exposure.
type LeakFinding struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	URL      string `json:"url,omitempty"`
	Kind     string `json:"kind"` // exposed-vcs|exposed-dotenv|dir-listing|server-status|es-open-indices|redis-unauth|banner
	Status   int    `json:"status,omitempty"`
	Server   string `json:"server,omitempty"`
	Evidence string `json:"evidence"` // redacted summary
}

// httpLeakPath is a sensitive path probed with a bounded GET.
type httpLeakPath struct {
	path string
	kind string
}

var httpLeakPaths = []httpLeakPath{
	{"/.git/config", "exposed-vcs"},
	{"/.env", "exposed-dotenv"},
	{"/server-status", "server-status"},
}

// classifyHTTPLeak decides whether a response at path is a data leak, returning
// the kind, whether it leaked, and a redacted evidence string. Pure, so it is
// unit-tested without the network.
func classifyHTTPLeak(kind string, status int, ctype, body string) (bool, string) {
	if status != 200 || body == "" {
		return false, ""
	}
	switch kind {
	case "exposed-vcs":
		if strings.Contains(body, "[core]") && strings.Contains(body, "repositoryformatversion") {
			return true, "git config exposed: " + textutil.FirstLine(body)
		}
	case "exposed-dotenv":
		// A served .env leaks KEY=VALUE lines. Confirm the shape, redact values.
		if looksLikeDotenv(body) {
			return true, "dotenv exposed: " + redactEnv(body)
		}
	case "server-status":
		if strings.Contains(body, "Apache Server Status") || strings.Contains(body, "Scoreboard") {
			return true, "mod_status exposed: " + textutil.FirstLine(body)
		}
	}
	return false, ""
}

// dirListing reports an index-of directory listing on "/".
func dirListing(body string) bool {
	return strings.Contains(body, "Index of /") || strings.Contains(body, "<title>Directory listing for")
}

func looksLikeDotenv(body string) bool {
	lines := 0
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, _, ok := strings.Cut(ln, "=")
		if !ok || k == "" || strings.ContainsAny(k, " \t<>") {
			return false // HTML or prose, not an env file
		}
		lines++
		if lines >= 2 {
			return true
		}
	}
	return false
}

// redactEnv returns the env keys only, never the values.
func redactEnv(body string) string {
	var keys []string
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if k, _, ok := strings.Cut(ln, "="); ok && k != "" {
			keys = append(keys, strings.TrimSpace(k))
		}
		if len(keys) >= 12 {
			keys = append(keys, "…")
			break
		}
	}
	return fmt.Sprintf("%d keys [%s] (values redacted)", len(keys), strings.Join(keys, ", "))
}

// RedisUnauth probes a Redis port with a single read-only INFO over an inline
// command. Returns true and a redacted banner when the server answers without
// requiring AUTH; false when it demands auth (-NOAUTH) or does not speak RESP.
// No password is ever sent.
func RedisUnauth(addr string) (bool, string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("INFO server\r\n")); err != nil {
		return false, ""
	}
	r := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "NOAUTH") || strings.Contains(resp, "WRONGPASS") {
		return false, "" // authentication required — not a leak
	}
	if strings.Contains(resp, "redis_version") || strings.HasPrefix(resp, "$") {
		ver := ""
		for _, ln := range strings.Split(resp, "\n") {
			if strings.HasPrefix(ln, "redis_version:") {
				ver = strings.TrimSpace(ln)
			}
		}
		if ver == "" {
			ver = "INFO answered without AUTH"
		}
		return true, "redis reachable unauthenticated: " + ver
	}
	return false, ""
}

// HTTPLeaks does a bounded GET of "/" (banner + dir-listing) and each sensitive
// path on one HTTP service. Read-only; no credentials.
func HTTPLeaks(client *probe.Client, tick <-chan time.Time, o Observation) []LeakFinding {
	base := fmt.Sprintf("%s://%s:%d", o.Service, o.IP, o.Port)
	var fs []LeakFinding

	status, hdr, body, ok := client.GetWithBody(base+"/", leakMaxBytes)
	if ok {
		server := ""
		if hdr != nil {
			server = hdr.Get("Server")
		}
		if dirListing(body) {
			fs = append(fs, LeakFinding{IP: o.IP, Port: o.Port, URL: base + "/", Kind: "dir-listing", Status: status, Server: server, Evidence: "directory listing enabled"})
		} else {
			fs = append(fs, LeakFinding{IP: o.IP, Port: o.Port, URL: base + "/", Kind: "banner", Status: status, Server: server, Evidence: "server=" + server})
		}
	}
	for _, lp := range httpLeakPaths {
		<-tick
		status, hdr, body, ok := client.GetWithBody(base+lp.path, leakMaxBytes)
		if !ok {
			continue
		}
		ctype := ""
		if hdr != nil {
			ctype = hdr.Get("Content-Type")
		}
		if leak, ev := classifyHTTPLeak(lp.kind, status, ctype, body); leak {
			fs = append(fs, LeakFinding{IP: o.IP, Port: o.Port, URL: base + lp.path, Kind: lp.kind, Status: status, Evidence: ev})
		}
	}
	return fs
}

// EsOpenIndices checks for an unauthenticated Elasticsearch index listing. A
// 200 from /_cat/indices means the cluster's index names are readable with no
// credentials — a data-leak opportunity. Only index names (redacted to a count
// and a small sample) reach the evidence, never document contents.
func EsOpenIndices(client *probe.Client, o Observation) (LeakFinding, bool) {
	base := fmt.Sprintf("http://%s:%d", o.IP, o.Port)
	status, _, body, ok := client.GetWithBody(base+"/_cat/indices?v", leakMaxBytes)
	if !ok || status != 200 || !strings.Contains(body, "index") {
		return LeakFinding{}, false
	}
	n := 0
	for _, ln := range strings.Split(body, "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return LeakFinding{IP: o.IP, Port: o.Port, URL: base + "/_cat/indices", Kind: "es-open-indices", Status: 200,
		Evidence: fmt.Sprintf("Elasticsearch index list readable unauthenticated (~%d rows)", n-1)}, true
}

// ReportLeaks prints the leak findings and where they were written.
func ReportLeaks(fs []LeakFinding, out string) {
	if len(fs) == 0 {
		fmt.Println("leakcheck: no unauthenticated data-leak opportunities found")
		return
	}
	// Banners are context, not leaks — split them out of the headline count.
	leaks, banners := 0, 0
	for _, f := range fs {
		if f.Kind == "banner" {
			banners++
		} else {
			leaks++
		}
	}
	fmt.Printf("leakcheck: %d leak opportunities, %d banners -> %s\n", leaks, banners, out)
	for _, f := range fs {
		if f.Kind == "banner" {
			continue
		}
		fmt.Printf("  %-16s %-16s %s\n", fmt.Sprintf("%s:%d", f.IP, f.Port), f.Kind, f.Evidence)
	}
}
