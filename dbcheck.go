package main

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/probe"
)

// Authenticated-exposure check for internet-reachable datastores (owner-directed,
// intrusive tier). It answers one question per datastore, read-only: is it OPEN
// (reachable with no authentication) or does it accept a DEFAULT vendor
// credential? It NEVER brute-forces (a small fixed default set only), never
// reads data beyond a single liveness command, and never writes. The working
// default is reported so the administrator can change it.
//
// Gated twice: --confirm and --intrusive-confirm. These are authentication
// attempts against customer hosts and must be an explicit, owner-authorized act.

//go:embed data/default-credentials.json
var defaultCredsJSON []byte

type credPair struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func loadDefaultCreds() (map[string][]credPair, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(defaultCredsJSON, &raw); err != nil {
		return nil, err
	}
	m := map[string][]credPair{}
	for k, v := range raw {
		if k == "_comment" {
			continue
		}
		var pairs []credPair
		if json.Unmarshal(v, &pairs) == nil {
			m[k] = pairs
		}
	}
	return m, nil
}

// dbResult is one datastore's authentication posture.
type dbResult struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Status  string `json:"status"` // OPEN-NOAUTH | DEFAULT-CRED | AUTH-ENFORCED | UNREACHABLE | NOT-TESTED
	Detail  string `json:"detail"`
}

func (r dbResult) critical() bool { return r.Status == "OPEN-NOAUTH" || r.Status == "DEFAULT-CRED" }

func cmdDBCheck(args []string) error {
	fs := flag.NewFlagSet("dbcheck", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir containing observations.jsonl")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	intrusive := fs.Bool("intrusive-confirm", false, "second confirmation: permit default-credential attempts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills dbcheck --workdir <dir> --confirm --intrusive-confirm")
	}
	if !*confirm || !*intrusive {
		return fmt.Errorf("dbcheck makes authentication attempts against hosts; it requires BOTH --confirm and --intrusive-confirm")
	}
	obs, err := probe.Load(filepath.Join(*wd, "observations.jsonl"))
	if err != nil {
		return err
	}
	creds, err := loadDefaultCreds()
	if err != nil {
		return err
	}

	var results []dbResult
	for _, o := range obs {
		if !datastorePorts[o.Service] || o.Service == "rdp" {
			continue
		}
		addr := net.JoinHostPort(o.IP, fmt.Sprint(o.Port))
		var r dbResult
		switch o.Service {
		case "redis":
			r = redisCheck(addr, creds["redis"])
		case "elasticsearch":
			r = esCheck(o.IP, o.Port, creds["elasticsearch"])
		case "mongodb":
			r = mongoCheck(addr)
		case "mysql":
			r = mysqlCheck(o.IP, o.Port, creds["mysql"])
		default:
			r = dbResult{Status: "NOT-TESTED", Detail: "no checker for service"}
		}
		r.IP, r.Port, r.Service = o.IP, o.Port, o.Service
		results = append(results, r)
	}

	out := filepath.Join(*wd, "dbcheck.jsonl")
	os.Remove(out)
	for _, r := range results {
		appendJSONL(out, r)
	}
	reportDBCheck(results, out)
	return nil
}

// ---- redis: native RESP, read-only ----

func redisCheck(addr string, creds []credPair) dbResult {
	// Open? INFO without AUTH.
	resp, ok := redisCmd(addr, "INFO server\r\n", "")
	if !ok {
		return dbResult{Status: "UNREACHABLE"}
	}
	if !strings.Contains(resp, "NOAUTH") && (strings.Contains(resp, "redis_version") || strings.HasPrefix(resp, "$")) {
		return dbResult{Status: "OPEN-NOAUTH", Detail: "INFO answered without authentication"}
	}
	// Auth required: try default passwords (read-only PING after AUTH).
	for _, c := range creds {
		if c.Pass == "" {
			continue
		}
		if r, ok := redisCmd(addr, fmt.Sprintf("AUTH %s\r\nPING\r\n", c.Pass), ""); ok && strings.Contains(r, "+PONG") && !strings.Contains(r, "ERR") {
			return dbResult{Status: "DEFAULT-CRED", Detail: "redis AUTH accepts default password: " + c.Pass}
		}
	}
	return dbResult{Status: "AUTH-ENFORCED", Detail: "requires authentication; no default password accepted"}
}

func redisCmd(addr, cmd, _ string) (string, bool) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", false
	}
	buf := make([]byte, 4096)
	n, _ := bufio.NewReader(conn).Read(buf)
	return string(buf[:n]), true
}

// ---- elasticsearch: native HTTP, read-only ----

func esCheck(ip string, port int, creds []credPair) dbResult {
	guard := func(u string) error { return probe.SafeURL(u, false) }
	client := probe.NewClient(guard, userAgent, false)
	base := fmt.Sprintf("http://%s:%d", ip, port)
	// Open? cluster health with no auth.
	if status, _, body, ok := client.GetWithBody(base+"/_cluster/health", 8192); ok && status == 200 && strings.Contains(body, "cluster_name") {
		return dbResult{Status: "OPEN-NOAUTH", Detail: "/_cluster/health readable without authentication"}
	}
	// Default basic-auth creds (read-only GET /).
	for _, c := range creds {
		if basicAuthGet(client, base+"/_cluster/health", c.User, c.Pass) {
			return dbResult{Status: "DEFAULT-CRED", Detail: fmt.Sprintf("accepts default credential %s:%s", c.User, c.Pass)}
		}
	}
	return dbResult{Status: "AUTH-ENFORCED", Detail: "requires authentication; no default credential accepted"}
}

// ---- mongodb: native OP_MSG listDatabases, read-only (open check only) ----

func mongoCheck(addr string) dbResult {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return dbResult{Status: "UNREACHABLE"}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := mongoOpMsg(bsonListDatabases())
	if _, err := conn.Write(msg); err != nil {
		return dbResult{Status: "UNREACHABLE"}
	}
	hdr := make([]byte, 16)
	if _, err := conn.Read(hdr); err != nil {
		return dbResult{Status: "UNREACHABLE"}
	}
	total := int(binary.LittleEndian.Uint32(hdr[0:4]))
	if total < 16 || total > 1<<20 {
		return dbResult{Status: "AUTH-ENFORCED", Detail: "unexpected mongo reply"}
	}
	rest := make([]byte, total-16)
	readFull(conn, rest)
	reply := string(rest)
	switch {
	case strings.Contains(reply, "databases") || strings.Contains(reply, "totalSize"):
		return dbResult{Status: "OPEN-NOAUTH", Detail: "listDatabases returned without authentication"}
	case strings.Contains(reply, "Unauthorized") || strings.Contains(reply, "requires authentication") || strings.Contains(reply, "not authorized"):
		return dbResult{Status: "AUTH-ENFORCED", Detail: "authentication required (no default-cred attempt: SCRAM not implemented)"}
	default:
		return dbResult{Status: "AUTH-ENFORCED", Detail: "reachable; command refused without clear data"}
	}
}

// ---- mysql: via the mysql client when present, read-only SELECT 1 ----

func mysqlCheck(ip string, port int, creds []credPair) dbResult {
	if !has("mysql") {
		return dbResult{Status: "NOT-TESTED", Detail: "mysql client absent; reachable datastore not credential-tested"}
	}
	for _, c := range creds {
		cmd := exec.Command("mysql", "-h", ip, "-P", fmt.Sprint(port), "-u", c.User,
			"--connect-timeout=4", "--protocol=TCP", "-N", "-B", "-e", "SELECT 1")
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+c.Pass) // never on the command line
		out, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(out), "1") {
			shown := c.Pass
			if shown == "" {
				shown = "(empty)"
			}
			return dbResult{Status: "DEFAULT-CRED", Detail: fmt.Sprintf("mysql accepts default credential %s / %s", c.User, shown)}
		}
	}
	return dbResult{Status: "AUTH-ENFORCED", Detail: "requires authentication; no default credential accepted"}
}

// ---- helpers ----

func basicAuthGet(client *probe.Client, url, user, pass string) bool {
	// probe.Client has no header injection; do a minimal authed GET here. Reuse
	// the guard by constructing a userinfo URL is unsafe, so use a dedicated
	// request via the standard library with the same non-destructive settings.
	status, _, body, ok := client.GetWithBasicAuth(url, user, pass, 8192)
	return ok && status == 200 && strings.Contains(body, "cluster_name")
}

// mongoOpMsg wraps a BSON command document in an OP_MSG frame.
func mongoOpMsg(doc []byte) []byte {
	body := make([]byte, 0, 5+len(doc))
	body = append(body, 0, 0, 0, 0) // flagBits = 0
	body = append(body, 0x00)       // section kind 0: single document
	body = append(body, doc...)
	total := 16 + len(body)
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], uint32(total))
	binary.LittleEndian.PutUint32(out[4:8], 1)      // requestID
	binary.LittleEndian.PutUint32(out[8:12], 0)     // responseTo
	binary.LittleEndian.PutUint32(out[12:16], 2013) // opCode OP_MSG
	return append(out, body...)
}

// bsonListDatabases builds {listDatabases:1, nameOnly:true, $db:"admin"}.
func bsonListDatabases() []byte {
	var b []byte
	b = append(b, 0x10) // int32
	b = append(b, []byte("listDatabases")...)
	b = append(b, 0x00)
	b = append(b, 1, 0, 0, 0)
	b = append(b, 0x08) // bool
	b = append(b, []byte("nameOnly")...)
	b = append(b, 0x00)
	b = append(b, 0x01)
	b = append(b, 0x02) // string
	b = append(b, []byte("$db")...)
	b = append(b, 0x00)
	admin := append([]byte("admin"), 0x00)
	ln := make([]byte, 4)
	binary.LittleEndian.PutUint32(ln, uint32(len(admin)))
	b = append(b, ln...)
	b = append(b, admin...)
	b = append(b, 0x00) // end of doc

	total := len(b) + 4
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(total))
	return append(out, b...)
}

func reportDBCheck(results []dbResult, out string) {
	crit := 0
	for _, r := range results {
		if r.critical() {
			crit++
		}
	}
	fmt.Printf("dbcheck: %d datastores, %d OPEN or DEFAULT-CRED -> %s\n", len(results), crit, out)
	for _, r := range results {
		mark := "  "
		if r.critical() {
			mark = "!!"
		}
		fmt.Printf("%s %-20s %-14s %-15s %s\n", mark, fmt.Sprintf("%s:%d", r.IP, r.Port), r.Service, r.Status, r.Detail)
	}
}
