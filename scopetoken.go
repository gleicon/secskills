package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

// Mode-B scope token (spec §5): a signed authorization a detection worker
// verifies before it touches anything. The worker refuses any target outside
// prefixes, any check outside allowed_classes, any run outside the window, and
// any intrusive action regardless of the token (D-4). This is the machine-
// verifiable form of the --confirm gate; the human path is unchanged.
type ScopeToken struct {
	Tenant         string   `json:"tenant"`
	ASN            int      `json:"asn"`
	Prefixes       []string `json:"prefixes"`
	NotBefore      string   `json:"not_before"` // RFC3339
	NotAfter       string   `json:"not_after"`
	MaxPPS         int      `json:"max_pps"`
	AllowedClasses []string `json:"allowed_classes"`
	Intrusive      bool     `json:"intrusive"`
	IssuedBy       string   `json:"issued_by"`
	Sig            string   `json:"sig,omitempty"`
}

// signingBytes is the canonical form the HMAC covers: the token with an empty
// signature. Go marshals struct fields in declaration order, so this is stable.
func (t ScopeToken) signingBytes() ([]byte, error) {
	c := t
	c.Sig = ""
	return json.Marshal(c)
}

// Sign returns the token with an HMAC-SHA256 signature over its canonical form.
func (t ScopeToken) Sign(key []byte) (ScopeToken, error) {
	b, err := t.signingBytes()
	if err != nil {
		return t, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	t.Sig = "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
	return t, nil
}

// Verify reports whether the token's signature is valid for key. It uses a
// constant-time comparison so a bad signature leaks no timing.
func (t ScopeToken) Verify(key []byte) error {
	want, err := t.Sign(key)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want.Sig), []byte(t.Sig)) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

// Authorizes decides whether this token permits touching ip for a check of the
// given class at time now. It assumes the signature is already verified. Any
// intrusive token is refused outright (D-4). Returns false and a reason on any
// failing condition.
func (t ScopeToken) Authorizes(ip net.IP, class string, now time.Time) (bool, string) {
	if t.Intrusive {
		return false, "token marked intrusive — refused at the worker regardless of token (D-4)"
	}
	nb, err := time.Parse(time.RFC3339, t.NotBefore)
	if err != nil {
		return false, "not_before unparseable"
	}
	na, err := time.Parse(time.RFC3339, t.NotAfter)
	if err != nil {
		return false, "not_after unparseable"
	}
	if now.Before(nb) {
		return false, "before the authorization window opens"
	}
	if now.After(na) {
		return false, "after the authorization window closes"
	}
	if !classAllowed(class, t.AllowedClasses) {
		return false, "check class " + class + " not in allowed_classes"
	}
	if ip == nil || !ipInAnyPrefix(ip, t.Prefixes) {
		return false, "target outside the token's prefixes"
	}
	return true, "authorized by token for " + t.Tenant
}

func classAllowed(class string, allowed []string) bool {
	for _, a := range allowed {
		if a == class {
			return true
		}
	}
	return false
}

func ipInAnyPrefix(ip net.IP, prefixes []string) bool {
	for _, p := range prefixes {
		if _, n, err := net.ParseCIDR(p); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func tokenKey() ([]byte, error) {
	k := os.Getenv("SECSKILLS_TOKEN_KEY")
	if k == "" {
		return nil, fmt.Errorf("set SECSKILLS_TOKEN_KEY to the shared HMAC key")
	}
	return []byte(k), nil
}

func cmdToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills token <sign|verify> --file <token.json>")
	}
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	file := fs.String("file", "", "token JSON file")
	ip := fs.String("ip", "", "verify: also check this IP is authorized")
	class := fs.String("class", "cve", "verify: check class for the --ip test")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	key, err := tokenKey()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var tok ScopeToken
	if err := json.Unmarshal(b, &tok); err != nil {
		return err
	}

	switch args[0] {
	case "sign":
		signed, err := tok.Sign(key)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(signed, "", "  ")
		fmt.Println(string(out))
		return nil
	case "verify":
		if err := tok.Verify(key); err != nil {
			return fmt.Errorf("REJECT: %w", err)
		}
		fmt.Printf("signature OK — tenant %s, AS%d, %d prefixes, window %s..%s, classes %v, intrusive=%v\n",
			tok.Tenant, tok.ASN, len(tok.Prefixes), tok.NotBefore, tok.NotAfter, tok.AllowedClasses, tok.Intrusive)
		if *ip != "" {
			ok, why := tok.Authorizes(net.ParseIP(*ip), *class, time.Now())
			fmt.Printf("authorizes %s (%s): %v — %s\n", *ip, *class, ok, why)
		}
		return nil
	default:
		return fmt.Errorf("unknown token subcommand %q (want sign|verify)", args[0])
	}
}
