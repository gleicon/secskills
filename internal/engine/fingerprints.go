package engine

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gleicon/secskills"
)

// Technology fingerprint registry — data-driven and growable, the way Shodan /
// Wappalyzer / FavFreak collect technology intelligence. Signatures live in
// embedded fingerprints.json (the seed) merged with a user overlay
// (~/.secskills-fingerprints.json) that grows from engagements and imports.

type fpSignature struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Headers     map[string]string `json:"headers,omitempty"` // header -> substring (empty = presence)
	Cookies     []string          `json:"cookies,omitempty"`
	Body        []string          `json:"body,omitempty"`
	SecondStage string            `json:"second_stage,omitempty"`
	Implies     []string          `json:"implies,omitempty"`
}

type fpRegistry struct {
	Version       string            `json:"version"`
	Signatures    []fpSignature     `json:"signatures"`
	FaviconHashes map[string]string `json:"favicon_hashes,omitempty"`
}

type fpMatch struct {
	Name        string
	Category    string
	SecondStage string
	Via         string // how it matched (header/cookie/body/favicon)
	LowConf     bool   // favicon-only hints are low confidence
}

var fpRegistryCache *fpRegistry

func loadFPRegistry() *fpRegistry {
	if fpRegistryCache != nil {
		return fpRegistryCache
	}
	var reg fpRegistry
	json.Unmarshal(secskills.Fingerprints, &reg)
	if reg.FaviconHashes == nil {
		reg.FaviconHashes = map[string]string{}
	}
	// merge the user overlay (learned/imported signatures)
	if b, err := os.ReadFile(fpOverlayPath()); err == nil {
		var ov fpRegistry
		if json.Unmarshal(b, &ov) == nil {
			reg.Signatures = append(reg.Signatures, ov.Signatures...)
			for h, n := range ov.FaviconHashes {
				reg.FaviconHashes[h] = n
			}
		}
	}
	fpRegistryCache = &reg
	return &reg
}

func fpOverlayPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secskills-fingerprints.json")
}

// matchFingerprints returns every technology signature that matches the response.
// favIconHash (0 = unavailable) adds low-confidence hints from the favicon map.
func matchFingerprints(hdr http.Header, body string, favIconHash int32) []fpMatch {
	reg := loadFPRegistry()
	lb := strings.ToLower(body)
	cookies := strings.ToLower(strings.Join(hdr.Values("Set-Cookie"), "; "))
	var out []fpMatch
	seen := map[string]bool{}
	add := func(m fpMatch) {
		if !seen[m.Name] {
			seen[m.Name] = true
			out = append(out, m)
		}
	}
	for _, s := range reg.Signatures {
		if via := sigMatches(s, hdr, lb, cookies); via != "" {
			add(fpMatch{Name: s.Name, Category: s.Category, SecondStage: s.SecondStage, Via: via})
		}
	}
	if favIconHash != 0 {
		if name, ok := reg.FaviconHashes[strconv.Itoa(int(favIconHash))]; ok {
			add(fpMatch{Name: name, Category: "favicon-hint", Via: "favicon", LowConf: true})
		}
	}
	return out
}

func sigMatches(s fpSignature, hdr http.Header, lb, cookies string) string {
	for h, want := range s.Headers {
		v := strings.ToLower(hdr.Get(h))
		if v == "" && hdr.Get(h) == "" {
			continue
		}
		if want == "" || strings.Contains(v, strings.ToLower(want)) {
			return "header:" + h
		}
	}
	for _, c := range s.Cookies {
		if strings.Contains(cookies, strings.ToLower(c)) {
			return "cookie:" + c
		}
	}
	for _, bsig := range s.Body {
		if strings.Contains(lb, strings.ToLower(bsig)) {
			return "body"
		}
	}
	return ""
}

// FPList prints the fingerprint registry grouped by category.
func FPList(args []string) error {
	reg := loadFPRegistry()
	byCat := map[string][]string{}
	for _, s := range reg.Signatures {
		byCat[s.Category] = append(byCat[s.Category], s.Name)
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	fmt.Printf("%d signatures, %d favicon hashes (embedded seed + overlay %s)\n\n", len(reg.Signatures), len(reg.FaviconHashes), fpOverlayPath())
	for _, c := range cats {
		sort.Strings(byCat[c])
		fmt.Printf("%-16s %s\n", c, strings.Join(byCat[c], ", "))
	}
	return nil
}

// FPAdd appends a learned signature to the user overlay — grow the registry from
// what an engagement actually observed.
func FPAdd(args []string) error {
	fs := flag.NewFlagSet("fp add", flag.ContinueOnError)
	name := fs.String("name", "", "technology name")
	cat := fs.String("category", "unknown", "category")
	header := fs.String("header", "", "signature header as Name:substring (substring optional)")
	body := fs.String("body", "", "signature body substring")
	cookie := fs.String("cookie", "", "signature cookie name")
	favicon := fs.String("favicon", "", "favicon mmh3 hash mapping to this tech")
	second := fs.String("second-stage", "", "second-stage pack key to trigger")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("required: --name")
	}
	sig := fpSignature{Name: *name, Category: *cat, SecondStage: *second}
	if *header != "" {
		kv := strings.SplitN(*header, ":", 2)
		sig.Headers = map[string]string{strings.TrimSpace(kv[0]): ""}
		if len(kv) == 2 {
			sig.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if *body != "" {
		sig.Body = []string{*body}
	}
	if *cookie != "" {
		sig.Cookies = []string{*cookie}
	}
	ov := readOverlay()
	if *favicon != "" {
		if ov.FaviconHashes == nil {
			ov.FaviconHashes = map[string]string{}
		}
		ov.FaviconHashes[*favicon] = *name
	}
	if *header != "" || *body != "" || *cookie != "" {
		ov.Signatures = append(ov.Signatures, sig)
	}
	if err := writeOverlay(ov); err != nil {
		return err
	}
	fmt.Printf("added signature for %q to %s\n", *name, fpOverlayPath())
	return nil
}

// FPImport ingests an external dataset. Supports the Wappalyzer technologies.json
// shape ({name: {headers, cookies, html, implies, cats}}) and our own schema.
func FPImport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills fp import <file.json>")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	ov := readOverlay()
	n := 0
	// try our schema first
	var native fpRegistry
	if json.Unmarshal(raw, &native) == nil && len(native.Signatures) > 0 {
		ov.Signatures = append(ov.Signatures, native.Signatures...)
		for h, name := range native.FaviconHashes {
			if ov.FaviconHashes == nil {
				ov.FaviconHashes = map[string]string{}
			}
			ov.FaviconHashes[h] = name
		}
		n = len(native.Signatures)
	} else {
		// Wappalyzer shape
		var wap map[string]struct {
			Headers map[string]string `json:"headers"`
			Cookies map[string]string `json:"cookies"`
			HTML    json.RawMessage   `json:"html"`
			Cats    []int             `json:"cats"`
		}
		if err := json.Unmarshal(raw, &wap); err != nil {
			return fmt.Errorf("unrecognized dataset (not our schema nor Wappalyzer technologies.json): %w", err)
		}
		for name, t := range wap {
			sig := fpSignature{Name: name, Category: "imported"}
			if len(t.Headers) > 0 {
				sig.Headers = map[string]string{}
				for h := range t.Headers {
					sig.Headers[h] = ""
				}
			}
			for c := range t.Cookies {
				sig.Cookies = append(sig.Cookies, c)
			}
			sig.Body = append(sig.Body, wappalyzerHTMLPatterns(t.HTML)...)
			ov.Signatures = append(ov.Signatures, sig)
			n++
		}
	}
	if err := writeOverlay(ov); err != nil {
		return err
	}
	fmt.Printf("imported %d signatures into %s\n", n, fpOverlayPath())
	return nil
}

// wappalyzerHTMLPatterns extracts plain substrings from Wappalyzer html patterns
// (which may be a string or array; regex metacharacters are dropped to a literal).
func wappalyzerHTMLPatterns(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	var many []string
	if json.Unmarshal(raw, &one) == nil {
		many = []string{one}
	} else {
		json.Unmarshal(raw, &many)
	}
	var out []string
	for _, p := range many {
		// keep the pattern up to the first regex metachar as a literal substring
		lit := p
		if i := strings.IndexAny(p, `\^$.*+?()[]{}|`); i > 4 {
			lit = p[:i]
		}
		lit = strings.TrimSpace(lit)
		if len(lit) >= 4 {
			out = append(out, lit)
		}
	}
	return out
}

func readOverlay() fpRegistry {
	var ov fpRegistry
	if b, err := os.ReadFile(fpOverlayPath()); err == nil {
		json.Unmarshal(b, &ov)
	}
	return ov
}

func writeOverlay(ov fpRegistry) error {
	fpRegistryCache = nil // invalidate cache
	b, _ := json.MarshalIndent(ov, "", "  ")
	return os.WriteFile(fpOverlayPath(), b, 0o644)
}
