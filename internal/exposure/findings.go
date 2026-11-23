package exposure

import (
	"regexp"

	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/netsec"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/intel"
)

// Network-block results become ordinary findings in the assessment workdir, so
// report, retest, tickets, export, override and attest treat a block exactly
// like an app target. IDs are deterministic per (family, asset, condition): a
// re-run updates a finding instead of duplicating it, and SyncFindings closes
// the ones a re-run no longer produces.
const (
	FamilyLeak = "NET-LEAK-"
	FamilyDB   = "NET-DB-"
	FamilyCVE  = "NET-CVE-"
)

// DetectorBannerCVE is the detector id for NVD-range CVE leads on banners.
const DetectorBannerCVE = "component.banner-nvd-range@1"

// DetectorDatastore is the detector id for open or default-credential datastores.
const DetectorDatastore = "datastore.unauthenticated@1"

func hostPort(ip string, port int) string { return net.JoinHostPort(ip, fmt.Sprint(port)) }

// leakSignature is the body pattern retest looks for to decide whether an
// exposed path is still served.
func leakSignature(l LeakFinding) string {
	switch l.Kind {
	case "exposed-vcs":
		return "repositoryformatversion"
	case "server-status":
		return "Scoreboard"
	case "exposed-dotenv":
		if keys := dotenvKeys(l.Evidence); len(keys) > 0 {
			return keys[0] + "="
		}
	}
	return ""
}

// envKeyRe is the shape of a dotenv key. Key names come from the target, so
// anything else is dropped before it reaches a signature or a command.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// dotenvKeys extracts the key names from redactEnv's evidence
// ("N keys [A, B] (values redacted)").
func dotenvKeys(ev string) []string {
	i, j := strings.IndexByte(ev, '['), strings.IndexByte(ev, ']')
	if i < 0 || j < i {
		return nil
	}
	var keys []string
	for _, k := range strings.Split(ev[i+1:j], ",") {
		if k = strings.TrimSpace(k); envKeyRe.MatchString(k) {
			keys = append(keys, k)
		}
	}
	return keys
}

var leakTitles = map[string]string{
	"exposed-vcs":     "Exposed path: .git repository metadata",
	"exposed-dotenv":  "Exposed path: .env environment file",
	"server-status":   "Exposed path: Apache server-status",
	"dir-listing":     "Exposed path: directory listing",
	"es-open-indices": "Unauthenticated Elasticsearch index listing",
	"redis-unauth":    "Unauthenticated Redis",
}

// LeakFindings converts leakcheck results into findings. HTTP leaks carry a
// body-contains probe so `report --retest` re-verifies them; datastore leaks
// are rechecked by re-running leakcheck.
func LeakFindings(ls []LeakFinding) []finding.Finding {
	var out []finding.Finding
	for _, l := range ls {
		title, ok := leakTitles[l.Kind]
		if !ok {
			continue // banners and unknown kinds are inventory, not findings
		}
		f := finding.Finding{
			ID:             FamilyLeak + hostPort(l.IP, l.Port) + "-" + l.Kind,
			Title:          title,
			Host:           hostPort(l.IP, l.Port),
			Severity:       "MEDIUM",
			Confidence:     "High",
			Validation:     "behavior-confirmed",
			DiscoveredFrom: "network sweep (leakcheck)",
			ProbeKind:      "manual",
		}
		ev := l.Evidence
		switch l.Kind {
		case "exposed-dotenv":
			// A reachable .env serves live credentials — HIGH, not MEDIUM.
			f.Severity = "HIGH"
			if keys := dotenvKeys(l.Evidence); len(keys) > 0 {
				ev += "\n[x] credential-like keys exposed (values redacted): " + strings.Join(keys, ", ")
			}
		case "exposed-vcs":
			// A reachable .git exposes full source and history, routinely with
			// secrets in past commits — HIGH.
			f.Severity = "HIGH"
			ev += "\n[x] version-control metadata exposed: source and commit history retrievable"
		case "redis-unauth", "es-open-indices":
			f.DetectorID = DetectorDatastore
			f.Severity = "HIGH"
			ev += "\n[x] unauthenticated datastore access"
		}
		if l.URL != "" {
			f.Host = l.URL
			if sig := leakSignature(l); sig != "" {
				f.ProbeKind, f.ProbeURL, f.ProbeArg = "body-contains", l.URL, sig
				// target-derived values: quoted so the printed command is safe to paste
				f.EvidenceCmd = "curl -s " + netsec.ShellQuote(l.URL) + " | grep -c " + netsec.ShellQuote(sig)
				f.ExpectedOpen = sig
			}
		}
		f.ObservedEvidence = ev
		finding.Classify(&f)
		out = append(out, f)
	}
	return out
}

// DBFindings converts dbcheck results into findings: only datastores that are
// open or accept a vendor default credential are findings.
func DBFindings(rs []DBResult) []finding.Finding {
	var out []finding.Finding
	for _, r := range rs {
		if !r.critical() {
			continue
		}
		title := fmt.Sprintf("Unauthenticated %s", r.Service)
		marker := "[x] unauthenticated datastore access"
		if r.Status == "DEFAULT-CRED" {
			title = fmt.Sprintf("%s accepts a vendor default credential", r.Service)
			marker = "[x] vendor default credential accepted (value not recorded)"
		}
		f := finding.Finding{
			ID:               FamilyDB + hostPort(r.IP, r.Port),
			Title:            title,
			Host:             hostPort(r.IP, r.Port),
			Severity:         "HIGH",
			Confidence:       "High",
			Validation:       "behavior-confirmed",
			DetectorID:       DetectorDatastore,
			DiscoveredFrom:   "network sweep (dbcheck)",
			ProbeKind:        "manual",
			ObservedEvidence: r.Status + ": " + r.Detail + "\n" + marker,
		}
		finding.Classify(&f)
		out = append(out, f)
	}
	return out
}

// ServiceMatch is one observed service and the CVE candidates its banner
// version matched.
type ServiceMatch struct {
	Obs   Observation
	Cands []intel.Candidate
}

// CVEFindings turns each matched service into one lead, the same shape as the
// app engine's OSV component leads: banner versions are leads to confirm, never
// confirmed vulnerabilities, because distros backport fixes behind unchanged
// version strings. KEV-listed CVEs sort first and are marked in the evidence.
func CVEFindings(ms []ServiceMatch, kev map[string]bool) []finding.Finding {
	var out []finding.Finding
	for _, m := range ms {
		if len(m.Cands) == 0 {
			continue
		}
		o, cs := m.Obs, append([]intel.Candidate(nil), m.Cands...)
		sort.SliceStable(cs, func(i, j int) bool {
			if kev[cs[i].CVE] != kev[cs[j].CVE] {
				return kev[cs[i].CVE]
			}
			if cs[i].Score != cs[j].Score {
				return cs[i].Score > cs[j].Score
			}
			return cs[i].CVE < cs[j].CVE
		})
		var ids, kevIDs, lines []string
		for _, c := range cs {
			ids = append(ids, c.CVE)
			mark := "   "
			if kev[c.CVE] {
				mark = "KEV"
				kevIDs = append(kevIDs, c.CVE)
			}
			lines = append(lines, fmt.Sprintf("%s %s cvss=%.1f epss=%.3f", mark, c.CVE, c.ScoreTerms["cvss"], c.ScoreTerms["epss"]))
		}
		hp := hostPort(o.IP, o.Port)
		ev := fmt.Sprintf("banner version %s %s on %s\n%s", o.Product, o.Version, hp, strings.Join(lines, "\n"))
		if len(kevIDs) > 0 {
			ev += "\n[x] CISA KEV (exploited in the wild): " + strings.Join(kevIDs, ", ")
		}
		f := finding.Finding{
			ID: FamilyCVE + hp,
			Title: fmt.Sprintf("Potentially vulnerable %s version %s — manual validation required (%d CVEs correlate via NVD ranges)",
				o.Product, o.Version, len(ids)),
			Host:       hp,
			Severity:   "MEDIUM",
			Confidence: "Low",
			Validation: "version-inferred",
			DetectorID: DetectorBannerCVE,
			ImpactText: fmt.Sprintf("The %s version is inferred from the service banner. NVD lists %d CVEs whose affected range includes %s, but this does NOT establish that the host runs the vulnerable build: distributions backport fixes without changing the upstream version. Treat as a lead for manual validation.",
				o.Product, len(ids), o.Version),
			CVEs:             ids,
			ProbeKind:        "manual",
			DiscoveredFrom:   "network sweep (cvematch)",
			ObservedEvidence: ev,
		}
		finding.Classify(&f)
		f.References = append(f.References, "Remediation: upgrade to a fixed release and confirm the running build. Hiding the version banner is not remediation.")
		out = append(out, f)
	}
	return out
}

// SyncResult counts what a sync changed.
type SyncResult struct{ Opened, Updated, Regressed, Closed int }

// SyncFindings writes one family of findings into the workdir. Findings keep
// their first-seen time, history, and any human decision (accepted, manual).
// A finding of the family that the new set no longer contains is closed as
// mitigated; one that returns after being mitigated is reopened as a
// regression — the same transitions `report --retest` applies.
func SyncFindings(wd, family string, fs []finding.Finding) (SyncResult, error) {
	var res SyncResult
	existing := map[string]finding.Finding{}
	for _, f := range finding.LoadWorkFindings(wd) {
		if strings.HasPrefix(f.ID, family) {
			existing[f.ID] = f
		}
	}
	now := finding.NowRFC()
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.ID] = true
		old, ok := existing[f.ID]
		if !ok {
			res.Opened++
			if err := finding.AddFinding(wd, f); err != nil {
				return res, err
			}
			continue
		}
		f.FirstSeen, f.RetestHistory, f.FixedAt, f.RegressedAt = old.FirstSeen, old.RetestHistory, old.FixedAt, old.RegressedAt
		switch old.Status {
		case "accepted", "manual":
			f.Status = old.Status
			res.Updated++
		case "mitigated":
			f.Status, f.RegressedAt = "open", now
			f.RetestHistory = append(f.RetestHistory, map[string]string{
				"date": now, "disposition": "REGRESSED", "change": "↑ regressed",
				"retest_evidence": "observed again by a network re-run", "prev_status": old.Status,
			})
			res.Regressed++
		default:
			f.Status = "open"
			res.Updated++
		}
		if err := finding.AddFinding(wd, f); err != nil {
			return res, err
		}
	}
	for id, old := range existing {
		if seen[id] || old.Status == "mitigated" || old.Status == "accepted" {
			continue
		}
		prev := old.Status
		old.Status, old.FixedAt = "mitigated", now
		old.RetestHistory = append(old.RetestHistory, map[string]string{
			"date": now, "disposition": "FIXED", "change": "✓ fixed",
			"retest_evidence": "no longer produced by a network re-run", "prev_status": prev,
		})
		res.Closed++
		if err := finding.AddFinding(wd, old); err != nil {
			return res, err
		}
	}
	return res, nil
}

// String renders a one-line summary.
func (r SyncResult) String() string {
	return fmt.Sprintf("%d new, %d updated, %d regressed, %d closed", r.Opened, r.Updated, r.Regressed, r.Closed)
}
