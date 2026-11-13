// Package secskills holds the data that ships inside the secskills binary: the
// OWASP knowledge base, the ast-grep rules, per-stack recipes, the tool
// registry, the technology fingerprint seed and the default-credential set.
//
// The command lives in ./cmd/secskills. Assets stay at the module root because
// embed patterns cannot reach parent directories. The rules are embedded from
// thirdparty/ast-grep-rules (a real directory) because embed cannot follow the
// rules/ symlink.
package secskills

import "embed"

// KB is the OWASP knowledge base, rooted at "kb/".
//
//go:embed all:kb
var KB embed.FS

// Rules is the ast-grep rule set, rooted at "thirdparty/ast-grep-rules/".
//
//go:embed all:thirdparty/ast-grep-rules
var Rules embed.FS

// RulesRoot is the directory inside Rules that holds sgconfig.yml.
const RulesRoot = "thirdparty/ast-grep-rules"

// Recipes are the per-stack secure/vulnerable recipes, rooted at "recipes/".
//
//go:embed all:recipes
var Recipes embed.FS

// ToolRegistry is the external tool registry (tab-separated).
//
//go:embed tools/registry.tsv
var ToolRegistry string

// Fingerprints is the seed technology fingerprint registry (JSON).
//
//go:embed data/fingerprints.json
var Fingerprints []byte

// DefaultCredentials is the fixed vendor default-credential set used by
// dbcheck (JSON). It is a short known list, never a brute-force dictionary.
//
//go:embed data/default-credentials.json
var DefaultCredentials []byte
