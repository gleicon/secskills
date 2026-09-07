package main

import "embed"

// Embedded data — the KB, the ast-grep rules, and the tool registry all ship
// inside the single binary so secskills works offline with no sidecar files.
// rules are embedded from thirdparty/ast-grep-rules (a real directory) because
// go:embed cannot follow the rules/ symlink.

//go:embed all:kb
var kbFS embed.FS

//go:embed all:thirdparty/ast-grep-rules
var rulesFS embed.FS

//go:embed all:recipes
var recipesFS embed.FS

//go:embed tools/registry.tsv
var registryTSV string
