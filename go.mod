module github.com/gleicon/secskills

go 1.27.4

require golang.org/x/net v0.62.0

// Published before a history rewrite that removed third-party names; their
// source differs from the cached module copies. Use v0.32.1 or later.
retract (
	v0.32.0
	[v0.31.0, v0.31.2]
)
