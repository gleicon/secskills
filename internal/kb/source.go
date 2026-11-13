package kb

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills"
)

// MaterializeRules writes the embedded ast-grep rules to a temp dir so the
// external ast-grep binary can read them. Returns the dir and a cleanup func.
func MaterializeRules() (string, func(), error) {
	dir, err := os.MkdirTemp("", "secskills-rules-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	err = fs.WalkDir(secskills.Rules, secskills.RulesRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(secskills.RulesRoot, p)
		dst := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := secskills.Rules.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dir, cleanup, nil
}
