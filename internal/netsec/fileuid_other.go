//go:build !unix

package netsec

import "io/fs"

// FileUID reports no owner where file ownership has no uid.
func FileUID(fi fs.FileInfo) (int, bool) { return 0, false }
