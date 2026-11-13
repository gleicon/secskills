//go:build unix

package netsec

import (
	"io/fs"
	"syscall"
)

// FileUID returns the owning uid of a stat result on unix systems.
func FileUID(fi fs.FileInfo) (int, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}
