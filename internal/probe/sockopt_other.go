//go:build !unix

package probe

// setIPOptions is unavailable here; IPv4OptionsReachable is Linux-gated anyway.
func setIPOptions(fd uintptr, opt []byte) error { return ErrUnsupported }
