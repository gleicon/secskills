//go:build unix

package probe

import "syscall"

// setIPOptions sets IPv4 header options on a socket.
func setIPOptions(fd uintptr, opt []byte) error {
	return syscall.SetsockoptString(int(fd), syscall.IPPROTO_IP, syscall.IP_OPTIONS, string(opt))
}
