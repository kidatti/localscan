//go:build windows

package scanner

import (
	"errors"
	"syscall"
)

func isConnRefused(err error) bool {
	var sysErr *syscall.Errno
	if errors.As(err, &sysErr) {
		// WSAECONNREFUSED = 10061
		return *sysErr == 10061
	}
	return false
}
