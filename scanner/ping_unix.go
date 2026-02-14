//go:build !windows

package scanner

import (
	"errors"
	"syscall"
)

func isConnRefused(err error) bool {
	var sysErr *syscall.Errno
	if errors.As(err, &sysErr) {
		return *sysErr == syscall.ECONNREFUSED
	}
	return false
}
