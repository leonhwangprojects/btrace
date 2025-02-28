// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"golang.org/x/sys/unix"
)

// isatty checks if the given file descriptor is a terminal (TTY).
func isatty(fd uintptr) bool {
	// Attempt to get terminal attributes for the file descriptor using IoctlGetTermios.
	// If the call succeeds (err is nil), the file descriptor is a TTY.
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
