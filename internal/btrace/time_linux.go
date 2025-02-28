// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package btrace

import (
	"syscall"
	"time"
)

func nanosleep() {
	var nano, left syscall.Timespec
	nano.Nsec = time.Microsecond.Nanoseconds()
	_ = syscall.Nanosleep(&nano, &left)
}
