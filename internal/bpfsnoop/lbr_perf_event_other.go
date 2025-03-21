// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package bpfsnoop

import (
	"golang.org/x/sys/unix"
)

func openLbrPerfEvent(cpu int) (int, error) {
	return 0, unix.EOPNOTSUPP
}
