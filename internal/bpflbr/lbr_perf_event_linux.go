// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bpflbr

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func openLbrPerfEvent(cpu int) (int, error) {
	var attr unix.PerfEventAttr
	attr.Size = uint32(unsafe.Sizeof(attr))
	attr.Type = unix.PERF_TYPE_HARDWARE
	attr.Config = unix.PERF_COUNT_HW_CPU_CYCLES
	attr.Sample = 4000
	attr.Bits |= unix.PerfBitFreq
	attr.Sample_type = unix.PERF_SAMPLE_BRANCH_STACK
	attr.Branch_sample_type = unix.PERF_SAMPLE_BRANCH_KERNEL |
		unix.PERF_SAMPLE_BRANCH_ANY

	return unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
}
