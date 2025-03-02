// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/leonhwangprojects/btrace/internal/assert"
)

func PrepareBPFMaps(spec *ebpf.CollectionSpec) map[string]*ebpf.Map {
	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu: %v")

	lbrsMapSpec := spec.Maps[".data.lbrs"]
	lbrsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	lbrsMapSpec.ValueSize = uint32(unsafe.Sizeof(LbrData{})) * uint32(numCPU)
	lbrsMapSpec.Contents[0].Value = make([]byte, lbrsMapSpec.ValueSize)
	lbrsData, err := ebpf.NewMap(lbrsMapSpec)
	assert.NoErr(err, "Failed to create lbrs map: %v")

	lbrs, err := ebpf.NewMap(spec.Maps["btrace_lbrs"])
	assert.NoErr(err, "Failed to create btrace_lbrs map: %v")

	strsMapSpec := spec.Maps[".data.strs"]
	strsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	strsMapSpec.ValueSize = uint32(unsafe.Sizeof(StrData{})) * uint32(numCPU)
	strsMapSpec.Contents[0].Value = make([]byte, strsMapSpec.ValueSize)
	strsData, err := ebpf.NewMap(strsMapSpec)
	assert.NoErr(err, "Failed to create strs map: %v")

	strs, err := ebpf.NewMap(spec.Maps["btrace_strs"])
	assert.NoErr(err, "Failed to create btrace_strs map: %v")

	stacks, err := ebpf.NewMap(spec.Maps["btrace_stacks"])
	assert.NoErr(err, "Failed to create btrace_stacks map: %v")

	readyDataMapSpec := spec.Maps[".data.ready"]
	readyDataMapSpec.Flags |= unix.BPF_F_MMAPABLE
	readyData, err := ebpf.NewMap(readyDataMapSpec)
	assert.NoErr(err, "Failed to create ready data map: %v")

	evsMapSpec := spec.Maps[".data.events"]
	evsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	evsMapSpec.ValueSize = uint32(unsafe.Sizeof(Event{})) * uint32(numCPU)
	evsMapSpec.Contents[0].Value = make([]byte, evsMapSpec.ValueSize)
	evsData, err := ebpf.NewMap(evsMapSpec)
	assert.NoErr(err, "Failed to create events data map: %v")

	events, err := ebpf.NewMap(spec.Maps["btrace_events"])
	assert.NoErr(err, "Failed to create events map: %v")

	return map[string]*ebpf.Map{
		"btrace_events": events,
		"btrace_lbrs":   lbrs,
		"btrace_strs":   strs,
		".data.events":  evsData,
		".data.lbrs":    lbrsData,
		".data.strs":    strsData,
		".data.ready":   readyData,
		"btrace_stacks": stacks,
	}
}

func CloseBPFMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}
