// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/knightsc/gapstone"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/leonhwangprojects/btrace/internal/assert"
	"github.com/leonhwangprojects/btrace/internal/btrace"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang btrace ./bpf/btrace.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -I./lib/libbpf/src -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang feat ./bpf/feature.c -- -g -D__TARGET_ARCH_x86 -I./bpf/headers -I./lib/libbpf/src -Wall

func main() {
	flags, err := btrace.ParseFlags()
	assert.NoErr(err, "Failed to parse flags: %v")

	if flags.Disasm() {
		btrace.Disasm(flags)
		return
	}

	if flags.ShowFuncProto() {
		btrace.ShowFuncProto(flags)
		return
	}

	mode := flags.Mode()
	assert.True(slices.Contains([]string{btrace.TracingModeEntry, btrace.TracingModeExit}, mode),
		fmt.Sprintf("Mode (%s) must be exit or entry", mode))

	progs, err := flags.ParseProgs()
	assert.NoErr(err, "Failed to parse bpf prog infos: %v")

	featBPFSpec, err := loadFeat()
	assert.NoErr(err, "Failed to load feat bpf spec: %v")

	err = btrace.DetectBPFFeatures(featBPFSpec)
	assert.NoErr(err, "Failed to detect bpf features: %v")

	if flags.OutputLbr() {
		lbrPerfEvents, err := btrace.OpenLbrPerfEvent()
		if err != nil &&
			(errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP)) {
			log.Fatalln("LBR is not supported on current system")
		}
		assert.NoErr(err, "Failed to open LBR perf event: %v")
		defer lbrPerfEvents.Close()
	}

	btrace.VerboseLog("Reading /proc/kallsyms ..")
	kallsyms, err := btrace.NewKallsyms()
	assert.NoErr(err, "Failed to read /proc/kallsyms: %v")

	var addr2line *btrace.Addr2Line

	vmlinux, err := btrace.FindVmlinux()
	if err != nil {
		if errors.Is(err, btrace.ErrNotFound) {
			btrace.VerboseLog("Dbgsym vmlinux not found")
		} else {
			assert.NoErr(err, "Failed to find vmlinux: %v")
		}
	}
	if err == nil {
		btrace.VerboseLog("Found vmlinux: %s", vmlinux)

		textAddr, err := btrace.ReadTextAddrFromVmlinux(vmlinux)
		assert.NoErr(err, "Failed to read .text address from vmlinux: %v")

		btrace.VerboseLog("Creating addr2line from vmlinux ..")
		kaslr := btrace.NewKaslr(kallsyms.Stext(), textAddr)
		addr2line, err = btrace.NewAddr2Line(vmlinux, kaslr, kallsyms.SysBPF())
		assert.NoErr(err, "Failed to create addr2line: %v")
	}

	engine, err := gapstone.New(int(gapstone.CS_ARCH_X86), int(gapstone.CS_MODE_64))
	assert.NoErr(err, "Failed to create capstone engine: %v")
	defer engine.Close()

	btrace.VerboseLog("Disassembling bpf progs ..")
	bpfProgs, err := btrace.NewBPFProgs(progs, false, false)
	assert.NoErr(err, "Failed to get bpf progs: %v")
	defer bpfProgs.Close()

	kfuncs, err := btrace.FindKernelFuncs(flags.Kfuncs(), kallsyms)
	assert.NoErr(err, "Failed to find kernel functions: %v")

	tracingTargets := bpfProgs.Tracings()
	assert.True(len(tracingTargets)+len(kfuncs) != 0, "No tracing target")

	btrace.VerboseLog("Tracing bpf progs or kernel functions ..")
	bpfSpec, err := loadBtrace()
	assert.NoErr(err, "Failed to load bpf spec: %v")
	delete(bpfSpec.Programs, btrace.TracingProgName(flags.OtherMode()))

	numCPU, err := ebpf.PossibleCPU()
	assert.NoErr(err, "Failed to get possible cpu: %v")

	eventsMapSpec := bpfSpec.Maps[".data.events"]
	eventsMapSpec.Flags |= unix.BPF_F_MMAPABLE
	eventsMapSpec.ValueSize = uint32(unsafe.Sizeof(btrace.Event{})) * uint32(numCPU)
	eventsMapSpec.Contents[0].Value = make([]byte, eventsMapSpec.ValueSize)
	eventsDataMap, err := ebpf.NewMap(eventsMapSpec)
	assert.NoErr(err, "Failed to create lbrs map: %v")

	funcStacks, err := ebpf.NewMap(bpfSpec.Maps["func_stacks"])
	assert.NoErr(err, "Failed to create func_stacks map: %v")
	defer funcStacks.Close()

	readyDataMapSpec := bpfSpec.Maps[".data.ready"]
	readyDataMapSpec.Flags |= unix.BPF_F_MMAPABLE
	readyDataMap, err := ebpf.NewMap(readyDataMapSpec)
	assert.NoErr(err, "Failed to create ready data map: %v")
	defer readyDataMap.Close()

	events, err := ebpf.NewMap(bpfSpec.Maps["events"])
	assert.NoErr(err, "Failed to create events map: %v")
	defer events.Close()

	reusedMaps := map[string]*ebpf.Map{
		"events":       events,
		".data.events": eventsDataMap,
		".data.ready":  readyDataMap,
		"func_stacks":  funcStacks,
	}

	if len(kfuncs) != 0 && len(progs) == 0 {
		tracingTargets = tracingTargets[:0]
	}

	if len(kfuncs) > 20 {
		log.Printf("btrace is tracing %d kernel functions, this may take a while", len(kfuncs))
	}

	tracings, err := btrace.NewBPFTracing(bpfSpec, reusedMaps, tracingTargets, kfuncs)
	assert.NoVerifierErr(err, "Failed to trace: %v")
	defer tracings.Close()
	assert.True(tracings.HaveTracing(), "No tracing target")

	err = bpfProgs.AddProgs(tracings.Progs(), true)
	assert.NoErr(err, "Failed to add bpf progs: %v")

	kallsyms, err = btrace.NewKallsyms()
	assert.NoErr(err, "Failed to reread /proc/kallsyms: %v")

	reader, err := ringbuf.NewReader(events)
	assert.NoErr(err, "Failed to create ringbuf reader: %v")
	defer reader.Close()

	w := os.Stdout
	if flags.OutputFile() != "" {
		f, err := os.OpenFile(flags.OutputFile(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		assert.NoErr(err, "Failed to create output file: %v")
		defer f.Close()
		w = f
	}

	err = readyDataMap.Put(uint32(0), uint32(1))
	assert.NoErr(err, "Failed to update ready data map: %v")
	defer readyDataMap.Put(uint32(0), uint32(0))

	log.Print("btrace is running..")
	defer log.Print("btrace is exiting..")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errg, ctx := errgroup.WithContext(ctx)

	errg.Go(func() error {
		<-ctx.Done()
		_ = reader.Close()
		return nil
	})

	errg.Go(func() error {
		return btrace.Run(reader, bpfProgs, addr2line, kallsyms, kfuncs, funcStacks, w)
	})

	err = errg.Wait()
	if err == btrace.ErrFinished {
		return
	}
	assert.NoErr(err, "Failed: %v")
}
