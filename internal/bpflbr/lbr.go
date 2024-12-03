// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type LbrEntry struct {
	From  uintptr
	To    uintptr
	Flags uint64
}
type Event struct {
	Entries [32]LbrEntry
	NrBytes int64
	Retval  int64
	FuncIP  uintptr
	CPU     uint32
	Pid     uint32
	Comm    [16]byte
}

func Run(reader *ringbuf.Reader, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, w io.Writer) error {
	stack := newLBRStack()

	var sb strings.Builder

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			return fmt.Errorf("failed to read ringbuf: %w", err)
		}

		if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
			continue
		}

		event := (*Event)(unsafe.Pointer(&record.RawSample[0]))

		if event.NrBytes < 0 && event.NrBytes == -int64(unix.ENOENT) {
			return fmt.Errorf("LBR not supported")
		}

		hasLbrEntries := event.NrBytes > 0 && event.Entries[0] != (LbrEntry{})
		hasLbrEntries = hasLbrEntries && ev2stack(event, progs, addr2line, ksyms, stack)

		var targetName string
		progInfo, isProg := progs.funcs[event.FuncIP]
		if isProg {
			targetName = progInfo.funcName() + "[bpf]"
		} else {
			ksym, ok := ksyms.find(event.FuncIP)
			if ok {
				targetName = ksym.name
			} else {
				targetName = fmt.Sprintf("0x%x", event.FuncIP)
			}
		}

		fmt.Fprintf(&sb, "Recv a record for %s with", targetName)
		if mode != TracingModeEntry {
			fmt.Fprintf(&sb, " retval=%d/%#x", event.Retval, uint64(event.Retval))
		}
		fmt.Fprintf(&sb, " cpu=%d process=(%d:%s)", event.CPU, event.Pid, nullTerminated(event.Comm[:]))

		if hasLbrEntries {
			fmt.Fprintln(&sb, " :")
			stack.output(&sb)
		} else {
			fmt.Fprintln(&sb)
		}
		fmt.Fprintln(w, sb.String())

		sb.Reset()
		stack.reset()
	}
}

func getLineInfo(addr uintptr, progs *bpfProgs, a2l *Addr2Line, ksyms *Kallsyms) *branchEndpoint {
	if li, ok := progs.get(addr); ok {
		var ep branchEndpoint
		ep.addr = addr
		ep.offset = addr - li.ksymAddr
		ep.funcName = li.funcName
		ep.fileName = li.fileName
		ep.fileLine = li.fileLine
		ep.isProg = true
		ep.updateInfo()
		return &ep
	}

	var ep branchEndpoint
	ep.addr = addr
	defer ep.updateInfo()

	if ksym, ok := ksyms.find(addr); ok {
		ep.funcName = ksym.name
		ep.offset = addr - uintptr(ksym.addr)
	}

	if a2l == nil {
		return &ep
	}

	li, err := a2l.get(addr)
	if err != nil {
		return &ep
	}

	fileName := li.File
	if strings.HasPrefix(fileName, a2l.buildDir) {
		fileName = fileName[len(a2l.buildDir):]
	}

	ep.funcName = li.Func
	ep.fileName = fileName
	ep.fileLine = uint32(li.Line)
	ep.fromVmlinux = true
	return &ep
}

func ev2stack(event *Event, progs *bpfProgs, addr2line *Addr2Line, ksyms *Kallsyms, stack *lbrStack) bool {
	progInfo, isProg := progs.funcs[event.FuncIP]

	nrEntries := event.NrBytes / int64(8*3)
	entries := event.Entries[:nrEntries]
	if !verbose {
		if isProg {
			for i := range entries {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[i:]
					break
				}
			}

			for i := len(entries) - 1; i >= 0; i-- {
				if progInfo.contains(entries[i].From) || progInfo.contains(entries[i].To) {
					entries = entries[:i+1]
					break
				}
			}
		} else {
			// Skip the first 14 entries as they are entries for fexit_fn
			// and bpf_get_branch_snapshot helper.
			const nrSkip = 14

			entries = entries[nrSkip:]
		}

		if len(entries) == 0 {
			return false
		}
	}

	lbrEntries := make([]branchEntry, 0, len(entries))
	for _, entry := range entries {
		from := getLineInfo(entry.From, progs, addr2line, ksyms)
		to := getLineInfo(entry.To, progs, addr2line, ksyms)
		lbrEntries = append(lbrEntries, branchEntry{from, to})
	}

	last := len(lbrEntries) - 1
	stack.pushFirstEntry(lbrEntries[last])
	for i := last - 1; i >= 0; i-- {
		stack.pushEntry(lbrEntries[i])
	}

	return true
}
