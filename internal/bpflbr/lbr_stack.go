// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import (
	"fmt"
	"io"
)

type branchEndpoint struct {
	addr uintptr

	funcName     string
	offset       uintptr
	endpointName string // ${funcName}+${offset}

	fileName string
	fileLine uint32
	lineInfo string // (${fileName}:${fileLine})
}

func (b *branchEndpoint) updateInfo() {
	b.endpointName = fmt.Sprintf("%#x:%s+%#x", b.addr, b.funcName, b.offset)
	if b.fileName != "" {
		b.lineInfo = fmt.Sprintf("(%s:%d)", b.fileName, b.fileLine)
	}
}

func (b *branchEndpoint) format(f string) string {
	switch {
	case b.endpointName != "" && b.lineInfo != "":
		return fmt.Sprintf(f, b.endpointName, b.lineInfo)
	case b.endpointName != "":
		return fmt.Sprintf(f, b.endpointName, "")
	case b.lineInfo != "":
		return fmt.Sprintf(f, "", b.lineInfo)
	default:
		return fmt.Sprintf(f, fmt.Sprintf("%#x", b.addr), "")
	}
}

type branchEntry struct {
	from, to *branchEndpoint
}

func (e *branchEntry) format(leftFmt, rightFmt string) string {
	l, r := e.from.format(leftFmt), e.to.format(rightFmt)
	return fmt.Sprintf("%s -> %s", l, r)
}

type branchRecord struct {
	entries []branchEntry
	last    int

	maxFromNameLen, maxFromLinfoLen int
	maxToNameLen, maxToLinfoLen     int
}

func newBranchRecord(entry branchEntry) *branchRecord {
	r := &branchRecord{
		entries: make([]branchEntry, 0, 32),
		last:    -1,
	}
	r.addEntry(entry)
	return r
}

func (r *branchRecord) addEntry(entry branchEntry) {
	r.entries = append(r.entries, entry)
	r.last++

	r.maxFromNameLen = max(r.maxFromNameLen, len(entry.from.endpointName))
	r.maxFromLinfoLen = max(r.maxFromLinfoLen, len(entry.from.lineInfo))
	r.maxToNameLen = max(r.maxToNameLen, len(entry.to.endpointName))
	r.maxToLinfoLen = max(r.maxToLinfoLen, len(entry.to.lineInfo))
}

func (r *branchRecord) appendRecord(record *branchRecord) {
	r.entries = append(r.entries, record.entries...)
	r.last += len(record.entries)

	r.maxFromNameLen = max(r.maxFromNameLen, record.maxFromNameLen)
	r.maxFromLinfoLen = max(r.maxFromLinfoLen, record.maxFromLinfoLen)
	r.maxToNameLen = max(r.maxToNameLen, record.maxToNameLen)
	r.maxToLinfoLen = max(r.maxToLinfoLen, record.maxToLinfoLen)
}

type lbrStack struct {
	last  int
	stack []*branchRecord
}

func newLBRStack() *lbrStack {
	return &lbrStack{
		stack: make([]*branchRecord, 0, 32),
	}
}

func (s *lbrStack) reset() {
	s.last = 0
	s.stack = s.stack[:0]
}

func (s *lbrStack) addRecord(record *branchRecord) {
	s.stack = append(s.stack, record)
	s.last++
}

func (s *lbrStack) pushFirstEntry(entry branchEntry) {
	s.stack = append(s.stack, newBranchRecord(entry))
}

func (s *lbrStack) pushEntry(entry branchEntry) {
	lastRecord := s.stack[s.last]
	lastEntry := lastRecord.entries[lastRecord.last]
	sameCallStack := lastEntry.to.funcName == entry.from.funcName

	if sameCallStack {
		lastRecord.addEntry(entry)
	} else {
		s.addRecord(newBranchRecord(entry))
	}
}

func (s *lbrStack) outputRecord(w io.Writer, lfmt, rfmt string, r *branchRecord, idx int) {
	fmt.Fprintf(w, "[#%02d] %s\n", idx, r.entries[0].format(lfmt, rfmt))

	i := 1
	for ; i < len(r.entries); i++ {
		entry := r.entries[i]
		fmt.Fprintf(w, "      %s\n", entry.format(lfmt, rfmt))
	}
}

func (s *lbrStack) getLeftFmt() string {
	var maxFromNameLen, maxFromLinfoLen int
	for _, r := range s.stack {
		maxFromNameLen = max(maxFromNameLen, r.maxFromNameLen)
		maxFromLinfoLen = max(maxFromLinfoLen, r.maxFromLinfoLen)
	}

	return fmt.Sprintf("%%-%ds %%-%ds", maxFromNameLen, maxFromLinfoLen)
}

func (s *lbrStack) getRightFmt() string {
	var maxToNameLen, maxToLinfoLen int
	for _, r := range s.stack {
		maxToNameLen = max(maxToNameLen, r.maxToNameLen)
		maxToLinfoLen = max(maxToLinfoLen, r.maxToLinfoLen)
	}

	return fmt.Sprintf("%%-%ds %%-%ds", maxToNameLen, maxToLinfoLen)
}

func (s *lbrStack) output(w io.Writer) {
	idx := 31
	lfmt := s.getLeftFmt()
	rfmt := s.getRightFmt()

	for _, r := range s.stack {
		s.outputRecord(w, lfmt, rfmt, r, idx)
		idx--
	}
}
