// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

import (
	"bytes"
	"fmt"
	"io"
)

type bufferReaderAt struct {
	data []byte
}

// ReadAt implements the io.ReaderAt interface
func (b *bufferReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}

	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}

	n = copy(p, b.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return n, err
}

func newBufferReaderAt(b *bytes.Buffer) io.ReaderAt {
	return &bufferReaderAt{data: b.Bytes()}
}
