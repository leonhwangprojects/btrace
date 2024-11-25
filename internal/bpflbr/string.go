// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpflbr

import "unsafe"

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}

	if len(b) == 0 {
		return ""
	}

	return unsafe.String(&b[0], len(b))
}
