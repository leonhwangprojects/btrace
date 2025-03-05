// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import "github.com/leonhwangprojects/btrace/internal/strx"

type ArgData struct {
	Args [4][2]uint64
	Str  [32]byte
}

func (a *ArgData) str() string {
	return strx.NullTerminated(a.Str[:])
}
