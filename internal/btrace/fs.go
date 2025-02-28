// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import "os"

func fileExists(filepath string) bool {
	stat, err := os.Stat(filepath)
	return err == nil && !stat.IsDir()
}
