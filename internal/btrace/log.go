// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import "log"

func VerboseLog(format string, args ...interface{}) {
	if verbose {
		log.Printf(format, args...)
	}
}
