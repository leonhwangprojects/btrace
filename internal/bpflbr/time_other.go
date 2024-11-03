// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package bpflbr

func nanosleep() {
}
