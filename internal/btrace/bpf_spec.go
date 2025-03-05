// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import "github.com/cilium/ebpf"

// TrimSpec trims unused bpf subprogs from the spec if it's unnecessary to inject
// `--filter-arg` or `--filter-pkt` expressions.
func TrimSpec(spec *ebpf.CollectionSpec) {
	for _, prog := range spec.Programs {
		if pktFilter.expr == "" {
			pktFilter.clear(prog)
		}

		if fnArg.expr == "" {
			fnArg.clear(prog)
		}
	}
}
