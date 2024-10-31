module github.com/Asphaltt/bpflbr

go 1.22.4

require (
	github.com/Asphaltt/addr2line v0.1.0
	github.com/cilium/ebpf v0.16.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/spf13/pflag v1.0.5
	golang.org/x/exp v0.0.0-20241009180824-f66d83c29e7c
)

require (
	github.com/ianlancetaylor/demangle v0.0.0-20240912202439-0a2b6291aafd // indirect
	golang.org/x/sys v0.20.0
)

replace github.com/knightsc/gapstone v4.0.1+incompatible => github.com/Asphaltt/gapstone v0.0.0-20241029140935-c5412a26abf7

replace github.com/cilium/ebpf v0.16.0 => github.com/Asphaltt/ebpf v0.0.0-20241102052356-d5a4c9e8b9c2
