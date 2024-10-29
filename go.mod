module github.com/Asphaltt/bpflbr

go 1.22.4

require (
	github.com/cilium/ebpf v0.16.0
	github.com/knightsc/gapstone v4.0.1+incompatible
	github.com/spf13/pflag v1.0.5
)

require golang.org/x/sys v0.20.0 // indirect

replace github.com/knightsc/gapstone v4.0.1+incompatible => github.com/Asphaltt/gapstone v0.0.0-20241029140935-c5412a26abf7

replace github.com/cilium/ebpf v0.16.0 => github.com/Asphaltt/ebpf v0.0.0-20241102052356-d5a4c9e8b9c2
