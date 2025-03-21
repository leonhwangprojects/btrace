# Copyright 2025 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0


CMD_BPFTOOL ?= bpftool
CMD_CC ?= clang
CMD_CD ?= cd
CMD_CHECKSUM ?= sha256sum
CMD_CP ?= cp
CMD_CXX ?= clang++
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar

DIR_BIN := ./bin

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include -I$(CURDIR)/lib/libpcap'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/capstone/build -lcapstone -L$(CURDIR)/lib/libpcap -lpcap -static'

BPF2GO := go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -go-package main
BPF2GO_EXTRA_FLAGS := -g -D__TARGET_ARCH_x86 -I./bpf -I./bpf/headers -I./lib/libbpf/src -Wno-address-of-packed-member -Wall

BTRACE_BPF_OBJ := btrace_bpfel.o btrace_bpfeb.o
BTRACE_BPF_SRC := bpf/btrace.c $(wildcard bpf/*.h) $(wildcard bpf/headers/*.h)

FEAT_BPF_OBJ := feat_bpfel.o feat_bpfeb.o
FEAT_BPF_SRC := bpf/feature.c

TRACEABLE_BPF_OBJ := traceable_bpfel.o traceable_bpfeb.o
TRACEABLE_BPF_SRC := bpf/traceable.c

TRACEPOINT_BPF_OBJ := tracepoint_bpfel.o tracepoint_bpfeb.o
TRACEPOINT_BPF_SRC := bpf/tracepoint.c

BPF_OBJS := $(BTRACE_BPF_OBJ) $(FEAT_BPF_OBJ) $(TRACEABLE_BPF_OBJ) $(TRACEPOINT_BPF_OBJ)

BTRACE_OBJ := btrace
BTRACE_SRC := $(shell find internal -type f -name '*.go') main.go
BTRACE_CSM := $(BTRACE_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a

LIBPCAP_OBJ := lib/libpcap/libpcap.a

VMLINUX_OBJ := $(CURDIR)/bpf/headers/vmlinux.h
