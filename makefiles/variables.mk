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

GOGEN := go generate

BPF_OBJ := btrace_bpfel.o btrace_bpfeb.o feat_bpfel.o feat_bpfeb.o
BPF_SRC := bpf/btrace.c bpf/feature.c $(wildcard bpf/*.h) $(wildcard bpf/headers/*.h)

BTRACE_OBJ := btrace
BTRACE_SRC := $(shell find internal -type f -name '*.go') main.go
BTRACE_CSM := $(BTRACE_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a

LIBPCAP_OBJ := lib/libpcap/libpcap.a

VMLINUX_OBJ := $(CURDIR)/bpf/headers/vmlinux.h
