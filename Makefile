# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

GOBUILD := go build -v -trimpath
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -lcapstone -static'

GOGEN := go generate

BPF_OBJ := lbr_bpfel.o lbr_bpfeb.o feat_bpfel.o feat_bpfeb.o
BPF_SRC := bpf/lbr.c bpf/feature.c

.DEFAULT_GOAL := build

$(BPF_OBJ): $(BPF_SRC)
	$(GOGEN)

.PHONY: build
build: $(BPF_OBJ)
	$(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ)
	rm -f bpflbr
