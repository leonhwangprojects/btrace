# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

CMD_BPFTOOL ?= bpftool
CMD_CD ?= cd
CMD_CP ?= cp
CMD_CHECKSUM ?= sha256sum
CMD_GH ?= gh
CMD_MV ?= mv
CMD_TAR ?= tar

DIR_BIN := ./bin

GOBUILD := go build -v -trimpath
GOBUILD_CGO_CFLAGS := CGO_CFLAGS='-O2 -I$(CURDIR)/lib/capstone/include'
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -L$(CURDIR)/lib/capstone/build -lcapstone -static'

GOGEN := go generate

BPF_OBJ := btrace_bpfel.o btrace_bpfeb.o feat_bpfel.o feat_bpfeb.o
BPF_SRC := bpf/btrace.c bpf/feature.c

BTRACE_OBJ := btrace
BTRACE_SRC := $(shell find internal -type f -name '*.go') main.go
BTRACE_CSM := $(BTRACE_OBJ).sha256sum
RELEASE_NOTES ?= release_notes.txt

LIBCAPSTONE_OBJ := lib/capstone/build/libcapstone.a

VMLINUX_OBJ := $(CURDIR)/bpf/headers/vmlinux.h

.DEFAULT_GOAL := $(BTRACE_OBJ)

# Build libcapstone for static linking
$(LIBCAPSTONE_OBJ):
	cd lib/capstone && \
		cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_ARCHITECTURE_DEFAULT=1 -DCAPSTONE_BUILD_CSTOOL=0 && \
		cmake --build build

$(VMLINUX_OBJ):
	$(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_OBJ)
	$(GOGEN)

$(BTRACE_OBJ): $(BPF_OBJ) $(BTRACE_SRC) $(LIBCAPSTONE_OBJ)
	$(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: local_release
local_release: $(BTRACE_OBJ)
	@$(CMD_CP) $(BTRACE_OBJ) $(DIR_BIN)/$(BTRACE_OBJ)
	$(CMD_CHECKSUM) $(BTRACE_OBJ) > $(DIR_BIN)/$(BTRACE_CSM)

.PHONY: clean
clean:
	rm -f $(BPF_OBJ)
	rm -f btrace
	rm -rf $(DIR_BIN)/*
	@touch $(DIR_BIN)/.gitkeep

.PHONY: publish
publish: local_release
	@if [ -z "$(VERSION)" ]; then echo "VERSION is not set"; exit 1; fi
	$(CMD_TAR) -czf $(DIR_BIN)/$(BTRACE_OBJ)-$(VERSION)-linux-amd64.tar.gz $(DIR_BIN)/$(BTRACE_OBJ) $(DIR_BIN)/$(BTRACE_CSM)
	@$(CMD_MV) $(RELEASE_NOTES) $(DIR_BIN)/$(RELEASE_NOTES)
	$(CMD_GH) release create $(VERSION) $(DIR_BIN)/$(BTRACE_OBJ)-$(VERSION)-linux-amd64.tar.gz --title "btrace $(VERSION)" --notes-file $(DIR_BIN)/$(RELEASE_NOTES)
