# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

include makefiles/variables.mk

.DEFAULT_GOAL := $(BTRACE_OBJ)

# Build libcapstone for static linking
$(LIBCAPSTONE_OBJ):
	cd lib/capstone && \
		cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_ARCHITECTURE_DEFAULT=1 -DCAPSTONE_BUILD_CSTOOL=0 && \
		cmake --build build

# Build libpcap for static linking
$(LIBPCAP_OBJ):
	cd lib/libpcap && \
		./autogen.sh && \
		CC=$(CMD_CC) CXX=$(CMD_CXX) ./configure --disable-rdma --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl && \
		make

$(VMLINUX_OBJ):
	$(CMD_BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_OBJ)

$(FEAT_BPF_OBJ): $(FEAT_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) feat bpf/feature.c -- $(BPF2GO_EXTRA_FLAGS)

$(TRACEABLE_BPF_OBJ): $(TRACEABLE_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) traceable bpf/traceable.c -- $(BPF2GO_EXTRA_FLAGS)

$(TRACEPOINT_BPF_OBJ): $(TRACEPOINT_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) tracepoint bpf/tracepoint.c -- $(BPF2GO_EXTRA_FLAGS)

$(BTRACE_BPF_OBJ): $(BTRACE_BPF_SRC) $(VMLINUX_OBJ)
	$(BPF2GO) btrace bpf/btrace.c -- $(BPF2GO_EXTRA_FLAGS)

$(BTRACE_OBJ): $(BPF_OBJS) $(BTRACE_SRC) $(LIBCAPSTONE_OBJ) $(LIBPCAP_OBJ)
	$(GOBUILD_CGO_CFLAGS) $(GOBUILD_CGO_LDFLAGS) $(GOBUILD)

.PHONY: local_release
local_release: $(BTRACE_OBJ)
	@$(CMD_CP) $(BTRACE_OBJ) $(DIR_BIN)/$(BTRACE_OBJ)
	$(CMD_CHECKSUM) $(BTRACE_OBJ) > $(DIR_BIN)/$(BTRACE_CSM)

.PHONY: clean
clean:
	rm -f $(BPF_OBJS)
	rm -f btrace
	rm -rf $(DIR_BIN)/*
	@touch $(DIR_BIN)/.gitkeep

.PHONY: publish
publish: local_release
	@if [ -z "$(VERSION)" ]; then echo "VERSION is not set"; exit 1; fi
	$(CMD_TAR) -czf $(DIR_BIN)/$(BTRACE_OBJ)-$(VERSION)-linux-amd64.tar.gz $(DIR_BIN)/$(BTRACE_OBJ) $(DIR_BIN)/$(BTRACE_CSM)
	@$(CMD_MV) $(RELEASE_NOTES) $(DIR_BIN)/$(RELEASE_NOTES)
	$(CMD_GH) release create $(VERSION) $(DIR_BIN)/$(BTRACE_OBJ)-$(VERSION)-linux-amd64.tar.gz --title "btrace $(VERSION)" --notes-file $(DIR_BIN)/$(RELEASE_NOTES)
