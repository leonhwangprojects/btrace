# Copyright 2024 Leon Hwang.
# SPDX-License-Identifier: Apache-2.0

GOBUILD := go build -v -trimpath
GOBUILD_CGO_LDFLAGS := CGO_LDFLAGS='-O2 -g -lcapstone -static'

.DEFAULT_GOAL := build

build:
	$(GOBUILD_CGO_LDFLAGS) $(GOBUILD)
