// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btrace

import (
	"fmt"
	"strings"
)

type KfuncFlag struct {
	name string
	arg  string
	typ  string
}

func parseKfuncFlag(k string) (KfuncFlag, error) {
	var kf KfuncFlag

	fields := strings.Split(k, ":")
	switch len(fields) {
	case 1:
		kf.name = strings.TrimSpace(fields[0])

	case 2:
		kf.name = strings.TrimSpace(fields[0])
		kf.arg = strings.TrimSpace(fields[1])

	case 3:
		kf.name = strings.TrimSpace(fields[0])
		kf.arg = strings.TrimSpace(fields[1])
		kf.typ = strings.TrimSpace(fields[2])

	default:
		return kf, fmt.Errorf("invalid kfunc flag: %s", k)
	}

	return kf, nil
}

func parseKfuncFlags(kfs []string) ([]KfuncFlag, error) {
	var kflags []KfuncFlag
	for _, k := range kfs {
		kf, err := parseKfuncFlag(k)
		if err != nil {
			return nil, err
		}
		kflags = append(kflags, kf)
	}

	return kflags, nil
}
