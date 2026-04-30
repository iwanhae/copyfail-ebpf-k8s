#!/bin/sh
set -eu

COMMAND=${1:-}
ARCH=${ARCH:-$(uname -m)}
OUT_DIR=${OUT_DIR:-build/$ARCH}
FILTER_OBJECT=${FILTER_OBJECT:-$OUT_DIR/ebpf-alg-socket-filter.o}
KILLER_OBJECT=${KILLER_OBJECT:-$OUT_DIR/ebpf-alg-socket-killer.o}
FILTER_PIN_PATH=${FILTER_PIN_PATH:-/sys/fs/bpf/ebpf-alg-socket-filter}
KILLER_PIN_PATH=${KILLER_PIN_PATH:-/sys/fs/bpf/ebpf-alg-socket-killer}

case "$ARCH" in
	x86_64|amd64)
		TARGET_ARCH=__TARGET_ARCH_x86
		;;
	aarch64|arm64)
		TARGET_ARCH=__TARGET_ARCH_arm64
		;;
	*)
		echo "Unsupported ARCH: $ARCH" >&2
		exit 1
		;;
esac

case "$COMMAND" in
	build)
		if [ ! -f vmlinux.h ] && [ -f "/lib/modules/$(uname -r)/build/vmlinux.h" ]; then
			cp "/lib/modules/$(uname -r)/build/vmlinux.h" .
		fi
		mkdir -p "$OUT_DIR"
		clang -O2 -g -target bpf -D"$TARGET_ARCH" -c ebpf-alg-socket-filter.c -o "$FILTER_OBJECT"
		clang -O2 -g -target bpf -D"$TARGET_ARCH" -c ebpf-alg-socket-killer.c -o "$KILLER_OBJECT"
		;;
	load)
		if [ -r /sys/kernel/security/lsm ] && grep -qw bpf /sys/kernel/security/lsm; then
			bpftool prog load "$FILTER_OBJECT" "$FILTER_PIN_PATH" type lsm autoattach
		else
			bpftool prog load "$KILLER_OBJECT" "$KILLER_PIN_PATH" autoattach
		fi
		;;
	unload)
		rm -f "$FILTER_PIN_PATH" "$KILLER_PIN_PATH"
		;;
	status)
		bpftool prog show | grep -Eq 'ebpf_alg_socket_(filter|killer)' && echo "Active" || echo "Inactive"
		;;
	*)
		echo "Usage: ARCH=<x86_64|aarch64> $0 <build|load|unload|status>"
esac
