#!/bin/sh
set -eu

ARCH=${ARCH:-$(uname -m)}
COMMAND=${1:-}
FILTER_OBJECT=${FILTER_OBJECT:-build/${ARCH}/ebpf-alg-socket-filter.o}
KILLER_OBJECT=${KILLER_OBJECT:-build/${ARCH}/ebpf-alg-socket-killer.o}
FILTER_PIN_PATH=${FILTER_PIN_PATH:-/sys/fs/bpf/ebpf-alg-socket-filter}
KILLER_PIN_PATH=${KILLER_PIN_PATH:-/sys/fs/bpf/ebpf-alg-socket-killer}

case "$COMMAND" in
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
		echo "Usage: $0 <load|unload|status>"
		exit 1
		;;
esac
