/**
 *  LSM eBPF module to patch CVE-2026-31431 aka Copy.Fail
 *  Copyright (C) 2026  Wargaming.Net
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 **/
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_ALG 38

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("lsm/socket_create")
int BPF_PROG(ebpf_alg_socket_filter, int family, int type, int protocol, int kern)
{
  if (kern) {
    return 0;
  }
  if (family != AF_ALG) {
    return 0;
  }
  __u64 uid_gid = bpf_get_current_uid_gid();
  bpf_printk("Blocking AF_ALG socket creation\n"); // information for audit later
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = uid_gid;
    e->gid = uid_gid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->action = EVENT_ACTION_BLOCKED;
    bpf_ringbuf_submit(e, 0);
  }
  return -1;
}
