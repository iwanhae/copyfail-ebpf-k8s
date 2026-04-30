/**
 *  eBPF tracepoint module to patch CVE-2026-31431 aka Copy.Fail
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
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_ALG 38
#define SIGKILL 9

SEC("tracepoint/syscalls/sys_enter_socket")
int ebpf_alg_socket_killer(struct trace_event_raw_sys_enter* ctx)
{
  int family = (int)ctx->args[0];
  if (family != AF_ALG) {
    return 0;
  }
  __u64 uid_gid = bpf_get_current_uid_gid();
  if (uid_gid == 0) { // allow root(0:0) to do anything (e.g. to run VPNs)
    return 0;
  }
  bpf_printk("Killing app for AF_ALG socket creation\n"); // information for audit later
  bpf_send_signal(SIGKILL);
  return 0;
}
