# CVE-2026-31431 aka [Copy.Fail](https://copy.fail) eBPF workaround

## Why it matters
This CVE allows authorized user change cache copy of any readable file, which leads to Local Privilege Escalation (aka local root exploit), sandbox/container escape and other issues.
It works by creating **AF\_ALG** socket that is provided by algif\* kernel modules.

Current well-known workaround recommends disabling **algif\_aead** module, that is not possible if the module is built-in, like in Fedora Linux, Oracle Linux and others RHEL-based.
Also, some upstreams are still missing the patch.
It means your systems will be vulnerable until you patch your kernel.

## Solution
This package provides you two eBPF programs:
- **ebpf-alg-socket-filter**, which filters AF\_ALG socket creation by eBPF/LSM kernel mechanism
- **ebpf-alg-socket-killer**, which kills any program that creates AF\_ALG socket

I recommend use first one IF you have eBPF LSM module enabled in your kernel. You can check it by calling
```
cat /sys/kernel/security/lsm
```
and checking if `bpf` is there.

If you don't have eBPF LSM module, use second program, it's more *rude* but protects as well.

## Building
- Install clang, kernel-heders, libbpf-devel and bpftool
- Copy vmlinux.h from your kernel headers
- run `build.sh build`

## Running
- Run `apply.sh load` to load
- Run `apply.sh unload` to unload
- Run `apply.sh status` to check status

