# copyfail-ebpf-k8s

eBPF-based mitigation for **CVE-2026-31431** ([Copy.Fail](https://copy.fail)), deployable on bare-metal hosts, containers, and Kubernetes.

## The Vulnerability

CVE-2026-31431 allows any authorized user to change the cached copy of any readable file via `AF_ALG` crypto sockets (provided by `algif_*` kernel modules). This leads to **local privilege escalation (root exploit)**, **container/sandbox escape**, and other issues.

The standard workaround -- disabling the `algif_aead` kernel module -- does not work when the module is built into the kernel (Fedora, Oracle Linux, other RHEL-based distros), and some upstreams have not yet shipped a fix.

## How It Works

This project provides two eBPF programs that block `AF_ALG` socket creation at the kernel level. A userspace loader auto-selects the best one based on your kernel's capabilities:

| Program | Hook | Action | Requires |
|---|---|---|---|
| `ebpf-alg-socket-filter` | `lsm/socket_create` | Denies socket creation (returns error) | BPF LSM enabled |
| `ebpf-alg-socket-killer` | `tracepoint/sys_enter_socket` | Kills the offending process (`SIGKILL`) | Any kernel with tracepoints |

Both programs skip kernel-internal sockets and root (uid 0) processes. Events are logged via a BPF ring buffer:

```
[2026-05-02 14:30:15] BLOCKED AF_ALG socket: pid=1234 uid=1000 gid=1000 comm="python3"
```

## Quick Start

### Kubernetes (DaemonSet)

```bash
kubectl apply -f k8s-daemonset.yaml
```

Deploys to every Linux node (including tainted masters) in `kube-system`. View logs with:

```bash
kubectl logs -n kube-system -l app=copyfail-ebpf
```

Remove with `kubectl delete -f k8s-daemonset.yaml`.

### Docker

```bash
docker build -t copyfail-ebpf .
docker run --rm --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  copyfail-ebpf
```

### Manual (Host)

**Prerequisites:** `clang`, `libbpf-devel`, `bpftool`, kernel headers, `vmlinux.h`

```bash
ARCH=$(uname -m) ./build.sh build   # compile eBPF programs
./apply.sh load                      # load into kernel
./apply.sh status                    # verify
./apply.sh unload                    # remove
```

Or use the compiled loader binary directly:

```bash
./copyfail-mitigation
```

## Building from Source

### Build Dependencies

| Package | Purpose |
|---|---|
| `clang` / `llvm` | Compile eBPF programs and userspace loader |
| `libbpf-devel` / `libbpf-static` | BPF library (headers + static archive) |
| `elfutils-libelf-devel` | ELF parsing for BPF object loading |
| `zlib-devel` | Required by libbpf |
| `bpftool` | BTF dump, program management |
| `kernel-devel` | Kernel headers (fallback for `vmlinux.h`) |

### Compile

```bash
# Generate vmlinux.h if missing
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Build eBPF programs
ARCH=$(uname -m) ./build.sh build

# Build userspace loader (static libbpf)
clang -O2 -o copyfail-mitigation loader.c /usr/lib64/libbpf.a -lelf -lz
```

### Container Image

```bash
docker build -t copyfail-ebpf .
```

### Push to GitHub Container Registry

```bash
GHCR_TOKEN=<token> ./push.sh push-build
TAG=v1.0.0 ./push.sh push-build
```

See `push.sh` for configurable variables (`GHCR_OWNER`, `GHCR_REPO`, `IMAGE_NAME`, `TAG`, `ARCH`).

## Checking for BPF LSM

The loader and `apply.sh` auto-detect which program to use. To check manually:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` appears in the comma-separated list, the LSM filter is used (preferred). Otherwise the tracepoint killer is used as a fallback.

## Environment Variables

### Loader (`copyfail-mitigation`)

| Variable | Default | Description |
|---|---|---|
| `BPF_OBJECT_DIR` | `/usr/local/share/copyfail-ebpf` | Directory containing `.o` files |

### `apply.sh`

| Variable | Default | Description |
|---|---|---|
| `ARCH` | `uname -m` | Target architecture |
| `FILTER_OBJECT` | `build/$ARCH/ebpf-alg-socket-filter.o` | Path to filter BPF object |
| `KILLER_OBJECT` | `build/$ARCH/ebpf-alg-socket-killer.o` | Path to killer BPF object |
| `FILTER_PIN_PATH` | `/sys/fs/bpf/ebpf-alg-socket-filter` | BPF pin path for filter |
| `KILLER_PIN_PATH` | `/sys/fs/bpf/ebpf-alg-socket-killer` | BPF pin path for killer |

### `build.sh`

| Variable | Default | Description |
|---|---|---|
| `ARCH` | `uname -m` | Target architecture (`x86_64` or `aarch64`) |
| `OUT_DIR` | `build/$ARCH` | Output directory for compiled objects |

## Architecture

```
                     Userspace
  ┌──────────────────────────────────────────┐
  │  copyfail-mitigation (loader.c)          │
  │   - Detects BPF LSM capability           │
  │   - Loads & attaches eBPF program        │
  │   - Logs BLOCKED/KILLED events to stdout │
  │                                          │
  │  apply.sh (standalone bpftool-based)     │
  └──────────────┬───────────────────────────┘
                 │ libbpf / bpftool
                     Kernel
  ┌──────────────┴───────────────────────────┐
  │  ebpf-alg-socket-filter (LSM)            │
  │   Hook: lsm/socket_create                │
  │   Action: return -EPERM (deny)           │
  │                  OR                       │
  │  ebpf-alg-socket-killer (tracepoint)     │
  │   Hook: sys_enter_socket                 │
  │   Action: SIGKILL                        │
  │                                          │
  │  Both: skip kernel sockets, skip root,   │
  │        only block AF_ALG (family 38)     │
  └──────────────────────────────────────────┘
```

## Important Notes

- **Root exemption:** Processes running as root (uid 0) are always allowed to create `AF_ALG` sockets (needed for VPNs and system services).
- **Privileged required:** Both the container and Kubernetes DaemonSet require `privileged: true` and access to `/sys/fs/bpf`.
- **Supported architectures:** `x86_64` / `amd64` and `aarch64` / `arm64`.
- **CO-RE:** eBPF programs use BTF/CO-RE for portability across kernel versions.
- **Graceful shutdown:** The loader handles `SIGTERM`/`SIGINT` to cleanly detach BPF programs.

## License

GPLv2
