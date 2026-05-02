# copyfail-ebpf-k8s

Kubernetes eBPF mitigation for **CVE-2026-31431** ([Copy.Fail](https://copy.fail)). Deploy the DaemonSet and every Linux node in your cluster is protected immediately.

## The Vulnerability

CVE-2026-31431 allows any authorized user to change the cached copy of any readable file via `AF_ALG` crypto sockets (provided by `algif_*` kernel modules). This leads to **local privilege escalation (root exploit)**, **container/sandbox escape**, and other issues.

The standard workaround -- disabling the `algif_aead` kernel module -- does not work when the module is built into the kernel (Fedora, Oracle Linux, other RHEL-based distros), and some upstreams have not yet shipped a fix.

## Quick Start

One command to remediate the issue across your entire cluster:

```bash
kubectl apply -f k8s-daemonset.yaml
```

This deploys a DaemonSet to **every Linux node** (including tainted masters) in `kube-system`. Each pod loads an eBPF program that blocks `AF_ALG` socket creation at the kernel level, neutralizing the exploit.

### Verify it's running

```bash
kubectl get daemonset -n kube-system copyfail-ebpf
kubectl logs -n kube-system -l app=copyfail-ebpf
```

### Remove

```bash
kubectl delete -f k8s-daemonset.yaml
```

## How It Works

The container image (`ghcr.io/iwanhae/copyfail-ebpf:latest`) bundles two eBPF programs. The userspace loader auto-selects the best one based on your kernel's capabilities:

| Program | Hook | Action | Requires |
|---|---|---|---|
| `ebpf-alg-socket-filter` | `lsm/socket_create` | Denies socket creation (returns error) | BPF LSM enabled |
| `ebpf-alg-socket-killer` | `tracepoint/sys_enter_socket` | Kills the offending process (`SIGKILL`) | Any kernel with tracepoints |

Both programs skip kernel-internal sockets. AF_ALG socket creation is blocked for all UIDs (including root). Events are logged via a BPF ring buffer:

```
[2026-05-02 14:30:15] BLOCKED AF_ALG socket: pid=1234 uid=1000 gid=1000 comm="python3"
```

## Architecture

```
                   Kubernetes Node
 ┌──────────────────────────────────────────┐
 │  DaemonSet Pod (privileged)              │
 │  ┌────────────────────────────────────┐  │
 │  │  copyfail-mitigation (loader)      │  │
 │  │   - Detects BPF LSM capability     │  │
 │  │   - Loads & attaches eBPF program  │  │
 │  │   - Logs events to stdout          │  │
 │  └──────────────┬─────────────────────┘  │
 │                  │ libbpf                 │
 │  ┌──────────────┴─────────────────────┐  │
 │  │  Kernel                            │  │
 │  │  ebpf-alg-socket-filter (LSM)      │  │
 │  │   Hook: lsm/socket_create          │  │
 │  │   Action: return -EPERM (deny)     │  │
 │  │                OR                   │  │
 │  │  ebpf-alg-socket-killer (tp)       │  │
 │  │   Hook: sys_enter_socket           │  │
 │  │   Action: SIGKILL                  │  │
 │  │                                    │  │
 │  │  Both: skip kernel sockets, only   │  │
 │  │  block AF_ALG (all UIDs)           │  │
 │  └────────────────────────────────────┘  │
 └──────────────────────────────────────────┘
```

## Checking for BPF LSM

The loader auto-detects which program to use. To check manually:

```bash
kubectl exec -n kube-system <pod-name> -- cat /sys/kernel/security/lsm
```

If `bpf` appears in the comma-separated list, the LSM filter is used (preferred). Otherwise the tracepoint killer is used as a fallback.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BPF_OBJECT_DIR` | `/usr/local/share/copyfail-ebpf` | Directory containing `.o` files |

## Important Notes

- **All UIDs blocked:** AF_ALG socket creation is blocked for all users including root, as any process can trigger the vulnerability.
- **Privileged required:** The DaemonSet requires `privileged: true` and access to `/sys/fs/bpf`.
- **Supported architectures:** `x86_64` / `amd64` and `aarch64` / `arm64`.
- **CO-RE:** eBPF programs use BTF/CO-RE for portability across kernel versions.
- **Graceful shutdown:** The loader handles `SIGTERM`/`SIGINT` to cleanly detach BPF programs.

## License

GPLv2
