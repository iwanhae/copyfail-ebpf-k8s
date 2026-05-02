FROM fedora:latest AS builder

RUN dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    libbpf-static \
    elfutils-libelf-devel \
    zlib-devel \
    bpftool \
    kernel-devel \
    findutils \
 && dnf clean all -y

COPY . /build/
WORKDIR /build

RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
    else \
        VMLINUX_H=$(find /usr/src/kernels -name vmlinux.h 2>/dev/null | head -1) && \
        [ -n "$VMLINUX_H" ] && cp "$VMLINUX_H" vmlinux.h || true; \
    fi

RUN ./build.sh build

RUN clang -O2 -o copyfail-mitigation loader.c /usr/lib64/libbpf.a -lelf -lz

FROM registry.fedoraproject.org/fedora-minimal:latest

RUN microdnf install -y elfutils-libelf zlib-ng-compat && microdnf clean all

COPY --from=builder /build/copyfail-mitigation /usr/local/bin/
COPY --from=builder /build/build/x86_64/*.o /usr/local/share/copyfail-ebpf/

ENTRYPOINT ["/usr/local/bin/copyfail-mitigation"]
