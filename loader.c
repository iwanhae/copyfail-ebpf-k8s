#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "event.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

static volatile bool running = true;
static struct bpf_object *obj = NULL;
static struct ring_buffer *rb = NULL;
static struct bpf_link *prog_link = NULL;

static void sig_handler(int sig)
{
    running = false;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;
    struct timespec ts;
    char buf[64];

    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);

    const char *action;
    switch (e->action) {
    case EVENT_ACTION_BLOCKED:
        action = "BLOCKED";
        break;
    case EVENT_ACTION_KILLED:
        action = "KILLED";
        break;
    default:
        action = "UNKNOWN";
        break;
    }

    printf("[%s] %s AF_ALG socket: pid=%u uid=%u gid=%u comm=\"%s\"\n",
           buf, action, e->pid, e->uid, e->gid, e->comm);

    return 0;
}

static bool has_bpf_lsm(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f)
        return false;

    char buf[4096];
    bool found = false;
    if (fgets(buf, sizeof(buf), f)) {
        char *saveptr;
        char *tok = strtok_r(buf, ",\n", &saveptr);
        while (tok) {
            if (strcmp(tok, "bpf") == 0) {
                found = true;
                break;
            }
            tok = strtok_r(NULL, ",\n", &saveptr);
        }
    }

    fclose(f);
    return found;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    libbpf_set_print(libbpf_print_fn);

    struct sigaction sa = {
        .sa_handler = sig_handler,
        .sa_flags = 0,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    const char *bpf_dir = getenv("BPF_OBJECT_DIR");
    if (!bpf_dir || bpf_dir[0] == '\0')
        bpf_dir = "/usr/local/share/copyfail-ebpf";

    bool lsm = has_bpf_lsm();

    const char *filename;
    const char *label;
    if (lsm) {
        filename = "ebpf-alg-socket-filter.o";
        label = "filter";
    } else {
        filename = "ebpf-alg-socket-killer.o";
        label = "killer";
    }

    char bpf_path[512];
    snprintf(bpf_path, sizeof(bpf_path), "%s/%s", bpf_dir, filename);

    struct timespec ts;
    char tbuf[64];
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);

    printf("[%s] Loading %s module from %s...\n", tbuf, label, bpf_path);

    obj = bpf_object__open_file(bpf_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", bpf_path);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "No BPF program found\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_link = bpf_program__attach(prog);
    if (libbpf_get_error(prog_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        prog_link = NULL;
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "Failed to find 'events' map\n");
        bpf_object__close(obj);
        return 1;
    }

    int map_fd = bpf_map__fd(map);
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    tm = localtime(&ts.tv_sec);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("[%s] Loaded %s module, watching for AF_ALG socket events...\n",
           tbuf, label);

    while (running) {
        ring_buffer__poll(rb, 100);
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    tm = localtime(&ts.tv_sec);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("[%s] Unloading, received signal...\n", tbuf);

    ring_buffer__free(rb);
    bpf_object__close(obj);

    return 0;
}
