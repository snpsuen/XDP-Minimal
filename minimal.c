// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <bpf/bpf.h>
/* XDP_FLAGS_SKB_MODE */
#include <linux/if_link.h>

#include "minimal.skel.h"


static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <iface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("failed to resolve iface to ifindex");
        return EXIT_FAILURE;
    }

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("failed to increase RLIMIT_MEMLOCK");
        return EXIT_FAILURE;
    }

    libbpf_set_print(libbpf_print);

    int err;
    struct minimal_bpf *obj;

    obj = minimal_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return EXIT_FAILURE;
    }
    err = minimal_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /*
     * Use "xdpgeneric" mode; less performance but supported by all drivers
     */
    int flags = XDP_FLAGS_SKB_MODE;
    int fd = bpf_program__fd(obj->progs.xdp_prog);

    /* Attach BPF to network interface */
    err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    if (err) {
        fprintf(stderr, "failed to attach BPF to iface %s (%d): %d\n",
            iface, ifindex, err);
        goto cleanup;
    }

    // XXX: replace with actual code, e.g. loop to get data from BPF
    sleep(10);

    /* Remove BPF from network interface */
    fd = -1;
    err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    if (err) {
        fprintf(stderr, "failed to detach BPF from iface %s (%d): %d\n",
            iface, ifindex, err);
        goto cleanup;
    }

cleanup:
    example_bpf__destroy(obj);

    if (err) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
