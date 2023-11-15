// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include <net/if.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>

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
    char* iface;
    int interval;
    switch(argc) {
        case 1:
            iface = "eth0";
            interval = 30;
            break;
        case 2:
            iface = argv[1];
            interval = 30;
            break;
        case default:
            iface = argv[1];
            interval = atoi(argv[2]);
    }
    
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
        minimal_bpf__destroy(obj);
        return EXIT_FAILURE;
    }

    /*
     * Use "xdpgeneric" mode; less performance but supported by all drivers
     */
    int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    flags |= XDP_FLAGS_SKB_MODE;
    
    int fd = bpf_program__fd(obj->progs.xdp_prog);

    /* Attach BPF to network interface */
    err = bpf_xdp_attach(ifindex, fd, flags, NULL);
    if (err < 0) {
        fprintf(stderr, "failed to attach BPF to iface %s (%d): %d\n", iface, ifindex, err);
        minimal_bpf__destroy(obj);
        return EXIT_FAILURE;
    }

    // XXX: replace with actual code, e.g. loop to get data from BPF
    sleep(interval);

    /* Remove BPF from network interface */
    err = bpf_xdp_detach(ifindex, flags, NULL);
    if (err < 0) {
        fprintf(stderr, "failed to detach BPF from iface %s (%d): %d\n", iface, ifindex, err);
        minimal_bpf__destroy(obj);
        return EXIT_FAILURE;
    }
                  
    return EXIT_SUCCESS;
}
