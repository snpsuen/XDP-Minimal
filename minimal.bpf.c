// SPDX-License-Identifier: (LGPL-2.1-or-later OR BSD-2-Clause)

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>


SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    (void)ctx;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
