// SPDX-License-Identifier: GPL-2.0
/*
 * qk_abi — report the shape of the kernel's congestion-control interface.
 *
 * The BPF congestion control interface changed shape between kernel
 * versions:
 *
 *   - older kernels: void (*cong_control)(struct sock *sk, const struct
 *     ack_sample *sample);
 *   - newer kernels: void (*cong_control)(struct sock *sk, u32 ack, int flag,
 *     const struct rate_sample *rs);
 *
 * The newer form gives the controller a rate sample with the delivery rate
 * and the loss counts; the older one gives only an ack sample, and the
 * erasure estimate has to come from the socket's own counters.
 *
 * This program prints the number of arguments the running kernel expects, so
 * that the build can compile the right variant. It prints nothing and exits
 * non-zero when the kernel has no BPF congestion control at all.
 */
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

int main(void)
{
	struct btf *btf;
	const struct btf_type *type;
	const struct btf_member *member;
	int id, i, n;

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		fprintf(stderr, "qk_abi: no kernel BTF\n");
		return 1;
	}

	id = btf__find_by_name_kind(btf, "tcp_congestion_ops", BTF_KIND_STRUCT);
	if (id < 0) {
		fprintf(stderr, "qk_abi: this kernel has no struct tcp_congestion_ops\n");
		return 1;
	}

	type = btf__type_by_id(btf, id);
	n = btf_vlen(type);
	member = btf_members(type);
	for (i = 0; i < n; i++) {
		const struct btf_type *mt, *pt;
		const char *name;

		name = btf__name_by_offset(btf, member[i].name_off);
		if (!name || strcmp(name, "cong_control"))
			continue;
		mt = btf__type_by_id(btf, member[i].type);
		if (!btf_is_ptr(mt))
			break;
		pt = btf__type_by_id(btf, mt->type);
		if (!btf_is_func_proto(pt))
			break;
		printf("%d\n", btf_vlen(pt));
		return 0;
	}

	fprintf(stderr, "qk_abi: this kernel has no cong_control callback\n");
	return 1;
}
