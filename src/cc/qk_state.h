/* SPDX-License-Identifier: GPL-2.0 */
/*
 * qk per-connection state.
 *
 * Shared between the BPF program and the userspace loader so that the loader
 * can read back what the controller measured for each connection. The layout
 * is a plain structure of fixed-width fields; the loader only reads it.
 */
#ifndef QK_STATE_H
#define QK_STATE_H

#include <linux/types.h>

struct qk_state {
	/* delivery rate estimate, bytes per second */
	__u64 bw;

	/* minimum and smoothed round-trip time, microseconds */
	__u32 min_rtt_us;
	__u32 smoothed_rtt_us;

	/* erasure accounting for the current round */
	__u32 win_lost;
	__u32 win_total;

	/* the erasure floor: the lowest loss ratio seen recently, in parts per
	 * million */
	__u32 floor_ppm;
	__u32 floor_valid;

	/* applied compensation, parts per million */
	__u32 comp_ppm;

	/* the delivery rate of the previous round, used to detect whether the
	 * path still has capacity to give */
	__u64 bw_prev;

	/* when the current round started, so that the rate estimate and the
	 * capacity probe advance once per round trip rather than once per
	 * acknowledged segment */
	__u64 round_start_ns;

	/* the delivery rate observed when the current compensation was raised,
	 * and the round counter at that time */
	__u64 bw_at_comp;
	__u32 comp_round;
	__u32 cycles;

	/* the window we set, remembered for undo_cwnd */
	__u32 prior_cwnd;

	/* capacity probing: the window that is being probed with, the delivery
	 * rate of the previous round, and how many rounds in a row the rate
	 * has failed to improve */
	__u32 probe_cwnd;
	__u32 no_gain_rounds;
	__u32 in_probe;
	__u32 new_round;

	/* diagnostics */
	__u32 calls;
	__u32 pad;
	/* the retransmission counter at the end of the last round, so that the
	 * number of segments lost during a round can be counted on kernels
	 * whose congestion-control interface has no rate sample */
	__u32 last_total_retrans;
	__u32 last_total_retrans_pad;

	/* the last rate sample, as the kernel reported it */
	__s32 last_delivered;
	__s32 last_interval_us;
	__s32 last_rtt_us;
	__u32 last_app_limited;
	__u32 last_losses;
	__u32 last_acked;
	__u32 last_new_round;
	__u32 last_cwnd;
};

#endif /* QK_STATE_H */
