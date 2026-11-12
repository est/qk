/* SPDX-License-Identifier: GPL-2.0 */
/*
 * qk tunable parameters.
 *
 * This header is shared by the BPF program and the userspace loader so that
 * the defaults have exactly one definition. The values live in a BPF map
 * (see qk.c) rather than in .rodata, because libbpf freezes .rodata once the
 * object is loaded, which would make the parameters compile-time only.
 *
 * Every field is a plain 32-bit integer so that the loader can address it by
 * name without knowing the layout, and so that a value can be changed while
 * the controller is running.
 */
#ifndef QK_TUNABLES_H
#define QK_TUNABLES_H

#include <linux/types.h>
#include <stddef.h>

/* "QKTU": marks a tunables entry as initialised. */
#define QK_TUN_MAGIC 0x514b5455u

/* Parts per million: the unit the ratios below are expressed in. */
#define QK_PPM 1000000u

/*
 * Upper bound on the erasure compensation, in parts per million. The
 * compensation is the factor by which the sending rate is multiplied to make
 * up for packets the channel erases; 4000000 means at most four times the
 * measured delivery rate.
 */
#define QK_DEFAULT_MAX_COMP_PPM 4000000u

/*
 * How much the compensation is reduced by, in percent, when a raise turns out
 * not to have bought any delivery.
 */
#define QK_DEFAULT_COMP_STEP_PCT 90u

/*
 * Decay of the delivery-rate maximum filter, in percent per round. 87
 * approximates the classic seven-eighths window.
 */
#define QK_DEFAULT_BW_DECAY_PCT 87u

/*
 * The delay bound, as a percentage of the path's minimum round-trip time.
 * 200 means the smoothed round-trip time may reach twice the minimum before
 * the brake starts to bite.
 */
#define QK_DEFAULT_BRAKE_RATIO_PCT 200u

/*
 * Number of rate samples that make up one round of erasure estimation.
 */
#define QK_DEFAULT_ERASURE_WINDOW 2000u

/*
 * How fast the erasure floor creeps back up, in percent per round. A floor
 * that never rose would keep compensating for a loss rate the path no longer
 * has.
 */
#define QK_DEFAULT_FLOOR_DECAY_PCT 75u

/* Congestion window bounds, in packets. */
#define QK_DEFAULT_MIN_CWND 10u
#define QK_DEFAULT_MAX_CWND 10000u

/* Assumed segment size for the bandwidth-delay product, in bytes. */
#define QK_DEFAULT_MSS 1460u

struct qk_tunables {
	__u32 magic;
	__u32 max_comp_ppm;
	__u32 comp_step_pct;
	__u32 bw_decay_pct;
	__u32 brake_ratio_pct;
	__u32 erasure_window;
	__u32 floor_decay_pct;
	__u32 min_cwnd;
	__u32 max_cwnd;
	__u32 mss;
	__u32 reserved;
};

/* The names the loader accepts on the command line, together with their
 * defaults and their offset inside struct qk_tunables. */
#define QK_TUNABLE_NAMES \
	{ "max_comp_ppm", QK_DEFAULT_MAX_COMP_PPM, \
	  offsetof(struct qk_tunables, max_comp_ppm) }, \
	{ "comp_step_pct", QK_DEFAULT_COMP_STEP_PCT, \
	  offsetof(struct qk_tunables, comp_step_pct) }, \
	{ "bw_decay_pct", QK_DEFAULT_BW_DECAY_PCT, \
	  offsetof(struct qk_tunables, bw_decay_pct) }, \
	{ "brake_ratio_pct", QK_DEFAULT_BRAKE_RATIO_PCT, \
	  offsetof(struct qk_tunables, brake_ratio_pct) }, \
	{ "erasure_window", QK_DEFAULT_ERASURE_WINDOW, \
	  offsetof(struct qk_tunables, erasure_window) }, \
	{ "floor_decay_pct", QK_DEFAULT_FLOOR_DECAY_PCT, \
	  offsetof(struct qk_tunables, floor_decay_pct) }, \
	{ "min_cwnd", QK_DEFAULT_MIN_CWND, \
	  offsetof(struct qk_tunables, min_cwnd) }, \
	{ "max_cwnd", QK_DEFAULT_MAX_CWND, \
	  offsetof(struct qk_tunables, max_cwnd) }, \
	{ "mss", QK_DEFAULT_MSS, \
	  offsetof(struct qk_tunables, mss) }

#define QK_TUNABLE_COUNT 9

#endif /* QK_TUNABLES_H */
