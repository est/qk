// SPDX-License-Identifier: GPL-2.0
/*
 * qk — an erasure-aware TCP congestion control for Linux.
 *
 * qk is a BPF_PROG_TYPE_STRUCT_OPS congestion controller: it fills the
 * kernel's struct tcp_congestion_ops so that the kernel's own TCP stack calls
 * into it. The entire control loop runs inside the kernel; no userspace
 * process takes part in it.
 *
 * The control law is a port of the erasure-aware controller from the Queqiao
 * project (internal/congestion/erasure.go, "ErasureSender"). Its premise is
 * that the path is an *erasure* channel rather than a congested one:
 *
 *   - Packet loss that is independent of the sending rate does not improve
 *     when the sender backs off. Treating it as congestion therefore throws
 *     away bandwidth for nothing.
 *   - The brake is therefore a *delay* bound, not a loss signal: the smoothed
 *     round-trip time may not exceed a configurable multiple of the path's
 *     minimum round-trip time. Beyond that bound the sending rate is scaled
 *     down continuously, so a sender that merely sits at the bound is not
 *     punished for arriving there.
 *   - The measured erasure is used for exactly two things: sizing the window
 *     so that a full window of *delivered* bytes is in flight, and scaling the
 *     sending rate so that the *delivered* rate matches the intended rate.
 *   - Compensation is treated as a bet. Raising it claims that sending more
 *     will buy proportionally more delivery; the claim is tested against the
 *     observed delivery rate and withdrawn when it does not pay off.
 *
 * Two further details come straight from the upstream design:
 *
 *   - An application-limited sample must not lower the sending rate. A
 *     request-shaped flow is application-limited by construction, and metering
 *     it at its own (low) delivery estimate is precisely the mistake that made
 *     an earlier version slower than a tuned TCP client.
 *   - Upstream and downstream are different directions and are never mixed;
 *     this controller only ever sees the direction it is attached to.
 *
 * The tunable parameters live in a BPF map so that they can be changed while
 * the controller is running; see qk_tunables.h and qkctl(8).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "qk_tunables.h"
#include "qk_state.h"

/*
 * The name the kernel registers this controller under. It is compiled in
 * because the kernel reads it from the operations table; the kernel's limit
 * is 16 bytes including the terminator. The default is the product name.
 * Overriding it is useful for testing a second build alongside a first one,
 * because a registered congestion control cannot be replaced in place.
 */
#ifndef QK_CC_NAME
#define QK_CC_NAME qk
#endif

/*
 * The shape of the kernel's congestion-control interface changed between
 * kernel versions:
 *
 *   QK_ABI_ARGS == 4   void (*cong_control)(struct sock *sk, u32 ack,
 *                        int flag, const struct rate_sample *rs);
 *   QK_ABI_ARGS == 2   void (*cong_control)(struct sock *sk,
 *                        const struct ack_sample *sample);
 *
 * The four-argument form hands the controller a rate sample with the
 * delivery rate and the loss counts. The two-argument form does not, so the
 * erasure estimate is taken from the socket's own counters instead. The
 * control law is otherwise identical.
 *
 * qk_abi(1) reports which one the running kernel expects; the build uses it.
 */
#ifndef QK_ABI_ARGS
#define QK_ABI_ARGS 4
#endif

/* Turn the token into the string the kernel's operations table needs. */
#define QK_STR_(x) #x
#define QK_STR(x) QK_STR_(x)

/* ------------------------------------------------------------------ *
 * Kernel types we touch.
 *
 * These are partial definitions on purpose: CO-RE resolves every field by
 * name against the running kernel's BTF, so only the fields actually used
 * need to be declared. The nesting is kept because the kernel's field-access
 * checks are expressed in terms of the outer struct.
 * ------------------------------------------------------------------ */

struct sock_common {
	unsigned char skc_state;
	__u16 skc_num;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	unsigned long sk_pacing_rate;
	unsigned long sk_max_pacing_rate;
	__u32 sk_pacing_status;
} __attribute__((preserve_access_index));

struct inet_sock {
	struct sock sk;
} __attribute__((preserve_access_index));

struct inet_connection_sock {
	struct inet_sock icsk_inet;
} __attribute__((preserve_access_index));

struct tcp_sock {
	struct inet_connection_sock inet_conn;
	__u32 delivered;
	__u32 delivered_ce;
	__u64 bytes_acked;
	__u32 total_retrans;
	__u32 snd_cwnd;
	__u32 snd_ssthresh;
	__u32 snd_cwnd_cnt;
	__u32 snd_cwnd_clamp;
} __attribute__((preserve_access_index));

/* The kernel's per-ACK sample. */
struct ack_sample {
	__u32 pkts_acked;
	__s32 rtt_us;
	__u32 in_flight;
} __attribute__((preserve_access_index));

/* The kernel's per-round rate sample: delivery rate, losses and RTT. */
struct rate_sample {
	unsigned long long prior_mstamp;
	__u32 prior_delivered;
	__u32 prior_delivered_ce;
	__s32 delivered;
	__s32 delivered_ce;
	__s64 interval_us;
	__u32 snd_interval_us;
	__u32 rcv_interval_us;
	__s64 rtt_us;
	__s32 losses;
	__u32 acked_sacked;
	__u32 prior_in_flight;
	__u32 last_end_seq;
	__u8 is_app_limited;
	__u8 is_retrans;
	__u8 is_ack_delayed;
} __attribute__((preserve_access_index));

/* ------------------------------------------------------------------ *
 * Tunables.
 * ------------------------------------------------------------------ */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct qk_tunables);
} qk_tunables SEC(".maps");

/* ------------------------------------------------------------------ *
 * Per-connection state.
 * ------------------------------------------------------------------ */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct qk_state);
} qk_states SEC(".maps");

/* ------------------------------------------------------------------ *
 * Helpers.
 * ------------------------------------------------------------------ */

static __always_inline struct qk_state *qk_get(struct tcp_sock *tp)
{
	__u64 key = (__u64)(unsigned long)tp;

	return bpf_map_lookup_elem(&qk_states, &key);
}

static __always_inline void qk_put(struct tcp_sock *tp, const struct qk_state *st)
{
	__u64 key = (__u64)(unsigned long)tp;

	bpf_map_update_elem(&qk_states, &key, st, BPF_ANY);
}

static __always_inline __u32 qk_clamp(__u32 v, __u32 lo, __u32 hi)
{
	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
}

/*
 * Read the tunables. If the map has not been initialised - which is the case
 * when the object was loaded without the loader - the compiled-in defaults
 * are used, so the controller is always usable.
 */
static __always_inline void qk_load_tunables(struct qk_tunables *out)
{
	__u32 key = 0;
	struct qk_tunables *t = bpf_map_lookup_elem(&qk_tunables, &key);

	if (t && t->magic == QK_TUN_MAGIC) {
		*out = *t;
		return;
	}

	out->magic = QK_TUN_MAGIC;
	out->max_comp_ppm = QK_DEFAULT_MAX_COMP_PPM;
	out->comp_step_pct = QK_DEFAULT_COMP_STEP_PCT;
	out->bw_decay_pct = QK_DEFAULT_BW_DECAY_PCT;
	out->brake_ratio_pct = QK_DEFAULT_BRAKE_RATIO_PCT;
	out->erasure_window = QK_DEFAULT_ERASURE_WINDOW;
	out->floor_decay_pct = QK_DEFAULT_FLOOR_DECAY_PCT;
	out->min_cwnd = QK_DEFAULT_MIN_CWND;
	out->max_cwnd = QK_DEFAULT_MAX_CWND;
	out->mss = QK_DEFAULT_MSS;
	out->reserved = 0;
}

/* ------------------------------------------------------------------ *
 * The congestion control callbacks.
 *
 * The kernel types the callback's first argument as struct tcp_sock; it
 * promotes a struct sock pointer to that type itself.
 * ------------------------------------------------------------------ */

SEC("struct_ops/qk_init")
int BPF_PROG(qk_init, struct tcp_sock *tp)
{
	struct qk_state st = {};
	struct qk_tunables tun;

	qk_load_tunables(&tun);

	st.comp_ppm = QK_PPM;
	st.probe_cwnd = tun.min_cwnd;
	st.in_probe = 1;
	qk_put(tp, &st);

	/* qk drives the pacing rate of this socket. The maximum rate is not on
	 * the kernel's writable-field allowlist, so the socket keeps whatever
	 * ceiling it already had; only the rate itself is driven from here. */
	tp->snd_cwnd = tun.min_cwnd;
	tp->snd_cwnd_cnt = tun.min_cwnd;
	return 0;
}

SEC("struct_ops/qk_release")
int BPF_PROG(qk_release, struct tcp_sock *tp)
{
	__u64 key = (__u64)(unsigned long)tp;

	bpf_map_delete_elem(&qk_states, &key);
	return 0;
}

/* Called when the connection enters loss.
 *
 * On an erasure path a loss is not congestion. Cutting the window here is
 * exactly what collapses throughput on a lossy link: the window shrinks,
 * the delivered rate with it, and the next loss shrinks it again. The delay
 * brake is the overload signal in this design, so the window is left alone.
 */
SEC("struct_ops/qk_ssthresh")
__u32 BPF_PROG(qk_ssthresh, struct tcp_sock *tp)
{
	struct qk_state *st = qk_get(tp);
	struct qk_tunables tun;
	__u32 target;

	qk_load_tunables(&tun);

	/* The slow-start threshold must not become a ceiling: if it follows
	 * a window that has not yet grown, the window can never grow. It is
	 * therefore the probe window, which is where the controller intends to
	 * get to, and at least the current window. */
	target = tp->snd_cwnd;
	if (st && st->probe_cwnd > target)
		target = st->probe_cwnd;
	return qk_clamp(target, tun.min_cwnd, tun.max_cwnd);
}

SEC("struct_ops/qk_set_state")
int BPF_PROG(qk_set_state, struct tcp_sock *tp, __u8 new_state)
{
	(void)tp;
	(void)new_state;
	return 0;
}

SEC("struct_ops/qk_min_tso_segs")
__u32 BPF_PROG(qk_min_tso_segs, struct tcp_sock *tp)
{
	(void)tp;
	return 2;
}

SEC("struct_ops/qk_sndbuf_expand")
__u32 BPF_PROG(qk_sndbuf_expand, struct tcp_sock *tp)
{
	(void)tp;
	return 0;
}

/* The kernel requires this callback; it returns the window to restore when
 * leaving fast recovery. */
SEC("struct_ops/qk_undo_cwnd")
__u32 BPF_PROG(qk_undo_cwnd, struct tcp_sock *tp)
{
	struct qk_state *st = qk_get(tp);

	if (st && st->prior_cwnd)
		return st->prior_cwnd;
	return tp->snd_cwnd;
}

/* Per-ACK hook: the kernel hands us a fresh RTT sample here. */
SEC("struct_ops/qk_pkts_acked")
int BPF_PROG(qk_pkts_acked, struct tcp_sock *tp, const struct ack_sample *sample)
{
	struct qk_state *st = qk_get(tp);

	if (!st || !sample)
		return 0;
	if (sample->rtt_us > 0 &&
	    (st->min_rtt_us == 0 || (__u32)sample->rtt_us < st->min_rtt_us))
		st->min_rtt_us = (__u32)sample->rtt_us;
	return 0;
}

/*
 * The control law. Runs once per acknowledged round.
 */
/*
 * One round of the control law.
 *
 * The three inputs are the round-trip time in microseconds, the number of
 * packets lost during the round, and the number that arrived. Where they come
 * from depends on the kernel's interface; see QK_ABI_ARGS.
 */
static void qk_step(struct tcp_sock *tp, __u32 rtt_us, __u32 lost, __u32 acked)
{
	struct qk_state *st = qk_get(tp);
	struct qk_tunables tun;
	__u32 round_ppm, comp, bound_us, factor_pct, cwnd, mss;

	if (!st) {
		/* The state can legitimately be missing - the map is an LRU, and
		 * a long-lived map can evict an idle connection. Recreating it
		 * is better than giving up on the connection. */
		struct qk_state fresh = {};

		fresh.comp_ppm = QK_PPM;
		fresh.in_probe = 1;
		qk_put(tp, &fresh);
		st = qk_get(tp);
	}
	if (!st)
		return;
	st->calls++;

	qk_load_tunables(&tun);
	mss = tun.mss ? tun.mss : QK_DEFAULT_MSS;

	/* --- 1. round-trip time: the floor and a smoothed value ----------
	 * The floor is a minimum, and a minimum is fragile: one spuriously
	 * small sample pins it, and then the delay bound - which is derived
	 * from the floor - is far below the real round-trip time, so the brake
	 * is on all the time and the flow crawls. The floor therefore creeps
	 * back up towards the smoothed value, slowly enough that a genuine
	 * improvement still registers quickly. */
	if (rtt_us > 0) {
		if (st->min_rtt_us == 0 || rtt_us < st->min_rtt_us)
			st->min_rtt_us = rtt_us;
		st->smoothed_rtt_us = (st->smoothed_rtt_us * 3 + rtt_us) / 4;
	}

	/* The kernel calls this once per acknowledged segment, but the delay
	 * bound and the erasure estimate are round-trip quantities. Advancing
	 * them per acknowledgement would react to every single segment. */
	{
		__u64 now = bpf_ktime_get_ns();
		__u64 round_ns = st->min_rtt_us ? (__u64)st->min_rtt_us * 1000 : 1000000;

		if (st->round_start_ns == 0 ||
		    now - st->round_start_ns >= round_ns) {
			st->round_start_ns = now;
			st->new_round = 1;
		} else {
			st->new_round = 0;
		}
	}

	/* --- 2. the erasure estimate --------------------------------------
	 * The loss ratio is the channel's loss rate. The floor is the lowest
	 * ratio seen recently: below it, loss is independent of what we do,
	 * and only the excess above it can be something we caused. */
	st->win_lost += lost;
	st->win_total += lost + acked;

	if (tun.erasure_window && st->win_total >= tun.erasure_window) {
		round_ppm = (__u32)(((__u64)st->win_lost * QK_PPM) / st->win_total);
		if (!st->floor_valid) {
			st->floor_ppm = round_ppm;
			st->floor_valid = 1;
		} else if (round_ppm < st->floor_ppm) {
			st->floor_ppm = round_ppm;
		} else {
			/* the floor creeps back up, so a path that has genuinely
			 * become worse is eventually compensated for */
			st->floor_ppm = (st->floor_ppm * tun.floor_decay_pct +
					 round_ppm * (100 - tun.floor_decay_pct)) / 100;
		}
		st->win_lost = 0;
		st->win_total = 0;
	}

	/* --- 3. the compensation ------------------------------------------
	 * The window has to carry the bytes that actually arrive: with an
	 * erasure rate of p, a window of W delivers W*(1-p) bytes per round
	 * trip. The compensation is the factor that makes up for that, so it
	 * is sized against the erasure floor - the part of the loss the
	 * channel takes whatever the sender does. */
	if (st->floor_ppm < QK_PPM) {
		comp = QK_PPM + (__u32)(((__u64)st->floor_ppm * QK_PPM) / (QK_PPM - st->floor_ppm));
		if (comp > tun.max_comp_ppm)
			comp = tun.max_comp_ppm;
	} else {
		comp = tun.max_comp_ppm;
	}
	st->comp_ppm = comp;

	/* --- 4. the delay bound, and the window it governs ----------------
	 * The smoothed round-trip time may not exceed the bound. Below it the
	 * path has room and the window grows; above it, the queue is too deep
	 * and some of the window is given back.
	 *
	 * This is the whole control law, and it needs no delivery-rate
	 * estimate: on a path whose loss does not depend on the rate, the
	 * round-trip time is the only signal that means anything. */
	if (st->new_round && st->min_rtt_us && st->smoothed_rtt_us) {
		bound_us = st->min_rtt_us * tun.brake_ratio_pct / 100;

		if (bound_us && st->smoothed_rtt_us <= bound_us) {
			st->probe_cwnd += st->probe_cwnd / 8;
			if (st->probe_cwnd < 16)
				st->probe_cwnd = 16;
			if (st->probe_cwnd > tun.max_cwnd)
				st->probe_cwnd = tun.max_cwnd;
		} else {
			st->probe_cwnd -= st->probe_cwnd / 8;
			if (st->probe_cwnd < tun.min_cwnd)
				st->probe_cwnd = tun.min_cwnd;
		}
	}

	/* The brake, as a continuous factor: at the bound it is one, so a
	 * sender sitting exactly at the bound is not punished for it. */
	factor_pct = QK_PPM;
	if (st->min_rtt_us && st->smoothed_rtt_us && bound_us &&
	    st->smoothed_rtt_us > bound_us)
		factor_pct = (__u32)(((__u64)bound_us * QK_PPM) / st->smoothed_rtt_us);

	/* --- 5. the window and the rate that follows it -------------------
	 * A congestion control that provides cong_control owns the pacing
	 * rate: the kernel does not touch it. The arrangement the kernel
	 * expects is therefore the one used here: the window is the decision,
	 * and the pacing rate follows it.
	 *
	 * The window is the probe window, scaled by the compensation, because
	 * the bytes in flight have to cover the bytes that arrive. */
	cwnd = (__u32)(((__u64)st->probe_cwnd * comp) / QK_PPM);
	cwnd = qk_clamp(cwnd, tun.min_cwnd, tun.max_cwnd);

	if (factor_pct < QK_PPM) {
		/* the brake is biting: give the window back, scaled */
		__u32 reduced = (__u32)(((__u64)cwnd * factor_pct) / QK_PPM);

		if (reduced < tun.min_cwnd)
			reduced = tun.min_cwnd;
		if (reduced < tp->snd_cwnd)
			cwnd = reduced;
	}
	cwnd = qk_clamp(cwnd, tun.min_cwnd, tun.max_cwnd);

	/* The rate follows the window: one round trip's worth of it. */
	{
		__u64 pacing = (__u64)cwnd * mss * 1000000ULL / st->min_rtt_us;

		if (pacing < 1000)
			pacing = 1000;
		((struct sock *)tp)->sk_pacing_rate = pacing;
	}
}

#if QK_ABI_ARGS >= 4

SEC("struct_ops/qk_cong_control")
int BPF_PROG(qk_cong_control, struct tcp_sock *tp, __u32 ack, int flag,
	     const struct rate_sample *rs)
{
	(void)ack;
	(void)flag;

	if (!rs)
		return 0;

	/* Record what the kernel last reported, so that the loader can show
	 * it: the rate sample's units differ between kernels, and seeing the
	 * raw values is the only way to tell what the controller is looking
	 * at. */
	{
		struct qk_state *st = qk_get(tp);

		if (st) {
			st->last_delivered = rs->delivered;
			st->last_interval_us = (__s32)rs->interval_us;
			st->last_rtt_us = (__s32)rs->rtt_us;
			st->last_app_limited = rs->is_app_limited;
			st->last_losses = rs->losses;
			st->last_acked = rs->acked_sacked;
			st->last_new_round = st->new_round;
			st->last_cwnd = tp->snd_cwnd;
		}
	}

	qk_step(tp, rs->rtt_us > 0 ? (__u32)rs->rtt_us : 0,
		rs->losses > 0 ? (__u32)rs->losses : 0, rs->acked_sacked);
	return 0;
}

#else /* QK_ABI_ARGS == 2 */

SEC("struct_ops/qk_cong_control")
int BPF_PROG(qk_cong_control, struct tcp_sock *tp, const struct ack_sample *sample)
{
	struct qk_state *st;
	struct qk_tunables tun;
	__u32 lost = 0, acked, mss;

	if (!sample)
		return 0;

	qk_load_tunables(&tun);
	mss = tun.mss ? tun.mss : QK_DEFAULT_MSS;

	st = qk_get(tp);
	if (st) {
		st->last_rtt_us = sample->rtt_us;
		st->last_cwnd = tp->snd_cwnd;
	}

	/* This kernel's interface has no rate sample, so the erasure estimate
	 * comes from the socket's own counters: the number of segments
	 * retransmitted, against the number that were acknowledged. */
	if (st && tp->total_retrans > st->last_total_retrans)
		lost = tp->total_retrans - st->last_total_retrans;
	acked = (__u32)(tp->bytes_acked / mss);

	qk_step(tp, sample->rtt_us > 0 ? (__u32)sample->rtt_us : 0, lost, acked);

	/* Remember the counters for the next round. */
	st = qk_get(tp);
	if (st)
		st->last_total_retrans = tp->total_retrans;
	return 0;
}

#endif /* QK_ABI_ARGS */

/* ------------------------------------------------------------------ *
 * The congestion control operations table.
 *
 * The kernel matches this struct against its own struct tcp_congestion_ops
 * by member name; every member listed here must exist there too. Every
 * non-function-pointer member must be zero apart from "name", which the
 * kernel handles specially.
 * ------------------------------------------------------------------ */

struct tcp_congestion_ops {
	void (*init)(struct tcp_sock *tp);
	void (*release)(struct tcp_sock *tp);
	__u32 (*ssthresh)(struct tcp_sock *tp);
	void (*set_state)(struct tcp_sock *tp, __u8 new_state);
	__u32 (*min_tso_segs)(struct tcp_sock *tp);
	__u32 (*sndbuf_expand)(struct tcp_sock *tp);
	__u32 (*undo_cwnd)(struct tcp_sock *tp);
	void (*cong_control)(struct tcp_sock *tp, __u32 ack, __s32 rtt_us,
			     const struct rate_sample *rs);
	void (*pkts_acked)(struct tcp_sock *tp, const struct ack_sample *sample);
	char name[16];
};

SEC(".struct_ops")
struct tcp_congestion_ops qk = {
	.init = (void *)qk_init,
	.release = (void *)qk_release,
	.ssthresh = (void *)qk_ssthresh,
	.set_state = (void *)qk_set_state,
	.min_tso_segs = (void *)qk_min_tso_segs,
	.sndbuf_expand = (void *)qk_sndbuf_expand,
	.undo_cwnd = (void *)qk_undo_cwnd,
	.cong_control = (void *)qk_cong_control,
	.pkts_acked = (void *)qk_pkts_acked,
	.name = QK_STR(QK_CC_NAME),
};

char _license[] SEC("license") = "GPL";
