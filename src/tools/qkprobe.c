// SPDX-License-Identifier: GPL-2.0
/*
 * qkprobe — an open-loop UDP probe.
 *
 * "Open loop" means the sender decides its own rate and never waits for
 * feedback.  That matters: a closed-loop measurement (TCP, for instance)
 * reports how the congestion control reacted to loss rather than how the
 * path itself behaves.
 *
 * The probe answers the question that decides the architecture of a
 * multi-path transport: does the carrier treat loss as *per source address*
 * (so several addresses give several independent erasure channels) or as one
 * shared bottleneck (so several addresses give no extra capacity at all)?
 *
 * To answer it you need, per source address:
 *
 *   - the loss rate             (gaps / highest sequence)
 *   - the delivered rate        (packets and bytes per second)
 *
 * and then the same three numbers with several source addresses running at
 * once.  If the aggregate scales with the number of addresses, the carrier
 * accounts loss per IP; if it does not, the bottleneck is shared.
 *
 * Every datagram starts with a fixed magic and a 32 bit sequence number, so
 * the receiver can validate it and spot holes.
 *
 * The machine readable summary goes to stdout, everything else to stderr:
 *
 *   RESULT role=send src=fd00::20 packets=60000 bytes=72000000 elapsed=12.00 rate=5000
 *   RESULT role=recv count=58100 bytes=69720000 last_seq=58199 gaps=1900
 *
 * Build:
 *
 *   cc -std=c11 -O2 -Wall -Wextra -g qkprobe.c -o qkprobe
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define QKPROBE_PROG "qkprobe"

/* "QKPP" in ASCII, little endian on the wire. */
#define QKPROBE_MAGIC 0x50504B51u

#define QKPROBE_HDR_LEN 8u

/* Defaults.  Every address, port and rate can be overridden on the
 * command line; nothing is hard coded. */
#define DEF_RATE_PPS	1000.0
#define DEF_SIZE_BYTES	1200
#define DEF_DURATION_S	10.0
#define DEF_RCVBUF_BYTES	(16u << 20)

#define MAX_PAYLOAD	65507u

static const char *progname = QKPROBE_PROG;
static volatile sig_atomic_t g_stop = 0;

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* ------------------------------------------------------------------ */
/* Time helpers                                                       */
/* ------------------------------------------------------------------ */

static double now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void sleep_until(const struct timespec *abs)
{
	int rc;

	do {
		rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, abs, NULL);
	} while (rc == EINTR && !g_stop);
}

/* ------------------------------------------------------------------ */
/* Reproducible PRNG (xoshiro256** seeded through splitmix64)         */
/* ------------------------------------------------------------------ */

struct rng {
	uint64_t s[4];
};

static uint64_t splitmix64(uint64_t *x)
{
	uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);

	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static uint64_t rotl64(uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static void rng_seed(struct rng *r, uint64_t seed)
{
	uint64_t x = seed;

	for (int i = 0; i < 4; i++)
		r->s[i] = splitmix64(&x);
	/* xoshiro requires a non-zero state */
	if (!(r->s[0] | r->s[1] | r->s[2] | r->s[3]))
		r->s[0] = 0x9E3779B97F4A7C15ULL;
}

static uint64_t rng_next(struct rng *r)
{
	uint64_t *s = r->s;
	uint64_t result = rotl64(s[1] * 5, 7) * 9;
	uint64_t t = s[1] << 17;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];
	s[2] ^= t;
	s[3] = rotl64(s[3], 45);
	return result;
}

static void rng_fill(struct rng *r, unsigned char *buf, size_t len)
{
	size_t i = 0;

	while (i + 8 <= len) {
		uint64_t v = rng_next(r);

		memcpy(buf + i, &v, 8);
		i += 8;
	}
	if (i < len) {
		uint64_t v = rng_next(r);

		memcpy(buf + i, &v, len - i);
	}
}

/* ------------------------------------------------------------------ */
/* Option parsing                                                     */
/* ------------------------------------------------------------------ */

struct options {
	const char *bind_addr;		/* recv: address to bind to        */
	const char *src_addr;		/* send: local source address      */
	const char *dst_addr;		/* send: destination address       */
	const char *port;		/* recv: listen port, send: dport  */
	double rate;			/* packets per second              */
	size_t size;			/* payload size in bytes           */
	double duration;		/* seconds                         */
	uint64_t seed;			/* PRNG seed                       */
	size_t bufbytes;		/* socket buffer size              */
};

static void usage(FILE *out)
{
	fprintf(out,
"Usage:\n"
"  %s recv --bind <ip> --port <n> [--duration <s>] [--bufbytes <n>]\n"
"      Listen on <ip>:<n>, count datagrams and report sequence gaps.\n"
"\n"
"  %s send --src <ip> --dst <ip> --port <n> [--rate <pps>] [--size <bytes>]\n"
"             [--duration <s>] [--seed <n>]\n"
"      Bind to <ip>, send numbered datagrams to <ip>:<n> at <pps>.\n"
"\n"
"Options:\n"
"  --rate <pps>        send rate in packets per second   (default %g)\n"
"  --size <bytes>      payload size in bytes              (default %d)\n"
"  --duration <s>      how long to run, in seconds        (default %g)\n"
"  --seed <n>          PRNG seed for the payload          (default 0)\n"
"  --bufbytes <n>      socket buffer size in bytes        (default %u)\n"
"\n"
"Addresses may be IPv4 or IPv6.  The machine readable summary line is\n"
"printed on stdout, human readable output goes to stderr.\n",
		progname, progname, DEF_RATE_PPS, DEF_SIZE_BYTES, DEF_DURATION_S,
		DEF_RCVBUF_BYTES);
}

static const char *need_value(int argc, char **argv, int *i, const char *opt)
{
	if (*i + 1 >= argc)
		die("option %s needs a value", opt);
	(*i)++;
	return argv[*i];
}

static void parse_args(int argc, char **argv, int start, struct options *o)
{
	int i;

	for (i = start; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "--bind"))
			o->bind_addr = need_value(argc, argv, &i, a);
		else if (!strcmp(a, "--src"))
			o->src_addr = need_value(argc, argv, &i, a);
		else if (!strcmp(a, "--dst"))
			o->dst_addr = need_value(argc, argv, &i, a);
		else if (!strcmp(a, "--port"))
			o->port = need_value(argc, argv, &i, a);
		else if (!strcmp(a, "--rate"))
			o->rate = strtod(need_value(argc, argv, &i, a), NULL);
		else if (!strcmp(a, "--size"))
			o->size = (size_t)strtoul(need_value(argc, argv, &i, a),
						  NULL, 10);
		else if (!strcmp(a, "--duration"))
			o->duration = strtod(need_value(argc, argv, &i, a), NULL);
		else if (!strcmp(a, "--seed"))
			o->seed = strtoull(need_value(argc, argv, &i, a), NULL, 10);
		else if (!strcmp(a, "--bufbytes"))
			o->bufbytes = (size_t)strtoul(need_value(argc, argv, &i, a),
						      NULL, 10);
		else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(stdout);
			exit(0);
		} else {
			die("unknown option: %s", a);
		}
	}
}

/* ------------------------------------------------------------------ */
/* Socket helpers                                                     */
/* ------------------------------------------------------------------ */

static int resolve_udp(const char *host, const char *port,
		       struct sockaddr_storage *out, socklen_t *outlen)
{
	struct addrinfo hints, *res = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo(host, port, &hints, &res);
	if (rc != 0 || !res) {
		fprintf(stderr, "%s: cannot resolve %s:%s: %s\n", progname,
			host ? host : "(null)", port ? port : "(null)",
			gai_strerror(rc));
		return -1;
	}
	memcpy(out, res->ai_addr, res->ai_addrlen);
	*outlen = res->ai_addrlen;
	freeaddrinfo(res);
	return 0;
}

static void print_addr(const char *label, const struct sockaddr *sa)
{
	char host[INET6_ADDRSTRLEN] = "?";
	char serv[32] = "?";

	getnameinfo(sa, sa->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
						 : sizeof(struct sockaddr_in),
		    host, sizeof(host), serv, sizeof(serv),
		    NI_NUMERICHOST | NI_NUMERICSERV);
	fprintf(stderr, "  %-10s %s:%s\n", label, host, serv);
}

/* ------------------------------------------------------------------ */
/* Sender                                                             */
/* ------------------------------------------------------------------ */

static int run_send(struct options *o)
{
	struct sockaddr_storage dst, src;
	socklen_t dstlen = 0, srclen = 0;
	unsigned char *buf;
	struct rng rng;
	struct timespec start, deadline;
	uint64_t packets = 0, bytes = 0, errors = 0, err_reported = 0;
	uint64_t tick = 0;
	uint32_t seq = 0, magic = 0;
	uint64_t interval_ns;
	double elapsed, t0;
	int fd, rc;

	if (!o->src_addr || !o->dst_addr || !o->port)
		die("send needs --src, --dst and --port");
	if (o->rate <= 0.0)
		die("--rate must be positive");
	if (o->size < QKPROBE_HDR_LEN)
		die("--size must be at least %u bytes", QKPROBE_HDR_LEN);
	if (o->size > MAX_PAYLOAD)
		die("--size must be at most %u bytes", MAX_PAYLOAD);
	if (o->duration <= 0.0)
		die("--duration must be positive");

	interval_ns = (uint64_t)(1e9 / o->rate);
	if (interval_ns == 0)
		interval_ns = 1;

	if (resolve_udp(o->dst_addr, o->port, &dst, &dstlen) < 0)
		return 1;
	if (resolve_udp(o->src_addr, "0", &src, &srclen) < 0)
		return 1;

	fd = socket(dst.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		die("socket: %s", strerror(errno));

	{
		int v = (int)o->bufbytes;

		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)) < 0)
			fprintf(stderr, "%s: warning: SO_SNDBUF: %s\n", progname,
				strerror(errno));
	}

	if (bind(fd, (struct sockaddr *)&src, srclen) < 0)
		die("bind to %s failed: %s", o->src_addr, strerror(errno));
	if (connect(fd, (struct sockaddr *)&dst, dstlen) < 0)
		die("connect to %s:%s failed: %s", o->dst_addr, o->port,
		    strerror(errno));

	rng_seed(&rng, o->seed);
	buf = malloc(o->size);
	if (!buf)
		die("out of memory");

	clock_gettime(CLOCK_MONOTONIC, &start);
	deadline = start;
	deadline.tv_sec += (time_t)o->duration;
	deadline.tv_nsec += (long)((o->duration - (double)(time_t)o->duration)
				   * 1e9);
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	fprintf(stderr, "qkprobe send\n");
	print_addr("source", (struct sockaddr *)&src);
	print_addr("dest", (struct sockaddr *)&dst);
	fprintf(stderr, "  %-10s %zu bytes, %.0f pps, %.2f s, seed %llu\n",
		"payload", o->size, o->rate, o->duration,
		(unsigned long long)o->seed);
	fflush(stderr);

	t0 = now_sec();
	for (;;) {
		struct timespec due;

		if (g_stop)
			break;
		if (clock_gettime(CLOCK_MONOTONIC, &due) >= 0 &&
		    (due.tv_sec > deadline.tv_sec ||
		     (due.tv_sec == deadline.tv_sec &&
		      due.tv_nsec >= deadline.tv_nsec)))
			break;

		/* absolute schedule: no drift, no catch-up burst */
		due = start;
		due.tv_sec += (time_t)(tick * interval_ns / 1000000000ULL);
		due.tv_nsec += (long)(tick * interval_ns % 1000000000ULL);
		if (due.tv_nsec >= 1000000000L) {
			due.tv_sec++;
			due.tv_nsec -= 1000000000L;
		}
		tick++;
		sleep_until(&due);

		/* magic + sequence number, then pseudo random filler */
		magic = QKPROBE_MAGIC;
		memcpy(buf, &magic, sizeof(magic));
		memcpy(buf + 4, &seq, sizeof(seq));
		rng_fill(&rng, buf + QKPROBE_HDR_LEN, o->size - QKPROBE_HDR_LEN);

		do {
			rc = (int)send(fd, buf, o->size, 0);
		} while (rc < 0 && errno == EINTR);
		if (rc < 0) {
			/*
			 * A connected UDP socket reports ICMP errors on the
			 * next send, so a single failure does not mean the
			 * path is gone.  Keep going and count them.
			 */
			errors++;
			if (err_reported < 5) {
				err_reported++;
				fprintf(stderr, "%s: send: %s\n", progname,
					strerror(errno));
			}
			continue;
		}
		packets++;
		bytes += (uint64_t)rc;
		seq++;
	}
	elapsed = now_sec() - t0;

	fprintf(stderr,
		"  sent %llu packets, %llu bytes in %.2f s (%.0f pps)\n",
		(unsigned long long)packets, (unsigned long long)bytes,
		elapsed, elapsed > 0 ? (double)packets / elapsed : 0.0);
	if (errors)
		fprintf(stderr, "  %llu send errors\n",
			(unsigned long long)errors);

	printf("RESULT role=send src=%s packets=%llu bytes=%llu elapsed=%.2f rate=%.0f\n",
	       o->src_addr, (unsigned long long)packets,
	       (unsigned long long)bytes, elapsed,
	       elapsed > 0 ? (double)packets / elapsed : 0.0);
	fflush(stdout);

	free(buf);
	close(fd);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Receiver                                                           */
/* ------------------------------------------------------------------ */

static int run_recv(struct options *o)
{
	struct sockaddr_storage local;
	socklen_t locallen = 0;
	unsigned char *buf;
	uint64_t count = 0, bytes = 0, gaps = 0, dups = 0, bad = 0;
	uint32_t last_seq = 0;
	bool have_last = false;
	double deadline, t0;
	int fd;

	if (!o->bind_addr || !o->port)
		die("recv needs --bind and --port");
	if (o->duration <= 0.0)
		die("--duration must be positive");
	if (o->bufbytes < QKPROBE_HDR_LEN)
		die("--bufbytes must be at least %u", QKPROBE_HDR_LEN);

	if (resolve_udp(o->bind_addr, o->port, &local, &locallen) < 0)
		return 1;

	fd = socket(local.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		die("socket: %s", strerror(errno));

	{
		int v = 1;

		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	}
	{
		int v = (int)o->bufbytes;

		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)) < 0)
			fprintf(stderr, "%s: warning: SO_RCVBUF: %s\n", progname,
				strerror(errno));
	}

	if (bind(fd, (struct sockaddr *)&local, locallen) < 0)
		die("bind to %s:%s failed: %s", o->bind_addr, o->port,
		    strerror(errno));

	buf = malloc(o->bufbytes);
	if (!buf)
		die("out of memory");

	fprintf(stderr, "qkprobe recv\n");
	print_addr("listen", (struct sockaddr *)&local);
	fprintf(stderr, "  %-10s %.2f s, buffer %zu bytes\n", "window",
		o->duration, o->bufbytes);
	fflush(stderr);

	t0 = now_sec();
	deadline = t0 + o->duration;

	while (!g_stop && now_sec() < deadline) {
		struct pollfd pfd;
		ssize_t n;
		uint32_t magic = 0, seq = 0;
		int rc;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		rc = poll(&pfd, 1, 100);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "%s: poll: %s\n", progname,
				strerror(errno));
			break;
		}
		if (rc == 0)
			continue;

		n = recv(fd, buf, o->bufbytes, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "%s: recv: %s\n", progname,
				strerror(errno));
			break;
		}
		if ((size_t)n < QKPROBE_HDR_LEN)
			continue;

		memcpy(&magic, buf, sizeof(magic));
		memcpy(&seq, buf + 4, sizeof(seq));
		if (magic != QKPROBE_MAGIC) {
			bad++;
			continue;
		}

		count++;
		bytes += (uint64_t)n;

		if (!have_last) {
			have_last = true;
			last_seq = seq;
			if (seq > 0)
				gaps += seq;	/* the head of the run was lost */
			continue;
		}
		if (seq > last_seq) {
			gaps += (uint64_t)(seq - last_seq - 1);
			last_seq = seq;
		} else {
			dups++;
		}
	}
	{
		double elapsed = now_sec() - t0;

		fprintf(stderr,
			"  received %llu datagrams, %llu bytes in %.2f s\n",
			(unsigned long long)count, (unsigned long long)bytes,
			elapsed);
		fprintf(stderr,
			"  highest sequence %u, %llu gaps, %llu duplicates, %llu rejected\n",
			last_seq, (unsigned long long)gaps,
			(unsigned long long)dups, (unsigned long long)bad);
		if (have_last && last_seq + 1 > 0) {
			double loss = 100.0 * (double)gaps /
				      (double)(last_seq + 1);

			fprintf(stderr, "  loss %.2f%%, delivery %.0f pps\n",
				loss, elapsed > 0 ? (double)count / elapsed : 0.0);
		}
	}

	printf("RESULT role=recv count=%llu bytes=%llu last_seq=%u gaps=%llu\n",
	       (unsigned long long)count, (unsigned long long)bytes, last_seq,
	       (unsigned long long)gaps);
	fflush(stdout);

	free(buf);
	close(fd);
	return 0;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	struct options o;
	const char *mode;

	memset(&o, 0, sizeof(o));
	o.rate = DEF_RATE_PPS;
	o.size = DEF_SIZE_BYTES;
	o.duration = DEF_DURATION_S;
	o.seed = 0;
	o.bufbytes = DEF_RCVBUF_BYTES;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	mode = argv[1];

	if (!strcmp(mode, "-h") || !strcmp(mode, "--help") || !strcmp(mode, "help")) {
		usage(stdout);
		return 0;
	}
	if (strcmp(mode, "send") && strcmp(mode, "recv")) {
		fprintf(stderr, "%s: unknown mode: %s\n", progname, mode);
		usage(stderr);
		return 2;
	}

	parse_args(argc, argv, 2, &o);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	if (!strcmp(mode, "send"))
		return run_send(&o);
	return run_recv(&o);
}
