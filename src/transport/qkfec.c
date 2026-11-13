// SPDX-License-Identifier: MIT
/*
 * qkfec — a multi-channel FEC transport.
 *
 * A prototype of the transport layer that the kernel-native congestion
 * control cannot replace: it sends the data as symbols over unreliable
 * datagrams, and repairs the erasures with forward error correction, so
 * that a loss does not turn into a stall.
 *
 * The idea the transport is built on is that the carrier accounts loss per
 * address. Several source addresses are then several independent erasure
 * channels, and a repair computed over the union of the channels can repair
 * a symbol that was lost on one of them using evidence from the others.
 *
 * The wire format is one datagram per symbol:
 *
 *     struct qkfec_hdr { u32 magic; u32 seq; u32 group; u32 mask; u8 kind; ... }
 *
 * kind 0 is a source symbol, and its mask names the symbol it carries.
 * kind 1 is a repair symbol, and its mask names the set of group symbols
 * that were XORed into it.
 *
 * A group is GROUP symbols. The sender emits the sources of a group and
 * then R repairs, each the XOR of a random subset of the group's symbols.
 * The receiver keeps a GF(2) basis per group and peels the rows that reduce
 * to a single symbol, so it emits symbols as soon as they are determined.
 *
 * This is a prototype, in userspace, for measuring what such a transport is
 * worth on a real path. It is not a finished transport: it has no
 * authentication, no congestion control of its own, and no protection
 * against a peer that sends the same sequence numbers twice.
 *
 * Build:  make            (in src/transport)
 * Use:    qkfec send fec <dst-ip> <port> <src-ip,...> <repairs> <file> [pps]
 *         qkfec recv <bind-ip> <port> <out-file> <seconds>
 */
//
// Hypothesis under test: on a path where loss is per-IP, N source addresses are
// N independent erasure channels. Then striping over them multiplies capacity,
// and a repair computed over the *union* of the channels can repair a symbol
// lost on one channel using evidence from the others.
//
// Wire format (one UDP datagram, HDRSZ + SYMSZ bytes):
//   struct hdr { u32 magic; u32 seq; u32 group; u32 mask; u8 kind; u8 pad[3]; }
//   kind 0 = source symbol  (mask = 1<<(seq%GROUP)), payload = the symbol
//   kind 1 = repair symbol  (mask = the set of group symbols XORed in)
//   kind 2 = duplicate      (payload = the symbol, delivered as-is)
//
// FEC mode: groups of GROUP symbols; the sender emits the sources plus R
// repairs per group (each a random subset XOR). The receiver keeps a GF(2)
// basis per group and, when the group's rank reaches GROUP, eliminates it once
// and recovers every symbol. Groups are emitted in order.
//
// DUP mode: every symbol is sent twice, on two different channels; the
// receiver takes the first copy. Overhead 100%, no coding, and it is the
// simplest thing a kernel datapath could do.
//
// Usage:
//   qkfec send fec <dst_ip> <port> <src0,src1,...> <repairs> <infile>
//   qkfec send dup <dst_ip> <port> <src0,src1,...> <0> <infile>
//   qkfec recv <bind_ip> <port> <outfile> <dur>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAGIC 0x514b4643u
#define SYMSZ 1184
#define HDRSZ 20
#define GROUP 32
#define MAXCH 8
#define NRING 8192

struct hdr {
	uint32_t magic, seq, group, mask;
	uint8_t kind, pad[3];
};

/* the header size is a wire constant: keep the struct and HDRSZ in lockstep */
_Static_assert(sizeof(struct hdr) == HDRSZ, "HDRSZ must match sizeof(struct hdr)");

struct basis {
	uint32_t row[GROUP];
	unsigned char val[GROUP][SYMSZ];
	unsigned char have[GROUP];
	int rank;
	int done;
};

/* forward elimination on insert: reduce against existing pivots */
static void basis_insert(struct basis *b, uint32_t mask, const unsigned char *val)
{
	unsigned char tmp[SYMSZ];
	memcpy(tmp, val, SYMSZ);
	for (int i = 0; i < GROUP; i++) {
		if (!((mask >> i) & 1))
			continue;
		if (b->have[i]) {
			for (int j = 0; j < SYMSZ; j++)
				tmp[j] ^= b->val[i][j];
			mask ^= b->row[i];
		} else {
			memcpy(b->val[i], tmp, SYMSZ);
			b->row[i] = mask;
			b->have[i] = 1;
			b->rank++;
			return;
		}
	}
}

/* full RREF once the group is fully ranked */
static int basis_solve(struct basis *b, unsigned char out[GROUP][SYMSZ])
{
	for (int i = 0; i < GROUP; i++) {
		if (!b->have[i])
			return -1;
	}
	for (int i = 0; i < GROUP; i++) {
		if (!(b->row[i] & (1u << i)))
			return -1;   /* not a pivot at i: the group is not solvable */
		for (int j = 0; j < GROUP; j++) {
			if (j == i || !b->have[j])
				continue;
			if (b->row[j] & (1u << i)) {
				b->row[j] ^= b->row[i];
				for (int k = 0; k < SYMSZ; k++)
					b->val[j][k] ^= b->val[i][k];
			}
		}
	}
	for (int i = 0; i < GROUP; i++)
		memcpy(out[i], b->val[i], SYMSZ);
	return 0;
}

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static uint32_t rng_state = 12345;
static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static double g_next;
static double g_pps;

static void pace(void)
{
	if (g_pps <= 0)
		return;
	double t = now();
	if (t < g_next) {
		double sl = g_next - t;
		if (sl > 0.002)
			usleep((useconds_t)(sl * 1e6));
	}
	g_next += 1.0 / g_pps;
}

static int mkchan(const char *src, const char *dst, int port)
{
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	int sb = 8 << 20;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
	struct sockaddr_in6 d = {0}, l = {0};
	d.sin6_family = AF_INET6;
	d.sin6_port = htons(port);
	inet_pton(AF_INET6, dst, &d.sin6_addr);
	l.sin6_family = AF_INET6;
	inet_pton(AF_INET6, src, &l.sin6_addr);
	if (bind(fd, (void *)&l, sizeof(l)) < 0) { perror("bind src"); exit(1); }
	if (connect(fd, (void *)&d, sizeof(d)) < 0) { perror("connect"); exit(1); }
	return fd;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;

	if (!strcmp(argv[1], "send")) {
		const char *mode = argv[2];
		const char *dstip = argv[3];
		int port = atoi(argv[4]);
		const char *srclist = argv[5];
		int repeats = atoi(argv[6]);
		const char *infile = argc > 7 ? argv[7] : "-";
		double pps = argc > 8 ? atof(argv[8]) : 0.0;   /* 0 = unpaced */

		char *sl = strdup(srclist), *srcs[MAXCH];
		int nch = 0;
		for (char *t = strtok(sl, ","); t && nch < MAXCH; t = strtok(NULL, ","))
			srcs[nch++] = t;
		int fd[MAXCH];
		for (int i = 0; i < nch; i++)
			fd[i] = mkchan(srcs[i], dstip, port);

		int in = strcmp(infile, "-") ? open(infile, O_RDONLY) : 0;
		if (in < 0) { perror("open in"); return 1; }

		unsigned char sym[SYMSZ], ring[GROUP][SYMSZ], acc[SYMSZ];
		char outbuf[HDRSZ + SYMSZ];
		uint32_t seq = 0;        /* datagram sequence (wire) */
		uint32_t gsym = 0;       /* symbol index (grouping)  */
		uint64_t nsym = 0, nrep = 0, bytes = 0, ndat = 0;
		double t0 = now();
		g_next = t0;
		g_pps = pps;

		for (;;) {
			ssize_t n = read(in, sym, SYMSZ);
			if (n <= 0)
				break;
			memset(sym + n, 0, SYMSZ - n);
			uint32_t group = gsym / GROUP;
			int idx = gsym % GROUP;

			if (!strcmp(mode, "dup")) {
				/* the same symbol on two different channels */
				struct hdr h = { .magic = MAGIC, .seq = seq,
						 .group = group, .mask = 1u << idx,
						 .kind = 2 };
				memcpy(outbuf, &h, HDRSZ);
				memcpy(outbuf + HDRSZ, sym, SYMSZ);
				pace();
				send(fd[0], outbuf, HDRSZ + SYMSZ, 0);
				if (nch > 1) {
					pace();
					send(fd[1], outbuf, HDRSZ + SYMSZ, 0);
				}
				ndat += (nch > 1) ? 2 : 1;
			} else {
				memcpy(ring[idx], sym, SYMSZ);
				struct hdr h = { .magic = MAGIC, .seq = seq,
						 .group = group, .mask = 1u << idx,
						 .kind = 0 };
				memcpy(outbuf, &h, HDRSZ);
				memcpy(outbuf + HDRSZ, sym, SYMSZ);
				pace();
				send(fd[seq % nch], outbuf, HDRSZ + SYMSZ, 0);
				ndat++;

				if (idx == GROUP - 1) {
					for (int r = 0; r < repeats; r++) {
						uint32_t mask = 0;
						memset(acc, 0, SYMSZ);
						int d = 2 + (rnd() % (GROUP / 2));
						for (int k = 0; k < d; k++) {
							int j = rnd() % GROUP;
							if (mask & (1u << j))
								continue;
							mask |= 1u << j;
							for (int z = 0; z < SYMSZ; z++)
								acc[z] ^= ring[j][z];
						}
						if (!mask)
							continue;
						struct hdr rh = { .magic = MAGIC,
								 .seq = seq,
								 .group = group,
								 .mask = mask,
								 .kind = 1 };
						memcpy(outbuf, &rh, HDRSZ);
						memcpy(outbuf + HDRSZ, acc, SYMSZ);
						pace();
						send(fd[(seq + r + 1) % nch], outbuf,
						     HDRSZ + SYMSZ, 0);
						nrep++;
						ndat++;
						seq++;
					}
				}
			}
			nsym++;
			bytes += n;
			seq++;
			gsym++;
		}
		double el = now() - t0;
		fprintf(stderr,
			"SEND mode=%s symbols=%llu repairs=%llu datagrams=%llu payload=%llu elapsed=%.2f "
			"wire_Mbit=%.2f payload_Mbit=%.2f overhead=%.1f%%\n",
			mode, (unsigned long long)nsym, (unsigned long long)nrep,
			(unsigned long long)ndat,
			(unsigned long long)bytes, el,
			ndat * (HDRSZ + SYMSZ) * 8 / el / 1e6,
			bytes * 8 / el / 1e6,
			100.0 * (ndat - nsym) / (nsym ? nsym : 1));
		return 0;
	}

	if (!strcmp(argv[1], "recv")) {
		const char *bindip = argv[2];
		int port = atoi(argv[3]);
		const char *outfile = argv[4];
		double dur = atof(argv[5]);

		int s = socket(AF_INET6, SOCK_DGRAM, 0);
		int one = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		int rb = 32 << 20;
		setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
		struct sockaddr_in6 la = {0};
		la.sin6_family = AF_INET6;
		la.sin6_port = htons(port);
		inet_pton(AF_INET6, bindip, &la.sin6_addr);
		if (bind(s, (void *)&la, sizeof(la)) < 0) { perror("bind"); return 1; }

		int out = strcmp(outfile, "-") ? open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644) : 1;
		if (out < 0) { perror("open out"); return 1; }

		struct basis *bs = calloc(4096, sizeof(struct basis));
		unsigned char (*solved)[GROUP][SYMSZ] = calloc(4096, sizeof(*solved));
		unsigned char *grpready = calloc(4096, 1);
		unsigned char *slots = calloc(NRING, 1);
		unsigned char (*slotval)[SYMSZ] = calloc(NRING, sizeof(*slotval));
		uint32_t next_seq = 0, highest = 0;
		uint64_t lost = 0;
		uint64_t got = 0, outbytes = 0, nsym_out = 0, nsolved = 0;

		char buf[HDRSZ + SYMSZ];
		double end = now() + dur;
		struct timeval tv = { .tv_sec = (int)dur + 3 };
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		while (now() < end) {
			ssize_t n = recv(s, buf, sizeof(buf), 0);
			if (n < 0)
				break;
			if (n != HDRSZ + SYMSZ)
				continue;
			struct hdr h;
			memcpy(&h, buf, HDRSZ);
			if (h.magic != MAGIC)
				continue;
			got++;
			if (h.kind == 2) {
				/* duplicate: first copy wins, emitted in seq order.
				 * A symbol the sender has moved past is lost; skip it
				 * rather than stalling the whole stream on it. */
				uint32_t sl = h.seq % NRING;
				if (!slots[sl]) {
					slots[sl] = 1;
					memcpy(slotval[sl], buf + HDRSZ, SYMSZ);
				}
				if (h.seq > highest)
					highest = h.seq;
				while (next_seq < highest) {
					uint32_t k = next_seq % NRING;
					if (slots[k]) {
						if (write(out, slotval[k], SYMSZ) < 0)
							break;
						slots[k] = 0;
						outbytes += SYMSZ;
						nsym_out++;
						next_seq++;
					} else if (highest - next_seq >= NRING) {
						next_seq++;   /* definitively lost */
						lost++;
					} else {
						break;
					}
				}
				continue;
			}
			if (h.group >= 4096)
				continue;
			struct basis *b = &bs[h.group];
			basis_insert(b, h.mask, (unsigned char *)buf + HDRSZ);
			if (b->rank == GROUP && !grpready[h.group]) {
				if (basis_solve(b, solved[h.group]) == 0) {
					grpready[h.group] = 1;
					nsolved++;
					for (int i = 0; i < GROUP; i++) {
						if (write(out, solved[h.group][i], SYMSZ) < 0)
							break;
						outbytes += SYMSZ;
						nsym_out++;
					}
				}
			}
		}
		/* flush the tail */
		for (uint32_t k = 0; k < NRING; k++) {
			if (slots[k]) {
				if (write(out, slotval[k], SYMSZ) < 0)
					break;
				outbytes += SYMSZ;
				nsym_out++;
				slots[k] = 0;
			}
		}
		fprintf(stderr,
			"RECV datagrams=%llu groups_solved=%llu symbols_out=%llu lost=%llu "
			"payload_Mbit=%.2f\n",
			(unsigned long long)got, (unsigned long long)nsolved,
			(unsigned long long)nsym_out, (unsigned long long)lost,
			outbytes * 8 / dur / 1e6);
		return 0;
	}
	return 1;
}
