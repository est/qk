/*
 * tcperf - a small TCP throughput probe for comparing Linux congestion
 *          control algorithms over a controlled (netem) path.
 *
 * WHAT IT DOES
 *   "tcperf server" accepts a connection and reads until EOF.
 *   "tcperf client" connects, streams data for a fixed duration and then
 *   shuts down its write side so the server observes EOF.
 *
 *   The client selects the congestion control *per socket* with
 *   setsockopt(IPPROTO_TCP, TCP_CONGESTION) before connect().  The requested
 *   algorithm is checked against
 *   /proc/sys/net/ipv4/tcp_available_congestion_control first; if it is not
 *   registered the tool fails loudly instead of silently falling back to the
 *   kernel default (a silent fallback would make the comparison meaningless).
 *   Note that a non "reno"/"cubic" algorithm (e.g. a BPF registered one such
 *   as "qk") requires CAP_NET_ADMIN in the network namespace of the socket.
 *
 * HOW TO BUILD
 *   Linux only (uses Linux UAPI headers):
 *       make
 *       cc -std=c11 -O2 -Wall -Wextra -g -o tcperf tcperf.c
 *
 * HOW TO RUN
 *   tcperf client --dst <ip> --port <n> [--cc <name>] [--duration <s>]
 *                  [--write-size <bytes>] [--connect-timeout <s>]
 *                  [--so-sndbuf <bytes>] [--bind <ip>] [--quiet]
 *   tcperf server --bind <ip> --port <n> [--duration <s>]
 *                  [--so-rcvbuf <bytes>] [--accept <n>] [--quiet]
 *
 * OUTPUT
 *   Exactly one machine readable summary line is printed on stdout:
 *
 *     RESULT role=client cc=cubic bytes=1234567 elapsed=12.34 mbit=8.21 \
 *            cwnd=42 ssthresh=100 rtt_us=200000 retrans=17 pacing=9000000
 *
 *   Human readable progress information goes to stderr (suppressed by
 *   --quiet).  Fields that the kernel does not provide are omitted, the
 *   key=value format never changes.  SIGINT/SIGTERM stop the transfer early
 *   and still produce a RESULT line.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/tcp.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* <linux/tcp.h> provides TCP_INFO/TCP_CONGESTION and the full struct
 * tcp_info including tcpi_pacing_rate (glibc's <netinet/tcp.h> stops at
 * tcpi_total_retrans).  Keep the two headers apart: including both
 * <netinet/tcp.h> and <linux/tcp.h> would redefine struct tcp_info. */
#ifndef TCP_INFO
#define TCP_INFO 11
#endif
#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif

#define TCP_CC_PROC "/proc/sys/net/ipv4/tcp_available_congestion_control"

#define DEFAULT_DURATION        10.0
#define DEFAULT_WRITE_SIZE      65536u
#define DEFAULT_CONNECT_TIMEOUT 5.0
#define DEFAULT_SNDBUF          65536
#define DEFAULT_RCVBUF          65536

/* The kernel may hand back more bytes than our headers know about; ask for
 * a buffer that is comfortably larger than any published struct tcp_info. */
#define TCP_INFO_BUFSZ 512

/* How long the server waits for further connections after the last one was
 * closed (only relevant when more than one connection is accepted). */
#define ACCEPT_GRACE_SEC 2.0

static volatile sig_atomic_t g_stop;
static bool g_quiet;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void note(const char *fmt, ...)
{
    va_list ap;

    if (g_quiet)
        return;

    va_start(ap, fmt);
    fputs("tcperf: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fputs("tcperf: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static double now_sec(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0.0;
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ------------------------------------------------------------------ */
/* small key=value result buffer                                       */
/* ------------------------------------------------------------------ */

struct kv {
    char buf[1024];
    size_t len;
};

static void kv_addf(struct kv *k, const char *fmt, ...)
{
    va_list ap;
    int n;
    size_t space;

    if (k->len + 1 >= sizeof(k->buf))
        return;

    va_start(ap, fmt);
    n = vsnprintf(k->buf + k->len, sizeof(k->buf) - k->len, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;

    space = sizeof(k->buf) - k->len - 1;
    if ((size_t)n > space)
        n = (int)space;
    k->len += (size_t)n;
}

/* ------------------------------------------------------------------ */
/* congestion control helpers                                          */
/* ------------------------------------------------------------------ */

/* Read the list of congestion control algorithms registered in the current
 * network namespace.  Returns a malloc()ed string or NULL. */
static char *read_cc_list(void)
{
    FILE *f;
    char buf[4096];
    size_t n;
    char *s;
    size_t end;

    f = fopen(TCP_CC_PROC, "r");
    if (!f)
        return NULL;

    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    end = strlen(buf);
    while (end > 0 && (buf[end - 1] == '\n' || buf[end - 1] == '\r' ||
                       buf[end - 1] == ' ' || buf[end - 1] == '\t'))
        buf[--end] = '\0';

    s = strdup(buf);
    if (!s)
        die("out of memory");
    return s;
}

/* Read the default congestion control algorithm of the namespace.  Returns a
 * malloc()ed string or NULL. */
static char *read_default_cc(void)
{
    FILE *f;
    char buf[256];
    size_t n;
    char *s;
    size_t end;

    f = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "r");
    if (!f)
        return NULL;

    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    end = strlen(buf);
    while (end > 0 && (buf[end - 1] == '\n' || buf[end - 1] == '\r' ||
                       buf[end - 1] == ' ' || buf[end - 1] == '\t'))
        buf[--end] = '\0';

    s = strdup(buf);
    if (!s)
        die("out of memory");
    return s;
}

/* True if `name` is one of the whitespace separated tokens in `list`. */
static bool cc_in_list(const char *list, const char *name)
{
    const char *p = list;
    size_t nlen = strlen(name);

    while (*p) {
        const char *start;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (!*p)
            break;
        start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            p++;
        if ((size_t)(p - start) == nlen && strncmp(start, name, nlen) == 0)
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* socket helpers                                                      */
/* ------------------------------------------------------------------ */

static int addr_family(const char *ip)
{
    return (ip && strchr(ip, ':')) ? AF_INET6 : AF_INET;
}

static int fill_addr(int family, const char *ip, int port,
                     struct sockaddr_storage *ss, socklen_t *slen)
{
    memset(ss, 0, sizeof(*ss));

    if (family == AF_INET6) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;

        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, ip, &sa->sin6_addr) != 1) {
            errno = EINVAL;
            return -1;
        }
        *slen = sizeof(*sa);
    } else {
        struct sockaddr_in *sa = (struct sockaddr_in *)ss;

        sa->sin_family = AF_INET;
        sa->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &sa->sin_addr) != 1) {
            errno = EINVAL;
            return -1;
        }
        *slen = sizeof(*sa);
    }
    return 0;
}

/* connect() with a timeout, using a non blocking socket internally. */
static int connect_with_timeout(int fd, const struct sockaddr *sa,
                                socklen_t salen, double timeout_s)
{
    struct pollfd pfd;
    int flags;
    int rc;
    int err = 0;
    socklen_t elen = sizeof(err);
    int saved;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    rc = connect(fd, sa, salen);
    if (rc == 0) {
        if (fcntl(fd, F_SETFL, flags) < 0)
            return -1;
        return 0;
    }
    if (errno != EINPROGRESS) {
        saved = errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved;
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    rc = poll(&pfd, 1, (int)(timeout_s * 1000.0));
    if (rc < 0) {
        saved = errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved;
        return -1;
    }
    if (rc == 0) {
        (void)fcntl(fd, F_SETFL, flags);
        errno = ETIMEDOUT;
        return -1;
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) {
        saved = errno;
        (void)fcntl(fd, F_SETFL, flags);
        errno = saved;
        return -1;
    }
    if (err != 0) {
        (void)fcntl(fd, F_SETFL, flags);
        errno = err;
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags) < 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* option parsing                                                      */
/* ------------------------------------------------------------------ */

struct options {
    const char *dst;
    const char *bind_addr;
    const char *cc;
    int port;
    double duration;
    double connect_timeout;
    size_t write_size;
    long so_sndbuf;
    long so_rcvbuf;
    int accept_max;
};

static void usage(FILE *out)
{
    fprintf(out,
"usage:\n"
"  tcperf client --dst <ip> --port <n> [--cc <name>] [--duration <s>]\n"
"                [--write-size <bytes>] [--connect-timeout <s>]\n"
"                [--so-sndbuf <bytes>] [--bind <ip>] [--quiet]\n"
"  tcperf server --bind <ip> --port <n> [--duration <s>]\n"
"                [--so-rcvbuf <bytes>] [--accept <n>] [--quiet]\n"
"\n"
"options:\n"
"  --cc <name>            congestion control to request for this socket; the\n"
"                         name must appear in " TCP_CC_PROC "\n"
"  --bind <ip>            optional local source address (client)\n"
"  --duration <s>         how long to transfer (default %.0f)\n"
"  --write-size <bytes>   bytes per write() call (default %u)\n"
"  --connect-timeout <s>  connect timeout in seconds (default %.0f)\n"
"  --so-sndbuf <bytes>    SO_SNDBUF (default %d)\n"
"  --so-rcvbuf <bytes>    SO_RCVBUF (default %d)\n"
"  --accept <n>           how many connections the server accepts (default 1)\n"
"  --quiet                only print the RESULT line\n"
"  -h, --help             this help\n",
            DEFAULT_DURATION, DEFAULT_WRITE_SIZE, DEFAULT_CONNECT_TIMEOUT,
            DEFAULT_SNDBUF, DEFAULT_RCVBUF);
}

static bool arg_is(const char *arg, const char *name)
{
    return strcmp(arg, name) == 0;
}

/* Fetch the value of an option that was given as "--opt value".  Dies when
 * the option is the last argument on the command line. */
static const char *next_value(int argc, char **argv, int *i, const char *opt)
{
    if (*i + 1 >= argc)
        die("%s requires a value", opt);
    (*i)++;
    return argv[*i];
}

static double parse_double(const char *s, const char *what)
{
    char *end = NULL;
    double v;

    errno = 0;
    v = strtod(s, &end);
    if (errno != 0 || !end || *end != '\0' || v < 0 || !isfinite(v))
        die("invalid value for %s: '%s'", what, s);
    return v;
}

static long parse_long(const char *s, const char *what)
{
    char *end = NULL;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v <= 0)
        die("invalid value for %s: '%s'", what, s);
    return v;
}

/* ------------------------------------------------------------------ */
/* client                                                              */
/* ------------------------------------------------------------------ */

static int run_client(const struct options *o)
{
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    int family = addr_family(o->dst);
    int fd;
    char *cclist = NULL;
    char *ccname = NULL;
    char *buf = NULL;
    uint64_t total = 0;
    double t0;
    double elapsed;
    double mbit;
    struct tcp_info ti;
    socklen_t tilen = 0;
    bool have_info = false;
    struct kv kv;

    if (!o->dst)
        die("client mode requires --dst");
    if (o->port <= 0 || o->port > 65535)
        die("client mode requires a valid --port");

    /* --- sanity check the requested algorithm ------------------------ */
    if (o->cc) {
        cclist = read_cc_list();
        if (cclist && !cc_in_list(cclist, o->cc)) {
            fprintf(stderr, "tcperf: congestion control '%s' is not available in this network namespace.\n",
                    o->cc);
            fprintf(stderr, "tcperf: available: %s\n", cclist);
            fprintf(stderr, "tcperf: (list read from %s)\n", TCP_CC_PROC);
            free(cclist);
            return 2;
        }
        if (!cclist)
            note("warning: %s could not be read, skipping availability check",
                 TCP_CC_PROC);
        else
            note("congestion control '%s' is available", o->cc);
        ccname = strdup(o->cc);
        if (!ccname)
            die("out of memory");
    } else {
        ccname = read_default_cc();
        note("no --cc given, using the kernel default congestion control");
        if (ccname)
            note("default congestion control is '%s'", ccname);
    }

    fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0)
        die("socket: %s", strerror(errno));

    /* Modest send buffer: the client must be rate limited by the path, not
     * by its own socket buffer. */
    if (o->so_sndbuf > 0) {
        int v = (int)o->so_sndbuf;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)) < 0)
            note("warning: SO_SNDBUF: %s", strerror(errno));
    }

    if (o->bind_addr) {
        struct sockaddr_storage bss;
        socklen_t blen = 0;

        if (fill_addr(addr_family(o->bind_addr), o->bind_addr, 0, &bss, &blen) < 0)
            die("invalid --bind address '%s'", o->bind_addr);
        if (bind(fd, (struct sockaddr *)&bss, blen) < 0)
            die("bind(%s): %s", o->bind_addr, strerror(errno));
    }

    /* Congestion control is selected per socket and must be set before the
     * connection is established. */
    if (o->cc) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, o->cc, strlen(o->cc) + 1) < 0)
            die("setsockopt(TCP_CONGESTION, \"%s\"): %s", o->cc, strerror(errno));
    }

    if (fill_addr(family, o->dst, o->port, &ss, &slen) < 0)
        die("invalid --dst address '%s'", o->dst);

    t0 = now_sec();
    if (connect_with_timeout(fd, (struct sockaddr *)&ss, slen, o->connect_timeout) < 0)
        die("connect(%s:%d): %s", o->dst, o->port, strerror(errno));
    note("connected to %s:%d in %.3fs", o->dst, o->port, now_sec() - t0);

    /* Bound the time a single write() may block, so that the transfer ends
     * close to the requested duration even on a stalled path. */
    {
        struct timeval sndtimeo;

        sndtimeo.tv_sec = 2;
        sndtimeo.tv_usec = 0;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo, sizeof(sndtimeo)) < 0)
            note("warning: SO_SNDTIMEO: %s", strerror(errno));
    }

    buf = malloc(o->write_size);
    if (!buf)
        die("out of memory");
    memset(buf, 'x', o->write_size);

    /* --- transfer ---------------------------------------------------- */
    /* The socket is switched to non blocking mode for the transfer: a very
     * slow congestion control (low pacing rate) can block a single write()
     * for far longer than the requested duration, which would make the
     * measurement meaningless.  poll() is used to wait for room in the send
     * buffer instead, always bounded by the deadline. */
    {
        int flags = fcntl(fd, F_GETFL, 0);

        if (flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
            note("warning: O_NONBLOCK: %s", strerror(errno));
    }

    t0 = now_sec();
    {
        double deadline = t0 + o->duration;

        while (!g_stop) {
            size_t off = 0;
            bool failed = false;

            if (now_sec() >= deadline)
                break;

            while (off < o->write_size) {
                ssize_t n;

                /* The deadline is checked inside the chunk as well. */
                if (g_stop || now_sec() >= deadline)
                    break;

                n = write(fd, buf + off, o->write_size - off);

                if (n > 0) {
                    off += (size_t)n;
                    total += (uint64_t)n;
                    continue;
                }
                if (n < 0 && errno == EINTR) {
                    if (g_stop)
                        break;
                    continue;
                }
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    struct pollfd pfd;
                    double left = deadline - now_sec();
                    int ms;

                    if (left <= 0.0)
                        break;
                    ms = (left > 0.2) ? 200 : (int)(left * 1000.0);
                    pfd.fd = fd;
                    pfd.events = POLLOUT;
                    pfd.revents = 0;
                    (void)poll(&pfd, 1, ms);
                    continue;
                }
                if (n < 0)
                    note("write: %s", strerror(errno));
                else
                    note("write returned 0");
                failed = true;
                break;
            }
            if (failed)
                break;
        }
    }

    elapsed = now_sec() - t0;
    mbit = (elapsed > 0.0) ? ((double)total * 8.0 / elapsed / 1e6) : 0.0;

    /* shutdown(SHUT_WR) so the peer sees EOF. */
    if (shutdown(fd, SHUT_WR) < 0)
        note("warning: shutdown: %s", strerror(errno));

    /* Collect the TCP_INFO counters before the socket goes away. */
    memset(&ti, 0, sizeof(ti));
    {
        unsigned char raw[TCP_INFO_BUFSZ];

        memset(raw, 0, sizeof(raw));
        tilen = sizeof(raw);
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, raw, &tilen) == 0) {
            size_t copy = (size_t)tilen;

            if (copy > sizeof(ti))
                copy = sizeof(ti);
            memcpy(&ti, raw, copy);
            have_info = true;
        } else {
            note("warning: getsockopt(TCP_INFO): %s", strerror(errno));
        }
    }

    /* Drain whatever the peer still has to say so that the connection is
     * closed cleanly instead of being reset. */
    {
        double drain_deadline = now_sec() + 5.0;
        unsigned char drain[65536];

        while (!g_stop && now_sec() < drain_deadline) {
            struct pollfd pfd;
            ssize_t n;

            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll(&pfd, 1, 200) <= 0)
                continue;
            n = read(fd, drain, sizeof(drain));
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            if (n <= 0)
                break;
        }
    }

    /* --- report ------------------------------------------------------- */
    memset(&kv, 0, sizeof(kv));
    kv_addf(&kv, "RESULT role=client");
    if (ccname)
        kv_addf(&kv, " cc=%s", ccname);
    kv_addf(&kv, " bytes=%" PRIu64, total);
    kv_addf(&kv, " elapsed=%.2f", elapsed);
    kv_addf(&kv, " mbit=%.2f", mbit);
    if (have_info) {
        kv_addf(&kv, " cwnd=%u", ti.tcpi_snd_cwnd);
        kv_addf(&kv, " ssthresh=%u", ti.tcpi_snd_ssthresh);
        kv_addf(&kv, " rtt_us=%u", ti.tcpi_rtt);
        kv_addf(&kv, " retrans=%u", ti.tcpi_total_retrans);
        if (tilen >= (socklen_t)(offsetof(struct tcp_info, tcpi_pacing_rate) +
                                 sizeof(ti.tcpi_pacing_rate)))
            kv_addf(&kv, " pacing=%" PRIu64, ti.tcpi_pacing_rate);
    }
    fputs(kv.buf, stdout);
    fputc('\n', stdout);
    fflush(stdout);

    note("wrote %" PRIu64 " bytes in %.2fs -> %.2f Mbit/s", total, elapsed, mbit);
    if (have_info)
        note("tcp_info: cwnd=%u ssthresh=%u rtt=%uus retrans=%u pacing=%" PRIu64 " B/s",
             ti.tcpi_snd_cwnd, ti.tcpi_snd_ssthresh, ti.tcpi_rtt,
             ti.tcpi_total_retrans, ti.tcpi_pacing_rate);

    free(buf);
    free(cclist);
    free(ccname);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* server                                                              */
/* ------------------------------------------------------------------ */

static int run_server(const struct options *o)
{
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    int fd;
    uint64_t total = 0;
    double t0;
    double elapsed;
    double mbit;
    struct kv kv;
    char *buf = NULL;
    struct pollfd *pfds = NULL;
    int *cfds = NULL;
    int nconn = 0;
    int accept_max = (o->accept_max > 0) ? o->accept_max : 1;

    if (!o->bind_addr)
        die("server mode requires --bind");
    if (o->port <= 0 || o->port > 65535)
        die("server mode requires a valid --port");

    fd = socket(addr_family(o->bind_addr), SOCK_STREAM, 0);
    if (fd < 0)
        die("socket: %s", strerror(errno));

    {
        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
            note("warning: SO_REUSEADDR: %s", strerror(errno));
    }
    if (o->so_rcvbuf > 0) {
        int v = (int)o->so_rcvbuf;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)) < 0)
            note("warning: SO_RCVBUF: %s", strerror(errno));
    }

    if (fill_addr(addr_family(o->bind_addr), o->bind_addr, o->port, &ss, &slen) < 0)
        die("invalid --bind address '%s'", o->bind_addr);
    if (bind(fd, (struct sockaddr *)&ss, slen) < 0)
        die("bind(%s:%d): %s", o->bind_addr, o->port, strerror(errno));
    if (listen(fd, 16) < 0)
        die("listen: %s", strerror(errno));

    note("listening on %s:%d (duration %.0fs, up to %d connection(s))",
         o->bind_addr, o->port, o->duration, accept_max);

    buf = malloc(65536);
    if (!buf)
        die("out of memory");
    pfds = calloc((size_t)accept_max + 1, sizeof(*pfds));
    cfds = calloc((size_t)accept_max, sizeof(*cfds));
    if (!pfds || !cfds)
        die("out of memory");

    /* Accept and read at the same time: a connection that is already
     * established must not wait for the remaining connections to show up.
     * After the last connection was closed the server lingers for a short
     * grace period to pick up further connections, then exits. */
    {
        double deadline = now_sec() + o->duration;
        double last_close = now_sec();
        int open_conns = 0;
        int i;

        t0 = now_sec();
        while (!g_stop) {
            int nfd = 0;
            int rc;

            if (now_sec() >= deadline)
                break;
            if (open_conns == 0) {
                if (nconn >= accept_max)
                    break;
                if (nconn > 0 && now_sec() - last_close > ACCEPT_GRACE_SEC)
                    break;
            }

            pfds[0].fd = (nconn < accept_max) ? fd : -1;
            pfds[0].events = POLLIN;
            pfds[0].revents = 0;
            nfd = 1;
            for (i = 0; i < nconn; i++) {
                pfds[nfd].fd = cfds[i];
                pfds[nfd].events = POLLIN;
                pfds[nfd].revents = 0;
                nfd++;
            }

            rc = poll(pfds, (nfds_t)nfd, 200);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                note("poll: %s", strerror(errno));
                break;
            }
            if (rc == 0)
                continue;

            /* new connection? */
            if (pfds[0].fd >= 0 && (pfds[0].revents & POLLIN) && nconn < accept_max) {
                int cfd = accept(fd, NULL, NULL);

                if (cfd >= 0) {
                    cfds[nconn] = cfd;
                    nconn++;
                    open_conns++;
                    note("accepted connection %d/%d", nconn, accept_max);
                } else if (errno != EINTR && errno != EAGAIN) {
                    note("accept: %s", strerror(errno));
                }
            }

            /* data on the established connections? */
            for (i = 1; i < nfd; i++) {
                ssize_t n;

                if (pfds[i].fd < 0 || pfds[i].revents == 0)
                    continue;
                n = read(pfds[i].fd, buf, 65536);
                if (n > 0) {
                    total += (uint64_t)n;
                    continue;
                }
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                if (n < 0)
                    note("read: %s", strerror(errno));
                close(pfds[i].fd);
                pfds[i].fd = -1;
                open_conns--;
                last_close = now_sec();
            }
        }
        elapsed = now_sec() - t0;

        for (i = 0; i < nconn; i++) {
            if (pfds[i + 1].fd >= 0)
                close(pfds[i + 1].fd);
        }
    }

    if (nconn == 0)
        note("no connection arrived within %.0fs", o->duration);

    mbit = (elapsed > 0.0) ? ((double)total * 8.0 / elapsed / 1e6) : 0.0;

    memset(&kv, 0, sizeof(kv));
    kv_addf(&kv, "RESULT role=server");
    kv_addf(&kv, " bytes=%" PRIu64, total);
    kv_addf(&kv, " elapsed=%.2f", elapsed);
    kv_addf(&kv, " mbit=%.2f", mbit);
    fputs(kv.buf, stdout);
    fputc('\n', stdout);
    fflush(stdout);

    note("read %" PRIu64 " bytes in %.2fs -> %.2f Mbit/s", total, elapsed, mbit);

    free(buf);
    free(pfds);
    free(cfds);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    struct options o;
    const char *mode;

    if (argc < 2) {
        usage(stderr);
        return 2;
    }

    mode = argv[1];
    if (arg_is(mode, "-h") || arg_is(mode, "--help")) {
        usage(stdout);
        return 0;
    }
    if (!arg_is(mode, "client") && !arg_is(mode, "server")) {
        fprintf(stderr, "tcperf: unknown mode '%s' (expected 'client' or 'server')\n", mode);
        usage(stderr);
        return 2;
    }

    memset(&o, 0, sizeof(o));
    o.port = -1;
    o.duration = DEFAULT_DURATION;
    o.connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    o.write_size = DEFAULT_WRITE_SIZE;
    o.so_sndbuf = DEFAULT_SNDBUF;
    o.so_rcvbuf = DEFAULT_RCVBUF;
    o.accept_max = 1;

    for (int i = 2; i < argc; i++) {
        char tok[64];
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        const char *val = NULL;

        if (eq) {
            size_t nlen = (size_t)(eq - argv[i]);

            if (nlen >= sizeof(tok))
                die("option name too long: '%s'", argv[i]);
            memcpy(tok, argv[i], nlen);
            tok[nlen] = '\0';
            arg = tok;
            val = eq + 1;
        }

        if (arg_is(arg, "--quiet")) {
            g_quiet = true;
        } else if (arg_is(arg, "--dst")) {
            if (!val) val = next_value(argc, argv, &i, "--dst");
            o.dst = val;
        } else if (arg_is(arg, "--bind")) {
            if (!val) val = next_value(argc, argv, &i, "--bind");
            o.bind_addr = val;
        } else if (arg_is(arg, "--cc")) {
            if (!val) val = next_value(argc, argv, &i, "--cc");
            o.cc = val;
        } else if (arg_is(arg, "--port")) {
            if (!val) val = next_value(argc, argv, &i, "--port");
            o.port = (int)parse_long(val, "--port");
        } else if (arg_is(arg, "--duration")) {
            if (!val) val = next_value(argc, argv, &i, "--duration");
            o.duration = parse_double(val, "--duration");
        } else if (arg_is(arg, "--write-size")) {
            if (!val) val = next_value(argc, argv, &i, "--write-size");
            o.write_size = (size_t)parse_long(val, "--write-size");
        } else if (arg_is(arg, "--connect-timeout")) {
            if (!val) val = next_value(argc, argv, &i, "--connect-timeout");
            o.connect_timeout = parse_double(val, "--connect-timeout");
        } else if (arg_is(arg, "--so-sndbuf")) {
            if (!val) val = next_value(argc, argv, &i, "--so-sndbuf");
            o.so_sndbuf = parse_long(val, "--so-sndbuf");
        } else if (arg_is(arg, "--so-rcvbuf")) {
            if (!val) val = next_value(argc, argv, &i, "--so-rcvbuf");
            o.so_rcvbuf = parse_long(val, "--so-rcvbuf");
        } else if (arg_is(arg, "--accept")) {
            if (!val) val = next_value(argc, argv, &i, "--accept");
            o.accept_max = (int)parse_long(val, "--accept");
        } else if (arg_is(arg, "-h") || arg_is(arg, "--help")) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "tcperf: unknown option '%s'\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (arg_is(mode, "client"))
        return run_client(&o);
    return run_server(&o);
}
