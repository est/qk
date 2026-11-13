// SPDX-License-Identifier: GPL-2.0
/*
 * qkctl — load, configure and unload the qk congestion controller.
 *
 * qk is a BPF congestion controller. Loading it means two things: loading the
 * BPF object into the kernel, and registering it with the kernel's TCP stack
 * through the struct_ops mechanism. A socket selects it the usual way:
 *
 *     setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "qk", 3);
 *
 * or, for a whole network namespace:
 *
 *     sysctl -w net.ipv4.tcp_congestion_control=qk
 *
 * Commands:
 *
 *   qkctl load   [--object FILE] [--set KEY=VALUE]... [--pin-dir DIR] [--daemon]
 *   qkctl tune   [--set KEY=VALUE]... [--pin-dir DIR]
 *   qkctl list
 *   qkctl info   [--object FILE]
 *   qkctl unload [--pin-dir DIR]
 *
 * Notes:
 *
 *   - The kernel's list of congestion control algorithms is global, not per
 *     network namespace: once "qk" is registered it is selectable from any
 *     socket in any namespace, and it cannot be replaced until the machine
 *     reboots. Loading it twice therefore reports that it is already there
 *     rather than failing; pass --strict to make that an error.
 *   - The kernel keeps a reference to the registered controller, so an
 *     unloaded controller stays registered until the namespace goes away. Use
 *     --daemon so that unloading is possible: qkctl unload then stops the
 *     process that holds the link, which releases the registration.
 *   - Tunables can be changed while the controller is running with
 *     "qkctl tune", provided the tunables map was pinned with --pin-dir.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "qk_tunables.h"
#include "qk_state.h"

#define QK_DEFAULT_OBJECT "qk.o"
#define QK_DEFAULT_PIN_DIR "/sys/fs/bpf/qk"
#define QK_DEFAULT_STATE_DIR "/run/qk"
#define QK_TUNABLES_MAP "qk_tunables"

static const struct {
	const char *name;
	uint32_t def;
	size_t offset;
} tunables[] = { QK_TUNABLE_NAMES };

#define TUNABLE_COUNT (sizeof(tunables) / sizeof(tunables[0]))

static struct bpf_object *g_obj;
static struct bpf_link *g_link;
static const char *g_state_dir = QK_DEFAULT_STATE_DIR;

/* The last component of a path, used to name the per-instance pid file. */
static const char *pin_base(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash && slash[1] ? slash + 1 : "qk";
}

/* Read the kernel's list of congestion control algorithms. */
static char *read_available(void)
{
	FILE *f = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "re");
	char buf[1024];
	char *out;

	if (!f)
		return NULL;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return NULL;
	}
	fclose(f);
	out = strdup(buf);
	if (!out)
		return NULL;
	out[strcspn(out, "\n")] = '\0';
	return out;
}

/* Find the name that appeared between two snapshots. */
static char *diff_name(const char *before, const char *after)
{
	char *copy, *tok, *save = NULL, *found = NULL;

	if (!after)
		return NULL;
	copy = strdup(after);
	if (!copy)
		return NULL;
	for (tok = strtok_r(copy, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		if (before && strstr(before, tok))
			continue;
		free(found);
		found = strdup(tok);
	}
	free(copy);
	return found;
}

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "qkctl: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static struct bpf_map *find_struct_ops_map(struct bpf_object *obj);

/* Set by the signal handler. */
static volatile sig_atomic_t g_unregister;

static void on_signal(int sig)
{
	if (sig == SIGUSR1)
		g_unregister = 1;
	else
		_exit(0);
}

/* Ask the kernel to unregister the controller.
 *
 * The kernel does not unregister when the link is released; it unregisters
 * when the struct_ops map element is deleted (kernel/bpf/bpf_struct_ops.c,
 * bpf_struct_ops_map_delete_elem). That element belongs to the map instance
 * that performed the registration, so this has to run in the process that
 * loaded the object. */
static void unregister_here(void)
{
	struct bpf_map *ops_map = find_struct_ops_map(g_obj);
	uint32_t key = 0;

	if (!ops_map) {
		fprintf(stderr, "qkctl: no struct_ops map to unregister\n");
		return;
	}
	if (bpf_map_delete_elem(bpf_map__fd(ops_map), &key) < 0)
		fprintf(stderr, "qkctl: cannot unregister: %s\n",
			strerror(errno));
	else
		printf("unregistered\n");
}

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

/* Find a map in the object by name, optionally checking its type. */
static struct bpf_map *find_map(struct bpf_object *obj, const char *name,
				enum bpf_map_type want_type, int check_type)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map)
		return NULL;
	if (check_type && bpf_map__type(map) != want_type) {
		fprintf(stderr, "qkctl: map %s has type %d, expected %d\n", name,
			bpf_map__type(map), want_type);
		return NULL;
	}
	return map;
}

/* Find the struct_ops map, which is the one the kernel registers. */
static struct bpf_map *find_struct_ops_map(struct bpf_object *obj)
{
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS)
			return map;
	}
	return NULL;
}

static int tunable_index(const char *name)
{
	for (size_t i = 0; i < TUNABLE_COUNT; i++) {
		if (!strcmp(tunables[i].name, name))
			return (int)i;
	}
	return -1;
}

/* Write the tunables into the map. `overrides` holds the values the user
 * asked for; anything not overridden keeps its default. */
static int apply_tunables(struct bpf_map *map, const uint32_t *overrides,
			  const char *const *override_names)
{
	struct qk_tunables t;
	uint32_t key = 0;
	int err;

	memset(&t, 0, sizeof(t));
	t.magic = QK_TUN_MAGIC;
	t.max_comp_ppm = QK_DEFAULT_MAX_COMP_PPM;
	t.comp_step_pct = QK_DEFAULT_COMP_STEP_PCT;
	t.bw_decay_pct = QK_DEFAULT_BW_DECAY_PCT;
	t.brake_ratio_pct = QK_DEFAULT_BRAKE_RATIO_PCT;
	t.erasure_window = QK_DEFAULT_ERASURE_WINDOW;
	t.floor_decay_pct = QK_DEFAULT_FLOOR_DECAY_PCT;
	t.min_cwnd = QK_DEFAULT_MIN_CWND;
	t.max_cwnd = QK_DEFAULT_MAX_CWND;
	t.mss = QK_DEFAULT_MSS;
	t.bw_pacing = QK_DEFAULT_BW_PACING;

	for (size_t i = 0; i < TUNABLE_COUNT; i++) {
		if (!override_names)
			break;
		if (!override_names[i])
			continue;
		*(uint32_t *)((char *)&t + tunables[i].offset) = overrides[i];
	}

	err = bpf_map_update_elem(bpf_map__fd(map), &key, &t, BPF_ANY);
	if (err)
		return -errno;
	return 0;
}

/* Parse a KEY=VALUE argument. */
static int parse_set(const char *arg, char **name, uint32_t *value)
{
	const char *eq = strchr(arg, '=');
	char *end;
	long v;

	if (!eq)
		return -1;
	*name = strndup(arg, (size_t)(eq - arg));
	if (!*name)
		return -1;
	errno = 0;
	v = strtol(eq + 1, &end, 0);
	if (errno || end == eq + 1 || *end != '\0' || v < 0 || v > UINT32_MAX) {
		free(*name);
		*name = NULL;
		return -1;
	}
	*value = (uint32_t)v;
	return 0;
}

static void print_tunables(void)
{
	printf("tunables (name default):\n");
	for (size_t i = 0; i < TUNABLE_COUNT; i++)
		printf("  %-18s %u\n", tunables[i].name, tunables[i].def);
}

static int cmd_list(void)
{
	FILE *f = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "re");
	char buf[1024];

	if (!f) {
		die("cannot read the list of congestion control algorithms: %s",
		    strerror(errno));
	}
	if (!fgets(buf, sizeof(buf), f))
		die("cannot read the list of congestion control algorithms");
	fclose(f);
	printf("available: %s", buf);
	return 0;
}

static int cmd_info(const char *object)
{
	struct bpf_object *obj;
	struct bpf_map *map;

	obj = bpf_object__open_file(object, NULL);
	if (!obj)
		die("cannot open %s", object);
	if (bpf_object__load(obj) < 0)
		die("cannot load %s", object);

	printf("maps:\n");
	{
		struct bpf_map *m;

		bpf_object__for_each_map(m, obj)
			printf("  %-24s type=%d value_size=%u\n", bpf_map__name(m),
			       bpf_map__type(m), bpf_map__value_size(m));
	}

	map = find_map(obj, QK_TUNABLES_MAP, BPF_MAP_TYPE_ARRAY, 0);
	if (map) {
		uint32_t key = 0;
		struct qk_tunables t;

		if (bpf_map_lookup_elem(bpf_map__fd(map), &key, &t) == 0 &&
		    t.magic == QK_TUN_MAGIC) {
			printf("tunables (name current):\n");
			for (size_t i = 0; i < TUNABLE_COUNT; i++)
				printf("  %-18s %u\n", tunables[i].name,
				       *(uint32_t *)((char *)&t + tunables[i].offset));
		} else {
			print_tunables();
		}
	} else {
		print_tunables();
	}

	bpf_object__close(obj);
	return 0;
}

static int cmd_tune(const char *pin_dir, char **names, uint32_t *values, int n)
{
	char path[512];
	int fd, err;
	uint32_t key = 0;
	struct qk_tunables t;

	snprintf(path, sizeof(path), "%s/%s", pin_dir, QK_TUNABLES_MAP);
	fd = bpf_obj_get(path);
	if (fd < 0)
		die("cannot open the pinned tunables map %s: %s "
		    "(load with --pin-dir and mount bpffs)",
		    path, strerror(errno));

	err = bpf_map_lookup_elem(fd, &key, &t);
	if (err) {
		close(fd);
		die("cannot read the tunables map: %s", strerror(errno));
	}
	for (int i = 0; i < n; i++) {
		int idx = tunable_index(names[i]);

		if (idx < 0) {
			close(fd);
			die("unknown tunable '%s'", names[i]);
		}
		*(uint32_t *)((char *)&t + tunables[idx].offset) = values[i];
		printf("%s = %u\n", names[i], values[i]);
	}
	err = bpf_map_update_elem(fd, &key, &t, BPF_ANY);
	close(fd);
	if (err)
		die("cannot write the tunables map: %s", strerror(errno));
	return 0;
}

/* Dump what the controller measured for each connection. Reads the pinned
 * qk_states map. */
static int cmd_stats(const char *pin_dir)
{
	char path[512];
	int fd;
	uint64_t key, next;
	int have = 0;

	snprintf(path, sizeof(path), "%s/qk_states", pin_dir);
	fd = bpf_obj_get(path);
	if (fd < 0)
		die("cannot open the pinned state map %s: %s "
		    "(load with --pin-dir and mount bpffs)",
		    path, strerror(errno));

	printf("RESULT role=stats connections=0\n");
	while (bpf_map_get_next_key(fd, have ? &key : NULL, &next) == 0) {
		struct qk_state st;

		key = next;
		have = 1;
		if (bpf_map_lookup_elem(fd, &key, &st) < 0)
			continue;
		printf("sock=%llx bw=%llu min_rtt_us=%u smooth_rtt_us=%u "
		       "floor_ppm=%u comp_ppm=%u calls=%u prior_cwnd=%u "
		       "loss_restores=%u\n",
		       (unsigned long long)key, (unsigned long long)st.bw,
		       st.min_rtt_us, st.smoothed_rtt_us, st.floor_ppm,
		       st.comp_ppm, st.calls, st.prior_cwnd,
		       st.loss_restores);
		printf("  sample: delivered=%d interval_us=%d rtt_us=%d "
		       "app_limited=%u losses=%u acked=%u new_round=%u cwnd=%u\n",
		       st.last_delivered, st.last_interval_us, st.last_rtt_us,
		       st.last_app_limited, st.last_losses, st.last_acked,
		       st.last_new_round, st.last_cwnd);
	}
	close(fd);
	return 0;
}

static int cmd_unload(const char *pin_dir)
{
	char path[512];
	int found = 0;

	/* Ask the holder of the registration to give it back. */
	snprintf(path, sizeof(path), "%s/%s.pid", g_state_dir, pin_base(pin_dir));
	{
		FILE *f = fopen(path, "re");
		int pid = 0;

		if (f) {
			if (fscanf(f, "%d", &pid) == 1 && pid > 0) {
				if (kill(pid, SIGUSR1) == 0) {
					printf("asked pid %d to unregister\n", pid);
					usleep(200000);
				} else {
					fprintf(stderr, "qkctl: cannot signal pid %d: %s\n",
						pid, strerror(errno));
				}
			}
			fclose(f);
		}
	}

	snprintf(path, sizeof(path), "%s/%s", pin_dir, "qk.struct_ops");
	if (unlink(path) == 0) {
		printf("removed %s\n", path);
		found = 1;
	}
	snprintf(path, sizeof(path), "%s/%s", pin_dir, QK_TUNABLES_MAP);
	if (unlink(path) == 0) {
		printf("removed %s\n", path);
		found = 1;
	}
	snprintf(path, sizeof(path), "%s/qk_states", pin_dir);
	if (unlink(path) == 0) {
		printf("removed %s\n", path);
		found = 1;
	}
	snprintf(path, sizeof(path), "%s/%s.pid", g_state_dir, pin_base(pin_dir));
	if (unlink(path) == 0) {
		printf("removed %s\n", path);
		found = 1;
	}
	if (!found)
		printf("nothing to unload under %s\n", pin_dir);
	printf("note: the kernel's list of congestion control algorithms is "
	       "global, so a controller that was never loaded through qkctl "
	       "cannot be removed\n");
	return 0;
}

static int cmd_load(const char *object, const char *fallback, const char *pin_dir,
		    char **names, uint32_t *values, int n, int daemon, int strict)
{
	struct bpf_map *ops_map, *tun_map, *states_map = NULL;
	char *before = NULL, *reg_name = NULL;
	int err;

	before = read_available();

	g_obj = bpf_object__open_file(object, NULL);
	if (!g_obj)
		die("cannot open %s", object);
	if (bpf_object__load(g_obj) < 0) {
		/* Some kernels refuse a congestion control that writes the
		 * socket's pacing rate, because their list of writable fields
		 * does not include it. The fallback object is the same controller
		 * working through the additive-increase callback, where the
		 * kernel computes the pacing rate from the window. */
		if (!fallback) {
			die("cannot load %s", object);
		}
		fprintf(stderr, "qkctl: %s did not load; trying %s\n", object, fallback);
		bpf_object__close(g_obj);
		g_obj = bpf_object__open_file(fallback, NULL);
		if (!g_obj)
			die("cannot open %s", fallback);
		if (bpf_object__load(g_obj) < 0)
			die("cannot load %s", fallback);
		object = fallback;
	}

	tun_map = find_map(g_obj, QK_TUNABLES_MAP, BPF_MAP_TYPE_ARRAY, 0);
	if (!tun_map)
		die("%s does not contain the %s map", object, QK_TUNABLES_MAP);

	ops_map = find_struct_ops_map(g_obj);
	if (!ops_map)
		die("%s does not contain a struct_ops map", object);

	{
		uint32_t overrides[TUNABLE_COUNT] = { 0 };
		const char *override_names[TUNABLE_COUNT] = { 0 };

		for (int i = 0; i < n; i++) {
			int idx = tunable_index(names[i]);

			if (idx < 0)
				die("unknown tunable '%s'", names[i]);
			overrides[idx] = values[i];
			override_names[idx] = names[i];
		}
		err = apply_tunables(tun_map, overrides, override_names);
		if (err)
			die("cannot set the tunables: %s", strerror(-err));
	}

	g_link = bpf_map__attach_struct_ops(ops_map);
	if (!g_link) {
		if (errno == EEXIST) {
			if (strict)
				die("the controller is already registered; the kernel's "
				    "list of congestion control algorithms is "
				    "global, so it cannot be replaced until the "
				    "machine reboots");
			printf("warning: the name is already registered in this "
			       "kernel. The kernel does not allow a registered name "
			       "to be replaced, so this may be a different build; "
			   "the machine has to be rebooted for a new one to take "
			   "effect. Continuing.\n");
			return 0;
		}
		die("cannot register the congestion controller: %s",
		    strerror(errno));
	}

	if (pin_dir && strcmp(pin_dir, "none") != 0) {
		char path[512];

		if (mkdir(pin_dir, 0755) < 0 && errno != EEXIST)
			die("cannot create %s: %s", pin_dir, strerror(errno));

		snprintf(path, sizeof(path), "%s/%s", pin_dir, QK_TUNABLES_MAP);
		if (bpf_map__pin(tun_map, path) < 0)
			fprintf(stderr, "qkctl: cannot pin %s: %s "
				"(is bpffs mounted?)\n", path, strerror(errno));
		else
			printf("pinned %s\n", path);

		states_map = find_map(g_obj, "qk_states", BPF_MAP_TYPE_LRU_HASH, 0);
		if (states_map) {
			snprintf(path, sizeof(path), "%s/qk_states", pin_dir);
			if (bpf_map__pin(states_map, path) < 0)
				fprintf(stderr, "qkctl: cannot pin %s: %s\n",
					path, strerror(errno));
			else
				printf("pinned %s\n", path);
		}
	}

	reg_name = diff_name(before, read_available());
	printf("registered congestion controller '%s'\n",
	       reg_name ? reg_name : "unknown");
	free(reg_name);
	free(before);
	for (int i = 0; i < n; i++)
		printf("  %s = %u\n", names[i], values[i]);

	if (daemon) {
		/* Hold the struct_ops link in a background process. The kernel
		 * keeps the registration either way; this only exists so that
		 * there is a process to point at, and so that a future kernel
		 * which unregisters on link release can be unloaded. */
		int pipefd[2];
		pid_t pid;
		char c;

		if (pipe(pipefd) < 0)
			die("pipe: %s", strerror(errno));
		pid = fork();
		if (pid < 0)
			die("fork: %s", strerror(errno));
		if (pid == 0) {
			struct sigaction sa = { 0 };
			int devnull;

			close(pipefd[0]);
			/* The daemon has nothing to say, and holding the
			 * caller's stdout would keep a pipe open: a plain
			 * "qkctl load --daemon | tail" would never see the
			 * end of its input. */
			devnull = open("/dev/null", O_RDWR);
			if (devnull >= 0) {
				dup2(devnull, STDOUT_FILENO);
				dup2(devnull, STDERR_FILENO);
				if (devnull > STDERR_FILENO)
					close(devnull);
			}
			sa.sa_handler = on_signal;
			sigaction(SIGTERM, &sa, NULL);
			sigaction(SIGINT, &sa, NULL);
			sigaction(SIGUSR1, &sa, NULL);
			if (write(pipefd[1], "x", 1) != 1)
				_exit(1);
			close(pipefd[1]);
			for (;;) {
				pause();
				if (g_unregister) {
					unregister_here();
					_exit(0);
				}
			}
		}
		close(pipefd[1]);
		if (read(pipefd[0], &c, 1) != 1)
			die("the daemon did not start");
		close(pipefd[0]);
		if (mkdir(g_state_dir, 0755) < 0 && errno != EEXIST)
			fprintf(stderr, "qkctl: cannot create %s: %s\n",
				g_state_dir, strerror(errno));
		{
			char path[512];

			snprintf(path, sizeof(path), "%s/%s.pid", g_state_dir,
				 pin_base(pin_dir));
			FILE *f = fopen(path, "w");

			if (f) {
				fprintf(f, "%d\n", (int)pid);
				fclose(f);
			} else {
				fprintf(stderr, "qkctl: cannot write %s: %s\n",
					path, strerror(errno));
			}
		}
		printf("running in the background as pid %d\n", (int)pid);
		return 0;
	}

	printf("the kernel keeps the registration for the lifetime of this "
	       "network namespace\n");
	return 0;
}

static void usage(FILE *out)
{
	fprintf(out,
		"usage: qkctl <command> [options]\n"
		"\n"
		"commands:\n"
		"  load    load the BPF object and register the controller\n"
		"  tune    change tunables of a running controller\n"
		"  list    list the congestion control algorithms the kernel knows\n"
		"  stats   show what the controller measured per connection\n"
		"  info    show the maps and tunables of an object\n"
		"  unload  release a pinned controller\n"
		"\n"
		"options:\n"
		"  --object FILE     BPF object to load (default %s)\n"
		"  --fallback FILE   object to try if the first one is refused\n"
		"  --set KEY=VALUE   set a tunable; repeatable\n"
		"  --pin-dir DIR     directory for the pinned maps (default %s,\n"
		"                    \"none\" to disable pinning)\n"
		"  --daemon          keep the registration in the background\n"
		"  --strict          fail if the controller is already registered\n"
		"  --state-dir DIR   directory for the pid file (default %s)\n"
		"  -h, --help        this text\n",
		QK_DEFAULT_OBJECT, QK_DEFAULT_PIN_DIR, QK_DEFAULT_STATE_DIR);
}

int main(int argc, char **argv)
{
	enum { OPT_OBJECT = 1000, OPT_SET, OPT_PIN_DIR, OPT_DAEMON, OPT_STRICT,
	       OPT_STATE_DIR, OPT_FALLBACK };
	static const struct option opts[] = {
		{ "object", required_argument, NULL, OPT_OBJECT },
		{ "fallback", required_argument, NULL, OPT_FALLBACK },
		{ "set", required_argument, NULL, OPT_SET },
		{ "pin-dir", required_argument, NULL, OPT_PIN_DIR },
		{ "daemon", no_argument, NULL, OPT_DAEMON },
		{ "strict", no_argument, NULL, OPT_STRICT },
		{ "state-dir", required_argument, NULL, OPT_STATE_DIR },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 },
	};
	const char *object = QK_DEFAULT_OBJECT;
	const char *fallback = NULL;
	const char *pin_dir = QK_DEFAULT_PIN_DIR;
	char *names[64];
	uint32_t values[64];
	int n = 0, daemon = 0, strict = 0, opt, idx;

	libbpf_set_print(libbpf_log);

	if (argc < 2) {
		usage(stderr);
		return 2;
	}

	/* Parse the options that come before the command as well as after it:
	 * the command word may appear anywhere. */
	while ((opt = getopt_long(argc, argv, "h", opts, &idx)) != -1) {
		switch (opt) {
		case OPT_OBJECT:
			object = optarg;
			break;
		case OPT_FALLBACK:
			fallback = optarg;
			break;
		case OPT_PIN_DIR:
			pin_dir = optarg;
			break;
		case OPT_DAEMON:
			daemon = 1;
			break;
		case OPT_STRICT:
			strict = 1;
			break;
		case OPT_STATE_DIR:
			g_state_dir = optarg;
			break;
		case OPT_SET:
			if (n >= (int)(sizeof(names) / sizeof(names[0])))
				die("too many --set options");
			if (parse_set(optarg, &names[n], &values[n]) < 0)
				die("malformed --set '%s', expected KEY=VALUE",
				    optarg);
			n++;
			break;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 2;
		}
	}

	if (optind >= argc) {
		usage(stderr);
		return 2;
	}

	if (!strcmp(argv[optind], "load"))
		return cmd_load(object, fallback, pin_dir, names, values, n, daemon, strict);
	if (!strcmp(argv[optind], "tune"))
		return cmd_tune(pin_dir, names, values, n);
	if (!strcmp(argv[optind], "list"))
		return cmd_list();
	if (!strcmp(argv[optind], "info"))
		return cmd_info(object);
	if (!strcmp(argv[optind], "stats"))
		return cmd_stats(pin_dir);
	if (!strcmp(argv[optind], "unload"))
		return cmd_unload(pin_dir);

	fprintf(stderr, "qkctl: unknown command '%s'\n", argv[optind]);
	usage(stderr);
	return 2;
}
