// SPDX-License-Identifier: GPL-2.0
/*
 * qkbtf — a small kernel BTF inspector.
 *
 * The kernel ships a complete binary description of every type it knows about
 * ("BTF", Binary Type Format) at /sys/kernel/btf/vmlinux.  bpftool can dump
 * it, but bpftool is not always installed and we mostly want a handful of
 * very specific answers:
 *
 *   - which kernel types exist with a given name fragment
 *   - what a struct/union looks like in C, so it can be pasted into a BPF
 *     program as a CO-RE type definition
 *   - where a struct's fields live (name / byte offset / type)
 *   - what a kernel function's prototype is
 *   - how big a type is
 *
 * Everything is read from the running kernel's BTF, so the answers always
 * describe the kernel that is actually running rather than some header tree.
 *
 * Build (needs libbpf >= 1.0, developed against 1.3.0):
 *
 *   cc -std=c11 -O2 -Wall -Wextra -g qkbtf.c -o qkbtf -lbpf -lelf -lz
 *
 * Only libbpf 1.x APIs are used:
 *   btf__load_vmlinux_btf(), btf__type_cnt(), btf__find_by_name_kind(),
 *   btf__type_by_id(), btf_vlen(), btf_members(), btf_array(), btf_params(),
 *   btf__name_by_offset(), btf__resolve_size().
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define QKBTF_PROG "qkbtf"

/* Working buffer sizes. */
#define BASE_BUF 256	/* type specifier: "struct sock", "unsigned int" */
#define DECL_BUF 1024	/* declarator prefix/suffix                         */
#define STR_BUF 1024	/* fully assembled declaration                     */
#define ARGS_BUF 512	/* argument list of a function prototype          */
#define NAME_BUF 512	/* synthesised type name                          */

static const char *progname = QKBTF_PROG;

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

static void *xmalloc(size_t n)
{
	void *p = malloc(n);

	if (!p)
		die("out of memory");
	return p;
}

static void *xrealloc(void *p, size_t n)
{
	void *r = realloc(p, n);

	if (!r)
		die("out of memory");
	return r;
}

/*
 * Append to a string, truncating if needed.  Written by hand rather than
 * with snprintf() so that the compiler does not have to reason about
 * truncation of the pieces we concatenate.
 */
static void app(char *dst, size_t dstsz, const char *src)
{
	size_t len, n;

	if (!dstsz)
		return;
	len = strlen(dst);
	if (len + 1 >= dstsz)
		return;
	n = strlen(src);
	if (n > dstsz - len - 1)
		n = dstsz - len - 1;
	memcpy(dst + len, src, n);
	dst[len + n] = '\0';
}

/* ------------------------------------------------------------------ */
/* BTF kind names                                                     */
/* ------------------------------------------------------------------ */

static const char *kind_name(__u16 kind)
{
	switch (kind) {
	case BTF_KIND_UNKN:	return "unknown";
	case BTF_KIND_INT:	return "int";
	case BTF_KIND_PTR:	return "ptr";
	case BTF_KIND_ARRAY:	return "array";
	case BTF_KIND_STRUCT:	return "struct";
	case BTF_KIND_UNION:	return "union";
	case BTF_KIND_ENUM:	return "enum";
	case BTF_KIND_FWD:	return "fwd";
	case BTF_KIND_TYPEDEF:	return "typedef";
	case BTF_KIND_VOLATILE:	return "volatile";
	case BTF_KIND_CONST:	return "const";
	case BTF_KIND_RESTRICT:	return "restrict";
	case BTF_KIND_FUNC:	return "func";
	case BTF_KIND_FUNC_PROTO: return "func_proto";
	case BTF_KIND_VAR:	return "var";
	case BTF_KIND_DATASEC:	return "datasec";
	case BTF_KIND_FLOAT:	return "float";
	case BTF_KIND_DECL_TAG:	return "decl_tag";
	case BTF_KIND_TYPE_TAG:	return "type_tag";
	case BTF_KIND_ENUM64:	return "enum64";
	default:		return "other";
	}
}

static const char *name_of(const struct btf *btf, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(btf, id);
	const char *n;

	if (!t)
		return NULL;
	n = btf__name_by_offset(btf, t->name_off);
	if (!n || !n[0])
		return NULL;
	return n;
}

/* ------------------------------------------------------------------ */
/* Name registry: composite types need a C-visible name               */
/*                                                                     */
/* Anonymous structs/unions/enums have no name in BTF, so we mint one   */
/* from the context in which they were found (parent__member).        */
/* ------------------------------------------------------------------ */

struct ctx {
	const struct btf *btf;
	__u32 ntypes;

	/* per type id: 0 = untouched, 1 = being emitted, 2 = done */
	unsigned char *state;

	/* per type id: already visited by the pointer walk */
	unsigned char *ptr_seen;

	/* assigned C names for composite types (struct/union/enum) */
	__u32 *ids;
	char (*names)[NAME_BUF];
	size_t nnames, capnames;

	/* hash index: index into names[] plus one, 0 means empty */
	__u32 *name_tab;
	size_t name_tab_sz;

	/* emission order (dependencies first) */
	__u32 *order;
	size_t norder, caporder;

	/* forward declarations needed (fwd types) */
	__u32 *fwd;
	size_t nfwd, capfwd;

	/* every name handed out, to keep them unique */
	char **used;
	size_t nused, capused;
};

static int name_taken(const struct ctx *c, const char *name)
{
	size_t i;

	for (i = 0; i < c->nused; i++) {
		if (!strcmp(c->used[i], name))
			return 1;
	}
	return 0;
}

static void remember_name(struct ctx *c, const char *name)
{
	size_t len;

	if (c->nused == c->capused) {
		c->capused = c->capused ? c->capused * 2 : 64;
		c->used = xrealloc(c->used, c->capused * sizeof(*c->used));
	}
	len = strlen(name) + 1;
	c->used[c->nused] = xmalloc(len);
	memcpy(c->used[c->nused], name, len);
	c->nused++;
}

static size_t name_hash(__u32 id, size_t sz)
{
	return ((size_t)id * 2654435761u) % sz;
}

static const char *lookup_name(const struct ctx *c, __u32 id)
{
	size_t h, i;

	if (!c->name_tab)
		return NULL;
	h = name_hash(id, c->name_tab_sz);
	for (i = 0; i < c->name_tab_sz; i++) {
		__u32 e = c->name_tab[(h + i) % c->name_tab_sz];

		if (e == 0)
			return NULL;
		if (c->ids[e - 1] == id)
			return c->names[e - 1];
	}
	return NULL;
}

static void store_name(struct ctx *c, __u32 id, const char *name)
{
	size_t h, i;

	if (!c->name_tab) {
		size_t sz = 64;

		while (sz < (size_t)c->ntypes * 2 + 16)
			sz *= 2;
		c->name_tab = xmalloc(sz * sizeof(*c->name_tab));
		c->name_tab_sz = sz;
	}

	if (c->nnames == c->capnames) {
		c->capnames = c->capnames ? c->capnames * 2 : 64;
		c->ids = xrealloc(c->ids, c->capnames * sizeof(*c->ids));
		c->names = xrealloc(c->names, c->capnames * sizeof(*c->names));
	}
	c->ids[c->nnames] = id;
	snprintf(c->names[c->nnames], NAME_BUF, "%s", name);
	c->nnames++;

	h = name_hash(id, c->name_tab_sz);
	for (i = 0; i < c->name_tab_sz; i++) {
		size_t s = (h + i) % c->name_tab_sz;

		if (c->name_tab[s] == 0) {
			c->name_tab[s] = (__u32)c->nnames;	/* index + 1 */
			break;
		}
	}
}

/*
 * Return the C name to use for composite type `id'.  Named types keep their
 * own name; anonymous ones get a synthesised "<context>__anon" name.
 */
static const char *composite_name(struct ctx *c, __u32 id, const char *hint)
{
	const char *existing = lookup_name(c, id);
	const char *btf_name = name_of(c->btf, id);
	char base[NAME_BUF];
	char cand[NAME_BUF];
	unsigned int n;

	if (existing)
		return existing;

	if (btf_name) {
		snprintf(base, sizeof(base), "%s", btf_name);
	} else if (hint && hint[0]) {
		size_t hl = strlen(hint);

		/* do not pile up "__anon" markers */
		if (hl >= 5 && !strcmp(hint + hl - 5, "__anon"))
			snprintf(base, sizeof(base), "%s", hint);
		else
			snprintf(base, sizeof(base), "%s__anon", hint);
	} else {
		snprintf(base, sizeof(base), "anon__%u", id);
	}

	for (n = 0; ; n++) {
		char suffix[32];

		cand[0] = '\0';
		app(cand, sizeof(cand), base);
		if (n) {
			snprintf(suffix, sizeof(suffix), "__%u", n);
			app(cand, sizeof(cand), suffix);
		}
		if (!name_taken(c, cand))
			break;
	}

	remember_name(c, cand);
	store_name(c, id, cand);
	return lookup_name(c, id);
}

/* ------------------------------------------------------------------ */
/* Integer rendering                                                  */
/*                                                                     */
/* The kernel's INT names are plain C type names, so we can reuse them  */
/* verbatim when they are recognisable.  Anything else is derived from */
/* the width and the signedness bit, which keeps the output valid C    */
/* without needing <linux/types.h>.                                    */
/* ------------------------------------------------------------------ */

static const char *known_int_names[] = {
	"char", "signed char", "unsigned char",
	"short", "short int", "unsigned short", "unsigned short int",
	"int", "unsigned int",
	"long", "long int", "unsigned long", "unsigned long int",
	"long long", "long long int",
	"unsigned long long", "unsigned long long int",
	"_Bool", "bool",
};

static const char *int_base_name(const struct btf *btf, const struct btf_type *t)
{
	const char *n = btf__name_by_offset(btf, t->name_off);
	__u8 enc = btf_int_encoding(t);
	__u32 sz = t->size;
	size_t i;

	if (n) {
		for (i = 0; i < sizeof(known_int_names) / sizeof(known_int_names[0]); i++) {
			if (!strcmp(n, known_int_names[i])) {
				if (!strcmp(n, "bool"))
					return "_Bool";
				return n;
			}
		}
	}

	if (enc & BTF_INT_BOOL)
		return "_Bool";
	if (enc & BTF_INT_CHAR)
		return (enc & BTF_INT_SIGNED) ? "signed char" : "unsigned char";

	switch (sz) {
	case 1:
		return (enc & BTF_INT_SIGNED) ? "signed char" : "unsigned char";
	case 2:
		return (enc & BTF_INT_SIGNED) ? "short" : "unsigned short";
	case 4:
		return (enc & BTF_INT_SIGNED) ? "int" : "unsigned int";
	case 8:
		return (enc & BTF_INT_SIGNED) ? "long" : "unsigned long";
	default:
		return (enc & BTF_INT_SIGNED) ? "long long" : "unsigned long long";
	}
}

/* ------------------------------------------------------------------ */
/* Type rendering                                                     */
/*                                                                     */
/* A C declaration is split into three pieces:                         */
/*                                                                     */
/*    base : the type specifier   ("struct sock", "unsigned int")      */
/*    pre  : declarator prefix    ("*", "(*")                          */
/*    suf  : declarator suffix    ("[4]", ")(int a)")                  */
/*                                                                     */
/* and the declaration is                                              */
/*                                                                     */
/*    base " " pre <name> suf                                         */
/*                                                                     */
/* which is exactly how C declarators nest.                            */
/* ------------------------------------------------------------------ */

struct dcl {
	char pre[DECL_BUF];
	char suf[DECL_BUF];
};

static void render_type(struct ctx *c, __u32 id, int expand_typedefs,
			char *base, size_t basesz, struct dcl *d);

/*
 * True if `id' denotes a pointer (possibly behind a typedef).  A qualifier
 * on a pointer qualifies the pointer itself, not the pointee, so the two
 * cases have to be rendered differently.
 */
static bool is_pointerish(const struct btf *btf, __u32 id)
{
	int depth;

	for (depth = 0; depth < 64; depth++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t)
			return false;
		switch (btf_kind(t)) {
		case BTF_KIND_PTR:
			return true;
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_VAR:
			id = t->type;
			continue;
		default:
			return false;
		}
	}
	return false;
}

/*
 * Drop one level of outer qualifier.  C ignores qualifiers on a function's
 * return type, and the kernel's BTF marks them, which would otherwise make
 * the generated code warn.
 */
static __u32 strip_outer_qual(const struct btf *btf, __u32 id)
{
	int depth;

	for (depth = 0; depth < 64; depth++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t)
			return id;
		switch (btf_kind(t)) {
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
			id = t->type;
			continue;
		default:
			return id;
		}
	}
	return id;
}

static void render_params(struct ctx *c, __u32 proto_id, int expand_typedefs,
			  char *out, size_t outsz)
{
	const struct btf_type *p = btf__type_by_id(c->btf, proto_id);
	int i, n;

	out[0] = '\0';
	if (!p)
		return;

	n = btf_vlen(p);
	for (i = 0; i < n; i++) {
		const struct btf_param *param = btf_params(p);
		const char *pname = btf__name_by_offset(c->btf, param[i].name_off);
		char pb[BASE_BUF];
		struct dcl pd;

		render_type(c, param[i].type, expand_typedefs, pb, sizeof(pb),
			    &pd);
		if (i)
			app(out, outsz, ", ");
		app(out, outsz, pb);
		if (pd.pre[0] || pd.suf[0] || (pname && pname[0]))
			app(out, outsz, " ");
		app(out, outsz, pd.pre);
		app(out, outsz, pname ? pname : "");
		app(out, outsz, pd.suf);
	}
	if (!out[0])
		app(out, outsz, "void");
}

static void render_type(struct ctx *c, __u32 id, int expand_typedefs,
			char *base, size_t basesz, struct dcl *d)
{
	const struct btf_type *t = btf__type_by_id(c->btf, id);

	base[0] = '\0';
	d->pre[0] = '\0';
	d->suf[0] = '\0';

	if (!t) {
		app(base, basesz, "void");
		return;
	}

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
		app(base, basesz, int_base_name(c->btf, t));
		return;
	case BTF_KIND_FLOAT:
		app(base, basesz, t->size == 4 ? "float" : "double");
		return;
	case BTF_KIND_UNKN:	/* void */
		app(base, basesz, "void");
		return;
	case BTF_KIND_STRUCT:
		app(base, basesz, "struct ");
		app(base, basesz, composite_name(c, id, NULL));
		return;
	case BTF_KIND_UNION:
		app(base, basesz, "union ");
		app(base, basesz, composite_name(c, id, NULL));
		return;
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		app(base, basesz, "enum ");
		app(base, basesz, composite_name(c, id, NULL));
		return;
	case BTF_KIND_FWD: {
		const char *n = name_of(c->btf, id);

		app(base, basesz, btf_kflag(t) ? "union " : "struct ");
		app(base, basesz, n ? n : "<anon>");
		return;
	}
	case BTF_KIND_TYPEDEF: {
		const char *n = name_of(c->btf, id);

		if (expand_typedefs) {
			render_type(c, t->type, expand_typedefs,
				    base, basesz, d);
			return;
		}
		app(base, basesz, n ? n : "<anon>");
		return;
	}
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
	case BTF_KIND_DECL_TAG: {
		const char *qual = "";
		char tmp[BASE_BUF];
		char tmp2[DECL_BUF];

		switch (btf_kind(t)) {
		case BTF_KIND_CONST:	qual = "const"; break;
		case BTF_KIND_VOLATILE:	qual = "volatile"; break;
		case BTF_KIND_RESTRICT:	qual = "restrict"; break;
		default:		qual = ""; break;
		}
		render_type(c, t->type, expand_typedefs, base, basesz, d);
		if (!qual[0])
			return;
		if (is_pointerish(c->btf, t->type)) {
			/* the qualifier belongs to the pointer: char * const */
			if (d->pre[0]) {
				tmp2[0] = '\0';
				app(tmp2, sizeof(tmp2), d->pre);
				app(tmp2, sizeof(tmp2), " ");
				app(tmp2, sizeof(tmp2), qual);
				memcpy(d->pre, tmp2, sizeof(tmp2));
			}
			return;
		}
		tmp[0] = '\0';
		app(tmp, sizeof(tmp), qual);
		app(tmp, sizeof(tmp), " ");
		app(tmp, sizeof(tmp), base);
		memcpy(base, tmp, sizeof(tmp));
		return;
	}
	case BTF_KIND_VAR:
		render_type(c, t->type, expand_typedefs, base, basesz, d);
		return;
	case BTF_KIND_ARRAY: {
		const struct btf_array *a = btf_array(t);
		char num[32];
		char eb[BASE_BUF];
		struct dcl ed;

		render_type(c, a->type, expand_typedefs, eb, sizeof(eb), &ed);
		app(base, basesz, eb);
		app(d->pre, sizeof(d->pre), ed.pre);
		/*
		 * A zero element array is how the kernel spells both a
		 * flexible array member and its "cacheline group" markers.
		 * It is printed as "[0]": the empty form "[]" is only legal
		 * as the very last member of a struct, and the markers are
		 * not.
		 */
		snprintf(num, sizeof(num), "[%u]", a->nelems);
		app(d->suf, sizeof(d->suf), num);
		app(d->suf, sizeof(d->suf), ed.suf);
		return;
	}
	case BTF_KIND_PTR: {
		const struct btf_type *tt = btf__type_by_id(c->btf, t->type);
		char tb[BASE_BUF];
		struct dcl td;

		if (tt && btf_is_func_proto(tt)) {
			/* function pointer:  ret (*name)(args) */
			const struct btf_type *proto = tt;
			char rb[BASE_BUF], args[ARGS_BUF];
			struct dcl rd;

			render_type(c, strip_outer_qual(c->btf, proto->type),
				    expand_typedefs, rb, sizeof(rb), &rd);
			app(base, basesz, rb);
			if (rd.pre[0]) {
				app(base, basesz, " ");
				app(base, basesz, rd.pre);
			}
			render_params(c, t->type, expand_typedefs, args,
				      sizeof(args));
			app(d->pre, sizeof(d->pre), "(*");
			app(d->suf, sizeof(d->suf), ")");
			if (rd.suf[0])
				app(d->suf, sizeof(d->suf), rd.suf);
			app(d->suf, sizeof(d->suf), "(");
			app(d->suf, sizeof(d->suf), args);
			app(d->suf, sizeof(d->suf), ")");
			return;
		}
		if (tt && btf_is_array(tt)) {
			/* pointer to array:  int (*name)[N] */
			const struct btf_array *a = btf_array(tt);
			char eb[BASE_BUF], num[32];
			struct dcl ed;

			render_type(c, a->type, expand_typedefs, eb, sizeof(eb),
				    &ed);
			app(base, basesz, eb);
			app(d->pre, sizeof(d->pre), ed.pre);
			app(d->pre, sizeof(d->pre), "(*");
			snprintf(num, sizeof(num), "[%u]", a->nelems);
			app(d->suf, sizeof(d->suf), ")");
			app(d->suf, sizeof(d->suf), num);
			app(d->suf, sizeof(d->suf), ed.suf);
			return;
		}
		render_type(c, t->type, expand_typedefs, tb, sizeof(tb), &td);
		app(base, basesz, tb);
		if (td.suf[0]) {
			/* pointer to something with a suffix */
			app(d->pre, sizeof(d->pre), "(*");
			app(d->pre, sizeof(d->pre), td.pre);
			app(d->suf, sizeof(d->suf), ")");
			app(d->suf, sizeof(d->suf), td.suf);
			return;
		}
		app(d->pre, sizeof(d->pre), "*");
		app(d->pre, sizeof(d->pre), td.pre);
		app(d->suf, sizeof(d->suf), td.suf);
		return;
	}
	case BTF_KIND_FUNC_PROTO: {
		/* a bare function type: only valid behind a pointer */
		char rb[BASE_BUF], args[ARGS_BUF];
		struct dcl rd;

		render_type(c, strip_outer_qual(c->btf, t->type),
			    expand_typedefs, rb, sizeof(rb), &rd);
		app(base, basesz, rb);
		if (rd.pre[0]) {
			app(base, basesz, " ");
			app(base, basesz, rd.pre);
		}
		render_params(c, id, expand_typedefs, args, sizeof(args));
		app(d->suf, sizeof(d->suf), "(");
		app(d->suf, sizeof(d->suf), args);
		app(d->suf, sizeof(d->suf), ")");
		return;
	}
	default:
		app(base, basesz, "void");
		return;
	}
}

/*
 * Assemble "base pre name suf" into a C declaration.
 */
static void assemble(const char *base, const struct dcl *d, const char *name,
		     char *out, size_t outsz)
{
	if (!outsz)
		return;
	out[0] = '\0';
	app(out, outsz, base);
	if (d->pre[0] || d->suf[0] || name[0])
		app(out, outsz, " ");
	app(out, outsz, d->pre);
	app(out, outsz, name);
	app(out, outsz, d->suf);
}

/* Render just the type of `id', e.g. "struct sock_common *". */
static void type_to_str(struct ctx *c, __u32 id, int expand_typedefs,
			 char *out, size_t outsz)
{
	char base[BASE_BUF];
	struct dcl d;
	char full[STR_BUF];
	char *p;

	if (!outsz)
		return;
	out[0] = '\0';

	render_type(c, id, expand_typedefs, base, sizeof(base), &d);
	assemble(base, &d, "", full, sizeof(full));

	/* collapse double spaces and trim */
	for (p = full; *p; p++) {
		if (*p == ' ' && p[1] == ' ')
			*p = ' ';
	}
	p = full;
	while (*p == ' ')
		p++;
	app(out, outsz, p);
}

/* ------------------------------------------------------------------ */
/* Dependency walking                                                 */
/* ------------------------------------------------------------------ */

/*
 * Follow pointers/qualifiers/typedefs down to the composite type that
 * actually has to be defined, or -1 if there is none.
 */
static __u32 composite_id(const struct btf *btf, __u32 id)
{
	int depth;

	for (depth = 0; depth < 64; depth++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t)
			return (__u32)-1;
		switch (btf_kind(t)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FWD:
			return id;
		case BTF_KIND_PTR:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_VAR:
			id = t->type;
			continue;
		case BTF_KIND_ARRAY:
			id = btf_array(t)->type;
			continue;
		default:
			return (__u32)-1;
		}
	}
	return (__u32)-1;
}

/*
 * Composite type that has to be *defined* before the type that refers to
 * it, i.e. one that is embedded by value.  A pointer only needs a forward
 * declaration, so pointer targets are not followed here.
 */
static __u32 value_composite_id(const struct btf *btf, __u32 id)
{
	int depth;

	for (depth = 0; depth < 64; depth++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t)
			return (__u32)-1;
		switch (btf_kind(t)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
			return id;
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_VAR:
			id = t->type;
			continue;
		case BTF_KIND_ARRAY:
			id = btf_array(t)->type;
			continue;
		default:
			return (__u32)-1;
		}
	}
	return (__u32)-1;
}

/*
 * If `id' denotes a function pointer, return the id of the function
 * prototype it points at.  Otherwise -1.
 */
static __u32 func_proto_of(const struct btf *btf, __u32 id)
{
	int depth;

	for (depth = 0; depth < 64; depth++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!t)
			return (__u32)-1;
		if (btf_is_func_proto(t))
			return id;
		switch (btf_kind(t)) {
		case BTF_KIND_PTR: {
			const struct btf_type *tt = btf__type_by_id(btf, t->type);

			if (tt && btf_is_func_proto(tt))
				return t->type;
			return (__u32)-1;
		}
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
		case BTF_KIND_DECL_TAG:
		case BTF_KIND_VAR:
			id = t->type;
			continue;
		default:
			return (__u32)-1;
		}
	}
	return (__u32)-1;
}

static void order_append(struct ctx *c, __u32 id)
{
	if (c->norder == c->caporder) {
		c->caporder = c->caporder ? c->caporder * 2 : 64;
		c->order = xrealloc(c->order, c->caporder * sizeof(*c->order));
	}
	c->order[c->norder++] = id;
}

static void fwd_append(struct ctx *c, __u32 id)
{
	size_t i;

	for (i = 0; i < c->nfwd; i++) {
		if (c->fwd[i] == id)
			return;
	}
	if (c->nfwd == c->capfwd) {
		c->capfwd = c->capfwd ? c->capfwd * 2 : 16;
		c->fwd = xrealloc(c->fwd, c->capfwd * sizeof(*c->fwd));
	}
	c->fwd[c->nfwd++] = id;
}

/*
 * Assign a C name to every composite type in the closure of `root'.
 *
 * The walk is breadth first on purpose: an anonymous struct that can be
 * reached through several members then gets its name from the shortest
 * path, which is the one a reader is most likely to recognise.
 */
struct qitem {
	__u32 id;
	char hint[NAME_BUF];
};

static void assign_names_bfs(struct ctx *c, __u32 root)
{
	struct qitem *q;
	size_t qn = 0, qcap = 256, qhead = 0;

	if (root == (__u32)-1 || root >= c->ntypes)
		return;

	q = xmalloc(qcap * sizeof(*q));
	q[qn].id = root;
	q[qn].hint[0] = '\0';
	qn++;

	while (qhead < qn) {
		struct qitem item = q[qhead++];
		const struct btf_type *t = btf__type_by_id(c->btf, item.id);
		const char *sname;
		int i, n;

		if (!t)
			continue;
		if (lookup_name(c, item.id))
			continue;	/* already named */

		sname = composite_name(c, item.id,
				       item.hint[0] ? item.hint : NULL);

		if (!btf_is_struct(t) && !btf_is_union(t))
			continue;

		n = btf_vlen(t);
		for (i = 0; i < n; i++) {
			const struct btf_member *m = btf_members(t);
			const char *mname =
				btf__name_by_offset(c->btf, m[i].name_off);
			__u32 cid = composite_id(c->btf, m[i].type);
			__u32 proto;
			const struct btf_type *ct;
			int j, np;

			if (cid != (__u32)-1 && cid != item.id) {
				ct = btf__type_by_id(c->btf, cid);
				if (ct && !btf_is_fwd(ct) &&
				    !lookup_name(c, cid)) {
					if (qn == qcap) {
						qcap *= 2;
						q = xrealloc(q, qcap * sizeof(*q));
					}
					q[qn].id = cid;
					snprintf(q[qn].hint, sizeof(q[qn].hint),
						 "%s__%s", sname,
						 mname && mname[0] ? mname
								   : "member");
					qn++;
				}
			}

			/* a function pointer hides its argument types */
			proto = func_proto_of(c->btf, m[i].type);
			if (proto == (__u32)-1)
				continue;
			{
				const struct btf_type *pt =
					btf__type_by_id(c->btf, proto);

				if (!pt)
					continue;
				np = btf_vlen(pt);
				for (j = 0; j < np; j++) {
					const struct btf_param *param =
						btf_params(pt);
					const char *pname =
						btf__name_by_offset(c->btf,
								    param[j].name_off);
					__u32 pid = composite_id(c->btf,
								 param[j].type);
					const struct btf_type *pt2;

					if (pid == (__u32)-1)
						continue;
					pt2 = btf__type_by_id(c->btf, pid);
					if (!pt2 || btf_is_fwd(pt2))
						continue;
					if (lookup_name(c, pid))
						continue;
					if (qn == qcap) {
						qcap *= 2;
						q = xrealloc(q, qcap * sizeof(*q));
					}
					q[qn].id = pid;
					snprintf(q[qn].hint, sizeof(q[qn].hint),
						 "%s__%s", sname,
						 pname && pname[0] ? pname
								   : "arg");
					qn++;
				}
			}
		}
	}

	free(q);
}

/*
 * Queue the definition of composite type `id'.
 *
 * Only by-value members are followed, so the resulting order is a valid
 * topological order: a struct is always defined after the structs it
 * embeds.  Pointer targets are picked up later, they only need a forward
 * declaration where they are used.
 */
static void define_by_value(struct ctx *c, __u32 id)
{
	const struct btf_type *t;
	int i, n;

	if (id == (__u32)-1 || id >= c->ntypes)
		return;
	if (c->state[id] != 0)
		return;

	c->state[id] = 1;
	t = btf__type_by_id(c->btf, id);
	if (!t) {
		c->state[id] = 2;
		return;
	}

	if (btf_is_fwd(t)) {
		fwd_append(c, id);
		c->state[id] = 2;
		return;
	}

	if (btf_is_enum(t) || btf_is_enum64(t)) {
		composite_name(c, id, NULL);
		order_append(c, id);
		c->state[id] = 2;
		return;
	}

	if (!btf_is_struct(t) && !btf_is_union(t)) {
		c->state[id] = 2;
		return;
	}

	composite_name(c, id, NULL);

	n = btf_vlen(t);
	for (i = 0; i < n; i++) {
		const struct btf_member *m = btf_members(t);
		__u32 cid = value_composite_id(c->btf, m[i].type);
		__u32 proto;
		int j, np;

		if (cid != (__u32)-1 && cid != id)
			define_by_value(c, cid);

		/*
		 * A function pointer hides its argument types, and those are
		 * passed by value, so they have to be complete as well.
		 */
		proto = func_proto_of(c->btf, m[i].type);
		if (proto == (__u32)-1)
			continue;
		{
			const struct btf_type *pt = btf__type_by_id(c->btf, proto);

			if (!pt)
				continue;
			np = btf_vlen(pt);
			for (j = 0; j < np; j++) {
				const struct btf_param *param = btf_params(pt);
				__u32 pid = value_composite_id(c->btf,
							      param[j].type);

				if (pid != (__u32)-1 && pid != id)
					define_by_value(c, pid);
			}
			cid = value_composite_id(c->btf, pt->type);
			if (cid != (__u32)-1 && cid != id)
				define_by_value(c, cid);
		}
	}

	order_append(c, id);
	c->state[id] = 2;
}

/*
 * Walk the whole closure of `id' and define the types that are only
 * reachable through a pointer.  They are appended after the by-value
 * closure, so they cannot break the ordering of the embedded ones.
 */
static void define_pointer_targets(struct ctx *c, __u32 id)
{
	const struct btf_type *t;
	int i, n;

	if (id == (__u32)-1 || id >= c->ntypes)
		return;
	if (c->ptr_seen[id])
		return;
	c->ptr_seen[id] = 1;

	t = btf__type_by_id(c->btf, id);
	if (!t)
		return;

	if (btf_is_fwd(t)) {
		fwd_append(c, id);
		return;
	}

	if (btf_is_enum(t) || btf_is_enum64(t)) {
		if (c->state[id] == 0)
			define_by_value(c, id);
		return;
	}

	if (btf_is_struct(t) || btf_is_union(t)) {
		if (c->state[id] == 0)
			define_by_value(c, id);
		n = btf_vlen(t);
		for (i = 0; i < n; i++) {
			const struct btf_member *m = btf_members(t);

			define_pointer_targets(c, m[i].type);
		}
		return;
	}

	switch (btf_kind(t)) {
	case BTF_KIND_PTR:
		define_pointer_targets(c, t->type);
		return;
	case BTF_KIND_ARRAY:
		define_pointer_targets(c, btf_array(t)->type);
		return;
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPE_TAG:
	case BTF_KIND_DECL_TAG:
	case BTF_KIND_VAR:
		define_pointer_targets(c, t->type);
		return;
	case BTF_KIND_FUNC_PROTO:
		/* the return type and the argument types need definitions too */
		define_pointer_targets(c, t->type);
		n = btf_vlen(t);
		for (i = 0; i < n; i++) {
			const struct btf_param *param = btf_params(t);

			define_pointer_targets(c, param[i].type);
		}
		return;
	default:
		return;
	}
}

/* ------------------------------------------------------------------ */
/* Definition emission                                                */
/* ------------------------------------------------------------------ */

static int struct_has_bitfield(const struct btf *btf, const struct btf_type *t)
{
	int i, n = btf_vlen(t);

	(void)btf;
	for (i = 0; i < n; i++) {
		if (btf_member_bitfield_size(t, i))
			return 1;
	}
	return 0;
}

static int struct_has_flex_array(const struct btf *btf, const struct btf_type *t)
{
	int i, n = btf_vlen(t);

	for (i = 0; i < n; i++) {
		const struct btf_member *m = btf_members(t);
		const struct btf_type *mt = btf__type_by_id(btf, m[i].type);

		if (mt && btf_is_array(mt) && btf_array(mt)->nelems == 0)
			return 1;
	}
	return 0;
}

static void emit_enum(struct ctx *c, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(c->btf, id);
	const char *name = composite_name(c, id, NULL);
	int i, n;

	printf("enum %s {\n", name);
	n = btf_vlen(t);
	if (btf_is_enum64(t)) {
		for (i = 0; i < n; i++) {
			const struct btf_enum64 *e = btf_enum64(t);
			const char *en = btf__name_by_offset(c->btf, e[i].name_off);

			printf("\t%s = %lluULL%s\n", en ? en : "_anon",
			       (unsigned long long)btf_enum64_value(&e[i]),
			       i + 1 < n ? "," : "");
		}
	} else {
		for (i = 0; i < n; i++) {
			const struct btf_enum *e = btf_enum(t);
			const char *en = btf__name_by_offset(c->btf, e[i].name_off);

			printf("\t%s = %d%s\n", en ? en : "_anon", e[i].val,
			       i + 1 < n ? "," : "");
		}
	}
	printf("};\n\n");
}

static void emit_struct(struct ctx *c, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(c->btf, id);
	const char *name = composite_name(c, id, NULL);
	int i, n;

	printf("%s %s {\n", btf_is_union(t) ? "union" : "struct", name);

	n = btf_vlen(t);
	for (i = 0; i < n; i++) {
		const struct btf_member *m = btf_members(t);
		const char *mname = btf__name_by_offset(c->btf, m[i].name_off);
		__u32 bsz = btf_member_bitfield_size(t, i);
		__u32 boff = btf_member_bit_offset(t, i);
		char base[BASE_BUF];
		struct dcl d;
		char line[STR_BUF];
		const char *use_name = mname;

		render_type(c, m[i].type, 1, base, sizeof(base), &d);

		if (!use_name || !use_name[0]) {
			/*
			 * Unnamed member.  The kernel uses those for anonymous
			 * structs/unions; C11 allows them, but then the type
			 * has to be spelled out inline.  We give the member a
			 * generated name instead, which keeps the output valid
			 * C and the offsets unchanged.
			 */
			char fake[32];

			snprintf(fake, sizeof(fake), "__anon_%d", i);
			use_name = fake;
		}

		assemble(base, &d, use_name, line, sizeof(line));

		if (bsz)
			printf("\t%s : %u; /* bit offset %u */\n", line, bsz, boff);
		else
			printf("\t%s;\n", line);
	}
	printf("}");

	if (!struct_has_bitfield(c->btf, t) && !struct_has_flex_array(c->btf, t))
		printf(" QK_PAI;\n\n");
	else
		printf(";\n\n");
}

/* ------------------------------------------------------------------ */
/* Type lookup helpers                                                */
/* ------------------------------------------------------------------ */

static __s32 find_any(const struct btf *btf, const char *name)
{
	static const __u16 kinds[] = {
		BTF_KIND_STRUCT, BTF_KIND_UNION, BTF_KIND_ENUM, BTF_KIND_ENUM64,
		BTF_KIND_TYPEDEF, BTF_KIND_FUNC, BTF_KIND_FWD,
	};
	size_t i;

	for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		__s32 id = btf__find_by_name_kind(btf, name, kinds[i]);

		if (id >= 0)
			return id;
	}
	return -1;
}

static void ctx_free(struct ctx *c)
{
	size_t i;

	for (i = 0; i < c->nused; i++)
		free(c->used[i]);
	free(c->used);
	free(c->ids);
	free(c->names);
	free(c->name_tab);
	free(c->order);
	free(c->fwd);
	free(c->state);
	free(c->ptr_seen);
}

static void ctx_init(struct ctx *c, const struct btf *btf)
{
	memset(c, 0, sizeof(*c));
	c->btf = btf;
	c->ntypes = btf__type_cnt(btf);
	c->state = xmalloc(c->ntypes ? c->ntypes : 1);
	memset(c->state, 0, c->ntypes ? c->ntypes : 1);
	c->ptr_seen = xmalloc(c->ntypes ? c->ntypes : 1);
	memset(c->ptr_seen, 0, c->ntypes ? c->ntypes : 1);
}

/* ------------------------------------------------------------------ */
/* Sub-commands                                                       */
/* ------------------------------------------------------------------ */

static int cmd_find(const struct btf *btf, const char *pattern)
{
	__u32 i, n = btf__type_cnt(btf);
	unsigned int hits = 0;

	for (i = 1; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name;

		if (!t)
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (!name || !name[0])
			continue;
		if (!strstr(name, pattern))
			continue;
		printf("id=%u kind=%s name=%s\n", i, kind_name(btf_kind(t)), name);
		hits++;
	}
	if (!hits)
		fprintf(stderr, "%s: no type matches \"%s\"\n", progname, pattern);
	return 0;
}

static int cmd_dump(const struct btf *btf, const char *type_name_arg)
{
	struct ctx c;
	__s32 id = find_any(btf, type_name_arg);
	const struct btf_type *t;
	size_t i;
	char guard[128];

	ctx_init(&c, btf);

	if (id < 0) {
		fprintf(stderr, "%s: type not found: %s\n", progname, type_name_arg);
		ctx_free(&c);
		return 1;
	}
	t = btf__type_by_id(btf, id);
	if (!t) {
		fprintf(stderr, "%s: invalid type id %d\n", progname, id);
		ctx_free(&c);
		return 1;
	}

	/* A typedef is dumped as the type it aliases. */
	if (btf_is_typedef(t)) {
		__u32 cid = composite_id(btf, t->type);

		if (cid == (__u32)-1) {
			fprintf(stderr,
				"%s: %s does not alias a composite type\n",
				progname, type_name_arg);
			ctx_free(&c);
			return 1;
		}
		id = (__s32)cid;
		t = btf__type_by_id(btf, id);
	}

	assign_names_bfs(&c, (__u32)id);
	define_by_value(&c, (__u32)id);
	define_pointer_targets(&c, (__u32)id);

	snprintf(guard, sizeof(guard), "__QKBTF_%s_H__", type_name_arg);
	for (i = 0; guard[i]; i++) {
		if (guard[i] >= 'a' && guard[i] <= 'z')
			guard[i] = (char)(guard[i] - 'a' + 'A');
		else if (!((guard[i] >= 'A' && guard[i] <= 'Z') ||
			   (guard[i] >= '0' && guard[i] <= '9') || guard[i] == '_'))
			guard[i] = '_';
	}

	printf("/*\n");
	printf(" * Type definitions extracted from the running kernel's BTF by %s.\n",
	       QKBTF_PROG);
	printf(" *\n");
	printf(" * The definitions are complete enough to be pasted into a BPF\n");
	printf(" * program as CO-RE type definitions: field offsets are resolved\n");
	printf(" * by name at load time, so the same object works across kernels.\n");
	printf(" *\n");
	printf(" * Anonymous members of the kernel's structs are given generated\n");
	printf(" * names (__anon_<n>); the layout is unchanged.\n");
	printf(" *\n");
	printf(" * Zero length arrays are printed as \"[0]\", which is how the kernel\n");
	printf(" * spells both flexible array members and its cacheline markers.\n");
	printf(" */\n");
	printf("#ifndef %s\n", guard);
	printf("#define %s\n\n", guard);

	/*
	 * preserve_access_index is what makes a local struct usable as a
	 * CO-RE type.  Only clang implements it, so keep it out of the way
	 * for other compilers.
	 */
	printf("#if defined(__clang__)\n");
	printf("#  if __has_attribute(preserve_access_index)\n");
	printf("#    define QK_PAI __attribute__((preserve_access_index))\n");
	printf("#  endif\n");
	printf("#endif\n");
	printf("#ifndef QK_PAI\n");
	printf("#  define QK_PAI\n");
	printf("#endif\n\n");

	/* forward declarations, so mutual references stay valid C */
	for (i = 0; i < c.norder; i++) {
		__u32 tid = c.order[i];
		const struct btf_type *ot = btf__type_by_id(btf, tid);

		if (!ot || (!btf_is_struct(ot) && !btf_is_union(ot)))
			continue;
		printf("%s %s;\n", btf_is_union(ot) ? "union" : "struct",
		       composite_name(&c, tid, NULL));
	}
	for (i = 0; i < c.nfwd; i++) {
		const struct btf_type *ft = btf__type_by_id(btf, c.fwd[i]);
		const char *n = ft ? name_of(btf, c.fwd[i]) : NULL;

		if (!n)
			continue;
		printf("%s %s;\n", btf_kflag(ft) ? "union" : "struct", n);
	}
	if (c.norder || c.nfwd)
		printf("\n");

	/*
	 * Enums first: an enum definition is self contained, and C has no way
	 * to forward declare one, so every enum has to be complete before the
	 * struct that uses it.
	 */
	for (i = 0; i < c.norder; i++) {
		__u32 tid = c.order[i];
		const struct btf_type *ot = btf__type_by_id(btf, tid);

		if (ot && (btf_is_enum(ot) || btf_is_enum64(ot)))
			emit_enum(&c, tid);
	}
	for (i = 0; i < c.norder; i++) {
		__u32 tid = c.order[i];
		const struct btf_type *ot = btf__type_by_id(btf, tid);

		if (!ot)
			continue;
		if (btf_is_struct(ot) || btf_is_union(ot))
			emit_struct(&c, tid);
	}

	printf("#endif /* %s */\n", guard);

	ctx_free(&c);
	return 0;
}

static int cmd_fields(const struct btf *btf, const char *struct_name,
		      const char *pattern)
{
	struct ctx c;
	__s32 id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
	const struct btf_type *t;
	int i, n;

	if (id < 0)
		id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_UNION);
	if (id < 0) {
		fprintf(stderr, "%s: struct not found: %s\n", progname,
			struct_name);
		return 1;
	}
	t = btf__type_by_id(btf, id);
	if (!t) {
		fprintf(stderr, "%s: invalid type id %d\n", progname, id);
		return 1;
	}

	ctx_init(&c, btf);

	/* Give nested anonymous types a contextual name. */
	assign_names_bfs(&c, (__u32)id);
	define_by_value(&c, (__u32)id);
	define_pointer_targets(&c, (__u32)id);

	printf("%s %s: %u bytes, %d members\n",
	       btf_is_union(t) ? "union" : "struct", struct_name, t->size,
	       btf_vlen(t));

	n = btf_vlen(t);
	for (i = 0; i < n; i++) {
		const struct btf_member *m = btf_members(t);
		const char *mname = btf__name_by_offset(btf, m[i].name_off);
		__u32 bsz = btf_member_bitfield_size(t, i);
		__u32 boff = btf_member_bit_offset(t, i);
		char ts[STR_BUF];

		if (pattern && (!mname || !strstr(mname, pattern)))
			continue;

		type_to_str(&c, m[i].type, 1, ts, sizeof(ts));
		printf("offset=%-5u bits=%-5u type=%-40s name=%s",
		       boff / 8, bsz, ts, mname && mname[0] ? mname : "<anonymous>");
		if (bsz)
			printf(" (bitfield, %u bits)", bsz);
		printf("\n");
	}

	ctx_free(&c);
	return 0;
}

static int cmd_proto(const struct btf *btf, const char *func_name)
{
	struct ctx c;
	__s32 id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
	const struct btf_type *t;
	const struct btf_type *proto;
	char base[BASE_BUF];
	char ret[STR_BUF];
	char line[ARGS_BUF];
	struct dcl rd;
	__u8 linkage;

	if (id < 0) {
		fprintf(stderr, "%s: function not found: %s\n", progname,
			func_name);
		return 1;
	}
	t = btf__type_by_id(btf, id);
	if (!t) {
		fprintf(stderr, "%s: invalid type id %d\n", progname, id);
		return 1;
	}
	proto = btf__type_by_id(btf, t->type);
	if (!proto || !btf_is_func_proto(proto)) {
		fprintf(stderr, "%s: %s has no prototype\n", progname, func_name);
		return 1;
	}

	ctx_init(&c, btf);

	/* return type */
	render_type(&c, proto->type, 1, base, sizeof(base), &rd);
	ret[0] = '\0';
	app(ret, sizeof(ret), base);
	if (rd.pre[0]) {
		app(ret, sizeof(ret), " ");
		app(ret, sizeof(ret), rd.pre);
	}

	/* arguments */
	render_params(&c, t->type, 1, line, sizeof(line));

	linkage = (__u8)(t->info & 0xffff);

	printf("%s%s %s(%s)\n",
	       linkage == BTF_FUNC_STATIC ? "static " :
	       linkage == BTF_FUNC_EXTERN ? "extern " : "",
	       ret, func_name, line);

	printf("btf_id=%d linkage=%s args=%d\n", id,
	       linkage == BTF_FUNC_STATIC ? "static" :
	       linkage == BTF_FUNC_EXTERN ? "extern" : "global",
	       btf_vlen(proto));

	ctx_free(&c);
	return 0;
}

static int cmd_size(const struct btf *btf, const char *type_name_arg)
{
	__s32 id = find_any(btf, type_name_arg);
	const struct btf_type *t;
	__s64 size;

	if (id < 0) {
		fprintf(stderr, "%s: type not found: %s\n", progname,
			type_name_arg);
		return 1;
	}
	t = btf__type_by_id(btf, id);
	if (!t) {
		fprintf(stderr, "%s: invalid type id %d\n", progname, id);
		return 1;
	}

	size = btf__resolve_size(btf, (__u32)id);
	if (size < 0) {
		printf("%s: size=unknown (kind=%s is not sized)\n", type_name_arg,
		       kind_name(btf_kind(t)));
		return 0;
	}

	printf("%s: size=%lld bytes (kind=%s, btf_id=%d)\n", type_name_arg,
	       (long long)size, kind_name(btf_kind(t)), id);
	return 0;
}

static void usage(FILE *out)
{
	fprintf(out,
"Usage:\n"
"  %s find <pattern>              list kernel types whose name contains <pattern>\n"
"  %s dump <type-name>            print a C definition (and its dependencies)\n"
"  %s fields <struct-name> [pat]  print a struct's fields: offset, type, name\n"
"  %s proto <function-name>       print a kernel function's prototype\n"
"  %s size <type-name>            print a type's size in bytes\n"
"\n"
"The kernel's BTF is read from /sys/kernel/btf/vmlinux.\n",
		progname, progname, progname, progname, progname);
}

int main(int argc, char **argv)
{
	const char *cmd;
	struct btf *btf;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	cmd = argv[1];

	if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
		usage(stdout);
		return 0;
	}

	btf = btf__load_vmlinux_btf();
	if (!btf) {
		fprintf(stderr,
			"%s: cannot load kernel BTF from /sys/kernel/btf/vmlinux\n",
			progname);
		return 1;
	}

	if (!strcmp(cmd, "find")) {
		if (argc < 3) {
			fprintf(stderr, "%s: find needs a pattern\n", progname);
			usage(stderr);
			return 2;
		}
		return cmd_find(btf, argv[2]);
	}
	if (!strcmp(cmd, "dump")) {
		if (argc < 3) {
			fprintf(stderr, "%s: dump needs a type name\n", progname);
			usage(stderr);
			return 2;
		}
		return cmd_dump(btf, argv[2]);
	}
	if (!strcmp(cmd, "fields")) {
		if (argc < 3) {
			fprintf(stderr, "%s: fields needs a struct name\n", progname);
			usage(stderr);
			return 2;
		}
		return cmd_fields(btf, argv[2], argc > 3 ? argv[3] : NULL);
	}
	if (!strcmp(cmd, "proto")) {
		if (argc < 3) {
			fprintf(stderr, "%s: proto needs a function name\n", progname);
			usage(stderr);
			return 2;
		}
		return cmd_proto(btf, argv[2]);
	}
	if (!strcmp(cmd, "size")) {
		if (argc < 3) {
			fprintf(stderr, "%s: size needs a type name\n", progname);
			usage(stderr);
			return 2;
		}
		return cmd_size(btf, argv[2]);
	}

	fprintf(stderr, "%s: unknown sub-command: %s\n", progname, cmd);
	usage(stderr);
	return 2;
}
