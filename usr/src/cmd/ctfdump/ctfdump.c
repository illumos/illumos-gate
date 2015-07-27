/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * Dump information about CTF containers. This was inspired by the original
 * ctfdump written in tools/ctf, but this has been reimplemented in terms of
 * libctf.
 */

#include <stdio.h>
#include <unistd.h>
#include <libctf.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

typedef enum ctfdump_arg {
	CTFDUMP_OBJECTS =	0x01,
	CTFDUMP_FUNCTIONS =	0x02,
	CTFDUMP_HEADER =	0x04,
	CTFDUMP_LABELS = 	0x08,
	CTFDUMP_STRINGS =	0x10,
	CTFDUMP_STATS = 	0x20,
	CTFDUMP_TYPES =		0x40,
	CTFDUMP_DEFAULT =	0x7f,
	CTFDUMP_OUTPUT =	0x80,
	CTFDUMP_ALL =		0xff
} ctfdump_arg_t;

typedef struct ctfdump_stat {
	ulong_t		cs_ndata;		/* number of data objects */
	ulong_t		cs_nfuncs;		/* number of functions */
	ulong_t		cs_nfuncargs;		/* number of function args */
	ulong_t		cs_nfuncmax;		/* largest number of args */
	ulong_t		cs_ntypes[CTF_K_MAX];	/* number of types */
	ulong_t		cs_nsmembs;		/* number of struct members */
	ulong_t		cs_nsmax;		/* largest number of members */
	ulong_t		cs_structsz;		/* sum of structures sizes */
	ulong_t		cs_sszmax;		/* largest structure */
	ulong_t		cs_numembs;		/* number of union members */
	ulong_t		cs_numax;		/* largest number of members */
	ulong_t		cs_unionsz;		/* sum of unions sizes */
	ulong_t		cs_uszmax;		/* largest union */
	ulong_t		cs_nemembs;		/* number of enum members */
	ulong_t		cs_nemax;		/* largest number of members */
	ulong_t		cs_nstrings;		/* number of strings */
	ulong_t		cs_strsz;		/* string size */
	ulong_t		cs_strmax;		/* longest string */
} ctfdump_stat_t;

static const char *g_progname;
static ctfdump_arg_t g_dump;
static ctf_file_t *g_fp;
static ctfdump_stat_t g_stats;
static ctf_id_t *g_fargc;
static int g_nfargc;

static int g_exit = 0;

static const char *ctfdump_fpenc[] = {
	NULL,
	"SINGLE",
	"DOUBLE",
	"COMPLEX",
	"DCOMPLEX",
	"LDCOMPLEX",
	"LDOUBLE",
	"INTERVAL",
	"DINTERVAL",
	"LDINTERVAL",
	"IMAGINARY",
	"DIMAGINARY",
	"LDIMAGINARY"
};

/*
 * When stats are requested, we have to go through everything. To make our lives
 * easier, we'll just always allow the code to print everything out, but only
 * output it if we have actually enabled that section.
 */
static void
ctfdump_printf(ctfdump_arg_t arg, const char *fmt, ...)
{
	va_list ap;

	if ((arg & g_dump) == 0)
		return;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

static void
ctfdump_warn(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", g_progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
ctfdump_fatal(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", g_progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(1);
}

static void
ctfdump_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;
		(void) fprintf(stderr, "%s: ", g_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-dfhlsSt] [-p parent] [-u outfile] "
	    "file\n"
	    "\n"
	    "\t-d  dump object data\n"
	    "\t-f  dump function data\n"
	    "\t-h  dump the CTF header\n"
	    "\t-l  dump the label table\n"
	    "\t-p  use parent to supply additional information\n"
	    "\t-s  dump the string table\n"
	    "\t-S  dump statistics about the CTF container\n"
	    "\t-t  dump type information\n"
	    "\t-u  dump uncompressed CTF data to outfile\n",
	    g_progname);
}

static void
ctfdump_title(ctfdump_arg_t arg, const char *header)
{
	static const char line[] = "----------------------------------------"
	    "----------------------------------------";
	ctfdump_printf(arg, "\n- %s %.*s\n\n", header, (int)78 - strlen(header),
	    line);
}

static int
ctfdump_objects_cb(const char *name, ctf_id_t id, ulong_t symidx, void *arg)
{
	int len;

	len = snprintf(NULL, 0, "  [%u] %u", g_stats.cs_ndata, id);
	ctfdump_printf(CTFDUMP_OBJECTS, "  [%u] %u %*s%s (%u)\n",
	    g_stats.cs_ndata, id, MAX(15 - len, 0), "", name, symidx);
	g_stats.cs_ndata++;
	return (0);
}

static void
ctfdump_objects(void)
{
	ctfdump_title(CTFDUMP_OBJECTS, "Data Objects");
	if (ctf_object_iter(g_fp, ctfdump_objects_cb, NULL) == CTF_ERR) {
		ctfdump_warn("failed to dump objects: %s\n",
		    ctf_errmsg(ctf_errno(g_fp)));
		g_exit = 1;
	}
}

static void
ctfdump_fargs_grow(int nargs)
{
	if (g_nfargc < nargs) {
		g_fargc = realloc(g_fargc, sizeof (ctf_id_t) * nargs);
		if (g_fargc == NULL)
			ctfdump_fatal("failed to get memory for %d "
			    "ctf_id_t's\n", nargs);
		g_nfargc = nargs;
	}
}

static int
ctfdump_functions_cb(const char *name, ulong_t symidx, ctf_funcinfo_t *ctc,
    void *arg)
{
	int i;

	if (ctc->ctc_argc != 0) {
		ctfdump_fargs_grow(ctc->ctc_argc);
		if (ctf_func_args(g_fp, symidx, g_nfargc, g_fargc) == CTF_ERR)
			ctfdump_fatal("failed to get arguments for function "
			    "%s: %s\n", name, ctf_errmsg(ctf_errno(g_fp)));
	}

	ctfdump_printf(CTFDUMP_FUNCTIONS,
	    "  [%lu] %s (%lu) returns: %u args: (", g_stats.cs_nfuncs, name,
	    symidx, ctc->ctc_return);
	for (i = 0; i < ctc->ctc_argc; i++)
		ctfdump_printf(CTFDUMP_FUNCTIONS, "%lu%s", g_fargc[i],
		    i + 1 == ctc->ctc_argc ? "" : ", ");
	if (ctc->ctc_flags & CTF_FUNC_VARARG)
		ctfdump_printf(CTFDUMP_FUNCTIONS, "%s...",
		    ctc->ctc_argc == 0 ? "" : ", ");
	ctfdump_printf(CTFDUMP_FUNCTIONS, ")\n");

	g_stats.cs_nfuncs++;
	g_stats.cs_nfuncargs += ctc->ctc_argc;
	g_stats.cs_nfuncmax = MAX(ctc->ctc_argc, g_stats.cs_nfuncmax);

	return (0);
}

static void
ctfdump_functions(void)
{
	ctfdump_title(CTFDUMP_FUNCTIONS, "Functions");

	if (ctf_function_iter(g_fp, ctfdump_functions_cb, NULL) == CTF_ERR) {
		ctfdump_warn("failed to dump functions: %s\n",
		    ctf_errmsg(ctf_errno(g_fp)));
		g_exit = 1;
	}
}

static void
ctfdump_header(void)
{
	const ctf_header_t *hp;
	const char *parname, *parlabel;

	ctfdump_title(CTFDUMP_HEADER, "CTF Header");
	ctf_dataptr(g_fp, (const void **)&hp, NULL);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_magic    = 0x%04x\n",
	    hp->cth_magic);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_version  = %u\n",
	    hp->cth_version);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_flags    = 0x%02x\n",
	    ctf_flags(g_fp));
	parname = ctf_parent_name(g_fp);
	parlabel = ctf_parent_label(g_fp);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_parlabel = %s\n",
	    parlabel == NULL ? "(anon)" : parlabel);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_parname  = %s\n",
	    parname == NULL ? "(anon)" : parname);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_lbloff   = %u\n",
	    hp->cth_lbloff);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_objtoff  = %u\n",
	    hp->cth_objtoff);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_funcoff  = %u\n",
	    hp->cth_funcoff);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_typeoff  = %u\n",
	    hp->cth_typeoff);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_stroff   = %u\n",
	    hp->cth_stroff);
	ctfdump_printf(CTFDUMP_HEADER, "  cth_strlen   = %u\n",
	    hp->cth_strlen);
}

static int
ctfdump_labels_cb(const char *name, const ctf_lblinfo_t *li, void *arg)
{
	ctfdump_printf(CTFDUMP_LABELS, "  %5lu %s\n", li->ctb_typeidx, name);
	return (0);
}

static void
ctfdump_labels(void)
{
	ctfdump_title(CTFDUMP_LABELS, "Label Table");
	if (ctf_label_iter(g_fp, ctfdump_labels_cb, NULL) == CTF_ERR) {
		ctfdump_warn("failed to dump labels: %s\n",
		    ctf_errmsg(ctf_errno(g_fp)));
		g_exit = 1;
	}
}

static int
ctfdump_strings_cb(const char *s, void *arg)
{
	size_t len = strlen(s) + 1;
	ulong_t *stroff = arg;
	ctfdump_printf(CTFDUMP_STRINGS, "  [%lu] %s\n", *stroff,
	    *s == '\0' ? "\\0" : s);
	*stroff = *stroff + len;
	g_stats.cs_nstrings++;
	g_stats.cs_strsz += len;
	g_stats.cs_strmax = MAX(g_stats.cs_strmax, len);
	return (0);
}

static void
ctfdump_strings(void)
{
	ulong_t stroff = 0;

	ctfdump_title(CTFDUMP_STRINGS, "String Table");
	if (ctf_string_iter(g_fp, ctfdump_strings_cb, &stroff) == CTF_ERR) {
		ctfdump_warn("failed to dump strings: %s\n",
		    ctf_errmsg(ctf_errno(g_fp)));
		g_exit = 1;
	}
}

static void
ctfdump_stat_int(const char *name, ulong_t value)
{
	ctfdump_printf(CTFDUMP_STATS, "  %-36s= %lu\n", name, value);
}

static void
ctfdump_stat_fp(const char *name, float value)
{
	ctfdump_printf(CTFDUMP_STATS, "  %-36s= %.2f\n", name, value);
}

static void
ctfdump_stats(void)
{
	int i;
	ulong_t sum;

	ctfdump_title(CTFDUMP_STATS, "CTF Statistics");

	ctfdump_stat_int("total number of data objects", g_stats.cs_ndata);
	ctfdump_printf(CTFDUMP_STATS, "\n");
	ctfdump_stat_int("total number of functions", g_stats.cs_nfuncs);
	ctfdump_stat_int("total number of function arguments",
	    g_stats.cs_nfuncargs);
	ctfdump_stat_int("maximum argument list length", g_stats.cs_nfuncmax);
	if (g_stats.cs_nfuncs != 0)
		ctfdump_stat_fp("average argument list length",
		    (float)g_stats.cs_nfuncargs / (float)g_stats.cs_nfuncs);
	ctfdump_printf(CTFDUMP_STATS, "\n");

	sum = 0;
	for (i = 0; i < CTF_K_MAX; i++)
		sum += g_stats.cs_ntypes[i];
	ctfdump_stat_int("total number of types", sum);
	ctfdump_stat_int("total number of integers",
	    g_stats.cs_ntypes[CTF_K_INTEGER]);
	ctfdump_stat_int("total number of floats",
	    g_stats.cs_ntypes[CTF_K_FLOAT]);
	ctfdump_stat_int("total number of pointers",
	    g_stats.cs_ntypes[CTF_K_POINTER]);
	ctfdump_stat_int("total number of arrays",
	    g_stats.cs_ntypes[CTF_K_ARRAY]);
	ctfdump_stat_int("total number of func types",
	    g_stats.cs_ntypes[CTF_K_FUNCTION]);
	ctfdump_stat_int("total number of structs",
	    g_stats.cs_ntypes[CTF_K_STRUCT]);
	ctfdump_stat_int("total number of unions",
	    g_stats.cs_ntypes[CTF_K_UNION]);
	ctfdump_stat_int("total number of enums",
	    g_stats.cs_ntypes[CTF_K_ENUM]);
	ctfdump_stat_int("total number of forward tags",
	    g_stats.cs_ntypes[CTF_K_FORWARD]);
	ctfdump_stat_int("total number of typedefs",
	    g_stats.cs_ntypes[CTF_K_TYPEDEF]);
	ctfdump_stat_int("total number of volatile types",
	    g_stats.cs_ntypes[CTF_K_VOLATILE]);
	ctfdump_stat_int("total number of const types",
	    g_stats.cs_ntypes[CTF_K_CONST]);
	ctfdump_stat_int("total number of restrict types",
	    g_stats.cs_ntypes[CTF_K_RESTRICT]);
	ctfdump_stat_int("total number of unknowns (holes)",
	    g_stats.cs_ntypes[CTF_K_UNKNOWN]);

	ctfdump_printf(CTFDUMP_STATS, "\n");
	ctfdump_stat_int("total number of struct members", g_stats.cs_nsmembs);
	ctfdump_stat_int("maximum number of struct members", g_stats.cs_nsmax);
	ctfdump_stat_int("total size of all structs", g_stats.cs_structsz);
	ctfdump_stat_int("maximum size of a struct", g_stats.cs_sszmax);
	if (g_stats.cs_ntypes[CTF_K_STRUCT] != 0) {
		ctfdump_stat_fp("average number of struct members",
		    (float)g_stats.cs_nsmembs /
		    (float)g_stats.cs_ntypes[CTF_K_STRUCT]);
		ctfdump_stat_fp("average size of a struct",
		    (float)g_stats.cs_structsz /
		    (float)g_stats.cs_ntypes[CTF_K_STRUCT]);
	}
	ctfdump_printf(CTFDUMP_STATS, "\n");
	ctfdump_stat_int("total number of union members", g_stats.cs_numembs);
	ctfdump_stat_int("maximum number of union members", g_stats.cs_numax);
	ctfdump_stat_int("total size of all unions", g_stats.cs_unionsz);
	ctfdump_stat_int("maximum size of a union", g_stats.cs_uszmax);
	if (g_stats.cs_ntypes[CTF_K_UNION] != 0) {
		ctfdump_stat_fp("average number of union members",
		    (float)g_stats.cs_numembs /
		    (float)g_stats.cs_ntypes[CTF_K_UNION]);
		ctfdump_stat_fp("average size of a union",
		    (float)g_stats.cs_unionsz /
		    (float)g_stats.cs_ntypes[CTF_K_UNION]);
	}
	ctfdump_printf(CTFDUMP_STATS, "\n");

	ctfdump_stat_int("total number of enum members", g_stats.cs_nemembs);
	ctfdump_stat_int("maximum number of enum members", g_stats.cs_nemax);
	if (g_stats.cs_ntypes[CTF_K_ENUM] != 0) {
		ctfdump_stat_fp("average number of enum members",
		    (float)g_stats.cs_nemembs /
		    (float)g_stats.cs_ntypes[CTF_K_ENUM]);
	}
	ctfdump_printf(CTFDUMP_STATS, "\n");

	ctfdump_stat_int("total number of strings", g_stats.cs_nstrings);
	ctfdump_stat_int("bytes of string data", g_stats.cs_strsz);
	ctfdump_stat_int("maximum string length", g_stats.cs_strmax);
	if (g_stats.cs_nstrings != 0)
		ctfdump_stat_fp("average string length",
		    (float)g_stats.cs_strsz / (float)g_stats.cs_nstrings);
	ctfdump_printf(CTFDUMP_STATS, "\n");
}

static void
ctfdump_intenc_name(ctf_encoding_t *cte, char *buf, int len)
{
	int off = 0;
	boolean_t space = B_FALSE;

	if (cte->cte_format == 0 || (cte->cte_format &
	    ~(CTF_INT_SIGNED | CTF_INT_CHAR | CTF_INT_BOOL |
	    CTF_INT_VARARGS)) != 0) {
		(void) snprintf(buf, len, "0x%x", cte->cte_format);
		return;
	}

	if (cte->cte_format & CTF_INT_SIGNED) {
		off += snprintf(buf + off, MAX(len - off, 0), "%sSIGNED",
		    space == B_TRUE ? " " : "");
		space = B_TRUE;
	}

	if (cte->cte_format & CTF_INT_CHAR) {
		off += snprintf(buf + off, MAX(len - off, 0), "%sCHAR",
		    space == B_TRUE ? " " : "");
		space = B_TRUE;
	}

	if (cte->cte_format & CTF_INT_BOOL) {
		off += snprintf(buf + off, MAX(len - off, 0), "%sBOOL",
		    space == B_TRUE ? " " : "");
		space = B_TRUE;
	}

	if (cte->cte_format & CTF_INT_VARARGS) {
		off += snprintf(buf + off, MAX(len - off, 0), "%sVARARGS",
		    space == B_TRUE ? " " : "");
		space = B_TRUE;
	}
}

static int
ctfdump_member_cb(const char *member, ctf_id_t type, ulong_t off, void *arg)
{
	int *count = arg;
	ctfdump_printf(CTFDUMP_TYPES, "\t%s type=%lu off=%lu\n", member, type,
	    off);
	*count = *count + 1;
	return (0);
}

static int
ctfdump_enum_cb(const char *name, int value, void *arg)
{
	int *count = arg;
	ctfdump_printf(CTFDUMP_TYPES, "\t%s = %d\n", name, value);
	*count = *count + 1;
	return (0);
}

static int
ctfdump_types_cb(ctf_id_t id, boolean_t root, void *arg)
{
	int kind, i, count;
	ctf_id_t ref;
	char name[512], ienc[128];
	const char *encn;
	ctf_funcinfo_t ctc;
	ctf_arinfo_t ar;
	ctf_encoding_t cte;
	ssize_t size;

	if ((kind = ctf_type_kind(g_fp, id)) == CTF_ERR)
		ctfdump_fatal("encountered malformed ctf, type %s does not "
		    "have a kind: %s\n", name, ctf_errmsg(ctf_errno(g_fp)));

	if (ctf_type_name(g_fp, id, name, sizeof (name)) == NULL) {
		if (ctf_errno(g_fp) != ECTF_NOPARENT)
			ctfdump_fatal("type %lu missing name: %s\n", id,
			    ctf_errmsg(ctf_errno(g_fp)));
		(void) snprintf(name, sizeof (name), "(unknown %s)",
		    ctf_kind_name(g_fp, kind));
	}

	g_stats.cs_ntypes[kind]++;
	if (root == B_TRUE)
		ctfdump_printf(CTFDUMP_TYPES, "  <%lu> ", id);
	else
		ctfdump_printf(CTFDUMP_TYPES, "  [%lu] ", id);

	switch (kind) {
	case CTF_K_UNKNOWN:
		break;
	case CTF_K_INTEGER:
		if (ctf_type_encoding(g_fp, id, &cte) == CTF_ERR)
			ctfdump_fatal("failed to get encoding information "
			    "for %s: %s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_intenc_name(&cte, ienc, sizeof (ienc));
		ctfdump_printf(CTFDUMP_TYPES,
		    "%s encoding=%s offset=%u bits=%u",
		    name, ienc, cte.cte_offset, cte.cte_bits);
		break;
	case CTF_K_FLOAT:
		if (ctf_type_encoding(g_fp, id, &cte) == CTF_ERR)
			ctfdump_fatal("failed to get encoding information "
			    "for %s: %s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		if (cte.cte_format < 1 || cte.cte_format > 12)
			encn = "unknown";
		else
			encn = ctfdump_fpenc[cte.cte_format];
		ctfdump_printf(CTFDUMP_TYPES, "%s encoding=%s offset=%u "
		    "bits=%u", name, encn, cte.cte_offset, cte.cte_bits);
		break;
	case CTF_K_POINTER:
		if ((ref = ctf_type_reference(g_fp, id)) == CTF_ERR)
			ctfdump_fatal("failed to get reference type for %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "%s refers to %lu", name,
		    ref);
		break;
	case CTF_K_ARRAY:
		if (ctf_array_info(g_fp, id, &ar) == CTF_ERR)
			ctfdump_fatal("failed to get array information for "
			    "%s: %s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "%s contents: %lu, index: %lu",
		    name, ar.ctr_contents, ar.ctr_index);
		break;
	case CTF_K_FUNCTION:
		if (ctf_func_info_by_id(g_fp, id, &ctc) == CTF_ERR)
			ctfdump_fatal("failed to get function info for %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		if (ctc.ctc_argc > 0) {
			ctfdump_fargs_grow(ctc.ctc_argc);
			if (ctf_func_args_by_id(g_fp, id, g_nfargc, g_fargc) ==
			    CTF_ERR)
				ctfdump_fatal("failed to get function "
				    "arguments for %s: %s\n", name,
				    ctf_errmsg(ctf_errno(g_fp)));
		}
		ctfdump_printf(CTFDUMP_TYPES,
		    "%s returns: %lu args: (", name, ctc.ctc_return);
		for (i = 0; i < ctc.ctc_argc; i++) {
			ctfdump_printf(CTFDUMP_TYPES, "%lu%s", g_fargc[i],
			    i + 1 == ctc.ctc_argc ? "" : ", ");
		}
		if (ctc.ctc_flags & CTF_FUNC_VARARG)
			ctfdump_printf(CTFDUMP_TYPES, "%s...",
			    ctc.ctc_argc == 0 ? "" : ", ");
		ctfdump_printf(CTFDUMP_TYPES, ")");
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		size = ctf_type_size(g_fp, id);
		if (size == CTF_ERR)
			ctfdump_fatal("failed to get size of %s: %s\n", name,
			    ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "%s (%d bytes)\n", name, size);
		count = 0;
		if (ctf_member_iter(g_fp, id, ctfdump_member_cb, &count) != 0)
			ctfdump_fatal("failed to iterate members of %s: %s\n",
			    name, ctf_errmsg(ctf_errno(g_fp)));
		if (kind == CTF_K_STRUCT) {
			g_stats.cs_nsmembs += count;
			g_stats.cs_nsmax = MAX(count, g_stats.cs_nsmax);
			g_stats.cs_structsz += size;
			g_stats.cs_sszmax = MAX(size, g_stats.cs_sszmax);
		} else {
			g_stats.cs_numembs += count;
			g_stats.cs_numax = MAX(count, g_stats.cs_numax);
			g_stats.cs_unionsz += size;
			g_stats.cs_uszmax = MAX(count, g_stats.cs_uszmax);
		}
		break;
	case CTF_K_ENUM:
		ctfdump_printf(CTFDUMP_TYPES, "%s\n", name);
		count = 0;
		if (ctf_enum_iter(g_fp, id, ctfdump_enum_cb, &count) != 0)
			ctfdump_fatal("failed to iterate enumerators of %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		g_stats.cs_nemembs += count;
		g_stats.cs_nemax = MAX(g_stats.cs_nemax, count);
		break;
	case CTF_K_FORWARD:
		ctfdump_printf(CTFDUMP_TYPES, "forward %s\n", name);
		break;
	case CTF_K_TYPEDEF:
		if ((ref = ctf_type_reference(g_fp, id)) == CTF_ERR)
			ctfdump_fatal("failed to get reference type for %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "typedef %s refers to %lu", name,
		    ref);
		break;
	case CTF_K_VOLATILE:
		if ((ref = ctf_type_reference(g_fp, id)) == CTF_ERR)
			ctfdump_fatal("failed to get reference type for %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "%s refers to %lu", name,
		    ref);
		break;
	case CTF_K_CONST:
		if ((ref = ctf_type_reference(g_fp, id)) == CTF_ERR)
			ctfdump_fatal("failed to get reference type for %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "%s refers to %lu", name,
		    ref);
		break;
	case CTF_K_RESTRICT:
		if ((ref = ctf_type_reference(g_fp, id)) == CTF_ERR)
			ctfdump_fatal("failed to get reference type for %s: "
			    "%s\n", name, ctf_errmsg(ctf_errno(g_fp)));
		ctfdump_printf(CTFDUMP_TYPES, "%s refers to %lu", name,
		    ref);
		break;
	default:
		ctfdump_fatal("encountered unknown kind for type %s: %d\n",
		    name, kind);
	}

	ctfdump_printf(CTFDUMP_TYPES, "\n");

	return (0);
}

static void
ctfdump_types(void)
{
	ctfdump_title(CTFDUMP_TYPES, "Types");

	if (ctf_type_iter(g_fp, B_TRUE, ctfdump_types_cb, NULL) == CTF_ERR) {
		ctfdump_warn("failed to dump labels: %s\n",
		    ctf_errmsg(ctf_errno(g_fp)));
		g_exit = 1;
	}
}

static void
ctfdump_output(const char *out)
{
	int fd, ret;
	const void *data;
	size_t len;

	ctf_dataptr(g_fp, &data, &len);
	if ((fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0)
		ctfdump_fatal("failed to open output file %s: %s\n", out,
		    strerror(errno));

	while (len > 0) {
		ret = write(fd, data, len);
		if (ret == -1 && errno == EINTR)
			continue;
		else if (ret == -1 && (errno == EFAULT || errno == EBADF))
			abort();
		else if (ret == -1)
			ctfdump_fatal("failed to write to %s: %s\n", out,
			    strerror(errno));
		data += ret;
		len -= ret;
	}

	do {
		ret = close(fd);
	} while (ret == -1 && errno == EINTR);
	if (ret != 0 && errno == EBADF)
		abort();
	if (ret != 0)
		ctfdump_fatal("failed to close %s: %s\n", out, strerror(errno));
}

int
main(int argc, char *argv[])
{
	int c, fd, err;
	const char *ufile = NULL, *parent = NULL;

	g_progname = basename(argv[0]);
	while ((c = getopt(argc, argv, ":dfhlp:sStu:")) != -1) {
		switch (c) {
		case 'd':
			g_dump |= CTFDUMP_OBJECTS;
			break;
		case 'f':
			g_dump |= CTFDUMP_FUNCTIONS;
			break;
		case 'h':
			g_dump |= CTFDUMP_HEADER;
			break;
		case 'l':
			g_dump |= CTFDUMP_LABELS;
			break;
		case 'p':
			parent = optarg;
			break;
		case 's':
			g_dump |= CTFDUMP_STRINGS;
			break;
		case 'S':
			g_dump |= CTFDUMP_STATS;
			break;
		case 't':
			g_dump |= CTFDUMP_TYPES;
			break;
		case 'u':
			g_dump |= CTFDUMP_OUTPUT;
			ufile = optarg;
			break;
		case '?':
			ctfdump_usage("Unknown option: -%c\n", optopt);
			return (2);
		case ':':
			ctfdump_usage("Option -%c requires an operand\n",
			    optopt);
			return (2);
		}
	}

	argc -= optind;
	argv += optind;

	/*
	 * Dump all information by default.
	 */
	if (g_dump == 0)
		g_dump = CTFDUMP_DEFAULT;

	if (argc != 1) {
		ctfdump_usage("no file to dump\n");
		return (2);
	}

	if ((fd = open(argv[0], O_RDONLY)) < 0)
		ctfdump_fatal("failed to open file %s: %s\n", argv[0],
		    strerror(errno));

	g_fp = ctf_fdopen(fd, &err);
	if (g_fp == NULL)
		ctfdump_fatal("failed to open file %s: %s\n", argv[0],
		    ctf_errmsg(err));

	if (parent != NULL) {
		ctf_file_t *pfp = ctf_open(parent, &err);

		if (pfp == NULL)
			ctfdump_fatal("failed to open parent file %s: %s\n",
			    parent, ctf_errmsg(err));
		if (ctf_import(g_fp, pfp) != 0)
			ctfdump_fatal("failed to import parent %s: %s\n",
			    parent, ctf_errmsg(ctf_errno(g_fp)));
	}

	/*
	 * If stats is set, we must run through everything exect CTFDUMP_OUTPUT.
	 * We also do CTFDUMP_STATS last as a result.
	 */
	if (g_dump & CTFDUMP_HEADER)
		ctfdump_header();

	if (g_dump & (CTFDUMP_LABELS | CTFDUMP_STATS))
		ctfdump_labels();

	if (g_dump & (CTFDUMP_OBJECTS | CTFDUMP_STATS))
		ctfdump_objects();

	if (g_dump & (CTFDUMP_FUNCTIONS | CTFDUMP_STATS))
		ctfdump_functions();

	if (g_dump & (CTFDUMP_TYPES | CTFDUMP_STATS))
		ctfdump_types();

	if (g_dump & (CTFDUMP_STRINGS | CTFDUMP_STATS))
		ctfdump_strings();

	if (g_dump & CTFDUMP_STATS)
		ctfdump_stats();

	if (g_dump & CTFDUMP_OUTPUT)
		ctfdump_output(ufile);

	return (g_exit);
}
