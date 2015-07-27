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
 * diff two CTF containers
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <libctf.h>
#include <libgen.h>
#include <stdarg.h>

#define	CTFDIFF_NAMELEN	256

#define	CTFDIFF_EXIT_SIMILAR	0
#define	CTFDIFF_EXIT_DIFFERENT	1
#define	CTFDIFF_EXIT_USAGE	2
#define	CTFDIFF_EXIT_ERROR	3

typedef enum ctf_diff_cmd {
	CTF_DIFF_TYPES =	0x01,
	CTF_DIFF_FUNCS =	0x02,
	CTF_DIFF_OBJS =		0x04,
	CTF_DIFF_DEFAULT =	0x07,
	CTF_DIFF_LABEL =	0x08,
	CTF_DIFF_ALL =		0x0f
} ctf_diff_cmd_t;

typedef struct {
	int		dil_next;
	const char	**dil_labels;
} ctfdiff_label_t;

static char *g_progname;
static const char *g_iname;
static ctf_file_t *g_ifp;
static const char *g_oname;
static ctf_file_t *g_ofp;
static char **g_typelist = NULL;
static int g_nexttype = 0;
static int g_ntypes = 0;
static char **g_objlist = NULL;
static int g_nextfunc = 0;
static int g_nfuncs = 0;
static char **g_funclist = NULL;
static int g_nextobj = 0;
static int g_nobjs = 0;
static boolean_t g_onlydiff = B_FALSE;
static boolean_t g_different = B_FALSE;
static ctf_diff_cmd_t g_flag = 0;

static void
ctfdiff_fatal(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", g_progname);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(CTFDIFF_EXIT_ERROR);
}

static const char *
ctfdiff_fp_to_name(ctf_file_t *fp)
{
	if (fp == g_ifp)
		return (g_iname);
	if (fp == g_ofp)
		return (g_oname);
	return (NULL);
}

/* ARGSUSED */
static void
ctfdiff_func_cb(ctf_file_t *ifp, ulong_t iidx, boolean_t similar,
    ctf_file_t *ofp, ulong_t oidx, void *arg)
{
	char namebuf[CTFDIFF_NAMELEN];

	if (similar == B_TRUE)
		return;

	if (ctf_symbol_name(ifp, iidx, namebuf, sizeof (namebuf)) == NULL) {
		if (g_nextfunc != 0)
			return;
		(void) printf("ctf container %s function %ld is different\n",
		    ctfdiff_fp_to_name(ifp), iidx);
	} else {
		if (g_nextfunc != 0) {
			int i;
			for (i = 0; i < g_nextfunc; i++) {
				if (strcmp(g_funclist[i], namebuf) == 0)
					break;
			}
			if (i == g_nextfunc)
				return;
		}
		(void) printf("ctf container %s function %s (%ld) is "
		    "different\n", ctfdiff_fp_to_name(ifp), namebuf, iidx);
	}

	g_different = B_TRUE;
}

/* ARGSUSED */
static void
ctfdiff_obj_cb(ctf_file_t *ifp, ulong_t iidx, ctf_id_t iid, boolean_t similar,
    ctf_file_t *ofp, ulong_t oidx, ctf_id_t oid, void *arg)
{
	char namebuf[CTFDIFF_NAMELEN];

	if (similar == B_TRUE)
		return;

	if (ctf_symbol_name(ifp, iidx, namebuf, sizeof (namebuf)) == NULL) {
		if (g_nextobj != 0)
			return;
		(void) printf("ctf container %s object %ld is different\n",
		    ctfdiff_fp_to_name(ifp), iidx);
	} else {
		if (g_nextobj != 0) {
			int i;
			for (i = 0; i < g_nextobj; i++) {
				if (strcmp(g_objlist[i], namebuf) == 0)
					break;
			}
			if (i == g_nextobj)
				return;
		}
		(void) printf("ctf container %s object %s (%ld) is different\n",
		    ctfdiff_fp_to_name(ifp), namebuf, iidx);
	}

	g_different = B_TRUE;
}

/* ARGSUSED */
static void
ctfdiff_cb(ctf_file_t *ifp, ctf_id_t iid, boolean_t similar, ctf_file_t *ofp,
    ctf_id_t oid, void *arg)
{
	if (similar == B_TRUE)
		return;

	if (ctf_type_kind(ifp, iid) == CTF_K_UNKNOWN)
		return;

	/*
	 * Check if it's the type the user cares about.
	 */
	if (g_nexttype != 0) {
		int i;
		char namebuf[CTFDIFF_NAMELEN];

		if (ctf_type_name(ifp, iid, namebuf, sizeof (namebuf)) ==
		    NULL) {
			ctfdiff_fatal("failed to obtain the name "
			    "of type %ld from %s: %s\n",
			    iid, ctfdiff_fp_to_name(ifp),
			    ctf_errmsg(ctf_errno(ifp)));
		}

		for (i = 0; i < g_nexttype; i++) {
			if (strcmp(g_typelist[i], namebuf) == 0)
				break;
		}

		if (i == g_nexttype)
			return;
	}

	g_different = B_TRUE;

	if (g_onlydiff == B_TRUE)
		return;

	(void) printf("ctf container %s type %ld is different\n",
	    ctfdiff_fp_to_name(ifp), iid);
}

/* ARGSUSED */
static int
ctfdiff_labels_count(const char *name, const ctf_lblinfo_t *li, void *arg)
{
	uint32_t *count = arg;
	*count = *count + 1;

	return (0);
}

/* ARGSUSED */
static int
ctfdiff_labels_fill(const char *name, const ctf_lblinfo_t *li, void *arg)
{
	ctfdiff_label_t *dil = arg;

	dil->dil_labels[dil->dil_next] = name;
	dil->dil_next++;

	return (0);
}

static int
ctfdiff_labels(ctf_file_t *ifp, ctf_file_t *ofp)
{
	int ret;
	uint32_t nilabel, nolabel, i, j;
	ctfdiff_label_t idl, odl;
	const char **ilptr, **olptr;

	nilabel = nolabel = 0;
	ret = ctf_label_iter(ifp, ctfdiff_labels_count, &nilabel);
	if (ret == CTF_ERR)
		return (ret);
	ret = ctf_label_iter(ofp, ctfdiff_labels_count, &nolabel);
	if (ret == CTF_ERR)
		return (ret);

	if (nilabel != nolabel) {
		(void) printf("ctf container %s labels differ from ctf "
		    "container %s\n", ctfdiff_fp_to_name(ifp),
		    ctfdiff_fp_to_name(ofp));
		g_different = B_TRUE;
		return (0);
	}

	if (nilabel == 0)
		return (0);

	ilptr = malloc(sizeof (char *) * nilabel);
	olptr = malloc(sizeof (char *) * nolabel);
	if (ilptr == NULL || olptr == NULL) {
		ctfdiff_fatal("failed to allocate memory for label "
		    "comparison\n");
	}

	idl.dil_next = 0;
	idl.dil_labels = ilptr;
	odl.dil_next = 0;
	odl.dil_labels = olptr;

	if ((ret = ctf_label_iter(ifp, ctfdiff_labels_fill, &idl)) != 0)
		goto out;
	if ((ret = ctf_label_iter(ofp, ctfdiff_labels_fill, &odl)) != 0)
		goto out;

	for (i = 0; i < nilabel; i++) {
		for (j = 0; j < nolabel; j++) {
			if (strcmp(ilptr[i], olptr[j]) == 0)
				break;
		}

		if (j == nolabel) {
			(void) printf("ctf container %s labels differ from ctf "
			    "container %s\n", ctfdiff_fp_to_name(ifp),
			    ctfdiff_fp_to_name(ofp));
			g_different = B_TRUE;
			break;
		}
	}

	ret = 0;
out:
	free(ilptr);
	free(olptr);
	return (ret);
}

static void
ctfdiff_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", g_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s [-afIloqt] [-F function] [-O object]"
	    "[-p parent] [-P parent]\n"
	    "\t[-T type] file1 file2\n"
	    "\n"
	    "\t-a diff label, types, objects, and functions\n"
	    "\t-f diff function type information\n"
	    "\t-F when diffing functions, only consider those named\n"
	    "\t-I ignore the names of integral types\n"
	    "\t-l diff CTF labels\n"
	    "\t-o diff global object type information\n"
	    "\t-O when diffing objects, only consider those named\n"
	    "\t-p set the CTF parent for file1\n"
	    "\t-P set the CTF parent for file2\n"
	    "\t-q set quiet mode (no diff information sent to stdout)\n"
	    "\t-t diff CTF type information\n"
	    "\t-T when diffing types, only consider those named\n",
	    g_progname);
}

int
main(int argc, char *argv[])
{
	ctf_diff_flag_t flags = 0;
	int err, c;
	ctf_file_t *ifp, *ofp;
	ctf_diff_t *cdp;
	ctf_file_t *pifp = NULL;
	ctf_file_t *pofp = NULL;

	g_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":aqtfolIp:F:O:P:T:")) != -1) {
		switch (c) {
		case 'a':
			g_flag |= CTF_DIFF_ALL;
			break;
		case 't':
			g_flag |= CTF_DIFF_TYPES;
			break;
		case 'f':
			g_flag |= CTF_DIFF_FUNCS;
			break;
		case 'o':
			g_flag |= CTF_DIFF_OBJS;
			break;
		case 'l':
			g_flag |= CTF_DIFF_LABEL;
			break;
		case 'q':
			g_onlydiff = B_TRUE;
			break;
		case 'p':
			pifp = ctf_open(optarg, &err);
			if (pifp == NULL) {
				ctfdiff_fatal("failed to open parent input "
				    "container %s: %s\n", optarg,
				    ctf_errmsg(err));
			}
			break;
		case 'F':
			if (g_nextfunc == g_nfuncs) {
				if (g_nfuncs == 0)
					g_nfuncs = 16;
				else
					g_nfuncs *= 2;
				g_funclist = realloc(g_funclist,
				    sizeof (char *) * g_nfuncs);
				if (g_funclist == NULL) {
					ctfdiff_fatal("failed to allocate "
					    "memory for the %dth -F option: "
					    "%s\n", g_nexttype + 1,
					    strerror(errno));
				}
			}
			g_funclist[g_nextfunc] = optarg;
			g_nextfunc++;
			break;
		case 'O':
			if (g_nextobj == g_nobjs) {
				if (g_nobjs == 0)
					g_nobjs = 16;
				else
					g_nobjs *= 2;
				g_objlist = realloc(g_objlist,
				    sizeof (char *) * g_nobjs);
				if (g_objlist == NULL) {
					ctfdiff_fatal("failed to allocate "
					    "memory for the %dth -F option: "
					    "%s\n", g_nexttype + 1,
					    strerror(errno));
					return (CTFDIFF_EXIT_ERROR);
				}
			}
			g_objlist[g_nextobj] = optarg;
			g_nextobj++;
			break;
		case 'I':
			flags |= CTF_DIFF_F_IGNORE_INTNAMES;
			break;
		case 'P':
			pofp = ctf_open(optarg, &err);
			if (pofp == NULL) {
				ctfdiff_fatal("failed to open parent output "
				    "container %s: %s\n", optarg,
				    ctf_errmsg(err));
			}
			break;
		case 'T':
			if (g_nexttype == g_ntypes) {
				if (g_ntypes == 0)
					g_ntypes = 16;
				else
					g_ntypes *= 2;
				g_typelist = realloc(g_typelist,
				    sizeof (char *) * g_ntypes);
				if (g_typelist == NULL) {
					ctfdiff_fatal("failed to allocate "
					    "memory for the %dth -T option: "
					    "%s\n", g_nexttype + 1,
					    strerror(errno));
				}
			}
			g_typelist[g_nexttype] = optarg;
			g_nexttype++;
			break;
		case ':':
			ctfdiff_usage("Option -%c requires an operand\n",
			    optopt);
			return (CTFDIFF_EXIT_USAGE);
		case '?':
			ctfdiff_usage("Unknown option: -%c\n", optopt);
			return (CTFDIFF_EXIT_USAGE);
		}
	}

	argc -= optind - 1;
	argv += optind - 1;

	if (g_flag == 0)
		g_flag = CTF_DIFF_DEFAULT;

	if (argc != 3) {
		ctfdiff_usage(NULL);
		return (CTFDIFF_EXIT_USAGE);
	}

	if (g_nexttype != 0 && !(g_flag & CTF_DIFF_TYPES)) {
		ctfdiff_usage("-T cannot be used if not diffing types\n");
		return (CTFDIFF_EXIT_USAGE);
	}

	if (g_nextfunc != 0 && !(g_flag & CTF_DIFF_FUNCS)) {
		ctfdiff_usage("-F cannot be used if not diffing functions\n");
		return (CTFDIFF_EXIT_USAGE);
	}

	if (g_nextobj != 0 && !(g_flag & CTF_DIFF_OBJS)) {
		ctfdiff_usage("-O cannot be used if not diffing objects\n");
		return (CTFDIFF_EXIT_USAGE);
	}

	ifp = ctf_open(argv[1], &err);
	if (ifp == NULL) {
		ctfdiff_fatal("failed to open %s: %s\n", argv[1],
		    ctf_errmsg(err));
	}
	if (pifp != NULL) {
		err = ctf_import(ifp, pifp);
		if (err != 0) {
			ctfdiff_fatal("failed to set parent container: %s\n",
			    ctf_errmsg(ctf_errno(pifp)));
		}
	}
	g_iname = argv[1];
	g_ifp = ifp;

	ofp = ctf_open(argv[2], &err);
	if (ofp == NULL) {
		ctfdiff_fatal("failed to open %s: %s\n", argv[2],
		    ctf_errmsg(err));
	}

	if (pofp != NULL) {
		err = ctf_import(ofp, pofp);
		if (err != 0) {
			ctfdiff_fatal("failed to set parent container: %s\n",
			    ctf_errmsg(ctf_errno(pofp)));
		}
	}
	g_oname = argv[2];
	g_ofp = ofp;

	if (ctf_diff_init(ifp, ofp, &cdp) != 0) {
		ctfdiff_fatal("failed to initialize libctf diff engine: %s\n",
		    ctf_errmsg(ctf_errno(ifp)));
	}

	if (ctf_diff_setflags(cdp, flags) != 0) {
		ctfdiff_fatal("failed to set ctfdiff flags: %s\n",
		    ctf_errmsg(ctf_errno(ifp)));
	}

	err = 0;
	if ((g_flag & CTF_DIFF_TYPES) && err != CTF_ERR)
		err = ctf_diff_types(cdp, ctfdiff_cb, NULL);
	if ((g_flag & CTF_DIFF_FUNCS) && err != CTF_ERR)
		err = ctf_diff_functions(cdp, ctfdiff_func_cb, NULL);
	if ((g_flag & CTF_DIFF_OBJS) && err != CTF_ERR)
		err = ctf_diff_objects(cdp, ctfdiff_obj_cb, NULL);
	if ((g_flag & CTF_DIFF_LABEL) && err != CTF_ERR)
		err = ctfdiff_labels(ifp, ofp);

	ctf_diff_fini(cdp);
	if (err == CTF_ERR) {
		ctfdiff_fatal("encountered a libctf error: %s!\n",
		    ctf_errmsg(ctf_errno(ifp)));
	}

	return (g_different == B_TRUE ? CTFDIFF_EXIT_DIFFERENT :
	    CTFDIFF_EXIT_SIMILAR);
}
