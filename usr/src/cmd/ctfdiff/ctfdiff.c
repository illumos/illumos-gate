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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * diff two CTF containers
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <libctf.h>

#define	CTFDIFF_EXIT_SIMILAR	0
#define	CTFDIFF_EXIT_DIFFERENT	1
#define	CTFDIFF_EXIT_ERROR	2

static const char *g_iname;
static ctf_file_t *g_ifp;
static const char *g_oname;
static ctf_file_t *g_ofp;
static char **g_typelist = NULL;
static int g_nexttype = 0;
static int g_ntypes = 0;
static boolean_t g_onlydiff = B_FALSE;
static boolean_t g_different = B_FALSE;

static const char *
fp_to_name(ctf_file_t *fp)
{
	if (fp == g_ifp)
		return (g_iname);
	if (fp == g_ofp)
		return (g_oname);
	return (NULL);
}

/* ARGSUSED */
static void
diff_cb(ctf_file_t *ifp, ctf_id_t iid, boolean_t similar, ctf_file_t *ofp,
    ctf_id_t oid, void *arg)
{
	if (similar == B_TRUE)
		return;

	/*
	 * Check if it's the type the user cares about.
	 */
	if (g_nexttype != 0) {
		int i;
		char namebuf[256];

		if (ctf_type_name(ifp, iid, namebuf, sizeof (namebuf)) ==
		    NULL) {
			(void) fprintf(stderr, "failed to obtain the name "
			    "of type %ld from %s: %s\n",
			    iid, fp_to_name(ifp),
			    ctf_errmsg(ctf_errno(ifp)));
			exit(CTFDIFF_EXIT_ERROR);
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

	(void) printf("fp %s type %ld ", fp_to_name(ifp), iid);
	if (similar == B_TRUE) {
		(void) printf("is the same as fp %s type %ld\n",
		    fp_to_name(ofp), oid);
	} else {
		(void) printf("is different\n");
	}
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

	while ((c = getopt(argc, argv, "qIp:P:T:")) != -1) {
		switch (c) {
		case 'q':
			g_onlydiff = B_TRUE;
			break;
		case 'p':
			pifp = ctf_open(optarg, &err);
			if (pifp == NULL) {
				(void) fprintf(stderr, "ctfdiff: failed to "
				    "open parent input container %s: %s\n",
				    optarg, ctf_errmsg(err));
				return (CTFDIFF_EXIT_ERROR);
			}
			break;
		case 'I':
			flags |= CTF_DIFF_F_IGNORE_INTNAMES;
			break;
		case 'P':
			pofp = ctf_open(optarg, &err);
			if (pofp == NULL) {
				(void) fprintf(stderr, "ctfdiff: failed to "
				    "open parent output container %s: %s\n",
				    optarg, ctf_errmsg(err));
				return (CTFDIFF_EXIT_ERROR);
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
					(void) fprintf(stderr, "ctfdiff: "
					    "failed to allocate memory for "
					    "the %dth -t option: %s\n",
					    g_nexttype + 1, strerror(errno));
				}
			}
			g_typelist[g_nexttype] = optarg;
			g_nexttype++;
		}
	}

	argc -= optind - 1;
	argv += optind - 1;

	if (argc != 3) {
		(void) fprintf(stderr, "usage: ctfdiff [-qI] [-p parent] "
		    "[-P parent] [-T type]... input output");
		return (CTFDIFF_EXIT_ERROR);
	}

	ifp = ctf_open(argv[1], &err);
	if (ifp == NULL) {
		(void) fprintf(stderr, "ctfdiff: failed to open %s: %s\n",
		    argv[1], ctf_errmsg(err));
		return (CTFDIFF_EXIT_ERROR);
	}
	if (pifp != NULL) {
		err = ctf_import(ifp, pifp);
		if (err != 0) {
			(void) fprintf(stderr, "ctfdiff: failed to set parent "
			    "container: %s\n", ctf_errmsg(ctf_errno(pifp)));
			return (CTFDIFF_EXIT_ERROR);
		}
	}
	g_iname = argv[1];
	g_ifp = ifp;

	ofp = ctf_open(argv[2], &err);
	if (ofp == NULL) {
		(void) fprintf(stderr, "ctfdiff: failed to open %s: %s\n",
		    argv[2], ctf_errmsg(err));
		return (CTFDIFF_EXIT_ERROR);
	}

	if (pofp != NULL) {
		err = ctf_import(ofp, pofp);
		if (err != 0) {
			(void) fprintf(stderr, "ctfdiff: failed to set parent "
			    "container: %s\n", ctf_errmsg(ctf_errno(pofp)));
			return (CTFDIFF_EXIT_ERROR);
		}
	}
	g_oname = argv[2];
	g_ofp = ofp;

	if (ctf_diff_init(ifp, ofp, &cdp) != 0) {
		(void) fprintf(stderr,
		    "ctfdiff: failed to initialize libctf diff engine: %s\n",
		    ctf_errmsg(ctf_errno(ifp)));
		return (CTFDIFF_EXIT_ERROR);
	}

	if (ctf_diff_setflags(cdp, flags) != 0) {
		(void) fprintf(stderr,
		    "ctfdiff: failed to set ctfdiff flags: %s\n",
		    ctf_errmsg(ctf_errno(ifp)));
	}

	err = ctf_diff_types(cdp, diff_cb, NULL);
	ctf_diff_fini(cdp);
	if (err == CTF_ERR) {
		(void) fprintf(stderr, "encountered a libctf error: %s!\n",
		    ctf_errmsg(ctf_errno(ifp)));
		return (CTFDIFF_EXIT_ERROR);
	}

	return (g_different == B_TRUE ? CTFDIFF_EXIT_DIFFERENT :
	    CTFDIFF_EXIT_SIMILAR);
}
