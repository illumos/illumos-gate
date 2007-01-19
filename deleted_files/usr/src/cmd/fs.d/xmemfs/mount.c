/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/fs/xmem.h>
#include <sys/types.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fslib.h>
#include <stdlib.h>

enum {
	FSSIZE,
	VERBOSE,
	LARGEBSIZE,
#ifdef DEBUG
	NOLARGEBSIZE,
	BSIZE,
	RESERVEMEM,
	NORESERVEMEM,
#endif
	XOPTSZ
};

static char *myopts[] = {
	"size",			/* required */
	"vb",
	"largebsize",
#ifdef DEBUG
	"nolargebsize",		/* default */
	"bsize",		/* internal use only */
	"reservemem",		/* default */
	"noreservemem",
#endif
	NULL
};

static offset_t
atosz(char *optarg)
{
	offset_t	off;
	char		*endptr;

	off = strtoll(optarg, &endptr, 0);

	switch (*endptr) {
	case 't': case 'T':
		off *= 1024;
		/* FALLTHROUGH */
	case 'g': case 'G':
		off *= 1024;
		/* FALLTHROUGH */
	case 'm': case 'M':
		off *= 1024;
		/* FALLTHROUGH */
	case 'k': case 'K':
		off *= 1024;
		/* FALLTHROUGH */
	default:
		break;
	}
	return (off);
}


int
main(int argc, char *argv[])
{
	struct mnttab		mnt;
	int			c;
	char			*myname;
	char			optbuf[MAX_MNTOPT_STR];
	char			typename[64];
	char			*options, *value;
	int			error = 0;
	int			verbose = 0;
	int			nmflg = 0;
	offset_t		fssize = 0;
	offset_t		bsize = 0;
	int			optsize = sizeof (struct xmemfs_args);
	int			mflg = 0;
	int			optcnt = 0;
	int			qflg = 0;
	char			*saveopt;
	struct xmemfs_args	xargs = {
		0,			/* xa_fssize - file system sz */
		0,			/* xa_bsize - blk sz */
		XARGS_RESERVEMEM	/* xa_flags */
	};

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	myname = myname ? myname + 1 : argv[0];
	(void) snprintf(typename, sizeof (typename), "%s_%s", MNTTYPE_XMEMFS,
	    myname);
	argv[0] = typename;

	/* RO xmemfs not supported... */
	(void) strlcpy(optbuf, "rw", sizeof (optbuf));

	while ((c = getopt(argc, argv, "Vqo:mO")) != EOF) {
		switch (c) {
		case 'q':
			qflg++;
			break;
		case 'V':
			verbose++;
			break;
		case 'm':
			nmflg++;
			mflg |= MS_NOMNTTAB;
			break;
		case 'O':
			mflg |= MS_OVERLAY;
			break;
		case 'o':
			options = optarg;
			while (*options != '\0') {
				saveopt = options;

				switch (getsubopt(&options, myopts, &value)) {
				case LARGEBSIZE:
					xargs.xa_flags |= XARGS_LARGEPAGES;
					break;
				case FSSIZE:
					if (value) {
						fssize = atosz(value);
						if (!fssize) {
							(void) fprintf(stderr,
gettext("%s: value %s for option \"%s\" is invalid\n"),
typename, value, myopts[FSSIZE]);
							error++;
							break;
						}
						xargs.xa_fssize = fssize;
						optcnt++;
						if (verbose)
							(void) fprintf(stderr,
gettext("setting fssize to %d\n"), fssize);
					} else {
						(void) fprintf(stderr,
gettext("%s: option \"%s\" requires value\n"), typename, myopts[FSSIZE]);
						error++;
					}
					break;
#ifdef DEBUG
				case RESERVEMEM:
					xargs.xa_flags |= XARGS_RESERVEMEM;
					break;
				case NORESERVEMEM:
					xargs.xa_flags &= ~XARGS_RESERVEMEM;
					break;
				case NOLARGEBSIZE:
					xargs.xa_flags &= ~XARGS_LARGEPAGES;
					break;
				case BSIZE:	/* file system block size */
					if (value) {
						bsize = atosz(value);
						if (!bsize) {
							(void) fprintf(stderr,
gettext("%s: value %s for option \"%s\" is invalid\n"),
typename, value, myopts[FSSIZE]);
							error++;
							break;
						}
						xargs.xa_bsize = bsize;
						optcnt++;
						if (verbose)
							(void) fprintf(stderr,
gettext("setting bsize to %d\n"), bsize);
					} else {
						(void) fprintf(stderr,
gettext("%s: option \"%s\" requires value\n"), typename, myopts[BSIZE]);
						error++;
					}
					break;
#endif

				case VERBOSE:
					verbose++;
					break;
				default:
					if (fsisstdopt(saveopt)) {
						(void) strlcat(optbuf, ",",
						    sizeof (optbuf));
						(void) strlcat(optbuf,
						    saveopt, sizeof (optbuf));
						break;
					}
					if (!qflg) {
						(void) fprintf(stderr, gettext(
						    "%s: WARNING: ignoring "
						    "option \"%s\"\n"),
						    typename, saveopt);
					}

					break;
				}
			}
			if (bsize) {
				(void) snprintf(optbuf, sizeof (optbuf),
				    "%s,bsize=%lld", optbuf, bsize);
				if (--optcnt)
					(void) strlcat(optbuf, ",",
					    sizeof (optbuf));
				if (verbose)
					(void) fprintf(stderr, "optbuf:%s\n",
					    optbuf);
			}
			if (fssize) {
				(void) snprintf(optbuf, sizeof (optbuf),
				    "%s,size=%lld", optbuf, fssize);
				if (--optcnt)
					(void) strlcat(optbuf, ",",
					    sizeof (optbuf));
				if (verbose)
					(void) fprintf(stderr, "optbuf:%s\n",
					    optbuf);
			} else {
				error++;
			}
			if (options[0] && !error) {
				(void) strlcat(optbuf, options,
				    sizeof (optbuf));
				if (verbose)
					(void) fprintf(stderr, "optbuf:%s\n",
					    optbuf);
			}
			if (verbose)
				(void) fprintf(stderr, "optsize:%d optbuf:%s\n",
				    optsize, optbuf);
			break;
		default:
			error++;
			break;
		}
	}

	if (verbose && !error) {
		char *optptr;

		(void) fprintf(stderr, "%s", typename);
		for (optcnt = 1; optcnt < argc; optcnt++) {
			optptr = argv[optcnt];
			if (optptr)
				(void) fprintf(stderr, " %s", optptr);
		}
		(void) fprintf(stderr, "\n");
	}

	if (argc - optind != 2 || error) {
		(void) fprintf(stderr,
		    gettext("Usage: %s -o[largebsize,]size=sz"
				" xmem mount_point\n"), typename);
		exit(1);
	}

	mnt.mnt_special = argv[optind++];
	mnt.mnt_mountp = argv[optind++];
	mnt.mnt_fstype = MNTTYPE_XMEMFS;
	mflg |= MS_DATA | MS_OPTIONSTR;
	mnt.mnt_mntopts = optbuf;

	saveopt = strdup(optbuf);

	if (verbose) {
		(void) fprintf(stderr, "mount(%s, \"%s\", %d, %s",
		    mnt.mnt_special, mnt.mnt_mountp, mflg, MNTTYPE_XMEMFS);
		if (optsize)
			(void) fprintf(stderr, ", \"%s\", %d)\n",
			    optbuf, strlen(optbuf));
		else
			(void) fprintf(stderr, ")\n");
	}
	if (mount(mnt.mnt_special, mnt.mnt_mountp, mflg, MNTTYPE_XMEMFS,
		    &xargs, optsize, optbuf, MAX_MNTOPT_STR)) {
		if (errno == EBUSY)
			(void) fprintf(stderr,
			    gettext("mount: %s already mounted\n"),
			    mnt.mnt_mountp);
		else
			perror("mount");
		exit(1);
	}

	if (!qflg && saveopt != NULL)
		cmp_requested_to_actual_options(saveopt, optbuf,
		    mnt.mnt_special, mnt.mnt_mountp);

	return (0);
}
