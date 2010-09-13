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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>	/* defines F_LOCK for lockf */
#include <stdlib.h>	/* for getopt(3) */
#include <signal.h>
#include <locale.h>
#include <fslib.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/fs/hsfs_susp.h>
#include <sys/fs/hsfs_rrip.h>

extern int optind;
extern char *optarg;

#define	NAME_MAX	64
#define	GLOBAL		0
#define	NOGLOBAL	1

#ifndef	MNTOPT_NOGLOBAL
#define	MNTOPT_NOGLOBAL	"noglobal"
#endif	/* MNTOPT_NOGLOBAL */

static int gflg		= 0;	/* mount into global name space: flag form */
static int global	= 0;	/* mount into global name space: option form */
static int havegblopt	= 0;	/* global value supercedes gflg value */
static int qflg		= 0;	/* quiet option - don't flag bad options */

static char fstype[] = MNTTYPE_HSFS;

static char typename[NAME_MAX], *myname;
/*
 * Mount options that require special handling
 */
static char *myopts[] = {
	MNTOPT_GLOBAL,
	MNTOPT_NOGLOBAL,
	NULL
};


static void rpterr(char *, char *);
static void usage(void);

int
main(int argc, char **argv)
{
	char *options, *value;
	char *special, *mountp;
	char *gopt;
	struct mnttab mm;
	int c;
	char	obuff[MAX_MNTOPT_STR];
	char	saved_input_options[MAX_MNTOPT_STR];
	int hsfs_flags;

	int flags;
	int Oflg = 0;   /* Overlay mounts */

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	if (myname)
		myname++;
	else
		myname = argv[0];
	snprintf(typename, sizeof (typename), "%s %s", fstype, myname);
	argv[0] = typename;

	/*
	 * Check for arguments requiring special handling.  Ignore
	 * unrecognized options.
	 */
	strcpy(obuff, "ro");	/* default */
	while ((c = getopt(argc, argv, "o:rmOgq")) != EOF) {
		switch (c) {
			case 'o':
				if (strlen(optarg) > MAX_MNTOPT_STR) {
					(void) fprintf(stderr, gettext(
					    "%s: option set too long\n"),
					    myname);
					exit(1);
				}
				if (strlen(optarg) == 0) {
					(void) fprintf(stderr, gettext(
					    "%s: missing suboptions\n"),
					    myname);
					exit(1);
				}
				strcpy(obuff, optarg);
				options = optarg;
				while (*options != '\0') {
					switch (getsubopt(&options, myopts,
					    &value)) {
					case GLOBAL:
						havegblopt = 1;
						global = 1;
						break;
					case NOGLOBAL:
						havegblopt = 1;
						global = 0;
						break;
					}
				}
				break;
			case 'O':
				Oflg++;
				break;
			case 'r':
				/* accept for backwards compatibility */
				break;
			case 'm':
				break;
			case 'g':
				gflg++;
				break;
			case 'q':
				qflg++;
				break;

		}
	}

	if ((argc - optind) != 2)
		usage();

	special = argv[optind++];
	mountp = argv[optind++];

	/*
	 * Force readonly.  obuff is guaranteed to have something in
	 * it.  We might end up with "ro,ro", but that's acceptable.
	 */
	flags = MS_RDONLY;

	if ((strlen(obuff) + strlen(MNTOPT_RO) + 2) > MAX_MNTOPT_STR) {
		(void) fprintf(stderr, gettext("%s: option set too long\n"),
		    myname);
		exit(1);
	}

	strcat(obuff, ",");
	strcat(obuff, MNTOPT_RO);

	flags |= Oflg ? MS_OVERLAY : 0;

	/*
	 * xxx it's not clear if should just put MS_GLOBAL in flags,
	 * or provide it as a string.  Be safe, do both.  The subopt
	 * version has precedence over the switch version.
	 */
	gopt = NULL;
	if ((havegblopt && global) || gflg) {
		gopt = MNTOPT_GLOBAL;
		flags |= MS_GLOBAL;
	} else if (havegblopt) {
		gopt = MNTOPT_NOGLOBAL;
	}

	if (gopt != NULL) {
		if ((strlen(obuff) + strlen(gopt) + 2) > MAX_MNTOPT_STR) {
			(void) fprintf(stderr,
			    gettext("%s: option set too long\n"), myname);
			exit(1);
		}

		strcat(obuff, ",");
		strcat(obuff, gopt);
	}

	signal(SIGHUP,  SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT,  SIG_IGN);

	/*
	 * Save a copy of the options to compare with the options that
	 * were actually recognized and supported by the kernel.
	 */

	(void) strcpy(saved_input_options, obuff);

	/*
	 * Perform the mount.
	 */

	if (mount(special, mountp, flags | MS_OPTIONSTR, fstype, NULL, 0,
		obuff, sizeof (obuff)) == -1) {
		rpterr(special, mountp);
		exit(31+2);
	}

	if (!qflg) {
		cmp_requested_to_actual_options(saved_input_options, obuff,
			special, mountp);
	}

	exit(0);
	/* NOTREACHED */
}


static void
rpterr(char *bs, char *mp)
{
	switch (errno) {
	case EPERM:
		(void) fprintf(stderr, gettext("%s: insufficient privileges\n"),
		    myname);
		break;
	case ENXIO:
		(void) fprintf(stderr, gettext("%s: %s no such device\n"),
		    myname, bs);
		break;
	case ENOTDIR:
		(void) fprintf(stderr, gettext("%s: %s not a directory\n\tor a "
		    "component of %s is not a directory\n"), myname, mp, bs);
		break;
	case ENOENT:
		(void) fprintf(stderr,
		    gettext("%s: %s or %s, no such file or directory\n"),
		    myname, bs, mp);
		break;
	case EINVAL:
		(void) fprintf(stderr, gettext("%s: %s is not an hsfs file "
		    "system.\n"), typename, bs);
		break;
	case EBUSY:
		(void) fprintf(stderr,
		    gettext("%s: %s is already mounted or %s is busy\n"),
		    myname, bs, mp);
		break;
	case ENOTBLK:
		(void) fprintf(stderr,
		    gettext("%s: %s not a block device\n"), myname, bs);
		break;
	case EROFS:
		(void) fprintf(stderr, gettext("%s: %s write-protected\n"),
		    myname, bs);
		break;
	case ENOSPC:
		(void) fprintf(stderr,
		    gettext("%s: %s is corrupted. needs checking\n"),
		    myname, bs);
		break;
	default:
		perror(myname);
		(void) fprintf(stderr, gettext("%s: cannot mount %s\n"), myname,
		    bs);
	}
}


static void
usage()
{
	char *opts;

opts = "{-r | -o ro | -o nrr | -o nosuid | -o notraildot | -o nomaplcase}";
	(void) fprintf(stdout,
gettext("hsfs usage: mount [-F hsfs] %s {special | mount_point}\n"), opts);
	(void) fprintf(stdout,
gettext("hsfs usage: mount [-F hsfs] %s special mount_point\n"), opts);
	exit(32);
}
