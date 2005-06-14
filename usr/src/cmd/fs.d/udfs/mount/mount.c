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
#include <stdlib.h>	/* for getopt(3) */
#include <signal.h>
#include <locale.h>
#include <fslib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mnttab.h>
#include <sys/mount.h>

#define	FSTYPE		"udfs"
#define	NAME_MAX	64

static int roflag = 0;
static int mflag = 0;
static int Oflag = 0;
static int qflag = 0;

static char  optbuf[MAX_MNTOPT_STR] = { '\0', };
static int   optsize = 0;

static char fstype[] = FSTYPE;

static char typename[NAME_MAX], *myname;

static void do_mount(char *, char *, int);
static void rpterr(char *, char *);
static void usage(void);

int
main(int argc, char **argv)
{
	char *special, *mountp;
	int flags = 0;
	int c;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	if (myname) {
		myname++;
	} else {
		myname = argv[0];
	}
	(void) snprintf(typename, sizeof (typename), "%s %s", fstype, myname);
	argv[0] = typename;

	/* check for proper arguments */

	while ((c = getopt(argc, argv, "mo:rOq")) != EOF) {
		switch (c) {
		case 'm':
			mflag++;
			break;
		case 'o':
			if (strlcpy(optbuf, optarg, sizeof (optbuf)) >=
			    sizeof (optbuf)) {
				(void) fprintf(stderr,
				    gettext("%s: Invalid argument: %s\n"),
				    myname, optarg);
				return (2);
			}
			optsize = strlen(optbuf);
			break;
		case 'r':
			roflag++;
			break;
		case 'O':
			Oflag++;
			break;
		case 'q':
			qflag = 1;
			break;
		default :
			break;
		}
	}

	if ((argc - optind) != 2)
		usage();

	special = argv[optind++];
	mountp = argv[optind++];

	if (roflag)
		flags = MS_RDONLY;

	if (optsize > 0) {
		struct mnttab m;

		m.mnt_mntopts = optbuf;
		if (hasmntopt(&m, "m"))
			mflag++;
	}

	flags |= (Oflag ? MS_OVERLAY : 0);
	flags |= (mflag ? MS_NOMNTTAB : 0);


	/*
	 *	Perform the mount.
	 *	Only the low-order bit of "roflag" is used by the system
	 *	calls (to denote read-only or read-write).
	 */
	do_mount(special, mountp, flags);
	return (0);
}


static void
rpterr(char *bs, char *mp)
{
	switch (errno) {
	case EPERM:
		(void) fprintf(stderr,
			gettext("%s: insufficient privileges\n"), myname);
		break;
	case ENXIO:
		(void) fprintf(stderr,
			gettext("%s: %s no such device\n"), myname, bs);
		break;
	case ENOTDIR:
		(void) fprintf(stderr,
			gettext("%s: %s not a directory\n\t"
				"or a component of %s is not a directory\n"),
		    myname, mp, bs);
		break;
	case ENOENT:
		(void) fprintf(stderr,
			gettext("%s: %s or %s, no such file or directory\n"),
			myname, bs, mp);
		break;
	case EINVAL:
		(void) fprintf(stderr,
			gettext("%s: %s is not an udfs file system.\n"),
			typename, bs);
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
		(void) fprintf(stderr,
			gettext("%s: %s write-protected\n"),
			myname, bs);
		break;
	case ENOSPC:
		(void) fprintf(stderr,
			gettext("%s: %s is corrupted. needs checking\n"),
			myname, bs);
		break;
	default:
		perror(myname);
		(void) fprintf(stderr,
			gettext("%s: cannot mount %s\n"), myname, bs);
	}
}


static void
do_mount(char *special, char *mountp, int flag)
{
	char *savedoptbuf;

	if ((savedoptbuf = strdup(optbuf)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    myname);
		exit(2);
	}
	if (mount(special, mountp, flag | MS_DATA | MS_OPTIONSTR,
	    fstype, NULL, 0, optbuf, MAX_MNTOPT_STR) == -1) {
		rpterr(special, mountp);
		exit(31+2);
	}
	if (optsize && !qflag)
		cmp_requested_to_actual_options(savedoptbuf, optbuf,
		    special, mountp);
}


static void
usage(void)
{
	(void) fprintf(stdout, gettext("udfs usage:\n"
			"mount [-F udfs] [generic options] "
			"[-o suboptions] {special | mount_point}\n"));
	(void) fprintf(stdout, gettext("\tsuboptions are: \n"
			"\t	ro,rw,nosuid,remount,m\n"));
	(void) fprintf(stdout, gettext(
			"\t	only one of ro, rw can be "
			"used at the same time\n"));
	(void) fprintf(stdout, gettext(
			"\t	remount can be used only with rw\n"));

	exit(32);
}
