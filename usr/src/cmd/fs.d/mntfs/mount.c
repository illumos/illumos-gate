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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/mnttab.h>
#include	<sys/mount.h>
#include	<sys/types.h>
#include 	<locale.h>
#include	<sys/stat.h>
#include	<string.h>

#include	<fslib.h>

#define	NAME_MAX	64	/* sizeof "fstype myname" */

#define	FSTYPE		"mntfs"

static void do_mount(char *, char *, int);
static void usage(void);
static void rpterr(char *, char *);

static char  optbuf[MAX_MNTOPT_STR] = { '\0', };
static int   optsize = 0;

static int	flags = 0;
static int	mflg = 0;	/* don't update /etc/mnttab flag */
static int	Oflg = 0;
static int	qflg = 0;

static char	typename[NAME_MAX], *myname;
static char	fstype[] = FSTYPE;

int
main(int argc, char *argv[])
{
	char	*special, *mountp;
	int	errflag = 0;
	int	cc;

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
	(void) snprintf(typename, sizeof (typename), "%s %s", fstype, myname);
	argv[0] = typename;

	/*
	 *	check for proper arguments
	 */

	while ((cc = getopt(argc, argv, "?rmOo:q")) != -1)
		switch (cc) {
		case 'm':
			mflg++;
			break;
		case 'r':
			flags |= MS_RDONLY;
			break;
		case 'O':
			Oflg++;
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
		case 'q':
			qflg++;
			break;
		case '?':
		default:
			errflag = 1;
			break;
		}

	/*
	 *	There must be at least 2 more arguments, the
	 *	special file and the directory.
	 */

	if (((argc - optind) != 2) || (errflag))
		usage();

	special = argv[optind++];
	mountp = argv[optind++];

	/*
	 *	Perform the mount.
	 */
	if (mflg)
		flags |= MS_NOMNTTAB;
	do_mount(special, mountp, flags);
	return (0);
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
		(void) fprintf(stderr,
gettext("%s: %s not a directory\n\tor a component of %s is not a directory\n"),
			myname, mp, bs);
		break;
	case ENOENT:
		(void) fprintf(stderr,
			gettext("%s: %s or %s, no such file or directory\n"),
			myname, bs, mp);
		break;
	case EINVAL:
		(void) fprintf(stderr, gettext("%s: %s is not this fstype.\n"),
			myname, bs);
		break;
	case EBUSY:
		(void) fprintf(stderr,
			gettext("%s: %s is already mounted or %s is busy\n"),
			myname, bs, mp);
		break;
	case EROFS:
		(void) fprintf(stderr, gettext("%s: %s write-protected\n"),
				myname, bs);
		break;
	case ENOSPC:
		(void) fprintf(stderr,
			gettext("%s: the state of %s is not okay\n"
			"\tand it was attempted to mount read/write\n"),
			myname, bs);
		break;
	default:
		perror(myname);
		(void) fprintf(stderr, gettext("%s: cannot mount %s\n"),
		    myname, bs);
	}
}

static void
do_mount(char *special, char *mountp, int rflag)
{
	char *savedoptbuf;

	if ((savedoptbuf = strdup(optbuf)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    myname);
		exit(1);
	}

	rflag |= Oflg ? MS_OVERLAY : 0;
	if (mount(special, mountp, rflag | MS_OPTIONSTR, fstype, NULL, 0,
	    optbuf, MAX_MNTOPT_STR)) {
		rpterr(special, mountp);
		exit(1);
	}

	if (optsize && !qflg)
		cmp_requested_to_actual_options(savedoptbuf, optbuf,
		    special, mountp);
}

static void
usage(void)
{
	(void) fprintf(stderr,
		gettext("%s usage:\n%s [-F %s] [-r] [-o specific_options] "
		"{special | mount_point}\n%s [-F %s] [-r] [-o specific_options]"
		" special mount_point\n"),
		fstype, myname, fstype, myname, fstype);
	exit(2);
}
