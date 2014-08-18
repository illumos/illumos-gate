/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <fslib.h>

#define	MNTTYPE_BOOTFS "bootfs"

static char  optbuf[MAX_MNTOPT_STR] = { '\0', };
static int   optsize = 0;

static void
usage(void)
{
	(void) fprintf(stderr,
	    "Usage: mount [-Ormq] [-o options] special mountpoint\n");
	exit(2);
}

/*
 * usage: mount [-Ormq] [-o options] special mountp
 *
 * This mount program is exec'ed by /usr/sbin/mount if '-F bootfs' is
 * specified.
 */
int
main(int argc, char *argv[])
{
	int c;
	char *special;		/* Entity being mounted */
	char *mountp;		/* Entity being mounted on */
	char *savedoptbuf;
	char *myname;
	char typename[64];
	int flags = 0;
	int errflag = 0;
	int qflg = 0;

	myname = strrchr(argv[0], '/');
	myname = myname ? myname+1 : argv[0];
	(void) snprintf(typename, sizeof (typename), "%s %s", MNTTYPE_BOOTFS,
	    myname);
	argv[0] = typename;

	while ((c = getopt(argc, argv, "o:rmOq")) != EOF) {
		switch (c) {
		case '?':
			errflag++;
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
		case 'O':
			flags |= MS_OVERLAY;
			break;
		case 'r':
			flags |= MS_RDONLY;
			break;

		case 'm':
			flags |= MS_NOMNTTAB;
			break;

		case 'q':
			qflg = 1;
			break;

		default:
			usage();
		}
	}
	if ((argc - optind != 2) || errflag) {
		usage();
	}
	special = argv[argc - 2];
	mountp = argv[argc - 1];

	if ((savedoptbuf = strdup(optbuf)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    myname);
		exit(2);
	}

	if (mount(special, mountp, flags | MS_OPTIONSTR, MNTTYPE_BOOTFS, NULL,
	    0, optbuf, MAX_MNTOPT_STR)) {
		(void) fprintf(stderr, "mount: ");
		perror(special);
		exit(2);
	}
	if (optsize && !qflg) {
		cmp_requested_to_actual_options(savedoptbuf, optbuf,
		    special, mountp);
	}

	return (0);
}
