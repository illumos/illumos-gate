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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/fs/pc_fs.h>
#include <fslib.h>

extern int	daylight;

/*
 * The "hidden/nohidden" option is private. It is not approved for
 * use (see PSARC/1996/443), which is why it is not in the usage message.
 */
static int roflag = 0;
static char optbuf[MAX_MNTOPT_STR] = { '\0', };
static int optsize = 0;

static struct pcfs_args tz;

int
main(int argc, char *argv[])
{
	char *mnt_special;
	char *mnt_mountp;
	int c;
	char *myname;
	char typename[64];
	char *savedoptbuf;
	extern int optind;
	extern char *optarg;
	int error = 0;
	int verbose = 0;
	int mflg = 0;
	int qflg = 0;
	int optcnt = 0;

	myname = strrchr(argv[0], '/');
	myname = myname ? myname + 1 : argv[0];
	(void) snprintf(typename, sizeof (typename), "%s_%s",
	    MNTTYPE_PCFS, myname);
	argv[0] = typename;

	while ((c = getopt(argc, argv, "Vvmr?o:Oq")) != EOF) {
		switch (c) {
		case 'V':
		case 'v':
			verbose++;
			break;
		case '?':
			error++;
			break;
		case 'r':
			roflag++;
			break;
		case 'm':
			mflg |= MS_NOMNTTAB;
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
			mflg |= MS_OVERLAY;
			break;
		case 'q':
			qflg = 1;
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
		/*
		 * don't hint at options yet (none are really supported)
		 */
		(void) fprintf(stderr, gettext(
		    "Usage: %s [generic options] [-o suboptions] "
		    "special mount_point\n"), typename);
		(void) fprintf(stderr, gettext(
		    "\tpcfs-specific suboptions are:\n"
		    "\t     clamptime,noclamptime\n"
		    "\t     foldcase,nofoldcase\n"));
		exit(32);
	}

	mnt_special = argv[optind++];
	mnt_mountp = argv[optind++];

	(void) tzset();
	tz.secondswest = timezone;
	tz.dsttime = daylight;
	mflg |= MS_DATA;
	if (roflag)
		mflg |= MS_RDONLY;

	if ((savedoptbuf = strdup(optbuf)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    myname);
		exit(2);
	}
	(void) signal(SIGHUP,  SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT,  SIG_IGN);

	if (verbose) {
		(void) fprintf(stderr, "mount(%s, \"%s\", %d, %s",
		    mnt_special, mnt_mountp, mflg, MNTTYPE_PCFS);
	}
	if (mount(mnt_special, mnt_mountp, mflg | MS_OPTIONSTR, MNTTYPE_PCFS,
	    (char *)&tz, sizeof (struct pcfs_args), optbuf, MAX_MNTOPT_STR)) {
		if (errno == EBUSY) {
			(void) fprintf(stderr, gettext(
			    "mount: %s is already mounted or %s is busy\n"),
			    mnt_special, mnt_mountp);
		} else if (errno == EINVAL) {
			(void) fprintf(stderr, gettext(
			    "mount: %s is not a DOS filesystem.\n"),
			    mnt_special);
		} else {
			perror("mount");
		}
		exit(32);
	}

	if (optsize && !qflg)
		cmp_requested_to_actual_options(savedoptbuf, optbuf,
		    mnt_special, mnt_mountp);
	return (0);
}
