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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <locale.h>
#include <sys/stat.h>
#include <fslib.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <poll.h>

#define	MNTTYPE_TMPFS	"tmpfs"

static int	nmflg = 0;
static int	qflg = 0;

static boolean_t
in_mnttab(char *mountp)
{
	FILE *file;
	int found = B_FALSE;
	struct mnttab mntent;

	if ((file = fopen("/etc/mnttab", "r")) == NULL)
		return (B_FALSE);
	while (getmntent(file, &mntent) == 0) {
		if (mntent.mnt_mountp != NULL &&
		    strcmp(mntent.mnt_mountp, mountp) == 0 &&
		    mntent.mnt_fstype != NULL &&
		    strcmp(mntent.mnt_fstype, MNTTYPE_TMPFS) == 0) {
			found = B_TRUE;
			break;
		}
	}
	(void) fclose(file);
	return (found);
}

int
main(int argc, char *argv[])
{
	/* mount information */
	char *special;
	char *mountp;

	int c;
	char *myname;
	char typename[64];
	extern int optind;
	extern char *optarg;
	int error = 0;
	int verbose = 0;
	int mflg = 0;
	int optcnt = 0;
	int mount_attempts = 5;

	char optbuf[MAX_MNTOPT_STR];
	int optsize = 0;
	char *saveoptbuf;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	myname = myname ? myname + 1 : argv[0];
	(void) snprintf(typename, sizeof (typename), "%s_%s",
	    MNTTYPE_TMPFS, myname);
	argv[0] = typename;
	optbuf[0] = '\0';

	while ((c = getopt(argc, argv, "?o:VmOq")) != EOF) {
		switch (c) {
		case 'V':
			verbose++;
			break;
		case '?':
			error++;
			break;
		case 'm':
			nmflg++;
			break;
		case 'O':
			mflg |= MS_OVERLAY;
			break;
		case 'o':
			(void) strncpy(optbuf, optarg, MAX_MNTOPT_STR);
			optbuf[MAX_MNTOPT_STR - 1] = '\0';
			optsize = strlen(optbuf);

			if (verbose)
				(void) fprintf(stderr, "optsize:%d optbuf:%s\n",
				    optsize, optbuf);
			break;
		case 'q':
			qflg++;
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
		    gettext("Usage: %s [-o size] swap mount_point\n"),
		    typename);
		exit(32);
	}

	special = argv[optind++];
	mountp = argv[optind++];
	mflg |= MS_OPTIONSTR;
	mflg |= (nmflg ? MS_NOMNTTAB : 0);

	if (verbose) {
		(void) fprintf(stderr, "mount(%s, \"%s\", %d, %s",
		    special, mountp, mflg, MNTTYPE_TMPFS);
		if (optsize)
			(void) fprintf(stderr, ", \"%s\", %d)\n",
			    optbuf, strlen(optbuf));
		else
			(void) fprintf(stderr, ")\n");
	}
	if (optsize) {
		if ((saveoptbuf = strdup(optbuf)) == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
				"mount");
			exit(1);
		}
	}
again:	if (mount(special, mountp, mflg, MNTTYPE_TMPFS, NULL, 0,
	    optbuf, MAX_MNTOPT_STR)) {
		if (errno == EBUSY && !(mflg & MS_OVERLAY)) {
			/*
			 * Because of bug 6176743, any attempt to mount
			 * tmpfs filesystem could fail for reasons
			 * described in that bug.  We're trying to detect
			 * that situation here by checking that the filesystem
			 * we're mounting is not in /etc/mnttab yet.
			 * When that bug is fixed, this code can be removed.
			 */
			if (!in_mnttab(mountp) && mount_attempts-- > 0) {
				(void) poll(NULL, 0, 50);
				goto again;
			}
			(void) fprintf(stderr, gettext(
			    "%s: %s is already mounted or %s is busy\n"),
			    myname, mountp, special);
		} else {
			perror("mount");
		}
		exit(32);
	}

	if (optsize && !qflg)
		cmp_requested_to_actual_options(saveoptbuf, optbuf,
			special, mountp);
	return (0);
}
