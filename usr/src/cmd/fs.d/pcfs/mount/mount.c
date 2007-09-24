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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

static int roflag = 0;
static char optbuf[MAX_MNTOPT_STR] = { '\0', };
static int optsize = 0;


/*
 * Since the format/value expected for the mount options listed below
 * differs between what the user mount command expects and what the
 * kernel module can grok, we transmogrify the mount option string
 * for such options. Others are copied through as-is.
 */
static char *pcfs_opts[] = { MNTOPT_PCFS_TIMEZONE, NULL };
#define	ARG_PCFS_TIMEZONE	0

/*
 * While constructing the mount option string, we need to append
 * comma separators if there have been previous options copied over
 * from the input string. This takes care of it.
 */
static int
append_opt(char *str, int strsz, char *opt)
{
	if (str[0] != '\0' && strlcat(str, ",", strsz) >= strsz)
		return (0);

	return (strlcat(str, opt, strsz) < strsz);
}

int
main(int argc, char *argv[])
{
	char *mnt_special;
	char *mnt_mountp;
	int c;
	char *myname;
	char typename[64];
	char tzstr[100];
	char *tzval;
	char *savedoptbuf = NULL, *savedoptarg = NULL;
	char *in_arg, *val, *curarg;
	extern int optind;
	extern char *optarg;
	int error = 0;
	int verbose = 0;
	int mflg = MS_OPTIONSTR;	/* we always pass mount options */
	int qflg = 0;
	int optcnt = 0;
	int tzdone = 0;

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
			in_arg = optarg;
			if ((savedoptarg = strdup(optarg)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"), myname);
				exit(2);
			}
			while (*in_arg != '\0') {
				curarg = in_arg;

				switch (getsubopt(&in_arg, pcfs_opts, &val)) {
				case ARG_PCFS_TIMEZONE:
					if (tzdone || val == NULL)
						goto invalarg;
					tzval = val;
					(void) snprintf(tzstr, 100,
					    "TZ=%s", tzval);
					tzstr[99] = '\0';
					(void) putenv(tzstr);
					tzdone = 1;
					break;
				default:
					/*
					 * Remove empty suboptions
					 * (happens on sequences of commas)
					 */
					if (*curarg == '\0')
						break;

					if (append_opt(optbuf, sizeof (optbuf),
					    curarg) == 0)
						goto invalarg;
				}
			}
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
		    "\t     hidden,nohidden\n"
		    "\t     atime,noatime\n"
		    "\t     foldcase,nofoldcase\n"
		    "\t     timezone=<valid TZ string>"));
		exit(32);
	}

	mnt_special = argv[optind++];
	mnt_mountp = argv[optind++];

	/*
	 * Pass timezone information to the kernel module so that
	 * FAT timestamps, as per spec, can be recorded in local time.
	 */
	tzset();
	/*
	 * We perform this validation only in case the user of
	 * mount(1m) specified the "timezone=..." option. That's
	 * because we don't want PCFS mounts to fail due to a
	 * botched $TZ environment variable. If the admin's
	 * environment contains garbage, it'll just parse as
	 * GMT (timezone=0).
	 */
	if (tzdone && timezone == 0 && altzone == 0 && daylight == 0 &&
	    strcmp(tzname[0], tzval) &&
	    strspn(tzname[1], " ") == strlen(tzname[1])) {
		goto invalarg;
	}
	(void) snprintf(tzstr, 100, "timezone=%d", timezone);
	tzstr[99] = '\0';
	if (append_opt(optbuf, sizeof (optbuf), tzstr) == 0)
		goto invalarg;

	optsize = strlen(optbuf);

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
	if (mount(mnt_special, mnt_mountp, mflg, MNTTYPE_PCFS,
	    NULL, 0, optbuf, MAX_MNTOPT_STR)) {
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

invalarg:
	(void) fprintf(stderr,
	    gettext("%s: Invalid mount options: %s\n"), myname, savedoptarg);
	return (2);
}
