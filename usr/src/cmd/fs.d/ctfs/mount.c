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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <locale.h>

#define	RET_OK		0
#define	RET_ERR		33
#define	EXIT_MAGIC	2

static void usage(void);

static char  optbuf[MAX_MNTOPT_STR] = { '\0', };
static int   optsize = 0;

static char fstype[] = "ctfs";

/*
 * usage: mount [-Ormq] [-o options] special mountp
 *
 * This mount program is exec'ed by /usr/sbin/mount if '-F ctfs' is
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
	char *typename;
	int flags = 0;
	int error_flag = 0;
	int q_flag = 0;

	int len;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);


	myname = strrchr(argv[0], '/');
	myname = myname ? myname + 1 : argv[0];

	len = strlen(fstype) + 1 + strlen(myname);
	typename = malloc(len + 1);
	if (!typename) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    myname);
		return (EXIT_MAGIC);
	}

	(void) snprintf(typename, len, "%s %s", fstype, myname);
	argv[0] = typename;

	while ((c = getopt(argc, argv, "o:rmOq")) != EOF) {
		switch (c) {
		case '?':
			error_flag = 1;
			break;

		case 'o':
			if (strlcpy(optbuf, optarg, sizeof (optbuf)) >=
			    sizeof (optbuf)) {
				(void) fprintf(stderr,
				    gettext("%s: Invalid argument: %s\n"),
				    myname, optarg);
				free(typename);
				return (EXIT_MAGIC);
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
			q_flag = 1;
			break;

		default:
			usage();
		}
	}
	if ((argc - optind != 2) || error_flag) {
		usage();
	}
	special = argv[argc - 2];
	mountp = argv[argc - 1];

	if ((savedoptbuf = strdup(optbuf)) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    myname);
		free(typename);
		exit(EXIT_MAGIC);
	}
	if (mount(special, mountp, flags | MS_OPTIONSTR, fstype, NULL, 0,
	    optbuf, MAX_MNTOPT_STR)) {
		(void) fprintf(stderr, "mount: ");
		perror(special);
		free(typename);
		exit(RET_ERR);
	}
	if (optsize && !q_flag)
		cmp_requested_to_actual_options(savedoptbuf, optbuf,
		    special, mountp);
	free(typename);
	return (RET_OK);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage: mount [-Ormq] [-o options] special mountpoint\n"));
	exit(RET_ERR);
}
