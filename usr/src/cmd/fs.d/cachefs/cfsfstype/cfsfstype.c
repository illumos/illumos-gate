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

/*
 *
 *			cfsfstype.c
 *
 * Cache FS admin utility.  Used to glean information out of the
 * rootfs, frontfs, and backfs variables in the kernel.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <ftw.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/filio.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dir.h>


static void pr_err(char *fmt, ...);
static void usage(char *);

/*
 *
 *			main
 *
 * Description:
 *	Main routine for the cfsfstype program.
 * Arguments:
 *	argc	number of command line arguments
 *	argv	command line arguments
 * Returns:
 *	Returns 0 for failure, > 0 for an error.
 * Preconditions:
 */

int
main(int argc, char **argv)
{
	int c;
	int nflag = 0;
	struct statvfs64 svb;
	int fd;

	/* verify root running command */
	if (getuid() != 0) {
		pr_err(gettext("must be run by root"));
		return (1);
	}

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* parse the command line arguments */
	while ((c = getopt(argc, argv, "n")) != EOF) {
		switch (c) {

		case 'n':
			nflag = 1;
			break;

		default:
			usage(gettext("illegal option"));
			return (1);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 1) {
		usage(gettext("too many file names specified"));
		return (1);
	}

	/* if just path is specified, just statvfs it */
	if (!nflag) {
		if (argc != 1) {
			usage(gettext("no file name"));
			return (1);
		}
		if (statvfs64(*argv, &svb) < 0) {
			pr_err(gettext("Cannot open %s: %s"), *argv,
				strerror(errno));
			return (1);
		}
		(void) printf("%s\n", svb.f_basetype);
		return (0);
	}

	fd = open("/", O_RDONLY);
	if (fd < 0) {
		perror(gettext("Open of root directory"));
		return (1);
	}

	if (argc == 1) {
		close(fd);
		fd = open(*argv, O_RDONLY);
		if (fd < 0) {
			perror(gettext("open of specified directory"));
			return (1);
		}
	}

	if (ioctl(fd, _FIOSTOPCACHE)) {
		perror(gettext("Convert ioctl fault"));
		return (1);
	}
	return (0);
}

/*
 *
 *			usage
 *
 * Description:
 *	Prints a usage message for this utility.
 * Arguments:
 *	msgp	message to include with the usage message
 * Returns:
 * Preconditions:
 *	precond(msgp)
 */

static void
usage(char *msgp)
{
	fprintf(stderr, gettext("cfsfstype: %s\n"), msgp);
	fprintf(stderr, gettext("usage: cfsfstype file\n"));
}

/*
 *
 *			pr_err
 *
 * Description:
 *	Prints an error message to stderr.
 * Arguments:
 *	fmt	printf style format
 *	...	arguments for fmt
 * Returns:
 * Preconditions:
 *	precond(fmt)
 */

static void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, gettext("cfsfstype: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}
