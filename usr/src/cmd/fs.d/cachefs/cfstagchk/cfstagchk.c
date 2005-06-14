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
 * -----------------------------------------------------------------
 *
 *			cfstagchk.c
 *
 * Cache FS admin utility.  Used to read and/or write a
 * cache tag from/to the specified partition.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/vtoc.h>

void pr_err(char *fmt, ...);
void usage(char *);

/*
 * -----------------------------------------------------------------
 *
 *			main
 *
 * Description:
 *	Main routine for the cfstagchk program
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
	int which;

	char *path;

	int wflag;
	int fd, err, slice;
	struct vtoc vtoc;
	struct partition *p;

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

	/* set defaults for command line options */
	wflag = 0;

	/* parse the command line arguments */
	while ((c = getopt(argc, argv, "w")) != EOF) {
		switch (c) {

		case 'w':		/* write */
			wflag = 1;
			break;

		default:
			usage(gettext("illegal option"));
			return (1);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1) {
		usage(gettext("must specify a single device"));
		return (1);
	}

	fd = open(*argv, O_RDWR);
	if (fd < 0) {
		pr_err("can't open %s", *argv);
		return (1);
	}

	slice = read_vtoc(fd, &vtoc);
	if (slice < 0) {
		pr_err(gettext("can't read vtoc"));
		return (1);
	}
	p = &vtoc.v_part[slice];
	if (!wflag) {
		err = 0;
		if (p->p_tag != V_CACHE)
			err++;
	} else {
		p->p_tag = V_CACHE;
		err = write_vtoc(fd, &vtoc);
		if (err < 0)
			pr_err(gettext("write_vtoc failure"));
	}
	return (err);
}

/*
 * -----------------------------------------------------------------
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

void
usage(char *msgp)
{
	fprintf(stderr, gettext("cfstagchk: %s\n"), msgp);
	fprintf(stderr, gettext("usage: cfstagchk [-w] device\n"));
}

/*
 * -----------------------------------------------------------------
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

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, gettext("cfstagchk: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}
