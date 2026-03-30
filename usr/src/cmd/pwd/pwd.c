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
 *	Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Print working (current) directory
 *
 * POSIX eventually added two flags in issue 6, which are for -P and -L. -P is
 * basically the mode that has traditionally been used, which should resolve
 * symlinks. -L is a logical mode that is designed to interact with the shell.
 * Basically it says if $PWD is set and meets the following conditions it should
 * be used:
 *
 * 1. It is an absolute path.
 * 2. It does not have any '.' or '..' path components in it.
 * 3. It actually is the current working directory by comparing a stat of that
 *    and '.'.
 *
 * If any of these is not true then it is supposed to fall back to the
 * traditional behavior here.
 *
 * Finally there is one last wrinkle, the default behavior. POSIX mandates that
 * the equivalent of -L be done by default. However, both GNU and *BSD generally
 * follow the traditional default of behaving as though -P is the default. Given
 * the 40+ year history of this command, we maintain that default and do the
 * same thing as others do.
 */

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<limits.h>
#include	<locale.h>
#include	<string.h>
#include	<stdbool.h>
#include	<err.h>
#include	<stdnoreturn.h>
#include	<sys/stat.h>

static char name[PATH_MAX+1];

static noreturn void
usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(gettext(fmt), ap);
		va_end(ap);
	}

	(void) fprintf(stderr, gettext("Usage:  pwd [-L | -P]\n"));
	exit(1);
}

static const char *
getcwd_log(void)
{
	const char *cwd = getenv("PWD");
	if (cwd == NULL || cwd[0] != '/')
		return (NULL);

	/*
	 * Look for path components that aren't solely '.' and '..'.
	 */
	for (size_t i = 0; cwd[i] != '\0'; i++) {
		if (cwd[i] != '/' || cwd[i + 1] != '.')
			continue;

		if (cwd[i + 2] == '\0' || cwd[i + 2] == '/') {
			return (NULL);
		}

		if (cwd[i + 2] == '.' && (cwd[i + 3] == '/' ||
		    cwd[i + 3] == '\0')) {
			return (NULL);
		}
	}

	struct stat log, phys;
	if (stat(cwd, &log) != 0 || stat(".", &phys) != 0 ||
	    log.st_dev != phys.st_dev || log.st_ino != phys.st_ino) {
		return (NULL);
	}

	return (cwd);
}

int
main(int argc, char *argv[])
{
	int c;
	bool Lflag = false;
	const char *cwd = NULL;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, ":LP")) != -1) {
		switch (c) {
		case 'L':
			Lflag = true;
			break;
		case 'P':
			Lflag = false;
			break;
		case ':':
			usage("option -%c requires an argument", optopt);
		case '?':
			usage("unknown option -%c", optopt);
		}
	}

	/*
	 * Historically our implementation of pwd has never checked for this. To
	 * reduce the likelihood of this being a fatal error if someone somehow
	 * gets /usr/bin/pwd, we instead make this a warning.
	 */
	if (argc - optind > 0) {
		warnx(gettext("ignoring unexpected operands starting with %s"),
		    argv[optind]);
	}

	if (Lflag) {
		cwd = getcwd_log();
	}

	if (cwd == NULL) {
		cwd = getcwd(name, PATH_MAX + 1);
		if (cwd == NULL) {
			err(2, gettext("cannot determine current directory"));
		}
	}

	if (puts(cwd) == EOF) {
		err(EXIT_FAILURE, gettext("failed to write out current working "
		    "directory"));
	}

	exit(0);
}
