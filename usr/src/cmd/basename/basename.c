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

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void output(char *);
static void usage(void);

int
main(int argc, char **argv)
{
	char	*p;
	char	*string;
	char	*suffix;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1)
		output(".");

	if (strcmp(argv[1], "--") == 0) {
		argv++;
		argc--;
	}

	if (argc == 1)
		output(".");

	if (argc > 3)
		usage();

	string = argv[1];
	suffix = (argc == 2) ? NULL : argv[2];

	if (*string == '\0')
		output(".");

	/* remove trailing slashes */
	p = string + strlen(string) -1;
	while ((p >= string) && (*p == '/'))
		*p-- = '\0';

	if (*string == '\0')
		output("/");

	/* skip to one past last slash */
	if ((p = strrchr(string, '/')) != NULL)
		string = p + 1;

	/*
	 * if a suffix is present and is not the same as the remaining
	 * string and is identical to the last characters in the remaining
	 * string, remove those characters from the string.
	 */
	if (suffix != NULL)
		if (strcmp(string, suffix) != NULL) {
			p = string + strlen(string) - strlen(suffix);
			if (strcmp(p, suffix) == NULL)
				*p = '\0';
		}

	output(string);
	return (0);
}

static void
output(char *string)
{
	(void) printf("%s\n", string);
	exit(0);
}

static void usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage: basename string [ suffix ]\n"));
	exit(1);
}
