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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>

int
main(int argc, char **argv)
{
	char	*p;
	char	*string;

	/*
	 * For better performance, defer the setlocale()/textdomain()
	 * calls until they get really required.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	if (argc == 1) {
		(void) puts(".");
		return (0);
	}
	if (strcmp(argv[1], "--") == 0) {
		argv++;
		argc--;
		if (argc == 1) {
			(void) puts(".");
			return (0);
		}
	}
	if (argc > 2) {
		(void) setlocale(LC_ALL, "");
		(void) textdomain(TEXT_DOMAIN);
		(void) fprintf(stderr, gettext("Usage: dirname [ path ]\n"));
		return (1);
	}

	string = argv[1];

	if (*string == '\0') {
		(void) puts(".");
		return (0);
	}

	/* remove trailing slashes */
	p = string + strlen(string) - 1;
	while (p >= string && *p == '/')
		*p-- = '\0';

	if (*string == '\0') {
		/* string contained only slashes */
		(void) puts("/");
		return (0);
	}

	/* remove non-slashes */
	while (p >= string && *p != '/')
		*p-- = '\0';

	if (*string == '\0') {
		/* string did not begin with a slash */
		(void) puts(".");
		return (0);
	}

	/* remove slashes delimiting dirname and basename */
	while (p >= string && *p == '/')
		*p-- = '\0';

	if (*string == '\0') {
		/* no dirname part found */
		(void) puts("/");
		return (0);
	}
	/* now string points to dirname part */
	(void) puts(string);
	return (0);
}
