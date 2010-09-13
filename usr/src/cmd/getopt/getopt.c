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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

#define	BLOCKLEN	5120

/* incr doesn't include a null termination */
#define	ALLOC_BUFMEM(buf, size, incr) \
	{ \
		size_t	len = strlen(buf); \
		if ((len + incr) >= size) { \
			size = len + incr + 1; \
			if ((buf = (char *)realloc((void *)buf, size)) \
			    == NULL) { \
				(void) fputs( \
				gettext("getopt: Out of memory\n"), stderr); \
				exit(2); \
			} \
		} \
	}

int
main(int argc, char **argv)
{
	int	c;
	int	errflg = 0;
	char	tmpstr[4];
	char	*outstr;
	char	*goarg;
	size_t	bufsize;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2) {
		(void) fputs(gettext("usage: getopt legal-args $*\n"), stderr);
		exit(2);
	}

	goarg = argv[1];
	argv[1] = argv[0];
	argv++;
	argc--;

	bufsize = BLOCKLEN;
	if ((outstr = (char *)malloc(bufsize)) == NULL) {
		(void) fputs(gettext("getopt: Out of memory\n"), stderr);
		exit(2);
	}
	outstr[0] = '\0';

	while ((c = getopt(argc, argv, goarg)) != EOF) {
		if (c == '?') {
			errflg++;
			continue;
		}

		tmpstr[0] = '-';
		tmpstr[1] = (char)c;
		tmpstr[2] = ' ';
		tmpstr[3] = '\0';

		/* If the buffer is full, expand it as appropriate */
		ALLOC_BUFMEM(outstr, bufsize, 3);

		(void) strcat(outstr, tmpstr);

		if (*(strchr(goarg, c)+1) == ':') {
			ALLOC_BUFMEM(outstr, bufsize, strlen(optarg)+1)
			(void) strcat(outstr, optarg);
			(void) strcat(outstr, " ");
		}
	}

	if (errflg) {
		exit(2);
	}

	ALLOC_BUFMEM(outstr, bufsize, 3)
	(void) strcat(outstr, "-- ");
	while (optind < argc) {
		ALLOC_BUFMEM(outstr, bufsize, strlen(argv[optind])+1)
		(void) strcat(outstr, argv[optind++]);
		(void) strcat(outstr, " ");
	}

	(void) printf("%s\n", outstr);
	return (0);
}
