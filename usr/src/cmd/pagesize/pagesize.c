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
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

int
main(int argc, char *argv[])
{

	int c, mps = 0;
	size_t *buf;
	int nelem, i;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, (char * const *)argv, "a")) != -1) {
		switch (c) {
		case 'a':
			mps = 1;
			break;
		case '?':
			(void) fprintf(stderr,
					gettext("usage: pagesize [-a]\n"));
			exit(1);
		}
	}

	if (!mps) {
		(void) printf("%d\n", getpagesize());
		exit(0);
	}

	nelem = getpagesizes(NULL, 0);
	if (nelem < 2) {
		(void) printf("%d\n", getpagesize());
		exit(0);
	}

	if ((buf = (size_t *)malloc(sizeof (*buf) * nelem)) == NULL) {
		(void) fprintf(stderr, gettext("Can't get memory\n"));
		exit(1);
	}

	nelem = getpagesizes(buf, nelem);
	for (i = 0; i < nelem; i++) {
		(void) fprintf(stdout, "%d\n", buf[i]);
	}
	free(buf);
	return (0);
}
