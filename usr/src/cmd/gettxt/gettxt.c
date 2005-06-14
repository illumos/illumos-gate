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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>
#include <libgen.h>

int
main(int argc, char **argv)
{
	char	*dfltp;
	char	*locp;

	locp = setlocale(LC_ALL, "");
	if (locp == NULL) {
		(void) setlocale(LC_CTYPE, "");
		(void) setlocale(LC_MESSAGES, "");
	}
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (argc != 2 && argc != 3) {
		(void) fprintf(stderr, gettext("Incorrect usage.\n"));
		(void) fprintf(stderr,
		    gettext("usage: gettxt msgid [ dflt_msg ] \n"));
		exit(1);
	}


	if (argc == 2) {
		(void) fputs(gettxt(argv[1], ""), stdout);
		exit(0);
	}

	if ((dfltp = malloc(strlen(argv[2] + 1))) == (char *)NULL) {
		(void) fprintf(stderr, gettext("malloc failed\n"));
		exit(1);
	}

	(void) strccpy(dfltp, argv[2]);

	(void) fputs(gettxt(argv[1], dfltp), stdout);

	free(dfltp);

	return (0);
}
