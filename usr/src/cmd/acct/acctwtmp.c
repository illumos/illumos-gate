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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 *	acctwtmp reason /var/adm/wtmpx
 *	writes utmpx.h record (with current time) to specific file
 *	acctwtmp `uname` /var/adm/wtmpx as part of startup
 *	acctwtmp pm /var/adm/wtmpx  (taken down for pm, for example)
 */
#include <stdio.h>
#include <sys/types.h>
#include "acctdef.h"
#include <utmpx.h>
#include <strings.h>
#include <stdlib.h>

struct	utmpx	wb;

int
main(int argc, char **argv)
{
	struct utmpx *p;

	if (argc < 3)
		(void) fprintf(stderr, "Usage: %s reason wtmpx_file\n",
		    argv[0]), exit(1);

	(void) strncpy(wb.ut_line, argv[1], sizeof (wb.ut_line));
	wb.ut_line[11] = '\0';
	wb.ut_type = ACCOUNTING;
	time(&wb.ut_xtime);
	utmpxname(argv[2]);
	setutxent();

	if (pututxline(&wb) == NULL)
		printf("acctwtmp - pututxline failed\n");
	endutxent();
	exit(0);
}
