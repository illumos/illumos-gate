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
#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <utmpx.h>
#include <locale.h>
#include <stdlib.h>

struct	utmpx	Ut;
static char time_buf[50];

static int inp(FILE *, struct utmpx *);

int
main(int c, char **v)
{

	int	iflg, cflg;

	(void) setlocale(LC_ALL, "");

	iflg = cflg = 0;

	while (--c > 0) {
		if (**++v == '-')
			while (*++*v)
				switch (**v) {
				case 'c':
					cflg++;
					continue;
				case 'i':
					iflg++;
					continue;
				}
	}

	for (;;) {
		if (iflg) {
			if (inp(stdin, &Ut) == EOF)
				break;
		} else {
			if (fread(&Ut, sizeof (Ut), 1, stdin) != 1)
				break;
		}
		if (cflg)
			fwrite(&Ut, sizeof (Ut), 1, stdout);
		else {
			cftime(time_buf, DATE_FMT, &Ut.ut_xtime);
			printf("%-*.*s %-4.4s %-*.*s %9d %2hd "
			    "%4.4ho %4.4ho %ld %ld %d %hd %-.*s %s",
			    NSZ,
			    NSZ,
			    Ut.ut_name,
			    Ut.ut_id,
			    LINESZ,
			    LINESZ,
			    Ut.ut_line,
			    Ut.ut_pid,
			    Ut.ut_type,
			    Ut.ut_exit.e_termination,
			    Ut.ut_exit.e_exit,
			    Ut.ut_xtime,
			    Ut.ut_tv.tv_usec,
			    Ut.ut_session,
			    Ut.ut_syslen,
			    Ut.ut_syslen,
			    Ut.ut_host,
			    time_buf);
		}
	}
	exit(0);
}

static int
inp(FILE *file, struct utmpx *u)
{

	char	buf[BUFSIZ];
	char *p;
	int i;

	if (fgets((p = buf), BUFSIZ, file) == NULL)
		return (EOF);

	for (i = 0; i < NSZ; i++)	/* Allow a space in name field */
		u->ut_name[i] = *p++;
	for (i = NSZ-1; i >= 0; i--) {
		if (u->ut_name[i] == ' ')
			u->ut_name[i] = '\0';
		else
			break;
	}
	p++;

	for (i = 0; i < 4; i++)
		if ((u->ut_id[i] = *p++) == ' ')
			u->ut_id[i] = '\0';
	p++;

	for (i = 0; i < LINESZ; i++)	/* Allow a space in line field */
		u->ut_line[i] = *p++;
	for (i = LINESZ-1; i >= 0; i--) {
		if (u->ut_line[i] == ' ')
			u->ut_line[i] = '\0';
		else
			break;
	}

	sscanf(p, "%d %hd %ho %ho %ld %ld %d %hd",
		&u->ut_pid,
		&u->ut_type,
		&u->ut_exit.e_termination,
		&u->ut_exit.e_exit,
		&u->ut_xtime,
		&u->ut_tv.tv_usec,
		&u->ut_session,
		&u->ut_syslen);

	if (u->ut_syslen > 1)
		sscanf(p, "%*d %*hd %*ho %*ho %*ld %*ld %*d %*hd %s",
		    u->ut_host);
	else
		u->ut_host[0] = '\0';

	return (1);
}
