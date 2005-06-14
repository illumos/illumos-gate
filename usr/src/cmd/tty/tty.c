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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Type tty name
 */

#include <locale.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stermio.h>

int
main(int argc, char **argv)
{
	char	*p;
	int	i;
	int	lflg	= 0;
	int	sflg	= 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	while ((i = getopt(argc, argv, "ls")) != EOF)
		switch (i) {
		case 'l':
			lflg = 1;
			break;
		case 's':
			sflg = 1;
			break;
		case '?':
			(void) printf(gettext("Usage: tty [-l] [-s]\n"));
			return (2);
		}
	p = ttyname(0);
	if (!sflg)
		(void) printf("%s\n", (p? p: gettext("not a tty")));
	if (lflg) {
		if ((i = ioctl(0, STWLINE, 0)) == -1)
			(void) printf(gettext(
			    "not on an active synchronous line\n"));
		else
			(void) printf(gettext("synchronous line %d\n"), i);
	}
	return (p? 0: 1);
}
