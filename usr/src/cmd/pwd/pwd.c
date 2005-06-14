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
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.14	*/
/*
 *	Print working (current) directory
 */

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<limits.h>
#include	<locale.h>
#include	<string.h>

char	name[PATH_MAX+1];

int
main()
{
	if (getcwd(name, PATH_MAX + 1) != NULL) {
		int	length;

		length = strlen(name);
		name[length] = '\n';
		(void) write(1, name, length + 1);
		exit(0);
	}
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	(void) fprintf(stderr,
		gettext("pwd: cannot determine current directory!\n"));
	exit(2);
}
