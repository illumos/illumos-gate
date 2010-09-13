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
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1 */
/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include "libadm.h"

int
getinput(char *s)
{
	char input[MAX_INPUT];
	char *copy, *pt;

	if (!fgets(input, MAX_INPUT, stdin))
		return (1);

	copy = s;
	pt = input;

	while (isspace((unsigned char)*pt))
		++pt;

	while (*pt)
		*copy++ = *pt++;
	*copy = '\0';

	if (copy != s) {
		copy--;
		while (isspace((unsigned char)*copy))
			*copy-- = '\0';
	}
	return (0);
}
