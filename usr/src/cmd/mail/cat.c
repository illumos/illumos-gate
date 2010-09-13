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


#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 1.3	*/
/*
    NAME
	cat - concatenate two strings

    SYNOPSIS
	void cat(char *to, char *from1, char *from2)

    DESCRIPTION
	cat() concatenates "from1" and "from2" to "to"
		to	-> destination string
		from1	-> source string
		from2	-> source string
*/
#include "mail.h"
void
cat(to, from1, from2)
register char *to, *from1, *from2;
{
	for (; *from1;) *to++ = *from1++;
	for (; *from2;) *to++ = *from2++;
	*to = '\0';
}
