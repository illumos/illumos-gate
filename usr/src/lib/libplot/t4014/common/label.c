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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/
/*LINTLIBRARY*/

#include "con.h"

#define	N 0104
#define	E 0101
#define	NE 0105
#define	S 0110
#define	W 0102
#define	SW 0112

/*
 *	arrange by incremental plotting that an initial
 *	character such as +, X, *, etc will fall
 *	right on the point, and undo it so that further
 *	labels will fall properly in place
 */


void
label(char *s)
{
	char lbl_mv[] = {036, 040, S, S, S, S, S, S, SW, SW,
	SW, SW, SW, SW, SW, SW, SW, SW, 037, 0};

	char lbl_umv[] = {036, 040, N, N, N, N, N, N, NE, NE,
	NE, NE, NE, NE, NE, NE, NE, NE, 037, 0};

	int i;
	char c;

	/* LINTED */
	for (i = 0; c = lbl_mv[i]; i++)
		putch(c);
	/* LINTED */
	for (i = 0; c = s[i]; i++)
		putch(c);
	/* LINTED */
	for (i = 0; c = lbl_umv[i]; i++)
		putch(c);
}
