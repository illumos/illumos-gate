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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/
/*LINTLIBRARY*/

#include <stdlib.h>
#include <stdio.h>
#include "con.h"

float obotx = 0.0;
float oboty = 0.0;
float botx = 0.0;
float boty = 0.0;
float scalex = 1.0;
float scaley = 1.0;
int scaleflag = 0;
int oloy = -1;
int ohiy = -1;
int ohix = -1;
int oextra = -1;


void
putch(char c)
{
	(void) putc(c, stdout);
}

void
cont(short x, short y)
{
	short hix, hiy, lox, loy, extra;
	short n;
	x = (short)((x - obotx) * scalex + botx);
	y = (short)((y - oboty) * scaley + boty);
	hix = (x>>7) & 037;
	hiy = (y>>7) & 037;
	lox = (x>>2) & 037;
	loy = (y>>2) & 037;
	extra = x & 03 + (y<<2) & 014;
	n = (abs(hix - ohix) + abs(hiy - ohiy) + 6) / 12;
	if (hiy != ohiy) {
		putch(hiy|040);
		ohiy = hiy;
	}
	if (hix != ohix) {
		if (extra != oextra) {
			putch(extra|0140);
			oextra = extra;
		}
		putch(loy|0140);
		putch(hix|040);
		ohix = hix;
		oloy = loy;
	} else {
		if (extra != oextra) {
			putch(extra|0140);
			putch(loy|0140);
			oextra = extra;
			oloy = loy;
		} else if (loy != oloy) {
			putch(loy|0140);
			oloy = loy;
		}
	}
	putch(lox|0100);
	while (n--)
		putch(0);
}
