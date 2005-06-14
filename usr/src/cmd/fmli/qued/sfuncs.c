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
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.7 */

#include <stdio.h>
#include <curses.h>
#include "wish.h"
#include "vtdefs.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "attrs.h"

extern void acswinschar();

fdelchar()
{
	int saverow, savecol;

	saverow = Cfld->currow;
	savecol = Cfld->curcol;
	wdelchar();
	/*
	 * go to last column and insert a blank
	 */
	fgo(saverow, LASTCOL);
	winschar(' ', Fieldattr);
	fgo(saverow, savecol);
}

finsstr(buff)
char *buff;
{
	register char *bptr;

	for (bptr = buff; *bptr & A_CHARTEXT != '\0'; bptr++)
		;
	bptr--;
	while (bptr >= buff)
		finschar(*bptr--);
}

finschar(c)
char c;
{
	int saverow, savecol;

	saverow = Cfld->currow;
	savecol = Cfld->curcol;
	/* 
	 * delete last character, re-position cursor and insert
	 * a character
	 */
	fgo(saverow, LASTCOL);
	wdelchar();
	fgo(saverow, savecol);
	winschar(c, Fieldattr);
}
