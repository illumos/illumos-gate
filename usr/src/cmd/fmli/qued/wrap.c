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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "terror.h"

#define MAXBOUND	3

extern int acsinsstr();

/*
 * PREV_BNDRY returns the position within the line of the previous blank
 * (or nonblank) starting from the last column of the current row
 */
int
prev_bndry(row, ch, val)
int row;
char ch;
int val;
{
	register int pos;

	for (pos = LASTCOL; pos >= 0; pos--)
		if ((freadchar(row, pos) == ch) == val)
			break;
	return(pos);
}

/*
 * WRAP returns TRUE if there is a character in the last line of the current
 * row and FALSE otherwise.
 */
int
wrap(void)
{
	if (freadchar(Cfld->currow, LASTCOL) != ' ')
		return(TRUE);
	else
		return(FALSE);
}

/*
 * DO_WRAP performs the word wrap ... It returns the number of characters
 * that were wrapped to the next line.
 */
int
do_wrap(void)
{
	register int i, need, pos, row;
	register chtype *bptr;
	int saverow, savecol;
	int numblanks;
	chtype *buff;
	int 	maxlength, totallength, lastnonblank;

	if ((row = Cfld->currow) >= LASTROW)
		return(-1);		/* can't wrap on last line */

	saverow = row; 
	savecol = Cfld->curcol;

	/*
	 * see if wrap word fits on the next line
	 */
	pos = prev_bndry(row, ' ', TRUE) + 1;
	need = LASTCOL - pos + 1;
	numblanks = padding(freadchar(row, LASTCOL));
	totallength = need + numblanks;
	lastnonblank = prev_bndry(row + 1, ' ', FALSE);
	maxlength = (LASTCOL - MAXBOUND + 1) - (lastnonblank + 1);
	if (totallength > maxlength)
		return(-1);

	/*
	 * clear the word from the current line
	 */
	fgo(row, pos);
	if ((buff = (chtype *)malloc((totallength + 1) * sizeof(*buff))) == NULL)
		fatal(NOMEM, "");
	bptr = buff;
	for (i = 0; i < need; i++) {
		*bptr++ = acsreadchar(row, pos++);
/*>>ATTR<<*/		fputchar(' ');
	}
	for (i = 0; i < numblanks; i++)
		*bptr++ = ' ';
	*bptr = '\0';

	/*
	 * .. and place it on the next row
	 */
	fgo(row + 1, 0);
	acsinsstr(buff);
	free(buff);

	/*
	 * replace the cursor and let the calling routine move it if
	 * necessary
	 */
	fgo(saverow, savecol);

	return(totallength - numblanks);
}

int
padding(lastchar)
int lastchar;
{
	register int numblanks;

	/*
	 * compute number of blanks that must follow the wrapped word
	 */
	if (lastchar == '"' || lastchar == '\'') 
		lastchar = freadchar(Cfld->currow, LASTCOL - 1);
	if (lastchar == '.' || lastchar == '?' || lastchar == ':' || lastchar == '!')
		numblanks = 2;
	else
		numblanks = 1;
	return(numblanks);
}
