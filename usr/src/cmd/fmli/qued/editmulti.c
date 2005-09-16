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

#include	<ctype.h>
#include	<stdio.h>
#include        <curses.h>
#include	"token.h"
#include	"winp.h"
#include	"fmacs.h"
#include	"wish.h"

int
editmulti(tok)
token tok;
{
	register token rettok;
	register int row, col;
	int wrapcol;

	row = Cfld->currow;
	col = Cfld->curcol;
	rettok = TOK_NOP;
	switch(tok) {
	case TOK_UP:
		if (row == 0)
			rettok = TOK_UP;
		else 
			row--;
		break;
	case TOK_DOWN:
		if (row == LASTROW)
			rettok = TOK_DOWN;
		else
			row++;
		break;
	case TOK_RETURN:
	case TOK_ENTER:
		if (row == LASTROW)
			rettok = TOK_RETURN;
		else {
			row++;
			col = 0;
		}
		break;
	case TOK_BACKSPACE:
		/* reposition cursor for further backspaces or erases */
		if (row == 0)
			rettok = tok;
		else {
			fgo(--row, col = LASTCOL);
			fputchar(' ');
		}
		break;
	case TOK_WRAP:
		if (row == LASTROW)
			rettok = tok;
		else if (Flags & I_WRAP) {
			if ((wrapcol = do_wrap()) < 0) {
				wrapcol = 0;
				beep();
			}
			if (col == LASTCOL) {	/* if cursor on last col */ 
				col = wrapcol;
				row++;
			}
		}
		else if (col == LASTCOL) {
			row++;
			col = 0;
		}
		else
			beep();
		break;
	default:
		rettok = tok;
	}
	fgo(row, col);
	return(rettok);
}
