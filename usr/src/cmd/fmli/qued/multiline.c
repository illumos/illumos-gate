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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.11 */

#include <stdio.h>
#include <ctype.h>
#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"

static token _fixed();
static token _virtual();

#define SCROLLSIZE	((Cfld->rows - 2 <= 0) ? 1 : Cfld->rows - 2)
#define HALFSIZE	(int)(Cfld->rows / 2)

token
multiline(tok)
{
	if (Flags & I_SCROLL)
		return(_virtual(tok));
	else
		return(_fixed(tok));
}

static token
_fixed(tok)
token tok;
{
	register token rettok;
	register int col;
	static int emptyrow();

	rettok = TOK_NOP;
	switch (tok) {
	case TOK_BACKSPACE:
	case TOK_RETURN:
	case TOK_WRAP:
	    if (Flags & I_AUTOADV)
		rettok = TOK_NEXT;
	    else
		beep();
	    break;
	case TOK_IL:
		if (Flags & I_NOEDIT)
			beep();
		else if (emptyrow(LASTROW) == FALSE)
			beep();
		else {
			finsline(1, TRUE);
			Flags |= I_CHANGED;
		}
		break;
	case TOK_DL:
		if (Flags & I_NOEDIT)
			beep();
		else {
			fdelline(1);
			Flags |= I_CHANGED;
		}
		break;
	case TOK_HOME:
	case TOK_BEG:
		fgo(0, 0);
		break;
	case TOK_SHOME:
	case TOK_END:
		col = LASTCOL;
		while (col >= 0 && freadchar(LASTROW, col) == ' ')
			col--;
		fgo(LASTROW, (col == LASTCOL || col == 0 ? col : col+1));
		break; 
	default:
		rettok = tok;
	}
	return(rettok);
}

static token
_virtual(tok)
token tok;
{
	register token rettok;
	register int col;

	rettok = TOK_NOP;
	switch (tok) {
	case TOK_DL:
		if (Flags & I_NOEDIT) {
			beep();
			break;
		}
		Flags |= I_CHANGED;
		fdelline(1);
		shiftbuf(UP);
		break;
	case TOK_IL:
		if (Flags & I_NOEDIT) {
			beep();
			break;
		}
		if (Cfld->currow == LASTROW) {
			if (scroll_down(1) == FALSE) {
				Bufflast += FIELDBYTES;
				growbuf(Bufflast);
				scroll_down(1);
			}
			fgo(LASTROW - 1, 0);
		}
		Flags |= I_CHANGED;
		shiftbuf(DOWN);
		finsline(1, TRUE);
		break;
	case TOK_NPAGE:
		if (Flags & I_NOPAGE)
			rettok = tok;	/* paging not permitted */
		else {
			if (scroll_down(SCROLLSIZE) == FALSE)
				beep();
		}
		break;
	case TOK_PPAGE:
		if (Flags & I_NOPAGE)
			rettok = tok;	/* paging not permitted */
		else {
			if (scroll_up(SCROLLSIZE) == FALSE)
				beep();
		}
		break;
	case TOK_UP:
	case TOK_SR:
		if (scroll_up(1) == FALSE)
			rettok = TOK_UP;
		break;
	case TOK_RETURN:
		if (scroll_down(HALFSIZE) == FALSE) {
			if (Flags & I_NOEDIT)
				beep();	
			else {	
				Bufflast += FIELDBYTES ;     /* abs k17 */
				growbuf(Bufflast);           /* abs k17 */
				scroll_down(HALFSIZE);
			}
		}
		fgo(Cfld->currow == LASTROW ? Cfld->currow : Cfld->currow + 1, 0);
		break;
	case TOK_DOWN:
	case TOK_SF:
		if (scroll_down(1) == FALSE)
			rettok = TOK_DOWN;	
		break;
	case TOK_WRAP:
		if (scroll_down(1) == FALSE) {
			Bufflast += FIELDBYTES; /* abs k17 */
			growbuf(Bufflast);	/* abs k17 */
			scroll_down(1);
		}
		fgo(LASTROW - 1, Cfld->curcol);
		if ((col = do_wrap()) < 0) {
			col = 0;
			beep();
		}
		if (Cfld->curcol == LASTCOL)  	/* if cursor on last col */ 
			fgo(Cfld->currow + 1, col);
		break;
	case TOK_BACKSPACE:
		if (scroll_up(1) == FALSE)
			beep();
		else {
			fgo(Cfld->currow, LASTCOL);
			fputchar(' ');
		}
		break;
	case TOK_HOME:
	case TOK_BEG:
		while (scroll_up(SCROLLSIZE) == TRUE)
			;
		fgo(0, 0);
		break;
	case TOK_SHOME:
	case TOK_END:
		while (scroll_down(SCROLLSIZE) == TRUE)
			;
		col = LASTCOL;
		while (col >= 0 && freadchar(LASTROW, col) == ' ')
			col--;
		fgo(LASTROW, (col == LASTCOL || col == 0 ? col : col+1));
		break;
	default:
		rettok = tok;
	}
	return(rettok);
}

static int
emptyrow(row)
register int row;
{
	register int col;
	int saverow, savecol;

	saverow = Cfld->currow;
	savecol = Cfld->curcol;
	fgo(row, col = LASTCOL);
	while (col >= 0 && freadchar(row, col) == ' ')
		col--;
	fgo(saverow, savecol);
	return(col < 0 ? TRUE : FALSE);
}
