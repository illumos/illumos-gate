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

#include	<stdio.h>
#include	<ctype.h>
#include        <curses.h>
#include	"wish.h"
#include	"token.h"
#include	"winp.h"
#include	"fmacs.h"
#include	"terror.h"

#define ischange(x)	(x == TOK_BACKSPACE || x == TOK_CLEAR || x == TOK_ERASE || x == TOK_DC ||\
			 x == TOK_EOL || x == TOK_SEOL || x == TOK_UNDO || \
			 x == TOK_IC)
#define isslash(x)	(x == '\b' || (isspace(x) && x != ' '))

int
editsingle(tok)
token tok;
{
	register token rettok;
	register int row, col;

	rettok = TOK_NOP;

	if (tok == TOK_NOP)
		return rettok;
	row = Cfld->currow;
	col = Cfld->curcol;
/*
	if ( isprint(tok) && !(Flags & I_NOEDIT))
*/
	if ( isascii(tok) && isprint(tok) && !(Flags & I_NOEDIT))
	{
		Flags |= I_CHANGED;
		if (Flags & I_BLANK) {
			/*
			 * check to see if character typed should clear field
			 */
			if ((Cfld->rows == 1) && (row == 0) && (col == 0)) {
				fclear();
				if (Flags & I_SCROLL)
					clearbuf();	/* clear scroll buff */
			}
		}
		if (Flags & I_INVISIBLE) {		/* invisible field */
		    int count;

		    if (Valptr == NULL)
			Valptr = Value;
		    count = Valptr - Value + 1;
		    if ( count < FIELDBYTES) {
			*Valptr++ = tok;
			*Valptr = '\0';
			if (++count == FIELDBYTES) /* abs for autoadvance */
			    rettok = TOK_WRAP;
		    }
			else
			       rettok = TOK_WRAP; /* abs was beep() */
		}
		else {
			fputchar(tok);			/* print character */
			if (col == LASTCOL)		/* end of line */
				rettok = TOK_WRAP;
			else 
				col++;
		}
	}
	else if (ischange(tok)) {
		Flags |= I_CHANGED;
		if (Flags & I_NOEDIT) {			/* no-edit field */
			beep();
			goto alldone;
		}
		switch(tok) {
		case TOK_CLEAR:
		case TOK_EOL:
			fgo(row, col = 0);
		case TOK_SEOL:
			fclearline();
			if (Currtype == SINGLE && (Flags & I_SCROLL))
				clearbuf();
			break;
		case TOK_BACKSPACE:
			if (col > 0) {
				if (col == LASTCOL && freadchar(row, col) != ' ') {
					fputchar(' ');
					fgo(row, col);
				}
				else {
					fgo(row, --col);
					fdelchar();
					finschar(' ');
				}
			}
			else
				rettok = TOK_BACKSPACE;
			break;
		case TOK_TAB:
			/* tab */
			while (col < LASTCOL && (col & 7))
				col++;
			break;
		case TOK_BTAB:
			/* back tab */
			while (col && (col & 7))
				col--;
			break;
		case TOK_IC:
			/*
			 * insert char and check for word wrapping
			 * due to line shift to the right
			 */
			if (Currtype == SINGLE && (Flags & I_SCROLL)) {
				shiftbuf(RIGHT);
				finschar(' ');
			}
			else if (wrap() == TRUE)
				rettok = TOK_WRAP;
			else
				finschar(' ');
			break;
		case TOK_DC:
		case TOK_ERASE:
			/* delete char */
			fdelchar();
			if (Currtype == SINGLE && (Flags & I_SCROLL))
				shiftbuf(LEFT);
			break;
		case TOK_UNDO:
			/* enhacement */ 
			beep();
			break;
		}
	}
	else {	
		switch(tok) {
		case TOK_ENTER:
		case TOK_RETURN:
			/* carriage return */
			rettok = TOK_RETURN; 
			break;
		case TOK_LEFT:
			/* move left */
			if (col == 0)
				rettok = TOK_LEFT;
			else
				fgo(row, --col);
			break;
		case TOK_RIGHT:
			/* move right */
			if (col == LASTCOL)
				rettok = TOK_RIGHT;
			else
				fgo(row, ++col);
			break;
		default:
			/* pass it back */
			rettok = tok;
		}
	}
alldone:
	Cfld->curcol = col;
	Flags &= ~(I_BLANK);
	return(rettok);
}
