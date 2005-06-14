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
#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "attrs.h"


extern char *attr_on();
extern char *attr_off();


/*
 * FPUTSTRING will return NULL if the entire string fits in the field
 * otherwise it returns a pointer to the beginning of the substring that
 * does not fit
 */
char *
fputstring(str)
char *str;
{
	register char *sptr;
	register int row, col, done; 
	int i, numspaces, pos;
	chtype attrs;

	col = Cfld->curcol;
	row = Cfld->currow;
	attrs = Lastattr;
	done = FALSE;
	sptr = str;
	while (!done) {
		if (*sptr == '\\') {
			switch(*(++sptr)) {
			case 'b':
				*sptr = '\b';
				break;
                        case '-':
				if (Cfld->flags & I_TEXT)
				    sptr = attr_off(sptr, &attrs, NULL) + 1;
                                continue;   /* don't need to wputchar */
			case 'n':
				*sptr = '\n';
				break;
                        case '+':
				if (Cfld->flags & I_TEXT)
				    sptr = attr_on(sptr, &attrs, NULL) + 1;
                                continue;   /* don't need to wputchar */
			case 't':
				*sptr = '\t';
				break;
			case 'r':
				*sptr = '\r';
				break;
			}
		}
		switch(*sptr) {
		case '\n':
			fgo(row, col);
			fclearline();
			if (row == LASTROW)
				done = TRUE;
			else
				fgo(++row, col = 0);
			sptr++;
			break;
		case '\b':
			if (col != 0)
				fgo(row, --col);
			sptr++;
			break;
		case '\t':
			numspaces = ((col + 8) & ~7) - col;
			for (i = 0; i < numspaces && col <= LASTCOL; i++, col++)
				wputchar(' ', attrs, NULL);
			sptr++;
			break;
		case '\0':
			done = TRUE;
			sptr = NULL;
			continue;
		default:
			wputchar(*sptr++, attrs, NULL);
			col++;
			break;
		}
		if (col > LASTCOL) {
			if (row == LASTROW) {
				if ((Flags & I_SCROLL) && (Flags & I_WRAP)) {
					/*
					 * If the word is not longer then
					 * the length of the field then
					 * clear away the word to wrap...
					 * and adjust the string pointer to
					 * "unput" the word ....
					 */
					pos = prev_bndry(row, ' ', TRUE);
					if (pos >= 0) {
						fgo(row, pos);
						fclearline();
						sptr -= (LASTCOL - pos);
					}
				}
				else
					sptr++;
				done = TRUE;
			}
			else if ((Flags & I_WRAP) && (wrap() == TRUE)) {
				if ((col = do_wrap()) < 0)
					col = 0;
				fgo(++row, col);
			}
			else {
				if (*sptr != '\n')
					fgo(++row, col = 0);
			}
		}
	}
	Lastattr = attrs;
	Cfld->curcol = col;
	Cfld->currow = row;
	return(sptr);
}
