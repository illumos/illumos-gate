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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<ctype.h>
#include	"wish.h"
#include	"menu.h"
#include	"menudefs.h"
#include	"vtdefs.h"
#include	"token.h"
#include	"ctl.h"
#include	"moremacros.h"
#include	"message.h"
#include	"sizes.h"

#define myisprint(C)	((C) >= ' ' && (C) <= '~')

static char	*curstring;
static int      menu_match();
/* mouse coordinates */
extern int Mouse_row;
extern int Mouse_col;

token
menu_stream(t)
register token	t;
{
	register int	newindex, begindex;
	register struct menu	*m;
	struct menu_line men;
	extern menu_id	MNU_curid;
	void	_menu_cleanup();
	char badmatch[PATHSIZ];

	if (MNU_curid < 0)
		return t;
	m = &MNU_array[MNU_curid];
	/* curstring is set if we partial-matched on the previous character */
	if (curstring) {
		if (myisprint((int) t) && (newindex = menu_match(m, curstring, m->hcols, t)) != FAIL) {
			menu_index(m, newindex, m->hcols + 1);
			return TOK_NEXT;
		}
		else if (t == TOK_BACKSPACE) {
			if (m->hcols > 1) {
				menu_index(m, m->index, m->hcols - 1);
				return TOK_NEXT;
			}
		}
		if (myisprint((int) t) && t != ' ') {
			sprintf(badmatch, "Can't match item starting with \"%.*s%c\"",
				 m->hcols, curstring, (char) t);
			mess_temp(badmatch);
			mess_lock();
			return(TOK_BADCHAR);
		}
	}

	/*
	 * NOTE: tokens that change the current menu item return
	 * TOK_NEXT so that application stream handler (objmenu_stream)
	 * is aware ...
 	 */		
	switch (t) {
	case ' ':
	case TOK_TAB:		/* abs k16 */
	case TOK_RIGHT:
		if (m->ncols > 1) {
			int	row, col;

			vt_ctl(m->vid, CTGETSIZ, &row, &col);
			begindex = m->index;
			if ((newindex = m->index + row) < m->number) {
				menu_index(m, newindex, MENU_ALL);
				men = (*m->disp)(m->index, m->arg);
				t = TOK_NEXT;
				/*
		 		 * RIGHT ARROW
		 		 * Do not match inactive menu items.
				 */
				while (men.flags & MENU_INACT) {
					if ((newindex = m->index + row) < m->number) {
						menu_index(m, newindex, MENU_ALL);
		   		 		t = TOK_NEXT;
						men = (*m->disp)(m->index, m->arg);
					}
					else {
		    				sprintf(badmatch,"Can't match inactive menu item.");
		    				mess_temp(badmatch);
		   	 			mess_lock();
						menu_index(m, begindex, MENU_ALL);
		   		 		t = TOK_NOP;
						break;
					}
				 }
			}
			break;
		}
		/* FALL THROUGH */
	case TOK_DOWN:
	case TOK_NEXT:
		if (m->index < m->number - 1) {
			menu_index(m, m->index + 1, MENU_ALL);
			t = TOK_NEXT;
			/*
		 	 * DOWN ARROW
		 	 * Do not match inactive menu items.
			 */
			men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				if (m->index < m->number - 1) {
					menu_index(m, m->index + 1, MENU_ALL);
		   	 		t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}
				else {
					menu_index(m, 0, MENU_ALL);
					t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}
			 }
		}
		else { 
			menu_index(m, 0, MENU_ALL);
			t = TOK_NEXT;
			/*
		 	 * DOWN ARROW when you are at the bottom of
			 * the menu and the down arrow will take you
			 * to the first menu item.
			 *
		 	 * Do not match inactive menu items.
			 */
			men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				menu_index(m, m->index + 1, MENU_ALL);
		   	 	t = TOK_NEXT;
				men = (*m->disp)(m->index, m->arg);
			 }
		}
		break;
	case TOK_BPRESSED:				/* Button 1 press */
		begindex = m->index;
		if (m->ncols > 1) {
			int	rows, dummy;
			
			/*
			 * Multicolumn menu: get frame size (rows)
			 * to determine menu item offset (newindex)
			 */
			vt_ctl(m->vid, CTGETSIZ, &rows, &dummy);
			newindex = rows * ((int)((Mouse_col + 1) / m->hwidth));
			newindex += Mouse_row;
		}
		else 
			newindex = m->topline + Mouse_row;
		if (newindex > (m->number - 1))
			t = TOK_BADCHAR;	/* out of bounds */
		else if (m->index == newindex)
			t = TOK_NOP;		/* do nothing */
		else {
			menu_index(m, newindex, MENU_ALL);
			men = (*m->disp)(m->index, m->arg);
		       /*
		 	* Do not match inactive menu items
			*
			* NOTE: The mouse code for inactive menu items
			* will remain untested until ported to the 386.
			* sfsup!njp 4/12/89	
		 	*/
			if (men.flags & MENU_INACT) {
		    		sprintf(badmatch,"Can't match inactive menu item.");
		    		mess_temp(badmatch);
		   	 	mess_lock();
				menu_index(m, begindex, MENU_ALL);
				t = TOK_NOP;
			}
			else 
				t = TOK_NEXT;
		}
		break;
	case TOK_BACKSPACE:
        case TOK_BTAB:		/* abs k16 */
	case TOK_LEFT:
		if (m->ncols > 1) {
			int	row, col;
			
			vt_ctl(m->vid, CTGETSIZ, &row, &col);
			begindex = m->index;
			if ((newindex = m->index - row) >= 0) {
				menu_index(m, newindex, MENU_ALL);
				men = (*m->disp)(m->index, m->arg);
				t = TOK_NEXT;
				/*
		 		 * LEFT ARROW
		 		 * Do not match inactive menu items.
				 */
				while (men.flags & MENU_INACT) {
					if ((newindex = m->index - row) > 0) {
						menu_index(m, newindex, MENU_ALL);
		   		 		t = TOK_NEXT;
						men = (*m->disp)(m->index, m->arg);
					}
					else {
		    				sprintf(badmatch,"Can't match inactive menu item.");
		    				mess_temp(badmatch);
		   	 			mess_lock();
						menu_index(m, begindex, MENU_ALL);
		   		 		t = TOK_NOP;
						break;
					}
				 }
			}
			break;
		}
		/* FALL THROUGH */
	case TOK_UP:
	case TOK_PREVIOUS:
		if (m->index > 0) {
			menu_index(m, m->index - 1, MENU_ALL);
			t = TOK_NEXT;
			/*
		 	 * UP ARROW
		 	 * Do not match inactive menu items.
			 */
			men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				if (m->index > 0) {
					menu_index(m, m->index - 1, MENU_ALL);
		   	 		t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}
				else {
					menu_index(m, m->number - 1, MENU_ALL);
					t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}

			}
		}
		else { 
			menu_index(m, m->number - 1, MENU_ALL);
			t = TOK_NEXT;
			/*
		 	 * UP ARROW when you are at the top of
			 * the menu and the up arrow will take you
			 * to the last menu item.
			 *
		 	 * Do not match inactive menu items.
			 */
			men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				menu_index(m, m->index - 1, MENU_ALL);
		   	 	t = TOK_NEXT;
				men = (*m->disp)(m->index, m->arg);
			 }
		}
		break;
	case TOK_BRELEASED:
		if (m->ncols > 1) {
			int	rows, dummy;
			
			/*
			 * Multicolumn menu: get frame size (rows)
			 * to determine menu item offset (newindex)
			 */  
			vt_ctl(m->vid, CTGETSIZ, &rows, &dummy);
			newindex = rows * ((int)((Mouse_col + 1) / m->hwidth));
			newindex += Mouse_row;
		}
		else 
			newindex = m->topline + Mouse_row;
		if (newindex != m->index)
			t = TOK_NOP;
		else if (m->flags & MENU_MSELECT)
			t = TOK_MARK;	/* multi-select menu */
		else
			t = TOK_OPEN;
		break;
	case TOK_RETURN:
	case TOK_OPEN:
	case TOK_ENTER:
		t = TOK_OPEN;
		break;
	case TOK_HOME:
		menu_index(m, m->topline, MENU_ALL);
		t = TOK_NEXT;
		men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				menu_index(m, m->index + 1, MENU_ALL);
		   	 	t = TOK_NEXT;
				men = (*m->disp)(m->index, m->arg);
			 }
		break;
	case TOK_BEG:
		menu_index(m, 0, MENU_ALL);
		t = TOK_NEXT;
		men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				menu_index(m, m->index + 1, MENU_ALL);
		   	 	t = TOK_NEXT;
				men = (*m->disp)(m->index, m->arg);
			 }
		break;
	case TOK_LL:
	case TOK_SHOME:		/* move to last item on cur. page */
		{
		    int	row, col;
		    int topline, index;	/* abs */
		    
		    vt_ctl(m->vid, CTGETSIZ, &row, &col);
		    menu_ctl(MNU_curid, CTGETPARMS, &topline, &index); /* abs */
		    menu_index(m, row + topline - 1, MENU_ALL);
		    t = TOK_NEXT;
		    men = (*m->disp)(m->index, m->arg);
		    while (men.flags & MENU_INACT) {
			menu_index(m, m->index - 1, MENU_ALL);
		    	t = TOK_NEXT;
			men = (*m->disp)(m->index, m->arg);
		    }
		}	
		break;
	case TOK_END:
		menu_index(m, m->number - 1, MENU_ALL);
		t = TOK_NEXT;
		men = (*m->disp)(m->index, m->arg);
		while (men.flags & MENU_INACT) {
			menu_index(m, m->index - 1, MENU_ALL);
		    	t = TOK_NEXT;
			men = (*m->disp)(m->index, m->arg);
	        }
		break;
	case TOK_SR:
		if (m->topline > 0) {
			begindex = m->index;
			newindex = m->index - 1;
			/* force reverse scroll */
			menu_index(m, m->topline - 1, 0);
			/*reset position */
			menu_index(m, newindex, MENU_ALL);
			men = (*m->disp)(m->index, m->arg);
			t = TOK_NEXT;
			/*
		 	 * REVERSE SCROLL
		 	 * Do not match inactive menu items.
			 */
			while (men.flags & MENU_INACT) {
				if (m->topline > 0) {
					newindex = m->index - 1;
					/* force reverse scroll */
					menu_index(m, m->topline - 1, 0);
					/*reset position */
					menu_index(m, newindex, MENU_ALL);
					men = (*m->disp)(m->index, m->arg);
					t = TOK_NEXT;
				}
				else {
					menu_index(m, begindex, MENU_ALL);
		   	 		t = TOK_NOP;
					break;
				}
			}
		}
		break;
	case TOK_SF:
		if (m->ncols == 1) {
			int	row;
			int	col;

			vt_ctl(m->vid, CTGETSIZ, &row, &col);
			if (m->topline + row < m->number) {
				begindex = m->index;
				newindex = m->index + 1;
				/* cause scroll */
				menu_index(m, m->topline + row, 0);
				/* reset position */
				menu_index(m, newindex, MENU_ALL);
				t = TOK_NEXT;
				men = (*m->disp)(m->index, m->arg);
				while (men.flags & MENU_INACT) {
					if (m->topline + row < m->number) {
						newindex = m->index + 1;
						/* cause scroll */
						menu_index(m, m->topline + row, 0);
						/* reset position */
						menu_index(m, newindex, MENU_ALL);
						t = TOK_NEXT;
						men = (*m->disp)(m->index, m->arg);
					}
					else {
						menu_index(m, begindex, MENU_ALL);
		   	 			t = TOK_NOP;
						break;
					}
				}
			}
		}
		break;
	case TOK_PPAGE:
		if (m->ncols == 1) {
			int	row;
			int	col;

			if (m->topline == 0)
				break;
			vt_ctl(m->vid, CTGETSIZ, &row, &col);
			newindex = m->topline - row + row / 2;
			if (newindex < 0)
				newindex = 0;
			/*
			 * force middle of page
			 * then set position to top of window
			 */
			menu_index(m, newindex, 0);
			menu_index(m, m->topline, MENU_ALL);
			t = TOK_NEXT;
			men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				if (m->index > 0) {
					menu_index(m, m->index - 1, MENU_ALL);
		   	 		t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}
				else {
					menu_index(m, m->number - 1, MENU_ALL);
					t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}

			}
		}
		break;
	case TOK_NPAGE:
		if (m->ncols == 1) { 
			int	row;
			int	col;

			vt_ctl(m->vid, CTGETSIZ, &row, &col);
			if ((m->topline + row) == m->number)
				break;
			newindex = m->topline + row + row / 2;
			if (newindex >= m->number)
				newindex = m->number;
			/*
			 * force middle of page
			 * then set position to top of window
			 */
			menu_index(m, newindex, 0);
			menu_index(m, m->topline, MENU_ALL);
			t = TOK_NEXT;
			men = (*m->disp)(m->index, m->arg);
			while (men.flags & MENU_INACT) {
				if (m->index < m->number - 1) {
					menu_index(m, m->index + 1, MENU_ALL);
		   	 		t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}
				else {
					menu_index(m, 0, MENU_ALL);
					t = TOK_NEXT;
					men = (*m->disp)(m->index, m->arg);
				}
			 }
		}
		break;
	default:
		if (myisprint((int) t)) {
			if ((newindex = menu_match(m, nil, 0, t)) != FAIL) {
				menu_index(m, newindex, 1);
				men = (*m->disp)(m->index, m->arg);
				while (men.flags & MENU_INACT) {
					if (m->index < m->number - 1) {
						menu_index(m, m->index + 1, MENU_ALL);
						men = (*m->disp)(m->index, m->arg);
					}
					else {
						menu_index(m, 0, MENU_ALL);
						men = (*m->disp)(m->index, m->arg);
					}
			 	}
				return TOK_NEXT;
			}
			else {
				sprintf(badmatch, "Can't match item starting with \"%c\"", (char) t);
				mess_temp(badmatch);
				mess_lock();
				return(TOK_BADCHAR);
			}
		}
		break;
	}
	_menu_cleanup();
	return t;
}

void
_menu_cleanup()
{
	if (curstring)
		free(curstring);
	curstring = NULL;
}

static int
menu_match(m, s, n, t)
register struct menu	*m;
char	*s;
int	n;
token	t;
{
	register int	i;
	register int	start;
	register int	count;
	register char	*p;
	static void strtolower();
	static int  nocase_strncmp();
	char badmatch[PATHSIZ];

	start = m->index;
	for (i = m->index, count = 0; count < m->number; count++) {
		struct menu_line men;

		men = (*m->disp)(i, m->arg);
		p = men.highlight;
		if (nocase_strncmp(p, s, n) == 0 && ((p[n] == t) || 
				(isupper(t) && (p[n] == _tolower(t))) ||
				(islower(t) && (p[n] == _toupper(t))))) {
			/*
		 	* Do not match inactive menu items
		 	*/
			if (men.flags & MENU_INACT) {
		    		sprintf(badmatch,"Can't match inactive menu item.");
		    		mess_temp(badmatch);
		   	 	mess_lock();
		   	 	return start;
			}
		else {
			if (m->index != i || curstring == NULL) {
				if (curstring)
					free(curstring);
				curstring = strsave(p);
				strtolower(curstring);
			}
		}
			return i;
		}
		if (++i >= m->number)
			i = 0;
	}
	return FAIL;
}

static void 
strtolower(s)
register char *s;
{
	for (; *s != '\0'; s++)
		*s = tolower(*s);
}

static int
nocase_strncmp(p, s, n)
register char *p, *s;
int n;
{
	register int i;

	if (!p || !s)
		return(1);
	for (i = 0; i < n; i++) {
		if (!(*p || *s))
			break;		/* both strings shorter than n */
		else if (tolower(*p++) != tolower(*s++))
			return(1);
	}
	return(0);
}
