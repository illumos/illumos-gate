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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* common mouse interface functions */

#include <stdio.h>	/* NULL */
#include <stdlib.h>	/* NULL */
#include <string.h>	/* NULL */
#include <ctype.h>	/* isdigit */
#include "global.h"

#define	ctrl(x)			(x & 037)

MOUSETYPE mouse;

static	MOUSEMENU *loadedmenu;
static	BOOL	changemenu = YES;

/* see if there is a mouse interface */

void
initmouse(void)
{
	char	*s, *term;

	if ((term = getenv("TERM")) == NULL) {
		return;
	}
	if (strcmp(term, "emacsterm") == 0 || strcmp(term, "viterm") == 0) {
		mouse = EMACSTERM;
	} else if ((s = getenv("MOUSE")) != NULL && strcmp(s, "myx") == 0) {
		/*
		 * the MOUSE enviroment variable is for 5620 terminal
		 * programs that have mouse support but the TERM environment
		 * variable is the same as a terminal without a mouse, such
		 * as myx
		 */
		mouse = MYX;
	}
	if ((s = getenv("MOUSEMENU")) != NULL && strcmp(s, "none") == 0) {
		changemenu = NO;
	}
	initmenu();
}

/* reinitialize the mouse in case curses changed the attributes */

void
reinitmouse(void)
{
	if (mouse == EMACSTERM) {

		/*
		 * enable the mouse click and sweep coordinate control
		 * sequence
		 */
		(void) printf("\033{2");
		if (changemenu) {
			(void) printf("\033#2");	/* switch to menu 2 */
		}
		(void) fflush(stdout);
	}
}

/* restore any original mouse attributes not handled by terminfo */

void
cleanupmouse(void)
{
	int	i;

	if (mouse == MYX && loadedmenu != NULL) {
		/* remove the mouse menu */
		(void) printf("\033[6;0X\033[9;0X");
		for (i = 0; loadedmenu[i].text != NULL; ++i) {
			(void) printf("\033[0;0x");
		}
		loadedmenu = NULL;
	}
}

/* download a mouse menu */

void
downloadmenu(MOUSEMENU *menu)
{
	int	i;
	int	len;

	switch (mouse) {
	case EMACSTERM:
		reinitmouse();
		(void) printf("\033V1");	/* display the scroll bar */
		if (changemenu) {
			(void) printf("\033M0@%s@%s@", menu[0].text,
			    menu[0].value);
			for (i = 1; menu[i].text != NULL; ++i) {
				(void) printf("\033M@%s@%s@", menu[i].text,
				    menu[i].value);
			}
		}
		(void) fflush(stdout);
		break;
	case MYX:
		if (changemenu) {
			cleanupmouse();
			(void) printf("\033[6;1X\033[9;1X");
			for (i = 0; menu[i].text != NULL; ++i) {
				len = strlen(menu[i].text);
				(void) printf("\033[%d;%dx%s%s", len,
				    len + strlen(menu[i].value),
				    menu[i].text, menu[i].value);
			}
			(void) fflush(stdout);
			loadedmenu = menu;
		}
		break;
	case NONE:
	case PC7300:
		break;
	}
}

/* draw the scroll bar */

void
drawscrollbar(int top, int bot, int total)
{
	int	p1, p2;

	if (mouse == EMACSTERM) {
		if (bot > top && total > 0) {
			p1 = 16 + (top - 1) * 100 / total;
			p2 = 16 + (bot - 1) * 100 / total;
			if (p2 > 116) {
				p2 = 116;
			}
			if (p1 < 16) {
				p1 = 16;
			}
			/*
			 * don't send ^S or ^Q to avoid hanging a layer using
			 * cu(1)
			 */
			if (p1 == ctrl('Q') || p1 == ctrl('S')) {
				++p1;
			}
			if (p2 == ctrl('Q') || p2 == ctrl('S')) {
				++p2;
			}
		} else {
			p1 = p2 = 16;
		}
		(void) printf("\033W%c%c", p1, p2);
	}
}

/* translate a mouse click or sweep to a selection */

int
mouseselection(MOUSEEVENT *p, int offset, int maxselection)
{
	int	i;

	i = p->y1 - offset;
	if (i < 0) {
		i = 0;
	} else if (i >= maxselection) {
		i = maxselection - 1;
	}
	return (i);
}

/* get the mouse event */

MOUSEEVENT *
getmouseevent(void)
{
	static	MOUSEEVENT	m;

	if (mouse == EMACSTERM) {
		switch (mygetch()) {
		case ctrl('_'):		/* click */
			if ((m.button = mygetch()) == '0') { /* if scroll bar */
				m.percent = getpercent();
			} else {
				m.x1 = getcoordinate();
				m.y1 = getcoordinate();
				m.x2 = m.y2 = -1;
			}
			break;

		case ctrl(']'):		/* sweep */
			m.button = mygetch();
			m.x1 = getcoordinate();
			m.y1 = getcoordinate();
			m.x2 = getcoordinate();
			m.y2 = getcoordinate();
			break;
		default:
			return (NULL);
		}
		return (&m);
	}
	return (NULL);
}

/* get a row or column coordinate from a mouse button click or sweep */

int
getcoordinate(void)
{
	int  c, next;

	c = mygetch();
	next = 0;
	if (c == ctrl('A')) {
		next = 95;
		c = mygetch();
	}
	if (c < ' ') {
		return (0);
	}
	return (next + c - ' ');
}

/* get a percentage */

int
getpercent(void)
{
	int c;

	c = mygetch();
	if (c < 16) {
		return (0);
	}
	if (c > 120) {
		return (100);
	}
	return (c - 16);
}

/* update the window label area */

int
labelarea(char *s)
{
	static	BOOL	labelon;

	switch (mouse) {
	case EMACSTERM:
		if (labelon == NO) {
			labelon = YES;
			(void) printf("\033L1");	/* force it on */
		}
		(void) printf("\033L!%s!", s);
		return (1);
	case MYX:
		(void) printf("\033[?%dv%s", strlen(s), s);
		return (1);
	case NONE:
	case PC7300:
	default:
		return (0);	/* no label area */
	}
}
