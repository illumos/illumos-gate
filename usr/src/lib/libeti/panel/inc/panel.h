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


#ifndef	_PANEL_H
#define	_PANEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

#include <curses.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct _obscured_list
	{
		struct PANEL	*panel_p;
		int	start, end;
		struct _obscured_list	*next;
	} _obscured_list;

typedef struct PANEL
	{
		WINDOW	*win;
		int	wstarty;
		int	wendy;
		int	wstartx;
		int	wendx;
		struct _obscured_list	*obscured;
		struct PANEL	*below, *above;
		char	*user;
	} PANEL;

#ifdef __STDC__

extern PANEL *new_panel(WINDOW *);
extern int del_panel(PANEL *);
extern int hide_panel(PANEL *);
extern int show_panel(PANEL *);
extern int panel_hidden(PANEL *);
extern int move_panel(PANEL *, int, int);
extern int replace_panel(PANEL *, WINDOW *);
extern int top_panel(PANEL *);
extern int bottom_panel(PANEL *);
extern void update_panels(void);
extern WINDOW *panel_window(PANEL *);
extern int set_panel_userptr(PANEL *, char *);
extern char *panel_userptr(PANEL *);
extern PANEL *panel_above(PANEL *);
extern PANEL *panel_below(PANEL *);

#else	/* old style extern's */

extern PANEL *new_panel();
extern int del_panel();
extern int hide_panel();
extern int show_panel();
extern int panel_hidden();
extern int move_panel();
extern int replace_panel();
extern int top_panel();
extern int bottom_panel();
extern void update_panels();
extern WINDOW *panel_window();
extern int set_panel_userptr();
extern char *panel_userptr();
extern PANEL *panel_above();
extern PANEL *panel_below();

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _PANEL_H */
