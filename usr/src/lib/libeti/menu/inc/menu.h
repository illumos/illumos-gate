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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MENU_H
#define	_MENU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.15	*/

#include <curses.h>
#include <eti.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Menu options: */
#define	O_ONEVALUE	0x01
#define	O_SHOWDESC	0x02
#define	O_ROWMAJOR	0x04
#define	O_IGNORECASE	0x08
#define	O_SHOWMATCH	0x10
#define	O_NONCYCLIC	0x20

/* Item options: */
#define	O_SELECTABLE	0x01

typedef struct {
	char	*str;
	int	length;
} TEXT;

typedef struct ITEM {
	TEXT		name;
	TEXT		description;
	int		index;		/* Item number */
	struct MENU	*imenu;		/* Pointer to parent menu */
	int		 value;
	char		*userptr;
	OPTIONS		 opt;
	int		 status;
	short		 y;		/* y and x location of item in menu */
	short		 x;
	struct ITEM	 *left;
	struct ITEM	 *right;
	struct ITEM	 *up;
	struct ITEM	 *down;
} ITEM;

#define	_POSTED		0x1
#define	_IN_DRIVER	0x2
#define	_LINK_NEEDED	0x4

typedef struct MENU {
	int		height;		/* Number of chars high */
	int		width;		/* Number of chars wide */
	int		rows;		/* Number of items high */
	int		cols;		/* Number of items wide */
	int		frows;		/* Number of formated items high */
	int		fcols;		/* Number of formated items wide */
	int		namelen;	/* Length of widest name */
	int		desclen;	/* Length of widest description */
	int		marklen;	/* Length of mark */
	int		itemlen;	/* Length of an one item */
	char		*pattern;	/* Buffer used to store match chars */
	int		pindex;		/* Index into pattern buffer */
	WINDOW		*win;		/* Window containing entire menu */
	WINDOW		*sub;		/* Portion of menu displayed */
	WINDOW		*userwin;	/* User's window */
	WINDOW		*usersub;	/* User's subwindow */
	ITEM		**items;
	int 		nitems;		/* Total number of items in menu */
	ITEM		*curitem;	/* Current item */
	int		toprow;		/* Top row of menu */
	int		pad;		/* Pad character */
	chtype		fore;		/* Attribute for selection */
	chtype		back;		/* Attribute for nonselection */
	chtype		grey;		/* Attribute for inactive */
	PTF_void	menuinit;
	PTF_void	menuterm;
	PTF_void	iteminit;
	PTF_void	itemterm;
	char		*userptr;
	char		*mark;
	OPTIONS		opt;
	int		status;
} MENU;

/* Define keys */

#define	REQ_LEFT_ITEM		KEY_MAX+1
#define	REQ_RIGHT_ITEM		KEY_MAX+2
#define	REQ_UP_ITEM		KEY_MAX+3
#define	REQ_DOWN_ITEM		KEY_MAX+4
#define	REQ_SCR_ULINE		KEY_MAX+5
#define	REQ_SCR_DLINE		KEY_MAX+6
#define	REQ_SCR_DPAGE		KEY_MAX+7
#define	REQ_SCR_UPAGE		KEY_MAX+8
#define	REQ_FIRST_ITEM		KEY_MAX+9
#define	REQ_LAST_ITEM		KEY_MAX+10
#define	REQ_NEXT_ITEM		KEY_MAX+11
#define	REQ_PREV_ITEM		KEY_MAX+12
#define	REQ_TOGGLE_ITEM		KEY_MAX+13
#define	REQ_CLEAR_PATTERN	KEY_MAX+14
#define	REQ_BACK_PATTERN	KEY_MAX+15
#define	REQ_NEXT_MATCH		KEY_MAX+16
#define	REQ_PREV_MATCH		KEY_MAX+17

#ifdef __STDC__

extern ITEM	**menu_items(MENU *),
		*current_item(MENU *),
		*new_item(char *, char *);
extern MENU	*new_menu(ITEM **);
extern OPTIONS	item_opts(ITEM *),
		menu_opts(MENU *);
extern PTF_void	item_init(MENU *),
		item_term(MENU *),
		menu_init(MENU *),
		menu_term(MENU *);
extern WINDOW	*menu_sub(MENU *),
		*menu_win(MENU *);
extern char	*item_description(ITEM *),
		*item_name(ITEM *),
		*item_userptr(ITEM *),
		*menu_mark(MENU *),
		*menu_pattern(MENU *),
		*menu_userptr(MENU *);
extern chtype	menu_back(MENU *),
		menu_fore(MENU *),
		menu_grey(MENU *);
extern int	free_item(ITEM *),
		free_menu(MENU *),
		item_count(MENU *),
		item_index(ITEM *),
		item_opts_off(ITEM *, OPTIONS),
		item_opts_on(ITEM *, OPTIONS),
		item_value(ITEM *),
		item_visible(ITEM *),
		menu_driver(MENU *, int),
		menu_opts_off(MENU *, OPTIONS),
		menu_opts_on(MENU *, OPTIONS),
		menu_pad(MENU *),
		pos_menu_cursor(MENU *),
		post_menu(MENU *),
		scale_menu(MENU *, int *, int *),
		set_current_item(MENU *, ITEM *),
		set_item_init(MENU *, PTF_void),
		set_item_opts(ITEM *, OPTIONS),
		set_item_term(MENU *, PTF_void),
		set_item_userptr(ITEM *, char *),
		set_item_value(ITEM *, int),
		set_menu_back(MENU *, chtype),
		set_menu_fore(MENU *, chtype),
		set_menu_format(MENU *, int, int),
		set_menu_grey(MENU *, chtype),
		set_menu_init(MENU *, PTF_void),
		set_menu_items(MENU *, ITEM **),
		set_menu_mark(MENU *, char *),
		set_menu_opts(MENU *, OPTIONS),
		set_menu_pad(MENU *, int),
		set_menu_pattern(MENU *, char *),
		set_menu_sub(MENU *, WINDOW *),
		set_menu_term(MENU *, PTF_void),
		set_menu_userptr(MENU *, char *),
		set_menu_win(MENU *, WINDOW *),
		set_top_row(MENU *, int),
		top_row(MENU *),
		unpost_menu(MENU *);
void		menu_format(MENU *, int *, int *);

#else	/* old style extern's */

extern ITEM	**menu_items(),
		*current_item(),
		*new_item();
extern MENU	*new_menu();
extern OPTIONS	item_opts(),
		menu_opts();
extern PTF_void	item_init(),
		item_term(),
		menu_init(),
		menu_term();
extern WINDOW	*menu_sub(),
		*menu_win();
extern char	*item_description(),
		*item_name(),
		*item_userptr(),
		*menu_mark(),
		*menu_pattern(),
		*menu_userptr();
extern chtype	menu_back(),
		menu_fore(),
		menu_grey();
extern int	free_item(),
		free_menu(),
		item_count(),
		item_index(),
		item_opts_off(),
		item_opts_on(),
		item_value(),
		item_visible(),
		menu_driver(),
		menu_opts_off(),
		menu_opts_on(),
		menu_pad(),
		pos_menu_cursor(),
		post_menu(),
		scale_menu(),
		set_current_item(),
		set_item_init(),
		set_item_opts(),
		set_item_term(),
		set_item_userptr(),
		set_item_value(),
		set_menu_back(),
		set_menu_fore(),
		set_menu_format(),
		set_menu_grey(),
		set_menu_init(),
		set_menu_items(),
		set_menu_mark(),
		set_menu_opts(),
		set_menu_pad(),
		set_menu_pattern(),
		set_menu_sub(),
		set_menu_term(),
		set_menu_userptr(),
		set_menu_win(),
		set_top_row(),
		top_row(),
		unpost_menu();
void		menu_format();

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_H */
