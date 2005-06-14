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
 * Copyright (c) 1997, by Sun Mircrosystems, Inc.
 * All rights reserved.
 */

#ifndef _MENU_PRIVATE_H
#define	_MENU_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include <menu.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Menu macros to access menu structure */

#define	Height(m)	(m)->height
#define	Width(m)	(m)->width
#define	Rows(m)		(m)->rows
#define	Cols(m)		(m)->cols
#define	FRows(m)	(m)->frows
#define	FCols(m)	(m)->fcols
#define	MaxName(m)	(m)->namelen
#define	MaxDesc(m)	(m)->desclen
#define	Marklen(m)	(m)->marklen
#define	Itemlen(m)	(m)->itemlen
#define	Pattern(m)	(m)->pattern
#define	Pindex(m)	(m)->pindex
#define	IthPattern(m, i)	(m)->pattern[i]
#define	Win(m)		(m)->win
#define	Sub(m)		(m)->sub
#define	UserWin(m)	(m)->userwin
#define	UserSub(m)	(m)->usersub
#define	UW(m)		(UserWin(m) ? UserWin(m) : stdscr)
#define	US(m)		(UserSub(m) ? UserSub(m) : UW(m))
#define	Items(m)	(m)->items
#define	IthItem(m, i)	(m)->items[i]
#define	Nitems(m)	(m)->nitems
#define	Current(m)	(m)->curitem
#define	Top(m)		(m)->toprow
#define	Pad(m)		(m)->pad
#define	Fore(m)		(m)->fore
#define	Back(m)		(m)->back
#define	Grey(m)		(m)->grey
#define	InvalidAttr(a)	(((a) & (chtype) A_ATTRIBUTES) != (a))
#define	Mhelp(m)	(m)->help
#define	Muserptr(m)	(m)->userptr
#define	Mopt(m)		(m)->opt
#define	Mark(m)		(m)->mark
#define	Mstatus(m)	(m)->status
#define	Posted(m)	(Mstatus(m) & _POSTED)
#define	Indriver(m)	(Mstatus(m) & _IN_DRIVER)
#define	LinkNeeded(m)	(Mstatus(m) & _LINK_NEEDED)
#define	SetPost(m)	(Mstatus(m) |= _POSTED)
#define	SetDriver(m)	(Mstatus(m) |= _IN_DRIVER)
#define	SetLink(m)	(Mstatus(m) |= _LINK_NEEDED)
#define	ResetPost(m)	(Mstatus(m) &= ~_POSTED)
#define	ResetDriver(m)	(Mstatus(m) &= ~_IN_DRIVER)
#define	ResetLink(m)	(Mstatus(m) &= ~_LINK_NEEDED)
#define	SMinit(m)	(m)->menuinit
#define	SMterm(m)	(m)->menuterm
#define	SIinit(m)	(m)->iteminit
#define	SIterm(m)	(m)->itemterm
#define	Minit(m)	if (m->menuinit) { \
			    SetDriver(m); \
			    (m)->menuinit(m); \
			    ResetDriver(m); \
			}
#define	Mterm(m)	if (m->menuterm) { \
			    SetDriver(m); \
			    (m)->menuterm(m); \
			    ResetDriver(m); \
			}
#define	Iinit(m)	if (m->iteminit) { \
			    SetDriver(m); \
			    (m)->iteminit(m); \
			    ResetDriver(m); \
			}
#define	Iterm(m)	if (m->itemterm) { \
			    SetDriver(m); \
			    (m)->itemterm(m); \
			    ResetDriver(m); \
			}

/* Define access to Mopt */

#define	OneValue(m)	(Mopt(m) & O_ONEVALUE)
#define	ShowDesc(m)	(Mopt(m) & O_SHOWDESC)
#define	RowMajor(m)	(Mopt(m) & O_ROWMAJOR)
#define	IgnoreCase(m)	(Mopt(m) & O_IGNORECASE)
#define	ShowMatch(m)	(Mopt(m) & O_SHOWMATCH)
#define	Cyclic(m)	(!(Mopt(m) & O_NONCYCLIC))

/* Item macros to access item structure */

#define	Name(i)		(i)->name.str
#define	NameLen(i)	(i)->name.length
#define	Description(i)	(i)->description.str
#define	DescriptionLen(i)	(i)->description.length
#define	Index(i)	(i)->index
#define	Y(i)		(i)->y
#define	X(i)		(i)->x
#define	Imenu(i)	(i)->imenu
#define	Value(i)	(i)->value
#define	Ihelp(i)	(i)->help
#define	Iuserptr(i)	(i)->userptr
#define	Iopt(i)		(i)->opt
#define	Istatus(i)	(i)->status
#define	Up(i)		(i)->up
#define	Down(i)		(i)->down
#define	Left(i)		(i)->left
#define	Right(i)	(i)->right
#define	Selectable(i)	(Iopt(i) & O_SELECTABLE)

/* Default menu macros */

#define	Dfl_Menu	(&_Default_Menu)
#define	Dfl_Item	(&_Default_Item)

#define	max(a, b)	((a) > (b)) ? (a) : (b)
#define	min(a, b)	((a) < (b)) ? (a) : (b)

extern MENU		_Default_Menu;
extern ITEM		_Default_Item;

extern void		_affect_change(MENU *, int, ITEM *);
extern void		_chk_current(MENU *, int *, ITEM *);
extern void		_chk_top(MENU *, int *, ITEM *);
extern void		_disconnect(MENU *);
extern void		_draw(MENU *);
extern void		_link_items(MENU *);
extern void		_move_post_item(MENU *, ITEM *);
extern void		_movecurrent(MENU *, ITEM *);
extern void		_position_cursor(MENU *);
extern void		_scale(MENU *);
extern void		_show(MENU *);
extern int		_match(MENU *, char, ITEM **);
extern int		_connect(MENU *, ITEM **);

#ifdef __cplusplus
}
#endif

#endif	/* _MENU_PRIVATE_H */
