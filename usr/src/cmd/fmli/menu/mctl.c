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
#include	<stdarg.h>
#include	"wish.h"
#include	"ctl.h"
#include	"menu.h"
#include	"menudefs.h"

int
menu_ctl(menu_id mid, unsigned cmd, ...)
{
    register int  retval;
    register struct menu *m;
    struct menu_line men;
    va_list args;

    retval = SUCCESS;
    if (mid < 0)
	mid = MNU_curid;
    m = &MNU_array[mid];
    va_start(args, cmd);
    switch (cmd)
    {
    case CTGETCUR:
	retval = MNU_curid;
	break;
    case CTGETPOS:
	*(va_arg(args, int *)) = m->index;
	break;
    case CTSETPOS:
	menu_index(m, va_arg(args, int), MENU_ALL);
	break;
    case CTSETATTR:
	m->flags |= MENU_MSELECT;
	break;
    case CTGETITLE:
    case CTSETITLE:
	retval = vt_ctl(m->vid, cmd, va_arg(args, char **));
	break;
    case CTGETWDW:
	retval = vt_ctl(m->vid, cmd);
	break;
    case CTGETVT:
	retval = m->vid;
	break;
    case CTGETSIZ:
	retval = m->number;
	break;
    case CTSETARG:
	m->arg = va_arg(args, char *);
	break;
    case CTSETDIRTY:
	m->flags |= MENU_DIRTY;
	break;
    case CTGETPARMS:
	*(va_arg(args, int *)) = m->topline;
	*(va_arg(args, int *)) = m->index;
	break;
    case CTSETPARMS:
    {
	int	rows, cols;

	m->topline = va_arg(args, int);
	m->index = va_arg(args, int);
	m->flags |= MENU_DIRTY;
	vt_ctl(m->vid, CTGETSIZ, &rows, &cols);
	if (m->index >= m->number)
	    m->index = m->number - 1;
    }
	break;
    case CTGETLIST:
    {
	int itemnum;
	char *item;

	itemnum = va_arg(args, int);
	item = (char *) menu_list(m, itemnum);
	*(va_arg(args, char **)) = item;
	
    }
	break;
    case CTSETSHAPE:
    {
	int	srow, scol, rows, cols;

	srow = va_arg(args, int);
	scol = va_arg(args, int);
	rows = va_arg(args, int);
	cols = va_arg(args, int);
	if (srow >= 0)
	    _menu_reshape(m, srow, scol, rows, cols);
    }
	break;
    case CTSETSTRT:
	vt_current(m->vid);	/* abs k15 */
	menu_index(m, 0, MENU_ALL);
	/*
	 * This code determines the first menu item reached
	 * when the menu is updated.
	 *
	 * Do not match inactive menu items.
	 */
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
	break;
    default:
#ifdef _DEBUG
	_debug(stderr, "menu_ctl(%d, %d, ...) unknown command\n", mid, cmd);
#endif
	retval = FAIL;
	break;
    }
    va_end(args);
    return retval;
}
