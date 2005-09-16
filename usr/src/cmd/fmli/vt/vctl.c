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

#include	<curses.h>
#include	<stdio.h>
#include	<stdarg.h>
#include	"wish.h"
#include	"ctl.h"
#include	"vt.h"
#include	"vtdefs.h"
#include	"attrs.h"
#include	"color_pair.h"

int
vt_ctl(vt_id vid, unsigned cmd, ...)
{
	register struct vt	*v;
	register int	retval;
	va_list	args;
	int colpair, attr;

#ifdef _DEBUG

	if (vid < 0) {
		if ((vid = VT_curid) < 0)
			_debug(stderr, "NO CURRENT VT!\n");
	}
#else

	if (vid < 0)
		vid = VT_curid;
#endif

	v = &VT_array[vid];
	retval = SUCCESS;
	va_start(args, cmd);
	switch (cmd) {
	case CTSETATTR:
		attr = va_arg(args, int);
		colpair = va_arg(args, int);
		wattrset(v->win, COL_ATTR(attr, colpair));
		break;
	case CTSETLIM:
		{
			extern int	VT_firstline;
			extern int	VT_lastline;

			VT_firstline = va_arg(args, int);
			VT_lastline = va_arg(args, int);
		}
		break;
	case CTGETCUR:
		retval = VT_curid;
		break;
	case CTGETITLE:
		*(va_arg(args, char **)) = v->title;
		break;
	case CTGETWDW:
		retval = v->number;
		break;
	case CTSETWDW:
		v->number = va_arg(args, int);
		v->flags |= VT_TDIRTY;
		break;
	case CTSETITLE:
		v->title = va_arg(args, char*);
		v->flags |= VT_TDIRTY;
		break;
	case CTSETPARROWS:
		v->flags &= ~(VT_UPPARROW | VT_DNPARROW);
		v->flags |= va_arg(args, int) & (VT_UPPARROW | VT_DNPARROW);
		v->flags |= VT_PADIRTY;		/* page arrows */
		break;
	case CTSETSARROWS:
		v->flags &= ~(VT_UPSARROW | VT_DNSARROW);
		v->flags |= va_arg(args, int) & (VT_UPSARROW | VT_DNSARROW);
		v->flags |= VT_SADIRTY;		/* scroll arrows */
		break;
	case CTGETVT:
		retval = vid;
		break;
	case CTGETSIZ:
		{
			int	*rows;
			int	*cols;
			int	r;
			int	c;

			rows = va_arg(args, int *);
			cols = va_arg(args, int *);
			getmaxyx(v->win, r, c);
			if (!(v->flags & VT_NOBORDER)) {
				r -= 2;
				c -= 2;
			}
			*rows = r;
			*cols = c;
		}
		break;
	case CTGETSTRT:
		{
			int	r;
			int	c;
			extern int	VT_firstline;

			getbegyx(v->win, r, c);
			if (!(v->flags & VT_NOBORDER)) {
				r++;
				c++;
			}
			r -= VT_firstline;
			*(va_arg(args, int *)) = r;
			*(va_arg(args, int *)) = c;
		}
		break;
	case CTGETPOS:
		{
			int	r;
			int	c;

			getyx(v->win, r, c);
			if (!(v->flags & VT_NOBORDER)) {
				r--;
				c--;
			}
			*(va_arg(args, int *)) = r;
			*(va_arg(args, int *)) = c;
		}
		break;
	case CTHIDE:
		{
			register vt_id	i;
			register struct vt	*v;

			wnoutrefresh(stdscr);
			for (i = VT_front; i != VT_UNDEFINED; i = v->next) {
				v = &VT_array[i];
				v->flags |= VT_DIRTY;
			}
		}
		break;
	case CTCLEARWIN:
		wgo(0, 0);
		wclrwin(TRUE);
		break;
	default:
#ifdef _DEBUG
		_debug(stderr, "vt_ctl(%d, %d, ...) unknown command\n", vid, cmd);
#endif
		retval = FAIL;
		break;
	}
	va_end(args);
	return retval;
}
