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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * wattr_on.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/wattr_on.c 1.3 1998/05/28 17:10:27 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef wattr_on

/* ARGSUSED */
int
wattr_on(WINDOW *w, attr_t at, void *opts)
{
	w->_fg._at |= at;

	return (OK);
}

#undef wattr_off

/* ARGSUSED */
int
wattr_off(WINDOW *w, attr_t at, void *opts)
{
	w->_fg._at &= ~at;

	return (OK);
}

#undef wattr_set

/* ARGSUSED */
int
wattr_set(WINDOW *w, attr_t at, short co, void *opts)
{
	w->_fg._co = co;
	w->_fg._at = w->_bg._at | at;

	return (OK);
}

#undef wattr_get

/* ARGSUSED */
int
wattr_get(WINDOW *w, attr_t *at, short *co, void *opts)
{
	if (at != NULL)
		*at = w->_fg._at;

	if (co != NULL)
		*co = w->_fg._co;

	return (OK);
}

#undef wcolor_set

/* ARGSUSED */
int
wcolor_set(WINDOW *w, short co, void *opts)
{
	w->_fg._co = co;

	return (OK);
}

#undef wstandout

int
wstandout(WINDOW *w)
{
	w->_fg._at |= WA_STANDOUT;

	return (1);
}

#undef wstandend

int
wstandend(WINDOW *w)
{
	w->_fg._at = WA_NORMAL;

	return (1);
}
