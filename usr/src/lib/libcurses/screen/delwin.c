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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<stdlib.h>
#include	<sys/types.h>
#include	"curses_inc.h"

/* This routine deletes a _window and releases it back to the system. */

int
delwin(WINDOW *win)
{
	int		i;
	WINDOW		*par;

	/* If we have children don't delte the window. */
	if (win->_ndescs > 0)
		return (ERR);

	/*
	 * If window is a pad, delete the padwin associated with it.
	 * NOTE: We shouldn't care that the recursive call will decrement
	 * ndescs for this window, since the window will be deleted anyhow.
	 */

	if (win->_padwin) {
		win->_padwin->_maxy = win->_maxy;
		(void) delwin(win->_padwin);
	}
	if (win->_parent == NULL) {
		/* Delete all the memory associated with this window. */
		for (i = win->_maxy; i-- > 0; ) {
			free((char *)win->_y[i]);
#ifdef	_VR3_COMPAT_CODE
			if (_y16update)
				free((char *)win->_y16[i]);
#endif	/* _VR3_COMPAT_CODE */
		}
	} else {
	/*
	 * We are a subwin and we don't want to delete the memory since
	 * it's shared by other windows.  We do want to decrement the
	 * descendant count so that if there are no children left to a
	 * particular window winsdelln.c will run in fast mode (look there).
	 */
		for (par = win->_parent; par != NULL; par = par->_parent)
			par->_ndescs--;
	}

#ifdef	_VR3_COMPAT_CODE
	if (_y16update)
		free((char *)win->_y16);
#endif	/* _VR3_COMPAT_CODE */

	free((char *)win->_y);
	free((char *)win->_firstch);
	free((char *)win);
	return (OK);
}
