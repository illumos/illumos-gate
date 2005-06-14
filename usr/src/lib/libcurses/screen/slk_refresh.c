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

#include	<sys/types.h>
#include	"curses_inc.h"

/* Update the soft-label window. */

int
slk_refresh(void)
{
	if (_slk_update()) {
		return (wrefresh(SP->slk->_win));
	}
	return (0);
}

/* Update soft labels. Return TRUE if a window was updated. */

int
_slk_update(void)
{
	WINDOW	*win;
	SLK_MAP	*slk;
	int	i;

	if ((slk = SP->slk) == NULL || (slk->_changed != TRUE))
		return (FALSE);

	win = slk->_win;
	for (i = 0; i < slk->_num; ++i)
		if (slk->_lch[i]) {
			if (win)
				(void) mvwaddstr(win, 0, slk->_labx[i],
				    slk->_ldis[i]);
			else
				_PUTS(tparm_p2(plab_norm, i + 1,
				    (long)slk->_ldis[i]), 1);

			slk->_lch[i] = FALSE;
		}
	if (!win) {
		_PUTS(label_on, 1);
		/*
		 * Added an fflush because if application code calls a
		 * slk_refresh or a slk_noutrefresh
		 * and a doupdate nothing will get flushed since this
		 * information is not being kept in curscr or _virtscr.
		 */
		(void) fflush(SP->term_file);
	}

	slk->_changed = FALSE;

	return (win ? TRUE : FALSE);
}
