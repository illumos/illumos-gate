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

int
wattroff(WINDOW *win, chtype a)
{
	/* if attribute contains color information, but this is not a color  */
	/* terminal, or that color information doesn't match the one stored  */
	/* inside _attrs,  ignore that information.			   */

	if (((a & A_COLOR) && (cur_term->_pairs_tbl == NULL)) ||
	    ((a & A_COLOR) != (win->_attrs & A_COLOR)))
		a &= ~A_COLOR;

	if ((a & A_ATTRIBUTES) == A_NORMAL)
		return (1);

	/* turn off the attributes		*/

	win->_attrs &= ~a & A_ATTRIBUTES;

	/* if background contains color information different from the one */
	/* we have just turned off, turn that color on.  (Reason: the	*/
	/* color we have just turned off was set by wattron(), so the	*/
	/* back-ground color was blocked.  However, now the background	*/
	/* color can be seen.						*/

	if ((a & A_COLOR) && ((a & A_COLOR) != (win->_bkgd & A_COLOR)))
		win->_attrs |= (win->_bkgd & A_COLOR);

	return (1);
}
