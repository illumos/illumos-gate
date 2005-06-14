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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"

void
_vt_mark_overlap(v)
register struct vt	*v;
{
	register int	n;
	int	sr1, r1, sc1, c1;
	int	sr2, r2, sc2, c2;
	register struct vt	*vp;

	getbegyx(v->win, sr1, sc1);
	getmaxyx(v->win, r1, c1);
#ifdef _DEBUG
	_debug3(stderr, "vmark: window %d(#%d) - %d,%d %d,%d\n", v - VT_array, v->number, sr1, sc1, r1, c1);
#endif
	for (n = VT_front; n != VT_UNDEFINED; n = vp->next) {
		vp = &VT_array[n];
		getbegyx(vp->win, sr2, sc2);
		getmaxyx(vp->win, r2, c2);
		if (_vt_overlap(sr1, r1, sr2, r2) && _vt_overlap(sc1, c1, sc2, c2)) {
#ifdef _DEBUG
			_debug3(stderr, "\t\tmarking %d(#%d) dirty\n", n, vp->number);
#endif
			vp->flags |= VT_BDIRTY;
		}
	}
}
