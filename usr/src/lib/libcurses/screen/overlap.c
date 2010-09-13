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

/*
 * This routine writes Srcwin on Dstwin.
 * Only the overlapping region is copied.
 */

int
_overlap(WINDOW *Srcwin, WINDOW *Dstwin, int Overlay)
{
	int	sby, sbx, sey, sex, dby, dbx, dey, dex,
		top, bottom, left, right;

#ifdef	DEBUG
	if (outf)
		fprintf(outf, "OVERWRITE(0%o, 0%o);\n", Srcwin, Dstwin);
#endif	/* DEBUG */

	sby = Srcwin->_begy;	dby = Dstwin->_begy;
	sbx = Srcwin->_begx;	dbx = Dstwin->_begx;
	sey = sby + Srcwin->_maxy;	dey = dby + Dstwin->_maxy;
	sex = sbx + Srcwin->_maxx;	dex = dbx + Dstwin->_maxx;

	if (sey < dby || sby > dey || sex < dbx || sbx > dex)
		return (ERR);

	top = _MAX(sby, dby);	bottom = _MIN(sey, dey);
	left = _MAX(sbx, dbx);	right = _MIN(sex, dex);

	sby = top - sby;		sbx = left - sbx;
	dey = bottom - dby - 1;	dex = right - dbx - 1;
	dby = top - dby;		dbx = left - dbx;

	return (copywin(Srcwin, Dstwin, sby, sbx, dby, dbx, dey, dex, Overlay));
}
