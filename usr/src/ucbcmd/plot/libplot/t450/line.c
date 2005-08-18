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

#include "con.h"

void iline(int, int, int, int);

void
line(int x0, int y0, int x1, int y1)
{
	iline(xconv(xsc(x0)),yconv(ysc(y0)),xconv(xsc(x1)),yconv(ysc(y1)));
		return;
}

void
cont(int x0, int y0)
{
	iline(xnow,ynow,xconv(xsc(x0)),yconv(ysc(y0)));
	return;
}

void
iline(int cx0, int cy0, int cx1, int cy1)
{
	int maxp,tt,j,np;
	char chx,chy;
	float xd,yd;
	float dist2(),sqrt();
		movep(cx0,cy0);
		maxp = sqrt(dist2(cx0,cy0,cx1,cy1))/2.;
		xd = cx1-cx0;
		yd = cy1-cy0;
		if(xd >= 0)chx = RIGHT;
		else chx = LEFT;
		if(yd >= 0)chy = UP;
		else chy = DOWN;
		if(maxp == 0){
			xd=0;
			yd=0;
		}
		else{
			xd /= maxp;
			yd /= maxp;
		}
		inplot();
		for (tt=0; tt<=maxp; tt++){
			j= cx0+xd*tt-xnow;
			xnow += j;
			j = abval(j);
			while(j-- > 0)spew(chx);
			j = cy0+yd*tt-ynow;
			ynow += j;
			j = abval(j);
			while(j-- > 0)spew(chy);
			spew ('.');
		}
		outplot();
		return;
}
