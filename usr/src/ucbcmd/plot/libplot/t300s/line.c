/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

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
	char chx,chy,command;
	    float xd,yd;
	float dist2(),sqrt();
	movep(cx0,cy0);
	maxp = sqrt(dist2(cx0,cy0,cx1,cy1))/2.;
	xd = cx1-cx0;
	yd = cy1-cy0;
	command = COM|((xd<0)<<1)|(yd<0);
	if(maxp == 0){
		xd=0;
		yd=0;
	}
	else {
		xd /= maxp;
		yd /= maxp;
	}
	inplot();
	spew(command);
	for (tt=0; tt<=maxp; tt++){
		chx= cx0+xd*tt-xnow;
		xnow += chx;
		chx = abval(chx);
		chy = cy0+yd*tt-ynow;
		ynow += chy;
		chy = abval(chy);
		spew(ADDR|chx<<3|chy);
	}
	outplot();
	return;
}
