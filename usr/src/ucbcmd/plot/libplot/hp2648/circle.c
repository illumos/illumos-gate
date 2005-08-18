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

#include "hp2648.h"

void
circle(int xc, int yc, int r)
{
	double costheta,sintheta,x,y,xn;
	int xi,yi;

	if(r<1){
		point(xc,yc);
		return;
	}
	sintheta = 1.0/r;
	costheta = pow(1-sintheta*sintheta,0.5);
	xi = x = r;
	yi = y = 0;
	do {
		point(xc+xi,yc+yi);
		xn = x;
		xi = x = x*costheta + y*sintheta;
		yi = y = y*costheta - xn*sintheta;
	} while( ! (yi==0 && xi >= r-1));
}
