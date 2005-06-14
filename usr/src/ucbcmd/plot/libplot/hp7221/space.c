/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */


#include "hp7221.h"

space(x0,y0,x1,y1)
int x0,y0,x1,y1;
{
	double scalex, scaley;
	lowx = x0;
	lowy = y0;
	scalex = XMAX/(double)(x1-lowx);
	scaley = YMAX/(double)(y1-lowy);
	scale = scalex < scaley ? scalex : scaley;
}
