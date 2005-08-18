/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

extern float botx;
extern float boty;
extern float obotx;
extern float oboty;
extern float scalex;
extern float scaley;
extern int scaleflag;

void
space(int x0, int y0, int x1, int y1)
{
	botx = 0.;
	boty = 0.;
	obotx = x0;
	oboty = y0;
	if(scaleflag)
		return;
	scalex = 780./(x1-x0);
	scaley = 780./(y1-y0);
}
