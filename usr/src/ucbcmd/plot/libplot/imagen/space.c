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


extern float botx;
extern float boty;
extern float obotx;
extern float oboty;
extern float scalex;
extern float scaley;

int PlotRes = DEFRES;

int scaleflag;
space(x0,y0,x1,y1){
	botx = 2.;
	boty = 2.;
	obotx = x0;
	oboty = y0;
	if(scaleflag)
		return;
	scalex = (8.0 * PlotRes)/(x1-x0);
	scaley = (8.0 * PlotRes)/(y1-y0);
}
