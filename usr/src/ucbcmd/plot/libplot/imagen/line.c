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

#include "imp.h"
#include "imPcodes.h"

float obotx = 0.;
float oboty = 0.;
float botx = 2.;
float boty = 2.;
float scalex = 1.;
float scaley = 1.;

void putch(int);
void putwd(int);

void
line(int x0, int y0, int x1, int y1)
{
	putch(imP_CREATE_PATH);
	putwd(2);		/* two coordinates follow */
	putwd((int)((x0-obotx)*scalex+botx));	
	putwd((int)((y0-oboty)*scaley+boty));	
	putwd((int)((x1-obotx)*scalex+botx));	
	putwd((int)((y1-oboty)*scaley+boty));	
	putch(imP_DRAW_PATH);
	putch(15);		/* "black" lines */
	imPx = x1;
	imPy = y1;
}

void
putch(int c)
{
	putc(c, stdout);
}

void
putwd(int w)
{
	putch(w>>8);
	putch(w);
}
