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

#include "dumb.h"

void
line(int x0, int y0, int x1, int y1)
{
	int x,y;

	scale(x0, y0);
	x = x1;
	y = y1;
	scale(x, y);
	currentx = x0;
	currenty = y0;
	screenmat[currentx][currenty] = '*';
	dda_line('*', x0, y0, x1, y1);
}
