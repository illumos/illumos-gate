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

# include "con.h"

float deltx = 4095.;
float delty = 4095.;

void
space(int x0, int y0, int x1, int y1)
{
	botx = -2047.;
	boty = -2047.;
	obotx = x0;
	oboty = y0;
	scalex = deltx/(x1-x0);
	scaley = delty/(y1-y0);
}
