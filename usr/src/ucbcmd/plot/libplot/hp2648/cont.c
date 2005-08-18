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
cont(int xi, int yi)
{
	char xb1,xb2,yb1,yb2;
	itoa(xsc(xi),&xb1,&xb2);
	itoa(ysc(yi),&yb1,&yb2);
	buffready(4);
	putchar(xb2);
	putchar(xb1);
	putchar(yb2);
	putchar(yb1); 
	currentx = xsc(xi);
	currenty = ysc(yi);
}
