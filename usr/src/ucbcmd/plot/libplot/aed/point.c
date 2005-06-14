/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */


#include "aed.h"

/*---------------------------------------------------------
 *	This routine plots a single point.
 *
 *	Results:	None.
 *
 *	Side Effects:
 *	A single point is displayed on the screen.
 *	The point is made the current point.
 *---------------------------------------------------------
 */
point(x, y)
int x, y;
{
    setcolor("01");
    putc('Q', stdout);
    outxy20(x, y);
    fputs("O01", stdout);
    (void) fflush(stdout);
    curx = x;
    cury = y;
}
