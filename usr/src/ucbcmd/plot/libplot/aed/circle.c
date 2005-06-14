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
 *	Circle draws a circle.
 *
 *	Results:	None.
 *
 *	Side Effects:
 *	A circle of radius r is drawn at (x,y).
 *---------------------------------------------------------
 */
circle(x, y, r)
int x, y, r;
{
    char buf[3];
    setcolor("01");
    putc('Q', stdout);
    outxy20(x, y);
    putc('O', stdout);
    chex((r*scale)>>12, buf, 2);
    fputs(buf, stdout);
    (void) fflush(stdout);
}
