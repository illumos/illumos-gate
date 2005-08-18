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

#include "aed.h"

/*---------------------------------------------------------
 *	This routine places a label starting at the current
 *	position.
 *
 *	Results:	None.
 *
 *	Side Effects:
 *	The string indicated by s starting at (curx, cury).
 *	The current position is updated accordingly.
 *---------------------------------------------------------
 */
void
label(char *s)
{
    setcolor("02");
    putc('Q', stdout);
    outxy20(curx + (4096/scale), cury + (4096/scale));
    putc('\6', stdout);
    fputs(s, stdout);
    putc('\33', stdout);
    (void) fflush(stdout);
    curx += ((6*4096*strlen(s)) + 4000)/scale;
}
