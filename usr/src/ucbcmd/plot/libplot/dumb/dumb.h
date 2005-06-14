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

/*
 * This accepts plot file formats and produces the appropriate plots
 * for dumb terminals.  It can also be used for printing terminals and
 * lineprinter listings, although there is no way to specify number of
 * lines and columns different from your terminal.  This would be easy
 * to change, and is left as an exercise for the reader.
 */

#include <math.h>

#define scale(x,y) y = LINES-1-(LINES*y/rangeY +minY); x = COLS*x/rangeX + minX

extern int minX, rangeX;	/* min and range of x */
extern int minY, rangeY;	/* min and range of y */
extern int currentx, currenty;
extern int COLS, LINES;

/* A very large screen! (probably should use malloc) */
#define MAXCOLS		132
#define MAXLINES	90

extern char screenmat[MAXCOLS][MAXLINES];
