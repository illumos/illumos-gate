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
erase(void)
{
	buffready(8);
	putchar(ESC);
	putchar(GRAPHIC);
	putchar(DISPLAY);
	putchar('a');
	putchar(ESC);
	putchar(GRAPHIC);
	putchar(PLOT);
	putchar(BINARY);
}
