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

#include "imPcodes.h"
#include "imp.h"

extern int imPcsize;

void
label(char *s)
{
	int i,c;
	putch(imP_SET_ABS_H);
	putwd((int)((imPx-obotx)*scalex+botx)-imPcsize/2);
	putch(imP_SET_ABS_V);
	putwd((int)((imPy-oboty)*scaley+boty-(imPcsize/1.6)));
	for(i=0; c=s[i]; i++)
	{
		imPx += imPcsize/scalex;
		putch((c == ' ')?imP_SP:c);
	}
}
