/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, Sun Microsystems, Inc.
 * All Rights Reserved.
 */


#include "imPcodes.h"
#include "imp.h"
extern imPcsize;
label(s)
char *s;
{
	register i,c;
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
