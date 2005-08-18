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

#include "imp.h"

/*
 * Hack to set font.
 */
void
linemod(char *s)
{
	char *tit;
	char *nam;
	int siz = 0;
	nam = s;
	for(tit = "charset="; *tit; )
		if (*tit++ != *nam++)
			return;
	s = nam;
	while(*nam) 
		switch(*nam++) {
		case ',':
		case '\n':
			*--nam = 0;
		}
	siz = atoi(++nam);
	if (siz == 0) {
		while (*--nam >= '0' && *nam <= '9')
			;
		siz = (atoi(++nam)*4)/3;
	}
	if (siz == 0)
		siz = imPcsize;
	setfont(s, siz);
}
