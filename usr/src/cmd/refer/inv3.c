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

int
getargs(char *s, char *arps[])
{
	int i = 0;

	while (1) {
		arps[i++] = s;
		while (*s != 0 && *s != ' ' && *s != '\t')
			s++;
		if (*s == 0)
			break;
		*s++ = 0;
		while (*s == ' ' || *s == '\t')
			s++;
		if (*s == 0)
			break;
	}
	return (i);
}
