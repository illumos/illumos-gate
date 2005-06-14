/*
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#ifndef lint
static char
sccsid[] = "@(#)longname.c 1.6 88/02/08 SMI"; /* from UCB 5.1 85/06/07 */
#endif /* not lint */

/*
 *	This routine fills in "def" with the long name of the terminal.
 */

char *
longname(char *bp, char *def)
{
	char	*cp;

	while (*bp && *bp != ':' && *bp != '|')
		bp++;
	if (*bp == '|') {
		bp++;
		cp = def;
		while (*bp && *bp != ':' && *bp != '|')
			*cp++ = *bp++;
		*cp = 0;
	}
	return (def);
}
