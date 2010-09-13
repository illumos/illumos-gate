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


char refdir[50];

extern int corout();
extern char *trimnl();

void
savedir(void)
{
	if (refdir[0] == 0)
		corout("", refdir, "/usr/bin/pwd", "", 50);
	trimnl(refdir);
}

void
restodir(void)
{
	chdir(refdir);
}
