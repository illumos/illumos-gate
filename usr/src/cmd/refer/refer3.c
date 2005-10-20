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

#include "refer..c"
#define	move(x, y) close(y); dup(x); close(x);

extern void err();

int
corout(char *in, char *out, char *rprog, char *arg, int outlen)
{
	int pipev[2], fr1, fr2, fw1, fw2, n;
	int status;

	pipe(pipev);
	fr1 = pipev[0];
	fw1 = pipev[1];
	pipe(pipev);
	fr2 = pipev[0];
	fw2 = pipev[1];
	if (fork() == 0) {
		close(fw1);
		close(fr2);
		move(fr1, 0);
		move(fw2, 1);
		execl(rprog, "deliv", arg, 0);
		err("Can't run %s", rprog);
	}
	close(fw2);
	close(fr1);
	write(fw1, in, strlen(in));
	close(fw1);
	wait(&status);
	n = read(fr2, out, outlen);
	out[n] = 0;
	close(fr2);
	return (n);
}
