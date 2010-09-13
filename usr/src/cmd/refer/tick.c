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

/* time programs */
#include <stdio.h>
#include <sys/types.h>

struct tbuffer {
	long	proc_user_time;
	long	proc_system_time;
	long	child_user_time;
	long	child_system_time;
};
static long start, user, systm;

void
tick(void)
{
	struct tbuffer tx;
	time_t tp;
	times(&tx);
	time(&tp);
	user =  tx.proc_user_time;
	systm = tx.proc_system_time;
	start = tp;
}

void
tock(void)
{
	struct tbuffer tx;
	time_t tp;
	float lap, use, sys;
	if (start == 0)
		return;
	times(&tx);
	time(&tp);
	lap = (tp - start)/60.;
	use = (tx.proc_user_time - user)/60.;
	sys = (tx.proc_system_time - systm)/60.;
	printf("Elapsed %.2f CPU %.2f (user %.2f, sys %.2f)\n",
	    lap, use+sys, use, sys);
}
