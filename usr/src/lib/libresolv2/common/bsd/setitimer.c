/*
 * Copyright (c) 1997-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef LINT
static const char rcsid[] = "$Id: setitimer.c,v 8.4 1999/10/13 16:39:21 vixie Exp $";
#endif


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "port_before.h"

#include <sys/time.h>

#include "port_after.h"

/*
 * Setitimer emulation routine.
 */
#ifndef NEED_SETITIMER
int __bindcompat_setitimer;
#else

int
__setitimer(int which, const struct itimerval *value,
	    struct itimerval *ovalue)
{
	if (alarm(value->it_value.tv_sec) >= 0)
		return (0);
	else
		return (-1);
}
#endif
