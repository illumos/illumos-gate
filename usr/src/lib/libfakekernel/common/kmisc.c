/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/zone.h>

#include <sys/poll.h>

#include <time.h>
#include <stdlib.h>
#include <unistd.h>

#include <fakekernel.h>

pri_t minclsyspri = 60;

/* Some kernel code takes the address of this. */
proc_t p0;

proc_t *
_curproc(void)
{
	return (&p0);
}

zone_t zone0 = {
	.zone_name = "global",
	.zone_zsched = &p0, 0
};

zone_t *
_curzone(void)
{
	return (&zone0);
}

pid_t
ddi_get_pid(void)
{
	return ((pid_t)getpid());
}

int
ddi_strtoul(const char *str, char **endp, int base, unsigned long *res)
{
	*res = strtoul(str, endp, base);
	return (0);
}

void
delay(clock_t ticks)
{
	int msec = ticks;  /* NB: hz==1000 */
	(void) poll(0, 0, msec);
}

/*
 * This library does not really need an "init" function, but
 * providing one the main program can call is an easy way to
 * make sure this library is loaded into the debugger, and
 * gives us a way to avoid elfcheck complaints in the build.
 */
void
fakekernel_init(void)
{
}
