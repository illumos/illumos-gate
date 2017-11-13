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
 * Copyright 2017 RackTop Systems.
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
#include <errno.h>

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

/*
 * Find highest one bit set.
 *	Returns bit number + 1 of highest bit that is set, otherwise returns 0.
 */
int
highbit64(uint64_t i)
{
	int h = 1;

	if (i == 0)
		return (0);
	if (i & 0xffffffff00000000ULL) {
		h += 32; i >>= 32;
	}
	if (i & 0xffff0000) {
		h += 16; i >>= 16;
	}
	if (i & 0xff00) {
		h += 8; i >>= 8;
	}
	if (i & 0xf0) {
		h += 4; i >>= 4;
	}
	if (i & 0xc) {
		h += 2; i >>= 2;
	}
	if (i & 0x2) {
		h += 1;
	}
	return (h);
}

int
ddi_strtoul(const char *str, char **endp, int base, unsigned long *res)
{
	*res = strtoul(str, endp, base);
	if (*res == 0)
		return (errno);
	return (0);
}

int
ddi_strtoull(const char *str, char **nptr, int base, u_longlong_t *res)
{
	char *end;

	*res = strtoull(str, &end, base);
	if (*res == 0)
		return (errno);
	return (0);
}

void
delay(clock_t ticks)
{
	int msec = ticks;  /* NB: hz==1000 */
	(void) poll(0, 0, msec);
}

int
issig(int why)
{
	return (0);
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
