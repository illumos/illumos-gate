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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/brand.h>
#include <sys/lx_brand.h>

/*
 * From "uts/common/syscall/getrandom.c":
 */
extern int getrandom(void *, size_t, int);

long
lx_getrandom(void *bufp, size_t buflen, int flags)
{
	/*
	 * According to signal(7), calls to getrandom(2) are restartable.
	 */
	ttolxlwp(curthread)->br_syscall_restart = B_TRUE;

	return (getrandom(bufp, buflen, flags));
}
