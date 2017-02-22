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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/brand.h>

#include <sys/lx_brand.h>
#include <sys/lx_syscalls.h>


extern int close(int);

long
lx_close(int fdes)
{
	return (close(fdes));
}
