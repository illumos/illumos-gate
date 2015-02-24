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

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>

/*
 * *xattr() family of functions.
 *
 * These are currently unimplemented.  We return EOPNOTSUPP for now, rather
 * than using NOSYS_NO_EQUIV to avoid unwanted stderr output from ls(1).
 */

long
lx_xattr(void)
{
	return (set_errno(EOPNOTSUPP));
}
