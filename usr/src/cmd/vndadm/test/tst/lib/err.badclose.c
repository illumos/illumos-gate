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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * This program should segfault.
 */

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include <libvnd.h>

int
main(void)
{
	vnd_handle_t *vhp = (void *)0x42;
	vnd_close(vhp);
	/* This should not be reached */
	return (0);
}
