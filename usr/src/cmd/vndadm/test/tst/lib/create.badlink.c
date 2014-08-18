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
 * Make sure that we can't create something in the context of a datalink that
 * doesn't exist.
 */

#include <assert.h>
#include <stdio.h>
#include <libvnd.h>

int
main(void)
{
	int syserr;
	vnd_errno_t vnderr;
	vnd_handle_t *vhp;

	vhp = vnd_create(NULL, "foobar", "foobar", &vnderr, &syserr);
	(void) printf("%d, %d\n", vnderr, syserr);
	assert(vhp == NULL);
	assert(vnderr == VND_E_NODATALINK);
	assert(syserr == 0);

	return (0);
}
