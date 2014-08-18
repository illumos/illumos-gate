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
 * Make sure we can't open a vnd device that doesn't exist
 */

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include <libvnd.h>

int
main(int argc, const char *argv[])
{
	int syserr;
	vnd_errno_t vnderr;
	vnd_handle_t *vhp;

	if (argc < 2) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= LIBVND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	vhp = vnd_open(NULL, argv[1], &vnderr, &syserr);
	assert(vhp == NULL);
	assert(vnderr == VND_E_SYS);
	assert(syserr == ENOENT);

	return (0);
}
