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
 * Verify that we can't allocate a handle when in an ENOMEM situation.
 */

#include <procfs.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <assert.h>
#include <strings.h>

#include <libvnd.h>

int
main(int argc, const char *argv[])
{
	int fd;
	int syserr;
	vnd_errno_t vnderr;
	vnd_handle_t *vhp;
	pstatus_t status;
	void *addr;

	if (argc < 2) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= LIBVND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		exit(1);
	if (read(fd, &status, sizeof (status)) != sizeof (status))
		exit(1);

	addr = mmap((caddr_t)P2ROUNDUP(status.pr_brkbase +
	    status.pr_brksize, 0x1000), 0x1000,
	    PROT_READ, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0);
	if (addr == (void *)-1) {
		perror("mmap");
		exit(1);
	}

	/* malloc an approximate size of the vnd_handle_t */
	for (;;) {
		void *buf;

		buf = malloc(8);
		if (buf == NULL)
			break;
	}

	for (;;) {
		void *buf;

		buf = malloc(4);
		if (buf == NULL)
			break;
	}

	vhp = vnd_create(NULL, argv[1], argv[1], &vnderr, &syserr);
	assert(vhp == NULL);
	assert(vnderr == VND_E_NOMEM);
	assert(syserr == 0);

	return (0);
}
