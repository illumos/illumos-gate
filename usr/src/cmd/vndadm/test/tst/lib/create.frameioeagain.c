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
 * Create a datalink, set it to non-blocking mode and ensure that we get EAGAIN
 * from frame I/O calls. Note that if this test is not plumbed up over an
 * etherstub, then it is likely that other traffic will appear on the device and
 * this will fail. Note that the test suite always creates these devices over an
 * etherstub.
 */

#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libvnd.h>

int
main(int argc, const char *argv[])
{
	int syserr, ret, fd;
	vnd_errno_t vnderr;
	vnd_handle_t *vhp;
	frameio_t *fio;
	char buf[1520];

	if (argc < 2) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= LIBVND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	vhp = vnd_create(NULL, argv[1], argv[1], &vnderr, &syserr);
	assert(vhp != NULL);
	assert(vnderr == 0);
	assert(syserr == 0);

	fd = vnd_pollfd(vhp);
	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	assert(ret == 0);

	fio = malloc(sizeof (frameio_t) +
	    sizeof (framevec_t));
	assert(fio != NULL);
	fio->fio_version = FRAMEIO_CURRENT_VERSION;
	fio->fio_nvpf = 1;
	fio->fio_nvecs = 1;

	fio->fio_vecs[0].fv_buf = buf;
	fio->fio_vecs[0].fv_buflen = sizeof (buf);

	ret = vnd_frameio_read(vhp, fio);
	(void) printf("%d, %d\n", ret, errno);
	assert(ret == -1);
	assert(errno == EAGAIN);

	vnd_close(vhp);
	free(fio);
	return (0);
}
