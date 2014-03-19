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
 * Here we test that all the ioctls which require us to be on a local device
 * fail to work. Specifically, the errno should be VND_E_NOTATTACHED
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/vnd.h>

#define	VND_PATH	"/dev/vnd/ctl"

static int vib_ioc[] = {
	VND_IOC_GETRXBUF,
	VND_IOC_SETRXBUF,
	VND_IOC_GETTXBUF,
	VND_IOC_SETTXBUF,
	VND_IOC_GETMINTU,
	VND_IOC_GETMAXTU,
	-1
};

int
main(void)
{
	int fd, ret, i;
	vnd_ioc_link_t vil;
	vnd_ioc_unlink_t viu;
	vnd_ioc_buf_t vib;
	frameio_t *fio;
	char buf[1];

	fd = open(VND_PATH, O_RDWR);
	if (fd < 0) {
		(void) fprintf(stderr, "failed to open %s r/w: %s\n", VND_PATH,
		    strerror(errno));
		return (1);
	}

	bzero(&vil, sizeof (vnd_ioc_link_t));
	vil.vil_name[0] = 'a';
	bzero(&viu, sizeof (vnd_ioc_unlink_t));
	bzero(&vib, sizeof (vnd_ioc_buf_t));
	fio = malloc(sizeof (frameio_t) + sizeof (framevec_t));
	assert(fio != NULL);
	fio->fio_version = FRAMEIO_CURRENT_VERSION;
	fio->fio_nvpf = 1;
	fio->fio_nvecs = 1;
	fio->fio_vecs[0].fv_buf = buf;
	fio->fio_vecs[0].fv_buflen = 1;

	ret = ioctl(fd, VND_IOC_LINK, &vil);
	assert(vil.vil_errno == VND_E_NOTATTACHED);
	ret = ioctl(fd, VND_IOC_UNLINK, &viu);
	assert(viu.viu_errno == VND_E_NOTLINKED);

	for (i = 0; vib_ioc[i] != -1; i++) {
		bzero(&vib, sizeof (vib));
		ret = ioctl(fd, vib_ioc[i], &vib);
		assert(vib.vib_errno == VND_E_NOTATTACHED);
	}

	/* The frameio ioctls only use standard errnos */
	ret = ioctl(fd, VND_IOC_FRAMEIO_READ, fio);
	assert(ret == -1);
	assert(errno == ENXIO);
	ret = ioctl(fd, VND_IOC_FRAMEIO_WRITE, fio);
	assert(ret == -1);
	assert(errno == ENXIO);

	free(fio);
	assert(close(fd) == 0);


	return (0);
}
