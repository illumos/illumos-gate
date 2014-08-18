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
 * Fail to open a /dev/vnd/%s without PRIV_NET_RAWACCESS
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <priv.h>

#include <sys/vnd.h>

#define	VND_PATH	"/dev/vnd/ctl"

int
main(int argc, const char *argv[])
{
	int fd, ret;
	char *path;
	priv_set_t *ps;
	vnd_ioc_attach_t via;
	vnd_ioc_link_t vil;

	if (argc < 2) {
		(void) fprintf(stderr, "missing arguments...\n");
		return (1);
	}

	if (strlen(argv[1]) >= VND_NAMELEN) {
		(void) fprintf(stderr, "vnic name too long...\n");
		return (1);
	}

	fd = open(VND_PATH, O_RDWR);
	assert(fd > 0);

	(void) strlcpy(via.via_name, argv[1], VND_NAMELEN);
	via.via_zoneid = 0;
	via.via_errno = 0;

	ret = ioctl(fd, VND_IOC_ATTACH, &via);
	assert(ret == 0);
	assert(via.via_errno == 0);

	(void) strlcpy(vil.vil_name, argv[1], VND_NAMELEN);
	vil.vil_errno = 0;
	ret = ioctl(fd, VND_IOC_LINK, &vil);
	assert(ret == 0);
	assert(vil.vil_errno == 0);

	ret = asprintf(&path, "/dev/vnd/%s", argv[1]);
	assert(ret != -1);

	ps = priv_allocset();
	assert(ps != NULL);
	assert(priv_addset(ps, PRIV_NET_RAWACCESS) == 0);
	assert(setppriv(PRIV_OFF, PRIV_PERMITTED, ps) == 0);

	ret = open(path, O_RDWR);
	assert(ret == -1);
	assert(errno == EPERM);

	return (0);
}
