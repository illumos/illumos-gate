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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This file implements device open/close/ioctl wrappers that
 * redirect access from the real "nsmb" device to the in-process
 * device simulation in libfknsmb.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/byteorder.h>

#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <libintl.h>
#include <assert.h>
#include <nss_dbdefs.h>

#include <cflib.h>
#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include <libfknsmb/common/libfknsmb.h>

#include "smb/charsets.h"
#include "smb/private.h"

int
smb_open_driver(void)
{
	dev32_t dev;
	int fd;
	int rc;

	rc = nsmb_drv_open(&dev, 0, 0);
	if (rc != 0) {
		errno = rc;
		return (-1);
	}

	assert((dev & 0xFFFF0000) != 0);
	fd = (int)dev;

	return (fd);
}

int
nsmb_ioctl(int fd, int cmd, void *arg)
{
	dev32_t dev;
	int err;

	dev = (dev32_t)fd;
	assert((dev & 0xFFFF0000) != 0);
	err = nsmb_drv_ioctl(dev, cmd, (intptr_t)arg, 0);
	if (err != 0) {
		errno = err;
		return (-1);
	}
	return (0);
}

int
nsmb_close(int fd)
{
	dev32_t dev;

	dev = (dev32_t)fd;
	assert((dev & 0xFFFF0000) != 0);
	(void) nsmb_drv_close(dev, 0, 0);
	return (0);
}
