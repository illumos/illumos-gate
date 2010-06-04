/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Client-side interface to the IO Daemon (IOD)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <door.h>

#include <sys/byteorder.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include <assert.h>

#include "charsets.h"
#include "private.h"

/*
 * This is constant for the life of a process,
 * and initialized at startup, so no locks.
 */
static char door_path[64];
static int iod_start_timeout = 10;	/* seconds */

char *
smb_iod_door_path(void)
{
	uid_t uid;
	int x;

	if (door_path[0] == '\0') {
		uid = getuid();
		x = snprintf(door_path, sizeof (door_path),
		    SMBIOD_USR_DOOR, uid);
		assert(x <= sizeof (door_path));
	}

	return (door_path);
}

/*
 * Open the door (client side) and
 * find out if the service is there.
 */
int
smb_iod_open_door(int *fdp)
{
	door_arg_t da;
	char *path;
	int fd, rc;
	int err = 0;

	path = smb_iod_door_path();
	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return (errno);

	/*
	 * Make sure the IOD is running.
	 * Pass NULL args.
	 */
	memset(&da, 0, sizeof (da));
	da.rbuf = (void *) &err;
	da.rsize = sizeof (err);
	rc = door_call(fd, &da);
	if (rc < 0) {
		err = errno;
		close(fd);
		return (err);
	}
	if (err != 0) {
		close(fd);
		return (err);
	}

	/* This handle controls per-process resources. */
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	*fdp = fd;
	return (0);
}

/*
 * Request the creation of our per-user smbiod
 * via door call to the "main" IOD service.
 */
static int
start_iod(void)
{
	const char *svc_door = SMBIOD_SVC_DOOR;
	door_arg_t da;
	int32_t cmd, err;
	int fd, rc;

	fd = open(svc_door, O_RDONLY, 0);
	if (fd < 0) {
		err = errno;
		DPRINT("%s: open failed, err %d", svc_door, err);
		return (err);
	}
	cmd = SMBIOD_START;
	memset(&da, 0, sizeof (da));
	da.data_ptr = (void *) &cmd;
	da.data_size = sizeof (cmd);
	da.rbuf = (void *) &err;
	da.rsize = sizeof (err);
	rc = door_call(fd, &da);
	close(fd);
	if (rc < 0) {
		err = errno;
		DPRINT("door_call, err %d", err);
		return (err);
	}

	return (err);
}

/*
 * Get a door handle to the IOD, starting it if necessary.
 * On success, sets ctx->ct_door_fd
 */
int
smb_iod_start(smb_ctx_t *ctx)
{
	int err, tmo;
	int fd = -1;

	tmo = iod_start_timeout;
	while ((err = smb_iod_open_door(&fd)) != 0) {
		if (--tmo <= 0)
			goto errout;

		/*
		 * We have no per-user IOD yet.  Request one.
		 * Do this request every time through the loop
		 * because the master IOD will only start our
		 * per-user IOD if we don't have one, and our
		 * first requst could have happened while we
		 * had an IOD that was doing shutdown.
		 * (Prevents a shutdown/startup race).
		 */
		err = start_iod();
		if (err != 0)
			goto errout;
		/*
		 * Wait for it to get ready.
		 */
		(void) sleep(1);
	}

	/* Save the door fd. */
	if (ctx->ct_door_fd != -1)
		close(ctx->ct_door_fd);
	ctx->ct_door_fd = fd;

	return (0);

errout:
	smb_error(dgettext(TEXT_DOMAIN,
	    "Could not contact service: %s"),
	    0, "svc:/network/smb/client");
	return (ENOTACTIVE);
}

/*
 * Ask the IOD to connect using the info in ctx.
 * Called by newvc.
 */
int
smb_iod_cl_newvc(smb_ctx_t *ctx)
{
	door_arg_t da;
	int err = 0;

	/* Should already have the IOD door. */
	if (ctx->ct_door_fd < 0)
		return (EINVAL);

	da.data_ptr = (void *) &ctx->ct_iod_ssn;
	da.data_size = sizeof (ctx->ct_iod_ssn);
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (void *) &err;
	da.rsize = sizeof (err);
	if (door_call(ctx->ct_door_fd, &da) < 0) {
		err = errno;
		DPRINT("door_call, err=%d", err);
	}

	return (err);
}
