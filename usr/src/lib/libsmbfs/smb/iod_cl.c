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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#include "charsets.h"
#include "private.h"

static const char smbiod_path[] = "/usr/lib/smbfs/smbiod";

/*
 * This is constant for the life of a process,
 * and initialized at startup, so no locks.
 */
static char door_path[40];

char *
smb_iod_door_path(void)
{
	static const char fmtR[] = "/var/run/smbiod-%d";
	static const char fmtU[] = "/tmp/.smbiod-%d";
	const char *fmt;
	uid_t uid;

	if (door_path[0] == '\0') {
		uid = getuid();
		fmt = (uid == 0) ? fmtR : fmtU;
		snprintf(door_path, sizeof (door_path), fmt, uid);
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
 * Start the IOD and wait until we can
 * open its client-side door.
 */
static int
start_iod(int *fdp)
{
	int err, pid, t;

	pid = vfork();
	if (pid < 0)
		return (errno);

	/*
	 * child: start smbiod
	 */
	if (pid == 0) {
		char *argv[2];
		argv[0] = "smbiod";
		argv[1] = NULL;
		execv(smbiod_path, argv);
		return (errno);
	}

	/*
	 * parent: wait for smbiod to start
	 */
	for (t = 0; t < 10; t++) {
		sleep(1);
		err = smb_iod_open_door(fdp);
		if (err == 0)
			break;
	}

	return (err);
}


/*
 * Start smbiod if necessary, and then
 * ask it to connect using the info in ctx.
 */
int
smb_iod_cl_newvc(smb_ctx_t *ctx)
{
	door_arg_t da;
	int fd, err = 0;

	err = smb_iod_open_door(&fd);
	if (err != 0) {
		err = start_iod(&fd);
		if (err)
			return (err);
	}

	da.data_ptr = (void *) &ctx->ct_iod_ssn;
	da.data_size = sizeof (ctx->ct_iod_ssn);
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (void *) &err;
	da.rsize = sizeof (err);
	if (door_call(fd, &da) < 0) {
		err = errno;
		DPRINT("door_call, err=%d", err);
	}
	close(fd);

	return (err);
}
