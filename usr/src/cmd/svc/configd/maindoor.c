/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ucred.h>

#include "repcache_protocol.h"
#include "configd.h"

#define	INVALID_RESULT		((uint32_t)-1U)

static int		main_door_fd = -1;

/*ARGSUSED*/
static void
main_switcher(void *cookie, char *argp, size_t arg_size, door_desc_t *desc,
    uint_t n_desc)
{
	repository_door_request_t *request;
	repository_door_response_t reply;
	door_desc_t reply_desc;

	thread_info_t *ti = thread_self();

	int send_desc = 0;
	int fd;

	thread_newstate(ti, TI_MAIN_DOOR_CALL);
	ti->ti_main_door_request = (void *)argp;

	assert(cookie == REPOSITORY_DOOR_COOKIE);

	reply.rdr_status = INVALID_RESULT;

	if (argp == DOOR_UNREF_DATA) {
		backend_fini();

		exit(CONFIGD_EXIT_LOST_MAIN_DOOR);
	}

	/*
	 * No file descriptors allowed
	 */
	assert(n_desc == 0);

	/*
	 * first, we just check the version
	 */
	if (arg_size < offsetofend(repository_door_request_t, rdr_version)) {
		reply.rdr_status = REPOSITORY_DOOR_FAIL_BAD_REQUEST;
		goto fail;
	}

	/* LINTED alignment */
	request = (repository_door_request_t *)argp;
	ti->ti_main_door_request = request;

	if (request->rdr_version != REPOSITORY_DOOR_VERSION) {
		reply.rdr_status = REPOSITORY_DOOR_FAIL_VERSION_MISMATCH;
		goto fail;
	}

	/*
	 * Now, check that the argument is of the minimum required size
	 */
	if (arg_size < offsetofend(repository_door_request_t, rdr_request)) {
		reply.rdr_status = REPOSITORY_DOOR_FAIL_BAD_REQUEST;
		goto fail;
	}

	if (door_ucred(&ti->ti_ucred) != 0) {
		reply.rdr_status = REPOSITORY_DOOR_FAIL_PERMISSION_DENIED;
		goto fail;
	}

	switch (request->rdr_request) {
	case REPOSITORY_DOOR_REQUEST_CONNECT:
		fd = -1;
		reply.rdr_status = create_connection(ti->ti_ucred, request,
		    arg_size, &fd);
		if (reply.rdr_status != REPOSITORY_DOOR_SUCCESS) {
			assert(fd == -1);
			goto fail;
		}
		assert(fd != -1);
		reply_desc.d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
		reply_desc.d_data.d_desc.d_descriptor = fd;
		send_desc = 1;
		break;

	default:
		reply.rdr_status = REPOSITORY_DOOR_FAIL_BAD_REQUEST;
		goto fail;
	}

fail:
	assert(reply.rdr_status != INVALID_RESULT);

	thread_newstate(ti, TI_DOOR_RETURN);
	ti->ti_main_door_request = NULL;

	(void) door_return((char *)&reply, sizeof (reply),
	    &reply_desc, (send_desc)? 1:0);
	(void) door_return(NULL, 0, NULL, 0);
}

int
setup_main_door(const char *doorpath)
{
	mode_t oldmask;
	int fd;

	int door_flags = DOOR_UNREF | DOOR_REFUSE_DESC;
#ifdef DOOR_NO_CANCEL
	door_flags |= DOOR_NO_CANCEL;
#endif
	if ((main_door_fd = door_create(main_switcher, REPOSITORY_DOOR_COOKIE,
	    door_flags)) < 0) {
		perror("door_create");
		return (0);
	}

#ifdef DOOR_PARAM_DATA_MIN
	if (door_setparam(main_door_fd, DOOR_PARAM_DATA_MIN,
	    offsetofend(repository_door_request_t, rdr_request)) == -1 ||
	    door_setparam(main_door_fd, DOOR_PARAM_DATA_MAX,
	    sizeof (repository_door_request_t)) == -1) {
		perror("door_setparam");
		return (0);
	}
#endif /* DOOR_PARAM_DATA_MIN */

	/*
	 * Create the file if it doesn't exist.  Ignore errors, since
	 * fattach(3C) will catch any real problems.
	 */
	oldmask = umask(000);		/* disable umask temporarily */
	fd = open(doorpath, O_RDWR | O_CREAT | O_EXCL, 0644);
	(void) umask(oldmask);

	if (fd >= 0)
		(void) close(fd);

	if (fattach(main_door_fd, doorpath) < 0) {
		if ((errno != EBUSY) ||
		    (fdetach(doorpath) < 0) ||
		    (fattach(main_door_fd, doorpath) < 0)) {
			perror("fattach");
			(void) door_revoke(main_door_fd);
			main_door_fd = -1;
			return (0);
		}
	}

	return (1);
}
