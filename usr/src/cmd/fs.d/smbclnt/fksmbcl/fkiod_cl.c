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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Client-side interface to the IO Daemon (IOD)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <thread.h>

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

#include "smb/charsets.h"
#include "smb/private.h"

/*
 * Make sure we don't call the real IOD here.
 */
int
smb_iod_open_door(int *fdp)
{
	*fdp = -1;
	return (ENOTSUP);
}

/*
 * Get a door handle to the IOD...
 */
int
smb_iod_start(smb_ctx_t *ctx)
{
	return (0);
}

void *
iod_work(void *arg)
{
	smb_ctx_t *ctx = arg;
	(void) smb_iod_work(ctx);
	smb_ctx_free(ctx);
	return (NULL);
}

/*
 * Ask the IOD to connect using the info in ctx.
 * Called by newvc.
 *
 * This function largely follows smbiod.c : iod_newvc()
 */
int
smb_iod_cl_newvc(smb_ctx_t *cl_ctx)
{
	smb_ctx_t *ctx;
	thread_t tid;
	int err = 0;

	/*
	 * Clone the context, like in smbiod.c
	 */
	err = smb_ctx_alloc(&ctx);
	if (err)
		return (err);
	bcopy(&cl_ctx->ct_iod_ssn, &ctx->ct_iod_ssn,
	    sizeof (ctx->ct_iod_ssn));

	/*
	 * Create the driver session first...
	 */
	if ((err = smb_ctx_gethandle(ctx)) != 0)
		goto out;
	if (nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_SSN_CREATE, &ctx->ct_ssn) < 0) {
		err = errno;
		if (err == EEXIST)
			err = 0; /* see above */
		goto out;
	}

	/*
	 * Do the initial connection setup here, so we can
	 * report the outcome to the door client.
	 */
	err = smb_iod_connect(ctx);
	if (err != 0) {
		fprintf(stderr, "smb_iod_connect, err=%d\n", err);
		goto out;
	}

	/* The rest happens in the iod_work thread. */
	err = thr_create(NULL, 0, iod_work, ctx, THR_DETACHED, &tid);
	if (err == 0) {
		/*
		 * Given to the new thread.
		 * free at end of iod_work
		 */
		ctx = NULL;
	}

out:
	if (ctx != NULL)
		smb_ctx_free(ctx);

	return (err);
}
