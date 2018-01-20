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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Functions called by the IO deamon (IOD).
 * Here in the library to simplify testing.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>

#include <sys/byteorder.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include "charsets.h"
#include "private.h"

/*
 * The user agent (smbiod) calls smb_iod_connect for the first
 * connection to some server, and if that succeeds, will start a
 * thread running this function, passing the smb_ctx_t
 *
 * This thread now enters the driver and stays there, reading
 * network responses as long as the connection is alive.
 */
int
smb_iod_work(smb_ctx_t *ctx)
{
	smbioc_ssn_work_t *work = &ctx->ct_work;
	int	err = 0;

	DPRINT("server: %s", ctx->ct_srvname);

	/*
	 * This is the reader / reconnect loop.
	 *
	 * We could start with state "idle", but
	 * we know someone wants a connection to
	 * this server, so start in "vcactive".
	 *
	 * XXX: Add some syslog calls in here?
	 */

	for (;;) {

		DPRINT("state: %s",
		    smb_iod_state_name(work->wk_out_state));

		switch (work->wk_out_state) {
		case SMBIOD_ST_IDLE:
			/*
			 * Wait for driver requests to arrive
			 * for this VC, then return here.
			 * Next state is normally RECONNECT.
			 */
			DPRINT("Call _ioc_idle...");
			if (nsmb_ioctl(ctx->ct_dev_fd,
			    SMBIOC_IOD_IDLE, work) == -1) {
				err = errno;
				DPRINT("ioc_idle: err %d", err);
				goto out;
			}
			continue;

		case SMBIOD_ST_RECONNECT:
			DPRINT("Call _iod_connect...");
			err = smb_iod_connect(ctx);
			if (err == 0)
				continue;
			DPRINT("iod_connect: err %d", err);
			/*
			 * If the error was EAUTH, retry is
			 * not likely to succeed either, so
			 * just exit this thread.  The user
			 * will need to run smbutil to get
			 * a new thread with new auth info.
			 */
			if (err == EAUTH)
				goto out;
			continue;

		case SMBIOD_ST_RCFAILED:
			/*
			 * Reconnect failed.  Kill off any
			 * requests waiting in the driver,
			 * then get ready to try again.
			 * Next state is normally IDLE.
			 */
			DPRINT("Call _iod_rcfail...");
			if (nsmb_ioctl(ctx->ct_dev_fd,
			    SMBIOC_IOD_RCFAIL, work) == -1) {
				err = errno;
				DPRINT("iod_rcfail: err %d", err);
				goto out;
			}
			continue;

		case SMBIOD_ST_AUTHOK:
			/*
			 * This is where we enter the driver and
			 * stay there.  While the connection is up
			 * the VC will have SMBIOD_ST_VCACTIVE
			 */
			DPRINT("Call _iod_work...");
			if (nsmb_ioctl(ctx->ct_dev_fd,
			    SMBIOC_IOD_WORK, work) == -1) {
				err = errno;
				DPRINT("iod_work: err %d", err);
				goto out;
			}
			continue;

		case SMBIOD_ST_DEAD:
			err = 0;
			goto out;

		default:
			DPRINT("Unexpected state: %d (%s)",
			    work->wk_out_state,
			    smb_iod_state_name(work->wk_out_state));
			err = EFAULT;
			goto out;
		}
	}

out:
	if (ctx->ct_dev_fd != -1) {
		nsmb_close(ctx->ct_dev_fd);
		ctx->ct_dev_fd = -1;
	}

	return (err);
}
