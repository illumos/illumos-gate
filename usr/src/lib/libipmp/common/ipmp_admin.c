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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * IPMP administrative interfaces (see PSARC/2007/272).
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include "ipmp_impl.h"
#include "ipmp_mpathd.h"
#include "ipmp_admin.h"

static int
ipmp_command(ipmp_handle_t handle, const void *req, uint_t reqsize)
{
	ipmp_state_t	*statep = (ipmp_state_t *)handle;
	mi_result_t	result;
	struct timeval	end;
	int		save_errno;
	int		retval;

	if (gettimeofday(&end, NULL) == -1)
		return (IPMP_FAILURE);
	end.tv_sec += IPMP_REQTIMEOUT;

	assert(statep->st_fd == -1);
	retval = ipmp_connect(&statep->st_fd);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_write(statep->st_fd, req, reqsize);
	if (retval != IPMP_SUCCESS)
		goto out;

	retval = ipmp_read(statep->st_fd, &result, sizeof (result), &end);
	if (retval != IPMP_SUCCESS)
		goto out;

	errno = result.me_sys_error;
	retval = result.me_mpathd_error;
out:
	save_errno = errno;
	(void) close(statep->st_fd);
	statep->st_fd = -1;
	errno = save_errno;
	return (retval);
}

int
ipmp_offline(ipmp_handle_t handle, const char *ifname, uint_t minred)
{
	mi_offline_t mio;

	mio.mio_command = MI_OFFLINE;
	mio.mio_min_redundancy = minred;
	(void) strlcpy(mio.mio_ifname, ifname, LIFNAMSIZ);
	return (ipmp_command(handle, &mio, sizeof (mio)));
}

int
ipmp_undo_offline(ipmp_handle_t handle, const char *ifname)
{
	mi_undo_offline_t miu;

	miu.miu_command = MI_UNDO_OFFLINE;
	(void) strlcpy(miu.miu_ifname, ifname, LIFNAMSIZ);
	return (ipmp_command(handle, &miu, sizeof (miu)));
}

int
ipmp_ping_daemon(ipmp_handle_t handle)
{
	mi_ping_t mip;

	mip.mip_command = MI_PING;
	return (ipmp_command(handle, &mip, sizeof (mip)));
}
