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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <dhcpmsg.h>
#include <libinetutil.h>
#include <dhcpagent_util.h>

#include "async.h"
#include "util.h"
#include "interface.h"
#include "script_handler.h"
#include "states.h"

/*
 * async_start(): starts an asynchronous command on a state machine
 *
 *   input: dhcp_smach_t *: the state machine to start the async command on
 *	    dhcp_ipc_type_t: the command to start
 *	    boolean_t: B_TRUE if the command was started by a user
 *  output: boolean: B_TRUE on success, B_FALSE on failure
 */

boolean_t
async_start(dhcp_smach_t *dsmp, dhcp_ipc_type_t cmd, boolean_t user)
{
	if (dsmp->dsm_async.as_present) {
		return (B_FALSE);
	} else {
		dsmp->dsm_async.as_cmd = cmd;
		dsmp->dsm_async.as_user = user;
		dsmp->dsm_async.as_present = B_TRUE;
		return (B_TRUE);
	}
}

/*
 * async_finish(): completes an asynchronous command
 *
 *   input: dhcp_smach_t *: the state machine with the pending async command
 *  output: void
 *    note: should only be used when the command has no residual state to
 *	    clean up
 */

void
async_finish(dhcp_smach_t *dsmp)
{
	/*
	 * be defensive here. the script may still be running if
	 * the asynchronous action times out before it is killed by the
	 * script helper process.
	 */

	if (dsmp->dsm_script_pid != -1)
		script_stop(dsmp);
	dsmp->dsm_async.as_present = B_FALSE;
}

/*
 * async_cancel(): cancels a pending asynchronous command
 *
 *   input: dhcp_smach_t *: the state machine with the pending async command
 *  output: boolean: B_TRUE if cancellation was successful, B_FALSE on failure
 */

boolean_t
async_cancel(dhcp_smach_t *dsmp)
{
	if (!dsmp->dsm_async.as_present)
		return (B_TRUE);
	if (dsmp->dsm_async.as_user) {
		dhcpmsg(MSG_DEBUG,
		    "async_cancel: cannot abort command %d from user",
		    (int)dsmp->dsm_async.as_cmd);
		return (B_FALSE);
	} else {
		async_finish(dsmp);
		dhcpmsg(MSG_DEBUG, "async_cancel: command %d aborted",
		    (int)dsmp->dsm_async.as_cmd);
		return (B_TRUE);
	}
}
