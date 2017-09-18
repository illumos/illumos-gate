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
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <dhcpmsg.h>
#include <dhcpagent_ipc.h>

#include "agent.h"
#include "states.h"
#include "interface.h"
#include "ipc_action.h"
#include "util.h"

static iu_tq_callback_t	ipc_action_timeout;

/*
 * ipc_action_init(): initializes the ipc_action structure
 *
 *   input: ipc_action_t *: the structure to initialize
 *  output: void
 */

void
ipc_action_init(ipc_action_t *ia)
{
	ia->ia_cmd = 0;
	ia->ia_fd = -1;
	ia->ia_tid = -1;
	ia->ia_eid = -1;
	ia->ia_request = NULL;
}

/*
 * ipc_action_start(): starts an ipc_action request on a DHCP state machine
 *
 *   input: dhcp_smach_t *: the state machine to start the action on
 *	    ipc_action_t *: request structure
 *  output: B_TRUE if the request is started successfully, B_FALSE otherwise
 *	    original request is still valid on failure, consumed otherwise.
 */

boolean_t
ipc_action_start(dhcp_smach_t *dsmp, ipc_action_t *iareq)
{
	struct ipc_action *ia = &dsmp->dsm_ia;

	if (ia->ia_fd != -1 || ia->ia_tid != -1 || iareq->ia_fd == -1) {
		dhcpmsg(MSG_CRIT, "ipc_action_start: attempted restart on %s",
		    dsmp->dsm_name);
		return (B_FALSE);
	}

	if (!async_cancel(dsmp)) {
		dhcpmsg(MSG_WARNING, "ipc_action_start: unable to cancel "
		    "action on %s", dsmp->dsm_name);
		return (B_FALSE);
	}

	if (iareq->ia_request->timeout == DHCP_IPC_WAIT_DEFAULT)
		iareq->ia_request->timeout = DHCP_IPC_DEFAULT_WAIT;

	if (iareq->ia_request->timeout == DHCP_IPC_WAIT_FOREVER) {
		iareq->ia_tid = -1;
	} else {
		iareq->ia_tid = iu_schedule_timer(tq,
		    iareq->ia_request->timeout, ipc_action_timeout, dsmp);

		if (iareq->ia_tid == -1) {
			dhcpmsg(MSG_ERROR, "ipc_action_start: failed to set "
			    "timer for %s on %s",
			    dhcp_ipc_type_to_string(iareq->ia_cmd),
			    dsmp->dsm_name);
			return (B_FALSE);
		}

		hold_smach(dsmp);
	}

	*ia = *iareq;

	/* We've taken ownership, so the input request is now invalid */
	ipc_action_init(iareq);

	dhcpmsg(MSG_DEBUG, "ipc_action_start: started %s (command %d) on %s,"
	    " buffer length %u",
	    dhcp_ipc_type_to_string(ia->ia_cmd), ia->ia_cmd, dsmp->dsm_name,
	    ia->ia_request == NULL ? 0 : ia->ia_request->data_length);

	dsmp->dsm_dflags |= DHCP_IF_BUSY;

	/* This cannot fail due to the async_cancel above */
	(void) async_start(dsmp, ia->ia_cmd, B_TRUE);

	return (B_TRUE);
}

/*
 * ipc_action_finish(): completes an ipc_action request on an interface
 *
 *   input: dhcp_smach_t *: the state machine to complete the action on
 *	    int: the reason why the action finished (nonzero on error)
 *  output: void
 */

void
ipc_action_finish(dhcp_smach_t *dsmp, int reason)
{
	struct ipc_action *ia = &dsmp->dsm_ia;

	dsmp->dsm_dflags &= ~DHCP_IF_BUSY;

	if (dsmp->dsm_ia.ia_fd == -1) {
		dhcpmsg(MSG_ERROR,
		    "ipc_action_finish: attempted to finish unknown action "
		    "on %s", dsmp->dsm_name);
		return;
	}

	dhcpmsg(MSG_DEBUG,
	    "ipc_action_finish: finished %s (command %d) on %s: %d",
	    dhcp_ipc_type_to_string(ia->ia_cmd), (int)ia->ia_cmd,
	    dsmp->dsm_name, reason);

	/*
	 * if we can't cancel this timer, we're really in the
	 * twilight zone.  however, as long as we don't drop the
	 * reference to the state machine, it shouldn't hurt us
	 */

	if (dsmp->dsm_ia.ia_tid != -1 &&
	    iu_cancel_timer(tq, dsmp->dsm_ia.ia_tid, NULL) == 1) {
		dsmp->dsm_ia.ia_tid = -1;
		release_smach(dsmp);
	}

	if (reason == 0)
		send_ok_reply(ia);
	else
		send_error_reply(ia, reason);

	async_finish(dsmp);
}

/*
 * ipc_action_timeout(): times out an ipc_action on a state machine (the
 *			 request continues asynchronously, however)
 *
 *   input: iu_tq_t *: unused
 *	    void *: the dhcp_smach_t * the ipc_action was pending on
 *  output: void
 */

/* ARGSUSED */
static void
ipc_action_timeout(iu_tq_t *tq, void *arg)
{
	dhcp_smach_t		*dsmp = arg;
	struct ipc_action	*ia = &dsmp->dsm_ia;

	dsmp->dsm_dflags &= ~DHCP_IF_BUSY;

	ia->ia_tid = -1;

	dhcpmsg(MSG_VERBOSE, "ipc timeout waiting for agent to complete "
	    "%s (command %d) for %s", dhcp_ipc_type_to_string(ia->ia_cmd),
	    ia->ia_cmd, dsmp->dsm_name);

	send_error_reply(ia, DHCP_IPC_E_TIMEOUT);

	async_finish(dsmp);
	release_smach(dsmp);
}

/*
 * send_ok_reply(): sends an "ok" reply to a request and closes the ipc
 *		    connection
 *
 *   input: ipc_action_t *: the request to reply to
 *  output: void
 *    note: the request is freed (thus the request must be on the heap).
 */

void
send_ok_reply(ipc_action_t *ia)
{
	send_error_reply(ia, 0);
}

/*
 * send_error_reply(): sends an "error" reply to a request and closes the ipc
 *		       connection
 *
 *   input: ipc_action_t *: the request to reply to
 *	    int: the error to send back on the ipc connection
 *  output: void
 *    note: the request is freed (thus the request must be on the heap).
 */

void
send_error_reply(ipc_action_t *ia, int error)
{
	send_data_reply(ia, error, DHCP_TYPE_NONE, NULL, 0);
}

/*
 * send_data_reply(): sends a reply to a request and closes the ipc connection
 *
 *   input: ipc_action_t *: the request to reply to
 *	    int: the status to send back on the ipc connection (zero for
 *		 success, DHCP_IPC_E_* otherwise).
 *	    dhcp_data_type_t: the type of the payload in the reply
 *	    const void *: the payload for the reply, or NULL if there is no
 *			  payload
 *	    size_t: the size of the payload
 *  output: void
 *    note: the request is freed (thus the request must be on the heap).
 */

void
send_data_reply(ipc_action_t *ia, int error, dhcp_data_type_t type,
    const void *buffer, size_t size)
{
	dhcp_ipc_reply_t	*reply;
	int retval;

	if (ia->ia_fd == -1 || ia->ia_request == NULL)
		return;

	reply = dhcp_ipc_alloc_reply(ia->ia_request, error, buffer, size,
	    type);
	if (reply == NULL) {
		dhcpmsg(MSG_ERR, "send_data_reply: cannot allocate reply");

	} else if ((retval = dhcp_ipc_send_reply(ia->ia_fd, reply)) != 0) {
		dhcpmsg(MSG_ERROR, "send_data_reply: dhcp_ipc_send_reply: %s",
		    dhcp_ipc_strerror(retval));
	}

	/*
	 * free the request since we've now used it to send our reply.
	 * we can also close the socket since the reply has been sent.
	 */

	free(reply);
	free(ia->ia_request);
	if (ia->ia_eid != -1)
		(void) iu_unregister_event(eh, ia->ia_eid, NULL);
	(void) dhcp_ipc_close(ia->ia_fd);
	ia->ia_request = NULL;
	ia->ia_fd = -1;
	ia->ia_eid = -1;
}
