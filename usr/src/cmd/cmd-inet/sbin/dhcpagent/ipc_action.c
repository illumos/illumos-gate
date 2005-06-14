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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/poll.h>
#include <dhcpmsg.h>

#include "interface.h"
#include "ipc_action.h"
#include "util.h"

static iu_tq_callback_t	ipc_action_timeout;

/*
 * ipc_action_init(): initializes the ipc_action structure
 *
 *   input: struct ifslist *: the interface to initialize it for
 *  output: void
 */

void
ipc_action_init(struct ifslist *ifsp)
{
	ifsp->if_ia.ia_tid = -1;
}

/*
 * ipc_action_start(): starts an ipc_action request on an interface
 *
 *   input: struct ifslist *: the interface to start the action on
 *	    dhcp_ipc_request_t *: the type of request
 *	    int: the descriptor to contact the action requestor
 *  output: int: 1 if the request is started successfully, 0 otherwise
 */

int
ipc_action_start(struct ifslist *ifsp, dhcp_ipc_request_t *request, int fd)
{
	if (request->timeout == DHCP_IPC_WAIT_DEFAULT)
		request->timeout = DHCP_IPC_DEFAULT_WAIT;

	ifsp->if_ia.ia_request	= request;
	ifsp->if_ia.ia_fd	= fd;
	ifsp->if_ia.ia_cmd	= DHCP_IPC_CMD(request->message_type);

	if (request->timeout == DHCP_IPC_WAIT_FOREVER)
		ifsp->if_ia.ia_tid = -1;
	else {
		ifsp->if_ia.ia_tid = iu_schedule_timer(tq, request->timeout,
		    ipc_action_timeout, ifsp);

		if (ifsp->if_ia.ia_tid == -1)
			return (0);

		hold_ifs(ifsp);
	}

	return (1);
}

/*
 * ipc_action_pending(): checks if there is a pending ipc_action request on
 *			 an interface
 *
 *   input: struct ifslist *: the interface to check for a pending ipc_action on
 *  output: boolean_t: B_TRUE if there is a pending ipc_action request
 */

boolean_t
ipc_action_pending(struct ifslist *ifsp)
{
	struct pollfd		pollfd;

	if (ifsp->if_ia.ia_fd > 0) {

		pollfd.events	= POLLIN;
		pollfd.fd	= ifsp->if_ia.ia_fd;

		if (poll(&pollfd, 1, 0) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * ipc_action_finish(): completes an ipc_action request on an interface
 *
 *   input: struct ifslist *: the interface to complete the action on
 *	    int: the reason why the action finished (nonzero on error)
 *  output: void
 */

void
ipc_action_finish(struct ifslist *ifsp, int reason)
{
	struct ipc_action *ia = &ifsp->if_ia;

	if (ipc_action_pending(ifsp) == B_FALSE)
		return;

	if (reason == 0)
		send_ok_reply(ia->ia_request, &ia->ia_fd);
	else
		send_error_reply(ia->ia_request, reason, &ia->ia_fd);

	ipc_action_cancel_timer(ifsp);
}

/*
 * ipc_action_timeout(): times out an ipc_action on an interface (the request
 *			 continues asynchronously, however)
 *
 *   input: iu_tq_t *: unused
 *	    void *: the struct ifslist * the ipc_action was pending on
 *  output: void
 */

/* ARGSUSED */
static void
ipc_action_timeout(iu_tq_t *tq, void *arg)
{
	struct ifslist		*ifsp = (struct ifslist *)arg;
	struct ipc_action	*ia = &ifsp->if_ia;

	if (check_ifs(ifsp) == 0) {
		(void) release_ifs(ifsp);
		return;
	}

	dhcpmsg(MSG_VERBOSE, "ipc timeout waiting for agent to complete "
	    "command %d for %s", ia->ia_cmd, ifsp->if_name);

	send_error_reply(ia->ia_request, DHCP_IPC_E_TIMEOUT, &ia->ia_fd);
	ia->ia_tid = -1;
}

/*
 * ipc_action_cancel_timer(): cancels the pending ipc_action timer for this
 *			      request
 *
 *   input: struct ifslist *: the interface with a pending request to cancel
 *  output: void
 */

void
ipc_action_cancel_timer(struct ifslist *ifsp)
{
	if (ifsp->if_ia.ia_tid == -1)
		return;

	/*
	 * if we can't cancel this timer, we're really in the
	 * twilight zone.  however, as long as we don't drop the
	 * reference to the ifsp, it shouldn't hurt us
	 */

	if (iu_cancel_timer(tq, ifsp->if_ia.ia_tid, NULL) == 1) {
		ifsp->if_ia.ia_tid = -1;
		(void) release_ifs(ifsp);
	}
}
