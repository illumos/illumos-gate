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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <dhcpmsg.h>
#include <libinetutil.h>

#include "async.h"
#include "util.h"
#include "agent.h"
#include "interface.h"
#include "script_handler.h"
#include "states.h"

static void	async_timeout(iu_tq_t *, void *);

/*
 * async_pending(): checks to see if an async command is pending.  if a stale
 *		    async command is found, cancellation is attempted.
 *
 *   input: struct ifslist *: the interface to check for an async command on
 *  output: boolean_t: B_TRUE if async command is pending, B_FALSE if not
 */

boolean_t
async_pending(struct ifslist *ifsp)
{
	if (!(ifsp->if_dflags & DHCP_IF_BUSY))
		return (B_FALSE);

	/*
	 * if the command was not started by the user (i.e., was
	 * started internal to the agent), then it will timeout in
	 * async_timeout() -- don't shoot it here.
	 */

	if (!ifsp->if_async.as_user)
		return (B_TRUE);

	if (ifsp->if_script_pid != -1)
		return (B_TRUE);

	/*
	 * user command -- see if they went away.  if they went away,
	 * either a timeout was already sent to them or they
	 * control-c'd out.
	 */

	if (ipc_action_pending(ifsp))
		return (B_TRUE);

	/*
	 * it appears they went away.  try to cancel their pending
	 * command.  if we can't cancel it, we leave their command
	 * pending and it's just gonna have to complete its business
	 * in any case, cancel the ipc_action timer, since we know
	 * they've gone away.
	 */

	dhcpmsg(MSG_DEBUG, "async_pending: async command left, attempting "
	    "cancellation");

	ipc_action_cancel_timer(ifsp);
	return (async_cancel(ifsp) ? B_FALSE : B_TRUE);
}

/*
 * async_start(): starts an asynchronous command on an interface
 *
 *   input: struct ifslist *: the interface to start the async command on
 *	    dhcp_ipc_type_t: the command to start
 *	    boolean_t: B_TRUE if the command was started by a user
 *  output: int: 1 on success, 0 on failure
 */

int
async_start(struct ifslist *ifsp, dhcp_ipc_type_t cmd, boolean_t user)
{
	iu_timer_id_t tid;

	if (async_pending(ifsp))
		return (0);

	tid = iu_schedule_timer(tq, DHCP_ASYNC_WAIT, async_timeout, ifsp);
	if (tid == -1)
		return (0);

	hold_ifs(ifsp);

	ifsp->if_async.as_tid	 = tid;
	ifsp->if_async.as_cmd	 = cmd;
	ifsp->if_async.as_user	 = user;
	ifsp->if_dflags		|= DHCP_IF_BUSY;

	return (1);
}


/*
 * async_finish(): completes an asynchronous command
 *
 *   input: struct ifslist *: the interface with the pending async command
 *  output: void
 *    note: should only be used when the command has no residual state to
 *	    clean up
 */

void
async_finish(struct ifslist *ifsp)
{
	/*
	 * be defensive here. the script may still be running if
	 * the asynchronous action times out before it is killed by the
	 * script helper process.
	 */

	if (ifsp->if_script_pid != -1)
		script_stop(ifsp);

	/*
	 * in case async_timeout() has already called async_cancel(),
	 * and to be idempotent, check the DHCP_IF_BUSY flag
	 */

	if (!(ifsp->if_dflags & DHCP_IF_BUSY))
		return;

	if (ifsp->if_async.as_tid == -1) {
		ifsp->if_dflags &= ~DHCP_IF_BUSY;
		return;
	}

	if (iu_cancel_timer(tq, ifsp->if_async.as_tid, NULL) == 1) {
		ifsp->if_dflags &= ~DHCP_IF_BUSY;
		ifsp->if_async.as_tid = -1;
		(void) release_ifs(ifsp);
		return;
	}

	/*
	 * if we can't cancel this timer, we'll just leave the
	 * interface busy and when the timeout finally fires, we'll
	 * mark it free, which will just cause a minor nuisance.
	 */

	dhcpmsg(MSG_WARNING, "async_finish: cannot cancel async timer");
}

/*
 * async_cancel(): cancels a pending asynchronous command
 *
 *   input: struct ifslist *: the interface with the pending async command
 *  output: int: 1 if cancellation was successful, 0 on failure
 */

int
async_cancel(struct ifslist *ifsp)
{
	boolean_t do_restart = B_FALSE;

	/*
	 * we decide how to cancel the command depending on our
	 * current state, since commands such as EXTEND may in fact
	 * cause us to enter back into SELECTING (if a NAK results
	 * from the EXTEND).
	 */

	switch (ifsp->if_state) {

	case BOUND:
	case INFORMATION:
		break;

	case RENEWING:					/* FALLTHRU */
	case REBINDING:					/* FALLTHRU */
	case INFORM_SENT:

		/*
		 * these states imply that we've sent a packet and we're
		 * awaiting an ACK or NAK.  just cancel the wait.
		 */

		if (unregister_acknak(ifsp) == 0)
			return (0);

		break;

	case INIT:					/* FALLTHRU */
	case SELECTING:					/* FALLTHRU */
	case REQUESTING:				/* FALLTHRU */
	case INIT_REBOOT:

		/*
		 * these states imply we're still trying to get a lease.
		 * jump to SELECTING and start from there -- but not until
		 * after we've finished the asynchronous command!
		 */

		do_restart = B_TRUE;
		break;

	default:
		dhcpmsg(MSG_WARNING, "async_cancel: cancellation in unexpected "
		    "state %d", ifsp->if_state);
		return (0);
	}

	async_finish(ifsp);
	dhcpmsg(MSG_DEBUG, "async_cancel: asynchronous command (%d) aborted",
	    ifsp->if_async.as_cmd);
	if (do_restart)
		dhcp_selecting(ifsp);

	return (1);
}

/*
 * async_timeout(): expires stale asynchronous commands
 *
 *   input: iu_tq_t *: the timer queue on which the timeout went off
 *	    void *: the interface with the pending async command
 *  output: void
 */

static void
async_timeout(iu_tq_t *tq, void *arg)
{
	struct ifslist		*ifsp = (struct ifslist *)arg;

	if (check_ifs(ifsp) == 0) {
		(void) release_ifs(ifsp);
		return;
	}

	/* we've expired now */
	ifsp->if_async.as_tid = -1;

	/*
	 * if the command was generated internally to the agent, try
	 * to cancel it immediately.  otherwise, if the user has gone
	 * away, we cancel it in async_pending().  otherwise, we let
	 * it live.
	 */

	if (!ifsp->if_async.as_user) {
		(void) async_cancel(ifsp);
		return;
	}

	if (async_pending(ifsp)) {

		ifsp->if_async.as_tid = iu_schedule_timer(tq, DHCP_ASYNC_WAIT,
		    async_timeout, ifsp);

		if (ifsp->if_async.as_tid != -1) {
			hold_ifs(ifsp);
			dhcpmsg(MSG_DEBUG, "async_timeout: asynchronous "
			    "command %d still pending", ifsp->if_async.as_cmd);
			return;
		}

		/*
		 * what can we do but cancel it?  we can't get called
		 * back again and otherwise we'll end up in the
		 * twilight zone with the interface permanently busy
		 */

		ipc_action_finish(ifsp, DHCP_IPC_E_INT);
		(void) async_cancel(ifsp);
	}
}
