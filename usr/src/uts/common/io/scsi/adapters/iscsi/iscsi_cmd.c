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
 * Copyright 2017 Nexenta Systems, Inc. All rights reserved.
 * iSCSI command interfaces
 */

#include "iscsi.h"

/* internal interfaces */
static void iscsi_cmd_state_free(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg);
static void iscsi_cmd_state_pending(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg);
static void iscsi_cmd_state_active(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg);
static void iscsi_cmd_state_aborting(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg);
static void iscsi_cmd_state_idm_aborting(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg);
static void iscsi_cmd_state_completed(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg);
static char *iscsi_cmd_state_str(iscsi_cmd_state_t state);
static char *iscsi_cmd_event_str(iscsi_cmd_event_t event);
/* LINTED E_STATIC_UNUSED */
static char *iscsi_cmd_type_str(iscsi_cmd_type_t type);

#define	ISCSI_INTERNAL_CMD_TIMEOUT	60

#define	ISCSI_CMD_ISSUE_CALLBACK(icmdp, status)	\
	icmdp->cmd_completed = B_TRUE;		\
	icmdp->cmd_result = status;		\
	cv_broadcast(&icmdp->cmd_completion);

#define	ISCSI_CMD_SET_REASON_STAT(icmdp, reason, stat)	\
	icmdp->cmd_un.scsi.pkt->pkt_reason = reason;	\
	icmdp->cmd_un.scsi.pkt->pkt_statistics = stat;

/*
 * The following private tunable, settable via
 *	set iscsi:iscsi_cmd_timeout_factor = 2
 * in /etc/system, provides customer relief for configurations experiencing
 * SCSI command timeouts due to high-latency/high-loss network connections
 * or slow target response (possibly due to backing store issues). If frequent
 * use of this tunable is necessary, a beter mechanism must be provided.
 */
int	iscsi_cmd_timeout_factor = 1;

/*
 * +--------------------------------------------------------------------+
 * | External Command Interfaces					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_cmd_state_machine - This function is used to drive the
 * state machine of the internal iscsi commands.  It takes in a command
 * and the associated event affecting the command.
 *
 * 7.1.3  Command State Diagram for an Initiator
 *      Symbolic Names for States:
 *      C1: FREE        - State on instantiation, or after successful
 *                        completion.
 *      C2: PENDING     - Command is in the session's pending queue awaiting
 *                        its turn to be sent on the wire.
 *      C3: ACTIVE      - Command has been sent on the wire and is
 *                        awaiting completion.
 *      C4: ABORTING    - Command which was sent on the wire has not timed
 *                        out or been requested to abort by an upper layer
 *                        driver.  At this point there is a task management
 *                        command in the active queue trying to abort the task.
 *	C4': IDM ABORTING - SCSI command is owned by IDM and idm_task_abort
 *                          has been called for this command.
 *      C5: COMPLETED	- Command which is ready to complete via pkt callback.
 *
 *      The state diagram is as follows:
 *               -------
 *              / C1    \
 *    I-------->\       /<------------
 *    N|         ---+---             |
 *    T|            |E1              |
 *    E|            V                |
 *    R|         -------             |
 *    N+--------/ C2    \            |
 *    A|  E4/6/7\       /--------    |
 *    L|         ---+---  E4/6/7|    |
 *     |            |E2    E10  |    |
 *    C|            V           | S  |
 *    M|         _______        | C  |
 *    D+--------/ C3    \       | S  |
 *    S E3/4/6/7\       /-------+ I  |
 *              /---+---E3/4/6/7|    |
 *             /    |      E9/10|    |
 *      ------/ E4/6|           | C  |
 *      |           V           | M  |
 *    E7|        -------        | D  |
 *  SCSI|    - >/ C4    \       | S  |
 *      |   /   \       /-------+    |
 *      |   |    ---+---E3/6/7/9|    |
 *      |   |  E4|  |           V   /E8
 *      |   ------  |        -------
 *      +-\         /       / C5    \
 *      V  \-------/  /---->\       /
 *   -------    E7   /       ---+---
 *  / C4'   \       /
 *  \       /------/ E9
 *   -------
 *
 * The state transition table is as follows:
 *
 *         +---------+---+---+-----+----+--------------+
 *         |C1       |C2 |C3 |C4   |C4' |C5            |
 *      ---+---------+---+---+-----+----+--------------+
 *       C1| -       |E1 | - | -   | -  |              |
 *      ---+---------+---+---+-----+----+--------------+
 *       C2|E4/6/7   |-  |E2 | -   | -  |E4/6/7/10     |
 *      ---+---------+---+---+-----+----+--------------+
 *       C3|E3/4/6/7 |-  |-  |E4/6 |E7  |E3/4/6/7/9/10 |
 *      ---+---------+---+---+-----+----+--------------+
 *       C4|         |-  |-  |E4   |E7  |E3/6/7/9      |
 *      ---+---------+---+---+-----+----+--------------+
 *      C4'|         |-  |-  |-    |-   |E9            |
 *      ---+---------+---+---+-----+----+--------------+
 *       C5|E8       |   |   |     |    |              |
 *      ---+---------+---+---+-----+----+--------------+
 *
 * Event definitions:
 *
 * -E1: Command was requested to be sent on wire
 * -E2: Command was submitted and now active on wire
 * -E3: Command was successfully completed
 *	- SCSI command is move to completion queue
 *	- ABORT/RESET/etc are completed.
 * -E4: Command has been requested to abort
 *	- SCSI command in pending queue will be returned
 *		to caller with aborted status.
 *	- SCSI command state updated and iscsi_handle_abort()
 *		will be called.
 *	- SCSI command with ABORTING state has already
 *		been requested to abort ignore request.
 *	- ABORT/RESET commands will be destroyed and the
 *		caller will be notify of the failure.
 *	- All other commands will just be destroyed.
 * -E6: Command has timed out
 *	- SCSI commands in pending queue will be returned up the
 *		stack with TIMEOUT errors.
 *	- SCSI commands in the active queue and timed out
 *		will be moved to the aborting queue.
 *	- SCSI commands in ABORTING state will be returned up
 *		up the stack with TIMEOUT errors.
 *	- ABORT/RESET commands will be destroyed and the caller
 *		notified of the failure.
 *	- All other commands will just be detroyed.
 * -E7: Connection has encountered a problem
 * -E8:	Command has completed
 *	- Only SCSI cmds should receive these events
 *		and reach the command state.
 * -E9: Callback received for previous idm_task_abort request
 * -E10: The command this abort was associated with has terminated on its own
 */
void
iscsi_cmd_state_machine(iscsi_cmd_t *icmdp, iscsi_cmd_event_t event, void *arg)
{
	boolean_t	release_lock = B_TRUE;

	ASSERT(icmdp != NULL);
	ASSERT(arg != NULL);

	DTRACE_PROBE3(event, iscsi_cmd_t *, icmdp, char *,
	    iscsi_cmd_state_str(icmdp->cmd_state),
	    char *, iscsi_cmd_event_str(event));

	mutex_enter(&icmdp->cmd_mutex);

	/* Audit event */
	idm_sm_audit_event(&icmdp->cmd_state_audit,
	    SAS_ISCSI_CMD, icmdp->cmd_state, event, (uintptr_t)arg);

	icmdp->cmd_prev_state = icmdp->cmd_state;
	switch (icmdp->cmd_state) {
	case ISCSI_CMD_STATE_FREE:
		iscsi_cmd_state_free(icmdp, event, arg);
		break;

	case ISCSI_CMD_STATE_PENDING:
		iscsi_cmd_state_pending(icmdp, event, arg);
		break;

	case ISCSI_CMD_STATE_ACTIVE:
		iscsi_cmd_state_active(icmdp, event, arg);
		break;

	case ISCSI_CMD_STATE_ABORTING:
		iscsi_cmd_state_aborting(icmdp, event, arg);
		break;

	case ISCSI_CMD_STATE_IDM_ABORTING:
		iscsi_cmd_state_idm_aborting(icmdp, event, arg);
		break;

	case ISCSI_CMD_STATE_COMPLETED:
		iscsi_cmd_state_completed(icmdp, event, arg);

		/*
		 * Once completed event is processed we DO NOT
		 * want to touch it again because the caller
		 * (sd, st, etc) may have freed the command.
		 */
		release_lock = B_FALSE;
		break;

	default:
		ASSERT(FALSE);
	}

	if (release_lock == B_TRUE) {
		/* Audit state if not completed */
		idm_sm_audit_state_change(&icmdp->cmd_state_audit,
		    SAS_ISCSI_CMD, icmdp->cmd_prev_state, icmdp->cmd_state);

		if (!(icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_FREE) ||
		    !(icmdp->cmd_misc_flags &
		    ISCSI_CMD_MISCFLAG_INTERNAL)) {
			mutex_exit(&icmdp->cmd_mutex);
			return;
		}
		mutex_exit(&icmdp->cmd_mutex);
		iscsi_cmd_free(icmdp);
	}
}

/*
 * iscsi_cmd_alloc -
 *
 */
iscsi_cmd_t *
iscsi_cmd_alloc(iscsi_conn_t *icp, int km_flags)
{
	iscsi_cmd_t	*icmdp;

	icmdp = kmem_zalloc(sizeof (iscsi_cmd_t), km_flags);
	if (icmdp) {
		icmdp->cmd_sig		= ISCSI_SIG_CMD;
		icmdp->cmd_state	= ISCSI_CMD_STATE_FREE;
		icmdp->cmd_conn		= icp;
		icmdp->cmd_misc_flags	|= ISCSI_CMD_MISCFLAG_INTERNAL;
		idm_sm_audit_init(&icmdp->cmd_state_audit);
		mutex_init(&icmdp->cmd_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&icmdp->cmd_completion, NULL, CV_DRIVER, NULL);
	}
	return (icmdp);
}

/*
 * iscsi_cmd_free -
 *
 */
void
iscsi_cmd_free(iscsi_cmd_t *icmdp)
{
	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_sig == ISCSI_SIG_CMD);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_FREE);
	ASSERT(icmdp->cmd_next == NULL);
	ASSERT(icmdp->cmd_prev == NULL);
	ASSERT(icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_INTERNAL);
	if (icmdp->cmd_type == ISCSI_CMD_TYPE_ABORT)
		ASSERT(icmdp->cmd_un.abort.icmdp == NULL);
	else if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
		ASSERT(icmdp->cmd_un.scsi.r2t_icmdp == NULL);
		ASSERT(icmdp->cmd_un.scsi.abort_icmdp == NULL);
	}
	mutex_destroy(&icmdp->cmd_mutex);
	cv_destroy(&icmdp->cmd_completion);
	kmem_free(icmdp, sizeof (iscsi_cmd_t));
}

/*
 * +--------------------------------------------------------------------+
 * | Internal Command Interfaces					|
 * +--------------------------------------------------------------------+
 */
/*
 * iscsi_cmd_state_free -
 *
 */
static void
iscsi_cmd_state_free(iscsi_cmd_t *icmdp, iscsi_cmd_event_t event, void *arg)
{
	iscsi_sess_t	*isp		= (iscsi_sess_t *)arg;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_FREE);
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {
	/* -E1: Command was requested to be sent on wire */
	case ISCSI_CMD_EVENT_E1:

		/* setup timestamps and timeouts for this command */
		icmdp->cmd_lbolt_pending = ddi_get_lbolt();
		if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
			/*
			 * Establish absolute time when command should timeout.
			 * For commands that depend on cmdsn window to go
			 * active, the timeout will be ignored while on
			 * the pending queue and a new timeout will be
			 * established when the command goes active.
			 */
			if (icmdp->cmd_un.scsi.pkt &&
			    icmdp->cmd_un.scsi.pkt->pkt_time)
				icmdp->cmd_lbolt_timeout =
				    icmdp->cmd_lbolt_pending + SEC_TO_TICK(
				    icmdp->cmd_un.scsi.pkt->pkt_time *
				    iscsi_cmd_timeout_factor);
			else
				icmdp->cmd_lbolt_timeout = 0;

			icmdp->cmd_un.scsi.pkt_stat &=
			    ISCSI_CMD_PKT_STAT_INIT;
		} else {
			icmdp->cmd_lbolt_timeout = icmdp->cmd_lbolt_pending +
			    SEC_TO_TICK(ISCSI_INTERNAL_CMD_TIMEOUT *
			    iscsi_cmd_timeout_factor);
		}

		/* place into pending queue */
		iscsi_enqueue_pending_cmd(isp, icmdp);

		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}

/*
 * iscsi_cmd_state_pending -
 *
 */
static void
iscsi_cmd_state_pending(iscsi_cmd_t *icmdp, iscsi_cmd_event_t event, void *arg)
{
	iscsi_status_t	status;
	iscsi_sess_t	*isp		= (iscsi_sess_t *)arg;
	boolean_t	free_icmdp	= B_FALSE;
	int		rval;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_PENDING);
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {
	/* -E2: Command was submitted and now active on wire */
	case ISCSI_CMD_EVENT_E2:

		/* A connection should have already been assigned */
		ASSERT(mutex_owned(&isp->sess_queue_pending.mutex));
		ASSERT(icmdp->cmd_conn != NULL);

		/*
		 * RESERVE RESOURSES
		 */
		switch (icmdp->cmd_type) {
		case ISCSI_CMD_TYPE_SCSI:
			/* check cmdsn window */
			mutex_enter(&isp->sess_cmdsn_mutex);
			if (!iscsi_sna_lte(isp->sess_cmdsn,
			    isp->sess_maxcmdsn)) {
				/* cmdsn window closed */
				mutex_exit(&isp->sess_cmdsn_mutex);
				mutex_exit(&isp->sess_queue_pending.mutex);
				isp->sess_window_open = B_FALSE;
				icmdp->cmd_misc_flags |=
				    ISCSI_CMD_MISCFLAG_STUCK;
				return;
			}

			/* assign itt */
			status = iscsi_sess_reserve_scsi_itt(icmdp);
			if (!ISCSI_SUCCESS(status)) {
				/* no available itt slots */
				mutex_exit(&isp->sess_cmdsn_mutex);
				mutex_exit(&isp->sess_queue_pending.mutex);
				isp->sess_window_open = B_FALSE;
				icmdp->cmd_misc_flags |=
				    ISCSI_CMD_MISCFLAG_STUCK;
				return;
			}
			mutex_exit(&isp->sess_cmdsn_mutex);
			break;

		case ISCSI_CMD_TYPE_ABORT:
			/*
			 * Verify ABORT's parent SCSI command is still
			 * there.  If parent SCSI command is completed
			 * then there is no longer any reason to abort
			 * the parent command.  This could occur due
			 * to a connection or target reset.
			 */
			ASSERT(icmdp->cmd_un.abort.icmdp != NULL);
			if (icmdp->cmd_un.abort.icmdp->cmd_state ==
			    ISCSI_CMD_STATE_COMPLETED) {
				iscsi_dequeue_pending_cmd(isp, icmdp);
				mutex_exit(&isp->sess_queue_pending.mutex);

				mutex_enter(&icmdp->cmd_un.abort.icmdp->
				    cmd_mutex);
				icmdp->cmd_un.abort.icmdp->
				    cmd_un.scsi.abort_icmdp = NULL;
				cv_broadcast(&icmdp->cmd_un.abort.icmdp->
				    cmd_completion);
				mutex_exit(&icmdp->cmd_un.abort.icmdp->
				    cmd_mutex);
				icmdp->cmd_un.abort.icmdp = NULL;

				icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
				icmdp->cmd_misc_flags |=
				    ISCSI_CMD_MISCFLAG_FREE;
				return;
			}
			/* FALLTHRU */
		case ISCSI_CMD_TYPE_RESET:
			/* FALLTHRU */
		case ISCSI_CMD_TYPE_LOGOUT:
			mutex_enter(&isp->sess_cmdsn_mutex);
			/* assign itt */
			status = iscsi_sess_reserve_itt(isp, icmdp);
			if (!ISCSI_SUCCESS(status)) {
				/* no available itt slots */
				mutex_exit(&isp->sess_cmdsn_mutex);
				mutex_exit(&isp->sess_queue_pending.mutex);
				isp->sess_window_open = B_FALSE;
				return;
			}
			mutex_exit(&isp->sess_cmdsn_mutex);
			break;
		case ISCSI_CMD_TYPE_NOP:
			/* assign itt, if needed */
			if (icmdp->cmd_itt == ISCSI_RSVD_TASK_TAG) {
				/* not expecting a response */
				free_icmdp = B_TRUE;
			} else {
				/* expecting response, assign an itt */
				mutex_enter(&isp->sess_cmdsn_mutex);
				/* assign itt */
				status = iscsi_sess_reserve_itt(isp, icmdp);
				if (!ISCSI_SUCCESS(status)) {
					/* no available itt slots */
					mutex_exit(&isp->sess_cmdsn_mutex);
					mutex_exit(&isp->sess_queue_pending.
					    mutex);
					isp->sess_window_open = B_FALSE;
					return;
				}
				mutex_exit(&isp->sess_cmdsn_mutex);
			}
			break;

		case ISCSI_CMD_TYPE_TEXT:
			mutex_enter(&isp->sess_cmdsn_mutex);
			/* check cmdsn window */
			if (!iscsi_sna_lte(isp->sess_cmdsn,
			    isp->sess_maxcmdsn)) {
				/* cmdsn window closed */
				isp->sess_window_open = B_FALSE;
				mutex_exit(&isp->sess_cmdsn_mutex);
				mutex_exit(&isp->sess_queue_pending.mutex);
				icmdp->cmd_misc_flags |=
				    ISCSI_CMD_MISCFLAG_STUCK;
				return;
			}
			if (icmdp->cmd_un.text.stage ==
			    ISCSI_CMD_TEXT_INITIAL_REQ) {
				/* assign itt */
				status = iscsi_sess_reserve_itt(isp, icmdp);
				if (!ISCSI_SUCCESS(status)) {
					/* no available itt slots */
					mutex_exit(&isp->sess_cmdsn_mutex);
					mutex_exit(&isp->sess_queue_pending.
					    mutex);
					isp->sess_window_open = B_FALSE;
					icmdp->cmd_misc_flags |=
					    ISCSI_CMD_MISCFLAG_STUCK;
					return;
				}
			}
			mutex_exit(&isp->sess_cmdsn_mutex);
			break;

		default:
			ASSERT(FALSE);
		}

		/*
		 * RESOURCES RESERVED
		 *
		 * Now that we have the resources reserved, establish timeout
		 * for cmd_type values that depend on having an open cmdsn
		 * window (i.e. cmd_type that called iscsi_sna_lte() above).
		 */
		if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
			if (icmdp->cmd_un.scsi.pkt &&
			    icmdp->cmd_un.scsi.pkt->pkt_time)
				icmdp->cmd_lbolt_timeout =
				    ddi_get_lbolt() + SEC_TO_TICK(
				    icmdp->cmd_un.scsi.pkt->pkt_time *
				    iscsi_cmd_timeout_factor);
			else
				icmdp->cmd_lbolt_timeout = 0;
		} else if (icmdp->cmd_type == ISCSI_CMD_TYPE_TEXT) {
			icmdp->cmd_lbolt_timeout = ddi_get_lbolt() +
			    SEC_TO_TICK(ISCSI_INTERNAL_CMD_TIMEOUT *
			    iscsi_cmd_timeout_factor);
		}

		/* remove command from pending queue */
		iscsi_dequeue_pending_cmd(isp, icmdp);
		/* check if expecting a response */
		if (free_icmdp == B_FALSE) {
			/* response expected, move to active queue */
			mutex_enter(&icmdp->cmd_conn->conn_queue_active.mutex);
			iscsi_enqueue_active_cmd(icmdp->cmd_conn, icmdp);
			mutex_exit(&icmdp->cmd_conn->conn_queue_active.mutex);
		}

		/*
		 * TRANSFER COMMAND
		 */
		rval = iscsi_tx_cmd(isp, icmdp);

		ASSERT(!mutex_owned(&isp->sess_queue_pending.mutex));

		/*
		 * CHECK SUCCESS/FAILURE
		 */
		if (!ISCSI_SUCCESS(rval)) {
			/*
			 * iscsi_tx_cmd failed.  No cleanup is required
			 * of commands that were put in the active queue.
			 * If the tx failed then rx will also fail and cleanup
			 * all items in the active/aborted queue in a common.
			 */

			/* EMPTY */
		}

		/* free temporary commands */
		if (free_icmdp == B_TRUE) {
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			icmdp->cmd_misc_flags |= ISCSI_CMD_MISCFLAG_FREE;
		}
		break;

	/* -E10: Abort is no longer required for this command */
	case ISCSI_CMD_EVENT_E10:
		/*
		 * Acquiring the sess_queue_pending lock while the
		 * conn_queue_active lock is held conflicts with the
		 * locking order in iscsi_cmd_state_pending where
		 * conn_queue_active is acquired while sess_queue_pending
		 * is held.  Normally this would be a dangerous lock
		 * order conflict, except that we know that if we are
		 * seeing ISCSI_CMD_EVENT_E10 then the command being
		 * aborted is in "aborting" state and by extension
		 * is not in "pending" state.  Therefore the code
		 * path with that alternate lock order will not execute.
		 * That's good because we can't drop the lock here without
		 * risking a deadlock.
		 */
		ASSERT(mutex_owned(&icmdp->cmd_conn->conn_queue_active.mutex));
		mutex_enter(&isp->sess_queue_pending.mutex);

		icmdp->cmd_lbolt_aborting = ddi_get_lbolt();

		iscsi_dequeue_pending_cmd(isp, icmdp);

		icmdp->cmd_un.abort.icmdp->cmd_un.scsi.abort_icmdp = NULL;
		icmdp->cmd_un.abort.icmdp = NULL;
		icmdp->cmd_misc_flags |= ISCSI_CMD_MISCFLAG_FREE;
		icmdp->cmd_state = ISCSI_CMD_STATE_FREE;

		mutex_exit(&isp->sess_queue_pending.mutex);
		break;

	/* -E4: Command has been requested to abort */
	case ISCSI_CMD_EVENT_E4:
		ASSERT(mutex_owned(&isp->sess_queue_pending.mutex));

		icmdp->cmd_lbolt_aborting = ddi_get_lbolt();
		ISCSI_CMD_SET_REASON_STAT(icmdp,
		    CMD_ABORTED, STAT_ABORTED);

		iscsi_dequeue_pending_cmd(isp, icmdp);
		iscsi_enqueue_completed_cmd(isp, icmdp);

		icmdp->cmd_lbolt_aborting = ddi_get_lbolt();

		break;

	/* -E7: Command has been reset */
	case ISCSI_CMD_EVENT_E7:

		/* FALLTHRU */

	/* -E6: Command has timed out */
	case ISCSI_CMD_EVENT_E6:
		ASSERT(mutex_owned(&isp->sess_queue_pending.mutex));
		iscsi_dequeue_pending_cmd(isp, icmdp);

		switch (icmdp->cmd_type) {
		case ISCSI_CMD_TYPE_SCSI:
			/* Complete to caller as TIMEOUT */
			if (event == ISCSI_CMD_EVENT_E6) {
				ISCSI_CMD_SET_REASON_STAT(icmdp,
				    CMD_TIMEOUT, STAT_TIMEOUT);
			} else {
				ISCSI_CMD_SET_REASON_STAT(icmdp,
				    CMD_TRAN_ERR, icmdp->cmd_un.scsi.pkt_stat);
			}
			iscsi_enqueue_completed_cmd(isp, icmdp);
			break;

		case ISCSI_CMD_TYPE_NOP:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			/*
			 * Timeout occured.  Just free NOP.  Another
			 * NOP request will be spawned to replace
			 * this one.
			 */
			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;

			break;

		case ISCSI_CMD_TYPE_ABORT:
			mutex_enter(&icmdp->cmd_un.abort.icmdp->cmd_mutex);
			icmdp->cmd_un.abort.icmdp->
			    cmd_un.scsi.abort_icmdp = NULL;
			cv_broadcast(&icmdp->cmd_un.abort.icmdp->
			    cmd_completion);
			mutex_exit(&icmdp->cmd_un.abort.icmdp->cmd_mutex);
			icmdp->cmd_un.abort.icmdp = NULL;

			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;
			break;

		case ISCSI_CMD_TYPE_RESET:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			/*
			 * If we are failing a RESET we need
			 * to notify the tran_reset caller.
			 * with the cmd and notify caller.
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		case ISCSI_CMD_TYPE_LOGOUT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			/* notify requester of failure */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		case ISCSI_CMD_TYPE_TEXT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_FINAL_RSP;
			/*
			 * If a TEXT command fails, notify the owner.
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		default:
			ASSERT(FALSE);
			break;
		}
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_cmd_state_active -
 *
 */
static void
iscsi_cmd_state_active(iscsi_cmd_t *icmdp, iscsi_cmd_event_t event, void *arg)
{
	iscsi_sess_t	*isp		= (iscsi_sess_t *)arg;
	iscsi_hba_t	*ihp;
	iscsi_cmd_t	*t_icmdp	= NULL;
	iscsi_conn_t	*icp		= NULL;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_ACTIVE);
	ASSERT(isp != NULL);

	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);
	ASSERT(mutex_owned(&icp->conn_queue_active.mutex));

	/* switch on event change */
	switch (event) {
	/* -E3: Command was successfully completed */
	case ISCSI_CMD_EVENT_E3:
		/*
		 * Remove command from the active list.  We need to protect
		 * someone from looking up this command ITT until it's
		 * freed of the command is moved to a new queue location.
		 */
		mutex_enter(&isp->sess_cmdsn_mutex);
		iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);

		switch (icmdp->cmd_type) {
		case ISCSI_CMD_TYPE_SCSI:
			iscsi_sess_release_scsi_itt(icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);
			iscsi_enqueue_completed_cmd(isp, icmdp);
			break;

		case ISCSI_CMD_TYPE_NOP:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/* free alloc */
			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;

			break;

		case ISCSI_CMD_TYPE_ABORT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * Abort was completed successfully.  We should
			 * complete the parent scsi command if it still
			 * exists as timed out, and the state is not
			 * COMPLETED
			 */
			t_icmdp = icmdp->cmd_un.abort.icmdp;
			ASSERT(t_icmdp != NULL);
			mutex_enter(&t_icmdp->cmd_mutex);
			t_icmdp->cmd_un.scsi.abort_icmdp = NULL;
			if (t_icmdp->cmd_state != ISCSI_CMD_STATE_COMPLETED) {
				iscsi_dequeue_active_cmd(
				    t_icmdp->cmd_conn, t_icmdp);
				mutex_enter(
				    &icp->conn_queue_idm_aborting.mutex);
				iscsi_enqueue_idm_aborting_cmd(
				    t_icmdp->cmd_conn,
				    t_icmdp);
				mutex_exit(&icp->conn_queue_idm_aborting.mutex);

				/*
				 * Complete abort processing after IDM
				 * calls us back.  Set the status to use
				 * when we complete the command.
				 */
				ISCSI_CMD_SET_REASON_STAT(
				    t_icmdp, CMD_TIMEOUT, STAT_ABORTED);
				(void) idm_task_abort(icp->conn_ic,
				    t_icmdp->cmd_itp, AT_TASK_MGMT_ABORT);
			} else {
				cv_broadcast(&t_icmdp->cmd_completion);
			}
			mutex_exit(&t_icmdp->cmd_mutex);
			icmdp->cmd_un.abort.icmdp = NULL;

			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;

			break;
		case ISCSI_CMD_TYPE_RESET:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * Complete the abort/reset command.
			 */
			if (icmdp->cmd_un.reset.response !=
			    SCSI_TCP_TM_RESP_COMPLETE) {
				ISCSI_CMD_ISSUE_CALLBACK(icmdp,
				    ISCSI_STATUS_CMD_FAILED);
			} else {
				ISCSI_CMD_ISSUE_CALLBACK(icmdp,
				    ISCSI_STATUS_SUCCESS);
			}

			break;

		case ISCSI_CMD_TYPE_LOGOUT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * Complete the logout successfully.
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp, ISCSI_STATUS_SUCCESS);
			break;

		case ISCSI_CMD_TYPE_TEXT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			if (icmdp->cmd_un.text.stage ==
			    ISCSI_CMD_TEXT_FINAL_RSP) {
				iscsi_sess_release_itt(isp, icmdp);
			}
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * Complete the text command successfully.
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp, icmdp->cmd_result);
			break;

		default:
			mutex_exit(&isp->sess_cmdsn_mutex);
			ASSERT(FALSE);
		}

		ASSERT(!mutex_owned(&isp->sess_cmdsn_mutex));
		break;

	/* -E10,E4: Command has been requested to abort */
	case ISCSI_CMD_EVENT_E10:
		/* FALLTHRU */
	case ISCSI_CMD_EVENT_E4:

		/* E4 is only for resets and aborts */
		ASSERT((icmdp->cmd_type == ISCSI_CMD_TYPE_ABORT) ||
		    (icmdp->cmd_type == ISCSI_CMD_TYPE_RESET));
		/* FALLTHRU */

	/* -E6: Command has timed out */
	case ISCSI_CMD_EVENT_E6:

		switch (icmdp->cmd_type) {
		case ISCSI_CMD_TYPE_SCSI:
			icmdp->cmd_state = ISCSI_CMD_STATE_ABORTING;
			iscsi_handle_abort(icmdp);
			break;

		case ISCSI_CMD_TYPE_NOP:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;

			mutex_enter(&isp->sess_cmdsn_mutex);
			iscsi_sess_release_itt(isp, icmdp);
			iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;

			break;

		case ISCSI_CMD_TYPE_ABORT:
			icmdp->cmd_state =
			    ISCSI_CMD_STATE_FREE;

			mutex_enter(&isp->sess_cmdsn_mutex);
			iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * If this is an E4 then we may need to deal with
			 * the abort's associated SCSI command.  If this
			 * is an E10 then IDM is already cleaning up the
			 * SCSI command and all we need to do is break the
			 * linkage between them and free the abort command.
			 */
			t_icmdp = icmdp->cmd_un.abort.icmdp;
			ASSERT(t_icmdp != NULL);
			if (event != ISCSI_CMD_EVENT_E10) {

				mutex_enter(&t_icmdp->cmd_mutex);
				t_icmdp->cmd_un.scsi.abort_icmdp = NULL;
				/*
				 * If abort command is aborted then we should
				 * not act on the parent scsi command.  If the
				 * abort command timed out then we need to
				 * complete the parent command if it still
				 * exists with a timeout failure.
				 */
				if ((event == ISCSI_CMD_EVENT_E6) &&
				    (t_icmdp->cmd_state !=
				    ISCSI_CMD_STATE_IDM_ABORTING) &&
				    (t_icmdp->cmd_state !=
				    ISCSI_CMD_STATE_COMPLETED)) {

					iscsi_dequeue_active_cmd(
					    t_icmdp->cmd_conn, t_icmdp);
					mutex_enter(&icp->
					    conn_queue_idm_aborting.mutex);
					iscsi_enqueue_idm_aborting_cmd(
					    t_icmdp->cmd_conn,  t_icmdp);
					mutex_exit(&icp->
					    conn_queue_idm_aborting.mutex);
					/*
					 * Complete abort processing after IDM
					 * calls us back.  Set the status to use
					 * when we complete the command.
					 */
					ISCSI_CMD_SET_REASON_STAT(t_icmdp,
					    CMD_TIMEOUT, STAT_TIMEOUT);
					(void) idm_task_abort(icp->conn_ic,
					    t_icmdp->cmd_itp,
					    AT_TASK_MGMT_ABORT);
				} else {
					cv_broadcast(&t_icmdp->cmd_completion);
				}
				mutex_exit(&t_icmdp->cmd_mutex);
			} else {
				t_icmdp->cmd_un.scsi.abort_icmdp = NULL;
			}
			icmdp->cmd_un.abort.icmdp = NULL;
			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;
			break;

		case ISCSI_CMD_TYPE_RESET:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;

			mutex_enter(&isp->sess_cmdsn_mutex);
			iscsi_sess_release_itt(isp, icmdp);
			iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * If we are failing a RESET we need
			 * to notify the tran_reset caller.
			 * It will free the memory associated
			 * with the cmd and notify caller.
			 */

			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		case ISCSI_CMD_TYPE_LOGOUT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;

			mutex_enter(&isp->sess_cmdsn_mutex);
			iscsi_sess_release_itt(isp, icmdp);
			iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * Notify caller of failure.
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		case ISCSI_CMD_TYPE_TEXT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_FINAL_RSP;
			mutex_enter(&isp->sess_cmdsn_mutex);
			iscsi_sess_release_itt(isp, icmdp);
			iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * If a TEXT command fails, notify caller so
			 * it can free assocated command
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		default:
			ASSERT(FALSE);
		}

		ASSERT(!mutex_owned(&isp->sess_cmdsn_mutex));
		break;

	/* -E7: Connection has encountered a problem */
	case ISCSI_CMD_EVENT_E7:
		mutex_enter(&isp->sess_cmdsn_mutex);
		iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);

		switch (icmdp->cmd_type) {
		case ISCSI_CMD_TYPE_SCSI:
			mutex_exit(&isp->sess_cmdsn_mutex);
			mutex_enter(&icp->conn_queue_idm_aborting.mutex);
			iscsi_enqueue_idm_aborting_cmd(icmdp->cmd_conn, icmdp);
			mutex_exit(&icp->conn_queue_idm_aborting.mutex);
			ISCSI_CMD_SET_REASON_STAT(icmdp,
			    CMD_TRAN_ERR, icmdp->cmd_un.scsi.pkt_stat);
			(void) idm_task_abort(icp->conn_ic, icmdp->cmd_itp,
			    AT_TASK_MGMT_ABORT);
			break;

		case ISCSI_CMD_TYPE_NOP:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;
			break;

		case ISCSI_CMD_TYPE_ABORT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			mutex_enter(&icmdp->cmd_un.abort.icmdp->cmd_mutex);
			icmdp->cmd_un.abort.icmdp->
			    cmd_un.scsi.abort_icmdp = NULL;
			cv_broadcast(&icmdp->cmd_un.abort.icmdp->
			    cmd_completion);
			mutex_exit(&icmdp->cmd_un.abort.icmdp->cmd_mutex);
			/*
			 * Nullify the abort command's pointer to its
			 * parent command. It does not have to complete its
			 * parent command because the parent command will
			 * also get an E7.
			 */
			icmdp->cmd_un.abort.icmdp = NULL;

			icmdp->cmd_misc_flags |=
			    ISCSI_CMD_MISCFLAG_FREE;
			break;

		case ISCSI_CMD_TYPE_RESET:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);
			/*
			 * If we are failing a ABORT we need
			 * to notify the tran_abort caller.
			 * It will free the memory associated
			 * with the cmd and notify caller.
			 */

			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		case ISCSI_CMD_TYPE_LOGOUT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			/*
			 * A connection problem and we attempted to
			 * logout?  I guess we can just free the
			 * request.  Someone has already pushed the
			 * connection state.
			 */
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			ISCSI_CMD_ISSUE_CALLBACK(icmdp, ISCSI_STATUS_SUCCESS);
			break;

		case ISCSI_CMD_TYPE_TEXT:
			icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
			icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_FINAL_RSP;
			iscsi_sess_release_itt(isp, icmdp);
			mutex_exit(&isp->sess_cmdsn_mutex);

			/*
			 * If a TEXT command fails, notify caller so
			 * it can free assocated command
			 */
			ISCSI_CMD_ISSUE_CALLBACK(icmdp,
			    ISCSI_STATUS_CMD_FAILED);
			break;

		default:
			mutex_exit(&isp->sess_cmdsn_mutex);
			ASSERT(FALSE);
			break;
		}

		ASSERT(!mutex_owned(&isp->sess_cmdsn_mutex));
		break;

	/* -E9: IDM is no longer processing this command */
	case ISCSI_CMD_EVENT_E9:
		iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);

		iscsi_task_cleanup(ISCSI_OP_SCSI_RSP, icmdp);
		iscsi_sess_release_scsi_itt(icmdp);

		ISCSI_CMD_SET_REASON_STAT(icmdp, CMD_TRAN_ERR,
		    icmdp->cmd_un.scsi.pkt_stat);
		iscsi_enqueue_completed_cmd(isp, icmdp);
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_cmd_state_aborting -
 *
 */
static void
iscsi_cmd_state_aborting(iscsi_cmd_t *icmdp, iscsi_cmd_event_t event, void *arg)
{
	iscsi_sess_t	*isp	= (iscsi_sess_t *)arg;
	iscsi_cmd_t	*a_icmdp;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_ABORTING);
	ASSERT(isp != NULL);
	ASSERT(mutex_owned(&icmdp->cmd_conn->conn_queue_active.mutex));

	/* switch on event change */
	switch (event) {
	/* -E3: Command was successfully completed */
	case ISCSI_CMD_EVENT_E3:
		/*
		 * Remove command from the aborting list
		 */
		mutex_enter(&isp->sess_cmdsn_mutex);
		iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
		iscsi_sess_release_scsi_itt(icmdp);
		mutex_exit(&isp->sess_cmdsn_mutex);

		iscsi_enqueue_completed_cmd(isp, icmdp);
		break;

	/* -E4: Command has been requested to abort */
	case ISCSI_CMD_EVENT_E4:
		/*
		 * An upper level driver might attempt to
		 * abort a command that we are already
		 * aborting due to a nop.  Since we are
		 * already in the process of aborting
		 * ignore the request.
		 */
		break;

	/* -E6: Command has timed out */
	case ISCSI_CMD_EVENT_E6:
		ASSERT(FALSE);
		/*
		 * Timeouts should not occur on command in abort queue
		 * they are already be processed due to a timeout.
		 */
		break;

	/* -E7: Connection has encountered a problem */
	case ISCSI_CMD_EVENT_E7:
		iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);
		mutex_enter(&icmdp->cmd_conn->conn_queue_idm_aborting.mutex);
		iscsi_enqueue_idm_aborting_cmd(icmdp->cmd_conn, icmdp);
		mutex_exit(&icmdp->cmd_conn->conn_queue_idm_aborting.mutex);

		/*
		 * Since we are in "aborting" state there is another command
		 * representing the abort of this command.  This command
		 * will cleanup at some indeterminate time after the call
		 * to idm_task_abort so we can't leave the abort request
		 * active.  An E10 event to the abort command will cause
		 * it to complete immediately.
		 */
		if ((a_icmdp = icmdp->cmd_un.scsi.abort_icmdp) != NULL) {
			iscsi_cmd_state_machine(a_icmdp,
			    ISCSI_CMD_EVENT_E10, arg);
		}

		ISCSI_CMD_SET_REASON_STAT(icmdp,
		    CMD_TRAN_ERR, icmdp->cmd_un.scsi.pkt_stat);

		(void) idm_task_abort(icmdp->cmd_conn->conn_ic, icmdp->cmd_itp,
		    AT_TASK_MGMT_ABORT);
		break;

	/* -E9: IDM is no longer processing this command */
	case ISCSI_CMD_EVENT_E9:
		iscsi_dequeue_active_cmd(icmdp->cmd_conn, icmdp);

		iscsi_task_cleanup(ISCSI_OP_SCSI_RSP, icmdp);
		iscsi_sess_release_scsi_itt(icmdp);

		ISCSI_CMD_SET_REASON_STAT(icmdp, CMD_TRAN_ERR,
		    icmdp->cmd_un.scsi.pkt_stat);
		iscsi_enqueue_completed_cmd(isp, icmdp);
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}

static void
iscsi_cmd_state_idm_aborting(iscsi_cmd_t *icmdp, iscsi_cmd_event_t event,
    void *arg)
{
	iscsi_sess_t	*isp	= (iscsi_sess_t *)arg;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_IDM_ABORTING);
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {
	/* -E3: Command was successfully completed */
	case ISCSI_CMD_EVENT_E3:
		/*
		 * iscsi_rx_process_cmd_rsp() and iscsi_rx_process_data_rsp()
		 * are supposed to confirm the cmd state is appropriate before
		 * generating an E3 event.  E3 is not allowed in this state.
		 */
		ASSERT(0);
		break;

	/* -E4: Command has been requested to abort */
	case ISCSI_CMD_EVENT_E4:
		/*
		 * An upper level driver might attempt to
		 * abort a command that we are already
		 * aborting due to a nop.  Since we are
		 * already in the process of aborting
		 * ignore the request.
		 */
		break;

	/* -E6: Command has timed out */
	case ISCSI_CMD_EVENT_E6:
		ASSERT(FALSE);
		/*
		 * Timeouts should not occur on aborting commands
		 */
		break;

	/* -E7: Connection has encountered a problem */
	case ISCSI_CMD_EVENT_E7:
		/*
		 * We have already requested IDM to stop processing this
		 * command so just update the pkt_statistics.
		 */
		ISCSI_CMD_SET_REASON_STAT(icmdp,
		    CMD_TRAN_ERR, icmdp->cmd_un.scsi.pkt_stat);
		break;

	/* -E9: IDM is no longer processing this command */
	case ISCSI_CMD_EVENT_E9:
		mutex_enter(&icmdp->cmd_conn->conn_queue_idm_aborting.mutex);
		iscsi_dequeue_idm_aborting_cmd(icmdp->cmd_conn, icmdp);
		mutex_exit(&icmdp->cmd_conn->conn_queue_idm_aborting.mutex);

		/* This is always an error so make sure an error has been set */
		ASSERT(icmdp->cmd_un.scsi.pkt->pkt_reason != CMD_CMPLT);
		iscsi_task_cleanup(ISCSI_OP_SCSI_RSP, icmdp);
		iscsi_sess_release_scsi_itt(icmdp);

		/*
		 * Whoever called idm_task_abort should have set the completion
		 * status beforehand.
		 */
		iscsi_enqueue_completed_cmd(isp, icmdp);
		cv_broadcast(&icmdp->cmd_completion);
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_cmd_state_completed -
 *
 */
static void
iscsi_cmd_state_completed(iscsi_cmd_t *icmdp,
    iscsi_cmd_event_t event, void *arg)
{
	iscsi_sess_t	*isp	= (iscsi_sess_t *)arg;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_COMPLETED);
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {
	/* -E8: */
	case ISCSI_CMD_EVENT_E8:
		icmdp->cmd_state = ISCSI_CMD_STATE_FREE;

		/* the caller has already remove cmd from queue */

		icmdp->cmd_next = NULL;
		icmdp->cmd_prev = NULL;
		iscsi_iodone(isp, icmdp);
		break;
	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_cmd_state_str -
 *
 */
static char *
iscsi_cmd_state_str(iscsi_cmd_state_t state)
{
	switch (state) {
	case ISCSI_CMD_STATE_FREE:
		return ("free");
	case ISCSI_CMD_STATE_PENDING:
		return ("pending");
	case ISCSI_CMD_STATE_ACTIVE:
		return ("active");
	case ISCSI_CMD_STATE_ABORTING:
		return ("aborting");
	case ISCSI_CMD_STATE_IDM_ABORTING:
		return ("idm-aborting");
	case ISCSI_CMD_STATE_COMPLETED:
		return ("completed");
	default:
		return ("unknown");
	}
}


/*
 * iscsi_cmd_event_str -
 *
 */
static char *
iscsi_cmd_event_str(iscsi_cmd_event_t event)
{
	switch (event) {
	case ISCSI_CMD_EVENT_E1:
		return ("E1");
	case ISCSI_CMD_EVENT_E2:
		return ("E2");
	case ISCSI_CMD_EVENT_E3:
		return ("E3");
	case ISCSI_CMD_EVENT_E4:
		return ("E4");
	case ISCSI_CMD_EVENT_E6:
		return ("E6");
	case ISCSI_CMD_EVENT_E7:
		return ("E7");
	case ISCSI_CMD_EVENT_E8:
		return ("E8");
	case ISCSI_CMD_EVENT_E9:
		return ("E9");
	case ISCSI_CMD_EVENT_E10:
		return ("E10");
	default:
		return ("unknown");
	}
}


/*
 * iscsi_cmd_event_str -
 *
 */
static char *
iscsi_cmd_type_str(iscsi_cmd_type_t type)
{
	switch (type) {
	case ISCSI_CMD_TYPE_SCSI:
		return ("scsi");
	case ISCSI_CMD_TYPE_NOP:
		return ("nop");
	case ISCSI_CMD_TYPE_ABORT:
		return ("abort");
	case ISCSI_CMD_TYPE_RESET:
		return ("reset");
	case ISCSI_CMD_TYPE_LOGOUT:
		return ("logout");
	default:
		return ("unknown");
	}
}
