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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * iSCSI connection interfaces
 */

#include "iscsi.h"
#include "persistent.h"
#include <sys/bootprops.h>

extern ib_boot_prop_t   *iscsiboot_prop;

/* interface connection interfaces */
static iscsi_status_t iscsi_conn_state_free(iscsi_conn_t *icp,
    iscsi_conn_event_t event);
static void iscsi_conn_state_in_login(iscsi_conn_t *icp,
    iscsi_conn_event_t event);
static void iscsi_conn_state_logged_in(iscsi_conn_t *icp,
    iscsi_conn_event_t event);
static void iscsi_conn_state_in_logout(iscsi_conn_t *icp,
    iscsi_conn_event_t event);
static void iscsi_conn_state_failed(iscsi_conn_t *icp,
    iscsi_conn_event_t event);
static void iscsi_conn_state_polling(iscsi_conn_t *icp,
    iscsi_conn_event_t event);
static char *iscsi_conn_event_str(iscsi_conn_event_t event);
static void iscsi_conn_flush_active_cmds(iscsi_conn_t *icp);

static void iscsi_conn_logged_in(iscsi_sess_t *isp,
    iscsi_conn_t *icp);
static void iscsi_conn_retry(iscsi_sess_t *isp,
    iscsi_conn_t *icp);

#define	SHUTDOWN_TIMEOUT	180 /* seconds */

extern int modrootloaded;
/*
 * +--------------------------------------------------------------------+
 * | External Connection Interfaces					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_conn_create - This creates an iscsi connection structure and
 * associates it with a session structure.  The session's sess_conn_list_rwlock
 * should be held as a writer before calling this function.
 */
iscsi_status_t
iscsi_conn_create(struct sockaddr *addr, iscsi_sess_t *isp, iscsi_conn_t **icpp)
{
	iscsi_conn_t	*icp	= NULL;
	char		th_name[ISCSI_TH_MAX_NAME_LEN];

	/* See if this connection already exists */
	for (icp = isp->sess_conn_list; icp; icp = icp->conn_next) {

		/*
		 * Compare the ioctl information to see if
		 * its a match for this connection.  (This
		 * is done by making sure the IPs are of
		 * the same size and then they are the
		 * same value.
		 */
		if (bcmp(&icp->conn_base_addr, addr,
		    SIZEOF_SOCKADDR(addr)) == 0) {
			/* It's a match, record this connection */
			break;
		}
	}

	/* If icp is found return it */
	if (icp != NULL) {
		*icpp = icp;
		return (ISCSI_STATUS_SUCCESS);
	}

	/* We are creating the connection, allocate, and setup */
	icp = (iscsi_conn_t *)kmem_zalloc(sizeof (iscsi_conn_t), KM_SLEEP);

	/*
	 * Setup connection
	 */
	icp->conn_sig			= ISCSI_SIG_CONN;
	icp->conn_state			= ISCSI_CONN_STATE_FREE;
	mutex_init(&icp->conn_state_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&icp->conn_state_change, NULL, CV_DRIVER, NULL);
	icp->conn_state_destroy		= B_FALSE;
	icp->conn_sess			= isp;
	icp->conn_state_lbolt		= ddi_get_lbolt();

	mutex_enter(&iscsi_oid_mutex);
	icp->conn_oid = iscsi_oid++;
	mutex_exit(&iscsi_oid_mutex);

	/* Creation of the receive thread */
	if (snprintf(th_name, sizeof (th_name) - 1, ISCSI_CONN_RXTH_NAME_FORMAT,
	    icp->conn_sess->sess_hba->hba_oid, icp->conn_sess->sess_oid,
	    icp->conn_oid) >= sizeof (th_name)) {
		cv_destroy(&icp->conn_state_change);
		mutex_destroy(&icp->conn_state_mutex);
		kmem_free(icp, sizeof (iscsi_conn_t));
		*icpp = NULL;
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	icp->conn_rx_thread = iscsi_thread_create(isp->sess_hba->hba_dip,
	    th_name, iscsi_rx_thread, icp);

	/* Creation of the transfer thread */
	if (snprintf(th_name, sizeof (th_name) - 1, ISCSI_CONN_TXTH_NAME_FORMAT,
	    icp->conn_sess->sess_hba->hba_oid, icp->conn_sess->sess_oid,
	    icp->conn_oid) >= sizeof (th_name)) {
		iscsi_thread_destroy(icp->conn_rx_thread);
		cv_destroy(&icp->conn_state_change);
		mutex_destroy(&icp->conn_state_mutex);
		kmem_free(icp, sizeof (iscsi_conn_t));
		*icpp = NULL;
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	icp->conn_tx_thread = iscsi_thread_create(isp->sess_hba->hba_dip,
	    th_name, iscsi_tx_thread, icp);

	/* setup connection queues */
	iscsi_init_queue(&icp->conn_queue_active);

	bcopy(addr, &icp->conn_base_addr, sizeof (icp->conn_base_addr));

	/* Add new connection to the session connection list */
	icp->conn_cid = isp->sess_conn_next_cid++;
	if (isp->sess_conn_list == NULL) {
		isp->sess_conn_list = isp->sess_conn_list_last_ptr = icp;
	} else {
		isp->sess_conn_list_last_ptr->conn_next = icp;
		isp->sess_conn_list_last_ptr = icp;
	}

	KSTAT_INC_SESS_CNTR_CONN(isp);
	(void) iscsi_conn_kstat_init(icp);

	*icpp = icp;

	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_conn_offline - This attempts to take a connection from
 * any state to ISCSI_CONN_STATE_FREE.
 */
iscsi_status_t
iscsi_conn_offline(iscsi_conn_t *icp)
{
	clock_t		delay;

	ASSERT(icp != NULL);

	/*
	 * We can only destroy a connection if its either in
	 * a state of FREE or LOGGED.  The other states are
	 * transitionary and its unsafe to perform actions
	 * on the connection in those states.  Set a flag
	 * on the connection to influence the transitions
	 * to quickly complete.  Then wait for a state
	 * transition.
	 */
	delay = ddi_get_lbolt() + SEC_TO_TICK(SHUTDOWN_TIMEOUT);
	mutex_enter(&icp->conn_state_mutex);
	icp->conn_state_destroy = B_TRUE;
	while ((icp->conn_state != ISCSI_CONN_STATE_FREE) &&
	    (icp->conn_state != ISCSI_CONN_STATE_LOGGED_IN) &&
	    (ddi_get_lbolt() < delay)) {
		/* wait for transition */
		(void) cv_timedwait(&icp->conn_state_change,
		    &icp->conn_state_mutex, delay);
	}

	/* Final check whether we can destroy the connection */
	switch (icp->conn_state) {
	case ISCSI_CONN_STATE_FREE:
		/* Easy case - Connection is dead */
		break;
	case ISCSI_CONN_STATE_LOGGED_IN:
		/* Hard case - Force connection logout */
		(void) iscsi_conn_state_machine(icp,
		    ISCSI_CONN_EVENT_T9);
		break;
	case ISCSI_CONN_STATE_IN_LOGIN:
	case ISCSI_CONN_STATE_IN_LOGOUT:
	case ISCSI_CONN_STATE_FAILED:
	case ISCSI_CONN_STATE_POLLING:
	default:
		/* All other cases fail the destroy */
		icp->conn_state_destroy = B_FALSE;
		mutex_exit(&icp->conn_state_mutex);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}
	mutex_exit(&icp->conn_state_mutex);

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_conn_destroy - This destroys an iscsi connection structure
 * and de-associates it with the session.  The connection should
 * already been in the ISCSI_CONN_STATE_FREE when attempting this
 * operation.
 */
iscsi_status_t
iscsi_conn_destroy(iscsi_conn_t *icp)
{
	iscsi_sess_t	*isp;
	iscsi_conn_t	*t_icp;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	if (icp->conn_state != ISCSI_CONN_STATE_FREE) {
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* Destroy receive thread */
	iscsi_thread_destroy(icp->conn_rx_thread);

	/* Destroy transfer thread */
	iscsi_thread_destroy(icp->conn_tx_thread);

	/* Terminate connection queues */
	iscsi_destroy_queue(&icp->conn_queue_active);

	cv_destroy(&icp->conn_state_change);
	mutex_destroy(&icp->conn_state_mutex);

	/*
	 * Remove connection from sessions linked list.
	 */
	if (isp->sess_conn_list == icp) {
		/* connection first item in list */
		isp->sess_conn_list = icp->conn_next;
		/*
		 * check if this is also the last item in the list
		 */
		if (isp->sess_conn_list_last_ptr == icp) {
			isp->sess_conn_list_last_ptr = NULL;
		}
	} else {
		/*
		 * search session list for icp pointing
		 * to connection being removed.  Then
		 * update that connections next pointer.
		 */
		t_icp = isp->sess_conn_list;
		while (t_icp->conn_next != NULL) {
			if (t_icp->conn_next == icp) {
				break;
			}
			t_icp = t_icp->conn_next;
		}
		if (t_icp->conn_next == icp) {
			t_icp->conn_next = icp->conn_next;
			/*
			 * if this is the last connection in the list
			 * update the last_ptr to point to t_icp
			 */
			if (isp->sess_conn_list_last_ptr == icp) {
				isp->sess_conn_list_last_ptr = t_icp;
			}
		} else {
			/* couldn't find session */
			ASSERT(FALSE);
		}
	}

	/* Free this Connections Data */
	iscsi_conn_kstat_term(icp);
	kmem_free(icp, sizeof (iscsi_conn_t));

	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_conn_set_login_min_max - set min/max login window
 *
 * Used to set the min and max login window.  Input values
 * are in seconds.
 */
void
iscsi_conn_set_login_min_max(iscsi_conn_t *icp, int min, int max)
{
	ASSERT(icp != NULL);

	icp->conn_login_min = ddi_get_lbolt() + SEC_TO_TICK(min);
	icp->conn_login_max = ddi_get_lbolt() + SEC_TO_TICK(max);
}



/*
 * iscsi_conn_state_machine - This function is used to drive the
 * state machine of the iscsi connection.  It takes in a connection
 * and the associated event effecting the connection.
 *
 * 7.1.3  Connection State Diagram for an Initiator
 *      Symbolic Names for States:
 *      S1: FREE        - State on instantiation, or after successful
 *                        connection closure.
 *      S2: IN_LOGIN    - Waiting for login process to conclude,
 *                        possibly involving several PDU exchanges.
 *      S3: LOGGED_IN   - In Full Feature Phase, waiting for all internal,
 *                        iSCSI, and transport events
 *      S4: IN_LOGOUT   - Waiting for the Logout repsonse.
 *      S5: FAILED      - The connection has failed.  Attempting
 *			  to reconnect.
 *      S6: POLLING     - The connection reconnect attempts have
 *                        failed.  Continue to poll at a lower
 *                        frequency.
 *
 *      States S3, S4 constitute the Full Feature Phase
 *              of the connection.
 *
 *      The state diagram is as follows:
 *                 -------
 *      +-------->/ S1    \<------------------------------+
 *      |      +->\       /<---+            /---\         |
 *      |     /    ---+---     |T7/30     T7|   |         |
 *      |    +        |        |            \->------     |
 *      |  T8|        |T1     /      T5       / S6   \--->|
 *      |    |        |      /     +----------\      /T30 |
 *      |    |        V     /     /            ------     |
 *      |    |     ------- /     /               ^        |
 *      |    |    / S2    \     /   T5           |T7      |
 *      |    |    \       /    +-------------- --+---     |
 *      |    |     ---+---    /               / S5   \--->|
 *      |    |        |      /      T14/T15   \      /T30 |
 *      |    |        |T5   /  +-------------> ------     |
 *      |    |        |    /  /                           |
 *      |    |        |   /  /         T11                |
 *      |    |        |  /  /         +----+              |
 *      |    |        V V  /          |    |              |
 *      |    |      ------+       ----+--  |              |
 *      |    +-----/ S3    \T9/11/ S4    \<+              |
 *      +----------\       /---->\       /----------------+
 *                  -------       -------        T15/T17
 *
 * The state transition table is as follows:
 *
 *         +-----+---+---+------+------+---+
 *         |S1   |S2 |S3 |S4    |S5    |S6 |
 *      ---+-----+---+---+------+------+---+
 *       S1|T1   |T1 | - | -    | -    |   |
 *      ---+-----+---+---+------+------+---+
 *       S2|T7/30|-  |T5 | -    | -    |   |
 *      ---+-----+---+---+------+------+---+
 *       S3|T8   |-  | - |T9/11 |T14/15|   |
 *      ---+-----+---+---+------+------+---+
 *       S4|     |-  | - |T11   |T15/17|   |
 *      ---+-----+---+---+------+------+---+
 *       S5|T30  |   |T5 |      |      |T7 |
 *      ---+-----+---+---+------+------+---+
 *       S6|T30  |   |T5 |      |      |T7 |
 *      ---+-----+---+---+------+------+---+
 *
 * Events definitions:
 *
 * -T1: Transport connection request was made (e.g., TCP SYN sent).
 * -T5: The final iSCSI Login response with a Status-Class of zero was
 *      received.
 * -T7: One of the following events caused the transition:
 *      - Login timed out.
 *      - A transport disconnect indication was received.
 *      - A transport reset was received.
 *      - An internal event indicating a transport timeout was
 *        received.
 *      - An internal event of receiving a Logout repsonse (success)
 *        on another connection for a "close the session" Logout
 *        request was received.
 *      * In all these cases, the transport connection is closed.
 * -T8: An internal event of receiving a Logout response (success)
 *      on another connection for a "close the session" Logout request
 *      was received, thus closing this connection requiring no further
 *      cleanup.
 * -T9: An internal event that indicates the readiness to start the
 *      Logout process was received, thus prompting an iSCSI Logout to
 *      be sent by the initiator.
 * -T11: Async PDU with AsyncEvent "Request Logout" was received.
 * -T13: An iSCSI Logout response (success) was received, or an internal
 *      event of receiving a Logout response (success) on another
 *      connection was received.
 * -T14: One or more of the following events case this transition:
 *	- Header Digest Error
 *	- Protocol Error
 * -T15: One or more of the following events caused this transition:
 *      - Internal event that indicates a transport connection timeout
 *        was received thus prompting transport RESET or transport
 *        connection closure.
 *      - A transport RESET
 *      - A transport disconnect indication.
 *      - Async PDU with AsyncEvent "Drop connection" (for this CID)
 *      - Async PDU with AsyncEvent "Drop all connections"
 * -T17: One or more of the following events caused this transition:
 *      - Logout response, (failure i.e., a non-zero status) was
 *      received, or Logout timed out.
 *      - Any of the events specified for T15.
 * -T30: One of the following event caused the transition:
 *	- Thefinal iSCSI Login response was received with a non-zero
 *	  Status-Class.
 */
iscsi_status_t
iscsi_conn_state_machine(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_status_t	    status = ISCSI_STATUS_SUCCESS;

	ASSERT(icp != NULL);
	ASSERT(mutex_owned(&icp->conn_state_mutex));

	DTRACE_PROBE3(event, iscsi_conn_t *, icp,
	    char *, iscsi_conn_state_str(icp->conn_state),
	    char *, iscsi_conn_event_str(event));

	icp->conn_prev_state = icp->conn_state;
	icp->conn_state_lbolt = ddi_get_lbolt();

	switch (icp->conn_state) {
	case ISCSI_CONN_STATE_FREE:
		status = iscsi_conn_state_free(icp, event);
		break;
	case ISCSI_CONN_STATE_IN_LOGIN:
		iscsi_conn_state_in_login(icp, event);
		break;
	case ISCSI_CONN_STATE_LOGGED_IN:
		iscsi_conn_state_logged_in(icp, event);
		break;
	case ISCSI_CONN_STATE_IN_LOGOUT:
		iscsi_conn_state_in_logout(icp, event);
		break;
	case ISCSI_CONN_STATE_FAILED:
		iscsi_conn_state_failed(icp, event);
		break;
	case ISCSI_CONN_STATE_POLLING:
		iscsi_conn_state_polling(icp, event);
		break;
	default:
		ASSERT(FALSE);
		status = ISCSI_STATUS_INTERNAL_ERROR;
	}

	cv_broadcast(&icp->conn_state_change);
	return (status);
}


/*
 * iscsi_conn_state_str - converts state enum to a string
 */
char *
iscsi_conn_state_str(iscsi_conn_state_t state)
{
	switch (state) {
	case ISCSI_CONN_STATE_FREE:
		return ("free");
	case ISCSI_CONN_STATE_IN_LOGIN:
		return ("in_login");
	case ISCSI_CONN_STATE_LOGGED_IN:
		return ("logged_in");
	case ISCSI_CONN_STATE_IN_LOGOUT:
		return ("in_logout");
	case ISCSI_CONN_STATE_FAILED:
		return ("failed");
	case ISCSI_CONN_STATE_POLLING:
		return ("polling");
	default:
		return ("unknown");
	}
}


/*
 * iscsi_conn_sync_params - used to update connection parameters
 *
 * Used to update connection parameters with current configured
 * parameters in the persistent store.  This should be called
 * before starting to make a new iscsi connection in iscsi_login.
 */
iscsi_status_t
iscsi_conn_sync_params(iscsi_conn_t *icp)
{
	iscsi_sess_t		*isp;
	iscsi_hba_t		*ihp;
	int			param_id;
	persistent_param_t	pp;
	iscsi_config_sess_t	*ics;
	int			idx, size;
	char			*name;

	ASSERT(icp != NULL);
	ASSERT((icp->conn_state == ISCSI_CONN_STATE_IN_LOGIN) ||
	    (icp->conn_state == ISCSI_CONN_STATE_FAILED) ||
	    (icp->conn_state == ISCSI_CONN_STATE_POLLING));
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/*
	 * Check if someone is trying to destroy this
	 * connection.  If so fail the sync request,
	 * as a method of fast fail.
	 */
	if (icp->conn_state_destroy == B_TRUE) {
		return (ISCSI_STATUS_SHUTDOWN);
	}

	bzero(&pp, sizeof (pp));

	/* First get a copy of the HBA params */
	bcopy(&ihp->hba_params, &icp->conn_params,
	    sizeof (iscsi_login_params_t));

	/*
	 * Now we need to get the session configured
	 * values from the persistent store and apply
	 * them to our connection.
	 */
	(void) persistent_param_get((char *)isp->sess_name, &pp);
	for (param_id = 0; param_id < ISCSI_NUM_LOGIN_PARAM;
	    param_id++) {
		if (iscsiboot_prop && modrootloaded &&
		    !iscsi_chk_bootlun_mpxio(ihp) && isp->sess_boot) {
			/*
			 * iscsi boot with mpxio disabled
			 * while iscsi booting target's parameter overriden
			 * do no update target's parameters.
			 */
			if (pp.p_bitmap) {
				cmn_err(CE_NOTE, "Adopting "
				    " default login parameters in"
				    " boot session as MPxIO is disabled");
			}
			break;
		}
		if (pp.p_bitmap & (1 << param_id)) {
				switch (param_id) {
			/*
			 * Boolean parameters
			 */
			case ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER:
				icp->conn_params.data_pdu_in_order =
				    pp.p_params.data_pdu_in_order;
				break;
			case ISCSI_LOGIN_PARAM_IMMEDIATE_DATA:
				icp->conn_params.immediate_data =
				    pp.p_params.immediate_data;
				break;
			case ISCSI_LOGIN_PARAM_INITIAL_R2T:
				icp->conn_params.initial_r2t =
				    pp.p_params.initial_r2t;
				break;
			case ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER:
				icp->conn_params.data_pdu_in_order =
				    pp.p_params.data_pdu_in_order;
				break;
			/*
			 * Integer parameters
			 */
			case ISCSI_LOGIN_PARAM_HEADER_DIGEST:
				icp->conn_params.header_digest =
				    pp.p_params.header_digest;
				break;
			case ISCSI_LOGIN_PARAM_DATA_DIGEST:
				icp->conn_params.data_digest =
				    pp.p_params.data_digest;
				break;
			case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN:
				icp->conn_params.default_time_to_retain =
				    pp.p_params.default_time_to_retain;
				break;
			case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT:
				icp->conn_params.default_time_to_wait =
				    pp.p_params.default_time_to_wait;
				break;
			case ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH:
				icp->conn_params.max_recv_data_seg_len =
				    pp.p_params.max_recv_data_seg_len;
				break;
			case ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH:
				icp->conn_params.first_burst_length =
				    pp.p_params.first_burst_length;
				break;
			case ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH:
				icp->conn_params.max_burst_length =
				    pp.p_params.max_burst_length;
				break;

			/*
			 * Integer parameters which currently are unsettable
			 */
			case ISCSI_LOGIN_PARAM_MAX_CONNECTIONS:
				/* FALLTHRU */
			case ISCSI_LOGIN_PARAM_OUTSTANDING_R2T:
				/* FALLTHRU */
			case ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL:
				/* FALLTHRU */
			default:
				break;
			}
		}
	}

	/* Skip binding checks on discovery sessions */
	if (isp->sess_type == ISCSI_SESS_TYPE_DISCOVERY) {
		return (ISCSI_STATUS_SUCCESS);
	}

	/*
	 * Now we need to get the current optional connection
	 * binding information.
	 */
	/* setup initial buffer for configured session information */
	size = sizeof (*ics);
	ics = kmem_zalloc(size, KM_SLEEP);
	ics->ics_in = 1;

	/* get configured sessions information */
	name = (char *)isp->sess_name;
	if (persistent_get_config_session(name, ics) == B_FALSE) {
		/*
		 * If we were unable to get target level information
		 * then check the initiator level information.
		 */
		name = (char *)isp->sess_hba->hba_name;
		if (persistent_get_config_session(name, ics) == B_FALSE) {
			/*
			 * No hba information is found.  So assume default
			 * one session unbound behavior.
			 */
			ics->ics_out = 1;
			ics->ics_bound = B_FALSE;
		}
	}

	if (iscsiboot_prop && (ics->ics_out > 1) && isp->sess_boot &&
	    !iscsi_chk_bootlun_mpxio(ihp)) {
		/*
		 * iscsi booting session with mpxio disabled,
		 * no need set multiple sessions for booting session
		 */
		ics->ics_out = 1;
		ics->ics_bound = B_FALSE;
		cmn_err(CE_NOTE, "MPxIO is disabled,"
		    " no need to configure multiple boot sessions");
	}

	/*
	 * Check to make sure this session is still a configured
	 * session.  The user might have decreased the session
	 * count. (NOTE: byte 5 of the sess_isid is the session
	 * count (via MS/T).  This counter starts at 0.)
	 */


	idx = isp->sess_isid[5];

	if (iscsiboot_prop && (idx == ISCSI_MAX_CONFIG_SESSIONS)) {
		/*
		 * This is temporary session for boot session propose
		 * no need to bound IP for this session
		 */
		icp->conn_bound = B_FALSE;
		kmem_free(ics, sizeof (iscsi_config_sess_t));
		return (ISCSI_STATUS_SUCCESS);
	}

	if (ics->ics_out <= idx) {
		/*
		 * No longer a configured session.  Return a
		 * failure so we don't attempt to relogin.
		 */
		return (ISCSI_STATUS_SHUTDOWN);
	}

	/*
	 * If sessions are unbound set this information on
	 * the connection and return success.
	 */
	if (ics->ics_bound == B_FALSE) {
		icp->conn_bound = B_FALSE;
		kmem_free(ics, sizeof (iscsi_config_sess_t));
		return (ISCSI_STATUS_SUCCESS);
	}

	/*
	 * Since the sessions are bound we need to find the matching
	 * binding information for the session's isid.  If this
	 * session's isid is > 0 then we need to get more configured
	 * session information to find the binding info.
	 */
	if (idx > 0) {
		int ics_out;

		ics_out = ics->ics_out;
		/* record new size and free last buffer */
		size = ISCSI_SESSION_CONFIG_SIZE(ics_out);
		kmem_free(ics, sizeof (*ics));

		/* allocate new buffer */
		ics = kmem_zalloc(size, KM_SLEEP);
		ics->ics_in = ics_out;

		/* get configured sessions information */
		if (persistent_get_config_session(name, ics) != B_TRUE) {
			cmn_err(CE_NOTE, "iscsi session(%d) - "
			    "unable to get configured session information\n",
			    isp->sess_oid);
			kmem_free(ics, size);
			return (ISCSI_STATUS_SHUTDOWN);
		}
	}

	/* Copy correct binding information to the connection */
	icp->conn_bound = B_TRUE;
	if (ics->ics_bindings[idx].i_insize == sizeof (struct in_addr)) {
		bcopy(&ics->ics_bindings[idx].i_addr.in4,
		    &icp->conn_bound_addr.sin4.sin_addr.s_addr,
		    sizeof (struct in_addr));
	} else {
		bcopy(&ics->ics_bindings[idx].i_addr.in6,
		    &icp->conn_bound_addr.sin6.sin6_addr.s6_addr,
		    sizeof (struct in6_addr));
	}

	kmem_free(ics, size);

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * +--------------------------------------------------------------------+
 * | Internal Connection Interfaces					|
 * +--------------------------------------------------------------------+
 */


/*
 * iscsi_conn_state_free -
 *
 * S1: FREE - State on instantiation, or after successful
 * connection closure.
 */
static iscsi_status_t
iscsi_conn_state_free(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_sess_t		*isp;
	iscsi_hba_t		*ihp;
	iscsi_task_t		*itp;
	iscsi_status_t		status = ISCSI_STATUS_SUCCESS;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_FREE);

	/* switch on event change */
	switch (event) {
	/* -T1: Transport connection request was request */
	case ISCSI_CONN_EVENT_T1:
		icp->conn_state = ISCSI_CONN_STATE_IN_LOGIN;

		/*
		 * Release the connection state mutex cross the
		 * the dispatch of the login task.  The login task
		 * will reacquire the connection state mutex when
		 * it pushes the connection successful or failed.
		 */
		mutex_exit(&icp->conn_state_mutex);

		/* start login */
		itp = kmem_zalloc(sizeof (iscsi_task_t), KM_SLEEP);
		itp->t_arg = icp;
		itp->t_blocking = B_TRUE;

		/*
		 * Sync base connection information before login
		 * A login redirection might have shifted the
		 * current information from the base.
		 */
		bcopy(&icp->conn_base_addr, &icp->conn_curr_addr,
		    sizeof (icp->conn_curr_addr));

		status = iscsi_login_start(itp);
		kmem_free(itp, sizeof (iscsi_task_t));

		mutex_enter(&icp->conn_state_mutex);
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
		status = ISCSI_STATUS_INTERNAL_ERROR;
	}
	return (status);
}

/*
 * iscsi_conn_state_in_login - During this state we are trying to
 * connect the TCP connection and make a successful login to the
 * target.  To complete this we have a task queue item that is
 * trying this processing at this point in time.  When the task
 * queue completed its processing it will issue either a T5/7
 * event.
 */
static void
iscsi_conn_state_in_login(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_sess_t	*isp;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_IN_LOGIN);

	/* switch on event change */
	switch (event) {
	/*
	 * -T5: The final iSCSI Login response with a Status-Class of zero
	 *	was received.
	 */
	case ISCSI_CONN_EVENT_T5:
		iscsi_conn_logged_in(isp, icp);
		break;

	/*
	 * -T30: One of the following event caused the transition:
	 *	- Thefinal iSCSI Login response was received with a non-zero
	 *	  Status-Class.
	 */
	case ISCSI_CONN_EVENT_T30:
		/* FALLTHRU */

	/*
	 * -T7: One of the following events caused the transition:
	 *	- Login timed out.
	 *	- A transport disconnect indication was received.
	 *	- A transport reset was received.
	 *	- An internal event indicating a transport timeout was
	 *	  received.
	 *	- An internal event of receiving a Logout repsonse (success)
	 *	  on another connection for a "close the session" Logout
	 *	  request was received.
	 *	* In all these cases, the transport connection is closed.
	 */
	case ISCSI_CONN_EVENT_T7:
		icp->conn_state = ISCSI_CONN_STATE_FREE;
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_conn_state_logged_in -
 *
 */
static void
iscsi_conn_state_logged_in(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_sess_t		*isp;
	iscsi_hba_t		*ihp;

	ASSERT(icp != NULL);
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ihp = isp->sess_hba;
	ASSERT(ihp != NULL);

	/* switch on event change */
	switch (event) {
	/*
	 * -T8: An internal event of receiving a Logout response (success)
	 *	on another connection for a "close the session" Logout request
	 *	was received, thus closing this connection requiring no further
	 *	cleanup.
	 */
	case ISCSI_CONN_EVENT_T8:
		icp->conn_state = ISCSI_CONN_STATE_FREE;

		/* stop tx thread */
		(void) iscsi_thread_stop(icp->conn_tx_thread);

		/* Disconnect connection */
		iscsi_net->close(icp->conn_socket);

		/* Notify session that a connection logged out */
		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(icp->conn_sess, ISCSI_SESS_EVENT_N3);
		mutex_exit(&isp->sess_state_mutex);
		break;

	/*
	 * -T9: An internal event that indicates the readiness to start the
	 *	Logout process was received, thus prompting an iSCSI Logout
	 *	to be sent by the initiator.
	 */
	case ISCSI_CONN_EVENT_T9:
		/* FALLTHRU */

	/*
	 * -T11: Aync PDU with AsyncEvent "Request Logout" was recevied
	 */
	case ISCSI_CONN_EVENT_T11:
		icp->conn_state = ISCSI_CONN_STATE_IN_LOGOUT;

		(void) iscsi_handle_logout(icp);
		break;

	/*
	 * -T14: One or more of the following events case this transition:
	 *	- Header Digest Error
	 *	- Protocol Error
	 */
	case ISCSI_CONN_EVENT_T14:
		icp->conn_state = ISCSI_CONN_STATE_FAILED;

		/* stop tx thread */
		(void) iscsi_thread_stop(icp->conn_tx_thread);

		/*
		 * Error Recovery Level 0 states we should drop
		 * the connection here.  Then we will fall through
		 * and treat this event like a T15.
		 */
		iscsi_net->close(icp->conn_socket);

		/* FALLTHRU */

	/*
	 * -T15: One or more of the following events caused this transition
	 *	- Internal event that indicates a transport connection timeout
	 *	  was received thus prompting transport RESET or transport
	 *	  connection closure.
	 *	- A transport RESET
	 *	- A transport disconnect indication.
	 *	- Async PDU with AsyncEvent "Drop connection" (for this CID)
	 *	- Async PDU with AsyncEvent "Drop all connections"
	 */
	case ISCSI_CONN_EVENT_T15:
		icp->conn_state = ISCSI_CONN_STATE_FAILED;

		/* stop tx thread, no-op if already done for T14 */
		(void) iscsi_thread_stop(icp->conn_tx_thread);

		iscsi_conn_flush_active_cmds(icp);

		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N5);
		mutex_exit(&isp->sess_state_mutex);

		/*
		 * If session type is NORMAL, create a new login task
		 * to get this connection reestablished.
		 */
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			iscsi_conn_retry(isp, icp);
		} else {
			icp->conn_state = ISCSI_CONN_STATE_FREE;
			mutex_enter(&isp->sess_state_mutex);
			iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N6);
			mutex_exit(&isp->sess_state_mutex);
		}
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_conn_state_in_logout -
 *
 */
static void
iscsi_conn_state_in_logout(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_sess_t	*isp	= NULL;

	ASSERT(icp != NULL);
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_IN_LOGOUT);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {
	/*
	 * -T11: Async PDU with AsyncEvent "Request Logout" was received again
	 */
	case ISCSI_CONN_EVENT_T11:
		icp->conn_state = ISCSI_CONN_STATE_IN_LOGOUT;

		/* Already in LOGOUT ignore the request */
		break;

	/*
	 * -T17: One or more of the following events caused this transition:
	 *	- Logout response, (failure i.e., a non-zero status) was
	 *	received, or logout timed out.
	 *	- Any of the events specified for T15
	 *
	 * -T14: One or more of the following events case this transition:
	 *	- Header Digest Error
	 *	- Protocol Error
	 *
	 * -T15: One or more of the following events caused this transition
	 *	- Internal event that indicates a transport connection timeout
	 *	  was received thus prompting transport RESET or transport
	 *	  connection closure.
	 *	- A transport RESET
	 *	- A transport disconnect indication.
	 *	- Async PDU with AsyncEvent "Drop connection" (for this CID)
	 *	- Async PDU with AsyncEvent "Drop all connections"
	 */
	case ISCSI_CONN_EVENT_T17:
	case ISCSI_CONN_EVENT_T14:
	case ISCSI_CONN_EVENT_T15:
		icp->conn_state = ISCSI_CONN_STATE_FREE;

		/* stop tx thread */
		(void) iscsi_thread_stop(icp->conn_tx_thread);

		/* Disconnect Connection */
		iscsi_net->close(icp->conn_socket);

		iscsi_conn_flush_active_cmds(icp);

		/* Notify session of a failed logout */
		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(icp->conn_sess, ISCSI_SESS_EVENT_N3);
		mutex_exit(&isp->sess_state_mutex);
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}


/*
 * iscsi_conn_state_failed -
 *
 */
static void
iscsi_conn_state_failed(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_sess_t	*isp;

	ASSERT(icp != NULL);
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_FAILED);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {

	/*
	 * -T5: The final iSCSI Login response with a Status-Class of zero
	 *	was received.
	 */
	case ISCSI_CONN_EVENT_T5:
		iscsi_conn_logged_in(isp, icp);
		break;

	/*
	 * -T30: One of the following event caused the transition:
	 *	- Thefinal iSCSI Login response was received with a non-zero
	 *	  Status-Class.
	 */
	case ISCSI_CONN_EVENT_T30:
		icp->conn_state = ISCSI_CONN_STATE_FREE;

		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N6);
		mutex_exit(&isp->sess_state_mutex);

		break;

	/*
	 * -T7: One of the following events caused the transition:
	 *	- Login timed out.
	 *	- A transport disconnect indication was received.
	 *	- A transport reset was received.
	 *	- An internal event indicating a transport timeout was
	 *	  received.
	 *	- An internal event of receiving a Logout repsonse (success)
	 *	  on another connection for a "close the session" Logout
	 *	  request was received.
	 *	* In all these cases, the transport connection is closed.
	 */
	case ISCSI_CONN_EVENT_T7:
		icp->conn_state = ISCSI_CONN_STATE_POLLING;

		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N6);
		mutex_exit(&isp->sess_state_mutex);

		iscsi_conn_retry(isp, icp);
		break;

	/* There are no valid transition out of this state. */
	default:
		ASSERT(FALSE);
	}
}

/*
 * iscsi_conn_state_polling -
 *
 * S6: POLLING - State on instantiation, or after successful
 * connection closure.
 */
static void
iscsi_conn_state_polling(iscsi_conn_t *icp, iscsi_conn_event_t event)
{
	iscsi_sess_t *isp = NULL;

	ASSERT(icp != NULL);
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_POLLING);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/* switch on event change */
	switch (event) {
	/*
	 * -T5: The final iSCSI Login response with a Status-Class of zero
	 *	was received.
	 */
	case ISCSI_CONN_EVENT_T5:
		iscsi_conn_logged_in(isp, icp);
		break;

	/*
	 * -T30: One of the following event caused the transition:
	 *	- Thefinal iSCSI Login response was received with a non-zero
	 *	  Status-Class.
	 */
	case ISCSI_CONN_EVENT_T30:
		icp->conn_state = ISCSI_CONN_STATE_FREE;

		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N6);
		mutex_exit(&isp->sess_state_mutex);

		break;

	/*
	 * -T7: One of the following events caused the transition:
	 *	- Login timed out.
	 *	- A transport disconnect indication was received.
	 *	- A transport reset was received.
	 *	- An internal event indicating a transport timeout was
	 *	  received.
	 *	- An internal event of receiving a Logout repsonse (success)
	 *	  on another connection for a "close the session" Logout
	 *	  request was received.
	 *	* In all these cases, the transport connection is closed.
	 */
	case ISCSI_CONN_EVENT_T7:
		/*
		 * If session type is NORMAL, create a new login task
		 * to get this connection reestablished.
		 */
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			iscsi_conn_retry(isp, icp);
		} else {
			icp->conn_state = ISCSI_CONN_STATE_FREE;
		}
		break;

	/* All other events are invalid for this state */
	default:
		ASSERT(FALSE);
	}
}

/*
 * iscsi_conn_event_str - converts event enum to a string
 */
static char *
iscsi_conn_event_str(iscsi_conn_event_t event)
{
	switch (event) {
	case ISCSI_CONN_EVENT_T1:
		return ("T1");
	case ISCSI_CONN_EVENT_T5:
		return ("T5");
	case ISCSI_CONN_EVENT_T7:
		return ("T7");
	case ISCSI_CONN_EVENT_T8:
		return ("T8");
	case ISCSI_CONN_EVENT_T9:
		return ("T9");
	case ISCSI_CONN_EVENT_T11:
		return ("T11");
	case ISCSI_CONN_EVENT_T14:
		return ("T14");
	case ISCSI_CONN_EVENT_T15:
		return ("T15");
	case ISCSI_CONN_EVENT_T17:
		return ("T17");
	case ISCSI_CONN_EVENT_T30:
		return ("T30");

	default:
		return ("unknown");
	}
}

/*
 * iscsi_conn_flush_active_cmds - flush all active icmdps
 *	for a connection.
 */
static void
iscsi_conn_flush_active_cmds(iscsi_conn_t *icp)
{
	iscsi_cmd_t	*icmdp;
	iscsi_sess_t	*isp;
	boolean_t	lock_held = B_FALSE;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	if (mutex_owned(&icp->conn_queue_active.mutex)) {
		lock_held = B_TRUE;
	} else {
		mutex_enter(&icp->conn_queue_active.mutex);
	}

	/* Flush active queue */
	icmdp = icp->conn_queue_active.head;
	while (icmdp != NULL) {
		iscsi_cmd_state_machine(icmdp,
		    ISCSI_CMD_EVENT_E7, isp);
		icmdp = icp->conn_queue_active.head;
	}

	if (lock_held == B_FALSE) {
		mutex_exit(&icp->conn_queue_active.mutex);
	}
}


/*
 * iscsi_conn_logged_in - connection has successfully logged in
 */
static void
iscsi_conn_logged_in(iscsi_sess_t *isp, iscsi_conn_t *icp)
{
	ASSERT(isp != NULL);
	ASSERT(icp != NULL);

	icp->conn_state = ISCSI_CONN_STATE_LOGGED_IN;
	/*
	 * We need to drop the connection state lock
	 * before updating the session state.  On update
	 * of the session state it will enumerate the
	 * target.  If we hold the lock during enumeration
	 * will block the watchdog thread from timing
	 * a scsi_pkt, if required.  This will lead to
	 * a possible hang condition.
	 *
	 * Also the lock is no longer needed once the
	 * connection state was updated.
	 */
	mutex_exit(&icp->conn_state_mutex);

	/* startup threads */
	(void) iscsi_thread_start(icp->conn_rx_thread);
	(void) iscsi_thread_start(icp->conn_tx_thread);

	/* Notify the session that a connection is logged in */
	mutex_enter(&isp->sess_state_mutex);
	iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N1);
	mutex_exit(&isp->sess_state_mutex);

	mutex_enter(&icp->conn_state_mutex);
}

/*
 * iscsi_conn_retry - retry connect/login
 */
static void
iscsi_conn_retry(iscsi_sess_t *isp, iscsi_conn_t *icp)
{
	iscsi_task_t *itp;

	ASSERT(isp != NULL);
	ASSERT(icp != NULL);

	/* set login min/max time values */
	iscsi_conn_set_login_min_max(icp,
	    ISCSI_CONN_DEFAULT_LOGIN_MIN,
	    ISCSI_CONN_DEFAULT_LOGIN_MAX);

	/*
	 * Sync base connection information before login.
	 * A login redirection might have shifted the
	 * current information from the base.
	 */
	bcopy(&icp->conn_base_addr, &icp->conn_curr_addr,
	    sizeof (icp->conn_curr_addr));

	/* schedule login task */
	itp = kmem_zalloc(sizeof (iscsi_task_t), KM_SLEEP);
	itp->t_arg = icp;
	itp->t_blocking = B_FALSE;
	if (ddi_taskq_dispatch(isp->sess_taskq,
	    (void(*)())iscsi_login_start, itp, DDI_SLEEP) !=
	    DDI_SUCCESS) {
		kmem_free(itp, sizeof (iscsi_task_t));
		cmn_err(CE_WARN,
		    "iscsi connection(%u) failure - "
		    "unable to schedule login task",
		    icp->conn_oid);

		icp->conn_state = ISCSI_CONN_STATE_FREE;
		mutex_enter(&isp->sess_state_mutex);
		iscsi_sess_state_machine(isp,
		    ISCSI_SESS_EVENT_N6);
		mutex_exit(&isp->sess_state_mutex);
	}
}
