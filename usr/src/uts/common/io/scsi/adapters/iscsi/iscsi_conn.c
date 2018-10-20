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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * iSCSI connection interfaces
 */

#define	ISCSI_ICS_NAMES
#include "iscsi.h"
#include "persistent.h"
#include <sys/bootprops.h>

extern ib_boot_prop_t   *iscsiboot_prop;

static void iscsi_client_notify_task(void *cn_task_void);

static void iscsi_conn_flush_active_cmds(iscsi_conn_t *icp);

#define	SHUTDOWN_TIMEOUT	180 /* seconds */

extern int modrootloaded;

boolean_t iscsi_conn_logging = B_FALSE;

#define	ISCSI_LOGIN_TPGT_NEGO_ERROR(icp) \
	(((icp)->conn_login_state == LOGIN_ERROR) && \
	((icp)->conn_login_status == ISCSI_STATUS_LOGIN_TPGT_NEGO_FAIL))

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
	mutex_init(&icp->conn_login_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&icp->conn_login_cv, NULL, CV_DRIVER, NULL);
	icp->conn_state_destroy		= B_FALSE;
	idm_sm_audit_init(&icp->conn_state_audit);
	icp->conn_sess			= isp;

	mutex_enter(&iscsi_oid_mutex);
	icp->conn_oid = iscsi_oid++;
	mutex_exit(&iscsi_oid_mutex);

	/*
	 * IDM CN taskq
	 */

	if (snprintf(th_name, sizeof (th_name) - 1,
	    ISCSI_CONN_CN_TASKQ_NAME_FORMAT,
	    icp->conn_sess->sess_hba->hba_oid, icp->conn_sess->sess_oid,
	    icp->conn_oid) >= sizeof (th_name)) {
		cv_destroy(&icp->conn_state_change);
		mutex_destroy(&icp->conn_state_mutex);
		kmem_free(icp, sizeof (iscsi_conn_t));
		*icpp = NULL;
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	icp->conn_cn_taskq =
	    ddi_taskq_create(icp->conn_sess->sess_hba->hba_dip, th_name, 1,
	    TASKQ_DEFAULTPRI, 0);
	if (icp->conn_cn_taskq == NULL) {
		cv_destroy(&icp->conn_state_change);
		mutex_destroy(&icp->conn_state_mutex);
		kmem_free(icp, sizeof (iscsi_conn_t));
		*icpp = NULL;
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* Creation of the transfer thread */
	if (snprintf(th_name, sizeof (th_name) - 1, ISCSI_CONN_TXTH_NAME_FORMAT,
	    icp->conn_sess->sess_hba->hba_oid, icp->conn_sess->sess_oid,
	    icp->conn_oid) >= sizeof (th_name)) {
		cv_destroy(&icp->conn_state_change);
		mutex_destroy(&icp->conn_state_mutex);
		kmem_free(icp, sizeof (iscsi_conn_t));
		ddi_taskq_destroy(icp->conn_cn_taskq);
		*icpp = NULL;
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	icp->conn_tx_thread = iscsi_thread_create(isp->sess_hba->hba_dip,
	    th_name, iscsi_tx_thread, icp);

	/* setup connection queues */
	iscsi_init_queue(&icp->conn_queue_active);
	iscsi_init_queue(&icp->conn_queue_idm_aborting);

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
 * iscsi_conn_online - This attempts to take a connection from
 * ISCSI_CONN_STATE_FREE to ISCSI_CONN_STATE_LOGGED_IN.
 */
iscsi_status_t
iscsi_conn_online(iscsi_conn_t *icp)
{
	iscsi_task_t	*itp;
	iscsi_status_t	rval;

	ASSERT(icp != NULL);
	ASSERT(mutex_owned(&icp->conn_state_mutex));
	ASSERT(icp->conn_state == ISCSI_CONN_STATE_FREE);

	/*
	 * If we are attempting to connect then for the purposes of the
	 * other initiator code we are effectively in ISCSI_CONN_STATE_IN_LOGIN.
	 */
	iscsi_conn_update_state_locked(icp, ISCSI_CONN_STATE_IN_LOGIN);
	mutex_exit(&icp->conn_state_mutex);

	/*
	 * Sync base connection information before login
	 * A login redirection might have shifted the
	 * current information from the base.
	 */
	bcopy(&icp->conn_base_addr, &icp->conn_curr_addr,
	    sizeof (icp->conn_curr_addr));

	itp = kmem_zalloc(sizeof (iscsi_task_t), KM_SLEEP);
	ASSERT(itp != NULL);

	itp->t_arg = icp;
	itp->t_blocking = B_TRUE;
	rval = iscsi_login_start(itp);
	kmem_free(itp, sizeof (iscsi_task_t));

	mutex_enter(&icp->conn_state_mutex);

	return (rval);
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
	 *
	 * ISCSI_CONN_STATE_LOGGED_IN is set immediately at the
	 * start of CN_NOTIFY_FFP processing. icp->conn_state_ffp
	 * is set to true at the end of ffp processing, at which
	 * point any session updates are complete.  We don't
	 * want to start offlining the connection before we're
	 * done completing the FFP processing since this might
	 * interrupt the discovery process.
	 */
	delay = ddi_get_lbolt() + SEC_TO_TICK(SHUTDOWN_TIMEOUT);
	mutex_enter(&icp->conn_state_mutex);
	icp->conn_state_destroy = B_TRUE;
	while ((((icp->conn_state != ISCSI_CONN_STATE_FREE) &&
	    (icp->conn_state != ISCSI_CONN_STATE_LOGGED_IN)) ||
	    ((icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN) &&
	    !icp->conn_state_ffp)) &&
	    (ddi_get_lbolt() < delay)) {
		/* wait for transition */
		(void) cv_timedwait(&icp->conn_state_change,
		    &icp->conn_state_mutex, delay);
	}

	switch (icp->conn_state) {
	case ISCSI_CONN_STATE_FREE:
		break;
	case ISCSI_CONN_STATE_LOGGED_IN:
		if (icp->conn_state_ffp) {
			/* Hold is released in iscsi_handle_logout */
			idm_conn_hold(icp->conn_ic);
			(void) iscsi_handle_logout(icp);
		} else {
			icp->conn_state_destroy = B_FALSE;
			mutex_exit(&icp->conn_state_mutex);
			return (ISCSI_STATUS_INTERNAL_ERROR);
		}
		break;
	case ISCSI_CONN_STATE_IN_LOGIN:
	case ISCSI_CONN_STATE_IN_LOGOUT:
	case ISCSI_CONN_STATE_FAILED:
	case ISCSI_CONN_STATE_POLLING:
	default:
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

	/* Destroy transfer thread */
	iscsi_thread_destroy(icp->conn_tx_thread);
	ddi_taskq_destroy(icp->conn_cn_taskq);

	/* Terminate connection queues */
	iscsi_destroy_queue(&icp->conn_queue_idm_aborting);
	iscsi_destroy_queue(&icp->conn_queue_active);

	cv_destroy(&icp->conn_login_cv);
	mutex_destroy(&icp->conn_login_mutex);
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
 * Process the idm notifications
 */
idm_status_t
iscsi_client_notify(idm_conn_t *ic, idm_client_notify_t icn, uintptr_t data)
{
	iscsi_cn_task_t		*cn;
	iscsi_conn_t		*icp = ic->ic_handle;
	iscsi_sess_t		*isp;
	uint32_t		event_count;

	/*
	 * Don't access icp if the notification is CN_CONNECT_DESTROY
	 * since icp may have already been freed.
	 *
	 * In particular, we cannot audit the CN_CONNECT_DESTROY event.
	 *
	 * Handle a few cases immediately, the rest in a task queue.
	 */
	switch (icn) {
	case CN_CONNECT_FAIL:
	case CN_LOGIN_FAIL:
		/*
		 * Wakeup any thread waiting for login stuff to happen.
		 */
		ASSERT(icp != NULL);

		mutex_enter(&icp->conn_state_mutex);
		idm_sm_audit_event(&icp->conn_state_audit,
		    SAS_ISCSI_CONN, icp->conn_state, icn, data);
		mutex_exit(&icp->conn_state_mutex);
		iscsi_login_update_state(icp, LOGIN_ERROR);
		return (IDM_STATUS_SUCCESS);

	case CN_READY_FOR_LOGIN:
		idm_conn_hold(ic); /* Released in CN_CONNECT_LOST */
		ASSERT(icp != NULL);

		mutex_enter(&icp->conn_state_mutex);
		idm_sm_audit_event(&icp->conn_state_audit,
		    SAS_ISCSI_CONN, icp->conn_state, icn, data);
		icp->conn_state_idm_connected = B_TRUE;
		cv_broadcast(&icp->conn_state_change);
		mutex_exit(&icp->conn_state_mutex);

		iscsi_login_update_state(icp, LOGIN_READY);
		return (IDM_STATUS_SUCCESS);

	case CN_CONNECT_DESTROY:
		/*
		 * We released any dependecies we had on this object in
		 * either CN_LOGIN_FAIL or CN_CONNECT_LOST so we just need
		 * to destroy the IDM connection now.
		 */
		idm_ini_conn_destroy(ic);
		return (IDM_STATUS_SUCCESS);
	}

	ASSERT(icp != NULL);
	mutex_enter(&icp->conn_state_mutex);
	idm_sm_audit_event(&icp->conn_state_audit,
	    SAS_ISCSI_CONN, icp->conn_state, icn, data);
	mutex_exit(&icp->conn_state_mutex);
	isp = icp->conn_sess;

	/*
	 * Dispatch notifications to the taskq since they often require
	 * long blocking operations.  In the case of CN_CONNECT_DESTROY
	 * we actually just want to destroy the connection which we
	 * can't do in the IDM taskq context.
	 */
	cn = kmem_alloc(sizeof (*cn), KM_SLEEP);

	cn->ct_ic = ic;
	cn->ct_icn = icn;
	cn->ct_data = data;

	idm_conn_hold(ic);

	if (ddi_taskq_dispatch(icp->conn_cn_taskq,
	    iscsi_client_notify_task, cn, DDI_SLEEP) != DDI_SUCCESS) {
		idm_conn_rele(ic);
		cmn_err(CE_WARN, "iscsi connection(%u) failure - "
		    "unable to schedule notify task", icp->conn_oid);
		iscsi_conn_update_state(icp, ISCSI_CONN_STATE_FREE);
		event_count = atomic_inc_32_nv(&isp->sess_state_event_count);
		iscsi_sess_enter_state_zone(isp);

		iscsi_sess_state_machine(isp,
		    ISCSI_SESS_EVENT_N6, event_count);

		iscsi_sess_exit_state_zone(isp);
	}

	return (IDM_STATUS_SUCCESS);
}

static void
iscsi_client_notify_task(void *cn_task_void)
{
	iscsi_cn_task_t		*cn_task = cn_task_void;
	iscsi_conn_t		*icp;
	iscsi_sess_t		*isp;
	idm_conn_t		*ic;
	idm_client_notify_t	icn;
	uintptr_t		data;
	idm_ffp_disable_t	disable_type;
	boolean_t		in_login;
	uint32_t		event_count;

	ic = cn_task->ct_ic;
	icn = cn_task->ct_icn;
	data = cn_task->ct_data;

	icp = ic->ic_handle;
	ASSERT(icp != NULL);
	isp = icp->conn_sess;

	switch (icn) {
	case CN_FFP_ENABLED:
		mutex_enter(&icp->conn_state_mutex);
		icp->conn_async_logout = B_FALSE;
		icp->conn_state_ffp = B_TRUE;
		cv_broadcast(&icp->conn_state_change);
		mutex_exit(&icp->conn_state_mutex);

		/*
		 * This logic assumes that the IDM login-snooping code
		 * and the initiator login code will agree to go when
		 * the connection is in FFP or final error received.
		 * The reason we do this is that we don't want to process
		 * CN_FFP_DISABLED until CN_FFP_ENABLED has been full handled.
		 */
		mutex_enter(&icp->conn_login_mutex);
		while ((icp->conn_login_state != LOGIN_FFP) &&
		    (icp->conn_login_state != LOGIN_ERROR)) {
			cv_wait(&icp->conn_login_cv, &icp->conn_login_mutex);
		}
		mutex_exit(&icp->conn_login_mutex);
		break;
	case CN_FFP_DISABLED:
		disable_type = (idm_ffp_disable_t)data;

		mutex_enter(&icp->conn_state_mutex);
		switch (disable_type) {
		case FD_SESS_LOGOUT:
		case FD_CONN_LOGOUT:
			if (icp->conn_async_logout) {
				/*
				 * Our logout was in response to an
				 * async logout request so treat this
				 * like a connection failure (we will
				 * try to re-establish the connection)
				 */
				iscsi_conn_update_state_locked(icp,
				    ISCSI_CONN_STATE_FAILED);
			} else {
				/*
				 * Logout due to to user config change,
				 * we will not try to re-establish
				 * the connection.
				 */
				iscsi_conn_update_state_locked(icp,
				    ISCSI_CONN_STATE_IN_LOGOUT);
				/*
				 * Hold off generating the ISCSI_SESS_EVENT_N3
				 * event until we get the CN_CONNECT_LOST
				 * notification.  This matches the pre-IDM
				 * implementation better.
				 */
			}
			break;

		case FD_CONN_FAIL:
		default:
			if (icp->conn_state == ISCSI_CONN_STATE_IN_LOGIN) {
				iscsi_conn_update_state_locked(icp,
				    ISCSI_CONN_STATE_FREE);
			} else {
				iscsi_conn_update_state_locked(icp,
				    ISCSI_CONN_STATE_FAILED);
			}
			break;
		}

		icp->conn_state_ffp = B_FALSE;
		cv_broadcast(&icp->conn_state_change);
		mutex_exit(&icp->conn_state_mutex);

		break;
	case CN_CONNECT_LOST:
		/*
		 * We only care about CN_CONNECT_LOST if we've logged in.  IDM
		 * sends a flag as the data payload to indicate whether we
		 * were trying to login.  The CN_LOGIN_FAIL notification
		 * gives us what we need to know for login failures and
		 * otherwise we will need to keep a bunch of state to know
		 * what CN_CONNECT_LOST means to us.
		 */
		in_login = (boolean_t)data;
		if (in_login ||
		    (icp->conn_prev_state == ISCSI_CONN_STATE_IN_LOGIN)) {
			mutex_enter(&icp->conn_state_mutex);

			icp->conn_state_idm_connected = B_FALSE;
			cv_broadcast(&icp->conn_state_change);
			mutex_exit(&icp->conn_state_mutex);

			/* Release connect hold from CN_READY_FOR_LOGIN */
			idm_conn_rele(ic);
			break;
		}

		/* Any remaining commands are never going to finish */
		iscsi_conn_flush_active_cmds(icp);

		/*
		 * The connection is no longer active so cleanup any
		 * references to the connection and release any holds so
		 * that IDM can finish cleanup.
		 */
		mutex_enter(&icp->conn_state_mutex);
		if (icp->conn_state != ISCSI_CONN_STATE_FAILED) {
			mutex_exit(&icp->conn_state_mutex);
			event_count = atomic_inc_32_nv(
			    &isp->sess_state_event_count);
			iscsi_sess_enter_state_zone(isp);

			iscsi_sess_state_machine(isp, ISCSI_SESS_EVENT_N3,
			    event_count);

			iscsi_sess_exit_state_zone(isp);

			mutex_enter(&icp->conn_state_mutex);
			iscsi_conn_update_state_locked(icp,
			    ISCSI_CONN_STATE_FREE);
		} else {
			mutex_exit(&icp->conn_state_mutex);
			event_count = atomic_inc_32_nv(
			    &isp->sess_state_event_count);
			iscsi_sess_enter_state_zone(isp);

			iscsi_sess_state_machine(isp,
			    ISCSI_SESS_EVENT_N5, event_count);

			iscsi_sess_exit_state_zone(isp);

			/*
			 * If session type is NORMAL, try to reestablish the
			 * connection.
			 */
			if ((isp->sess_type == ISCSI_SESS_TYPE_NORMAL) &&
			    !(ISCSI_LOGIN_TPGT_NEGO_ERROR(icp))) {
				iscsi_conn_retry(isp, icp);
				mutex_enter(&icp->conn_state_mutex);
			} else {
				event_count = atomic_inc_32_nv(
				    &isp->sess_state_event_count);
				iscsi_sess_enter_state_zone(isp);

				iscsi_sess_state_machine(isp,
				    ISCSI_SESS_EVENT_N6, event_count);

				iscsi_sess_exit_state_zone(isp);

				mutex_enter(&icp->conn_state_mutex);
				iscsi_conn_update_state_locked(icp,
				    ISCSI_CONN_STATE_FREE);
			}
		}

		(void) iscsi_thread_stop(icp->conn_tx_thread);

		icp->conn_state_idm_connected = B_FALSE;
		cv_broadcast(&icp->conn_state_change);
		mutex_exit(&icp->conn_state_mutex);

		/* Release connect hold from CN_READY_FOR_LOGIN */
		idm_conn_rele(ic);
		break;
	default:
		ISCSI_CONN_LOG(CE_WARN,
		    "iscsi_client_notify: unknown notification: "
		    "%x: NOT IMPLEMENTED YET: icp: %p ic: %p ",
		    icn, (void *)icp, (void *)ic);
		break;
	}
	/* free the task notify structure we allocated in iscsi_client_notify */
	kmem_free(cn_task, sizeof (*cn_task));

	/* Release the hold we acquired in iscsi_client_notify */
	idm_conn_rele(ic);
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
	persistent_tunable_param_t	ptp;
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
	bcopy(&ihp->hba_tunable_params, &icp->conn_tunable_params,
	    sizeof (iscsi_tunable_params_t));

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

	if (persistent_get_tunable_param((char *)isp->sess_name, &ptp) ==
	    B_TRUE) {
		if (ptp.p_bitmap & ISCSI_TUNABLE_PARAM_RX_TIMEOUT_VALUE) {
			icp->conn_tunable_params.recv_login_rsp_timeout =
			    ptp.p_params.recv_login_rsp_timeout;
		}
		if (ptp.p_bitmap & ISCSI_TUNABLE_PARAM_CONN_LOGIN_MAX) {
			icp->conn_tunable_params.conn_login_max =
			    ptp.p_params.conn_login_max;
		}
		if (ptp.p_bitmap & ISCSI_TUNABLE_PARAM_LOGIN_POLLING_DELAY) {
			icp->conn_tunable_params.polling_login_delay =
			    ptp.p_params.polling_login_delay;
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
		icp->conn_bound_addr.sin4.sin_family = AF_INET;
	} else {
		bcopy(&ics->ics_bindings[idx].i_addr.in6,
		    &icp->conn_bound_addr.sin6.sin6_addr.s6_addr,
		    sizeof (struct in6_addr));
		icp->conn_bound_addr.sin6.sin6_family = AF_INET6;
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

		mutex_enter(&icmdp->cmd_mutex);
		if (icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
			icmdp->cmd_un.scsi.pkt_stat |= STAT_ABORTED;
		}
		mutex_exit(&icmdp->cmd_mutex);

		iscsi_cmd_state_machine(icmdp,
		    ISCSI_CMD_EVENT_E7, isp);
		icmdp = icp->conn_queue_active.head;
	}

	/* Wait for active queue to drain */
	while (icp->conn_queue_active.count) {
		mutex_exit(&icp->conn_queue_active.mutex);
		delay(drv_usectohz(100000));
		mutex_enter(&icp->conn_queue_active.mutex);
	}

	if (lock_held == B_FALSE) {
		mutex_exit(&icp->conn_queue_active.mutex);
	}

	/* Wait for IDM abort queue to drain (if necessary) */
	mutex_enter(&icp->conn_queue_idm_aborting.mutex);
	while (icp->conn_queue_idm_aborting.count) {
		mutex_exit(&icp->conn_queue_idm_aborting.mutex);
		delay(drv_usectohz(100000));
		mutex_enter(&icp->conn_queue_idm_aborting.mutex);
	}
	mutex_exit(&icp->conn_queue_idm_aborting.mutex);
}

/*
 * iscsi_conn_retry - retry connect/login
 */
void
iscsi_conn_retry(iscsi_sess_t *isp, iscsi_conn_t *icp)
{
	iscsi_task_t *itp;
	uint32_t event_count;

	ASSERT(isp != NULL);
	ASSERT(icp != NULL);

	/* set login min/max time values */
	iscsi_conn_set_login_min_max(icp,
	    ISCSI_CONN_DEFAULT_LOGIN_MIN,
	    icp->conn_tunable_params.conn_login_max);

	ISCSI_CONN_LOG(CE_NOTE, "DEBUG: iscsi_conn_retry: icp: %p icp: %p ",
	    (void *)icp,
	    (void *)icp->conn_ic);

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
	if (ddi_taskq_dispatch(isp->sess_login_taskq,
	    iscsi_login_cb, itp, DDI_SLEEP) !=
	    DDI_SUCCESS) {
		kmem_free(itp, sizeof (iscsi_task_t));
		cmn_err(CE_WARN, "iscsi connection(%u) failure - "
		    "unable to schedule login task", icp->conn_oid);

		iscsi_conn_update_state(icp, ISCSI_CONN_STATE_FREE);
		event_count = atomic_inc_32_nv(
		    &isp->sess_state_event_count);
		iscsi_sess_enter_state_zone(isp);

		iscsi_sess_state_machine(isp,
		    ISCSI_SESS_EVENT_N6, event_count);

		iscsi_sess_exit_state_zone(isp);
	}
}

void
iscsi_conn_update_state(iscsi_conn_t *icp, iscsi_conn_state_t next_state)
{
	mutex_enter(&icp->conn_state_mutex);
	(void) iscsi_conn_update_state_locked(icp, next_state);
	mutex_exit(&icp->conn_state_mutex);
}

void
iscsi_conn_update_state_locked(iscsi_conn_t *icp, iscsi_conn_state_t next_state)
{
	ASSERT(mutex_owned(&icp->conn_state_mutex));
	next_state = (next_state > ISCSI_CONN_STATE_MAX) ?
	    ISCSI_CONN_STATE_MAX : next_state;
	idm_sm_audit_state_change(&icp->conn_state_audit,
	    SAS_ISCSI_CONN, icp->conn_state, next_state);
	switch (next_state) {
	case ISCSI_CONN_STATE_FREE:
	case ISCSI_CONN_STATE_IN_LOGIN:
	case ISCSI_CONN_STATE_LOGGED_IN:
	case ISCSI_CONN_STATE_IN_LOGOUT:
	case ISCSI_CONN_STATE_FAILED:
	case ISCSI_CONN_STATE_POLLING:
		ISCSI_CONN_LOG(CE_NOTE,
		    "iscsi_conn_update_state conn %p %s(%d) -> %s(%d)",
		    (void *)icp,
		    iscsi_ics_name[icp->conn_state], icp->conn_state,
		    iscsi_ics_name[next_state], next_state);
		icp->conn_prev_state = icp->conn_state;
		icp->conn_state = next_state;
		cv_broadcast(&icp->conn_state_change);
		break;
	default:
		cmn_err(CE_WARN, "Update state found illegal state: %x "
		    "prev_state: %x", next_state, icp->conn_prev_state);
		ASSERT(0);
	}
}
