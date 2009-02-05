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
 */

#include <sys/ib/mgt/ibmf/ibmf_saa_impl.h>
#include <sys/ib/mgt/ibmf/ibmf_saa_utils.h>

/* Global sa_access State Pointer */
saa_state_t *saa_statep;
_NOTE(READ_ONLY_DATA(saa_statep))

extern	int	ibmf_trace_level;

extern	int	ibmf_taskq_max_tasks;

static int
ibmf_saa_impl_new_smlid_retry(saa_port_t *saa_portp, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ibmf_callback, void *ibmf_callback_arg, int transport_flags);
static int
ibmf_saa_impl_revert_to_qp1(saa_port_t *saa_portp, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ibmf_callback, void *ibmf_callback_args, int transport_flags);
static int
ibmf_saa_check_sa_and_retry(saa_port_t *saa_portp, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ibmf_callback, void *ibmf_callback_arg,
    hrtime_t trans_send_time, int transport_flags);
static int ibmf_saa_impl_init_msg(saa_impl_trans_info_t *trans_info,
    boolean_t sleep_flag, ibmf_msg_t **msgp, uint32_t *transport_flagsp,
    ibmf_retrans_t *ibmf_retransp);
static int ibmf_saa_must_purge(saa_port_t *saa_portp);
static void ibmf_saa_impl_invalidate_port(saa_port_t *saa_portp);
static void ibmf_saa_impl_destroy_port(saa_port_t *saa_portp);
static void ibmf_saa_impl_uninit_kstats(saa_port_t *saa_portp);
static void ibmf_saa_impl_get_cpi_cb(void *arg, size_t length, char *buffer,
    int status);
static void ibmf_saa_impl_async_event_cb(ibmf_handle_t ibmf_handle,
    void *clnt_private, ibmf_async_event_t event_type);
static void ibmf_saa_impl_port_up(ib_guid_t ci_guid, uint8_t port_num);
static void ibmf_saa_impl_port_down(ib_guid_t ci_guid, uint8_t port_num);
static void ibmf_saa_impl_hca_detach(saa_port_t *saa_removed);
static void ibmf_saa_impl_prepare_response(ibmf_handle_t ibmf_handle,
    ibmf_msg_t *msgp, boolean_t ignore_data, int *status, void **result,
    size_t *length, boolean_t sleep_flag);
static int ibmf_saa_impl_check_sa_support(uint16_t cap_mask, uint16_t attr_id);
static uint_t ibmf_saa_impl_get_attr_id_length(uint16_t attr_id);
static void ibmf_saa_impl_free_msg(ibmf_handle_t ibmf_hdl, ibmf_msg_t *msgp);
static int ibmf_saa_impl_get_port_guid(ibt_hca_portinfo_t *ibt_portinfop,
    ib_guid_t *guid_ret);
static void ibmf_saa_impl_set_transaction_params(saa_port_t *saa_portp,
    ibt_hca_portinfo_t *portinfop);
static void ibmf_saa_impl_update_sa_address_info(saa_port_t *saa_portp,
    ibmf_msg_t *msgp);
static int ibmf_saa_impl_ibmf_unreg(saa_port_t *saa_portp);

int	ibmf_saa_max_wait_time = IBMF_SAA_MAX_WAIT_TIME_IN_SECS;
int	ibmf_saa_trans_wait_time = IBMF_SAA_TRANS_WAIT_TIME_IN_SECS;

/*
 * ibmf_saa_impl_init:
 * Allocates memory for the ibmf_saa state structure and initializes the taskq.
 * Called from the modules init() routine.
 *
 * Input Arguments
 * none
 *
 * Output Arguments
 * none
 *
 * Returns
 * IBMF_NO_RESOURCES if taskq could not be created.
 * IBMF_SUCCESS on success
 *
 */
int
ibmf_saa_impl_init()
{
	int		res;

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_init_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init() enter\n");

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*saa_statep))

	saa_statep = kmem_zalloc(sizeof (saa_state_t), KM_SLEEP);

	/* create taskq for notifying event subscribers */
	saa_statep->saa_event_taskq = taskq_create(
	    "ibmf_saa_event_taskq", IBMF_TASKQ_NTHREADS,
	    MINCLSYSPRI, 1, ibmf_taskq_max_tasks, TASKQ_DYNAMIC |
	    TASKQ_PREPOPULATE);
	if (saa_statep->saa_event_taskq == NULL) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L4,
		    ibmf_saa_impl_init_end_err,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init(): %s\n",
		    tnf_string, msg, "event taskq create failed");

		kmem_free(saa_statep, sizeof (saa_state_t));

		res = IBMF_NO_RESOURCES;

		goto bail;
	}

	mutex_init(&saa_statep->saa_port_list_mutex, NULL, MUTEX_DRIVER,
	    NULL);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*saa_statep))

	res = IBMF_SUCCESS;
bail:

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_saa_impl_init_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init() exit: status = %d\n",
	    tnf_int, res, res);

	return (res);
}

/*
 * ibmf_saa_impl_fini:
 * If there are no registered clients, cleans up all memory associated with the
 * state, including each of the port list entries.
 * Called from the modules fini() routine.
 *
 * Input Arguments
 * none
 *
 * Output Arguments
 * none
 *
 * Returns
 * EBUSY if there are outstanding transactions or registered clients
 * 0 if cleanup was sucessfull
 *
 */
int
ibmf_saa_impl_fini()
{
	int		ret = 0;
	saa_port_t	*saa_portp;
	saa_port_t	*next;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_fini_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_fini() enter\n");

	/* make sure there are no registered clients */
	mutex_enter(&saa_statep->saa_port_list_mutex);

	saa_portp = saa_statep->saa_port_list;
	while (saa_portp != NULL) {

		mutex_enter(&saa_portp->saa_pt_mutex);

		if (saa_portp->saa_pt_reference_count > 0) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_fini_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_fini: %s, port %016" PRIx64 "\n",
			    tnf_string, msg,
			    "cannot unload ibmf_saa. Client on port still"
			    " registered", tnf_opaque, port,
			    saa_portp->saa_pt_port_guid);

			mutex_exit(&saa_portp->saa_pt_mutex);

			mutex_exit(&saa_statep->saa_port_list_mutex);

			ret = EBUSY;
			goto bail;
		}

		/* make sure there are no outstanding transactions */

		if (saa_portp->saa_pt_num_outstanding_trans > 0) {

			IBMF_TRACE_3(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_fini_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_fini: %s, port = %016" PRIx64
			    ", num transactions = %d\n",
			    tnf_string, msg, "Cannot unload ibmf_saa."
			    "  Outstanding transactions on port.",
			    tnf_opaque, port,
			    saa_portp->saa_pt_port_guid,
			    tnf_uint, outstanding_transactions,
			    saa_portp->saa_pt_num_outstanding_trans);

			mutex_exit(&saa_portp->saa_pt_mutex);

			mutex_exit(&saa_statep->saa_port_list_mutex);

			ret = EBUSY;
			goto bail;
		}

		mutex_exit(&saa_portp->saa_pt_mutex);

		saa_portp = saa_portp->next;
	}

	mutex_exit(&saa_statep->saa_port_list_mutex);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(saa_statep->saa_port_list,
	    *saa_portp))

	/*
	 * no more clients nor pending transaction:
	 * unregister ibmf and destroy port entries
	 */
	while (saa_statep->saa_port_list != NULL) {

		saa_portp = saa_statep->saa_port_list;
		next = saa_portp->next;

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_fini, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_fini: %s, prefix = %016" PRIx64 "\n",
		    tnf_string, msg, "deinitializing port",
		    tnf_opaque, port_guid, saa_portp->saa_pt_port_guid);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*saa_portp))

		mutex_enter(&saa_portp->saa_pt_mutex);

		/* unregister from ibmf */
		if (saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_READY) {

			mutex_exit(&saa_portp->saa_pt_mutex);

			if (ibmf_saa_impl_ibmf_unreg(saa_portp)
			    != IBMF_SUCCESS) {
				ret = EBUSY;
				goto bail;
			}
		} else
			mutex_exit(&saa_portp->saa_pt_mutex);

		ibmf_saa_impl_destroy_port(saa_portp);

		saa_statep->saa_port_list = next;
	}

	taskq_destroy(saa_statep->saa_event_taskq);

	mutex_destroy(&saa_statep->saa_port_list_mutex);

	kmem_free(saa_statep, sizeof (saa_state_t));

bail:
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_fini_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_fini() exit\n");

	return (ret);
}

/*
 * ibmf_saa_is_valid
 * Returns true the entry is valid.
 *
 * Input Arguments
 * saa_portp		pointer to state structure
 * add_ref 		if B_TRUE ref count is incremented on a valid portp
 *
 * Output Arguments
 * none
 *
 * Returns
 * B_TRUE if entry was in a valid state, B_FALSE otherwise
 */
boolean_t
ibmf_saa_is_valid(saa_port_t *saa_portp, int add_ref)
{
	boolean_t is_valid = B_TRUE;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_is_valid_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_is_valid() enter\n");

	mutex_enter(&saa_portp->saa_pt_mutex);

	if (saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_INVALID ||
	    saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_PURGING) {

		is_valid = B_FALSE;

	} else if (add_ref == B_TRUE) {
		/*
		 * increment reference count here to ensure that
		 * entry does not get purged behind our backs
		 */
		saa_portp->saa_pt_reference_count++;
	}
	mutex_exit(&saa_portp->saa_pt_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_is_valid_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_is_valid() exit\n");

	return (is_valid);
}

/*
 * ibmf_saa_must_purge
 * Determines if we can purge a portp (remove it from the list) based on the
 * state and number of clients
 *
 * Input Arguments
 * saa_portp		pointer to state structure
 *
 * Output Arguments
 * none
 *
 * Returns
 * B_TRUE if the entry can be removed, B_FALSE otherwise
 */
static int
ibmf_saa_must_purge(saa_port_t *saa_portp)
{
	int must_purge = B_FALSE;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_must_purge_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_must_purge() enter\n");

	mutex_enter(&saa_portp->saa_pt_mutex);

	if (saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_INVALID &&
	    saa_portp->saa_pt_reference_count == 0) {

		saa_portp->saa_pt_state = IBMF_SAA_PORT_STATE_PURGING;
		must_purge = B_TRUE;
	}

	mutex_exit(&saa_portp->saa_pt_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_must_purge_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_must_purge() exit\n");

	return (must_purge);
}


/*
 * ibmf_saa_impl_purge:
 * Removes invalid port state entries from the list
 *
 * Input Arguments
 * none
 *
 * Output Arguments
 * none
 *
 * Returns
 * void
 */
void
ibmf_saa_impl_purge()
{
	saa_port_t *cur_portp  = NULL;
	saa_port_t *prev_portp = NULL;
	saa_port_t *rem_portp  = NULL;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_purge_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_purge() enter\n");

	mutex_enter(&saa_statep->saa_port_list_mutex);

	cur_portp = saa_statep->saa_port_list;
	prev_portp = cur_portp;

	while (cur_portp != NULL) {

		if (ibmf_saa_must_purge(cur_portp) == B_TRUE) {

			rem_portp = cur_portp;

			/* unlink entry */
			if (cur_portp == saa_statep->saa_port_list) {

				saa_statep->saa_port_list = cur_portp->next;
				cur_portp = saa_statep->saa_port_list;
				prev_portp = cur_portp;

			} else {

				prev_portp->next = cur_portp->next;
				cur_portp = cur_portp->next;
			}

			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rem_portp))

			/* destroy entry */
			ASSERT(rem_portp != NULL);
			ibmf_saa_impl_destroy_port(rem_portp);

		} else {

			prev_portp = cur_portp;
			cur_portp = cur_portp->next;
		}
	}

	mutex_exit(&saa_statep->saa_port_list_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_purge_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_purge() exit\n");
}

/*
 * saa_impl_add_client:
 * Adds a client for a particular portp.  Reference count has been incremented
 * before this call.  It is decremented by saa_impl_add_client() if the call
 * fails.
 *
 * Input Arguments
 * none
 *
 * Output Arguments
 * none
 *
 * Returns
 * IBMF_BUSY if there are already too many clients registered,
 * IBMF_BAD_PORT_STATE if the port is invalid (generally because a previous
 * client failed during registration for this port)
 * IBMF_SUCCESS otherwise
 */
int
ibmf_saa_impl_add_client(saa_port_t *saa_portp)
{
	int status = IBMF_SUCCESS;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_add_client_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_add_client() enter\n");

	mutex_enter(&saa_portp->saa_pt_mutex);

	/*
	 * check that we don't exceed max clients
	 */
	if (saa_portp->saa_pt_reference_count >
	    SAA_MAX_CLIENTS_PER_PORT) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_add_client_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_add_client: %s, num_reg_clients %d\n",
		    tnf_string, msg, "too many clients registered for"
		    " port", tnf_uint, num_reg_clients,
		    saa_portp->saa_pt_reference_count);

		status = IBMF_BUSY;
		goto bail;
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_add_client, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_add_client: num_registered_clients %d\n",
	    tnf_uint, num_registered_clients,
	    saa_portp->saa_pt_reference_count);

	/*
	 * wait until anyone who is currently registering
	 * this port with ibmf is done
	 */
	while (saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_REGISTERING) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_add_client, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_add_client: %s\n",
		    tnf_string, msg, "someone is registering. waiting"
		    " for them to finish");

		cv_wait(&saa_portp->saa_pt_ibmf_reg_cv,
		    &saa_portp->saa_pt_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_add_client,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_add_client: %s\n",
		    tnf_string, msg, "done waiting");
	}

	/*
	 * if port isn't ready here, fail.
	 */
	if (saa_portp->saa_pt_state != IBMF_SAA_PORT_STATE_READY) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_add_client_err, IBMF_TNF_ERROR,
		    "", "ibmf_saa_impl_add_client: %s\n",
		    tnf_string, msg, "port state not ready,"
		    " removing client.");

		status = IBMF_BAD_PORT_STATE;
		goto bail;
	}

bail:
	mutex_exit(&saa_portp->saa_pt_mutex);

	if (status != IBMF_SUCCESS) {

		mutex_enter(&saa_portp->saa_pt_kstat_mutex);

		IBMF_SAA_ADD32_KSTATS(saa_portp,
		    clients_reg_failed, 1);

		mutex_exit(&saa_portp->saa_pt_kstat_mutex);

		/* decrementing refcount is last thing we do on entry */

		mutex_enter(&saa_portp->saa_pt_mutex);

		ASSERT(saa_portp->saa_pt_reference_count > 0);
		saa_portp->saa_pt_reference_count--;

		mutex_exit(&saa_portp->saa_pt_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_add_client_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_add_client() exit\n");

	return (status);
}

/*
 * ibmf_saa_impl_create_port()
 * Create port entry with mimimal inits because
 * we're holding the list mutex: NO BLOCKING CALLS HERE, please.
 *
 * Initialize port state to "registering", so that clients accessing
 * same port concurrently will wait for the end of the ibmf registration.
 * Note: this thread will access port members without locking mutex.
 *
 * Input Arguments
 * pt_guid		guid of port
 *
 * Output Arguments
 * saa_portpp		pointer to new saa_portp structure
 *
 * Returns
 * IBMF_NO_MEMORY if memory could not be allocated
 * IBMF_SUCCESS otherwise
 */
int
ibmf_saa_impl_create_port(ib_guid_t pt_guid, saa_port_t **saa_portpp)
{
	int		status		= IBMF_SUCCESS;
	saa_port_t	*saa_portp	= NULL;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_saa_impl_create_port_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_create_port:"
	    " guid %016" PRIx64 "\n",
	    tnf_opaque, port_guid, pt_guid);

	ASSERT(MUTEX_HELD(&saa_statep->saa_port_list_mutex));

	/* create & initialize new port */
	saa_portp = kmem_zalloc(sizeof (saa_port_t), KM_NOSLEEP);

	if (saa_portp == NULL) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_create_port: %s\n",
		    tnf_string, msg, "could not allocate memory for "
		    "new port");

		status = IBMF_NO_MEMORY;
		goto bail;
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_sa_session_open,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_create_port: %s\n",
	    tnf_string, msg, "first client registering, initializing");

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*saa_portp))

	/* tell everyone that kstats are not initialized */
	saa_portp->saa_pt_kstatp = NULL;

	/*
	 * set up mutexe and state variable to indicate to
	 * other clients that were currently in the process of
	 * setting up the port data.  This will prevent a subsequent
	 * client from trying to to register with ibmf before the
	 * port data has been initialized.
	 */
	mutex_init(&saa_portp->saa_pt_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&saa_portp->saa_pt_ibmf_reg_cv, NULL, CV_DRIVER, NULL);

	saa_portp->saa_pt_state = IBMF_SAA_PORT_STATE_REGISTERING;

	/* create other mutexes */
	mutex_init(&saa_portp->saa_pt_kstat_mutex, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&saa_portp->saa_pt_event_sub_mutex, NULL, MUTEX_DRIVER,
	    NULL);

	/*
	 * clients assume all arrive; set mask to this so we only notify
	 * if something failed
	 */
	saa_portp->saa_pt_event_sub_last_success_mask =
	    IBMF_SAA_PORT_EVENT_SUB_ALL_ARRIVE;

	/*
	 * set port_guid now so any immediately subsequent clients
	 * registering on this port, guid will know we're already here
	 */
	saa_portp->saa_pt_port_guid = pt_guid;
	saa_portp->saa_pt_reference_count = 1;
	saa_portp->saa_pt_current_tid = pt_guid << 32;

	saa_portp->saa_pt_redirect_active = B_FALSE;

	/* set sa_uptime now in case we never receive anything from SA */
	saa_portp->saa_pt_sa_uptime = gethrtime();

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*saa_portp))

	/* Set new pointer in caller's */
	*saa_portpp = saa_portp;

bail:
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_create_port_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_create_port() exit\n");

	return (status);
}

/*
 * ibmf_saa_impl_invalidate_port:
 * invalidates port entry (assumes exist) and deletes kstat object
 * kstat object is destroyed in order to allow creating port entry
 * even if this entry is not purged
 */
static void
ibmf_saa_impl_invalidate_port(saa_port_t *saa_portp)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_invalidate_port_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_invalidate_port() enter\n");

	ASSERT(saa_portp != NULL);
	ASSERT(MUTEX_HELD(&saa_portp->saa_pt_mutex));

	saa_portp->saa_pt_state = IBMF_SAA_PORT_STATE_INVALID;
	ibmf_saa_impl_uninit_kstats(saa_portp);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_invalidate_port_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_invalidate_port() exit\n");
}

/*
 * ibmf_saa_impl_destroy_port:
 * Frees the resources associated with an saa_portp structure.  Assumes the
 * saa_portp exists
 *
 * Input Arguments
 * saa_portp		pointer to saa_portp structure
 *
 * Output Arguments
 * none
 *
 * Returns
 * void
 */
static void
ibmf_saa_impl_destroy_port(saa_port_t *saa_portp)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_destroy_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_destroy() enter\n");

	ASSERT(saa_portp != NULL);

	_NOTE(ASSUMING_PROTECTED(*saa_portp))

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_destroy, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_destroy(): destroying port_guid %016" PRIx64 "\n",
	    tnf_opaque, port_guid, saa_portp->saa_pt_port_guid);

	ibmf_saa_impl_uninit_kstats(saa_portp);

	/* uninit synchronization variables used for registration */
	mutex_destroy(&saa_portp->saa_pt_mutex);
	cv_destroy(&saa_portp->saa_pt_ibmf_reg_cv);

	mutex_destroy(&saa_portp->saa_pt_event_sub_mutex);
	mutex_destroy(&saa_portp->saa_pt_kstat_mutex);

	kmem_free(saa_portp, sizeof (saa_port_t));

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_destroy_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_destroy() exit\n");
}

/*
 * ibmf_saa_impl_init_kstats:
 * Create kstats structure.  Should be called when memory is alloced for a new
 * port entry.
 */
int
ibmf_saa_impl_init_kstats(saa_port_t *saa_portp)
{
	char			buf[128];
	ibmf_saa_kstat_t	*ksp;

	_NOTE(ASSUMING_PROTECTED(saa_portp->saa_pt_kstatp))

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_init_kstats_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init_kstats() enter\n");

	/* set up kstats structure */
	(void) sprintf(buf, "ibmf_saa_%016" PRIx64 "_stat",
	    saa_portp->saa_pt_port_guid);

	saa_portp->saa_pt_kstatp = kstat_create("ibmf_saa",
	    0, buf, "misc", KSTAT_TYPE_NAMED,
	    sizeof (ibmf_saa_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_WRITABLE);

	if (saa_portp->saa_pt_kstatp == NULL)
		return (IBMF_NO_RESOURCES);

	ksp = (ibmf_saa_kstat_t *)saa_portp->saa_pt_kstatp->ks_data;

	kstat_named_init(&ksp->clients_registered,
	    "clients_registered", KSTAT_DATA_UINT32);

	kstat_named_init(&ksp->clients_reg_failed,
	    "clients_reg_failed", KSTAT_DATA_UINT32);

	kstat_named_init(&ksp->outstanding_requests,
	    "outstanding_requests", KSTAT_DATA_UINT32);

	kstat_named_init(&ksp->total_requests,
	    "total_requests", KSTAT_DATA_UINT32);

	kstat_named_init(&ksp->failed_requests,
	    "failed_requests", KSTAT_DATA_UINT32);

	kstat_named_init(&ksp->requests_timedout,
	    "requests_timedout", KSTAT_DATA_UINT32);

	kstat_install(saa_portp->saa_pt_kstatp);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_init_kstats_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init_kstats() exit\n");

	return (IBMF_SUCCESS);
}

/*
 * ibmf_saa_impl_uninit_kstats:
 * Free kstats context.  Should be called when port is either destroyed
 * or invalidated.
 */
static void
ibmf_saa_impl_uninit_kstats(saa_port_t *saa_portp)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_uninit_kstats_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_uninit_kstats() enter\n");

	mutex_enter(&saa_portp->saa_pt_kstat_mutex);

	if (saa_portp->saa_pt_kstatp != NULL) {
		kstat_delete(saa_portp->saa_pt_kstatp);
	}
	saa_portp->saa_pt_kstatp = NULL;

	mutex_exit(&saa_portp->saa_pt_kstat_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_uninit_kstats_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_uninit_kstats() exit\n");
}

/*
 * ibmf_saa_impl_register_failed:
 * invalidate entry and kick waiters
 */
void
ibmf_saa_impl_register_failed(saa_port_t *saa_portp)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_register_failed_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_register_failed() enter\n");

	mutex_enter(&saa_portp->saa_pt_mutex);

	ibmf_saa_impl_invalidate_port(saa_portp);

	cv_broadcast(&saa_portp->saa_pt_ibmf_reg_cv);

	/* decrementing refcount is last thing we do on entry */

	ASSERT(saa_portp->saa_pt_reference_count > 0);
	saa_portp->saa_pt_reference_count--;

	mutex_exit(&saa_portp->saa_pt_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_register_failed_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_register_failed() exit\n");
}

static int
ibmf_saa_impl_setup_qp_async_cb(saa_port_t *saa_portp, int setup_async_cb_only)
{
	int		status;
	int		unreg_status;
	ib_pkey_t	p_key;
	ib_qkey_t	q_key;
	uint8_t		portnum;
	boolean_t	qp_alloced = B_FALSE;

	if (setup_async_cb_only == 0) {

		/* allocate a qp through ibmf */
		status = ibmf_alloc_qp(saa_portp->saa_pt_ibmf_handle,
		    IB_PKEY_DEFAULT_LIMITED, IB_GSI_QKEY,
		    IBMF_ALT_QP_MAD_RMPP, &saa_portp->saa_pt_qp_handle);

		if (status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_setup_qp_async_cb, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_setup_qp_async_cb: %s, "
			    "ibmf_status = %d\n",
			    tnf_string, msg, "Cannot alloc qp with ibmf",
			    tnf_int, status, status);

			return (status);
		}

		qp_alloced = B_TRUE;

		/*
		 * query the queue pair number; we will need it to unsubscribe
		 * from notice reports
		 */
		status = ibmf_query_qp(saa_portp->saa_pt_ibmf_handle,
		    saa_portp->saa_pt_qp_handle, &saa_portp->saa_pt_qpn,
		    &p_key, &q_key, &portnum, 0);

		if (status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_setup_qp_async_cb, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_setup_qp_async_cb: %s, "
			    "ibmf_status = %d\n",
			    tnf_string, msg,
			    "Cannot query alt qp to get qp num",
			    tnf_int, status, status);

			goto bail;
		}
	}

	/*
	 * core ibmf is taking advantage of the fact that saa_portp is our
	 * callback arg. If this changes, the code in ibmf_recv would need to
	 * change as well
	 */
	status = ibmf_setup_async_cb(saa_portp->saa_pt_ibmf_handle,
	    saa_portp->saa_pt_qp_handle, ibmf_saa_report_cb, saa_portp, 0);
	if (status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_setup_qp_async_cb, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_setup_qp_async_cb: %s, ibmf_status = %d\n",
		    tnf_string, msg, "Cannot register async cb with ibmf",
		    tnf_int, status, status);

		goto bail;
	}

	return (IBMF_SUCCESS);

bail:
	if (qp_alloced == B_TRUE) {
		/* free alternate qp */
		unreg_status = ibmf_free_qp(saa_portp->saa_pt_ibmf_handle,
		    &saa_portp->saa_pt_qp_handle, 0);
		if (unreg_status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_setup_qp_async_cb, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_setup_qp_async_cb: %s, ibmf_status ="
			    " %d\n", tnf_string, msg,
			    "Cannot free alternate queue pair with ibmf",
			    tnf_int, unreg_status, unreg_status);
		}
	}

	return (status);
}

/*
 * ibmf_saa_impl_register_port:
 */
int
ibmf_saa_impl_register_port(
	saa_port_t *saa_portp)
{
	uint_t		hca_count	= 0;
	ib_guid_t	*hca_list 	= NULL;
	int		status 		= IBMF_SUCCESS;
	int		unreg_status 	= IBMF_SUCCESS;
	int		ibt_status	= IBT_SUCCESS;
	ibt_hca_portinfo_t *port_info_list = NULL;
	uint_t		port_count	= 0;
	uint_t		port_size	= 0;
	int		ihca, iport;
	ib_guid_t	port_guid;
	boolean_t	ibmf_reg = B_FALSE;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_register_port_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_register_port() enter\n");

	ASSERT(saa_portp != NULL);

	_NOTE(ASSUMING_PROTECTED(*saa_portp))

	/* get the HCA list */

	hca_count = ibt_get_hca_list(&hca_list);

	if (hca_count == 0) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_register_port, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_register_port: %s\n",
		    tnf_string, msg, "cannot register port (no HCAs).\n");

		status = IBMF_BAD_PORT;
		goto bail;
	}

	/* lookup requested port guid in hca list */
	for (ihca = 0; ihca != hca_count; ihca++) {

		ibt_status = ibt_query_hca_ports_byguid(hca_list[ihca],
		    0 /* all ports */, &port_info_list,
		    &port_count, &port_size);

		if (ibt_status != IBT_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_register_port, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_register_port: %s, %016" PRIx64 "\n",
			    tnf_string, msg, "Could not query hca.  Exiting.",
			    tnf_opaque, guid, hca_list[ihca]);

			status = IBMF_TRANSPORT_FAILURE;
			break;
		}

		for (iport = 0; iport < port_count; iport++) {

			/* get port guid associated with hca guid, port num */
			if (ibmf_saa_impl_get_port_guid(
			    port_info_list + iport, &port_guid) != IBMF_SUCCESS)
				continue;

			if (saa_portp->saa_pt_port_guid != port_guid)
				continue;

			IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_saa_impl_register_port,
			    IBMF_TNF_TRACE, "",
			    "ibmf_saa_impl_register_port: %s, hca_guid = %016"
			    PRIx64 ", port_guid = %016" PRIx64
			    ", number = %d\n",
			    tnf_string, msg, "found port",
			    tnf_opaque, hca_guid, hca_list[ihca],
			    tnf_opaque, port_guid, port_guid,
			    tnf_uint,   port, iport + 1);

			/*
			 * we're here? then we found our port:
			 * fill in ibmf registration info
			 * and address parameters from the portinfo
			 */

			saa_portp->saa_pt_ibmf_reginfo.ir_ci_guid
			    = hca_list[ihca];
			saa_portp->saa_pt_ibmf_reginfo.ir_port_num = iport+1;
			saa_portp->saa_pt_ibmf_reginfo.ir_client_class
			    = SUBN_ADM_MANAGER;

			saa_portp->saa_pt_node_guid = hca_list[ihca];
			saa_portp->saa_pt_port_num = iport + 1;

			ibmf_saa_impl_set_transaction_params(
			    saa_portp, port_info_list + iport);
			break;
		}

		ibt_free_portinfo(port_info_list, port_size);

		if (iport != port_count)
			break;	/* found our port */
	}

	ibt_free_hca_list(hca_list, hca_count);

	if (ihca == hca_count) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_register_port, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_register_port: %s, port_guid %016"
		    PRIx64 "\n",
		    tnf_string, msg, "Could not find port,  exiting",
		    tnf_opaque, port_guid, saa_portp->saa_pt_port_guid);

		status = IBMF_BAD_PORT;
	}

	if (status != IBMF_SUCCESS) {

		goto bail;
	}

	/*
	 * Now we found the port we searched for,
	 * and open an ibmf session on that port.
	 */

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_register_port, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_register_port: %s, port_guid = %016" PRIx64
	    ", port = %d\n", tnf_string, msg, "Registering with ibmf",
	    tnf_opaque, port_guid, saa_portp->saa_pt_ibmf_reginfo.ir_ci_guid,
	    tnf_uint, port, saa_portp->saa_pt_ibmf_reginfo.ir_port_num);

	status = ibmf_register(&saa_portp->saa_pt_ibmf_reginfo,
	    IBMF_VERSION, IBMF_REG_FLAG_RMPP,
	    ibmf_saa_impl_async_event_cb, saa_portp,
	    &saa_portp->saa_pt_ibmf_handle,
	    &saa_portp->saa_pt_ibmf_impl_features);

	if (status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_register_port, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_register_port: %s, ibmf_status = %d\n",
		    tnf_string, msg, "Could not register with ibmf",
		    tnf_int, status, status);

		goto bail;
	}

	ibmf_reg = B_TRUE;

	if (ibmf_saa_impl_setup_qp_async_cb(saa_portp, 0) == IBMF_SUCCESS)
		return (IBMF_SUCCESS);

bail:
	if (ibmf_reg == B_TRUE) {
		/* unregister from ibmf */
		unreg_status = ibmf_unregister(
		    &saa_portp->saa_pt_ibmf_handle, 0);

		if (unreg_status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_register_port, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_register_port: %s, ibmf_status ="
			    " %d\n", tnf_string, msg,
			    "Cannot unregister from ibmf",
			    tnf_int, unreg_status, unreg_status);
		}
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_register_port_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_register_port() exit\n");

	return (status);
}

/*
 * ibmf_saa_impl_getclassportinfo:
 */
void
ibmf_saa_impl_get_classportinfo(saa_port_t *saa_portp)
{
	int			res;
	saa_impl_trans_info_t	*trans_info;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_get_classportinfo_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_classportinfo() enter\n");

	/*
	 * allocate memory for trans_info; send_request's callback will free up
	 * memory since request is asynchronous
	 */
	trans_info = kmem_zalloc(sizeof (saa_impl_trans_info_t), KM_NOSLEEP);
	if (trans_info == NULL) {

		mutex_enter(&saa_portp->saa_pt_mutex);

		/* cpi transaction is handled as a client, decrement refcount */
		ASSERT(saa_portp->saa_pt_reference_count > 0);
		saa_portp->saa_pt_reference_count--;

		mutex_exit(&saa_portp->saa_pt_mutex);

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_get_classportinfo_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_get_classportinfo: %s\n", tnf_string, msg,
		    "Could not allocate memory for classportinfo trans_info");

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_saa_impl_get_classportinfo_end, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_get_classportinfo() exiting\n");

		return;
	}

	/* no specific client associated with this transaction */
	trans_info->si_trans_client_data = NULL;
	trans_info->si_trans_port	 = saa_portp;
	trans_info->si_trans_method	 = SA_SUBN_ADM_GET;
	trans_info->si_trans_attr_id	 = MAD_ATTR_ID_CLASSPORTINFO;

	trans_info->si_trans_callback = ibmf_saa_impl_get_cpi_cb;
	trans_info->si_trans_callback_arg = saa_portp;

	mutex_enter(&saa_portp->saa_pt_kstat_mutex);

	IBMF_SAA_ADD32_KSTATS(saa_portp, outstanding_requests, 1);
	IBMF_SAA_ADD32_KSTATS(saa_portp, total_requests, 1);

	mutex_exit(&saa_portp->saa_pt_kstat_mutex);

	res = ibmf_saa_impl_send_request(trans_info);

	if (res != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_impl_get_classportinfo_err, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_get_classportinfo: %s, res = 0x%x\n",
		    tnf_string, msg, "ibmf_saa_impl_send_request failed",
		    tnf_opaque, res, res);

		mutex_enter(&saa_portp->saa_pt_kstat_mutex);

		IBMF_SAA_SUB32_KSTATS(saa_portp, outstanding_requests, 1);
		IBMF_SAA_ADD32_KSTATS(saa_portp, failed_requests, 1);

		mutex_exit(&saa_portp->saa_pt_kstat_mutex);

		mutex_enter(&saa_portp->saa_pt_mutex);

		/* cpi transaction is handled as a client, decrement refcount */
		ASSERT(saa_portp->saa_pt_reference_count > 0);
		saa_portp->saa_pt_reference_count--;

		mutex_exit(&saa_portp->saa_pt_mutex);

	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_get_classportinfo_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_classportinfo() exit\n");
}

/*
 * ibmf_saa_impl_get_cpi_cb:
 *
 * Called when the asynchronous getportinfo request receives its response.
 * Checks the status.  If success, updates the times in the port's
 * ibmf_retrans structure that is used in ibmf_msg_transport calls.  If failure,
 * just use default values.
 *
 * Input Arguments
 * arg		user-specified pointer (points to the current port data)
 * length	length of payload returned (should be size of classportinfo_t)
 * buffer	pointer to classportinfo returned (should not be null)
 * status	status of sa access request
 *
 * Output Arguments
 * none
 *
 * Returns void
 */
static void
ibmf_saa_impl_get_cpi_cb(void *arg, size_t length, char *buffer, int status)
{
	saa_port_t		*saa_portp;
	uint64_t		base_time, resp_timeout, rttv_timeout;
	ib_mad_classportinfo_t	*classportinfo;
	int			resp_time_value;
	uint16_t		sa_cap_mask;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_get_cpi_cb_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_cpi_cb() enter\n");

	/*
	 * access port entry: note that it may have become invalid
	 * but we hold a ref count for cpi and the interactions on
	 * the entry are harmless
	 */
	saa_portp = (saa_port_t *)arg;

	/* process response */

	if ((status != IBMF_SUCCESS) || (buffer == NULL)) {

		IBMF_TRACE_4(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_get_cpi_cb, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_get_cpi_cb: %s, status = %d, buffer = "
		    " 0x%p, length = %d\n", tnf_string, msg,
		    "could not get classportinfo.  Check node and path to sm"
		    " lid", tnf_int, status, status,
		    tnf_opaque, buffer, buffer, tnf_uint, length, length);

		/*
		 * IB spec (C13-13) indicates 20 can be used as default or
		 * intial value for classportinfo->resptimeout value
		 */
		resp_time_value = 20;

		sa_cap_mask = 0xFFFF;

	} else if (buffer != NULL) {

		classportinfo = (ib_mad_classportinfo_t *)buffer;

		resp_time_value = classportinfo->RespTimeValue & 0x1f;

		sa_cap_mask = classportinfo->CapabilityMask;

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_get_cpi_cb, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_get_cpi_cb: %s, timeout = 0x%x,"
		    " cap_mask = 0x%x\n",
		    tnf_string, msg, "got classportinfo",
		    tnf_opaque, timeout, resp_time_value,
		    tnf_opaque, cap_mask, sa_cap_mask);

		kmem_free(buffer, length);
	}

	/*
	 * using IB spec calculation from 13.4.6.2
	 * use bit shifting for 2^x.
	 */
	base_time = (1 << resp_time_value);

	resp_timeout = (4 * base_time * 1000 + 96 * base_time) / 1000;

	mutex_enter(&saa_portp->saa_pt_mutex);

	base_time = 2 * (1 << saa_portp->saa_pt_timeout);

	rttv_timeout = (4 * base_time * 1000 + 96 * base_time) / 1000;

	saa_portp->saa_pt_ibmf_retrans.retrans_rtv = resp_timeout;
	saa_portp->saa_pt_ibmf_retrans.retrans_rttv = rttv_timeout;
	saa_portp->saa_pt_sa_cap_mask = sa_cap_mask;

	/*
	 * cpi transaction is handled as a client,
	 * decrement refcount; make sure it's the last
	 * thing we do on this entry
	 */
	ASSERT(saa_portp->saa_pt_reference_count > 0);
	saa_portp->saa_pt_reference_count--;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_get_cpi_cb, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_get_cpi_cb: %s, subnet_timeout = 0x%x, "
	    "resp_time_value = 0x%x\n",
	    tnf_string, msg, "updated resp timeout",
	    tnf_opaque, subnet_timeout, saa_portp->saa_pt_timeout,
	    tnf_opaque, resp_time_value, resp_time_value);

	mutex_exit(&saa_portp->saa_pt_mutex);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_get_cpi_cb_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_cpi_cb() exit\n");
}

/*
 * ibmf_saa_impl_send_request:
 * Sends a request to the sa.  Can be used for both classportinfo and record
 * requests.  Will set up all data structures for using the multi-packet
 * protocol, create the mad, and send it.  Returns SA_SUCCESS if msg transport
 * worked, meaning succesful send for the async case and a succesful send and
 * recv for the sync case.
 */
int
ibmf_saa_impl_send_request(saa_impl_trans_info_t *trans_info)
{
	uint16_t 		attr_id;
	saa_client_data_t	*client_data;
	saa_port_t		*saa_portp;
	uint32_t		transport_flags;
	ibmf_msg_cb_t		ibmf_callback;
	void			*ibmf_callback_arg;
	ibmf_msg_t		*msgp;
	ibmf_retrans_t		ibmf_retrans;
	uint16_t		sa_cap_mask;
	boolean_t		sleep_flag;
	int			ibmf_status = IBMF_SUCCESS;
	int			retry_count;
	uint16_t		mad_status;
	boolean_t		sa_is_redirected = B_FALSE;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_send_request_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_send_request() enter\n");

	attr_id = trans_info->si_trans_attr_id;
	client_data = trans_info->si_trans_client_data;
	saa_portp   = trans_info->si_trans_port;

	/*
	 * don't send on invalid entry
	 * Note that there is a window where it could become
	 * invalid after this test is done, but we'd rely on ibmf errors...
	 */
	if (ibmf_saa_is_valid(saa_portp, B_FALSE) == B_FALSE) {

		IBMF_TRACE_4(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_send_request,
		    IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_send_request: %s, hca_guid = %016"
		    PRIx64 ", port_guid = %016" PRIx64
		    ", number = %d\n",
		    tnf_string, msg, "sending on invalid port",
		    tnf_opaque, hca_guid,
		    saa_portp->saa_pt_ibmf_reginfo.ir_ci_guid,
		    tnf_opaque, port_guid,
		    saa_portp->saa_pt_port_guid,
		    tnf_uint,   port,
		    saa_portp->saa_pt_ibmf_reginfo.ir_port_num);

		ibmf_status = IBMF_REQ_INVALID;
		goto bail;
	}

	/* check whether SA supports this attribute */
	mutex_enter(&saa_portp->saa_pt_mutex);

	sa_cap_mask = saa_portp->saa_pt_sa_cap_mask;
	sa_is_redirected = saa_portp->saa_pt_redirect_active;

	mutex_exit(&saa_portp->saa_pt_mutex);

	ibmf_status = ibmf_saa_impl_check_sa_support(sa_cap_mask, attr_id);

	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_send_request_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_send_request: %s, ibmf_status = %d\n",
		    tnf_string, msg, "SA does not support attribute",
		    tnf_int, ibmf_status, ibmf_status);

		goto bail;
	}

	/* make only non-blocking calls if this is an async request */
	if ((trans_info->si_trans_callback == NULL) &&
	    (trans_info->si_trans_sub_callback == NULL)) {
		ibmf_callback = NULL;
		ibmf_callback_arg = NULL;
		sleep_flag = B_TRUE;
	} else {
		ibmf_callback = ibmf_saa_async_cb;
		ibmf_callback_arg = (void *)trans_info;
		sleep_flag = B_FALSE;
	}

	ibmf_status = ibmf_saa_impl_init_msg(trans_info, sleep_flag, &msgp,
	    &transport_flags, &ibmf_retrans);
	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_send_request_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_send_request: %s, ibmf_status = %d\n",
		    tnf_string, msg, "init_msg() failed",
		    tnf_int, ibmf_status, ibmf_status);

		goto bail;
	}

	mutex_enter(&saa_portp->saa_pt_mutex);

	saa_portp->saa_pt_num_outstanding_trans++;

	mutex_exit(&saa_portp->saa_pt_mutex);

	/*
	 * increment the number of outstanding transaction so
	 * ibmf_close_sa_session() will wait.  classportinfo requests
	 * don't have associated clients so check for valid clientp
	 */
	if (client_data != NULL) {

		mutex_enter(&client_data->saa_client_mutex);

		client_data->saa_client_num_pending_trans++;

		mutex_exit(&client_data->saa_client_mutex);
	}

	/*
	 * make the call to msg_transport.  If synchronous and success,
	 * check that the response mad isn't status busy.  If so, repeat the
	 * call
	 */
	retry_count = 0;

	/*
	 * set the send time here. We only set this once at the beginning of
	 * the transaction.  Retrying because of busys or mastersmlid changes
	 * does not change the original send time.  It is meant to be an
	 * absolute time out value and will only be used if there are other
	 * problems (i.e. a buggy SA)
	 */
	trans_info->si_trans_send_time = gethrtime();

	for (;;) {

		ibmf_status = ibmf_msg_transport(saa_portp->saa_pt_ibmf_handle,
		    saa_portp->saa_pt_qp_handle, msgp, &ibmf_retrans,
		    ibmf_callback, ibmf_callback_arg, transport_flags);

		if (ibmf_callback != NULL)
			break;

		/*
		 * stop here for non-sequenced transactions since they wouldn't
		 * receive a timeout or busy response
		 */
		if (!(transport_flags & IBMF_MSG_TRANS_FLAG_SEQ))
			break;

		/*
		 * if the transaction timed out and this was a synchronous
		 * request there's a possiblity we were talking to the wrong
		 * master smlid or that the SA has stopped responding on the
		 * redirected desination (if redirect is active).
		 * Check this and retry if necessary.
		 */
		if ((ibmf_status == IBMF_TRANS_TIMEOUT) &&
		    (sleep_flag == B_TRUE)) {
			if (sa_is_redirected == B_TRUE) {
				ibmf_status = ibmf_saa_impl_revert_to_qp1(
				    saa_portp, msgp, ibmf_callback,
				    ibmf_callback_arg, transport_flags);
			} else {
				ibmf_status = ibmf_saa_impl_new_smlid_retry(
				    saa_portp, msgp, ibmf_callback,
				    ibmf_callback_arg, transport_flags);
			}
		}

		/*
		 * if the transaction timed out (and retrying with a new SM LID
		 * didn't help) check how long it's been since we received an SA
		 * packet.  If it hasn't been max_wait_time then retry the
		 * request.
		 */
		if ((ibmf_status == IBMF_TRANS_TIMEOUT) &&
		    (sleep_flag == B_TRUE)) {

			ibmf_status = ibmf_saa_check_sa_and_retry(
			    saa_portp, msgp, ibmf_callback, ibmf_callback_arg,
			    trans_info->si_trans_send_time, transport_flags);
		}

		if (ibmf_status != IBMF_SUCCESS)
			break;

		if (retry_count >= IBMF_SAA_MAX_BUSY_RETRY_COUNT)
			break;

		/* sync transaction with status SUCCESS should have response */
		ASSERT(msgp->im_msgbufs_recv.im_bufs_mad_hdr != NULL);

		mad_status = b2h16(msgp->im_msgbufs_recv.
		    im_bufs_mad_hdr->Status);

		if ((mad_status != MAD_STATUS_BUSY) &&
		    (mad_status != MAD_STATUS_REDIRECT_REQUIRED))
			break;

		if (mad_status == MAD_STATUS_REDIRECT_REQUIRED) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_impl_send_request, IBMF_TNF_TRACE, "",
			    "ibmf_saa_impl_send_request: %s, retry_count %d\n",
			    tnf_string, msg,
			    "response returned redirect status",
			    tnf_int, retry_count, retry_count);

			/* update address info and copy it into msgp */
			ibmf_saa_impl_update_sa_address_info(saa_portp, msgp);
		} else {
			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_impl_send_request, IBMF_TNF_TRACE, "",
			    "ibmf_saa_impl_send_request: %s, retry_count %d\n",
			    tnf_string, msg, "response returned busy status",
			    tnf_int, retry_count, retry_count);
		}

		retry_count++;

		/*
		 * since this is a blocking call, sleep for some time
		 * to allow SA to transition from busy state (if busy)
		 */
		if (mad_status == MAD_STATUS_BUSY)
			delay(drv_usectohz(
			    IBMF_SAA_BUSY_RETRY_SLEEP_SECS * 1000000));
	}

	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_impl_send_request, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_send_request: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_msg_transport() failed",
		    tnf_int, ibmf_status, ibmf_status);

		ibmf_saa_impl_free_msg(saa_portp->saa_pt_ibmf_handle, msgp);

		mutex_enter(&saa_portp->saa_pt_mutex);

		ASSERT(saa_portp->saa_pt_num_outstanding_trans > 0);
		saa_portp->saa_pt_num_outstanding_trans--;

		mutex_exit(&saa_portp->saa_pt_mutex);

		if (client_data != NULL) {

			mutex_enter(&client_data->saa_client_mutex);

			ASSERT(client_data->saa_client_num_pending_trans > 0);
			client_data->saa_client_num_pending_trans--;

			if ((client_data->saa_client_num_pending_trans == 0) &&
			    (client_data->saa_client_state ==
			    SAA_CLIENT_STATE_WAITING))
				cv_signal(&client_data->saa_client_state_cv);

			mutex_exit(&client_data->saa_client_mutex);
		}

	} else if (sleep_flag == B_TRUE) {

		mutex_enter(&saa_portp->saa_pt_mutex);

		ASSERT(saa_portp->saa_pt_num_outstanding_trans > 0);
		saa_portp->saa_pt_num_outstanding_trans--;

		mutex_exit(&saa_portp->saa_pt_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_send_request, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_send_request: %s\n",
		    tnf_string, msg, "Message sent and received successfully");

		/* fill in response values and free the message */
		ibmf_saa_impl_prepare_response(saa_portp->saa_pt_ibmf_handle,
		    msgp, B_FALSE, &trans_info->si_trans_status,
		    &trans_info->si_trans_result,
		    &trans_info->si_trans_length, sleep_flag);

		if (client_data != NULL) {
			mutex_enter(&client_data->saa_client_mutex);

			ASSERT(client_data->saa_client_num_pending_trans > 0);
			client_data->saa_client_num_pending_trans--;

			if ((client_data->saa_client_num_pending_trans == 0) &&
			    (client_data->saa_client_state ==
			    SAA_CLIENT_STATE_WAITING))
				cv_signal(&client_data->saa_client_state_cv);

			mutex_exit(&client_data->saa_client_mutex);
		}
	} else {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_send_request, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_send_request: %s\n",
		    tnf_string, msg, "Message sent successfully");
	}

bail:
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_send_request_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_send_request() exiting"
	    " ibmf_status = %d\n", tnf_int, result, ibmf_status);

	return (ibmf_status);
}

/*
 * ibmf_saa_impl_init_msg:
 * Allocates an ibmf message and fills out the header fields and formatted data
 * fields.  Also sets up the correct transport_flags and retrans argument for
 * the message transport call based on the request information.
 *
 * Input Arguments
 * trans_info		saa_trans_info structure passed to send_request
 * sleep_flag		B_TRUE if init_msg can sleep in function calls
 *
 * Output Arguments
 * msgp			ibmf message that should be given to msg_transport
 * transport_flagsp	transport flags that should be given to msg_transport
 * ibmf_retrans_t	retrans parameter that should be given to msg_transport
 *
 * Returns
 * ibmf_status
 */
static int
ibmf_saa_impl_init_msg(saa_impl_trans_info_t *trans_info, boolean_t sleep_flag,
    ibmf_msg_t **msgp, uint32_t *transport_flagsp,
    ibmf_retrans_t *ibmf_retransp)
{
	int			ibmf_status;
	ibmf_msg_bufs_t		*req_mad;
	ib_mad_hdr_t		*mad_hdr;
	int			ibmf_sleep_flag, km_sleep_flag;
	int 			free_res;
	ib_sa_hdr_t		sa_hdr;
	ibmf_msg_t		*ibmf_msg;
	uint16_t 		attr_id, pack_attr_id;
	uint8_t			method;
	saa_client_data_t	*client_data;
	saa_port_t		*saa_portp;
	sa_multipath_record_t	*multipath_template;
	size_t			payload_length;
	uint32_t		transport_flags;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_init_msg_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init_msg() entering\n");

	attr_id = trans_info->si_trans_attr_id;
	method = trans_info->si_trans_method;
	client_data = trans_info->si_trans_client_data;
	saa_portp   = trans_info->si_trans_port;

	if (sleep_flag == B_TRUE) {
		ibmf_sleep_flag = IBMF_ALLOC_SLEEP;
		km_sleep_flag = KM_SLEEP;
	} else {
		ibmf_sleep_flag = IBMF_ALLOC_NOSLEEP;
		km_sleep_flag = KM_NOSLEEP;
	}

	ibmf_status = ibmf_alloc_msg(saa_portp->saa_pt_ibmf_handle,
	    ibmf_sleep_flag, &ibmf_msg);
	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_init_msg_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_init_msg: %s, ibmf_status = %d\n",
		    tnf_string, msg, "Cannot allocate msg_buf.",
		    tnf_int, ibmf_status, ibmf_status);

		goto bail;
	}

	req_mad = &ibmf_msg->im_msgbufs_send;

	/* create a template (SA MAD) */
	mad_hdr = kmem_zalloc(sizeof (ib_mad_hdr_t), km_sleep_flag);

	if (mad_hdr == NULL) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_init_msg_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_init_msg: %s\n",
		    tnf_string, msg, "Cannot allocate mad header.");

		free_res = ibmf_free_msg(saa_portp->saa_pt_ibmf_handle,
		    &ibmf_msg);
		ASSERT(free_res == IBMF_SUCCESS);

		ibmf_status = IBMF_NO_MEMORY;
		goto bail;
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mad_hdr,
	    *req_mad))

	bzero(mad_hdr, sizeof (ib_mad_hdr_t));
	mad_hdr->BaseVersion = SAA_MAD_BASE_VERSION;
	mad_hdr->MgmtClass = MAD_MGMT_CLASS_SUBN_ADM;
	mad_hdr->ClassVersion = SAA_MAD_CLASS_VERSION;
	mad_hdr->R_Method = method;
	mad_hdr->AttributeID = h2b16(attr_id);

	/* attribute modifier is all Fs since RIDs are no longer used */
	mad_hdr->AttributeModifier = h2b32(0xffffffff);

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_init_msg, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_init_msg: %s, class = 0x%x, method = 0x%x,"
	    " attr_id = 0x%x\n", tnf_string, msg, "Sending MAD",
	    tnf_opaque, class, mad_hdr->MgmtClass,
	    tnf_opaque, method, mad_hdr->R_Method,
	    tnf_opaque, attr_id, attr_id);

	bzero(&sa_hdr, sizeof (ib_sa_hdr_t));
	sa_hdr.ComponentMask = trans_info->si_trans_component_mask;

	if (client_data != NULL)
		sa_hdr.SM_KEY = client_data->saa_client_sm_key;

	/*
	 * pack data for IB wire format; req_mad will have different pointers to
	 * sa header and payload, mad_hdr will be the same
	 */
	req_mad->im_bufs_mad_hdr = mad_hdr;

	ibmf_status = ibmf_saa_utils_pack_sa_hdr(&sa_hdr,
	    &req_mad->im_bufs_cl_hdr, &req_mad->im_bufs_cl_hdr_len,
	    km_sleep_flag);

	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_init_msg, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_init_msg: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_saa_utils_pack_sa_hdr() failed",
		    tnf_int, ibmf_status, ibmf_status);

		kmem_free(mad_hdr, sizeof (ib_mad_hdr_t));

		free_res = ibmf_free_msg(saa_portp->saa_pt_ibmf_handle,
		    &ibmf_msg);
		ASSERT(free_res == IBMF_SUCCESS);

		goto bail;
	}

	if (attr_id == SA_MULTIPATHRECORD_ATTRID) {

		multipath_template =
		    (sa_multipath_record_t *)trans_info->si_trans_template;

		payload_length = sizeof (sa_multipath_record_t) +
		    ((multipath_template->SGIDCount +
		    multipath_template->DGIDCount) * sizeof (ib_gid_t));

		pack_attr_id = attr_id;
	} else {

		/* trace record template is a path record */
		pack_attr_id = (attr_id == SA_TRACERECORD_ATTRID) ?
		    SA_PATHRECORD_ATTRID : attr_id;

		payload_length = ibmf_saa_impl_get_attr_id_length(pack_attr_id);

		if (payload_length == 0) {
			payload_length = trans_info->si_trans_template_length;

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_saa_impl_init_msg, IBMF_TNF_TRACE, "",
			    "ibmf_saa_impl_init_msg: %s, length = %d\n",
			    tnf_string, msg,
			    "Unknown attribute.  Using user-defined length.",
			    tnf_uint, length, payload_length)
		}
	}

	/* transport type depends on method */
	switch (method) {

		case SA_SUBN_ADM_GET:
		case SA_SUBN_ADM_DELETE:
		case SA_SUBN_ADM_GET_TABLE:
		case SA_SUBN_ADM_GET_TRACE_TABLE:
			transport_flags = IBMF_MSG_TRANS_FLAG_SEQ;
			break;
		case SA_SUBN_ADM_SET:
			/* unsubscribes can be sequenced or unsequenced */
			if (trans_info->si_trans_unseq_unsubscribe == B_TRUE) {
				transport_flags = 0;
			} else {
				transport_flags = IBMF_MSG_TRANS_FLAG_SEQ;
			}
			break;
		case SA_SUBN_ADM_GET_MULTI:
			transport_flags = IBMF_MSG_TRANS_FLAG_SEQ |
			    IBMF_MSG_TRANS_FLAG_RMPP;
			break;
		default :
			ibmf_status = IBMF_UNSUPP_METHOD;
			goto bail;
	}

	trans_info->si_trans_transport_flags = transport_flags;

	if (trans_info->si_trans_template != NULL) {

		ibmf_status = ibmf_saa_utils_pack_payload(
		    trans_info->si_trans_template, payload_length, pack_attr_id,
		    &req_mad->im_bufs_cl_data, &req_mad->im_bufs_cl_data_len,
		    km_sleep_flag);
		if (ibmf_status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_init_msg_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_init_msg: %s, ibmf_status ="
			    " %d\n", tnf_string, msg,
			    "ibmf_saa_utils_pack_payload() failed",
			    tnf_int, ibmf_status, ibmf_status);

			kmem_free(mad_hdr, sizeof (ib_mad_hdr_t));

			kmem_free(req_mad->im_bufs_cl_hdr,
			    req_mad->im_bufs_cl_hdr_len);

			free_res = ibmf_free_msg(saa_portp->saa_pt_ibmf_handle,
			    &ibmf_msg);
			ASSERT(free_res == IBMF_SUCCESS);

			goto bail;
		}

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_init_msg, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_init_msg: %s, attr_id = 0x%x, length ="
		    " %d\n", tnf_string, msg, "Packed payload successfully",
		    tnf_opaque, attr_id, attr_id,
		    tnf_uint, length, req_mad->im_bufs_cl_data_len);

		/* non-RMPP transactions have template size limit */
		if (((transport_flags & IBMF_MSG_TRANS_FLAG_RMPP) == 0) &&
		    ((req_mad->im_bufs_cl_data_len + req_mad->im_bufs_cl_hdr_len
		    + sizeof (ib_mad_hdr_t)) > IBMF_MAD_SIZE)) {

			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_init_msg_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_init_msg: %s\n", tnf_string, msg,
			    "Template too large to fit in single packet");

			kmem_free(mad_hdr, sizeof (ib_mad_hdr_t));

			kmem_free(req_mad->im_bufs_cl_hdr,
			    req_mad->im_bufs_cl_hdr_len);

			kmem_free(req_mad->im_bufs_cl_data,
			    req_mad->im_bufs_cl_data_len);

			free_res = ibmf_free_msg(saa_portp->saa_pt_ibmf_handle,
			    &ibmf_msg);
			ASSERT(free_res == IBMF_SUCCESS);

			ibmf_status = IBMF_REQ_INVALID;
			goto bail;
		}
	}

	mutex_enter(&saa_portp->saa_pt_mutex);

	mad_hdr->TransactionID = h2b64(saa_portp->saa_pt_current_tid++);

	bcopy(&saa_portp->saa_pt_ibmf_retrans, ibmf_retransp,
	    sizeof (ibmf_retrans_t));

	/* copy local addressing information to message */
	bcopy(&saa_portp->saa_pt_ibmf_addr_info, &ibmf_msg->im_local_addr,
	    sizeof (ibmf_addr_info_t));

	/* copy global addressing information to message if in use */
	if (saa_portp->saa_pt_ibmf_msg_flags & IBMF_MSG_FLAGS_GLOBAL_ADDRESS) {

		ibmf_msg->im_msg_flags = IBMF_MSG_FLAGS_GLOBAL_ADDRESS;

		bcopy(&saa_portp->saa_pt_ibmf_global_addr,
		    &ibmf_msg->im_global_addr,
		    sizeof (ibmf_global_addr_info_t));
	} else {
		ibmf_msg->im_msg_flags = 0;
	}

	mutex_exit(&saa_portp->saa_pt_mutex);

	*msgp = ibmf_msg;
	*transport_flagsp = transport_flags;
bail:
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_init_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_init_msg() exiting"
	    " ibmf_status = %d\n", tnf_int, result, ibmf_status);

	return (ibmf_status);

}

/*
 * ibmf_saa_impl_new_smlid_retry:
 *
 * It's possible for the MasterSMLID to change while ibmf_saa is running.  The
 * MasterSMLID is set when we first register with ibmf_saa.  If a request
 * timesout, this function should be called to check whether the SM LID changed.
 * If so, it will call msg_transport again with the request.
 *
 * msgp, ibmf_callback, ibmf_callback_arg, and transport flags should be the
 * same values passed to the original ibmf_msg_transport that timedout.  The
 * ibmf_retrans parameter will be re-retrieved from the saa_portp structure.
 *
 * If the lid did not change then this function returns IBMF_TRANS_TIMEOUT.
 * That way, callers can simply return the result of this function.
 *
 * Input Arguments
 * saa_portp		pointer to saa_port structure
 * msgp			ibmf message that timedout
 * ibmf_callback	callback that should be called by msg_transport
 * ibmf_callback_arg	args for ibmf_callback
 * transport_flags	flags for ibmf_msg_transport
 *
 * Output Arguments
 * none
 *
 * Returns
 * IBMF_SUCCESS if lid changed and request was resent successfully,
 * IBMF_TRANS_TIMEOUT if lid did not change,
 * same values as ibmf_msg_transport() if lid changed but request could not be
 * resent.
 */
static int
ibmf_saa_impl_new_smlid_retry(saa_port_t *saa_portp, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ibmf_callback, void *ibmf_callback_arg, int transport_flags)
{
	ibt_hca_portinfo_t	*ibt_portinfop;
	ib_lid_t		master_sm_lid;
	int			subnet_timeout;
	uint_t			nports, size;
	ibmf_retrans_t		ibmf_retrans;
	int			ibmf_status;
	ibt_status_t		ibt_status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_new_smlid_retry_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_new_smlid_retry() enter\n");

	_NOTE(ASSUMING_PROTECTED(*msgp))
	_NOTE(ASSUMING_PROTECTED(*msgp->im_msgbufs_send.im_bufs_mad_hdr))

	/* first query the portinfo to see if the lid changed */
	ibt_status = ibt_query_hca_ports_byguid(saa_portp->saa_pt_node_guid,
	    saa_portp->saa_pt_port_num, &ibt_portinfop, &nports, &size);

	if (ibt_status != IBT_SUCCESS)  {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_new_smlid_retry_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_new_smlid_retry: %s, ibmf_status ="
		    " %d\n", tnf_string, msg,
		    "ibt_query_hca_ports_byguid() failed",
		    tnf_int, ibt_status, ibt_status);

		ibmf_status = IBMF_TRANSPORT_FAILURE;

		goto bail;
	}

	master_sm_lid = ibt_portinfop->p_sm_lid;
	subnet_timeout = ibt_portinfop->p_subnet_timeout;

	ibt_free_portinfo(ibt_portinfop, size);

	/* if master smlid is different than the remote lid we sent to */
	if (master_sm_lid != msgp->im_local_addr.ia_remote_lid) {

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_impl_new_smlid_retry, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_new_smlid_retry: %s, new_lid 0x%x,"
		    " old_lid 0x%x\n", tnf_string, msg,
		    "master smlid has changed.  retrying msg_transport",
		    tnf_opaque, new_lid, master_sm_lid,
		    tnf_opaque, old_lid, msgp->im_local_addr.ia_remote_lid);

		mutex_enter(&saa_portp->saa_pt_mutex);

		/* update the master sm lid value in ibmf_saa */
		saa_portp->saa_pt_ibmf_addr_info.ia_remote_lid =
		    master_sm_lid;

		/* new tid needed */
		msgp->im_msgbufs_send.im_bufs_mad_hdr->TransactionID =
		    h2b64(saa_portp->saa_pt_current_tid++);

		bcopy(&saa_portp->saa_pt_ibmf_retrans, &ibmf_retrans,
		    sizeof (ibmf_retrans_t));

		/* update the subnet timeout since this may be a new sm/sa */
		saa_portp->saa_pt_timeout = subnet_timeout;

		/* place upper bound on subnet timeout in case of faulty SM */
		if (saa_portp->saa_pt_timeout > IBMF_SAA_MAX_SUBNET_TIMEOUT)
			saa_portp->saa_pt_timeout = IBMF_SAA_MAX_SUBNET_TIMEOUT;

		/* increment the reference count to account for the cpi call */
		saa_portp->saa_pt_reference_count++;

		mutex_exit(&saa_portp->saa_pt_mutex);

		/* update the remote lid for this particular message */
		msgp->im_local_addr.ia_remote_lid = master_sm_lid;

		/* get the classportinfo again since this may be a new sm/sa */
		ibmf_saa_impl_get_classportinfo(saa_portp);

		ibmf_status = ibmf_msg_transport(saa_portp->saa_pt_ibmf_handle,
		    saa_portp->saa_pt_qp_handle, msgp, &ibmf_retrans,
		    ibmf_callback, ibmf_callback_arg, transport_flags);

		if (ibmf_status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_impl_new_smlid_retry, IBMF_TNF_TRACE, "",
			    "ibmf_saa_impl_new_smlid_retry: %s, ibmf_status = "
			    "%d\n", tnf_string, msg,
			    "ibmf_msg_transport() failed",
			    tnf_int, ibmf_status, ibmf_status);
		}

		goto bail;
	}

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_new_smlid_retry, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_new_smlid_retry: %s, master_smlid = 0x%x\n",
	    tnf_string, msg,
	    "master smlid did not change.  returning failure",
	    tnf_opaque, master_smlid, master_sm_lid);

	/* mark status as timeout since that was original failure */
	ibmf_status = IBMF_TRANS_TIMEOUT;

bail:
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_new_smlid_retry_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_new_smlid_retry() exiting"
	    " ibmf_status = %d\n", tnf_int, result, ibmf_status);

	return (ibmf_status);
}

/*
 * ibmf_saa_impl_revert_to_qp1()
 *
 * The SA that we had contact with via redirect may fail to respond. If this
 * occurs SA should revert back to qp1 and the SMLID set in the port.
 * msg_transport for the message that timed out will be retried with
 * these new parameters.
 *
 * msgp, ibmf_callback, ibmf_callback_arg, and transport flags should be the
 * same values passed to the original ibmf_msg_transport that timedout.  The
 * ibmf_retrans parameter will be re-retrieved from the saa_portp structure.
 *
 * Input Arguments
 * saa_portp		pointer to saa_port structure
 * msgp			ibmf message that timedout
 * ibmf_callback	callback that should be called by msg_transport
 * ibmf_callback_arg	args for ibmf_callback
 * transport_flags	flags for ibmf_msg_transport
 *
 * Output Arguments
 * none
 *
 * Returns
 * none
 */
static int
ibmf_saa_impl_revert_to_qp1(saa_port_t *saa_portp, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ibmf_callback, void *ibmf_callback_args, int transport_flags)
{
	ibt_hca_portinfo_t	*ibt_portinfop;
	ib_lid_t		master_sm_lid, base_lid;
	uint8_t			sm_sl;
	int			subnet_timeout;
	uint_t			nports, size;
	ibmf_retrans_t		ibmf_retrans;
	int			ibmf_status;
	ibt_status_t		ibt_status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_revert_to_qp1_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_revert_to_qp1() enter\n");

	_NOTE(ASSUMING_PROTECTED(*msgp))
	_NOTE(ASSUMING_PROTECTED(*msgp->im_msgbufs_send.im_bufs_mad_hdr))

	/* first query the portinfo to see if the lid changed */
	ibt_status = ibt_query_hca_ports_byguid(saa_portp->saa_pt_node_guid,
	    saa_portp->saa_pt_port_num, &ibt_portinfop, &nports, &size);

	if (ibt_status != IBT_SUCCESS)  {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_revert_to_qp1_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_impl_revert_to_qp1: %s, ibmf_status ="
		    " %d\n", tnf_string, msg,
		    "ibt_query_hca_ports_byguid() failed",
		    tnf_int, ibt_status, ibt_status);

		ibmf_status = IBMF_TRANSPORT_FAILURE;

		goto bail;
	}

	master_sm_lid = ibt_portinfop->p_sm_lid;
	base_lid = ibt_portinfop->p_base_lid;
	sm_sl = ibt_portinfop->p_sm_sl;
	subnet_timeout = ibt_portinfop->p_subnet_timeout;

	ibt_free_portinfo(ibt_portinfop, size);


	mutex_enter(&saa_portp->saa_pt_mutex);

	saa_portp->saa_pt_redirect_active = B_FALSE;

	/* update the address info in ibmf_saa */
	saa_portp->saa_pt_ibmf_addr_info.ia_local_lid = base_lid;
	saa_portp->saa_pt_ibmf_addr_info.ia_remote_lid = master_sm_lid;
	saa_portp->saa_pt_ibmf_addr_info.ia_service_level = sm_sl;
	saa_portp->saa_pt_ibmf_addr_info.ia_remote_qno = 1;
	saa_portp->saa_pt_ibmf_addr_info.ia_p_key = IB_PKEY_DEFAULT_LIMITED;
	saa_portp->saa_pt_ibmf_addr_info.ia_q_key = IB_GSI_QKEY;
	saa_portp->saa_pt_ibmf_msg_flags = 0;

	/* new tid needed */
	msgp->im_msgbufs_send.im_bufs_mad_hdr->TransactionID =
	    h2b64(saa_portp->saa_pt_current_tid++);

	bcopy(&saa_portp->saa_pt_ibmf_retrans, &ibmf_retrans,
	    sizeof (ibmf_retrans_t));

	/* update the subnet timeout since this may be a new sm/sa */
	saa_portp->saa_pt_timeout = subnet_timeout;

	/* place upper bound on subnet timeout in case of faulty SM */
	if (saa_portp->saa_pt_timeout > IBMF_SAA_MAX_SUBNET_TIMEOUT)
		saa_portp->saa_pt_timeout = IBMF_SAA_MAX_SUBNET_TIMEOUT;

	/* increment the reference count to account for the cpi call */
	saa_portp->saa_pt_reference_count++;

	mutex_exit(&saa_portp->saa_pt_mutex);

	/* update the address info for this particular message */
	bcopy(&saa_portp->saa_pt_ibmf_addr_info, &msgp->im_local_addr,
	    sizeof (ibmf_addr_info_t));
	msgp->im_msg_flags = 0; /* No GRH */

	/* get the classportinfo again since this may be a new sm/sa */
	ibmf_saa_impl_get_classportinfo(saa_portp);

	ibmf_status = ibmf_msg_transport(saa_portp->saa_pt_ibmf_handle,
	    saa_portp->saa_pt_qp_handle, msgp, &ibmf_retrans,
	    ibmf_callback, ibmf_callback_args, transport_flags);

	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_impl_revert_to_qp1, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_revert_to_qp1: %s, ibmf_status = "
		    "%d\n", tnf_string, msg,
		    "ibmf_msg_transport() failed",
		    tnf_int, ibmf_status, ibmf_status);
	}

bail:

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_revert_to_qp1_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_revert_to_qp1() exiting"
	    " ibmf_status = %d\n", tnf_int, result, ibmf_status);

	return (ibmf_status);
}

/*
 * ibmf_saa_impl_async_event_cb:
 *	ibmf event callback, argument to ibmf_register
 *	ibmf_handle is unused
 */
/*  ARGSUSED */
static void
ibmf_saa_impl_async_event_cb(
	ibmf_handle_t		ibmf_handle,
	void			*clnt_private,
	ibmf_async_event_t	event_type)
{
	saa_port_t		*saa_portp;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_async_event_cb_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_async_event_cb: Handling event type 0x%x\n",
	    tnf_opaque, event_type, event_type);

	saa_portp = (saa_port_t *)clnt_private;
	ASSERT(saa_portp != NULL);

	switch (event_type) {

	case IBMF_CI_OFFLINE:
		ibmf_saa_impl_hca_detach(saa_portp);
		break;
	default:
		break;
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_async_event_cb_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_async_event_cb() exit\n");
}


/*
 * ibmf_saa_impl_ibt_async_handler:
 * MUST NOT BE STATIC (referred from within IBMF)
 */
void
ibmf_saa_impl_ibt_async_handler(ibt_async_code_t code, ibt_async_event_t *event)
{
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_ibt_async_handler_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_ibt_async_handler: Handling event code 0x%x\n",
	    tnf_opaque, code, code);

	switch (code) {

	case IBT_EVENT_PORT_UP:
		ibmf_saa_impl_port_up(event->ev_hca_guid, event->ev_port);
		break;
	case IBT_ERROR_PORT_DOWN:
		ibmf_saa_impl_port_down(event->ev_hca_guid, event->ev_port);
		break;
	default:
		break;
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_async_handler_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_ibt_async_handler() exit\n");
}

/*
 * ibmf_saa_impl_port_up:
 */
static void
ibmf_saa_impl_port_up(ib_guid_t ci_guid, uint8_t port_num)
{
	saa_port_t		*saa_portp	= NULL;
	int			is_ready;
	ibt_hca_portinfo_t	*ibt_portinfop;
	ib_lid_t		master_sm_lid;
	uint_t			nports, size;
	ibt_status_t		ibt_status;
	boolean_t		event_subs = B_FALSE;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_saa_impl_port_up_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_port_up: Handling port up"
	    " guid %016" PRIx64 " port %d\n",
	    tnf_opaque, hca_guid, ci_guid, tnf_uint, port, port_num);

	/* Get classportinfo of corresponding entry */
	mutex_enter(&saa_statep->saa_port_list_mutex);

	saa_portp = saa_statep->saa_port_list;
	while (saa_portp != NULL) {

		if (saa_portp->saa_pt_ibmf_reginfo.ir_ci_guid == ci_guid &&
		    saa_portp->saa_pt_ibmf_reginfo.ir_port_num == port_num) {

			mutex_enter(&saa_portp->saa_pt_mutex);

			is_ready = (saa_portp->saa_pt_state
			    == IBMF_SAA_PORT_STATE_READY) ? B_TRUE : B_FALSE;

			/*
			 * increment reference count to account for cpi and
			 * informinfos.  All 4 informinfo's sent are treated as
			 * one port client reference
			 */
			if (is_ready == B_TRUE)
				saa_portp->saa_pt_reference_count += 2;

			mutex_exit(&saa_portp->saa_pt_mutex);

			if (is_ready == B_TRUE)
				break; /* normally, only 1 port entry */
		}
		saa_portp = saa_portp->next;
	}

	mutex_exit(&saa_statep->saa_port_list_mutex);

	if (saa_portp != NULL && is_ready == B_TRUE) {

		/* verify whether master sm lid changed */

		/* first query the portinfo to see if the lid changed */
		ibt_status = ibt_query_hca_ports_byguid(ci_guid, port_num,
		    &ibt_portinfop, &nports, &size);

		if (ibt_status != IBT_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_saa_impl_port_up_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_impl_port_up: %s, ibmf_status ="
			    " %d\n", tnf_string, msg,
			    "ibt_query_hca_ports_byguid() failed",
			    tnf_int, ibt_status, ibt_status);

			goto bail;
		}

		master_sm_lid = ibt_portinfop->p_sm_lid;

		ibt_free_portinfo(ibt_portinfop, size);

		/* check whether we need to subscribe for events */
		mutex_enter(&saa_portp->saa_pt_event_sub_mutex);

		event_subs = (saa_portp->saa_pt_event_sub_client_list != NULL) ?
		    B_TRUE : B_FALSE;

		mutex_exit(&saa_portp->saa_pt_event_sub_mutex);

		/* update the master smlid */
		mutex_enter(&saa_portp->saa_pt_mutex);

		/* update the master sm lid value in ibmf_saa */
		saa_portp->saa_pt_ibmf_addr_info.ia_remote_lid =
		    master_sm_lid;

		/* if we're not subscribed for events, dec reference count */
		if (event_subs == B_FALSE)
			saa_portp->saa_pt_reference_count--;

		mutex_exit(&saa_portp->saa_pt_mutex);

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_port_up, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_port_up: %s, master_sm_lid = 0x%x\n",
		    tnf_string, msg,
		    "port is up.  Sending classportinfo request",
		    tnf_opaque, master_sm_lid, master_sm_lid);

		/* get the classportinfo again */
		ibmf_saa_impl_get_classportinfo(saa_portp);

		/*
		 * resubscribe to events if there are subscribers since SA may
		 * have removed our subscription records when the port went down
		 */
		if (event_subs == B_TRUE)
			ibmf_saa_subscribe_events(saa_portp, B_TRUE, B_FALSE);
	}

bail:

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_port_up_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_port_up() exit\n");
}

/*
 * ibmf_saa_impl_port_down:
 */
static void
ibmf_saa_impl_port_down(ib_guid_t ci_guid, uint8_t port_num)
{

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_saa_impl_port_down_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_port_down: Handling port down"
	    " guid %016" PRIx64 " port %d\n",
	    tnf_opaque, hca_guid, ci_guid, tnf_uint, port, port_num);


	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_port_down_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_port_down() exit\n");
}

/*
 * ibmf_saa_impl_hca_detach:
 * find entry, unregister if there are no clients
 * have to unregister since ibmf needs to close the hca and will only do this if
 * no clients are registered
 */
static void
ibmf_saa_impl_hca_detach(saa_port_t *saa_removed)
{
	saa_port_t 	*saa_portp;
	boolean_t	must_unreg, must_unsub;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_saa_impl_hca_detach_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_hca_detach: Detaching"
	    " entry %016" PRIx64 "\n", tnf_opaque, entry, saa_removed);

	/* find this entry */
	mutex_enter(&saa_statep->saa_port_list_mutex);

	saa_portp = saa_statep->saa_port_list;
	while (saa_portp != NULL) {

		if (saa_portp == saa_removed)
			break;

		saa_portp = saa_portp->next;
	}
	mutex_exit(&saa_statep->saa_port_list_mutex);

	ASSERT(saa_portp != NULL);

	if (saa_portp == NULL) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_hca_detach, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_hca_detach: %s, entry %016"
		    PRIx64 "\n",
		    tnf_string, msg,
		    "Port entry NOT found",
		    tnf_opaque, entryp, saa_removed);

		goto bail;
	}

	/* if there are clients expecting Reports(), unsusbscribe */
	mutex_enter(&saa_portp->saa_pt_event_sub_mutex);

	must_unsub = (saa_portp->saa_pt_event_sub_client_list != NULL) ?
	    B_TRUE : B_FALSE;

	mutex_exit(&saa_portp->saa_pt_event_sub_mutex);

	/* fail if outstanding transactions */
	mutex_enter(&saa_portp->saa_pt_mutex);

	if (saa_portp->saa_pt_num_outstanding_trans > 0) {

		IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_fini_err, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_fini: %s, port = %016" PRIx64
		    ", num transactions = %d\n",
		    tnf_string, msg, "Detaching HCA."
		    "  Outstanding transactions on port.",
		    tnf_opaque, port,
		    saa_portp->saa_pt_port_guid,
		    tnf_uint, outstanding_transactions,
		    saa_portp->saa_pt_num_outstanding_trans);

		mutex_exit(&saa_portp->saa_pt_mutex);

		goto bail;
	}


	/*
	 * increment reference count by one to account for unsubscribe requests
	 * that are about to be sent.  All four informinfo's are treated as one
	 * port client reference.  The count will be decremented by
	 * subscribe_events() before the call returns.
	 */
	if (must_unsub == B_TRUE)
		saa_portp->saa_pt_reference_count++;

	mutex_exit(&saa_portp->saa_pt_mutex);

	/*
	 * try and unsubscribe from SA.  Generate synchronous, unsequenced
	 * unsubscribe requests.
	 */
	if (must_unsub == B_TRUE)
		ibmf_saa_subscribe_events(saa_portp, B_FALSE, B_TRUE);

	/* warning if registered clients */
	mutex_enter(&saa_portp->saa_pt_mutex);

	if (saa_portp->saa_pt_reference_count > 0) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_hca_detach, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_hca_detach: %s, port %016"
		    PRIx64 "\n",
		    tnf_string, msg,
		    "Detaching HCA for port with clients still"
		    " registered", tnf_opaque, port,
		    saa_portp->saa_pt_port_guid);
	}

	/* synchronize on end of registration */
	while (saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_REGISTERING) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_hca_detach, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_hca_detach: %s\n",
		    tnf_string, msg, "someone is registering. waiting"
		    " for them to finish");

		cv_wait(&saa_portp->saa_pt_ibmf_reg_cv,
		    &saa_portp->saa_pt_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_hca_detach,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_hca_detach: %s\n",
		    tnf_string, msg, "done waiting");
	}

	/* unregister from ibmf */
	if (saa_portp->saa_pt_state == IBMF_SAA_PORT_STATE_READY) {
		must_unreg = B_TRUE;
	} else
		must_unreg = B_FALSE;

	ibmf_saa_impl_invalidate_port(saa_portp);

	mutex_exit(&saa_portp->saa_pt_mutex);

	if (must_unreg == B_TRUE) {
		if (ibmf_saa_impl_ibmf_unreg(saa_portp) != IBMF_SUCCESS) {
			mutex_enter(&saa_portp->saa_pt_mutex);
			mutex_enter(&saa_portp->saa_pt_kstat_mutex);
			(void) ibmf_saa_impl_init_kstats(saa_portp);
			mutex_exit(&saa_portp->saa_pt_kstat_mutex);
			saa_portp->saa_pt_state = IBMF_SAA_PORT_STATE_READY;
			if (must_unsub == B_TRUE)
				saa_portp->saa_pt_reference_count++;
			mutex_exit(&saa_portp->saa_pt_mutex);

			if (must_unsub == B_TRUE) {
				ibmf_saa_subscribe_events(saa_portp, B_TRUE,
				    B_FALSE);
			}
		}
	}
bail:
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_saa_impl_hca_detach_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_hca_detach() exit\n");
}

/* ARGSUSED */
void
ibmf_saa_async_cb(ibmf_handle_t ibmf_handle, ibmf_msg_t *msgp, void *args)
{
	saa_impl_trans_info_t	*trans_info;
	int			status;
	size_t			length;
	void			*result;
	saa_port_t		*saa_portp;
	saa_client_data_t	*client_data;
	int			ibmf_status;
	boolean_t		ignore_data;
	ibmf_retrans_t		ibmf_retrans;
	boolean_t		sa_is_redirected = B_FALSE;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_async_cb_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_async_cb() enter\n");

	trans_info = (saa_impl_trans_info_t *)args;

	client_data = trans_info->si_trans_client_data;
	saa_portp   = trans_info->si_trans_port;

	mutex_enter(&saa_portp->saa_pt_mutex);
	sa_is_redirected = saa_portp->saa_pt_redirect_active;
	mutex_exit(&saa_portp->saa_pt_mutex);

	if ((msgp->im_msg_status == IBMF_TRANS_TIMEOUT) &&
	    (sa_is_redirected == B_TRUE)) {

		/*
		 * We should retry the request using SM_LID and QP1 if we
		 * have been using redirect up until now
		 */
		ibmf_status = ibmf_saa_impl_revert_to_qp1(
		    saa_portp, msgp, ibmf_saa_async_cb, args,
		    trans_info->si_trans_transport_flags);

		/*
		 * If revert_to_qp1 returns success msg was resent.
		 * Otherwise msg could not be resent. Continue normally
		 */
		if (ibmf_status == IBMF_SUCCESS)
			goto bail;

	} else if (msgp->im_msg_status == IBMF_TRANS_TIMEOUT) {


		ibmf_status = ibmf_saa_impl_new_smlid_retry(saa_portp, msgp,
		    ibmf_saa_async_cb, args,
		    trans_info->si_trans_transport_flags);

		/*
		 * if smlid_retry() returns success sm lid changed and msg
		 * was resent.  Otherwise, lid did not change or msg could not
		 * be resent.  Continue normally.
		 */
		if (ibmf_status == IBMF_SUCCESS)
			goto bail;

		/*
		 * check whether we've received anything from the SA in a while.
		 * If we have, this function will retry and return success.  If
		 * we haven't continue normally so that we return a timeout to
		 * the client
		 */
		ibmf_status = ibmf_saa_check_sa_and_retry(
		    saa_portp, msgp, ibmf_saa_async_cb, args,
		    trans_info->si_trans_send_time,
		    trans_info->si_trans_transport_flags);

		if (ibmf_status == IBMF_SUCCESS)
			goto bail;
	}

	/*
	 * If SA returned success but mad status is busy, retry a few times.
	 * If SA returned success but mad status says redirect is required,
	 * update the address info and retry the request to the new SA address
	 */
	if (msgp->im_msg_status == IBMF_SUCCESS) {

		ASSERT(msgp->im_msgbufs_recv.im_bufs_mad_hdr != NULL);

		if ((b2h16(msgp->im_msgbufs_recv.im_bufs_mad_hdr->Status) ==
		    MAD_STATUS_BUSY) &&
		    (trans_info->si_trans_retry_busy_count <
		    IBMF_SAA_MAX_BUSY_RETRY_COUNT)) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_async_cb, IBMF_TNF_TRACE, "",
			    "ibmf_saa_async_cb: %s, retry_count = %d\n",
			    tnf_string, msg,
			    "async response returned busy status",
			    tnf_int, retry_count,
			    trans_info->si_trans_retry_busy_count);

			trans_info->si_trans_retry_busy_count++;

			bcopy(&saa_portp->saa_pt_ibmf_retrans, &ibmf_retrans,
			    sizeof (ibmf_retrans_t));

			ibmf_status = ibmf_msg_transport(
			    saa_portp->saa_pt_ibmf_handle,
			    saa_portp->saa_pt_qp_handle, msgp, &ibmf_retrans,
			    ibmf_saa_async_cb, args,
			    trans_info->si_trans_transport_flags);

			/*
			 * if retry is successful, quit here since async_cb will
			 * get called again; otherwise, let this function call
			 * handle the cleanup
			 */
			if (ibmf_status == IBMF_SUCCESS)
				goto bail;
		} else if (b2h16(msgp->im_msgbufs_recv.im_bufs_mad_hdr->Status)
		    == MAD_STATUS_REDIRECT_REQUIRED) {

			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_async_cb, IBMF_TNF_TRACE, "",
			    "ibmf_saa_async_cb: "
			    "async response returned redirect status\n");

			/* update address info and copy it into msgp */
			ibmf_saa_impl_update_sa_address_info(saa_portp, msgp);

			/* retry with new address info */
			bcopy(&saa_portp->saa_pt_ibmf_retrans, &ibmf_retrans,
			    sizeof (ibmf_retrans_t));

			ibmf_status = ibmf_msg_transport(
			    saa_portp->saa_pt_ibmf_handle,
			    saa_portp->saa_pt_qp_handle, msgp, &ibmf_retrans,
			    ibmf_saa_async_cb, args,
			    trans_info->si_trans_transport_flags);

			/*
			 * if retry is successful, quit here since async_cb will
			 * get called again; otherwise, let this function call
			 * handle the cleanup
			 */
			if (ibmf_status == IBMF_SUCCESS)
				goto bail;
		}
	}

	mutex_enter(&saa_portp->saa_pt_mutex);

	ASSERT(saa_portp->saa_pt_num_outstanding_trans > 0);
	saa_portp->saa_pt_num_outstanding_trans--;

	mutex_exit(&saa_portp->saa_pt_mutex);

	if ((trans_info->si_trans_callback == NULL) &&
	    (trans_info->si_trans_sub_callback == NULL))
		ignore_data = B_TRUE;
	else
		ignore_data = B_FALSE;

	ibmf_saa_impl_prepare_response(ibmf_handle, msgp, ignore_data, &status,
	    &result, &length, B_FALSE);

	mutex_enter(&saa_portp->saa_pt_kstat_mutex);

	IBMF_SAA_SUB32_KSTATS(saa_portp, outstanding_requests, 1);

	if (status != IBMF_SUCCESS)
		IBMF_SAA_ADD32_KSTATS(saa_portp, failed_requests, 1);

	if (status == IBMF_TRANS_TIMEOUT)
		IBMF_SAA_ADD32_KSTATS(saa_portp, requests_timedout, 1);

	mutex_exit(&saa_portp->saa_pt_kstat_mutex);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_async_cb, IBMF_TNF_TRACE, "",
	    "ibmf_saa_async_cb: %s\n", tnf_string, msg,
	    "Calling ibmf_saa client's callback");

	/*
	 * there are three classes or trans_info users: ibmf_saa clients and
	 * classportinfo requests; informinfo subscribe requests, and report
	 * responses.  For the first two, call the correct callback.  For report
	 * responses there's no need to notify anyone.
	 */
	if (trans_info->si_trans_callback != NULL) {
		/* ibmf_saa client or classportinfo request */
		trans_info->si_trans_callback(trans_info->si_trans_callback_arg,
		    length, result, status);
	} else if (trans_info->si_trans_sub_callback != NULL) {
		/* informinfo subscribe request */
		trans_info->si_trans_sub_callback(
		    trans_info->si_trans_callback_arg, length, result, status,
		    trans_info->si_trans_sub_producer_type);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_async_cb, IBMF_TNF_TRACE, "",
	    "ibmf_saa_async_cb: %s\n", tnf_string, msg,
	    "Returned from callback");

	if (client_data != NULL) {
		mutex_enter(&client_data->saa_client_mutex);

		ASSERT(client_data->saa_client_num_pending_trans > 0);
		client_data->saa_client_num_pending_trans--;

		if ((client_data->saa_client_num_pending_trans == 0) &&
		    (client_data->saa_client_state == SAA_CLIENT_STATE_WAITING))
			cv_signal(&client_data->saa_client_state_cv);

		mutex_exit(&client_data->saa_client_mutex);
	}

	kmem_free(trans_info, sizeof (saa_impl_trans_info_t));

bail:

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_async_cb_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_async_cb() exit\n");
}

/*
 * ibmf_saa_check_sa_and_retry:
 *
 * If a particular transaction times out, we don't want to give up if we know
 * the SA is responding.  Check the time since we last received a response. If
 * it's less than ibmf_saa_max_wait_time retry the request.
 *
 * msgp, ibmf_callback, ibmf_callback_arg, and transport flags should be the
 * same values passed to the original ibmf_msg_transport that timed out.  The
 * ibmf_retrans parameter will be re-retrieved from the saa_portp structure.
 *
 * If max_wait_time seconds have passed, this function returns IBMF_TIMEOUT.
 * That way, callers can simply return the result of this function.
 *
 * Input Arguments
 * saa_portp		pointer to saa_port structure
 * msgp			ibmf message that timedout
 * ibmf_callback	callback that should be called by msg_transport
 * ibmf_callback_arg	args for ibmf_callback
 * transport_flags	flags for ibmf_msg_transport
 *
 * Output Arguments
 * none
 *
 * Returns
 * IBMF_SUCCESS if we've recently received data from the SA and request was
 * resent.
 * IBMF_TRANS_TIMEOUT if no data has been received from the SA in max_wait_time
 * same values as ibmf_msg_transport() if data has been received but request
 * could not be resent.
 */
static int
ibmf_saa_check_sa_and_retry(saa_port_t *saa_portp, ibmf_msg_t *msgp,
    ibmf_msg_cb_t ibmf_callback, void *ibmf_callback_arg,
    hrtime_t trans_send_time, int transport_flags)
{
	hrtime_t		curr_time, sa_uptime;
	ibmf_retrans_t		ibmf_retrans;
	int			ibmf_status;

	do {

		mutex_enter(&saa_portp->saa_pt_mutex);

		sa_uptime = saa_portp->saa_pt_sa_uptime;

		/* if nothing received from SA since we sent */
		curr_time = gethrtime();

		/*
		 * check if it's been a very long time since this
		 * particular transaction was sent
		 */
		if (((curr_time - trans_send_time) / 1000000000) >
		    ibmf_saa_trans_wait_time) {

			mutex_exit(&saa_portp->saa_pt_mutex);

			IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_saa_check_sa_and_retry_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_check_sa_and_retry: %s, msgp = "
			    "%p sa_uptime = %" PRIu64 ", trans send time = %"
			    PRIu64 ", curr_time = %" PRIu64 "\n",
			    tnf_string, msg,
			    "Nothing received for this transaction",
			    tnf_opaque, msgp, msgp,
			    tnf_long, sa_uptime, sa_uptime,
			    tnf_long, trans_send_time, trans_send_time,
			    tnf_long, curr_time, curr_time);

			ibmf_status = IBMF_TRANS_TIMEOUT;

			break;
		}

		/*
		 * check time since we received something,
		 * and make sure that it hasn't been an extra long
		 * time for this particular transaction
		 */
		if (((curr_time - sa_uptime) / 1000000000) <
		    ibmf_saa_max_wait_time) {

			IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_check_sa_and_retry, IBMF_TNF_TRACE, "",
			    "ibmf_saa_check_sa_and_retry: %s, msgp = "
			    "%p sa_uptime = %" PRIu64 " trans_send_time = %"
			    PRIu64 " curr_time = %" PRIu64 "\n",
			    tnf_string, msg, "Something received.  Retrying",
			    tnf_opaque, msgp, msgp,
			    tnf_long, sa_uptime, sa_uptime,
			    tnf_long, trans_send_time, trans_send_time,
			    tnf_long, curr_time, curr_time);

			/*
			 * something received in WAIT_TIME_IN_SECS;
			 * resend request
			 */

			/* new tid needed */
			msgp->im_msgbufs_send.im_bufs_mad_hdr->TransactionID =
			    h2b64(saa_portp->saa_pt_current_tid++);

			bcopy(&saa_portp->saa_pt_ibmf_retrans,
			    &ibmf_retrans, sizeof (ibmf_retrans_t));

			mutex_exit(&saa_portp->saa_pt_mutex);

			ibmf_status = ibmf_msg_transport(
			    saa_portp->saa_pt_ibmf_handle,
			    saa_portp->saa_pt_qp_handle, msgp,
			    &ibmf_retrans, ibmf_callback, ibmf_callback_arg,
			    transport_flags);

			if (ibmf_status == IBMF_SUCCESS)
				goto bail;

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
			    ibmf_saa_check_sa_and_retry, IBMF_TNF_TRACE, "",
			    "ibmf_saa_check_sa_and_retry: %s, ibmf_status = "
			    "%d\n", tnf_string, msg,
			    "ibmf_msg_transport() failed",
			    tnf_int, ibmf_status, ibmf_status);
		} else {

			mutex_exit(&saa_portp->saa_pt_mutex);

			IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_saa_check_sa_and_retry_err, IBMF_TNF_ERROR, "",
			    "ibmf_saa_check_sa_and_retry: %s, msgp = "
			    "%p sa_uptime = %" PRIu64 " curr_time = %"
			    PRIu64 "\n", tnf_string, msg,
			    "Nothing received.  Timing out",
			    tnf_opaque, msgp, msgp,
			    tnf_long, sa_uptime, sa_uptime,
			    tnf_long, curr_time, curr_time);

			ibmf_status = IBMF_TRANS_TIMEOUT;

			break;
		}
	} while (ibmf_status == IBMF_TRANS_TIMEOUT);

bail:
	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_check_sa_and_retry_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_check_sa_and_retry() exiting"
	    " ibmf_status = %d\n", tnf_int, result, ibmf_status);

	return (ibmf_status);
}


/*
 * ibmf_saa_impl_prepare_response:
 */
static void
ibmf_saa_impl_prepare_response(ibmf_handle_t ibmf_handle,
    ibmf_msg_t *msgp, boolean_t ignore_data, int *status, void **result,
    size_t *length, boolean_t sleep_flag)
{
	ibmf_msg_bufs_t	*resp_buf;
	uint16_t	attr_id;
	uint8_t		method;
	boolean_t	is_get_resp;
	uint16_t	mad_status;
	uint16_t	attr_offset;
	ib_sa_hdr_t	*sa_hdr;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_prepare_response_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_prepare_response() enter\n");

	_NOTE(ASSUMING_PROTECTED(*msgp))

	*result = NULL;
	*length = 0;
	sa_hdr = NULL;

	resp_buf = &msgp->im_msgbufs_recv;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*resp_buf))

	if (msgp->im_msg_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_impl_prepare_response, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_prepare_response: %s, msg_status = %d\n",
		    tnf_string, msg, "Bad ibmf status",
		    tnf_int, msg_status, msgp->im_msg_status);

		*status = msgp->im_msg_status;

		goto exit;
	}

	if (resp_buf->im_bufs_mad_hdr == NULL) {

		/*
		 * this was an unsequenced transaction (from an unsubscribe for
		 * following a CI_OFFLINE event)
		 */
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_prepare_response, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_prepare_response: %s\n",
		    tnf_string, msg, "Unsequenced transaction callback");

		goto exit;
	}

	if ((mad_status = b2h16(resp_buf->im_bufs_mad_hdr->Status)) !=
	    MAD_STATUS_NO_INVALID_FIELDS) {

		/* convert mad packet status to IBMF status */
		switch (mad_status) {

			case SA_STATUS_ERR_NO_RESOURCES:
				*status = IBMF_NO_RESOURCES;
				break;
			case SA_STATUS_ERR_REQ_INVALID:
				*status = IBMF_REQ_INVALID;
				break;
			case SA_STATUS_ERR_NO_RECORDS:
				*status = IBMF_NO_RECORDS;
				break;
			case SA_STATUS_ERR_TOO_MANY_RECORDS:
				*status = IBMF_TOO_MANY_RECORDS;
				break;
			case SA_STATUS_ERR_REQ_INVALID_GID:
				*status = IBMF_INVALID_GID;
				break;
			case SA_STATUS_ERR_REQ_INSUFFICIENT_COMPONENTS:
				*status = IBMF_INSUFF_COMPS;
				break;
			case MAD_STATUS_UNSUPP_METHOD:
				*status = IBMF_UNSUPP_METHOD;
				break;
			case MAD_STATUS_UNSUPP_METHOD_ATTR:
				*status = IBMF_UNSUPP_METHOD_ATTR;
				break;
			case MAD_STATUS_INVALID_FIELD:
				*status = IBMF_INVALID_FIELD;
				break;
			default:
				*status = IBMF_REQ_INVALID;
				break;
		}

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_impl_prepare_response, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_prepare_response: %s, mad_status = %x\n",
		    tnf_string, msg, "Bad MAD status",
		    tnf_int, mad_status, mad_status);

		goto exit;
	}

	attr_id = b2h16(resp_buf->im_bufs_mad_hdr->AttributeID);
	method = resp_buf->im_bufs_mad_hdr->R_Method;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_prepare_response, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_prepare_response: attr_id = 0x%x, method = "
	    "0x%x\n",
	    tnf_opaque, attr_id, attr_id,
	    tnf_opaque, method, method);

	/*
	 * ignore any data from deleteresp since there's no way to know whether
	 * real data was returned; also ignore data if this was a Report
	 * response
	 */
	if (method == SA_SUBN_ADM_DELETE_RESP) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_prepare_response, IBMF_TNF_TRACE, "",
		    "impf_saa_impl_prepare_response: %s\n",
		    tnf_string, msg,
		    "DeleteResp or NoticeResp returned.  "
		    "Ignoring response data");

		*status = IBMF_SUCCESS;

		*length = 0;
		*result = NULL;

		goto exit;
	}

	if (attr_id == SA_MULTIPATHRECORD_ATTRID) {

		/*
		 * getmulti is only for requests; attribute should not
		 * be returned from SA
		 */
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_impl_prepare_response_err, IBMF_TNF_ERROR,
		    "", "ibmf_saa_impl_prepare_response: %s\n",
		    tnf_string, msg, "SA returned getmulti record");

		*status = IBMF_REQ_INVALID;

		goto exit;
	}

	/* if we are supposed to ignore data, stop here */
	if (ignore_data == B_TRUE) {

		*status = IBMF_SUCCESS;

		goto exit;
	}

	is_get_resp = resp_buf->im_bufs_mad_hdr->R_Method ==
	    SA_SUBN_ADM_GET_RESP ? B_TRUE: B_FALSE;

	/* unpack the sa header to get the attribute offset */
	*status = ibmf_saa_utils_unpack_sa_hdr(resp_buf->im_bufs_cl_hdr,
	    resp_buf->im_bufs_cl_hdr_len, &sa_hdr, sleep_flag);
	if (*status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_prepare_response_err,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_prepare_response: %s,"
		    " ibmf_status = %d\n", tnf_string, msg,
		    "Could not unpack sa hdr", tnf_int, ibmf_status, *status);

		goto exit;
	}

	attr_offset = sa_hdr->AttributeOffset;

	/*
	 * unpack data payload; if unpack function doesn't return success
	 * (because it could not allocate memory) forward this status to waiting
	 * client
	 */
	*status = ibmf_saa_utils_unpack_payload(resp_buf->im_bufs_cl_data,
	    resp_buf->im_bufs_cl_data_len, attr_id, result, length,
	    attr_offset, is_get_resp, sleep_flag);
	if (*status == IBMF_SUCCESS) {

		IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_saa_impl_prepare_response,
		    IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_prepare_response: attr_id = "
		    "0x%x, attr_offset = %d, packed_payload_len = %d, "
		    "unpacked_payload_len = %d\n",
		    tnf_opaque, attr_id, attr_id,
		    tnf_opaque, attr_offset, attr_offset,
		    tnf_opaque, packed_payload_len,
		    resp_buf->im_bufs_cl_data_len,
		    tnf_opaque, unpacked_payload_len, *length);
	} else {

		IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_prepare_response_err,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_prepare_response: %s,"
		    "attr_id = 0x%x, attr_offset = %d, packed_payload_len = %d,"
		    "status = %d\n",
		    tnf_string, msg, "Could not unpack payload",
		    tnf_opaque, attr_id, attr_id,
		    tnf_int, attr_offset, attr_offset,
		    tnf_int, packed_payload_len,
		    resp_buf->im_bufs_cl_data_len,
		    tnf_int, status, *status);
	}
exit:
	if (sa_hdr != NULL)
		kmem_free(sa_hdr, sizeof (ib_sa_hdr_t));

	ibmf_saa_impl_free_msg(ibmf_handle, msgp);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_prepare_response_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_prepare_response() exit,"
	    " status = 0x%d\n", tnf_int, status, *status);
}


/*
 * ibmf_saa_impl_check_sa_support:
 * Checks the capability mask (returned from the SA classportinfo response) to
 * determine whether the sa supports the specified attribute ID.
 *
 * Input Arguments
 * cap_mask	16-bit capability mask returned in SA's classportinfo
 * attr_id	attribute ID of current request
 *
 * Returns
 * IBMF_NOT_SUPPORTED if capability mask indicates SA does not support attribute
 * IBMF_SUCCESS otherwise
 */
static int
ibmf_saa_impl_check_sa_support(uint16_t cap_mask, uint16_t attr_id)
{
	boolean_t	attr_supported = B_TRUE;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_check_sa_support, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_check_sa_support: cap_mask = 0x%x, "
	    "attr_id = 0x%x\n", tnf_opaque, cap_mask, cap_mask,
	    tnf_opaque, attr_id, attr_id);

	switch (attr_id) {

		case SA_SWITCHINFORECORD_ATTRID:
		case SA_LINEARFDBRECORD_ATTRID:
		case SA_RANDOMFDBRECORD_ATTRID:
		case SA_MULTICASTFDBRECORD_ATTRID:
		case SA_SMINFORECORD_ATTRID:
		case SA_INFORMINFORECORD_ATTRID:
		case SA_LINKRECORD_ATTRID:
		case SA_GUIDINFORECORD_ATTRID:
		case SA_TRACERECORD_ATTRID:
		case SA_SERVICEASSNRECORD_ATTRID:

			if ((cap_mask &
			    SA_CAPMASK_OPT_RECORDS_SUPPORTED) == 0) {

				IBMF_TRACE_3(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_saa_impl_check_sa_support,
				    IBMF_TNF_ERROR, "",
				    "ibmf_saa_impl_check_sa_support: %s, "
				    "cap_mask = 0x%x\n", tnf_string, msg,
				    "SA does not support optional records",
				    tnf_opaque, cap_mask, cap_mask,
				    tnf_opaque, attr_id, attr_id);

				attr_supported = B_FALSE;
			}
			break;

		case SA_MULTIPATHRECORD_ATTRID:

			if ((cap_mask & SA_CAPMASK_MULTIPATH_SUPPORTED) == 0) {

				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_saa_impl_check_sa_support,
				    IBMF_TNF_ERROR, "",
				    "ibmf_saa_impl_check_sa_support: %s, "
				    "cap_mask = 0x%x\n", tnf_string, msg,
				    "SA does not support multipath records",
				    tnf_opaque, cap_mask, cap_mask);

				attr_supported = B_FALSE;
			}
			break;

		case SA_MCMEMBERRECORD_ATTRID:

			if ((cap_mask & SA_CAPMASK_UD_MCAST_SUPPORTED) == 0) {

				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_saa_impl_check_sa_support,
				    IBMF_TNF_ERROR, "",
				    "ibmf_saa_impl_check_sa_support: %s, "
				    "cap_mask = 0x%x\n", tnf_string, msg,
				    "SA does not support ud multicast",
				    tnf_opaque, cap_mask, cap_mask);

				attr_supported = B_FALSE;
			}
			break;

		default:
			break;
	} /* switch */

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_check_sa_support_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_check_sa_support() exiting, attr_supported = %d\n",
	    tnf_opaque, attr_supported, attr_supported);

	if (attr_supported == B_FALSE)
		return (IBMF_UNSUPP_METHOD_ATTR);
	else
		return (IBMF_SUCCESS);
}

/*
 * ibmf_saa_impl_get_attr_id_length:
 *
 * Returns the host size of the specified sa record.  Returns 0 for unknown
 * attributes.  multipath record size is a dynamic value given as a parameter
 * specified with the ibmf_sa_access() call.
 */
static uint_t
ibmf_saa_impl_get_attr_id_length(uint16_t attr_id)
{
	uint_t	attr_length;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_get_attr_id_length_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_attr_id_length() enter\n");

	/* this function should not be used for multipath record */
	ASSERT(attr_id != SA_MULTIPATHRECORD_ATTRID);

	switch (attr_id) {
		case SA_CLASSPORTINFO_ATTRID:
			attr_length = sizeof (ib_mad_classportinfo_t);
			break;
		case SA_NOTICE_ATTRID:
			attr_length = sizeof (ib_mad_notice_t);
			break;
		case SA_INFORMINFO_ATTRID:
			attr_length = sizeof (ib_mad_informinfo_t);
			break;
		case SA_NODERECORD_ATTRID:
			attr_length = sizeof (sa_node_record_t);
			break;
		case SA_PORTINFORECORD_ATTRID:
			attr_length = sizeof (sa_portinfo_record_t);
			break;
		case SA_SLTOVLRECORD_ATTRID:
			attr_length = sizeof (sa_SLtoVLmapping_record_t);
			break;
		case SA_SWITCHINFORECORD_ATTRID:
			attr_length = sizeof (sa_switchinfo_record_t);
			break;
		case SA_LINEARFDBRECORD_ATTRID:
			attr_length = sizeof (sa_linearft_record_t);
			break;
		case SA_RANDOMFDBRECORD_ATTRID:
			attr_length = sizeof (sa_randomft_record_t);
			break;
		case SA_MULTICASTFDBRECORD_ATTRID:
			attr_length = sizeof (sa_multicastft_record_t);
			break;
		case SA_SMINFORECORD_ATTRID:
			attr_length = sizeof (sa_sminfo_record_t);
			break;
		case SA_INFORMINFORECORD_ATTRID:
			attr_length = sizeof (sa_informinfo_record_t);
			break;
		case SA_LINKRECORD_ATTRID:
			attr_length = sizeof (sa_link_record_t);
			break;
		case SA_GUIDINFORECORD_ATTRID:
			attr_length = sizeof (sa_guidinfo_record_t);
			break;
		case SA_SERVICERECORD_ATTRID:
			attr_length = sizeof (sa_service_record_t);
			break;
		case SA_PARTITIONRECORD_ATTRID:
			attr_length = sizeof (sa_pkey_table_record_t);
			break;
		case SA_PATHRECORD_ATTRID:
			attr_length = sizeof (sa_path_record_t);
			break;
		case SA_VLARBRECORD_ATTRID:
			attr_length = sizeof (sa_VLarb_table_record_t);
			break;
		case SA_MCMEMBERRECORD_ATTRID:
			attr_length = sizeof (sa_mcmember_record_t);
			break;
		case SA_TRACERECORD_ATTRID:
			attr_length = sizeof (sa_trace_record_t);
			break;
		case SA_SERVICEASSNRECORD_ATTRID:
			attr_length = sizeof (sa_service_assn_record_t);
			break;
		default:
			/* should only get the above type of packets */
			attr_length = 0;
			break;
	}

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_get_attr_id_length_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_attr_id_length():"
	    " attr_id: 0x%x size %d\n",
	    tnf_opaque, attr_id, attr_id, tnf_uint, attr_length, attr_length);

	return (attr_length);
}

/*
 * ibmf_saa_impl_free_msg:
 * Takes a completed message and free memory associated with the message,
 * including the individual fields of the im_msgbufs_send.
 * ibmf_free_msg, called at the end of this function, takes a pointer to the
 * message pointer so that it can set the message pointer to NULL.  This
 * function takes just the message pointer so the msgp will not be NULL after
 * this function returns.
 *
 * Input Arguments
 * ibmf_hdl	ibmf handle used in ibmf_msg_alloc
 * msgp		pointer to ibmf_msg_t to free
 *
 * Returns
 * void
 */
static void
ibmf_saa_impl_free_msg(ibmf_handle_t ibmf_hdl, ibmf_msg_t *msgp)
{
	int	res;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_free_msg_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_free_msg() enter: msg %p\n",
	    tnf_opaque, msg, msgp);

	ASSERT(msgp != NULL);

	kmem_free(msgp->im_msgbufs_send.im_bufs_mad_hdr,
	    sizeof (ib_mad_hdr_t));

	kmem_free(msgp->im_msgbufs_send.im_bufs_cl_hdr,
	    msgp->im_msgbufs_send.im_bufs_cl_hdr_len);

	if (msgp->im_msgbufs_send.im_bufs_cl_data_len > 0)
		kmem_free(msgp->im_msgbufs_send.im_bufs_cl_data,
		    msgp->im_msgbufs_send.im_bufs_cl_data_len);

	res = ibmf_free_msg(ibmf_hdl, &msgp);
	ASSERT(res == IBMF_SUCCESS);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_free_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_free_msg() exit\n");
}

/*
 * ibmf_saa_impl_get_port_guid:
 */
static int
ibmf_saa_impl_get_port_guid(ibt_hca_portinfo_t *ibt_portinfop,
    ib_guid_t *guid_ret)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_get_port_guid_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_get_port_guid() enter\n");

	if (ibt_portinfop->p_linkstate != IBT_PORT_ACTIVE) {

		return (IBMF_BAD_PORT_STATE);
	}

	if (ibt_portinfop->p_sgid_tbl_sz == 0) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L2,
		    ibmf_saa_impl_get_port_guid_end, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_get_port_guid: %s\n", tnf_string, msg,
		    "portinfo sgid table size is 0. Exiting.\n");

		return (IBMF_TRANSPORT_FAILURE);
	}

	*guid_ret = ibt_portinfop->p_sgid_tbl[0].gid_guid;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_get_port_guid_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_get_port_guid: Returning port_guid %016" PRIx64 "\n",
	    tnf_opaque, port_guid, *guid_ret);

	return (IBMF_SUCCESS);
}

/*
 * ibmf_saa_impl_set_transaction_params:
 */
static void
ibmf_saa_impl_set_transaction_params(saa_port_t *saa_portp,
    ibt_hca_portinfo_t *portinfop)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_set_transaction_params_start,
	    IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_set_transaction_params() enter\n");

	_NOTE(ASSUMING_PROTECTED(*saa_portp))

	saa_portp->saa_pt_ibmf_retrans.retrans_retries =
	    IBMF_SAA_RETRANS_RETRIES;
	/*
	 * For the first transaction (generally getting the
	 * classportinfo) have ibmf pick our timeouts.  It should be using the
	 * default IB spec values.
	 * Once we get the classportinfo we'll update the correct response time
	 * value (rtv) and round-trip time (rttv).  ibmf should always calculate
	 * trans_to since it depends on the particular transaction's number of
	 * packets.
	 */
	saa_portp->saa_pt_ibmf_retrans.retrans_rtv = 0;
	saa_portp->saa_pt_ibmf_retrans.retrans_rttv = 0;
	saa_portp->saa_pt_ibmf_retrans.retrans_trans_to = 0;

	/*
	 * Assume that the SA supports all optional records. If it
	 * does not, the request will get returned with ERR_NOT_SUPP.  When
	 * the classportinfo response comes back we will update the cap mask
	 * to prevent unnecessary unsupported requests.
	 */
	saa_portp->saa_pt_sa_cap_mask = 0xFFFF;

	saa_portp->saa_pt_ibmf_msg_flags = 0;
	saa_portp->saa_pt_ibmf_addr_info.ia_remote_qno 	= 1;
	saa_portp->saa_pt_ibmf_addr_info.ia_p_key 	=
	    IB_PKEY_DEFAULT_LIMITED;
	saa_portp->saa_pt_ibmf_addr_info.ia_q_key 	= IB_GSI_QKEY;

	/*
	 * fill out addr information for MADs that will be sent
	 * to SA on this port
	 */
	saa_portp->saa_pt_ibmf_addr_info.ia_local_lid 	= portinfop->p_base_lid;
	saa_portp->saa_pt_ibmf_addr_info.ia_remote_lid 	= portinfop->p_sm_lid;
	saa_portp->saa_pt_ibmf_addr_info.ia_service_level = portinfop->p_sm_sl;

	/* place upper bound on subnet timeout in case of faulty SM */
	saa_portp->saa_pt_timeout = portinfop->p_subnet_timeout;

	if (saa_portp->saa_pt_timeout > IBMF_SAA_MAX_SUBNET_TIMEOUT) {

		saa_portp->saa_pt_timeout = IBMF_SAA_MAX_SUBNET_TIMEOUT;
	}

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_impl_set_transaction_params,
	    IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_set_transaction_params: local_lid = 0x%x, "
	    "sm_lid = 0x%x, sm_sl = 0x%x, sn_timeout = 0x%x\n",
	    tnf_opaque, local_lid, portinfop->p_base_lid,
	    tnf_opaque, sm_lid, portinfop->p_sm_lid,
	    tnf_opaque, sm_sl, portinfop->p_sm_sl,
	    tnf_opaque, subnet_timeout, portinfop->p_subnet_timeout);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_set_transaction_params_end,
	    IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_set_transaction_params() exit\n");
}


/*
 * ibmf_saa_impl_update_sa_address_info
 */
static void
ibmf_saa_impl_update_sa_address_info(saa_port_t *saa_portp, ibmf_msg_t *msgp)
{
	void			*result;
	ib_sa_hdr_t		*sa_hdr;
	int			rv;
	size_t			length;
	uint16_t		attr_id;
	ib_mad_classportinfo_t	*cpi;
	ibmf_global_addr_info_t	*gaddrp = &saa_portp->saa_pt_ibmf_global_addr;
	ibt_hca_portinfo_t	*ibt_pinfo;
	uint_t			nports, size;
	ibt_status_t		ibt_status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_impl_update_sa_address_info,
	    IBMF_TNF_TRACE, "",
	    "ibmf_saa_impl_update_sa_address_info() enter\n");

	/*
	 * decode the respons of msgp as a classportinfo attribute
	 */
	rv = ibmf_saa_utils_unpack_sa_hdr(msgp->im_msgbufs_recv.im_bufs_cl_hdr,
	    msgp->im_msgbufs_recv.im_bufs_cl_hdr_len, &sa_hdr, KM_NOSLEEP);
	if (rv != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_update_sa_address_err,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_update_sa_address_info: "
		    "%s, ibmf_status = %d\n", tnf_string, msg,
		    "Could not unpack sa hdr", tnf_int, ibmf_status, rv);

		return;
	}

	attr_id = b2h16(msgp->im_msgbufs_recv.im_bufs_mad_hdr->AttributeID);
	if (attr_id != MAD_ATTR_ID_CLASSPORTINFO) {
		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_update_sa_address_info_err,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_update_sa_address_info: "
		    "%s, attrID = %x\n", tnf_string, msg,
		    "Wrong attribute ID", tnf_int, ibmf_status, attr_id);

		kmem_free(sa_hdr, sizeof (ib_sa_hdr_t));
		return;
	}
	rv = ibmf_saa_utils_unpack_payload(
	    msgp->im_msgbufs_recv.im_bufs_cl_data,
	    msgp->im_msgbufs_recv.im_bufs_cl_data_len, attr_id, &result,
	    &length, sa_hdr->AttributeOffset, B_TRUE, KM_NOSLEEP);
	if (rv != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_update_sa_address_err,
		    IBMF_TNF_TRACE, "", "ibmf_saa_impl_update_sa_address_info: "
		    "%s, ibmf_status = %d\n", tnf_string, msg,
		    "Could not unpack payload", tnf_int, ibmf_status, rv);

		kmem_free(sa_hdr, sizeof (ib_sa_hdr_t));
		return;
	}

	kmem_free(sa_hdr, sizeof (ib_sa_hdr_t));

	/*
	 * Use the classportinfo contents to update the SA address info
	 */
	cpi = (ib_mad_classportinfo_t *)result;
	mutex_enter(&saa_portp->saa_pt_mutex);
	saa_portp->saa_pt_ibmf_addr_info.ia_remote_lid	= cpi->RedirectLID;
	saa_portp->saa_pt_ibmf_addr_info.ia_remote_qno 	= cpi->RedirectQP;
	saa_portp->saa_pt_ibmf_addr_info.ia_p_key 	= cpi->RedirectP_Key;
	saa_portp->saa_pt_ibmf_addr_info.ia_q_key 	= cpi->RedirectQ_Key;
	saa_portp->saa_pt_ibmf_addr_info.ia_service_level = cpi->RedirectSL;

	saa_portp->saa_pt_redirect_active = B_TRUE;

	if ((cpi->RedirectGID_hi != 0) || (cpi->RedirectGID_lo != 0)) {

		mutex_exit(&saa_portp->saa_pt_mutex);
		ibt_status = ibt_query_hca_ports_byguid(
		    saa_portp->saa_pt_node_guid, saa_portp->saa_pt_port_num,
		    &ibt_pinfo, &nports, &size);
		if (ibt_status != IBT_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_saa_impl_update_sa_address_err, IBMF_TNF_TRACE,
			    "", "ibmf_saa_impl_update_sa_address_info: "
			    "%s, ibt_status = %d\n", tnf_string, msg,
			    "Could not query hca port",
			    tnf_int, ibt_status, ibt_status);

			kmem_free(result, length);
			return;
		}

		mutex_enter(&saa_portp->saa_pt_mutex);
		/*
		 * Fill in global address info parameters
		 *
		 * NOTE: The HopLimit value is not specified through the
		 * contents of ClassPortInfo. It may be possible to find
		 * out the proper value to use even for SA beeing redirected
		 * to another subnet. But we do only support redirect within
		 * our local subnet
		 */
		gaddrp->ig_sender_gid.gid_prefix =
		    ibt_pinfo->p_sgid_tbl[0].gid_prefix;
		gaddrp->ig_sender_gid.gid_guid = saa_portp->saa_pt_port_guid;
		gaddrp->ig_recver_gid.gid_prefix = cpi->RedirectGID_hi;
		gaddrp->ig_recver_gid.gid_guid = cpi->RedirectGID_lo;
		gaddrp->ig_flow_label = cpi->RedirectFL;
		gaddrp->ig_tclass = cpi->RedirectTC;
		gaddrp->ig_hop_limit = 0;

		saa_portp->saa_pt_ibmf_msg_flags =
		    IBMF_MSG_FLAGS_GLOBAL_ADDRESS;

		mutex_exit(&saa_portp->saa_pt_mutex);
		ibt_free_portinfo(ibt_pinfo, size);
	} else {
		saa_portp->saa_pt_ibmf_msg_flags = 0;
		mutex_exit(&saa_portp->saa_pt_mutex);
	}
	kmem_free(result, length);

	/*
	 * Update the address info of msgp with the new address parameters
	 */
	mutex_enter(&saa_portp->saa_pt_mutex);
	bcopy(&saa_portp->saa_pt_ibmf_addr_info, &msgp->im_local_addr,
	    sizeof (ibmf_addr_info_t));
	if (saa_portp->saa_pt_ibmf_msg_flags & IBMF_MSG_FLAGS_GLOBAL_ADDRESS) {

		msgp->im_msg_flags = IBMF_MSG_FLAGS_GLOBAL_ADDRESS;

		bcopy(&saa_portp->saa_pt_ibmf_global_addr,
		    &msgp->im_global_addr, sizeof (ibmf_global_addr_info_t));
	} else {
		msgp->im_msg_flags = 0;
	}
	mutex_exit(&saa_portp->saa_pt_mutex);
}

/*
 * ibmf_saa_impl_ibmf_unreg:
 */
static int
ibmf_saa_impl_ibmf_unreg(saa_port_t *saa_portp)
{
	int	ibmf_status;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_ibmf_unreg_start,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_ibmf_unreg() enter\n");

	/* teardown async cb */
	ibmf_status = ibmf_tear_down_async_cb(saa_portp->saa_pt_ibmf_handle,
	    saa_portp->saa_pt_qp_handle, 0);
	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_ibmf_unreg, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_ibmf_unreg: %s, ibmf_status = %d\n",
		    tnf_string, msg, "Could not tear down async cb",
		    tnf_int, ibmf_status, ibmf_status);

		goto bail;
	}

	/* free qp */
	ibmf_status = ibmf_free_qp(saa_portp->saa_pt_ibmf_handle,
	    &saa_portp->saa_pt_qp_handle, 0);

	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_ibmf_unreg, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_ibmf_unreg: %s, ibmf_status = %d\n",
		    tnf_string, msg, "Could not free queue pair",
		    tnf_int, ibmf_status, ibmf_status);

		(void) ibmf_saa_impl_setup_qp_async_cb(saa_portp, 1);
		goto bail;
	}

	ibmf_status = ibmf_unregister(&saa_portp->saa_pt_ibmf_handle, 0);

	if (ibmf_status != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L1,
		    ibmf_saa_impl_ibmf_unreg, IBMF_TNF_TRACE, "",
		    "ibmf_saa_impl_ibmf_unreg: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_unregister() failed",
		    tnf_int, ibmf_status, ibmf_status);

		(void) ibmf_saa_impl_setup_qp_async_cb(saa_portp, 0);
	}

bail:
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_saa_impl_ibmf_unreg_end,
	    IBMF_TNF_TRACE, "", "ibmf_saa_impl_ibmf_unreg() exit\n");

	return (ibmf_status);
}
