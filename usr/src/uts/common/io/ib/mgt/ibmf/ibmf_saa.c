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

/*
 * ibmf_saa.c
 *
 */

#include <sys/ib/mgt/ibmf/ibmf_saa_impl.h>

/*
 * As a primitive error checking scheme, the first 4 bytes of the client state
 * have a well-known pattern.  We write this pattern during session_open, make
 * sure all subsequent calls still have this pattern in the client state, and
 * clear the pattern on session_close.  Clients could still run into trouble
 * providing a bad handle since we don't check a known list of handles.  But
 * this mechanism will protect against making ibmf_saa calls after the session
 * has been closed.
 */
#define	IBMF_SAA_SET_CLIENT_SIGNATURE(clientp) {		\
		(clientp)->saa_client_sig = (void *)0xACEDFACE;	\
}

#define	IBMF_SAA_VERIFY_CLIENT_SIGNATURE(clientp) 		\
	(((clientp) != NULL && (clientp)->saa_client_sig ==	\
	    (void *)0xACEDFACE) ? B_TRUE: B_FALSE)

#define	IBMF_SAA_CLEAR_CLIENT_SIGNATURE(clientp) {		\
		(clientp)->saa_client_sig = 0;			\
}

/* Global Sa_access State Pointer */
extern saa_state_t *saa_statep;
extern int ibmf_trace_level;

/*
 * Locking scheme:
 * ibmf_saa maintains a linked list of port entries.  Each element of the list
 * contains information about a certain port.  There may be multiple clients
 * associated with each of these entries.  The list is synchronized with a state
 * port_list_mutex.  Each of the entries has their own individual mutex.  When
 * adding a new port entry to the mutex the client, with the list mutex,  marks
 * the port as registering, adds the port, and releases the list mutex.
 * Subsequent clients aquire the list mutex, find the port, acquire the port
 * mutex, release the list mutex, and wait if the port is marked as registering.
 * Clients should never try to acquire the list mutex when they have a port
 * mutex.
 */

/*
 * ibmf_sa_session_open():
 *
 * Before using the ibmf_saa interface, consumers should register with the
 * ibmf_saa interface by calling ibmf_sa_session_open(). Upon a successful
 * registration, a handle is returned for use in subsequent interaction with the
 * ibmf_saa interface; this handle is also provided as an argument to subnet
 * event notification function.
 *
 * Consumers can register to be notified of subnet events such as GID
 * being available/unavailable.  Clients which provide a non-NULL event args
 * structure will have the is_event_callback function called when an event is
 * received or there is a failure in subscribing for events.  This callback may
 * be generated before the ibmf_sa_session_open() call returns.
 *
 * This interface blocks allocating memory, but not waiting for any packet
 * responses.
 *
 * Arguments:
 * port_guid            - GUID of the port.
 * event_args		- subnet event registration details
 * sm_key               - only filled in if the consumer is an SM
 * ibmf_version         - version of the interface (IBMF_VERSION)
 * flags                - unused
 *
 * Output Arguments:
 * ibmf_sa_handle	- pointer to ibmf_saa_handle to be used in future calls
 *
 * Return values:
 * IBMF_SUCCESS         - registration succeeded
 * IBMF_BAD_PORT	- registration failed; active port not found
 * IBMF_BAD_PORT_STATE  - registration failed; port found but not active or
 * 			previous registration failed
 * IBMF_NO_MEMORY	- registration failed; could not allocate memory
 * IBMF_NO_RESOURCES    - registration failed due to a resource issue
 * IBMF_BUSY            - registration failed; too many clients registered
 *                      for this port
 * IBMF_TRANSPORT_FAILURE - failure with underlying transport framework
 * IBMF_INVALID_ARG     - ibmf_saa_handle arg was NULL
 *
 * The ibmf_saa module maintains a linked list of ports which it knows about.
 * For each port, a reference count is kept.  When the first client for a
 * port registers with ibmf_saa, ibmf_saa registers with ibmf.
 * The reference count checking must be serialized to
 * ensure that only one client modifies the reference count at a time.
 * When a client determines that it is responsible for registering it
 * sets the state field to "registering" in the port.  Clients registering with
 * sa_acess will cv_wait on this field before modifying the reference count.
 * Unregistering clients do not need to wait on this field since no one else
 * will be registering while they are completing (the port's ref count will
 * be greater than 0).
 * If ibmf registration fails, the entry is set to "invalid"; we decrement
 * the reference count that we just incremented.
 *
 * WARNING: after decrementing the reference count, NO further access to
 * the entry should be performed in the same thread, because invalid entries
 *  with ref counts of 0 are purged.
 */
/* ARGSUSED */
int
ibmf_sa_session_open(ib_guid_t port_guid, ib_smkey_t sm_key,
    ibmf_saa_subnet_event_args_t *event_args, uint_t ibmf_version,
    uint_t flags, ibmf_saa_handle_t *ibmf_saa_handle)
{
	saa_port_t			*saa_portp	= NULL;
	int				status		= IBMF_SUCCESS;
	saa_client_data_t		*saa_client	= NULL;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_sa_session_open_start, IBMF_TNF_TRACE, "",
	    "ibmf_sa_session_open() enter\n");

	if (ibmf_version != IBMF_VERSION) {

		IBMF_TRACE_0(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_session_open: Bad Version\n");

		status = IBMF_BAD_VERSION;
		goto bail;
	}

	if (ibmf_saa_handle == NULL) {

		IBMF_TRACE_0(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_session_open: invalid argument, null pointer\n");

		status = IBMF_INVALID_ARG;
		goto bail;
	}

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_sa_session_open, IBMF_TNF_TRACE, "",
	    "ibmf_sa_session_open: %s, guid = %016" PRIx64 ", prefix = %016"
	    PRIx64 "\n", tnf_string, msg, "opening session",
	    tnf_opaque, guid, port_guid);

	/*
	 * Find a valid entry matching the port guid
	 * Refcount is immediately incremented
	 */

	/* acquire list mutex (and keep it locked until after creation) */
	mutex_enter(&saa_statep->saa_port_list_mutex);

	saa_portp = saa_statep->saa_port_list;
	while (saa_portp != NULL) {

		if (saa_portp->saa_pt_port_guid == port_guid &&
		    ibmf_saa_is_valid(saa_portp, B_TRUE) == B_TRUE) {

			break;
		}
		saa_portp = saa_portp->next;
	}

	if (saa_portp != NULL) {

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_sa_session_open, IBMF_TNF_TRACE, "",
		    "ibmf_sa_session_open(): %s\n",
		    tnf_string, msg, "port exists\n");

		/* release list mutex */
		mutex_exit(&saa_statep->saa_port_list_mutex);

		/*
		 * now add client to existing port
		 * (will wait till end of ibmf registering)
		 * Note that the state may have changed in the meantime...
		 */
		status = ibmf_saa_impl_add_client(saa_portp);

		if (status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_session_open: %s, status = %d\n",
			    tnf_string, msg, "ibmf_saa_impl_add_client()"
			    " failed", tnf_int, status, status);

			goto bail;
		}
	} else {

		/* create minimal port entry, non blocking */
		status = ibmf_saa_impl_create_port(port_guid, &saa_portp);

		if (status != IBMF_SUCCESS) {

			/* release list mutex */
			mutex_exit(&saa_statep->saa_port_list_mutex);

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_session_open: %s, status = %d\n",
			    tnf_string, msg, "ibmf_saa_impl_create_port()"
			    " failed", tnf_int, status, status);

			goto bail;
		}

		/* link to list */
		saa_portp->next = saa_statep->saa_port_list;
		saa_statep->saa_port_list = saa_portp;

		/*
		 * release the list mutex since we now have the minimum amount
		 * of port data initialized to prevent subsequent clients from
		 * continuing with registration (they will cv_wait on registe-
		 * -ring state).  We don't want to hold the list mutex since
		 * other ports may need it and since we're about to make calls
		 * to functions which may block.
		 *
		 * We do not need the port registering mutex since clients will
		 * not proceed while saa_pt_state ==
		 * IBMF_SAA_PORT_STATE_REGISTERING.
		 */
		mutex_exit(&saa_statep->saa_port_list_mutex);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(saa_portp->saa_pt_kstatp))

		status = ibmf_saa_impl_init_kstats(saa_portp);

		if (status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_session_open: %s, status = %d\n",
			    tnf_string, msg, "could not initialize kstats",
			    tnf_int, status, status);

			ibmf_saa_impl_register_failed(saa_portp);

			goto bail;
		}

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*saa_portp))

		status = ibmf_saa_impl_register_port(saa_portp);

		if (status != IBMF_SUCCESS) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_session_open_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_session_open: %s, ibmf_status = %d\n",
			    tnf_string, msg,
			    "ibmf_saa_impl_register_port failed",
			    tnf_int, ibmf_status, status);

			ibmf_saa_impl_register_failed(saa_portp);

			/*
			 * Note: we don't update kstats as this entry
			 * will eventually go away...
			 */
			goto bail;

		}

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_sa_session_open, IBMF_TNF_TRACE, "",
		    "ibmf_sa_session_open: %s, prefix = %016" PRIx64
		    "\n", tnf_string, msg, "successfully initialized port");

		/* mark port as registered */
		mutex_enter(&saa_portp->saa_pt_mutex);

		/* incremement reference count to account for cpi */
		saa_portp->saa_pt_reference_count++;

		saa_portp->saa_pt_state = IBMF_SAA_PORT_STATE_READY;

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*saa_portp))

		/* kick waiters  */
		cv_broadcast(&saa_portp->saa_pt_ibmf_reg_cv);

		mutex_exit(&saa_portp->saa_pt_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_sa_session_open, IBMF_TNF_TRACE, "",
		    "ibmf_sa_session_open: %s\n", tnf_string, msg,
		    "port is up.  Sending classportinfo request");

		ibmf_saa_impl_get_classportinfo(saa_portp);
	}

	mutex_enter(&saa_portp->saa_pt_kstat_mutex);

	IBMF_SAA_ADD32_KSTATS(saa_portp, clients_registered, 1);

	mutex_exit(&saa_portp->saa_pt_kstat_mutex);

	/* create new client structure */
	saa_client = kmem_zalloc(sizeof (saa_client_data_t), KM_SLEEP);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*saa_client))

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_sa_session_open, IBMF_TNF_TRACE, "",
	    "ibmf_sa_session_open: clientp = %p, subnetp = %p\n",
	    tnf_opaque, clientp, saa_client,
	    tnf_opaque, subnetp, saa_portp);

	saa_client->saa_client_port = saa_portp;
	mutex_init(&saa_client->saa_client_mutex, NULL, MUTEX_DRIVER,
	    NULL);
	cv_init(&saa_client->saa_client_state_cv, NULL, CV_DRIVER, NULL);
	cv_init(&saa_client->saa_client_event_cb_cv, NULL, CV_DRIVER, NULL);

	IBMF_SAA_SET_CLIENT_SIGNATURE(saa_client);

	saa_client->saa_client_state  = SAA_CLIENT_STATE_ACTIVE;
	saa_client->saa_client_sm_key = sm_key;

	*ibmf_saa_handle = (ibmf_saa_handle_t)saa_client;

	/* if client is interested in subnet event notifications */
	if (event_args != NULL) {
		ibmf_saa_add_event_subscriber(saa_client, event_args);
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*saa_client))


bail:
	/* purge invalid entries */
	ibmf_saa_impl_purge();

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_sa_session_open_end,
	    IBMF_TNF_TRACE, "", "ibmf_sa_session_open() exit\n");

	return (status);
}


/*
 * ibmf_sa_session_close()
 *
 * Unregister a consumer of the SA_Access interface
 *
 * This interface blocks.
 *
 * Arguments:
 *	SA_Access handle
 *
 * Return values:
 *	IBMF_SUCCESS        - unregistration succeeded
 *      IBMF_FAILURE        - unregistration failed for unknown reasons
 *
 * All outstanding callbacks will be canceled before this function returns.
 *
 */
/* ARGSUSED */
int
ibmf_sa_session_close(ibmf_saa_handle_t *ibmf_saa_handle, uint_t flags)
{
	saa_client_data_t	*client_data	= NULL;
	saa_port_t		*saa_portp	= NULL;
	int			status		= IBMF_SUCCESS;
	saa_client_data_t	*curr_clientp, *prev_clientp;
	uint8_t			port_state;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_sa_session_close_start, IBMF_TNF_TRACE, "",
	    "ibmf_sa_session_close() enter\n");

	if (ibmf_saa_handle == NULL) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_session_close_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_session_close: %s\n",
		    tnf_string, msg, "invalid argument, NULL pointer argument");

		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* ibmf_saa_handle is pointer to the client data structure */
	client_data = (saa_client_data_t *)*ibmf_saa_handle;

	/* sanity check to make sure nothing happened to handle */
	if (IBMF_SAA_VERIFY_CLIENT_SIGNATURE(client_data) == B_FALSE) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_session_close_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_session_close: %s\n",
		    tnf_string, msg, "bad handle");

		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	saa_portp = client_data->saa_client_port;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_sa_session_close, IBMF_TNF_TRACE,
	    "", "ibmf_sa_session_close: saa_portp = %p\n",
	    tnf_opaque, saa_portp, saa_portp);

	mutex_enter(&saa_portp->saa_pt_mutex);

	port_state = saa_portp->saa_pt_state;

	mutex_exit(&saa_portp->saa_pt_mutex);

	/*
	 * if there are pending async transactions, wait for them to finish
	 * note that we wait only once, not loop....
	 * note we test the state outside saa_pt_mutex
	 */
	mutex_enter(&client_data->saa_client_mutex);

	if ((client_data->saa_client_num_pending_trans > 0) &&
	    (port_state == IBMF_SAA_PORT_STATE_READY)) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_sa_session_close, IBMF_TNF_TRACE,
		    "", "ibmf_sa_session_close: %s, num_pending_trans = %d\n",
		    tnf_string, msg, "waiting for async callbacks",
		    tnf_uint, num_pending_trans,
		    client_data->saa_client_num_pending_trans);

		client_data->saa_client_state = SAA_CLIENT_STATE_WAITING;

		/*
		 * we rely on IBMF calling the callback in all cases,
		 * callback signals cv
		 */
		cv_wait(&client_data->saa_client_state_cv,
		    &client_data->saa_client_mutex);

		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_sa_session_close,
		    IBMF_TNF_TRACE, "", "ibmf_sa_session_close: %s\n",
		    tnf_string, msg, "done waiting");
	}

	/* mark state as closed so no more event callbacks will be generated */
	client_data->saa_client_state = SAA_CLIENT_STATE_CLOSED;

	/*
	 * if there are pending subnet event callbacks wait for them to finish
	 */
	if (client_data->saa_client_event_cb_num_active > 0) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_sa_session_close, IBMF_TNF_TRACE,
		    "", "ibmf_sa_session_close: %s, num_active_cb = %d\n",
		    tnf_string, msg, "waiting for event callbacks",
		    tnf_uint, num_active_cb,
		    client_data->saa_client_event_cb_num_active);

		cv_wait(&client_data->saa_client_event_cb_cv,
		    &client_data->saa_client_mutex);
	}

	mutex_exit(&client_data->saa_client_mutex);

	mutex_enter(&saa_portp->saa_pt_kstat_mutex);

	IBMF_SAA_SUB32_KSTATS(saa_portp, clients_registered, 1);

	mutex_exit(&saa_portp->saa_pt_kstat_mutex);

	/*
	 * if client was subscribed for events then remove the callback from the
	 * list, and possibly unsubscribe from the SA
	 */
	if (client_data->saa_client_event_cb != NULL) {

		/* remove the client from the port's list of clients */
		mutex_enter(&saa_portp->saa_pt_event_sub_mutex);

		curr_clientp = saa_portp->saa_pt_event_sub_client_list;
		prev_clientp = NULL;
		while (curr_clientp != NULL) {

			if (curr_clientp == client_data) {

				break;
			}

			prev_clientp = curr_clientp;
			curr_clientp = curr_clientp->next;
		}

		/* should have found the client */
		ASSERT(curr_clientp != NULL);

		if (curr_clientp == NULL) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_session_close, IBMF_TNF_ERROR, "",
			    "ibmf_sa_session_close: %s.  ref_count = %d\n",
			    tnf_string, msg, "could not find client in list",
			    tnf_opaque, client, client_data);
		} else {

			if (prev_clientp == NULL) {

				saa_portp->saa_pt_event_sub_client_list =
				    curr_clientp->next;

			} else
				prev_clientp->next = curr_clientp->next;

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_sa_session_close, IBMF_TNF_TRACE, "",
			    "ibmf_sa_session_close: %s\n", tnf_string, msg,
			    "Removed client from event subscriber list");
		}


		mutex_exit(&saa_portp->saa_pt_event_sub_mutex);

	}

	/* decrementing refcount is last thing we do on port entry */
	mutex_enter(&saa_portp->saa_pt_mutex);

	ASSERT(saa_portp->saa_pt_reference_count > 0);
	saa_portp->saa_pt_reference_count--;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_sa_session_close,
	    IBMF_TNF_TRACE, "",
	    "ibmf_sa_session_close: ref_count = %d\n",
	    tnf_uint, port_ref_count,
	    saa_portp->saa_pt_reference_count);

	mutex_exit(&saa_portp->saa_pt_mutex);

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_sa_session_close, IBMF_TNF_TRACE, "",
	    "ibmf_sa_session_close: %s, clientp = %p\n", tnf_string, msg,
	    "freeing client memory", tnf_opaque, clientp, *ibmf_saa_handle);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*client_data))

	/* destroy client */
	mutex_destroy(&client_data->saa_client_mutex);

	cv_destroy(&client_data->saa_client_state_cv);
	cv_destroy(&client_data->saa_client_event_cb_cv);

	IBMF_SAA_CLEAR_CLIENT_SIGNATURE(client_data);

	kmem_free(*ibmf_saa_handle, sizeof (saa_client_data_t));

	*ibmf_saa_handle = NULL;

bail:
	/* purge invalid entries */
	ibmf_saa_impl_purge();

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_sa_session_close_end,
	    IBMF_TNF_TRACE, "", "ibmf_sa_session_close() exit\n");

	return (status);
}

/*
 * ibmf_sa_access
 *
 * Retrieve records from the SA given an AttributeID, ComponentMask,
 * and a template
 *
 * This interface blocks if the callback parameter is NULL.
 *
 * Input Arguments:
 * ibmf_saa_handle	- handle returned from ibmf_sa_session_open()
 * access_args 		- structure containing various parameters for the query
 * flags 		- unsused
 *
 * Output Arguments:
 * length		- size of buffer returned
 * result		- pointer to buffer of records returned in response.
 *			  Buffer is host-endian, unpacked and can be cast to one
 *			  of the record types in sa_recs.h
 * Return values:
 * IBMF_SUCCESS 	- query succeeded
 * IBMF_BAD_HANDLE	- sa session handle is invalid
 * IBMF_BAD_PORT_STATE	- port in incorrect state
 * IBMF_INVALID_ARG	- one of the pointer parameters was NULL
 * IBMF_NO_RESOURCES	- ibmf could not allocate ib resources or SA returned
 *			  ERR_NO_RESOURCES
 * IBMF_TRANS_TIMEOUT	- transaction timed out
 * IBMF_TRANS_FAILURE	- transaction failure
 * IBMF_NO_MEMORY	- ibmf could not allocate memory
 * IBMF_REQ_INVALID	- send and recv buffer the same for a sequenced
 *			  transaction or the SA returned an ERR_REQ_INVALID
 * IBMF_NO_RECORDS	- no records matched query
 * IBMF_TOO_MANY_RECORDS- SA returned SA_ERR_TOO_MANY_RECORDS
 * IBMF_INVALID_GID	- SA returned SA_INVALID_GID
 * IBMF_INSUFF_COMPS	- SA returned SA_ERR_INSUFFICIENT_COMPS
 * IBMF_UNSUPP_METHOD	- SA returned MAD_STATUS_UNSUPP_METHOD
 * IBMF_UNSUPP_METHOD_ATTR - SA returned MAD_STATUS_UNSUPP_METHOD_ATTR
 * IBMF_INVALID_FIELD	- SA returned MAD_STATUS_INVALID_FIELD
 *
 * Upon successful completion, result points to a buffer containing the records.
 * length is the size in bytes of the buffer returned in result.  If there are
 * no records or the call failed the length is 0.
 *
 * The consumer is responsible for freeing the memory associated with result.
 */
/* ARGSUSED */
int
ibmf_sa_access(ibmf_saa_handle_t ibmf_saa_handle,
    ibmf_saa_access_args_t *access_args, uint_t flags, size_t *length,
    void **result)
{
	int			res = IBMF_SUCCESS;

	saa_impl_trans_info_t	*trans_info;
	saa_client_data_t	*clientp;
	saa_port_t		*saa_portp;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_sa_access_start, IBMF_TNF_TRACE, "",
	    "ibmf_sa_access_start() enter. attr_id = 0x%x, access_type ="
	    " 0x%x, comp_mask = %016" PRIx64 "\n",
	    tnf_opaque, attr_id, access_args->sq_attr_id,
	    tnf_opaque, access_type, access_args->sq_access_type,
	    tnf_opaque, comp_mask, access_args->sq_component_mask);

	if ((access_args == NULL) || (length == NULL) || (result == NULL)) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_access: %s\n",
		    tnf_string, msg, "invalid argument, NULL pointer argument");

		res = IBMF_INVALID_ARG;
		goto bail;
	}

	/* sanity check to make sure nothing happened to handle */
	if (IBMF_SAA_VERIFY_CLIENT_SIGNATURE(
	    (saa_client_data_t *)ibmf_saa_handle) == B_FALSE) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_access: %s\n",
		    tnf_string, msg, "bad handle");

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_sa_access_end, IBMF_TNF_TRACE,
		    "", "ibmf_sa_access() exit\n");

		res = IBMF_BAD_HANDLE;
		goto bail;
	}

	if (access_args->sq_callback == NULL) {

		trans_info = kmem_zalloc(sizeof (saa_impl_trans_info_t),
		    KM_SLEEP);
	} else {
		trans_info = kmem_zalloc(sizeof (saa_impl_trans_info_t),
		    KM_NOSLEEP);
		if (trans_info == NULL) {

			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_access: %s\n", tnf_string, msg,
			    "could not allocate memory for trans_info");

			res = IBMF_NO_MEMORY;
			goto bail;
		}
	}

	clientp = (saa_client_data_t *)ibmf_saa_handle;
	saa_portp = clientp->saa_client_port;

	trans_info->si_trans_client_data = clientp;
	trans_info->si_trans_port = saa_portp;

	/*
	 * method is get_multi if attribute is multipath; otherwise method is
	 * based on query type
	 */
	if (access_args->sq_attr_id == SA_MULTIPATHRECORD_ATTRID) {

		if (access_args->sq_access_type != IBMF_SAA_RETRIEVE) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_access: %s, access_type = 0x%x\n",
			    tnf_string, msg, "access_type for multi-path"
			    " records must be IBMF_SAA_RETRIEVE",
			    tnf_opaque, access_type,
			    access_args->sq_access_type);

			kmem_free(trans_info, sizeof (saa_impl_trans_info_t));

			res = IBMF_REQ_INVALID;
			goto bail;
		}

		trans_info->si_trans_method = SA_SUBN_ADM_GET_MULTI;
	} else if (access_args->sq_attr_id == SA_TRACERECORD_ATTRID) {

		if (access_args->sq_access_type != IBMF_SAA_RETRIEVE) {

			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
			    "ibmf_sa_access: %s, access_type = 0x%x\n",
			    tnf_string, msg, "access_type for trace"
			    " records must be IBMF_SAA_RETRIEVE",
			    tnf_opaque, access_type,
			    access_args->sq_access_type);

			kmem_free(trans_info, sizeof (saa_impl_trans_info_t));

			res = IBMF_REQ_INVALID;
			goto bail;
		}

		trans_info->si_trans_method = SA_SUBN_ADM_GET_TRACE_TABLE;
	} else {

		switch (access_args->sq_access_type) {

			case IBMF_SAA_RETRIEVE:
				trans_info->si_trans_method =
				    SA_SUBN_ADM_GET_TABLE;
				break;
			case IBMF_SAA_UPDATE:
				trans_info->si_trans_method = SA_SUBN_ADM_SET;
				break;
			case IBMF_SAA_DELETE:
				trans_info->si_trans_method =
				    SA_SUBN_ADM_DELETE;
				break;
			default:

				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
				    "ibmf_sa_access: %s, access_type = 0x%x\n",
				    tnf_string, msg, "unknown access_type",
				    tnf_opaque, access_type,
				    access_args->sq_access_type);

				kmem_free(trans_info,
				    sizeof (saa_impl_trans_info_t));

				res = IBMF_REQ_INVALID;
				goto bail;
		}
	}

	trans_info->si_trans_attr_id = access_args->sq_attr_id;
	trans_info->si_trans_component_mask = access_args->sq_component_mask;
	trans_info->si_trans_template = access_args->sq_template;
	trans_info->si_trans_template_length = access_args->sq_template_length;
	trans_info->si_trans_callback = access_args->sq_callback;
	trans_info->si_trans_callback_arg = access_args->sq_callback_arg;

	mutex_enter(&saa_portp->saa_pt_kstat_mutex);

	IBMF_SAA_ADD32_KSTATS(saa_portp, outstanding_requests, 1);
	IBMF_SAA_ADD32_KSTATS(saa_portp, total_requests, 1);

	mutex_exit(&saa_portp->saa_pt_kstat_mutex);

	res = ibmf_saa_impl_send_request(trans_info);
	if (res != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_sa_access_err, IBMF_TNF_ERROR, "",
		    "ibmf_sa_access: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_saa_impl_send_request() failed",
		    tnf_int, ibmf_status, res);

		*length = 0;
		*result = NULL;

		kmem_free(trans_info, sizeof (saa_impl_trans_info_t));

		mutex_enter(&saa_portp->saa_pt_kstat_mutex);

		IBMF_SAA_SUB32_KSTATS(saa_portp, outstanding_requests, 1);
		IBMF_SAA_ADD32_KSTATS(saa_portp, failed_requests, 1);

		if (res == IBMF_TRANS_TIMEOUT)
			IBMF_SAA_ADD32_KSTATS(saa_portp, requests_timedout,
			    1);

		mutex_exit(&saa_portp->saa_pt_kstat_mutex);

		goto bail;
	}

	/*
	 * if async call don't do anything as callback will take care of
	 * everything; for sync call, copy parameters back to client and free
	 * trans_info structure
	 */
	if (access_args->sq_callback == NULL) {
		*length = trans_info->si_trans_length;
		*result = trans_info->si_trans_result;
		res = trans_info->si_trans_status;

		mutex_enter(&saa_portp->saa_pt_kstat_mutex);

		IBMF_SAA_SUB32_KSTATS(saa_portp, outstanding_requests, 1);

		if (res != IBMF_SUCCESS)
			IBMF_SAA_ADD32_KSTATS(saa_portp, failed_requests,
			    1);

		if (res == IBMF_TRANS_TIMEOUT)
			IBMF_SAA_ADD32_KSTATS(saa_portp, requests_timedout,
			    1);

		mutex_exit(&saa_portp->saa_pt_kstat_mutex);

		kmem_free(trans_info, sizeof (saa_impl_trans_info_t));
	}

bail:

	if (res != IBMF_SUCCESS) {
		if (length != NULL)
			*length = 0;
		if (result != NULL)
			*result = NULL;
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_sa_access, IBMF_TNF_TRACE,
	    "", "ibmf_sa_access() exit: result = 0x%x\n",
	    tnf_opaque, result, res);

	return (res);
}

/*
 * Helper Functions.
 *	Ease of use functions so that the consumer doesn't
 * 	have to do the overhead of calling ibmf_sa_access for
 *	commonly used queries
 */

/*
 * ibmf_saa_gid_to_pathrecords
 * 	Given a source gid and a destination gid, return paths
 *	between the gids.
 *
 * This interface blocks.
 *
 * Input Arguments:
 * ibmf_saa_handle	- handle returned from ibmf_sa_session_open()
 * sgid 		- source gid of path
 * dgid			- destination gid of path
 * p_key		- partition of path.  This value may be wildcarded with
 *			  IBMF_SAA_PKEY_WC.
 * mtu 			- preferred MTU of the path.  This argument may be
 *			  wildcarded with IBMF_SAA_MTU_WC.
 * reversible		- if B_TRUE, ibmf will query only reversible paths
 *			  see Infiniband Specification table 171
 * num_paths		- maximum number of paths to return
 *			  num_paths should be checked for the actual number of
 *			  records returned.
 * flags		- unused
 *
 * Output Arguments:
 * num_paths		- actual number of paths returned
 * length		- size of buffer returned
 * result		- pointer to buffer of path records returned in response
 *
 * Return values:
 * Error codes are the same as ibmf_sa_access() return values
 *
 * Upon successful completion, result points to a buffer containing the records.
 * length is the size in bytes of the buffer returned in result.  If there are
 * no records or the call failed the length is 0.
 *
 * The consumer is responsible for freeing the memory associated with result.
 */
/* ARGSUSED */
int
ibmf_saa_gid_to_pathrecords(ibmf_saa_handle_t ibmf_saa_handle, ib_gid_t sgid,
    ib_gid_t dgid, ib_pkey_t p_key, ib_mtu_t mtu, boolean_t reversible,
    uint8_t *num_paths, uint_t flags, size_t *length, sa_path_record_t **result)
{
	sa_path_record_t	path_record;
	uint64_t		comp_mask;
	int			res;
	ibmf_saa_access_args_t	access_args;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_gid_to_pathrecords_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_gid_to_pathrecords() enter\n");

	/*
	 * check num_paths pointer here since we dereference before calling
	 * ibmf_sa_access
	 */
	if (num_paths == NULL) {

		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_gid_to_pathrecords_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_gid_to_pathrecords: %s\n",
		    tnf_string, msg, "invalid argument, NULL pointer argument");

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_saa_gid_to_pathrecords_end, IBMF_TNF_TRACE,
		    "", "ibmf_saa_gid_to_pathrecords() exit\n");

		if (length != NULL)
			*length = 0;
		if (result != NULL)
			*result = NULL;

		return (IBMF_INVALID_ARG);
	}

	/* check valid handle; in non-debug system ibmf_sa_access() will fail */
	ASSERT(ibmf_saa_handle != NULL);

	ASSERT(length != NULL);
	ASSERT(result != NULL);

	*length = 0;
	*result = NULL;

	comp_mask = SA_PR_COMPMASK_SGID | SA_PR_COMPMASK_DGID |
	    SA_PR_COMPMASK_NUMBPATH;

	bzero(&path_record, sizeof (sa_path_record_t));

	path_record.SGID = sgid;
	path_record.DGID = dgid;
	path_record.NumbPath = *num_paths;

	if (reversible == B_TRUE) {
		path_record.Reversible = 1;
		comp_mask |= SA_PR_COMPMASK_REVERSIBLE;
	}

	if (p_key != IBMF_SAA_PKEY_WC) {

		path_record.P_Key = p_key;
		comp_mask |= SA_PR_COMPMASK_PKEY;
	}

	/*
	 * gid_to_pathrecords specifies greater than or equal to MTU.  Path
	 * records can only do strictly greater.  Set the mtu value to one
	 * less than the mtu parameter.  If it's the lowest value possible (256)
	 * don't do anything and any path mtu will be allowed.
	 */
	if ((mtu != IBMF_SAA_MTU_WC) && (mtu > IB_MTU_256)) {

		path_record.MtuSelector = SA_PR_MTU_SEL_GREATER;
		path_record.Mtu = (mtu - 1);

		comp_mask |= SA_PR_COMPMASK_MTUSELECTOR | SA_PR_COMPMASK_MTU;
	}

	access_args.sq_attr_id = SA_PATHRECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_component_mask = comp_mask;
	access_args.sq_template = &path_record;
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	res = ibmf_sa_access(ibmf_saa_handle, &access_args, 0, length,
	    (void **)result);
	if (res != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_gid_to_pathrecords, IBMF_TNF_TRACE, "",
		    "ibmf_saa_gid_to_pathrecords: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_sa_access() failed",
		    tnf_int, ibmf_status, res);
	}

	*num_paths = *length / sizeof (sa_path_record_t);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_gid_to_pathrecords_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_gid_to_pathrecords() exit: result = 0x%x\n",
	    tnf_opaque, result, res);

	return (res);
}

/*
 * ibmf_saa_paths_from_gid
 *      Given a source GID, return a path from the source gid
 *	to every other port on the subnet.  It is assumed that the
 *	subnet is fully connected.  Only one path per port on the subnet
 *	is returned.
 *
 * This interface blocks.
 *
 * Input Arguments:
 * ibmf_saa_handle	- handle returned from ibmf_sa_session_open()
 * sgid 		- source gid of path
 * pkey			- paritition of path.  This value may be wildcarded with
 *			  IBMF_SAA_PKEY_WC.
 * reversible		- if B_TRUE, ibmf will query only reversible paths;
 *			  see Infiniband Specification table 171
 * flags		- unused
 *
 * Output Arguments:
 * num_paths		- number of paths returned
 * length		- size of buffer returned
 * result		- pointer to buffer of path records returned in response
 *
 * Return values:
 * Error codes are the same as ibmf_sa_access() return values
 *
 * Upon successful completion, result points to a buffer containing the records.
 * and num_records is the number of path records returned.  length is the size
 * in bytes of the buffer returned in result.  If there are no records or the
 * call failed the length is 0.
 *
 * The consumer is responsible for freeing the memory associated with result.
 */
/* ARGSUSED */
int
ibmf_saa_paths_from_gid(ibmf_saa_handle_t ibmf_saa_handle, ib_gid_t sgid,
    ib_pkey_t p_key, boolean_t reversible, uint_t flags, uint_t *num_paths,
    size_t *length, sa_path_record_t **result)
{
	sa_path_record_t	path_record;
	uint64_t		comp_mask;
	int			res;
	ibmf_saa_access_args_t	access_args;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_paths_from_gid_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_paths_from_gid() enter\n");

	/* check valid handle; in non-debug system ibmf_sa_access() will fail */
	ASSERT(ibmf_saa_handle != NULL);

	ASSERT(length != NULL);
	ASSERT(result != NULL);

	comp_mask = SA_PR_COMPMASK_SGID | SA_PR_COMPMASK_NUMBPATH;

	bzero(&path_record, sizeof (sa_path_record_t));

	path_record.SGID = sgid;
	path_record.NumbPath = 1;

	if (reversible == B_TRUE) {
		path_record.Reversible = 1;
		comp_mask |= SA_PR_COMPMASK_REVERSIBLE;
	}

	if (p_key != IBMF_SAA_PKEY_WC) {

		path_record.P_Key = p_key;
		comp_mask |= SA_PR_COMPMASK_PKEY;
	}

	access_args.sq_attr_id = SA_PATHRECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_component_mask = comp_mask;
	access_args.sq_template = &path_record;
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	res = ibmf_sa_access(ibmf_saa_handle, &access_args, 0, length,
	    (void **)result);
	if (res != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_gid_to_pathrecords, IBMF_TNF_TRACE, "",
		    "ibmf_saa_gid_to_pathrecords: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_sa_access() failed",
		    tnf_int, ibmf_status, res);
	}

	*num_paths = *length / sizeof (sa_path_record_t);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_paths_from_gid_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_paths_from_gid() exit: result = 0x%x\n",
	    tnf_opaque, result, res);

	return (res);
}

/*
 * ibmf_saa_name_to_service_record:
 *	Given a service name, return the service records associated
 *	with it.
 *
 * This interface blocks.
 *
 * Input Arguments:
 * ibmf_saa_handle	- handle returned from ibmf_sa_session_open()
 * name			- service name, a null terminated string
 * p_key		- partition that the service is requested on.  This
 *			  value may be wildcarded with IBMF_SAA_PKEY_WC.
 * flags		- unused
 *
 * Output Arguments:
 * num_records		- number of service records returned
 * length		- size of buffer returned
 * result		- pointer to buffer of service records returned in
 *			  response
 * Return values:
 * Error codes are the same as ibmf_sa_access() return values
 *
 * Upon successful completion, result points to a buffer containing the records.
 * and num_records is the number of service records returned.  length is the
 * size in bytes of the buffer returned in result.  If there are no records or
 * the call failed the length is 0.
 *
 * The consumer is responsible for freeing the memory associated with result.
 */
/* ARGSUSED */
int
ibmf_saa_name_to_service_record(ibmf_saa_handle_t ibmf_saa_handle,
    char *service_name, ib_pkey_t p_key, uint_t flags,
    uint_t *num_records, size_t *length, sa_service_record_t **result)
{
	sa_service_record_t	service_record;
	int			res;
	ibmf_saa_access_args_t	access_args;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_name_to_service_record_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_name_to_service_record() enter\n");

	/* check valid handle; in non-debug system ibmf_sa_access() will fail */
	ASSERT(ibmf_saa_handle != NULL);

	ASSERT(num_records != NULL);
	ASSERT(length != NULL);
	ASSERT(result != NULL);

	bzero((void *)&service_record, sizeof (sa_service_record_t));

	if (strlen(service_name) >= IB_SVC_NAME_LEN) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_name_to_service_record_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_gid_to_pathrecords: %s, service_name = %s\n",
		    tnf_string, msg, "service name too long",
		    tnf_string, service_name, service_name);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_saa_name_to_service_record_end, IBMF_TNF_TRACE, "",
		    "ibmf_saa_name_to_service_record() exit\n");

		*num_records = 0;
		*length = 0;
		*result = NULL;

		return (IBMF_REQ_INVALID);
	}

	/* copy IB_SVC_NAME_LEN bytes, leaving room at end for null char */
	(void) strncpy((char *)(service_record.ServiceName), service_name,
	    IB_SVC_NAME_LEN-1);

	if (p_key != IBMF_SAA_PKEY_WC) {
		service_record.ServiceP_Key = p_key;
		access_args.sq_component_mask = SA_SR_COMPMASK_NAME |
		    SA_SR_COMPMASK_PKEY;
	} else
		access_args.sq_component_mask = SA_SR_COMPMASK_NAME;

	access_args.sq_attr_id = SA_SERVICERECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_template = &service_record;
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	res = ibmf_sa_access(ibmf_saa_handle, &access_args, 0, length,
	    (void *)result);
	if (res != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_name_to_service_record, IBMF_TNF_TRACE, "",
		    "ibmf_saa_name_to_service_record: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_sa_access() failed",
		    tnf_int, ibmf_status, res);
	}

	*num_records = *length / sizeof (sa_service_record_t);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_name_to_service_record_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_name_to_service_record() exit: result = 0x%x\n",
	    tnf_opaque, result, res);

	return (res);
}

/*
 * ibmf_saa_id_to_service_record:
 *      Given a service id, return the service records associated
 *      with it.
 *
 * This interface blocks.
 *
 * Input Arguments:
 * ibmf_saa_handle	- handle returned from ibmf_sa_session_open()
 * id			- service id
 * p_key		- partition that the service is requested on.  This
 *			  value may be wildcarded with IBMF_SAA_PKEY_WC.
 * flags		- unused
 *
 * Output Arguments:
 * num_records		- number of service records returned
 * length		- size of buffer returned
 * result		- pointer to buffer of service records returned in
 *			  response
 *
 * Return values:
 * Error codes are the same as ibmf_sa_access() return values
 *
 * Upon successful completion, result points to a buffer containing the records.
 * and num_records is the number of service records returned.  length is the
 * size in bytes of the buffer returned in result.  If there are no records or
 * the call failed the length is 0.
 *
 * The consumer is responsible for freeing the memory associated with result.
 */
/* ARGSUSED */
int
ibmf_saa_id_to_service_record(ibmf_saa_handle_t ibmf_saa_handle,
    ib_svc_id_t service_id, ib_pkey_t p_key, uint_t flags, uint_t *num_records,
    size_t *length, sa_service_record_t **result)
{
	sa_service_record_t	service_record;
	int	res;
	ibmf_saa_access_args_t	access_args;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_id_to_service_record_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_id_to_service_record() enter\n");

	/* check valid handle; in non-debug system ibmf_sa_access() will fail */
	ASSERT(ibmf_saa_handle != NULL);

	ASSERT(num_records != NULL);
	ASSERT(length != NULL);
	ASSERT(result != NULL);

	bzero((void *)&service_record, sizeof (sa_service_record_t));

	service_record.ServiceID = service_id;

	if (p_key != IBMF_SAA_PKEY_WC) {
		service_record.ServiceP_Key = p_key;
		access_args.sq_component_mask = SA_SR_COMPMASK_ID |
		    SA_SR_COMPMASK_PKEY;
	} else
		access_args.sq_component_mask = SA_SR_COMPMASK_ID;

	access_args.sq_attr_id = SA_SERVICERECORD_ATTRID;
	access_args.sq_access_type = IBMF_SAA_RETRIEVE;
	access_args.sq_template = &service_record;
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	res = ibmf_sa_access(ibmf_saa_handle, &access_args, 0, length,
	    (void **)result);
	if (res != IBMF_SUCCESS) {

		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L2,
		    ibmf_saa_id_to_service_record, IBMF_TNF_TRACE, "",
		    "ibmf_saa_id_to_service_record: %s, ibmf_status = %d\n",
		    tnf_string, msg, "ibmf_sa_access() failed",
		    tnf_int, ibmf_status, res);
	}

	*num_records = *length / sizeof (sa_service_record_t);

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_id_to_service_record_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_id_to_service_record() exit: result = 0x%x\n",
	    tnf_opaque, result, res);

	return (res);
}

/*
 * ibmf_saa_update_service_record
 *	Given a pointer to a service record, either insert or delete it
 *
 * This interface blocks.
 *
 * Input Arguments:
 * ibmf_saa_handle	- handle returned from ibmf_sa_session_open()
 * service_record	- service record is to be inserted or deleted.  To
 *			  delete a service record the GID, ID, P_Key, and
 *			  Service Key must match what is in the SA.
 * access_type		- indicates whether this is an insertion or deletion.
 *			  valid values are IBMF_SAA_UPDATE or IBMF_SAA_DELETE
 * flags		- unused
 *
 * Output Arguments
 * none
 *
 * Return values:
 * Error codes are the same as ibmf_sa_access() return values
 */
/* ARGSUSED */
int
ibmf_saa_update_service_record(ibmf_saa_handle_t ibmf_saa_handle,
    sa_service_record_t *service_record, ibmf_saa_access_type_t access_type,
    uint_t flags)
{
	size_t			length;
	void			*result;
	int			res;
	uint64_t		comp_mask;
	ibmf_saa_access_args_t	access_args;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_saa_update_service_record_start, IBMF_TNF_TRACE, "",
	    "ibmf_saa_update_service_record() enter\n");

	/* check valid handle; in non-debug system ibmf_sa_access() will fail */
	ASSERT(ibmf_saa_handle != NULL);

	if ((access_type != IBMF_SAA_UPDATE) &&
	    (access_type != IBMF_SAA_DELETE)) {

		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_saa_update_service_record_err, IBMF_TNF_ERROR, "",
		    "ibmf_saa_update_service_record: %s, access_type = 0x%x\n",
		    tnf_string, msg, "invalid query type",
		    tnf_opaque, access_type, access_type);

		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_saa_update_service_record_end, IBMF_TNF_TRACE, "",
		    "ibmf_saa_update_service_record() exit\n");

		return (IBMF_REQ_INVALID);
	}

	/*
	 * call ibmf_sa_access with the following special parameters:
	 * attrid : service_record
	 * component_mask : RID fields of service record (GID, ID, and P_key)
	 *		    and service key
	 */
	comp_mask =  SA_SR_COMPMASK_ID | SA_SR_COMPMASK_GID |
	    SA_SR_COMPMASK_PKEY | SA_SR_COMPMASK_KEY;

	access_args.sq_attr_id = SA_SERVICERECORD_ATTRID;
	access_args.sq_access_type = access_type;
	access_args.sq_component_mask = comp_mask;
	access_args.sq_template = service_record;
	access_args.sq_callback = NULL;
	access_args.sq_callback_arg = NULL;

	res = ibmf_sa_access(ibmf_saa_handle, &access_args, 0, &length,
	    &result);

	/* if a valid add request, response buffer should be one service rec */
	if (res == IBMF_SUCCESS && length > 0) {

		if (length > sizeof (sa_service_record_t)) {

			IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L1,
			    ibmf_saa_update_service_record, IBMF_TNF_TRACE, "",
			    "ibmf_saa_update_service_record: %s\n",
			    tnf_string, msg,
			    "SA returned more than one record");
		}

		kmem_free(result, length);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_saa_update_service_record_end, IBMF_TNF_TRACE, "",
	    "ibmf_saa_update_service_record() exit: result = 0x%x\n",
	    tnf_opaque, result, res);

	return (res);
}
