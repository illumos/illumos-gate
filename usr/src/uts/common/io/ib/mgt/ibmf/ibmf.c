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
 */

/*
 * This file implements the client interfaces of the IBMF.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>

#define	IBMF_SET_CLIENT_SIGNATURE(clientp) {			\
		(clientp)->ic_client_sig = (void *)0xf00DdEaD;	\
}

#define	IBMF_VERIFY_CLIENT_SIGNATURE(clientp)			\
	(((clientp) != NULL && (clientp)->ic_client_sig ==	\
	    (void *)0xf00DdEaD) ? B_TRUE: B_FALSE)

#define	IBMF_INVALID_PKEY(pkey)	(((pkey) & 0x7FFF) == 0)
#define	QP1 1

extern ibmf_state_t *ibmf_statep;
extern int ibmf_trace_level;

/* ARGSUSED */
int
ibmf_register(ibmf_register_info_t *client_infop, uint_t ibmf_version,
    uint_t flags, ibmf_async_event_cb_t client_cb, void  *client_cb_args,
    ibmf_handle_t *ibmf_handlep, ibmf_impl_caps_t *ibmf_impl_features)
{
	ibmf_ci_t	*ibmf_cip;
	ibmf_qp_t	*ibmf_qpp;
	ibmf_client_t	*ibmf_clientp;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_register_start,
	    IBMF_TNF_TRACE, "", "ibmf_register() enter, client_infop = %p "
	    " ibmf_version = %d, flags = 0x%x, ibmf_impl_featuresp = %p\n",
	    tnf_opaque, client_infop, client_infop,
	    tnf_uint, ibmf_version, ibmf_version, tnf_uint, flags, flags,
	    tnf_opaque, ibmf_impl_features, ibmf_impl_features);

	/* validate client_infop and ibmf_handlep */
	if ((client_infop == NULL) || (ibmf_handlep == NULL) ||
	    (ibmf_impl_features == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* check IBMF version */
	if (ibmf_version != IBMF_VERSION) {
		(void) sprintf(errmsg, "Bad version");
		error = B_TRUE;
		status = IBMF_BAD_VERSION;
		goto bail;
	}

	/* check flags validity */
	if ((flags & IBMF_REG_FLAG_NO_OFFLOAD) &&
	    (flags & IBMF_REG_FLAG_SINGLE_OFFLOAD)) {
		(void) sprintf(errmsg, "Bad flags");
		error = B_TRUE;
		status = IBMF_BAD_FLAGS;
		goto bail;
	}

	/* check client mask and size */
	status = ibmf_i_validate_class_mask(client_infop);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "invalid class");
		error = B_TRUE;
		goto bail;
	}
	/*
	 * verify the node identified by ir_ci_guid exists and that the
	 * port ir_port_num is valid.
	 */
	status = ibmf_i_validate_ci_guid_and_port(client_infop->ir_ci_guid,
	    client_infop->ir_port_num);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "guid/port validation failed");
		error = B_TRUE;
		goto bail;
	}

	/* get the ci */
	status = ibmf_i_get_ci(client_infop, &ibmf_cip);
	if (status != IBMF_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_register_error, IBMF_TNF_ERROR, "",
		    "ibmf_register(): %s, guid = 0x%p\n",
		    tnf_string, msg, "unable to get ci",
		    tnf_ulonglong, guid, client_infop->ir_ci_guid);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_register_end,
		    IBMF_TNF_TRACE, "", "ibmf_register() exit\n");
		return (status);
	}

	/*
	 * check if classes and port are already registered for.
	 */
	status = ibmf_i_validate_classes_and_port(ibmf_cip, client_infop);
	if (status != IBMF_SUCCESS) {
		mutex_enter(&ibmf_cip->ci_mutex);
		IBMF_ADD32_PORT_KSTATS(ibmf_cip, client_regs_failed, 1);
		mutex_exit(&ibmf_cip->ci_mutex);
		/* release ci */
		ibmf_i_release_ci(ibmf_cip);
		(void) sprintf(errmsg,
		    "class and port already registered for or unsupported");
		error = B_TRUE;
		goto bail;
	}

	/*
	 * the class is valid, get qp and alloc the client
	 */
	/* obtain the qp corresponding to the port and classes */
	status = ibmf_i_get_qp(ibmf_cip, client_infop->ir_port_num,
	    client_infop->ir_client_class, &ibmf_qpp);
	if (status != IBMF_SUCCESS) {
		mutex_enter(&ibmf_cip->ci_mutex);
		IBMF_ADD32_PORT_KSTATS(ibmf_cip, client_regs_failed, 1);
		mutex_exit(&ibmf_cip->ci_mutex);
		ibmf_i_release_ci(ibmf_cip);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_register_error, IBMF_TNF_ERROR, "",
		    "ibmf_register(): %s, class = 0x%x\n",
		    tnf_string, msg, "can't get qp",
		    tnf_int, class, client_infop->ir_client_class);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_register_end,
		    IBMF_TNF_TRACE, "", "ibmf_register() exit\n");
		return (status);
	}

	/* alloc the client */
	status = ibmf_i_alloc_client(client_infop, flags, &ibmf_clientp);
	if (status != IBMF_SUCCESS) {
		mutex_enter(&ibmf_cip->ci_mutex);
		IBMF_ADD32_PORT_KSTATS(ibmf_cip, client_regs_failed, 1);
		mutex_exit(&ibmf_cip->ci_mutex);
		ibmf_i_release_ci(ibmf_cip);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_register_error, IBMF_TNF_ERROR, "",
		    "ibmf_register(): %s, class = 0x%x\n",
		    tnf_string, msg, "can't alloc client",
		    tnf_int, class, client_infop->ir_client_class);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_register_end,
		    IBMF_TNF_TRACE, "", "ibmf_register() exit\n");
		return (status);
	}

	ASSERT(ibmf_clientp != NULL);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibmf_clientp))

	/* initialize the IBMF client context */
	ibmf_clientp->ic_myci = ibmf_cip;
	ibmf_clientp->ic_qp = ibmf_qpp;
	ibmf_clientp->ic_ci_handle = ibmf_cip->ci_ci_handle;

	ibmf_clientp->ic_reg_flags = flags;

	ibmf_clientp->ic_async_cb = client_cb;
	ibmf_clientp->ic_async_cb_arg = client_cb_args;

	IBMF_SET_CLIENT_SIGNATURE(ibmf_clientp);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ibmf_clientp))

	/* add the client to the list of clients */
	ibmf_i_add_client(ibmf_cip, ibmf_clientp);

	/* increment kstats for number of registered clients */
	mutex_enter(&ibmf_cip->ci_mutex);
	IBMF_ADD32_PORT_KSTATS(ibmf_cip, clients_registered, 1);
	mutex_exit(&ibmf_cip->ci_mutex);

	/* Setup ibmf_handlep -- handle is last allocated clientp */
	*ibmf_handlep = (ibmf_handle_t)ibmf_clientp;
	*ibmf_impl_features = 0;

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_register_error, IBMF_TNF_ERROR, "",
		    "ibmf_register(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_register_end,
	    IBMF_TNF_TRACE, "", "ibmf_register() exit, ibmf_handle = %p\n",
	    tnf_opaque, ibmf_handle, *ibmf_handlep);

	return (status);
}

/* ARGSUSED */
int
ibmf_unregister(ibmf_handle_t *ibmf_handlep, uint_t flags)
{
	ibmf_ci_t	*cip;
	ibmf_client_t	*clientp;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];
	int		secs;

	clientp = (ibmf_client_t *)*ibmf_handlep;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_unregister_start,
	    IBMF_TNF_TRACE, "", "ibmf_unregister() enter, "
	    "ibmf_handlep = %p, flags = 0x%x\n",
	    tnf_opaque, ibmf_handle, *ibmf_handlep, tnf_uint, flags, flags);

	/* check for null ibmf_handlep */
	if (ibmf_handlep == NULL) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handlep */
	if (ibmf_i_is_ibmf_handle_valid(*ibmf_handlep) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad client signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/*
	 * Verify the client does not have a receive callback registered.
	 * If there are messages, give some time for the messages to be
	 * cleaned up.
	 */
	secs = 60;
	mutex_enter(&clientp->ic_mutex);
	while (clientp->ic_recv_cb == NULL && clientp->ic_msgs_alloced != 0 &&
	    secs > 0) {
		mutex_exit(&clientp->ic_mutex);
		delay(drv_usectohz(1000000)); /* one second delay */
		secs--;
		mutex_enter(&clientp->ic_mutex);
	}

	if (clientp->ic_recv_cb != NULL || clientp->ic_msgs_alloced != 0) {
		IBMF_TRACE_4(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_unregister_err, IBMF_TNF_ERROR, "",
		    "ibmf_unregister(): %s, flags = 0x%x, recv_cb = 0x%p, "
		    "msgs_alloced = %d\n",
		    tnf_string, msg, "busy with resources", tnf_uint, ic_flags,
		    clientp->ic_flags, tnf_opaque, recv_cb, clientp->ic_recv_cb,
		    tnf_uint, msgs_allocd, clientp->ic_msgs_alloced);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_unregister_end,
		    IBMF_TNF_TRACE, "", "ibmf_unregister() exit\n");
		mutex_exit(&clientp->ic_mutex);
		return (IBMF_BUSY);
	}

	mutex_exit(&clientp->ic_mutex);

	cip = clientp->ic_myci;

	/* remove the client from the list of clients */
	ibmf_i_delete_client(cip, clientp);

	/* release the reference to the qp */
	ibmf_i_release_qp(cip, &clientp->ic_qp);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*clientp))

	/* and free the client structure */
	ibmf_i_free_client(clientp);

	/* release the ci; this may delete & free the ci structure */
	ibmf_i_release_ci(cip);

	/* decrement kstats for number of registered clients */
	mutex_enter(&cip->ci_mutex);
	IBMF_SUB32_PORT_KSTATS(cip, clients_registered, 1);
	mutex_exit(&cip->ci_mutex);

	*ibmf_handlep = NULL;

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_unregister_err, IBMF_TNF_ERROR, "",
		    "ibmf_unregister(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_unregister_end,
	    IBMF_TNF_TRACE, "", "ibmf_unregister() exit\n");

	return (status);
}


/* ARGSUSED */
int
ibmf_setup_async_cb(ibmf_handle_t ibmf_handle, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_cb_t async_msg_cb, void *async_msg_cb_args, uint_t flags)
{
	ibmf_client_t	*clientp;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	clientp = (ibmf_client_t *)ibmf_handle;

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_setup_async_cb_start,
	    IBMF_TNF_TRACE, "", "ibmf_setup_async_cb() enter, "
	    "ibmf_handlep = %p, cb = 0x%p, cb_args = 0x%p, flags = 0x%x\n",
	    tnf_opaque, ibmf_handle, ibmf_handle, tnf_opaque, cb,
	    async_msg_cb, tnf_opaque, cb_args, async_msg_cb_args,
	    tnf_uint, flags, flags);

	/* check for null ibmf_handlep */
	if (ibmf_handle == NULL) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_i_is_qp_handle_valid(ibmf_handle, ibmf_qp_handle) !=
	    IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad qp handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	ASSERT(clientp->ic_myci != NULL);

	/* store the registered callback in the appropriate context */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {

		/*
		 * if using the default QP handle, store the callback in
		 * the client context
		 */
		mutex_enter(&clientp->ic_mutex);

		/* check if the callback has already been registered */
		if (clientp->ic_recv_cb != NULL) {
			mutex_exit(&clientp->ic_mutex);
			(void) sprintf(errmsg, "cb already exists");
			error = B_TRUE;
			status = IBMF_CB_REGISTERED;
			goto bail;
		}

		clientp->ic_recv_cb = async_msg_cb;
		clientp->ic_recv_cb_arg = async_msg_cb_args;
		mutex_exit(&clientp->ic_mutex);

	} else {
		ibmf_alt_qp_t *qp_ctxp = (ibmf_alt_qp_t *)ibmf_qp_handle;

		/*
		 * if using an alternate QP handle, store the callback in
		 * the alternate QP context because there can be more than
		 * one alternate QP associated with a client
		 */
		mutex_enter(&qp_ctxp->isq_mutex);

		/* check if the callback has already been registered */
		if (qp_ctxp->isq_recv_cb != NULL) {
			mutex_exit(&qp_ctxp->isq_mutex);
			(void) sprintf(errmsg, "cb already exists");
			error = B_TRUE;
			status = IBMF_CB_REGISTERED;
			goto bail;
		}

		qp_ctxp->isq_recv_cb = async_msg_cb;
		qp_ctxp->isq_recv_cb_arg = async_msg_cb_args;

		mutex_exit(&qp_ctxp->isq_mutex);
	}

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_setup_async_cb_err, IBMF_TNF_ERROR, "",
		    "ibmf_setup_async_cb(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_setup_async_cb_end,
	    IBMF_TNF_TRACE, "", "ibmf_setup_async_cb() exit\n");

	return (status);
}


/* ARGSUSED */
int
ibmf_tear_down_async_cb(ibmf_handle_t ibmf_handle,
    ibmf_qp_handle_t ibmf_qp_handle, uint_t flags)
{
	ibmf_client_t	*clientp;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	clientp = (ibmf_client_t *)ibmf_handle;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_tear_down_async_cb_start,
	    IBMF_TNF_TRACE, "", "ibmf_tear_down_async_cb() enter, "
	    "ibmf_handlep = %p, ibmf_qp_handle = %p, flags = 0x%x\n",
	    tnf_opaque, ibmf_handle, ibmf_handle,
	    tnf_opaque, ibmf_qp_handle, ibmf_qp_handle, tnf_uint, flags, flags);

	/* check for null ibmf_handlep */
	if (ibmf_handle == NULL) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_i_is_qp_handle_valid(ibmf_handle, ibmf_qp_handle) !=
	    IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad qp handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	ASSERT(clientp->ic_myci != NULL);

	/* remove the registered callback from the appropriate context */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {

		mutex_enter(&clientp->ic_mutex);

		/* check if callback has not been registered */
		if (clientp->ic_recv_cb == NULL) {
			mutex_exit(&clientp->ic_mutex);
			(void) sprintf(errmsg, "no cb exists");
			error = B_TRUE;
			status = IBMF_CB_NOT_REGISTERED;
			goto bail;
		}

		/*
		 * if an unsolicited MAD just arrived for this
		 * client, wait for it to be processed
		 */
		while (clientp->ic_flags & IBMF_CLIENT_RECV_CB_ACTIVE) {
			clientp->ic_flags |= IBMF_CLIENT_TEAR_DOWN_CB;
			cv_wait(&clientp->ic_recv_cb_teardown_cv,
			    &clientp->ic_mutex);
			clientp->ic_flags &= ~IBMF_CLIENT_TEAR_DOWN_CB;
		}

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(clientp->ic_recv_cb,
		     clientp->ic_recv_cb_arg))

		/*
		 * if using the default QP handle, remove the callback from
		 * the client context
		 */
		clientp->ic_recv_cb = NULL;
		clientp->ic_recv_cb_arg = NULL;

		ASSERT((clientp->ic_flags & IBMF_CLIENT_RECV_CB_ACTIVE) == 0);

		mutex_exit(&clientp->ic_mutex);
	} else {
		ibmf_alt_qp_t *qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;

		mutex_enter(&qpp->isq_mutex);

		/* check if callback has not been registered */
		if (qpp->isq_recv_cb == NULL) {
			mutex_exit(&qpp->isq_mutex);
			(void) sprintf(errmsg, "no cb exists");
			error = B_TRUE;
			status = IBMF_CB_NOT_REGISTERED;
			goto bail;
		}

		/*
		 * if an unsolicited MAD just arrived for this
		 * client on the alternate QP, wait for it to be processed
		 */
		while (qpp->isq_flags & IBMF_CLIENT_RECV_CB_ACTIVE) {
			qpp->isq_flags |= IBMF_CLIENT_TEAR_DOWN_CB;
			cv_wait(&qpp->isq_recv_cb_teardown_cv,
			    &qpp->isq_mutex);
			qpp->isq_flags &= ~IBMF_CLIENT_TEAR_DOWN_CB;
		}

		/*
		 * if using an alternate QP handle, remove the callback from
		 * the alternate QP context
		 */
		qpp->isq_recv_cb = NULL;
		qpp->isq_recv_cb_arg = NULL;

		ASSERT((qpp->isq_flags & IBMF_CLIENT_RECV_CB_ACTIVE) == 0);

		mutex_exit(&qpp->isq_mutex);
	}

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_tear_down_async_cb_err, IBMF_TNF_ERROR, "",
		    "ibmf_tear_down_async_cb(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_tear_down_async_cb_end,
	    IBMF_TNF_TRACE, "", "ibmf_tear_down_async_cb() exit\n");

	return (status);
}


int
ibmf_alloc_msg(ibmf_handle_t ibmf_handle, int flag, ibmf_msg_t **ibmf_msgpp)
{
	ibmf_msg_impl_t	*ibmf_msg_impl;
	ibmf_client_t	*clientp;
	int		km_flags;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	clientp = (ibmf_client_t *)ibmf_handle;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_alloc_msg_start,
	    IBMF_TNF_TRACE, "", "ibmf_alloc_msg() enter, "
	    "ibmf_handle = %p, flags = 0x%x\n",
	    tnf_opaque, ibmf_handle, ibmf_handle, tnf_uint, flag, flag);

	/* check for null ibmf_handle and ibmf_msgpp */
	if ((ibmf_handle == NULL) || (ibmf_msgpp == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate flag */
	if (flag != IBMF_ALLOC_SLEEP && flag != IBMF_ALLOC_NOSLEEP) {
		(void) sprintf(errmsg, "invalid flags, flags = 0x%x", flag);
		error = B_TRUE;
		status = IBMF_BAD_FLAGS;
		goto bail;
	}

	/* set flags for kmem allocaton */
	km_flags = (flag == IBMF_ALLOC_SLEEP) ? KM_SLEEP : KM_NOSLEEP;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibmf_msg_impl))

	/* call the internal function to allocate the IBMF message context */
	status = ibmf_i_alloc_msg(clientp, &ibmf_msg_impl, km_flags);
	if (status != IBMF_SUCCESS) {
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, msg_allocs_failed, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
		(void) sprintf(errmsg, "message allocation failure");
		error = B_TRUE;
		goto bail;
	}

	/* increment counter and kstats for number of allocated messages */
	mutex_enter(&clientp->ic_mutex);
	clientp->ic_msgs_alloced++;
	mutex_exit(&clientp->ic_mutex);
	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_ADD32_KSTATS(clientp, msgs_alloced, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	/* initialize the msg */
	ibmf_msg_impl->im_client = clientp;
	cv_init(&ibmf_msg_impl->im_trans_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&ibmf_msg_impl->im_mutex, NULL, MUTEX_DRIVER, NULL);
	*ibmf_msgpp = (ibmf_msg_t *)ibmf_msg_impl;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*ibmf_msg_impl))

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_alloc_msg_err, IBMF_TNF_ERROR, "",
		    "ibmf_alloc_msg(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_alloc_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_alloc_msg() exit\n");

	return (status);
}


int
ibmf_free_msg(ibmf_handle_t ibmf_handle, ibmf_msg_t **ibmf_msgpp)
{
	ibmf_client_t	*clientp;
	ibmf_msg_impl_t	*ibmf_msg_impl;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];
	timeout_id_t	msg_rp_set_id, msg_tr_set_id;
	timeout_id_t	msg_rp_unset_id, msg_tr_unset_id;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_free_msg_start,
	    IBMF_TNF_TRACE, "", "ibmf_free_msg() enter, " "ibmf_handle = %p\n",
	    tnf_opaque, ibmf_handle, ibmf_handle);

	/* check for null ibmf_handle and ibmf_msgpp */
	if ((ibmf_handle == NULL) || (ibmf_msgpp == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	ibmf_msg_impl = (ibmf_msg_impl_t *)*ibmf_msgpp;

	/* check for null message pointer */
	if (ibmf_msg_impl == NULL) {
		(void) sprintf(errmsg, "null message");
		error = B_TRUE;
		status = IBMF_FAILURE;
		goto bail;
	}

	mutex_enter(&ibmf_msg_impl->im_mutex);

	/* check if message context flags indicate a busy message */
	if (ibmf_msg_impl->im_flags & IBMF_MSG_FLAGS_BUSY) {
		mutex_exit(&ibmf_msg_impl->im_mutex);
		(void) sprintf(errmsg, "message in use");
		error = B_TRUE;
		status = IBMF_BUSY;
		goto bail;
	}

	ASSERT((ibmf_msg_impl->im_flags & IBMF_MSG_FLAGS_ON_LIST) == 0);

	/* Initialize the timer ID holders */
	msg_rp_set_id = msg_tr_set_id = 0;
	msg_rp_unset_id = msg_tr_unset_id = 0;

	/* Clear any timers that are still set */

	if (ibmf_msg_impl->im_rp_timeout_id != 0) {
		msg_rp_set_id = ibmf_msg_impl->im_rp_timeout_id;
		ibmf_msg_impl->im_rp_timeout_id = 0;
	}

	if (ibmf_msg_impl->im_tr_timeout_id != 0) {
		msg_tr_set_id = ibmf_msg_impl->im_tr_timeout_id;
		ibmf_msg_impl->im_tr_timeout_id = 0;
	}

	if (ibmf_msg_impl->im_rp_unset_timeout_id != 0) {
		msg_rp_unset_id = ibmf_msg_impl->im_rp_unset_timeout_id;
		ibmf_msg_impl->im_rp_unset_timeout_id = 0;
	}

	if (ibmf_msg_impl->im_tr_unset_timeout_id != 0) {
		msg_tr_unset_id = ibmf_msg_impl->im_tr_unset_timeout_id;
		ibmf_msg_impl->im_tr_unset_timeout_id = 0;
	}

	/* mark the message context flags to indicate a freed message */
	ibmf_msg_impl->im_flags |= IBMF_MSG_FLAGS_FREE;

	mutex_exit(&ibmf_msg_impl->im_mutex);

	/* cast pointer to client context */
	clientp = (ibmf_client_t *)ibmf_handle;

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* Clear the timers */
	if (msg_rp_unset_id != 0) {
		(void) untimeout(msg_rp_unset_id);
	}

	if (msg_tr_unset_id != 0) {
		(void) untimeout(msg_tr_unset_id);
	}

	if (msg_rp_set_id != 0) {
		(void) untimeout(msg_rp_set_id);
	}

	if (msg_tr_set_id != 0) {
		(void) untimeout(msg_tr_set_id);
	}

	/* destroy the condition variables */
	cv_destroy(&ibmf_msg_impl->im_trans_cv);

	/* decrement counter and kstats for number of allocated messages */
	mutex_enter(&clientp->ic_mutex);
	clientp->ic_msgs_alloced--;
	mutex_exit(&clientp->ic_mutex);
	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_SUB32_KSTATS(clientp, msgs_alloced, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ibmf_msg_impl,
	    ibmf_msg_impl->im_msgbufs_recv,
	    ibmf_msg_impl->im_msgbufs_send))

	/* call the internal function to free the message context */
	ibmf_i_free_msg(ibmf_msg_impl);

	*ibmf_msgpp = NULL;

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_free_msg_err, IBMF_TNF_ERROR, "",
		    "ibmf_free_msg(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_free_msg_end,
	    IBMF_TNF_TRACE, "", "ibmf_free_msg() exit\n");

	return (status);
}


/* ARGSUSED */
int
ibmf_msg_transport(ibmf_handle_t ibmf_handle, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_t *msgp, ibmf_retrans_t *retrans, ibmf_msg_cb_t msg_cb,
    void *msg_cb_args, uint_t flags)
{
	ibmf_client_t	*clientp;
	ibmf_msg_impl_t	*msgimplp;
	boolean_t	blocking, loopback, error = B_FALSE;
	int		status = IBMF_SUCCESS;
	sm_dr_mad_hdr_t	*dr_hdr;
	char		errmsg[128];

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_msg_transport_start,
	    IBMF_TNF_TRACE, "", "ibmf_msg_transport() enter, "
	    "ibmf_handlep = %p, ibmf_qp_handle = %p, flags = 0x%x "
	    "msgp = 0x%p, retrans = 0x%p\n",
	    tnf_opaque, ibmf_handle, ibmf_handle,
	    tnf_opaque, ibmf_qp_handle, ibmf_qp_handle, tnf_uint, flags, flags,
	    tnf_opaque, msgp, msgp, tnf_opaque, retrans, retrans);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msgp,*msgimplp))

	/* check for null ibmf_handle and msgp */
	if ((ibmf_handle == NULL) || (msgp == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_i_is_qp_handle_valid(ibmf_handle, ibmf_qp_handle) !=
	    IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad qp handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	clientp = (ibmf_client_t *)ibmf_handle;

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/*
	 * Check the validity of the pkey and qkey in the posted packet
	 * For special QPs do the check for QP1 only
	 * For the alternate qps, the pkey and qkey should match the
	 * pkey and qkey maintained in the ibmf cached qp context
	 */
	if ((ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) &&
	    ((clientp->ic_client_info.client_class != SUBN_AGENT) &&
	    (clientp->ic_client_info.client_class != SUBN_MANAGER))) {

		if ((msgp->im_local_addr.ia_p_key != IBMF_P_KEY_DEF_FULL) &&
		    (msgp->im_local_addr.ia_p_key != IBMF_P_KEY_DEF_LIMITED)) {
			(void) sprintf(errmsg,
			    "PKey in packet not default PKey");
			error = B_TRUE;
			status = IBMF_BAD_QP_HANDLE;
			goto bail;
		}

		if (msgp->im_local_addr.ia_q_key != IBMF_MGMT_Q_KEY) {
			(void) sprintf(errmsg, "QKey in packet not Mgt QKey");
			error = B_TRUE;
			status = IBMF_BAD_QP_HANDLE;
			goto bail;
		}
	} else if (ibmf_qp_handle != IBMF_QP_HANDLE_DEFAULT) {
		ibmf_alt_qp_t *qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;

		/* alternate QP context */

		mutex_enter(&qpp->isq_mutex);

		if (msgp->im_local_addr.ia_p_key != qpp->isq_pkey) {
			mutex_exit(&qpp->isq_mutex);
			(void) sprintf(errmsg, "PKey in packet does not match "
			    "PKey in the QP context");
			error = B_TRUE;
			status = IBMF_BAD_QP_HANDLE;
			goto bail;
		}

		if (msgp->im_local_addr.ia_q_key != qpp->isq_qkey) {
			mutex_exit(&qpp->isq_mutex);
			(void) sprintf(errmsg, "QKey in packet does not match "
			    "QKey in the QP context");
			error = B_TRUE;
			status = IBMF_BAD_QP_HANDLE;
			goto bail;
		}

		mutex_exit(&qpp->isq_mutex);
	}

	msgimplp = (ibmf_msg_impl_t *)msgp;

	ASSERT(msgimplp->im_client != NULL);
	ASSERT(msgimplp->im_client == clientp);

	msgimplp->im_transp_op_flags = flags;

	mutex_enter(&msgimplp->im_mutex);

	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		if (msgimplp->im_msgbufs_send.im_bufs_mad_hdr == NULL) {
			mutex_exit(&msgimplp->im_mutex);
			(void) sprintf(errmsg, "Send buffer MAD header data "
			    "not provided for special QP");
			error = B_TRUE;
			status = IBMF_BAD_SIZE;
			goto bail;
		}
	} else {
		ibmf_alt_qp_t *qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;

		mutex_enter(&qpp->isq_mutex);

		if (((qpp->isq_flags & IBMF_RAW_ONLY) == 0) &&
		    (msgimplp->im_msgbufs_send.im_bufs_mad_hdr == NULL)) {
			mutex_exit(&qpp->isq_mutex);
			mutex_exit(&msgimplp->im_mutex);
			(void) sprintf(errmsg, "Send buffer MAD header data "
			    "not provided for alternate QP");
			error = B_TRUE;
			status = IBMF_BAD_SIZE;
			goto bail;
		}
		mutex_exit(&qpp->isq_mutex);
	}

	/* check if client has freed the message by calling ibmf_free_msg() */
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_FREE) {
		mutex_exit(&msgimplp->im_mutex);
		(void) sprintf(errmsg, "Message is being freed");
		error = B_TRUE;
		status = IBMF_BUSY;
		goto bail;
	}

	/*
	 * check if the message is already in use in an
	 * ibmf_msg_transport() call
	 */
	if (msgimplp->im_flags & IBMF_MSG_FLAGS_BUSY) {
		mutex_exit(&msgimplp->im_mutex);
		(void) sprintf(errmsg,
		    "Message is being processed by an other thread");
		error = B_TRUE;
		status = IBMF_BUSY;
		goto bail;
	}

	msgimplp->im_flags = IBMF_MSG_FLAGS_BUSY;

	mutex_exit(&msgimplp->im_mutex);

	/* check for the Directed Route SMP loopback case */
	loopback = B_FALSE;
	dr_hdr = (sm_dr_mad_hdr_t *)msgimplp->im_msgbufs_send.im_bufs_mad_hdr;
	if ((dr_hdr->MgmtClass == MAD_MGMT_CLASS_SUBN_DIRECT_ROUTE) &&
	    (dr_hdr->HopCount == 0)) {
		loopback = B_TRUE;
	}

	/* check for and perform DR loopback on tavor */
	status = ibmf_i_check_for_loopback(msgimplp, msg_cb, msg_cb_args,
	    retrans, &loopback);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "dr_loopback_check failed");
		error = B_TRUE;
		mutex_enter(&msgimplp->im_mutex);
		msgimplp->im_flags &= ~IBMF_MSG_FLAGS_BUSY;
		mutex_exit(&msgimplp->im_mutex);
		goto bail;
	}
	if (loopback == B_TRUE) {
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_msg_transport_end, IBMF_TNF_TRACE, "",
		    "ibmf_msg_transport() exit, dr_loopback ok\n");
		return (IBMF_SUCCESS);
	}

	if (msg_cb == NULL) {
		blocking = B_TRUE;
	} else {
		blocking = B_FALSE;
	}

	/* initialize the message context */
	ibmf_i_init_msg(msgimplp, msg_cb, msg_cb_args, retrans, blocking);

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msgp,*msgimplp))

	/* call the internal function to transport the message */
	status = ibmf_i_msg_transport(clientp, ibmf_qp_handle, msgimplp,
	    blocking);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "message transport failed");
		error = B_TRUE;
		mutex_enter(&msgimplp->im_mutex);
		msgimplp->im_flags &= ~IBMF_MSG_FLAGS_BUSY;
		mutex_exit(&msgimplp->im_mutex);
		goto bail;
	}

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_msg_transport_err, IBMF_TNF_ERROR, "",
		    "ibmf_msg_transport(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_msg_transport_end,
	    IBMF_TNF_TRACE, "", "ibmf_msg_transport() exit\n");

	return (status);
}


/* ARGSUSED */
int
ibmf_alloc_qp(ibmf_handle_t ibmf_handle, ib_pkey_t p_key, ib_qkey_t q_key,
    uint_t flags, ibmf_qp_handle_t *ibmf_qp_handlep)
{
	ibmf_client_t	*clientp = (ibmf_client_t *)ibmf_handle;
	uint_t		alloc_flags;
	ibmf_alt_qp_t	*qp_ctx;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_alloc_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_alloc_qp() enter, "
	    "ibmf_handlep = %p, p_key = 0x%x, q_key = 0x%x\n",
	    tnf_opaque, ibmf_handle, ibmf_handle,
	    tnf_uint, pkey, p_key, tnf_uint, qkey, q_key);

	/* check for null ibmf_handle and ibmf_qp_handle */
	if ((ibmf_handle == NULL) || (ibmf_qp_handlep == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate PKey */
	if (IBMF_INVALID_PKEY(p_key)) {
		(void) sprintf(errmsg, "invalid value in p_key argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	if (((flags & IBMF_ALT_QP_MAD_NO_RMPP) == 0) &&
	    ((flags & IBMF_ALT_QP_MAD_RMPP) == 0) &&
	    ((flags & IBMF_ALT_QP_RAW_ONLY) == 0)) {
		(void) sprintf(errmsg, "invalid flags combination");
		error = B_TRUE;
		status = IBMF_BAD_FLAGS;
		goto bail;
	}

	alloc_flags = IBMF_ALLOC_SLEEP;

	/* call the internal function to allocate the alternate QP context */
	status = ibmf_i_alloc_qp(clientp, p_key, q_key, alloc_flags,
	    ibmf_qp_handlep);
	if (status != IBMF_SUCCESS) {
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, alt_qp_allocs_failed, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
		(void) sprintf(errmsg, "unable to allocate QP");
		error = B_TRUE;
		status = IBMF_NO_RESOURCES;
		goto bail;
	}

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*qp_ctx))

	qp_ctx = (ibmf_alt_qp_t *)*ibmf_qp_handlep;

	/* initialize the alternate qp context */
	if (flags & IBMF_ALT_QP_MAD_NO_RMPP)
		qp_ctx->isq_flags |= IBMF_MAD_ONLY;

	if (flags & IBMF_ALT_QP_RAW_ONLY)
		qp_ctx->isq_flags |= IBMF_RAW_ONLY;

	if (flags & IBMF_ALT_QP_MAD_RMPP)
		qp_ctx->isq_supports_rmpp = B_TRUE;
	else
		qp_ctx->isq_supports_rmpp = B_FALSE;

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_alloc_qp_err, IBMF_TNF_ERROR, "",
		    "ibmf_alloc_qp(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_alloc_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_alloc_qp() exit\n");


	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*qp_ctx))

	return (status);
}


/* ARGSUSED */
int
ibmf_query_qp(ibmf_handle_t ibmf_handle, ibmf_qp_handle_t ibmf_qp_handle,
    uint_t *qp_num, ib_pkey_t *p_key, ib_qkey_t *q_key, uint8_t *portnum,
    uint_t flags)
{
	ibmf_client_t	*clientp = (ibmf_client_t *)ibmf_handle;
	ibmf_alt_qp_t *qp_ctx = (ibmf_alt_qp_t *)ibmf_qp_handle;
	uint_t		query_flags;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_query_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_query_qp() enter, "
	    "ibmf_handlep = %p, ibmf_qp_handle = %p\n",
	    tnf_opaque, ibmf_handle, ibmf_handle,
	    tnf_opaque, ibmf_qp_handle, ibmf_qp_handle);

	/* check for null args */
	if ((ibmf_handle == NULL) || (ibmf_qp_handle == NULL) ||
	    (qp_num == NULL) || (p_key == NULL) || (q_key == NULL) ||
	    (portnum == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_i_is_qp_handle_valid(ibmf_handle, ibmf_qp_handle) !=
	    IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad qp handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		(void) sprintf(errmsg, "bad qp handle (default)");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad client signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate client context handle */
	if (qp_ctx->isq_client_hdl != clientp) {
		(void) sprintf(errmsg, "bad QP handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	query_flags = IBMF_ALLOC_NOSLEEP;

	/* call the internal function to query the alternate qp */
	status = ibmf_i_query_qp(ibmf_qp_handle, query_flags, qp_num, p_key,
	    q_key, portnum);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "unable to query QP");
		error = B_TRUE;
		goto bail;
	}

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_query_qp_err, IBMF_TNF_ERROR, "",
		    "ibmf_query_qp(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_query_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_query_qp() exit, qp = %d, "
	    "pkey = 0x%x, qkey = 0x%x\n", tnf_uint, qp_num, *qp_num,
	    tnf_uint, pkey, *p_key, tnf_uint, qkey, *q_key);

	return (status);
}


/* ARGSUSED */
int
ibmf_modify_qp(ibmf_handle_t ibmf_handle, ibmf_qp_handle_t ibmf_qp_handle,
    ib_pkey_t p_key, ib_qkey_t q_key, uint_t flags)
{
	ibmf_client_t	*clientp = (ibmf_client_t *)ibmf_handle;
	ibmf_alt_qp_t *qp_ctx = (ibmf_alt_qp_t *)ibmf_qp_handle;
	uint_t		modify_flags;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_modify_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_modify_qp() enter, "
	    "ibmf_handlep = %p, ibmf_qp_handle = %p, pkey = 0x%x, "
	    "qkey = 0x%x\n", tnf_opaque, ibmf_handle, ibmf_handle,
	    tnf_opaque, ibmf_qp_handle, ibmf_qp_handle,
	    tnf_uint, p_key, p_key, tnf_uint, q_key, q_key);

	/* check for null args */
	if ((ibmf_handle == NULL) || (ibmf_qp_handle == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_i_is_qp_handle_valid(ibmf_handle, ibmf_qp_handle) !=
	    IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad qp handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		(void) sprintf(errmsg, "bad qp handle (default)");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad client signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate PKey */
	if (IBMF_INVALID_PKEY(p_key)) {
		(void) sprintf(errmsg, "invalid value in p_key argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	if (qp_ctx->isq_client_hdl != clientp) {
		(void) sprintf(errmsg, "bad QP handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	modify_flags = IBMF_ALLOC_SLEEP;

	/* call the internal function to modify the qp */
	status = ibmf_i_modify_qp(ibmf_qp_handle, p_key, q_key, modify_flags);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "unable to modify QP");
		error = B_TRUE;
		goto bail;
	}

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_modify_qp_err, IBMF_TNF_ERROR, "",
		    "ibmf_modify_qp(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_modify_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_modify_qp() exit\n");

	return (status);
}

/* ARGSUSED */
int
ibmf_free_qp(ibmf_handle_t ibmf_handle, ibmf_qp_handle_t *ibmf_qp_handle,
    uint_t flags)
{
	ibmf_client_t	*clientp = (ibmf_client_t *)ibmf_handle;
	ibmf_alt_qp_t	*qp_ctx = (ibmf_alt_qp_t *)*ibmf_qp_handle;
	uint_t		modify_flags;
	boolean_t	error = B_FALSE;
	int		status = IBMF_SUCCESS;
	char		errmsg[128];

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_free_qp_start,
	    IBMF_TNF_TRACE, "", "ibmf_free_qp() enter, "
	    "ibmf_handlep = %p, ibmf_qp_handle = %p\n",
	    tnf_opaque, ibmf_handle, ibmf_handle,
	    tnf_opaque, ibmf_qp_handle, *ibmf_qp_handle);

	/* check for null args */
	if ((ibmf_handle == NULL) || (ibmf_qp_handle == NULL)) {
		(void) sprintf(errmsg,
		    "invalid argument, NULL pointer argument");
		error = B_TRUE;
		status = IBMF_INVALID_ARG;
		goto bail;
	}

	/* validate ibmf_handle */
	if (ibmf_i_is_ibmf_handle_valid(ibmf_handle) != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad ibmf registration handle");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (ibmf_i_is_qp_handle_valid(ibmf_handle, *ibmf_qp_handle) !=
	    IBMF_SUCCESS) {
		(void) sprintf(errmsg, "bad qp handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* validate ibmf_qp_handle */
	if (*ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		(void) sprintf(errmsg, "bad qp handle (default)");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	/* check signature */
	if (IBMF_VERIFY_CLIENT_SIGNATURE(clientp) == B_FALSE) {
		(void) sprintf(errmsg, "bad client signature");
		error = B_TRUE;
		status = IBMF_BAD_HANDLE;
		goto bail;
	}

	/* validate client context handle */
	if (qp_ctx->isq_client_hdl != clientp) {
		(void) sprintf(errmsg, "bad QP handle");
		error = B_TRUE;
		status = IBMF_BAD_QP_HANDLE;
		goto bail;
	}

	mutex_enter(&qp_ctx->isq_mutex);

	if (qp_ctx->isq_recv_cb != NULL) {
		mutex_exit(&qp_ctx->isq_mutex);
		(void) sprintf(errmsg, "QP busy, callback active");
		error = B_TRUE;
		status = IBMF_BUSY;
		goto bail;
	}

	mutex_exit(&qp_ctx->isq_mutex);

	modify_flags = IBMF_ALLOC_SLEEP;

	status = ibmf_i_free_qp(*ibmf_qp_handle, modify_flags);
	if (status != IBMF_SUCCESS) {
		(void) sprintf(errmsg, "unable to free QP");
		error = B_TRUE;
		goto bail;
	}

	*ibmf_qp_handle = NULL;

bail:
	if (error) {
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_free_qp_err, IBMF_TNF_ERROR, "",
		    "ibmf_free_qp(): %s\n", tnf_string, msg, errmsg);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_free_qp_end,
	    IBMF_TNF_TRACE, "", "ibmf_free_qp() exit\n");

	return (status);
}
