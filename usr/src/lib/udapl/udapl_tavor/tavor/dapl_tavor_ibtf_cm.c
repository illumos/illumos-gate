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

#include <strings.h>

#include <dapl.h>
#include <dapl_adapter_util.h>
#include <dapl_evd_util.h>
#include <dapl_cr_util.h>
#include <dapl_lmr_util.h>
#include <dapl_rmr_util.h>
#include <dapl_cookie.h>
#include <dapl_name_service.h>
#include <dapl_tavor_ibtf_impl.h>

/* Function prototypes */
extern DAT_RETURN dapls_tavor_wrid_init(ib_qp_handle_t);
extern void dapls_tavor_wrid_cleanup(DAPL_EP *, ib_qp_handle_t);

int g_dapl_loopback_connection = 0;

/*
 * dapls_ib_connect
 *
 * Initiate a connection with the passive listener on another node
 *
 * Input:
 *        ep_handle,
 *        remote_ia_address,
 *        remote_conn_qual,
 *	  prd_size		size of private data and structure
 *	  prd_prt		pointer to private data structure
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */

DAT_RETURN
dapls_ib_connect(IN DAT_EP_HANDLE ep_handle,
    IN DAT_IA_ADDRESS_PTR remote_ia_address, IN DAT_CONN_QUAL remote_conn_qual,
    IN DAT_COUNT prd_size, IN DAPL_PRIVATE *prd_ptr, IN DAT_TIMEOUT timeout)
{
	dapl_ep_connect_t args;
	DAPL_EP *ep_p = (DAPL_EP *)ep_handle;
	struct sockaddr *s;
	char addr_buf[64];
	ib_gid_t dgid;
	int retval;
	struct sockaddr_in6 *v6addr;
	struct sockaddr_in *v4addr;
	dapl_ia_addr_t *sap;

	s = (struct sockaddr *)remote_ia_address;
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_connect: ep 0x%p\n"
	    "                  addr %s, conn_qual %016llu, ep_hkey %016llx\n"
	    "                  prd_size %d, timeout 0x%x\n",
	    ep_p, dapls_inet_ntop(s, addr_buf, 64), remote_conn_qual,
	    ep_p->qp_handle->ep_hkey, prd_size, timeout);
	if (ep_p->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_connect: ep 0x%p, addr %s, conn_qual %016llu, "
		    "qp_handle == NULL\n", ep_p, dapls_inet_ntop(s,
		    addr_buf, 64), remote_conn_qual);
		return (DAT_INVALID_PARAMETER);
	}
	if (timeout == DAT_TIMEOUT_INFINITE) {
		args.epc_timeout = 0;
	} else {
		args.epc_timeout = timeout;
	}
	/* resolve remote address to dgid */
	retval = dapls_ns_lookup_address(ep_p->header.owner_ia,
	    remote_ia_address, timeout, &dgid);
	if (retval == DAT_SUCCESS) {
		args.epc_dgid = dgid;
	} else if ((retval & DAT_SUBTYPE_MASK) ==
	    DAT_INVALID_ADDRESS_UNREACHABLE) {
		/* let the kernel driver look up the dgid from ATS */
		args.epc_dgid.gid_guid = 0ULL;
		args.epc_dgid.gid_prefix = 0ULL;
	} else {
		return (retval);
	}
	args.epc_sid = remote_conn_qual;
	args.epc_hkey = ep_p->qp_handle->ep_hkey;
	sap = (dapl_ia_addr_t *)&args.epc_raddr_sadata;
	/*
	 * filled in the remote_ia_address for consistent though
	 * not necessary when dapls_ns_lookup_address has resolved the dgid
	 */
	switch (s->sa_family) {
	case AF_INET:
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		v4addr = (struct sockaddr_in *)s;
		sap->iad_v4pad[0] = 0;
		sap->iad_v4pad[1] = 0;
		sap->iad_v4pad[2] = 0;
		sap->iad_v4 = v4addr->sin_addr;
		break;
	case AF_INET6:
		/* LINTED: E_BAD_PTR_CAST_ALIGN */
		v6addr = (struct sockaddr_in6 *)s;
		sap->iad_v6 = v6addr->sin6_addr;
		break;
	}

	/* establish the hello message */
	(void) dapl_os_memzero((void *)&prd_ptr->hello_msg,
	    sizeof (DAPL_HELLO_MSG));
	/* on ATS leave the msg blank to avoid confusion to 3rd parties */
	if ((args.epc_dgid.gid_guid | args.epc_dgid.gid_prefix)) {
		prd_ptr->hello_msg.hi_checksum = DAPL_CHECKSUM;
		prd_ptr->hello_msg.hi_clen = prd_size;
		prd_ptr->hello_msg.hi_mid = 0;
		prd_ptr->hello_msg.hi_vers = DAPL_HELLO_MSG_VERS;

		/* fill in local address */
		s = (struct sockaddr *)
		    &ep_p->header.owner_ia->hca_ptr->hca_address;
		prd_ptr->hello_msg.hi_ipv = (uint8_t)s->sa_family;
		switch (s->sa_family) {
		case AF_INET:
			/* LINTED: E_BAD_PTR_CAST_ALIGN */
			v4addr = (struct sockaddr_in *)s;
			prd_ptr->hello_msg.hi_port = v4addr->sin_port;
			prd_ptr->hello_msg.hi_v4ipaddr = v4addr->sin_addr;
			break;
		case AF_INET6:
			/* LINTED: E_BAD_PTR_CAST_ALIGN */
			v6addr = (struct sockaddr_in6 *)s;
			prd_ptr->hello_msg.hi_port = v6addr->sin6_port;
			prd_ptr->hello_msg.hi_v6ipaddr = v6addr->sin6_addr;
			break;
		default:
			break; /* fall through */
		}
	}
	if (prd_size > 0) {
		(void) dapl_os_memcpy((void *)&args.epc_priv[0],
		    (void *)prd_ptr, sizeof (DAPL_PRIVATE));
	} else {
		(void) dapl_os_memcpy((void *)
		    &args.epc_priv[DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE],
		    (void *)&prd_ptr->hello_msg, sizeof (DAPL_HELLO_MSG));
	}
	args.epc_priv_sz = sizeof (DAPL_PRIVATE);

	retval = ioctl(ep_p->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_EP_CONNECT, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_connect: connect failed %s, retval %d\n\n",
		    strerror(errno), retval);
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_connect: connected to %s\n\n",
	    dapls_inet_ntop(s, addr_buf, 64));
	return (DAT_SUCCESS);
}

/*
 * dapls_ib_disconnect
 *
 * Disconnect an EP
 *
 * Input:
 *        ep_handle,
 *        disconnect_flags
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
/* ARGSUSED */
DAT_RETURN
dapls_ib_disconnect(IN DAPL_EP *ep_ptr,
    IN DAT_CLOSE_FLAGS close_flags)
{
	dapl_ep_disconnect_t args;
	struct sockaddr *s;
	char addr_buf[64];
	int retval;

	if (ep_ptr->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_disconnect: qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}
	args.epd_hkey = ep_ptr->qp_handle->ep_hkey;

	retval = ioctl(ep_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_EP_DISCONNECT, &args);
	/* no reason for disconnect to fail so transition the state */
	ep_ptr->qp_state = IBT_STATE_ERROR;

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_disconnect: disconnect failed %s\n",
		    strerror(errno));
		return (dapls_convert_error(errno, retval));
	}
	s = (struct sockaddr *)ep_ptr->param.remote_ia_address_ptr;
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_disconnect: disconnected from %s, conn_qual %016llu\n",
	    dapls_inet_ntop(s, addr_buf, 64), ep_ptr->param.remote_port_qual);
	return (DAT_SUCCESS);
}


/*
 * dapls_ib_connected
 *
 * transition qp_state to IBT_STATE_RTS
 *
 */
void
dapls_ib_connected(IN DAPL_EP *ep_ptr)
{
	ep_ptr->qp_state = IBT_STATE_RTS;
}


/*
 * dapls_ib_disconnect_clean
 *
 * transition qp_state to IBT_STATE_ERROR.
 * abort connection if necessary.
 *
 * Input:
 *	ep_ptr		DAPL_EP
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
/* ARGSUSED */
void
dapls_ib_disconnect_clean(IN DAPL_EP *ep_ptr, IN DAT_BOOLEAN active,
    IN const ib_cm_events_t ib_cm_event)
{
	switch (ib_cm_event) {
	case IB_CME_CONNECTED:
	case IB_CME_CONNECTION_REQUEST_PENDING:
	case IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA:
		(void) dapls_ib_disconnect(ep_ptr, DAT_CLOSE_ABRUPT_FLAG);
		/* FALLTHROUGH */
	case IB_CME_DESTINATION_REJECT:
	case IB_CME_DESTINATION_REJECT_PRIVATE_DATA:
	case IB_CME_DESTINATION_UNREACHABLE:
	case IB_CME_TOO_MANY_CONNECTION_REQUESTS:
	case IB_CME_LOCAL_FAILURE:
	case IB_CME_TIMED_OUT:
	case IB_CME_DISCONNECTED_ON_LINK_DOWN:
		ep_ptr->qp_state = IBT_STATE_ERROR;
	}
}


/*
 * dapls_ib_reinit_ep
 *
 * Move the QP to INIT state again.
 *
 * Input:
 *	ep_ptr		DAPL_EP
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	void
 *
 */
void
dapls_ib_reinit_ep(IN DAPL_EP *ep_ptr)
{
	dapl_ep_reinit_t	reinit_args;
	ib_hca_handle_t		hca_hndl;
	ib_qp_handle_t		qp_p;
	char			addr_buf[64];
	int			retval;

	hca_hndl = ep_ptr->header.owner_ia->hca_ptr->ib_hca_handle;
	qp_p = ep_ptr->qp_handle;

	if (qp_p == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_reinit: qp_handle == NULL\n");
		return;
	}
	/*
	 * Do all the work request cleanup processing right away
	 * no one should really be doing any operation on this
	 * qp (we are not threadsafe)...
	 */
	dapls_tavor_wrid_cleanup(ep_ptr, qp_p);

	reinit_args.epri_hkey = qp_p->ep_hkey;
	if (ioctl(hca_hndl->ia_fd, DAPL_EP_REINIT, &reinit_args) != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_reinit: reinit failed %s\n",
		    strerror(errno));
		return;
	}

	qp_p->qp_sq_lastwqeaddr = NULL;
	qp_p->qp_rq_lastwqeaddr = NULL;

	/*
	 * Setup data structure for work request processing
	 */
	retval = dapls_tavor_wrid_init(qp_p);
	if (retval != DAT_SUCCESS) {
		/*
		 * we failed to create data structures for work request
		 * processing. Lets unmap and leave, the qp will get
		 * cleaned when ep gets destroyed - the ep is unusable
		 * in this state.
		 */
		if (munmap((void *)qp_p->qp_addr, qp_p->qp_map_len) < 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "qp_free: munmap failed(%d)\n", errno);
		}
		qp_p->qp_addr = NULL;
		dapl_dbg_log(DAPL_DBG_TYPE_CM,
		    "dapls_ib_reinit: wrid_init failed %d\n", retval);
		return;
	}

	/* we have a new ep and it is in the init state */
	ep_ptr->qp_state = IBT_STATE_INIT;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_reinit: successful, ia_address %s, conn_qual %016llu\n",
	    dapls_inet_ntop((struct sockaddr *)ep_ptr->param.
	    remote_ia_address_ptr, addr_buf, 64),
	    ep_ptr->param.remote_port_qual);
}


/*
 * dapl_ib_setup_conn_listener
 *
 * Have the CM set up a connection listener.
 *
 * Input:
 *        ibm_hca_handle           HCA handle
 *        qp_handle                QP handle
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_setup_conn_listener(IN DAPL_IA *ia_ptr,
    IN DAT_UINT64 ServiceID, IN DAPL_SP *sp_ptr)
{
	ib_hca_handle_t hca_hdl = ia_ptr->hca_ptr->ib_hca_handle;
	struct dapls_ib_cm_srvc_handle *srvc_hdl;
	dapl_service_register_t args;
	struct sockaddr *s;
	char addr_buf[64];
	DAPL_EVD *evd_p = (DAPL_EVD *)sp_ptr->evd_handle;
	int retval;

	if (hca_hdl == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "setup_conn_listener: hca_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}
	if (evd_p == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "setup_conn_listener: evd_p == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}
	srvc_hdl = (struct dapls_ib_cm_srvc_handle *)
	    dapl_os_alloc(sizeof (*srvc_hdl));
	if (srvc_hdl == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "setup_conn_listener: srvc_handle == NULL\n");
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	args.sr_sid = ServiceID;
	args.sr_evd_hkey = evd_p->ib_cq_handle->evd_hkey;
	args.sr_sp_cookie = (uintptr_t)sp_ptr;

	retval = ioctl(hca_hdl->ia_fd, DAPL_SERVICE_REGISTER, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "setup_conn_listener: register failed %s\n",
		    strerror(errno));
		dapl_os_free(srvc_hdl, sizeof (*srvc_hdl));
		return (dapls_convert_error(errno, retval));
	}
	srvc_hdl->sv_sp_hkey = args.sr_sp_hkey;
	sp_ptr->cm_srvc_handle = srvc_hdl;
	sp_ptr->conn_qual = args.sr_retsid;

	s = (struct sockaddr *)&ia_ptr->hca_ptr->hca_address;
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "setup_conn_listener: listening on ia_address %s, "
	    "conn_qual %016llu\n\n", dapls_inet_ntop(s, addr_buf, 64),
	    sp_ptr->conn_qual);
	return (DAT_SUCCESS);
}

/*
 * dapl_ib_remove_conn_listener
 *
 * Have the CM remove a connection listener.
 *
 * Input:
 *      ia_handle               IA handle
 *      ServiceID               IB Channel Service ID
 *
 * Output:
 *      none
 *
 * Returns:
 *      DAT_SUCCESS
 *      DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_remove_conn_listener(IN DAPL_IA *ia_ptr, IN DAPL_SP *sp_ptr)
{
	ib_hca_handle_t hca_hdl = ia_ptr->hca_ptr->ib_hca_handle;
	struct dapls_ib_cm_srvc_handle *srvc_hdl;
	dapl_service_deregister_t args;
	struct sockaddr *s;
	char addr_buf[64];
	int retval;

	if (hca_hdl == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "remove_conn_listener: hca_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}
	srvc_hdl = (struct dapls_ib_cm_srvc_handle *)sp_ptr->
	    cm_srvc_handle;

	args.sdr_sp_hkey = srvc_hdl->sv_sp_hkey;
	retval = ioctl(hca_hdl->ia_fd, DAPL_SERVICE_DEREGISTER, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "remove_conn_listener: deregister failed %s\n",
		    strerror(errno));
		return (dapls_convert_error(errno, retval));
	}
	dapl_os_free(srvc_hdl, sizeof (*srvc_hdl));
	sp_ptr->cm_srvc_handle = NULL;

	s = (struct sockaddr *)&ia_ptr->hca_ptr->hca_address;
	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "remove_conn_listener: successful, ia_address %s, "
	    "conn_qual %016llu\n\n", dapls_inet_ntop(s, addr_buf, 64),
	    sp_ptr->conn_qual);
	return (DAT_SUCCESS);
}

/*
 * dapls_ib_reject_connection
 *
 * Perform necessary steps to reject a connection
 *
 * Input:
 *        cr_handle
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_reject_connection(IN ib_cm_handle_t cm_handle,
    IN int reject_reason, IN DAPL_SP *sp_ptr)
{
	dapl_cr_reject_t args;
	int retval;

	args.crr_reason = reject_reason;
	args.crr_bkl_cookie = (uint64_t)cm_handle;
	args.crr_sp_hkey = sp_ptr->cm_srvc_handle->sv_sp_hkey;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_reject: fd %d, sp_hkey %016llx, bkl_index 0x%llx\n",
	    sp_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    args.crr_sp_hkey, args.crr_bkl_cookie);

	retval = ioctl(sp_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_CR_REJECT, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_reject: reject failed %s\n",
		    strerror(errno));
		return (dapls_convert_error(errno, retval));
	}
	return (DAT_SUCCESS);
}


/*
 * dapls_ib_accept_connection
 *
 * Perform necessary steps to accept a connection
 *
 * Input:
 *        cr_handle
 *        ep_handle
 *        private_data_size
 *        private_data
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_accept_connection(IN DAT_CR_HANDLE cr_handle,
    IN DAT_EP_HANDLE ep_handle, IN DAPL_PRIVATE *prd_ptr)
{
	DAPL_EP		*ep_p = (DAPL_EP *)ep_handle;
	DAPL_CR		*cr_p = (DAPL_CR *)cr_handle;
	dapl_cr_accept_t	args;
	int			retval;

	/* check if ep is valid */
	if (ep_p->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_accept: qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_accept: fd %d, sp_hkey %016llx, "
	    "bkl_index 0x%llx, ep_hkey %016llx\n",
	    cr_p->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    cr_p->sp_ptr->cm_srvc_handle->sv_sp_hkey,
	    (uint64_t)cr_p->ib_cm_handle, ep_p->qp_handle->ep_hkey);

	args.cra_bkl_cookie = (uint64_t)cr_p->ib_cm_handle;
	args.cra_sp_hkey = cr_p->sp_ptr->cm_srvc_handle->sv_sp_hkey;
	args.cra_ep_hkey = ep_p->qp_handle->ep_hkey;

	args.cra_priv_sz = IB_MAX_REP_PDATA_SIZE;
	bcopy(prd_ptr, args.cra_priv, IB_MAX_REP_PDATA_SIZE);

	retval = ioctl(cr_p->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_CR_ACCEPT, &args);
	if (retval != 0) {
		ep_p->qp_state = IBT_STATE_ERROR;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_accept: accept failed %s\n",
		    strerror(errno));
		return (dapls_convert_error(errno, retval));
	}
	return (DAT_SUCCESS);
}
/*
 * dapls_ib_cm_remote_addr
 *
 * Obtain the remote IP address given a connection
 *
 * Input:
 *      cr_handle
 *      private data structure handle (only for IBHOSTS_NAMING)
 *
 * Output:
 *      remote_ia_address: where to place the remote address
 *
 * Returns:
 *      DAT_SUCCESS
 *      DAT_INSUFFICIENT_RESOURCES
 *      DAT_INVALID_PARAMETER
 *
 */
/* ARGSUSED */
DAT_RETURN
dapls_ib_cm_remote_addr(
	IN DAT_HANDLE	dat_handle,
	IN DAPL_PRIVATE	*prd_ptr,
	OUT DAT_SOCK_ADDR6 *remote_ia_address)
{
	return (DAT_SUCCESS);
}


/*
 * dapls_ib_handoff_connection
 *
 * handoff connection to a different qualifier
 *
 * Input:
 *        cr_ptr
 *        cr_handoff
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_handoff_connection(IN DAPL_CR *cr_ptr, IN DAT_CONN_QUAL cr_handoff)
{
	dapl_cr_handoff_t args;
	int retval;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "dapls_ib_handoff: fd %d, sp_hkey %016llx, "
	    "bkl_index 0x%llx conn_qual %llu\n",
	    cr_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    cr_ptr->sp_ptr->cm_srvc_handle->sv_sp_hkey,
	    (uint64_t)cr_ptr->ib_cm_handle, cr_handoff);

	args.crh_bkl_cookie = (uint64_t)cr_ptr->ib_cm_handle;
	args.crh_sp_hkey = cr_ptr->sp_ptr->cm_srvc_handle->sv_sp_hkey;
	args.crh_conn_qual = cr_handoff;

	retval = ioctl(cr_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd,
	    DAPL_CR_HANDOFF, &args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_handoff: failed %s\n", strerror(errno));
		return (dapls_convert_error(errno, retval));
	}
	return (DAT_SUCCESS);
}
