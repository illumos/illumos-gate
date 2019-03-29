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


/*
 * This file implements the MAD receive logic in IBMF.
 */

#include <sys/ib/mgt/ibmf/ibmf_impl.h>
#include <sys/ib/mgt/ibmf/ibmf_saa_impl.h>

extern ibmf_state_t *ibmf_statep;
extern int ibmf_recv_wqes_per_port;
extern int ibmf_send_wqes_posted_per_qp;
extern int ibmf_recv_wqes_posted_per_qp;

#define	IBMF_RECV_WR_ID_TO_ADDR(id, ptr)		 \
	(ptr) = (void *)(uintptr_t)((uint64_t)(id) & ~IBMF_RCV_CQE)

#define	IBMF_QP0_NUM			0
#define	IBMF_QP1_NUM			1
#define	IBMF_BM_MAD_ATTR_MOD_REQRESP_BIT	0x00000001
#define	IBMF_BM_MAD_ATTR_MOD_RESP		0x1

/*
 * Structure defintion of entries in the module names table
 */
typedef struct _ibmf_mod_names_t {
	char			mod_name[8];
	ibmf_client_type_t	mgt_class;
} ibmf_mod_names_t;

typedef struct _ibmf_mod_load_args_t {
	ibmf_ci_t		*cip;
	ibmf_recv_wqe_t		*recv_wqep;
	char			*modname;
	ibmf_client_type_t	ibmf_class;
} ibmf_mod_load_args_t;

extern int ibmf_trace_level;
extern int ibmf_send_wqes_posted_per_qp;
extern int ibmf_recv_wqes_posted_per_qp;

static void ibmf_i_do_recv_cb(void *taskq_arg);
static int ibmf_i_repost_recv_buffer(ibmf_ci_t *cip,
    ibmf_recv_wqe_t *recv_wqep);
static int ibmf_i_get_class(ib_mad_hdr_t *madhdrp,
    ibmf_qp_handle_t dest_ibmf_qp_handle, ib_lid_t slid,
    ibmf_client_type_t *dest_classp);
static void ibmf_i_handle_non_rmpp(ibmf_client_t *clientp,
    ibmf_msg_impl_t *msgimplp, uchar_t *mad);
static void ibmf_get_mod_name(uint8_t mad_class, ibmf_client_type_t class,
    char *modname);
static void ibmf_module_load(void *taskq_arg);
static void ibmf_send_busy(ibmf_mod_load_args_t *modlargsp);

#define	AGENT_CLASS(class)					\
	(((class & 0x000F0000) == IBMF_AGENT_ID))
#define	MANAGER_CLASS(class)				\
	(((class & 0x000F0000) == IBMF_MANAGER_ID))
#define	AGENT_MANAGER_CLASS(class)				\
	(((class & 0x000F0000) == IBMF_AGENT_MANAGER_ID))
#define	IS_MANDATORY_CLASS(class)			\
	((class == PERF_AGENT) || (class == BM_AGENT))

char 	ibmf_client_modname[16];

/*
 * ibmf_i_handle_recv_completion():
 *	Process the WQE from the RQ, obtain the management class of the
 *	packet and retrieve the corresponding client context
 */
void
ibmf_i_handle_recv_completion(ibmf_ci_t *cip, ibt_wc_t *wcp)
{
	int			ret;
	ibmf_client_type_t	class;
	ibmf_client_t		*clientp;
	ib_mad_hdr_t		*madhdrp;
	ibmf_recv_wqe_t		*recv_wqep;
	ibt_recv_wr_t		*rwrp;
	ibmf_qp_handle_t	ibmf_qp_handle;
	struct kmem_cache	*kmem_cachep;
	ibmf_alt_qp_t		*altqp;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_recv_completion_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_recv_completion() enter, cip = %p, wcp = %p\n",
	    tnf_opaque, cip, cip, tnf_opaque, wcp, wcp);

	mutex_enter(&cip->ci_ud_dest_list_mutex);
	if (cip->ci_ud_dest_list_count < IBMF_UD_DEST_LO_WATER_MARK) {
		ret = ibmf_ud_dest_tq_disp(cip);
		if (ret == 0) {
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L3,
			    ibmf_i_handle_recv_completion_err, IBMF_TNF_ERROR,
			    "", "ibmf_i_handle_recv_completion(): %s\n",
			    tnf_string, msg, "taskq dispatch of ud_dest "
			    "population thread failed");
		}
	}
	mutex_exit(&cip->ci_ud_dest_list_mutex);

	ASSERT(IBMF_IS_RECV_WR_ID(wcp->wc_id));
	IBMF_RECV_WR_ID_TO_ADDR(wcp->wc_id, recv_wqep);

	rwrp = &recv_wqep->recv_wr;

	/* Retrieve the QP handle from the receive WQE context */
	ibmf_qp_handle = recv_wqep->recv_ibmf_qp_handle;

	/* Get the WQE kmem cache pointer based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		kmem_cachep = cip->ci_recv_wqes_cache;
	} else {
		altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		kmem_cachep = altqp->isq_recv_wqes_cache;
	}

	/*
	 * if the wqe is being flushed due to shutting down of the qp, free
	 * the wqe and return.
	 */
	if (wcp->wc_status == IBT_WC_WR_FLUSHED_ERR) {
		kmem_free(rwrp->wr_sgl, IBMF_MAX_RQ_WR_SGL_ELEMENTS *
		    sizeof (ibt_wr_ds_t));
		kmem_cache_free(kmem_cachep, recv_wqep);
		mutex_enter(&cip->ci_mutex);
		IBMF_SUB32_PORT_KSTATS(cip, recv_wqes_alloced, 1);
		mutex_exit(&cip->ci_mutex);
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
			mutex_enter(&cip->ci_mutex);
			cip->ci_wqes_alloced--;
			if (cip->ci_wqes_alloced == 0)
				cv_signal(&cip->ci_wqes_cv);
			mutex_exit(&cip->ci_mutex);
		} else {
			mutex_enter(&altqp->isq_mutex);
			altqp->isq_wqes_alloced--;
			if (altqp->isq_wqes_alloced == 0)
				cv_signal(&altqp->isq_wqes_cv);
			mutex_exit(&altqp->isq_mutex);
		}
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_handle_recv_completion, IBMF_TNF_TRACE,
		    "", "ibmf_i_handle_recv_completion(): %s\n",
		    tnf_string, msg, "recv wqe flushed");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_recv_completion_end, IBMF_TNF_TRACE,
		    "", "ibmf_i_handle_recv_completion() exit\n");
		return;
	}

	/*
	 * Dynamic Posting of WQEs to the Receive Queue (RQ) of the QP:
	 * If the number of RQ WQEs posted to the QP drops below half
	 * the initial number of RQ WQEs posted to the QP, then, one additional
	 * WQE is posted to the RQ of the QP while processing this CQE.
	 */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		ibmf_qp_t *qpp = recv_wqep->recv_qpp;

		mutex_enter(&qpp->iq_mutex);
		qpp->iq_rwqes_posted--;
		if (qpp->iq_rwqes_posted <= (ibmf_recv_wqes_per_port >> 1)) {
			mutex_exit(&qpp->iq_mutex);

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_handle_recv_compl, IBMF_TNF_TRACE, "",
			    "ibmf_i_handle_recv_compl(): %s, "
			    "QP# = %d\n", tnf_string, msg,
			    "Posting more RQ WQEs",
			    tnf_int, qpnum, qpp->iq_qp_num);

			/* Post an additional WQE to the RQ */
			ret = ibmf_i_post_recv_buffer(cip, qpp,
			    B_FALSE, ibmf_qp_handle);
			if (ret != IBMF_SUCCESS) {
				IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
				    ibmf_i_handle_recv_compl, IBMF_TNF_TRACE,
				    "", "ibmf_i_handle_recv_compl(): %s, "
				    "status = %d\n", tnf_string, msg,
				    "ibmf_i_post_recv_buffer() failed",
				    tnf_int, status, ret);
			}

			mutex_enter(&qpp->iq_mutex);
		}
		mutex_exit(&qpp->iq_mutex);
	} else {
		mutex_enter(&altqp->isq_mutex);
		altqp->isq_rwqes_posted--;
		if (altqp->isq_rwqes_posted <= (ibmf_recv_wqes_per_port >> 1)) {
			mutex_exit(&altqp->isq_mutex);

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_handle_recv_compl, IBMF_TNF_TRACE, "",
			    "ibmf_i_handle_recv_compl(): %s, "
			    "QP# = %d\n", tnf_string, msg,
			    "Posting more RQ WQEs",
			    tnf_int, qpnum, altqp->isq_qpn);

			/* Post an additional WQE to the RQ */
			ret = ibmf_i_post_recv_buffer(cip, NULL,
			    B_FALSE, ibmf_qp_handle);
			if (ret != IBMF_SUCCESS) {
				IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
				    ibmf_i_handle_recv_compl, IBMF_TNF_TRACE,
				    "", "ibmf_i_handle_recv_compl(): %s, "
				    "status = %d\n", tnf_string, msg,
				    "ibmf_i_post_recv_buffer() failed",
				    tnf_int, status, ret);
			}

			mutex_enter(&altqp->isq_mutex);
		}
		mutex_exit(&altqp->isq_mutex);
	}

	/*
	 * for all other completion errors, repost the wqe, and if that
	 * fails, free the wqe and return.
	 */
	if (wcp->wc_status != IBT_WC_SUCCESS) {
		(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_handle_recv_completion_err, IBMF_TNF_ERROR,
		    "", "ibmf_i_handle_recv_completion(): %s, wc_status = %d\n",
		    tnf_string, msg, "bad completion status received",
		    tnf_uint, wc_status, wcp->wc_status);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_recv_completion_end, IBMF_TNF_TRACE,
		    "", "ibmf_i_handle_recv_completion() exit\n");
		return;
	}

	/* find the client corresponding to this recv cqe */
	madhdrp = (ib_mad_hdr_t *)((uintptr_t)recv_wqep->recv_mem +
	    sizeof (ib_grh_t));

	/* drop packet if MAD Base Version is not as expected */
	if (madhdrp->BaseVersion != MAD_CLASS_BASE_VERS_1) {
		(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_handle_recv_completion_err, IBMF_TNF_ERROR,
		    "", "ibmf_i_handle_recv_completion(): %s\n",
		    tnf_string, msg, "bad MAD version");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_recv_completion_end, IBMF_TNF_TRACE,
		    "", "ibmf_i_handle_recv_completion() exit\n");
		return;
	}

	if (ibmf_i_get_class(madhdrp, recv_wqep->recv_ibmf_qp_handle,
	    wcp->wc_slid, &class) != IBMF_SUCCESS) {
		/* bad class & type? */
#ifdef DEBUG
		ibmf_i_dump_wcp(cip, wcp, recv_wqep);
#endif
		(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);
		IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_handle_recv_completion_err, IBMF_TNF_ERROR,
		    "", "ibmf_i_handle_recv_completion(): %s\n",
		    tnf_string, msg, "bad class/type");
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
		    ibmf_i_handle_recv_completion_end, IBMF_TNF_TRACE,
		    "", "ibmf_i_handle_recv_completion() exit\n");
		return;
	}

	ret = ibmf_i_lookup_client_by_mgmt_class(cip, recv_wqep->recv_port_num,
	    class, &clientp);
	if (ret == IBMF_SUCCESS) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqep))
		recv_wqep->recv_client = clientp;
		recv_wqep->recv_wc = *wcp; /* struct copy */

		/*
		 * Increment the kstats for the number of active receiver side
		 * callbacks
		 */
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, recv_cb_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

		if ((clientp->ic_reg_flags & IBMF_REG_FLAG_NO_OFFLOAD) == 0) {
			/* Dispatch the taskq thread to do further processing */
			ret = taskq_dispatch(clientp->ic_recv_taskq,
			    ibmf_i_do_recv_cb, recv_wqep, TQ_NOSLEEP);
			if (ret == TASKQID_INVALID) {
				mutex_enter(&clientp->ic_kstat_mutex);
				IBMF_SUB32_KSTATS(clientp, recv_cb_active, 1);
				mutex_exit(&clientp->ic_kstat_mutex);
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_handle_recv_completion_err,
				    IBMF_TNF_ERROR, "",
				    "ibmf_i_handle_recv_completion(): %s\n",
				    tnf_string, msg, "dispatch failed");
				(void) ibmf_i_repost_recv_buffer(cip,
				    recv_wqep);
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_handle_recv_completion_end,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_handle_recv_completion() exit\n");
				return;
			}
		} else {
			ibmf_i_do_recv_cb((void *)recv_wqep);
		}

		/*
		 * Decrement the kstats for the number of active receiver side
		 * callbacks
		 */
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_SUB32_KSTATS(clientp, recv_cb_active, 1);
		mutex_exit(&clientp->ic_kstat_mutex);

	} else {
		/*
		 * A client has not registered to receive MADs of this
		 * management class. IBMF must attempt to load the
		 * client and request a resend of the request MAD.
		 * The name of the client MAD is derived using a
		 * convention described in PSARC case 2003/753.
		 */

		ibmf_mod_load_args_t	*modlargsp;

		/*
		 * HCA driver handles the Performance management
		 * class MAD's. It registers with the IBMF during early
		 * boot and unregisters during detach and during
		 * HCA unconfigure operation. We come here
		 * 1. Before HCA registers with IBMF
		 * 	Drop the MAD. Since this is a UD MAD,
		 *	sender will resend the request
		 * 2. After HCA unregistered with IBMF during DR operation.
		 *	Since HCA is going away, we can safely drop the PMA
		 *	MAD's here.
		 * Solaris does not support BM_AGENT and so drop the BM MAD's
		 */
		if ((class == PERF_AGENT) || (class == BM_AGENT)) {
			(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);
			return;
		}

		recv_wqep->recv_wc = *wcp; /* struct copy */

		IBMF_TRACE_3(IBMF_TNF_NODEBUG, DPRINT_L4,
		    ibmf_i_handle_recv_completion_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_handle_recv_completion(): %s, port = %d, "
		    "class = 0x%x\n",
		    tnf_string, msg, "no client registered", tnf_uint, port,
		    recv_wqep->recv_port_num, tnf_opaque, class, class);

		/* Construct the IBMF client module name */
		ibmf_get_mod_name(madhdrp->MgmtClass, class,
		    ibmf_client_modname);

		/* Load the module using a taskq thread */
		modlargsp = (ibmf_mod_load_args_t *)kmem_zalloc(
		    sizeof (ibmf_mod_load_args_t), KM_NOSLEEP);
		if (modlargsp != NULL) {
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*modlargsp))
			modlargsp->cip		= cip;
			modlargsp->recv_wqep	= recv_wqep;
			modlargsp->modname	= ibmf_client_modname;
			modlargsp->ibmf_class	= class;
			ret = taskq_dispatch(ibmf_statep->ibmf_taskq,
			    ibmf_module_load, modlargsp, TQ_NOSLEEP);
			if (ret == TASKQID_INVALID) {
				kmem_free(modlargsp,
				    sizeof (ibmf_mod_load_args_t));
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_handle_recv_completion_error,
				    IBMF_TNF_TRACE, "",
				    "ibmf_i_handle_recv_completion(): Failed "
				    "to dispatch ibmf_module_load taskq\n");
				(void) ibmf_i_repost_recv_buffer(cip,
				    recv_wqep);
			}
		} else {
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_handle_recv_completion_end, IBMF_TNF_TRACE,
			    "", "ibmf_i_handle_recv_completion(): "
			    "Failed to allocate memory for modlargs\n");
			(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);
		}
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_recv_completion_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_recv_completion() exit\n");
}

/*
 * ibmf_i_do_recv_cb():
 *	This routine does the following:
 *	o looks for a message in the client's message list
 *	o creates a new message if one does not exist for unsolicited data
 *	o invoke routines to do specific handling for rmpp and non-rmpp cases
 *	o on a failure, the receive WQE is reposted to the RQ
 */
static void
ibmf_i_do_recv_cb(void *taskq_arg)
{
	ibt_wc_t		*wcp;
	ibmf_msg_impl_t		*msgimplp;
	ibmf_client_t		*clientp;
	ibmf_addr_info_t	addrinfo;
	ibmf_recv_wqe_t		*recv_wqep;
	ib_grh_t		*ib_grh;
	boolean_t		grhpresent;
	ibmf_qp_handle_t	ibmf_qp_handle;
	ib_mad_hdr_t		*mad_hdr;
	ibmf_rmpp_hdr_t		*rmpp_hdr;
	ibmf_alt_qp_t		*qpp;
	ib_gid_t		gid;
	ib_lid_t		lid;
	int			msg_trans_state_flags, msg_flags;
	uint_t			ref_cnt;
	timeout_id_t		msg_rp_unset_id, msg_tr_unset_id;
	timeout_id_t		msg_rp_set_id, msg_tr_set_id;
	int			status;
	saa_port_t		*saa_portp;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*recv_wqep))

	/* The taskq_arg argument is a pointer to the receive WQE context */
	recv_wqep = taskq_arg;

	/* Retrieve the QP handle from the receive WQE context */
	ibmf_qp_handle = recv_wqep->recv_ibmf_qp_handle;

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_do_recv_cb_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_do_recv_cb() enter, recv_wqep = %p\n",
	    tnf_opaque, recv_wqep, recv_wqep);

	/* Retrieve the client context pointer from the receive WQE context */
	clientp = recv_wqep->recv_client;

	/* Get a pointer to the IBT work completion structure */
	wcp = &recv_wqep->recv_wc;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wcp))

	/*
	 * Identify the port by the  LID or GID depending on whether the
	 * Global Route Header is valid or not
	 */
	if (wcp->wc_flags & IBT_WC_GRH_PRESENT) {
		grhpresent = B_TRUE;
		ib_grh = (ib_grh_t *)recv_wqep->recv_mem;
		gid.gid_prefix	= b2h64(ib_grh->SGID.gid_prefix);
		gid.gid_guid 	= b2h64(ib_grh->SGID.gid_guid);
	} else {
		grhpresent = B_FALSE;
		lid = wcp->wc_slid;
	}

	/* Get a pointer to the MAD header */
	mad_hdr = (ib_mad_hdr_t *)((uintptr_t)recv_wqep->recv_mem +
	    sizeof (ib_grh_t));

	/* Get a pointer to the RMPP header */
	rmpp_hdr = (ibmf_rmpp_hdr_t *)((uintptr_t)recv_wqep->recv_mem +
	    sizeof (ib_grh_t) + sizeof (ib_mad_hdr_t));

	IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3,
	    ibmf_i_do_recv_cb, IBMF_TNF_TRACE, "",
	    "ibmf_i_do_recv_cb(): %s, tid = %016" PRIx64 ", class = 0x%x, "
	    "attrID = 0x%x, lid = 0x%x\n",
	    tnf_string, msg, "Received MAD", tnf_opaque, tid,
	    b2h64(mad_hdr->TransactionID), tnf_opaque, class,
	    mad_hdr->MgmtClass, tnf_opaque, attr_id,
	    b2h16(mad_hdr->AttributeID), tnf_opaque, remote_lid, lid);

	/*
	 * Look for the matching message in the client's message list
	 * NOTE: if the message is found, the message reference count will
	 * have been increased by 1.
	 */
	msgimplp = ibmf_i_find_msg(clientp, b2h64(mad_hdr->TransactionID),
	    mad_hdr->MgmtClass, mad_hdr->R_Method, lid, &gid, grhpresent,
	    rmpp_hdr, IBMF_REG_MSG_LIST);

	/*
	 * If the message is not on the regular message list, search
	 * for it in the termination message list.
	 */
	if (msgimplp == NULL) {
		msgimplp = ibmf_i_find_msg(clientp,
		    b2h64(mad_hdr->TransactionID), mad_hdr->MgmtClass,
		    mad_hdr->R_Method, lid, &gid, grhpresent, rmpp_hdr,
		    IBMF_TERM_MSG_LIST);
	}

	if (msgimplp != NULL) {

		/* if this packet is from the SA */
		if (clientp->ic_client_info.client_class == SUBN_ADM_MANAGER) {

			/*
			 * ibmf_saa's callback arg is its saa_portp;
			 * take advantage of this fact to quickly update the
			 * port's SA uptime.  ibmf_saa uses the up time to
			 * determine if the SA is still alive
			 */
			saa_portp = clientp->ic_async_cb_arg;

			/* update the SA uptime */
			mutex_enter(&saa_portp->saa_pt_mutex);

			saa_portp->saa_pt_sa_uptime = gethrtime();

			mutex_exit(&saa_portp->saa_pt_mutex);
		}

		mutex_enter(&msgimplp->im_mutex);

		/*
		 * Clear timers for transactions of solicited incoming packets
		 */
		if (msgimplp->im_rp_timeout_id != 0) {
			ibmf_i_unset_timer(msgimplp, IBMF_RESP_TIMER);
		}

		/*
		 * If a MAD is received in the middle of an RMPP receive
		 * transaction, and the MAD's RMPPFlags.Active bit is 0,
		 * drop the MAD
		 */
		if (ibmf_i_is_rmpp(clientp, ibmf_qp_handle) &&
		    (msgimplp->im_flags & IBMF_MSG_FLAGS_RECV_RMPP) &&
		    ((rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_ACTIVE) == 0)) {
			mutex_exit(&msgimplp->im_mutex);
			(void) ibmf_i_repost_recv_buffer(clientp->ic_myci,
			    recv_wqep);
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L3,
			    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
			    "ibmf_i_do_recv_cb(): %s, msg = %p\n",
			    tnf_string, msg,
			    "Non-RMPP MAD received in RMPP transaction, "
			    "dropping MAD", tnf_opaque, msgimplp, msgimplp);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_recv_cb() exit\n");
			return;
		}

		/*
		 * If the message has been marked unitialized or done
		 * release the message mutex and return
		 */
		if ((msgimplp->im_trans_state_flags &
		    IBMF_TRANS_STATE_FLAG_DONE) ||
		    (msgimplp->im_trans_state_flags &
		    IBMF_TRANS_STATE_FLAG_UNINIT)) {
			IBMF_MSG_DECR_REFCNT(msgimplp);
			msg_trans_state_flags = msgimplp->im_trans_state_flags;
			msg_flags = msgimplp->im_flags;
			ref_cnt = msgimplp->im_ref_count;
			mutex_exit(&msgimplp->im_mutex);
			(void) ibmf_i_repost_recv_buffer(clientp->ic_myci,
			    recv_wqep);
			/*
			 * This thread may notify the client only if the
			 * transaction is done, the message has been removed
			 * from the client's message list, and the message
			 * reference count is 0.
			 * If the transaction is done, and the message reference
			 * count = 0, there is still a possibility that a
			 * packet could arrive for the message and its reference
			 * count increased if the message is still on the list.
			 * If the message is still on the list, it will be
			 * removed by a call to ibmf_i_client_rem_msg() at
			 * the completion point of the transaction.
			 * So, the reference count should be checked after the
			 * message has been removed.
			 */
			if ((msg_trans_state_flags &
			    IBMF_TRANS_STATE_FLAG_DONE) &&
			    !(msg_flags & IBMF_MSG_FLAGS_ON_LIST) &&
			    (ref_cnt == 0)) {

				ibmf_i_notify_sequence(clientp, msgimplp,
				    msg_flags);

			}
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L3,
			    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
			    "ibmf_i_do_recv_cb(): %s, msg = %p\n",
			    tnf_string, msg,
			    "Message already marked for removal, dropping MAD",
			    tnf_opaque, msgimplp, msgimplp);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_recv_cb() exit\n");
			return;
		}
	} else {
		/* unsolicited message packet */

		/*
		 * Check if the client context, the alternate QP context
		 * (if not the default QP), and the incoming MAD support RMPP
		 */
		if (ibmf_i_is_rmpp(clientp, ibmf_qp_handle) &&
		    (rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_ACTIVE)) {

			/* Only unsolicited packets should be data seg 1 */
			if ((rmpp_hdr->rmpp_flags &
			    IBMF_RMPP_FLAGS_FIRST_PKT) == 0) {
				(void) ibmf_i_repost_recv_buffer(
				    clientp->ic_myci, recv_wqep);
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L3,
				    ibmf_i_do_recv_cb_error, IBMF_TNF_TRACE, "",
				    "ibmf_i_do_recv_cb(): %s\n",
				    tnf_string, msg,
				    "unsolicited rmpp packet not first packet");
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
				    "ibmf_i_do_recv_cb() exit\n");
				return;
			}
		}

		/*
		 * Before we alloc a message context, check to see if
		 * a callback has been registered with the client
		 * for this unsolicited message.
		 * If one has been registered, increment the recvs active
		 * count to get the teardown routine to wait until
		 * this callback is complete.
		 */
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {

			mutex_enter(&clientp->ic_mutex);
			if (clientp->ic_recv_cb == NULL) {
				mutex_exit(&clientp->ic_mutex);
				(void) ibmf_i_repost_recv_buffer(
				    clientp->ic_myci, recv_wqep);
				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
				    "ibmf_i_do_recv_cb(): %s, class %x\n",
				    tnf_string, msg,
				    "ibmf_tear_down_recv_cb already occurred",
				    tnf_opaque, class,
				    clientp->ic_client_info.client_class);
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
				    "ibmf_i_do_recv_cb() exit\n");
				return;
			}
			IBMF_RECV_CB_SETUP(clientp);
			mutex_exit(&clientp->ic_mutex);
		} else {
			qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;

			mutex_enter(&qpp->isq_mutex);
			if (qpp->isq_recv_cb == NULL) {
				mutex_exit(&qpp->isq_mutex);
				(void) ibmf_i_repost_recv_buffer(
				    clientp->ic_myci, recv_wqep);
				IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
				    "ibmf_i_do_recv_cb(): %s, class %x\n",
				    tnf_string, msg,
				    "ibmf_tear_down_recv_cb already occurred",
				    tnf_opaque, class,
				    clientp->ic_client_info.client_class);
				IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
				    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
				    "ibmf_i_do_recv_cb() exit\n");
				return;
			}
			IBMF_ALT_RECV_CB_SETUP(qpp);
			mutex_exit(&qpp->isq_mutex);
		}

		/*
		 * Allocate a message context
		 */
		msgimplp = (ibmf_msg_impl_t *)kmem_zalloc(
		    sizeof (ibmf_msg_impl_t), KM_NOSLEEP);

		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msgimplp))

		/* If we cannot allocate memory, drop the packet and clean up */
		if (msgimplp == NULL) {
			if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
				mutex_enter(&clientp->ic_mutex);
				IBMF_RECV_CB_CLEANUP(clientp);
				mutex_exit(&clientp->ic_mutex);
			} else {
				qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;
				mutex_enter(&qpp->isq_mutex);
				IBMF_ALT_RECV_CB_CLEANUP(qpp);
				mutex_exit(&qpp->isq_mutex);
			}
			(void) ibmf_i_repost_recv_buffer(clientp->ic_myci,
			    recv_wqep);
			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
			    "ibmf_i_do_recv_cb(): %s\n", tnf_string, msg,
			    "mem allocation failure");
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_recv_cb() exit\n");
			return;
		}

		/* Get the port's base LID if it's not in the client context */
		if ((clientp->ic_base_lid == 0) &&
		    (clientp->ic_qp->iq_qp_num != 0)) {
			(void) ibt_get_port_state_byguid(
			    clientp->ic_client_info.ci_guid,
			    clientp->ic_client_info.port_num, NULL,
			    &clientp->ic_base_lid);
			if (clientp->ic_base_lid == 0) {
				IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
				    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
				    "ibmf_i_do_recv_cb(): %s\n",
				    tnf_string, msg, "base_lid is undefined");
			}
		}

		/* Set up address information */
		addrinfo.ia_local_lid = clientp->ic_base_lid +
		    wcp->wc_path_bits;
		addrinfo.ia_remote_lid = wcp->wc_slid;
		addrinfo.ia_remote_qno = wcp->wc_qpn;

		/* Get the pkey, including the correct partiton membership */
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
			if (recv_wqep->recv_qpp->iq_qp_num == IBMF_QP1_NUM) {

				/*
				 * here too we expect the pkey index in the work
				 * completion belongs to a pkey in the pkey
				 * table
				 */
				status = ibmf_i_pkey_ix_to_key(
				    clientp->ic_myci, recv_wqep->recv_port_num,
				    wcp->wc_pkey_ix, &addrinfo.ia_p_key);
				if (status != IBMF_SUCCESS) {
					IBMF_TRACE_2(IBMF_TNF_NODEBUG,
					    DPRINT_L1, ibmf_i_do_recv_cb_error,
					    IBMF_TNF_ERROR, "",
					    "ibmf_i_do_recv_cb(): "
					    "get_pkey failed for ix %d,"
					    "status = %d\n", tnf_uint,
					    pkeyix, wcp->wc_pkey_ix, tnf_uint,
					    ibmf_status, status);
					mutex_enter(&clientp->ic_mutex);
					IBMF_RECV_CB_CLEANUP(clientp);
					mutex_exit(&clientp->ic_mutex);
					(void) ibmf_i_repost_recv_buffer(
					    clientp->ic_myci, recv_wqep);
					mutex_destroy(&msgimplp->im_mutex);
					cv_destroy(&msgimplp->im_trans_cv);
					kmem_free(msgimplp,
					    sizeof (ibmf_msg_impl_t));
					IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
					    ibmf_i_do_recv_cb_end,
					    IBMF_TNF_TRACE, "",
					    "ibmf_i_do_recv_cb() exit\n");
					return;
				}
			}
			addrinfo.ia_q_key = IBMF_MGMT_Q_KEY;
		} else {
			qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;

			/* For alternate QPs, the pkey is in the QP context */
			mutex_enter(&qpp->isq_mutex);
			addrinfo.ia_p_key = qpp->isq_pkey;
			addrinfo.ia_q_key = qpp->isq_qkey;
			mutex_exit(&qpp->isq_mutex);
		}

		addrinfo.ia_service_level = wcp->wc_sl;
		msgimplp->im_local_addr = addrinfo;

		/* Initialize the message context */
		cv_init(&msgimplp->im_trans_cv, NULL, CV_DRIVER, NULL);
		mutex_init(&msgimplp->im_mutex, NULL, MUTEX_DRIVER, NULL);
		msgimplp->im_client = clientp;
		msgimplp->im_qp_hdl = ibmf_qp_handle;
		msgimplp->im_flags = 0;
		msgimplp->im_unsolicited = B_TRUE;
		msgimplp->im_tid = b2h64(mad_hdr->TransactionID);
		msgimplp->im_mgt_class = mad_hdr->MgmtClass;
		msgimplp->im_retrans.retrans_retries = IBMF_RETRANS_DEF_RETRIES;
		msgimplp->im_retrans.retrans_rtv = IBMF_RETRANS_DEF_RTV;
		msgimplp->im_retrans.retrans_rttv = IBMF_RETRANS_DEF_RTTV;
		msgimplp->im_retrans.retrans_trans_to =
		    IBMF_RETRANS_DEF_TRANS_TO;
		msgimplp->im_rmpp_ctx.rmpp_state = IBMF_RMPP_STATE_UNDEFINED;
		msgimplp->im_rmpp_ctx.rmpp_respt = IBMF_RMPP_DEFAULT_RRESPT;
		IBMF_MSG_INCR_REFCNT(msgimplp);
		msgimplp->im_trans_state_flags = IBMF_TRANS_STATE_FLAG_UNINIT;

		/*
		 * Initialize (and possibly allocate) the IBT UD destination
		 * address handle.
		 */
		status = ibmf_i_alloc_ud_dest(clientp, msgimplp,
		    &msgimplp->im_ud_dest, B_FALSE);
		if (status != IBMF_SUCCESS) {
			if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
				mutex_enter(&clientp->ic_mutex);
				IBMF_RECV_CB_CLEANUP(clientp);
				mutex_exit(&clientp->ic_mutex);
			} else {
				qpp = (ibmf_alt_qp_t *)ibmf_qp_handle;
				mutex_enter(&qpp->isq_mutex);
				IBMF_ALT_RECV_CB_CLEANUP(qpp);
				mutex_exit(&qpp->isq_mutex);
			}
			(void) ibmf_i_repost_recv_buffer(clientp->ic_myci,
			    recv_wqep);
			mutex_destroy(&msgimplp->im_mutex);
			cv_destroy(&msgimplp->im_trans_cv);
			kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
			IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_do_recv_cb_error, IBMF_TNF_ERROR, "",
			    "ibmf_i_do_recv_cb(): %s, status = %d\n",
			    tnf_string, msg, "alloc ah failed", tnf_uint,
			    ibmf_status, status);
			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_recv_cb() exit\n");
			return;
		}

		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*msgimplp))

		/* add message to client's list */
		ibmf_i_client_add_msg(clientp, msgimplp);

		mutex_enter(&msgimplp->im_mutex);

		/* no one should have touched our state */
		ASSERT(msgimplp->im_trans_state_flags ==
		    IBMF_TRANS_STATE_FLAG_UNINIT);

		/* transition out of uninit state */
		msgimplp->im_trans_state_flags = IBMF_TRANS_STATE_FLAG_INIT;
	}

	/* fill in the grh with the contents of the recv wqe */
	if (grhpresent == B_TRUE) {
		uint32_t tmp32;

		msgimplp->im_msg_flags |= IBMF_MSG_FLAGS_GLOBAL_ADDRESS;
		ib_grh = (ib_grh_t *)recv_wqep->recv_mem;
		msgimplp->im_global_addr.ig_sender_gid.gid_prefix =
		    b2h64(ib_grh->SGID.gid_prefix);
		msgimplp->im_global_addr.ig_sender_gid.gid_guid =
		    b2h64(ib_grh->SGID.gid_guid);
		msgimplp->im_global_addr.ig_recver_gid.gid_prefix =
		    b2h64(ib_grh->DGID.gid_prefix);
		msgimplp->im_global_addr.ig_recver_gid.gid_guid =
		    b2h64(ib_grh->DGID.gid_guid);
		/*
		 * swap to get byte order back to wire format on little endian
		 * systems so we can apply the GRH masks
		 */
		tmp32 = b2h32(ib_grh->IPVer_TC_Flow);
		msgimplp->im_global_addr.ig_flow_label =
		    tmp32 & IB_GRH_FLOW_LABEL_MASK;
		msgimplp->im_global_addr.ig_tclass =
		    (tmp32 & IB_GRH_TCLASS_MASK) >> 20;
		msgimplp->im_global_addr.ig_hop_limit =
		    ib_grh->HopLmt;
	}

	/* Perform RMPP or non-RMPP processing */
	if (ibmf_i_is_rmpp(clientp, ibmf_qp_handle) &&
	    (rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_ACTIVE)) {
		IBMF_TRACE_5(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_recv_cb, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_recv_cb(): %s, tid = %016" PRIx64 ","
		    "flags = 0x%x rmpp_type = %d, rmpp_segnum = %d\n",
		    tnf_string, msg, "Handling rmpp MAD",
		    tnf_opaque, tid, b2h64(mad_hdr->TransactionID),
		    tnf_opaque, flags, rmpp_hdr->rmpp_flags,
		    tnf_opaque, type, rmpp_hdr->rmpp_type,
		    tnf_opaque, segment, b2h32(rmpp_hdr->rmpp_segnum));

		/*
		 * Set the RMPP state to "receiver active" on the first packet
		 * of all RMPP message, and initialize the
		 * the expected segment to 1.
		 */
		if ((msgimplp->im_rmpp_ctx.rmpp_state ==
		    IBMF_RMPP_STATE_UNDEFINED) &&
		    (rmpp_hdr->rmpp_flags & IBMF_RMPP_FLAGS_FIRST_PKT)) {

			msgimplp->im_flags |= IBMF_MSG_FLAGS_RECV_RMPP;

			if (rmpp_hdr->rmpp_type == IBMF_RMPP_TYPE_DATA) {
				msgimplp->im_rmpp_ctx.rmpp_state =
				    IBMF_RMPP_STATE_RECEVR_ACTIVE;

				IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
				    ibmf_i_do_recv_cb, IBMF_TNF_TRACE, "",
				    "ibmf_i_do_recv_cb(): %s, msgimplp = %p\n",
				    tnf_string, msg, "first RMPP pkt received",
				    tnf_opaque, msgimplp, msgimplp);
			}

			msgimplp->im_rmpp_ctx.rmpp_es = 1;
			msgimplp->im_rmpp_ctx.rmpp_wl = 1;
			msgimplp->im_rmpp_ctx.rmpp_wf = 1;

			/* set double-sided transfer flag for certain methods */
			if (mad_hdr->R_Method == SA_SUBN_ADM_GET_MULTI)
				msgimplp->im_rmpp_ctx.rmpp_is_ds = B_TRUE;
			else	msgimplp->im_rmpp_ctx.rmpp_is_ds = B_FALSE;

			msgimplp->im_trans_state_flags |=
			    IBMF_TRANS_STATE_FLAG_RECV_ACTIVE;
		}

		if (rmpp_hdr->rmpp_resp_time != IBMF_RMPP_DEFAULT_RRESPT) {
			msgimplp->im_retrans.retrans_rtv =
			    1 << rmpp_hdr->rmpp_resp_time;

			IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
			    ibmf_i_do_recv_cb, IBMF_TNF_TRACE, "",
			    "ibmf_i_do_recv_cb: %s, resp_time %d\n",
			    tnf_string, msg, "new resp time received",
			    tnf_uint, resp_time, rmpp_hdr->rmpp_resp_time);
		}

		ibmf_i_handle_rmpp(clientp, ibmf_qp_handle, msgimplp,
		    (uchar_t *)((uintptr_t)recv_wqep->recv_mem +
		    sizeof (ib_grh_t)));
	} else {

		msgimplp->im_trans_state_flags |=
		    IBMF_TRANS_STATE_FLAG_RECV_ACTIVE;

		ibmf_i_handle_non_rmpp(clientp, msgimplp,
		    (uchar_t *)((uintptr_t)recv_wqep->recv_mem +
		    sizeof (ib_grh_t)));
	}

	msg_rp_unset_id = msg_tr_unset_id = msg_rp_set_id = msg_tr_set_id = 0;

	/*
	 * Save the transaction state flags and the timeout IDs
	 * before releasing the mutex as they may be changed after that.
	 */
	msg_trans_state_flags = msgimplp->im_trans_state_flags;
	msg_flags = msgimplp->im_flags;
	msg_rp_unset_id = msgimplp->im_rp_unset_timeout_id;
	msg_tr_unset_id = msgimplp->im_tr_unset_timeout_id;
	msgimplp->im_rp_unset_timeout_id = 0;
	msgimplp->im_tr_unset_timeout_id = 0;

	/*
	 * Decrement the message reference count
	 * This count was incremented either when the message was found
	 * on the client's message list (ibmf_i_find_msg()) or when
	 * a new message was created for unsolicited data
	 */
	IBMF_MSG_DECR_REFCNT(msgimplp);

	if (msg_trans_state_flags & IBMF_TRANS_STATE_FLAG_DONE) {
		if (msgimplp->im_rp_timeout_id != 0) {
			msg_rp_set_id = msgimplp->im_rp_timeout_id;
			msgimplp->im_rp_timeout_id = 0;
		}
		if (msgimplp->im_tr_timeout_id != 0) {
			msg_tr_set_id = msgimplp->im_tr_timeout_id;
			msgimplp->im_tr_timeout_id = 0;
		}
	}

	mutex_exit(&msgimplp->im_mutex);

	/*
	 * Call untimeout() after releasing the lock because the
	 * lock is acquired in the timeout handler as well. Untimeout()
	 * does not return until the timeout handler has run, if it already
	 * fired, which would result in a deadlock if we did not first
	 * release the im_mutex lock.
	 */
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

	/* Increment the kstats for number of messages received */
	mutex_enter(&clientp->ic_kstat_mutex);
	IBMF_ADD32_KSTATS(clientp, msgs_received, 1);
	mutex_exit(&clientp->ic_kstat_mutex);

	/*
	 * now that we are done gleaning all we want out of the receive
	 * completion, we repost the receive request.
	 */
	(void) ibmf_i_repost_recv_buffer(clientp->ic_myci, recv_wqep);

	/*
	 * If the transaction flags indicate a completed transaction,
	 * notify the client
	 */
	if (msg_trans_state_flags & IBMF_TRANS_STATE_FLAG_DONE) {
		IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L3,
		    ibmf_i_do_recv_cb, IBMF_TNF_TRACE, "",
		    "ibmf_i_do_recv_cb(): %s, msgimplp = %p\n",
		    tnf_string, msg, "notifying client",
		    tnf_opaque, msgimplp, msgimplp);

		/* Remove the message from the client's message list */
		ibmf_i_client_rem_msg(clientp, msgimplp, &ref_cnt);

		/*
		 * Notify the client if the message reference count is zero.
		 * At this point, we know that the transaction is done and
		 * the message has been removed from the client's message list.
		 * So, we only need to make sure the reference count is zero
		 * before notifying the client.
		 */
		if (ref_cnt == 0) {

			ibmf_i_notify_sequence(clientp, msgimplp, msg_flags);

		}
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_do_recv_cb_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_do_recv_cb() exit, msgimplp = %p\n",
	    tnf_opaque, msgimplp, msgimplp);
}

/*
 * ibmf_i_handle_non_rmpp():
 *	Handle non-RMPP processing of an incoming IB packet
 */
void
ibmf_i_handle_non_rmpp(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    uchar_t *mad)
{
	ibmf_rmpp_ctx_t	*rmpp_ctx = &msgimplp->im_rmpp_ctx;
	ib_mad_hdr_t	*mad_hdr;
	size_t		offset;
	uchar_t		*msgbufp;
	uint32_t	clhdrsz, clhdroff;

	IBMF_TRACE_3(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_handle_non_rmpp_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_handle_non_rmpp(): clientp = 0x%p, "
	    "msgp = 0x%p, madp = 0x%p\n", tnf_opaque, clientp, clientp,
	    tnf_opaque, msg, msgimplp, tnf_opaque, mad, mad);

	ASSERT(MUTEX_HELD(&msgimplp->im_mutex));

	/* Get the MAD header */
	mad_hdr = (ib_mad_hdr_t *)mad;

	/* Determine the MAD's class header size */
	ibmf_i_mgt_class_to_hdr_sz_off(mad_hdr->MgmtClass, &clhdrsz, &clhdroff);

	/* Allocate the message receive buffers if not already allocated */
	if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {

		msgimplp->im_msgbufs_recv.im_bufs_mad_hdr =
		    (ib_mad_hdr_t *)kmem_zalloc(IBMF_MAD_SIZE, KM_NOSLEEP);
		if (msgimplp->im_msgbufs_recv.im_bufs_mad_hdr == NULL) {

			IBMF_TRACE_1(IBMF_TNF_NODEBUG, DPRINT_L1,
			    ibmf_i_handle_non_rmpp_err, IBMF_TNF_ERROR, "",
			    "ibmf_i_handle_non_rmpp(): %s\n", tnf_string, msg,
			    "mem allocation failure (non-rmpp payload)");

			IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,
			    ibmf_i_handle_non_rmpp_end, IBMF_TNF_TRACE, "",
			    "ibmf_i_handle_non_rmpp() exit\n");

			return;
		}
		mutex_enter(&clientp->ic_kstat_mutex);
		IBMF_ADD32_KSTATS(clientp, recv_bufs_alloced, 1);
		mutex_exit(&clientp->ic_kstat_mutex);
	}

	/* Get a pointer to the MAD location in the receive buffer */
	msgbufp = (uchar_t *)msgimplp->im_msgbufs_recv.im_bufs_mad_hdr;

	/* Copy the incoming MAD into the receive buffer */
	bcopy((const void *)mad, (void *)msgbufp, IBMF_MAD_SIZE);

	/* Get the offset of the class header */
	offset = sizeof (ib_mad_hdr_t) + clhdroff;

	/* initialize class header pointer */
	if (clhdrsz == 0) {
		msgimplp->im_msgbufs_recv.im_bufs_cl_hdr = NULL;
	} else {
		msgimplp->im_msgbufs_recv.im_bufs_cl_hdr =
		    (void *)(msgbufp + offset);
	}
	msgimplp->im_msgbufs_recv.im_bufs_cl_hdr_len = clhdrsz;

	offset += clhdrsz;

	/* initialize data area pointer */
	msgimplp->im_msgbufs_recv.im_bufs_cl_data = (void *)(msgbufp + offset);
	msgimplp->im_msgbufs_recv.im_bufs_cl_data_len = IBMF_MAD_SIZE -
	    sizeof (ib_mad_hdr_t) - clhdroff - clhdrsz;

	rmpp_ctx->rmpp_state = IBMF_RMPP_STATE_DONE;
	ibmf_i_terminate_transaction(clientp, msgimplp, IBMF_SUCCESS);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4,	ibmf_i_handle_non_rmpp_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_handle_non_rmpp() exit\n");
}

/*
 * ibmf_i_repost_recv_buffer():
 *	Repost a WQE to the RQ after processing it
 */
/* ARGSUSED */
int
ibmf_i_repost_recv_buffer(ibmf_ci_t *cip, ibmf_recv_wqe_t *recv_wqep)
{
	int			ret;
	ibt_status_t		status;
	ibmf_qp_handle_t	ibmf_qp_handle = recv_wqep->recv_ibmf_qp_handle;
	struct kmem_cache	*kmem_cachep;
	ibmf_alt_qp_t		*altqp;
	ibmf_qp_t		*qpp;

	IBMF_TRACE_2(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_repost_recv_buffer_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_repost_recv_buffer() enter, cip = %p, rwqep = %p\n",
	    tnf_opaque, cip, cip, tnf_opaque, rwqep, recv_wqep);

	ASSERT(MUTEX_NOT_HELD(&cip->ci_mutex));

	/* Get the WQE kmem cache pointer based on the QP type */
	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		kmem_cachep = cip->ci_recv_wqes_cache;
		qpp = recv_wqep->recv_qpp;
	} else {
		altqp = (ibmf_alt_qp_t *)ibmf_qp_handle;
		kmem_cachep = altqp->isq_recv_wqes_cache;
	}

	/* post recv wqe; free it if the post fails */
	status = ibt_post_recv(recv_wqep->recv_qp_handle, &recv_wqep->recv_wr,
	    1, NULL);

	ret = ibmf_i_ibt_to_ibmf_status(status);
	if (ret != IBMF_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_repost_recv_buffer_err, IBMF_TNF_ERROR, "",
		    "ibmf_i_repost_recv_buffer(): %s, status = %d\n",
		    tnf_string, msg, "repost_recv failed", tnf_uint,
		    ibt_status, status);
		kmem_free(recv_wqep->recv_wr.wr_sgl,
		    IBMF_MAX_RQ_WR_SGL_ELEMENTS * sizeof (ibt_wr_ds_t));
		kmem_cache_free(kmem_cachep, recv_wqep);
		mutex_enter(&cip->ci_mutex);
		IBMF_SUB32_PORT_KSTATS(cip, recv_wqes_alloced, 1);
		mutex_exit(&cip->ci_mutex);
		if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
			mutex_enter(&cip->ci_mutex);
			cip->ci_wqes_alloced--;
			if (cip->ci_wqes_alloced == 0)
				cv_signal(&cip->ci_wqes_cv);
			mutex_exit(&cip->ci_mutex);
		} else {
			mutex_enter(&altqp->isq_mutex);
			altqp->isq_wqes_alloced--;
			if (altqp->isq_wqes_alloced == 0)
				cv_signal(&altqp->isq_wqes_cv);
			mutex_exit(&altqp->isq_mutex);
		}
	}

	if (ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT) {
		mutex_enter(&qpp->iq_mutex);
		qpp->iq_rwqes_posted++;
		mutex_exit(&qpp->iq_mutex);
	} else {
		mutex_enter(&altqp->isq_mutex);
		altqp->isq_rwqes_posted++;
		mutex_exit(&altqp->isq_mutex);
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_repost_recv_buffer_end,
	    IBMF_TNF_TRACE, "", "ibmf_i_repost_recv_buffer() exit\n");
	return (ret);
}

/*
 * ibmf_i_get_class:
 * Parses the mad header and determines which class should be notified of the
 * notification.
 *
 * Input Argument
 * madhdrp    contents of mad header for the packet
 *
 * Output Argument
 * dest_classp pointer to the class type of the client that should be notified
 *
 * Returns
 * status
 */
static int
ibmf_i_get_class(ib_mad_hdr_t *madhdrp, ibmf_qp_handle_t dest_ibmf_qp_handle,
    ib_lid_t slid, ibmf_client_type_t *dest_classp)
{
	int		method = madhdrp->R_Method;
	int		attrib = b2h16(madhdrp->AttributeID);
	int		class = madhdrp->MgmtClass;
	uint32_t	attrib_mod = b2h32(madhdrp->AttributeModifier);

	IBMF_TRACE_4(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_get_class_start, IBMF_TNF_TRACE, "",
	    "ibmf_i_get_class() enter, class = 0x%x, method = 0x%x, "
	    "attribute = 0x%x, dest_qp_hdl = 0x%p\n",
	    tnf_opaque, class, class,
	    tnf_opaque, method, method,
	    tnf_opaque, attrib, attrib,
	    tnf_opaque, ibmf_qp_handle, dest_ibmf_qp_handle);

	/* set default for error checking */
	*dest_classp = 0;

	/*
	 * Determine the class type
	 */
	switch (class) {
	case MAD_MGMT_CLASS_SUBN_LID_ROUTED:
	case MAD_MGMT_CLASS_SUBN_DIRECT_ROUTE:

		/*
		 * tavor generates trap by sending mad with slid 0;
		 * deliver this to SMA
		 */
		if ((method == MAD_METHOD_TRAP) && (slid == 0)) {
			*dest_classp = SUBN_AGENT;
			break;
		}

		/* this is derived from table 109 of IB Spec 1.1, vol1 */
		if (attrib == SM_SMINFO_ATTRID || method == MAD_METHOD_TRAP ||
		    method == MAD_METHOD_GET_RESPONSE)
			*dest_classp = SUBN_MANAGER;
		else
			*dest_classp = SUBN_AGENT;

		break;
	case MAD_MGMT_CLASS_SUBN_ADM:

		/*
		 * Deliver to SA client (agent) if packet was sent to default qp
		 * Deliver to ibmf_saa client (manager) if packet was sent to
		 * alternate qp
		 */
		if (dest_ibmf_qp_handle == IBMF_QP_HANDLE_DEFAULT)
			*dest_classp = SUBN_ADM_AGENT;
		else
			*dest_classp = SUBN_ADM_MANAGER;
		break;
	case MAD_MGMT_CLASS_PERF:

		/* Deliver to PM if response bit is set */
		if ((method & MAD_RESPONSE_BIT_MASK) == MAD_RESPONSE_BIT)
			*dest_classp = PERF_MANAGER;
		else
			*dest_classp = PERF_AGENT;
		break;
	case MAD_MGMT_CLASS_BM:

		/*
		 * Deliver to BM if response bit is set, packet is a trap,
		 * or packet is a BMSend
		 */
		if (((method & MAD_RESPONSE_BIT_MASK) == MAD_RESPONSE_BIT) ||
		    (method == MAD_METHOD_TRAP) ||
		    ((method == MAD_METHOD_SEND) &&
		    ((attrib_mod & IBMF_BM_MAD_ATTR_MOD_REQRESP_BIT) ==
		    IBMF_BM_MAD_ATTR_MOD_RESP)))
			*dest_classp = BM_MANAGER;
		else
			*dest_classp = BM_AGENT;

		break;
	case MAD_MGMT_CLASS_DEV_MGT:

		/* Deliver to DM if response bit is set or packet is a trap */
		if (((method & MAD_RESPONSE_BIT_MASK) == MAD_RESPONSE_BIT) ||
		    (method == MAD_METHOD_TRAP))
			*dest_classp = DEV_MGT_MANAGER;
		else
			*dest_classp = DEV_MGT_AGENT;
		break;
	case MAD_MGMT_CLASS_COMM_MGT:
		*dest_classp = COMM_MGT_MANAGER_AGENT;
		break;
	case MAD_MGMT_CLASS_SNMP:
		*dest_classp = SNMP_MANAGER_AGENT;
		break;
	default:

		if ((class >= MAD_MGMT_CLASS_VENDOR_START) &&
		    (class <= MAD_MGMT_CLASS_VENDOR_END)) {
			*dest_classp = VENDOR_09_MANAGER_AGENT +
			    (class - MAD_MGMT_CLASS_VENDOR_START);
		} else if ((class >= MAD_MGMT_CLASS_VENDOR2_START) &&
		    (class <= MAD_MGMT_CLASS_VENDOR2_END)) {
			*dest_classp = VENDOR_30_MANAGER_AGENT +
			    (class - MAD_MGMT_CLASS_VENDOR2_START);
		} else if ((class >= MAD_MGMT_CLASS_APPLICATION_START) &&
		    (class <= MAD_MGMT_CLASS_APPLICATION_END)) {
			*dest_classp = APPLICATION_10_MANAGER_AGENT +
			    (class - MAD_MGMT_CLASS_APPLICATION_START);
		}

		break;
	}

	if (*dest_classp == 0) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_i_get_class_type_err, IBMF_TNF_TRACE, "",
		    "ibmf_i_get_class(): %s, class = 0x%x\n",
		    tnf_string, msg, "invalid class", tnf_opaque, class, class);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_i_get_class_end,
		    IBMF_TNF_TRACE, "", "ibmf_i_get_class() exit\n");
		return (IBMF_FAILURE);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L4,
	    ibmf_i_get_class_end, IBMF_TNF_TRACE, "",
	    "ibmf_i_get_class() exit, class = 0x%x\n",
	    tnf_opaque, class, *dest_classp);

	return (IBMF_SUCCESS);
}

/*
 * ibmf_get_mod_name():
 * Constructs the module name based on the naming convention described in
 * PSARC case 2003/753.
 * The name should be "sunwibmgt<MgtClass><a_m>
 * where:
 *	MgtClass = Management class field in the MAD header.
 *		   Two lower-case characters are used to represent
 *		   this 8-bit value as 2 hex digits.
 *	a_m	 = "a" if the client is an agent-only module
 *		   "m" if the client is a manager-only module
 *		   ""  if the client is both agent and manager.
 *
 * Input Argument
 * mad_class	management class in the MAD header
 * class	IBMF management class of incoming MAD
 *
 * Output Argument
 * modname	pointer to the character array that holds the module name
 *
 * Status
 * None
 */
static void
ibmf_get_mod_name(uint8_t mad_class, ibmf_client_type_t class, char *modname)
{
	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_get_mod_name_start,
	    IBMF_TNF_TRACE, "", "ibmf_get_mod_name_qphdl() enter\n");

	if (AGENT_CLASS(class)) {
		(void) sprintf(modname, "sunwibmgt%02xa", mad_class);
	} else if (MANAGER_CLASS(class)) {
		(void) sprintf(modname, "sunwibmgt%02xm", mad_class);
	} else {
		/* AGENT+MANAGER class */
		(void) sprintf(modname, "sunwibmgt%02x", mad_class);
	}

	IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L3, ibmf_get_mod_name,
	    IBMF_TNF_TRACE, "", "ibmf_get_mod_name(): name = %s\n",
	    tnf_string, msg, modname);

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_get_mod_name_end,
	    IBMF_TNF_TRACE, "", "ibmf_get_mod_name() exit\n");
}

/*
 * ibmf_send_busy():
 *
 * When a MAD request is received for an IB mandatory agent (BMA or PMA),
 * which has not yet registered with IBMF, IBMF returns a BUSY MAD
 * to the source of the request to solicit a retry while IBMF attempts
 * to load the mandatory agent.
 * A temporary, alternate QP is allocated for the purpose of sending the
 * MAD. This QP is configured to be in the same partition as the manager
 * that sent the request.
 *
 * Input Argument
 * modlargsp	Pointer to ibmf_mod_load_args_t structure
 *
 * Output Argument
 * None
 *
 * Status
 * None
 */
static void
ibmf_send_busy(ibmf_mod_load_args_t *modlargsp)
{
	ibmf_ci_t		*cip = modlargsp->cip;
	ibmf_recv_wqe_t		*recv_wqep = modlargsp->recv_wqep;
	ibt_wr_ds_t		sgl[1];
	ibmf_send_wqe_t		*send_wqep;
	ibt_send_wr_t		*swrp;
	ibmf_msg_impl_t 	*msgimplp;
	ibmf_ud_dest_t		*ibmf_ud_dest;
	ibt_ud_dest_t		*ud_dest;
	ib_mad_hdr_t		*smadhdrp, *rmadhdrp;
	ibt_adds_vect_t		adds_vec;
	ibt_wc_t		*wcp = &recv_wqep->recv_wc;
	ibt_status_t		ibtstatus;
	uint_t			num_work_reqs;
	ibt_qp_alloc_attr_t	qp_attrs;
	ibt_qp_info_t		qp_modify_attr;
	ibt_chan_sizes_t	qp_sizes;
	ib_qpn_t		qp_num;
	ibt_qp_hdl_t		ibt_qp_handle;
	ibt_mr_hdl_t		mem_hdl;
	ibt_mr_desc_t		mem_desc;
	ibt_mr_attr_t		mem_attr;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_start,
	    IBMF_TNF_TRACE, "", "ibmf_send_busy() enter\n");

	/* setup the qp attrs for the alloc call */
	qp_attrs.qp_scq_hdl = cip->ci_alt_cq_handle;
	qp_attrs.qp_rcq_hdl = cip->ci_alt_cq_handle;
	qp_attrs.qp_pd_hdl = cip->ci_pd;
	qp_attrs.qp_sizes.cs_sq_sgl = IBMF_MAX_SQ_WR_SGL_ELEMENTS;
	qp_attrs.qp_sizes.cs_rq_sgl = IBMF_MAX_RQ_WR_SGL_ELEMENTS;
	qp_attrs.qp_sizes.cs_sq = ibmf_send_wqes_posted_per_qp;
	qp_attrs.qp_sizes.cs_rq = ibmf_recv_wqes_posted_per_qp;
	qp_attrs.qp_flags = IBT_ALL_SIGNALED;
	qp_attrs.qp_alloc_flags = IBT_QP_NO_FLAGS;

	/* request IBT for a qp with the desired attributes */
	ibtstatus = ibt_alloc_qp(cip->ci_ci_handle, IBT_UD_RQP,
	    &qp_attrs, &qp_sizes, &qp_num, &ibt_qp_handle);
	if (ibtstatus != IBT_SUCCESS) {
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_send_busy_err,
		    IBMF_TNF_ERROR, "", "ibmf_send_busy(): %s, status = %d\n",
		    tnf_string, msg, "failed to allocate alternate QP",
		    tnf_int, ibt_status, ibtstatus);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_end,
		    IBMF_TNF_TRACE, "", "ibmf_send_busy() exit\n");
		return;
	}

	qp_modify_attr.qp_trans = IBT_UD_SRV;
	qp_modify_attr.qp_flags = IBT_CEP_NO_FLAGS;
	qp_modify_attr.qp_transport.ud.ud_qkey = IB_GSI_QKEY;
	qp_modify_attr.qp_transport.ud.ud_sq_psn = 0;
	qp_modify_attr.qp_transport.ud.ud_pkey_ix = wcp->wc_pkey_ix;
	qp_modify_attr.qp_transport.ud.ud_port = recv_wqep->recv_port_num;

	/* call the IB transport to initialize the QP */
	ibtstatus = ibt_initialize_qp(ibt_qp_handle, &qp_modify_attr);
	if (ibtstatus != IBT_SUCCESS) {
		(void) ibt_free_qp(ibt_qp_handle);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_send_busy_err,
		    IBMF_TNF_ERROR, "", "ibmf_send_busy(): %s, status = %d\n",
		    tnf_string, msg, "failed to initialize alternate QP",
		    tnf_int, ibt_status, ibtstatus);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_end,
		    IBMF_TNF_TRACE, "", "ibmf_send_busy() exit\n");
		return;
	}

	/* allocate the message context */
	msgimplp = (ibmf_msg_impl_t *)kmem_zalloc(sizeof (ibmf_msg_impl_t),
	    KM_SLEEP);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*msgimplp))

	ibmf_i_pop_ud_dest_thread(cip);

	/*
	 * Get a UD dest structure from the pool, this will not fail
	 * because ibmf_i_pop_ud_dest_thread() calls
	 * ibmf_i_populate_ud_dest_list with the KM_SLEEP flag.
	 */
	ibmf_ud_dest = ibmf_i_get_ud_dest(cip);

	msgimplp->im_ibmf_ud_dest = ibmf_ud_dest;
	msgimplp->im_ud_dest = &ibmf_ud_dest->ud_dest;
	msgimplp->im_qp_hdl = NULL;

	/*
	 * Reset send_done to indicate we have not received the completion
	 * for this send yet.
	 */
	msgimplp->im_trans_state_flags &= ~IBMF_TRANS_STATE_FLAG_SEND_DONE;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*send_wqep))

	/*
	 * Allocate resources needed to send a UD packet including the
	 * send WQE context
	 */
	send_wqep = (ibmf_send_wqe_t *)kmem_zalloc(sizeof (ibmf_send_wqe_t),
	    KM_SLEEP);
	send_wqep->send_mem = (void *)kmem_zalloc(IBMF_MEM_PER_WQE, KM_SLEEP);

	mem_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)send_wqep->send_mem;
	mem_attr.mr_len = IBMF_MEM_PER_WQE;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	mem_attr.mr_as = NULL;

	/* Register the allocated memory */
	ibtstatus = ibt_register_mr(cip->ci_ci_handle, cip->ci_pd, &mem_attr,
	    &mem_hdl, &mem_desc);
	if (ibtstatus != IBT_SUCCESS) {
		kmem_free(send_wqep->send_mem, IBMF_MEM_PER_WQE);
		kmem_free(send_wqep, sizeof (ibmf_send_wqe_t));
		ibmf_i_put_ud_dest(cip, msgimplp->im_ibmf_ud_dest);
		kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
		(void) ibt_free_qp(ibt_qp_handle);
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_send_busy_err,
		    IBMF_TNF_ERROR, "", "ibmf_send_busy(): %s, status = %d\n",
		    tnf_string, msg, "failed to register memory",
		    tnf_int, ibt_status, ibtstatus);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_end,
		    IBMF_TNF_TRACE, "", "ibmf_send_busy() exit\n");
		return;
	}

	send_wqep->send_sg_lkey = mem_desc.md_lkey;
	send_wqep->send_mem_hdl = mem_hdl;

	swrp = &send_wqep->send_wr;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*swrp))

	/* use send wqe pointer as the WR ID */
	swrp->wr_id		= (ibt_wrid_t)(uintptr_t)send_wqep;
	ASSERT(swrp->wr_id != NULL);
	swrp->wr_flags		= IBT_WR_NO_FLAGS;
	swrp->wr_opcode		= IBT_WRC_SEND;
	swrp->wr_trans		= IBT_UD_SRV;

	send_wqep->send_client	= NULL;
	send_wqep->send_msg	= msgimplp;

	/* Initialize the scatter-gather list */
	sgl[0].ds_va		= (ib_vaddr_t)(uintptr_t)send_wqep->send_mem;
	sgl[0].ds_key		= send_wqep->send_sg_lkey;
	sgl[0].ds_len		= IBMF_MAD_SIZE;

	wcp			= &recv_wqep->recv_wc;

	/* Initialize the address vector */
	adds_vec.av_send_grh	= B_FALSE;
	adds_vec.av_dlid	= wcp->wc_slid;
	adds_vec.av_src_path	= wcp->wc_path_bits;
	adds_vec.av_srvl	= 0;
	adds_vec.av_srate	= IBT_SRATE_1X;
	adds_vec.av_port_num	= recv_wqep->recv_port_num;

	ud_dest			= msgimplp->im_ud_dest;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*ud_dest))
	ud_dest->ud_qkey	= IB_GSI_QKEY;
	ud_dest->ud_dst_qpn	= wcp->wc_qpn;

	/* modify the address handle with the address vector information */
	ibtstatus = ibt_modify_ah(cip->ci_ci_handle, ud_dest->ud_ah, &adds_vec);
	if (ibtstatus != IBT_SUCCESS) {
		(void) ibt_deregister_mr(cip->ci_ci_handle, mem_hdl);
		kmem_free(send_wqep->send_mem, IBMF_MEM_PER_WQE);
		kmem_free(send_wqep, sizeof (ibmf_send_wqe_t));
		ibmf_i_put_ud_dest(cip, msgimplp->im_ibmf_ud_dest);
		kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1, ibmf_send_busy_err,
		    IBMF_TNF_ERROR, "", "ibmf_send_busy(): %s, status = %d\n",
		    tnf_string, msg, "ibt modify ah failed", tnf_uint,
		    ibt_status, ibtstatus);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_end,
		    IBMF_TNF_TRACE, "", "ibmf_send_busy(() exit\n");
		return;
	}

	bzero(send_wqep->send_mem, IBMF_MAD_SIZE);

	rmadhdrp = (ib_mad_hdr_t *)((uintptr_t)recv_wqep->recv_mem +
	    sizeof (ib_grh_t));
	smadhdrp = (ib_mad_hdr_t *)send_wqep->send_mem;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*rmadhdrp))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*smadhdrp))

	/* Set up the MAD header */
	smadhdrp->BaseVersion	= rmadhdrp->BaseVersion;
	smadhdrp->MgmtClass	= rmadhdrp->MgmtClass;
	smadhdrp->ClassVersion	= rmadhdrp->ClassVersion;
	smadhdrp->R_Method	= MAD_METHOD_GET_RESPONSE;
	smadhdrp->Status	= MAD_STATUS_BUSY;
	smadhdrp->TransactionID	= rmadhdrp->TransactionID;
	smadhdrp->AttributeID	= rmadhdrp->AttributeID;
	smadhdrp->AttributeModifier = rmadhdrp->AttributeModifier;

	swrp->wr_sgl		= sgl;
	swrp->wr_nds		= 1;
	swrp->wr.ud.udwr_dest	= msgimplp->im_ud_dest;
	send_wqep->send_port_num = recv_wqep->recv_port_num;
	send_wqep->send_qp_handle = ibt_qp_handle;
	send_wqep->send_ibmf_qp_handle = NULL;

	/* Post the MAD to the IBT layer */
	num_work_reqs		= 1;

	ibtstatus = ibt_post_send(ibt_qp_handle, &send_wqep->send_wr,
	    num_work_reqs, NULL);
	if (ibtstatus != IBT_SUCCESS) {
		(void) ibt_deregister_mr(cip->ci_ci_handle, mem_hdl);
		kmem_free(send_wqep->send_mem, IBMF_MEM_PER_WQE);
		kmem_free(send_wqep, sizeof (ibmf_send_wqe_t));
		ibmf_i_put_ud_dest(cip, msgimplp->im_ibmf_ud_dest);
		kmem_free(msgimplp, sizeof (ibmf_msg_impl_t));
		IBMF_TRACE_2(IBMF_TNF_NODEBUG, DPRINT_L1,
		    ibmf_send_busy_err, IBMF_TNF_TRACE, "",
		    "ibmf_send_busy(): %s, status = %d\n", tnf_string, msg,
		    "post send failure", tnf_uint, ibt_status, ibtstatus);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_end,
		    IBMF_TNF_TRACE, "", "ibmf_send_busy(() exit\n");
		return;
	}

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_send_busy_end,
	    IBMF_TNF_TRACE, "", "ibmf_send_busy() exit\n");
}

/*
 * ibmf_module_load():
 * This function attempts to load a client module that has not yet
 * registered with IBMF at the time a request MAD arrives for it.
 * Prior to loading the module, it sends a busy MAD to the sender of
 * the request MAD, this soliciting a resend of the request MAD.
 *
 * Input Argument
 * modlargsp	Pointer to ibmf_mod_load_args_t structure
 *
 * Output Argument
 * None
 *
 * Status
 * None
 */
static void
ibmf_module_load(void *taskq_arg)
{
	char *modname;
	ibmf_mod_load_args_t *modlargsp = (ibmf_mod_load_args_t *)taskq_arg;
	ibmf_ci_t *cip = modlargsp->cip;
	ibmf_recv_wqe_t	*recv_wqep = modlargsp->recv_wqep;
	ibmf_client_type_t class = modlargsp->ibmf_class;

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_module_load_start,
	    IBMF_TNF_TRACE, "", "ibmf_module_load_busy() enter\n");
	modname = modlargsp->modname;

	if (IS_MANDATORY_CLASS(class)) {
		ibmf_send_busy(modlargsp);
	}

	if (modload("misc", modname) < 0) {
		(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);
		kmem_free(modlargsp, sizeof (ibmf_mod_load_args_t));
		IBMF_TRACE_1(IBMF_TNF_DEBUG, DPRINT_L1, ibmf_module_load_error,
		    IBMF_TNF_TRACE, "",
		    "ibmf_module_load(): modload failed for %s\n",
		    tnf_string, module, modname);
		IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_module_load_end,
		    IBMF_TNF_TRACE, "", "ibmf_module_load() exit\n");
		return;
	}

	(void) ibmf_i_repost_recv_buffer(cip, recv_wqep);

	kmem_free(modlargsp, sizeof (ibmf_mod_load_args_t));

	IBMF_TRACE_0(IBMF_TNF_DEBUG, DPRINT_L4, ibmf_module_load_end,
	    IBMF_TNF_TRACE, "", "ibmf_module_load_busy() exit\n");
}
