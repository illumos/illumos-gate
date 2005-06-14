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

#ifndef	_SYS_IB_IBTL_IBVTI_H
#define	_SYS_IB_IBTL_IBVTI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ibvti.h
 *
 * This file contains private verbs level transport interface extensions.
 */
#include <sys/ib/ibtl/ibti_common.h>
#include <sys/ib/ibtl/ibtl_ci_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	IBT_CM_NO_QP		IBT_CM_NO_CHAN		/* ibt_cm_reason_t */

#define	IBT_CM_SREP_QPN_VALID	IBT_CM_SREP_CHAN_VALID	/* ibt_sidr_status_t */
#define	IBT_CM_SREP_NO_QP	IBT_CM_SREP_NO_CHAN	/* ibt_sidr_status_t */

#define	IBT_OCHAN_CM_RETRY	IBT_OCHAN_OPAQUE1 /* ibt_chan_open_flags_t */
#define	IBT_OCHAN_STARTING_PSN	IBT_OCHAN_OPAQUE2 /* ibt_chan_open_flags_t */
#define	IBT_OCHAN_LOCAL_CM_TM	IBT_OCHAN_OPAQUE3 /* ibt_chan_open_flags_t */
#define	IBT_OCHAN_REMOTE_CM_TM	IBT_OCHAN_OPAQUE4 /* ibt_chan_open_flags_t */
#define	IBT_OCHAN_RDC_EXISTS	IBT_OCHAN_OPAQUE5 /* ibt_chan_open_flags_t */

#define	oc_cm_retry_cnt		oc_opaque1	/* ibt_chan_open_args_t */
						/* The number of times the */
						/* CM will retry its MADs */
						/* when IBT_OCHAN_CM_RETRY */
						/* is set */
#define	oc_starting_psn		oc_opaque2	/* ibt_chan_open_args_t */
						/* use oc_starting_psn when */
						/* IBT_OCHAN_STARTING_PSN is */
						/* set */

#define	oc_local_cm_time	oc_opaque3	/* ibt_chan_open_args_t */
						/* The maximum time in */
						/* microseconds that local */
						/* client takes to  respond */
						/* for a CM callback */

#define	oc_remote_cm_time	oc_opaque4	/* ibt_chan_open_args_t */
						/* The maximum time in */
						/* microseconds that remote */
						/* node takes to  respond */
						/* for a CM MAD */

#define	cm_eec_hdl		cm_opaque	/* ibt_cm_event_t */

#define	req_remote_eecn		req_opaque1	/* ibt_cm_req_rcv_t */
#define	req_local_eecn		req_opaque2	/* ibt_cm_req_rcv_t */

#define	IBT_CM_RDC_EXISTS	0x4		/* ibt_cm_flags_t */

#define	ai_dlid			ai_opaque1	/* Local dest, or router LID */
#define	ai_src_path		ai_opaque2	/* Source path bits */


/*
 * Note that variables of type ibt_qp_hdl_t (really ibt_channel_hdl_t)
 * can be used in some of the IBTI interfaces, e.g., ibt_open_rc_channel().
 */
#define	ibt_qp_hdl_t		ibt_channel_hdl_t

/*
 * ibt_cq_priority_t
 * VTI clients have full control over CQ priorities.
 */
#define	IBT_CQ_PRI_1	IBT_CQ_OPAQUE_1		/* Lowest priority */
#define	IBT_CQ_PRI_2	IBT_CQ_OPAQUE_2
#define	IBT_CQ_PRI_3	IBT_CQ_OPAQUE_3
#define	IBT_CQ_PRI_4	IBT_CQ_OPAQUE_4
#define	IBT_CQ_PRI_5	IBT_CQ_OPAQUE_5
#define	IBT_CQ_PRI_6	IBT_CQ_OPAQUE_6
#define	IBT_CQ_PRI_7	IBT_CQ_OPAQUE_7
#define	IBT_CQ_PRI_8	IBT_CQ_OPAQUE_8
#define	IBT_CQ_PRI_9	IBT_CQ_OPAQUE_9
#define	IBT_CQ_PRI_10	IBT_CQ_OPAQUE_10
#define	IBT_CQ_PRI_11	IBT_CQ_OPAQUE_11
#define	IBT_CQ_PRI_12	IBT_CQ_OPAQUE_12
#define	IBT_CQ_PRI_13	IBT_CQ_OPAQUE_13
#define	IBT_CQ_PRI_14	IBT_CQ_OPAQUE_14
#define	IBT_CQ_PRI_15	IBT_CQ_OPAQUE_15
#define	IBT_CQ_PRI_16	IBT_CQ_OPAQUE_16	/* Highest priority */

/*
 * FUNCTION PROTOTYPES.
 */
/*
 * ibt_alloc_ah()
 *	Allocates and returns an address handle (ibt_ah_hdl_t).
 *
 *	hca_hdl		The IBT HCA handle returned to the client
 *			on an ibt_open_hca() call.
 *
 *	flags		IBT_AH_NO_FLAGS, IBT_AH_USER_MAP and IBT_AH_DEFER_ALLOC
 *
 *	pd		Is a protection domain to associate with this handle.
 *
 *	adds_vectp	Points to an ibt_adds_vect_t struct.
 *
 *	ah_p		The address to store the allocated address handle.
 *
 */
ibt_status_t ibt_alloc_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_flags_t flags,
    ibt_pd_hdl_t pd, ibt_adds_vect_t *adds_vectp, ibt_ah_hdl_t *ah_p);

/*
 * ibt_free_ah()
 *	Release/de-allocate the specified handle.
 *
 *	hca_hdl		The IBT HCA handle.
 *
 *	ah		The address handle.
 */
ibt_status_t ibt_free_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah);

/*
 * ibt_query_ah
 *	Obtain the address vector information for the specified address handle.
 *
 *	hca_hdl		The IBT HCA handle returned to the client
 *			on an ibt_open_hca() call.
 *
 *	ah		The address handle.
 *
 *	pd_p		The protection domain handle of the PD with which this
 *			address handle is associated.
 *
 *	adds_vectp	Points to an ibt_adds_vect_t struct.
 *
 */
ibt_status_t ibt_query_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah,
    ibt_pd_hdl_t *pd_p, ibt_adds_vect_t *adds_vectp);

/*
 * ibt_modify_ah
 *	Modify the address vector information for the specified address handle.
 *
 *	hca_hdl		The IBT HCA handle returned to the client on an
 *			ibt_open_hca() call.
 *
 *	ah		The address handle.
 *
 *	adds_vectp	Points to an ibt_adds_vect_t struct. The new address
 *			vector information is specified is this returned struct.
 */
ibt_status_t ibt_modify_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah,
    ibt_adds_vect_t *adds_vectp);


/*
 * ibt_alloc_qp()
 *	Allocate a QP with specified attributes.
 *
 *	hca_hdl		Specifies the QP's HCA.
 *
 *	type		Specifies the type of QP to alloc in ibt_alloc_qp()
 *
 *	qp_attr		Specifies the ibt_qp_alloc_attr_t that are needed to
 *			allocate a QP. All allocated QP's are returned in the
 *			RESET state.
 *
 *	queue_sizes_p	NULL or a pointer to ibt_chan_sizes_s struct to return
 *			new channel sizes.
 *			cs_sq		Returned new SendQ size.
 *			cs_rq		Returned new RecvQ size.
 *			cs_sq_sgl	Returned Max SGL elements in a SQ WR.
 *			cs_rq_sgl	Returned Max SGL elements in a RQ WR.
 *
 *	qpn_p		NULL or a pointer to return QP Number of the
 *			allocated QP.
 *
 *	ibt_qp_p	The address to store the handle of the allocated QP.
 *
 * Note:
 *	QPs allocated by ibt_alloc_qp are in the RESET state.  The client
 *	needs to transition an RC QP into the INIT state if it is going to
 *	use ibt_open_rc_channel to establish the connection.
 *	The client needs to transition an UD QP into the RTS state.
 */
ibt_status_t ibt_alloc_qp(ibt_hca_hdl_t hca_hdl, ibt_qp_type_t type,
    ibt_qp_alloc_attr_t *qp_attr, ibt_chan_sizes_t *queue_sizes_p,
    ib_qpn_t *qpn_p, ibt_qp_hdl_t *ibt_qp_p);

/*
 * ibt_alloc_special_qp()
 *	Allocate a special QP with specified attributes.
 *
 *	hca_hdl		Specifies the QP's HCA.
 *
 *	port		Specifies the Port on the HCA.
 *
 *	type		Specifies the type of Special QP to alloc.
 *
 *	qp_attr		Specifies the ibt_qp_alloc_attr_t that are needed to
 *			allocate a Special QP. All allocated QP's are returned
 *			in the RESET state.
 *
 *	queue_sizes_p	NULL or a pointer to ibt_chan_sizes_s struct to return
 *			new channel sizes.
 *			cs_sq		Returned new SendQ size.
 *			cs_rq		Returned new RecvQ size.
 *			cs_sq_sgl	Returned Max SGL elements in a SQ WR.
 *			cs_rq_sgl	Returned Max SGL elements in a RQ WR.
 *
 *	ibt_qp_p	The address to store the handle of the allocated QP.
 *
 * Note:
 *	QPs allocated by ibt_alloc_special_qp are in the RESET state.
 *	The client needs to transition an UD QP into the RTS state.
 */
ibt_status_t ibt_alloc_special_qp(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ibt_sqp_type_t type, ibt_qp_alloc_attr_t *qp_attr,
    ibt_chan_sizes_t *queue_sizes_p, ibt_qp_hdl_t *ibt_qp_p);

/*
 * ibt_flush_qp()
 *	Transition a QP into error state to flush all outstanding
 *	work requests. Must be called before calling ibt_free_qp().
 *	Use ibt_close_rc_channel for RC QPs that have been opened
 *	successfully.
 *
 *	ibt_qp		The ibt_qp_hdl_t of previously allocated QP.
 */
ibt_status_t ibt_flush_qp(ibt_qp_hdl_t ibt_qp);

/*
 * ibt_initialize_qp()
 *	Transition a QP from RESET state into a usable state.
 *	An RC QP is transitioned into the INIT state, ready for
 *	a call to ibt_open_rc_channel().  A UD QP is transitioned
 *	all the way to the RTS state.
 *
 *	ibt_qp		The ibt_qp_hdl_t of previously allocated QP.
 *
 *	modify_attrp	Points to an ibt_qp_info_t struct that contains all
 *			the attributes of the specified QP that a client is
 *			allowed to modify after a QP has been allocated.
 */
ibt_status_t ibt_initialize_qp(ibt_qp_hdl_t ibt_qp,
    ibt_qp_info_t *modify_attrp);


/*
 * ibt_free_qp()
 *	De-allocate or free the resources associated with an existing QP.
 *
 *	ibt_qp		The ibt_qp_hdl_t of previously allocated QP.
 */
ibt_status_t ibt_free_qp(ibt_qp_hdl_t ibt_qp);


/*
 * ibt_query_qp()
 *	Query the attributes of an existing QP.
 *
 *	ibt_qp		The ibt_qp_hdl_t of previously allocated QP.
 *
 *	qp_attrp	Specifies the ibt_qp_query_attr_t contains all the
 *			attributes of the specified QP.
 */
ibt_status_t ibt_query_qp(ibt_qp_hdl_t ibt_qp, ibt_qp_query_attr_t *qp_attrp);


/*
 * ibt_modify_qp()
 *	Modify the attributes of an existing QP.
 *
 *	ibt_qp		The ibt_qp_hdl_t of previously allocated QP.
 *
 *	flags		Specifies which attributes in ibt_qp_mod_attr_t
 *			are to be modified.
 *
 *	qp_attr		Points to an ibt_qp_info_t struct that contains all
 *			the attributes of the specified QP that a client is
 *			allowed to modify after a QP has been allocated.
 *
 *	actual_sz	NULL or a pointer to ibt_queue_size_s struct to
 *			return new queue sizes.
 *			sq_sz		Returned new SendQ size.
 *			rq_sz		Returned new RecvQ size.
 */
ibt_status_t ibt_modify_qp(ibt_qp_hdl_t ibt_qp, ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *qp_attr, ibt_queue_sizes_t *actual_sz);

/*
 * ibt_set_qp_private(), ibt_get_qp_private()
 *	Set/Get the client private data.
 *
 *	ibt_qp		The ibt_qp_hdl_t of the allocated QP.
 *
 *	clnt_private	The client private data.
 */
void ibt_set_qp_private(ibt_qp_hdl_t ibt_qp, void *clnt_private);
void *ibt_get_qp_private(ibt_qp_hdl_t ibt_qp);


/*
 * ibt_qp_to_hca_guid
 *      A helper function to retrieve HCA GUID for the specified QP.
 *
 *      ibt_qp		The ibt_qp_hdl_t of the allocated QP.
 *
 *      hca_guid        Returned HCA GUID on which the specified QP is
 *                      allocated. Valid if it is non-NULL on return.
 */
ib_guid_t ibt_qp_to_hca_guid(ibt_qp_hdl_t ibt_qp);


/*
 * ibt_recover_ud_qp()
 *      Recover an UD QP which has transitioned to SQ Error state. The
 *      ibt_recover_ud_qp() transitions the QP from SQ Error state to
 *	Ready-To-Send QP state.
 *
 *      If a work request posted to a UD QP's send queue completes with
 *      an error (see ibt_wc_status_t), the QP gets transitioned to SQ
 *      Error state. In order to reuse this QP, ibt_recover_ud_qp() can
 *      be used to recover the QP to a usable (Ready-to-Send) state.
 *
 *      ibt_qp         An UD QP handle which is in SQError state.
 */
ibt_status_t ibt_recover_ud_qp(ibt_qp_hdl_t ibt_qp);


/*
 * Datagram Domain Functions
 */

/*
 * ibt_ud_get_dqpn
 *	Finds the destination QPN at the specified destination that the
 *	specified service can be reached on. The IBTF CM initiates the
 *	service ID resolution protocol (SIDR) to determine a destination QPN.
 *
 *	attr		A pointer to an ibt_ud_dest_attr_t struct input arg.
 *
 *	mode		IBT_BLOCKING		Do not return until completed.
 *						"returns" must not be NULL.
 *			IBT_NONBLOCKING		Return as soon as possible.
 *						This requires that the client
 *						supplies a UD CM handler to
 *						be called when this completes.
 *						"returns" must be NULL.
 *
 *	returns		If the function is called in blocking mode, "returns"
 *			is a pointer to an ibt_ud_returns_t struct, containing:
 *
 *			ud_status	  Indicates if the UD destination handle
 *					  was allocated successfully. If the
 *					  handle was not allocated the status
 *					  code gives an indication why not.
 *			ud_redirect	  A ibt_redirect_info_s struct, valid
 *					  for a ud_status of
 *					  IBT_CM_SREP_REDIRECT. The remote
 *					  destination could not provide the
 *					  service requested in dest_attrs. The
 *					  request was redirected to a new
 *					  destination, the details of which are
 *					  returned in ud_redirect.
 *			ud_dqpn		  Returned destination QPN.
 *			ud_qkey		  Q_Key for destination QPN.
 *			ud_priv_data_len  The length (in bytes) of the buffer
 *					  pointed to by ud_priv_data.
 *			ud_priv_data	  A pointer to the caller's buffer
 *					  where private data from the
 *					  destination node is returned.
 */
ibt_status_t ibt_ud_get_dqpn(ibt_ud_dest_attr_t *attr,
    ibt_execution_mode_t mode, ibt_ud_returns_t *returns);

/*
 * ibt_get_module_failure()
 *
 *	Used to obtain a special IBTF failure code for IB module specific
 *	failures, i.e. failures other than those defined in ibt_status_t.
 *
 *	type	Identifies the failing IB module.
 *
 *	ena	'0' or the data for Fault Management Architecture (ENA).
 */
ibt_status_t ibt_get_module_failure(ibt_failure_type_t type, uint64_t ena);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBVTI_H */
