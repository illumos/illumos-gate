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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_IBTL_IBVTI_H
#define	_SYS_IB_IBTL_IBVTI_H

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
#define	IBT_OCHAN_OFUV		IBT_OCHAN_OPAQUE6 /* ibt_chan_open_flags_t */

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
 * FUNCTION PROTOTYPES.
 */
/*
 * ibt_alloc_ah()
 *	Allocates and returns an address handle (ibt_ah_hdl_t).
 */
ibt_status_t ibt_alloc_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_flags_t flags,
    ibt_pd_hdl_t pd, ibt_adds_vect_t *adds_vectp, ibt_ah_hdl_t *ah_p);

/*
 * ibt_free_ah()
 *	Release/de-allocate the specified handle.
 */
ibt_status_t ibt_free_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah);

/*
 * ibt_query_ah
 *	Obtain the address vector information for the specified address handle.
 */
ibt_status_t ibt_query_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah,
    ibt_pd_hdl_t *pd_p, ibt_adds_vect_t *adds_vectp);

/*
 * ibt_modify_ah
 *	Modify the address vector information for the specified address handle.
 */
ibt_status_t ibt_modify_ah(ibt_hca_hdl_t hca_hdl, ibt_ah_hdl_t ah,
    ibt_adds_vect_t *adds_vectp);


/*
 * ibt_alloc_qp()
 *	Allocate a QP with specified attributes.
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
 */
ibt_status_t ibt_flush_qp(ibt_qp_hdl_t ibt_qp);

/*
 * ibt_initialize_qp()
 *	Transition a QP from RESET state into a usable state.
 *	An RC QP is transitioned into the INIT state, ready for
 *	a call to ibt_open_rc_channel().  A UD QP is transitioned
 *	all the way to the RTS state.
 */
ibt_status_t ibt_initialize_qp(ibt_qp_hdl_t ibt_qp,
    ibt_qp_info_t *modify_attrp);


/*
 * ibt_free_qp()
 *	De-allocate or free the resources associated with an existing QP.
 */
ibt_status_t ibt_free_qp(ibt_qp_hdl_t ibt_qp);


/*
 * ibt_query_qp()
 *	Query the attributes of an existing QP.
 */
ibt_status_t ibt_query_qp(ibt_qp_hdl_t ibt_qp, ibt_qp_query_attr_t *qp_attrp);


/*
 * ibt_modify_qp()
 *	Modify the attributes of an existing QP.
 */
ibt_status_t ibt_modify_qp(ibt_qp_hdl_t ibt_qp, ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *qp_attr, ibt_queue_sizes_t *actual_sz);

/*
 * ibt_set_qp_private(), ibt_get_qp_private()
 *	Set/Get the client private data.
 */
void ibt_set_qp_private(ibt_qp_hdl_t ibt_qp, void *clnt_private);
void *ibt_get_qp_private(ibt_qp_hdl_t ibt_qp);


/*
 * ibt_qp_to_hca_guid
 *      A helper function to retrieve HCA GUID for the specified QP.
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
 */
ibt_status_t ibt_ud_get_dqpn(ibt_ud_dest_attr_t *attr,
    ibt_execution_mode_t mode, ibt_ud_returns_t *returns);

/*
 * ibt_get_module_failure()
 *
 *	Used to obtain a special IBTF failure code for IB module specific
 *	failures, i.e. failures other than those defined in ibt_status_t.
 */
ibt_status_t ibt_get_module_failure(ibt_failure_type_t type, uint64_t ena);

ibt_status_t ibt_ofuvcm_get_req_data(void *, ibt_ofuvcm_req_data_t *);

ibt_status_t ibt_ofuvcm_proceed(ibt_cm_event_type_t, void *,
    ibt_cm_status_t, ibt_cm_proceed_reply_t *, void *,
    ibt_priv_data_len_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBVTI_H */
