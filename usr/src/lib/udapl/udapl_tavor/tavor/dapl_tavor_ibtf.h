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

#ifndef _DAPL_TAVOR_IBTI_H
#define	_DAPL_TAVOR_IBTI_H

/*
 * This header file defines various IB types that is used by the
 * generic reference implementation. These IB types are mapped to
 * IBTF types.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/ibtl/ibti.h>
#include <daplt_if.h>
#include <sys/ib/adapters/mlnx_umap.h>

#define	DAPLIB_NEEDS_INIT(ep)  ((ep)->qp_state == IBT_STATE_ERROR)
#define	DAPL_MAX_IOV		8

/*
 * The InfiniBand Specification, Section 9.7.7, states that the
 * upper bound on the maximum message size for an RC connection
 * is 2^31 bytes. Implementations are free to support a smaller
 * value. see dapli_ep_default_attrs
 */
#define	DAPL_IB_MAX_MESSAGE_SIZE	0x80000000
#define	DAPL_MAX_ADDRESS		0xfffffffffffffff0ULL


#define	true				B_TRUE
#define	false				B_FALSE
#define	IB_INVALID_HANDLE		0

#define	DAPL_CQE_INVALID_PRMEVENT	0x1015
#define	DAPL_CQE_VALID_PRMEVENT		0x1215

#define	DAPL_GET_CQE_WRID(cqe_p)	\
			((ib_work_completion_t *)(cqe_p))->wc_id
#define	DAPL_GET_CQE_OPTYPE(cqe_p)	\
			((ib_work_completion_t *)(cqe_p))->wc_type
#define	DAPL_GET_CQE_BYTESNUM(cqe_p)	\
			((ib_work_completion_t *)(cqe_p))->wc_bytes_xfer
#define	DAPL_GET_CQE_STATUS(cqe_p)	\
			((ib_work_completion_t *)(cqe_p))->wc_status
#define	DAPL_GET_CQE_QPN(cqe_p)	\
			((ib_work_completion_t *)(cqe_p))->wc_qpn
#define	DAPL_CQE_IS_VALID(cqe_p)	\
			(((ib_work_completion_t *)(cqe_p))->wc_res_hash == \
			DAPL_CQE_VALID_PRMEVENT)
#define	DAPL_SET_CQE_INVALID(cqe_p)	\
			(((ib_work_completion_t *)(cqe_p))->wc_res_hash = \
			DAPL_CQE_INVALID_PRMEVENT)
#define	DAPL_SET_CQE_VALID(cqe_p)	\
			(((ib_work_completion_t *)(cqe_p))->wc_res_hash = \
			DAPL_CQE_VALID_PRMEVENT)

/*
 * Map private data constants to IBTF constants
 */
#define	IB_MAX_REQ_PDATA_SIZE		IBT_REQ_PRIV_DATA_SZ
#define	IB_MAX_REP_PDATA_SIZE		IBT_REP_PRIV_DATA_SZ
#define	IB_MAX_REJ_PDATA_SIZE		IBT_REJ_PRIV_DATA_SZ
#define	IB_MAX_DREQ_PDATA_SIZE		IBT_DREQ_PRIV_DATA_SZ
#define	IB_MAX_DREP_PDATA_SIZE		IBT_DREP_PRIV_DATA_SZ

/*
 * Definitions to map DTO OPs to IBTF definitions
 */
#define	OP_RDMA_READ			IBT_WRC_RDMAR
#define	OP_RDMA_WRITE			IBT_WRC_RDMAW
#define	OP_SEND				IBT_WRC_SEND
#define	OP_RECEIVE			IBT_WRC_RECV
#define	OP_COMP_AND_SWAP		IBT_WRC_CSWAP
#define	OP_FETCH_AND_ADD		IBT_WRC_FADD
#define	OP_BIND_MW			IBT_WRC_BIND

/*
 * Definitions to map Memory OPs
 */
#define	IB_ACCESS_LOCAL_WRITE	IBT_MR_ENABLE_LOCAL_WRITE
#define	IB_ACCESS_REMOTE_READ	IBT_MR_ENABLE_REMOTE_READ
#define	IB_ACCESS_REMOTE_WRITE	IBT_MR_ENABLE_REMOTE_WRITE

/*
 * Definitions to map WR_BIND request flags -
 * IBTF uses diff set of flags for the ibt_bind_flags_t
 */
#define	IB_BIND_ACCESS_REMOTE_READ	IBT_WR_BIND_READ
#define	IB_BIND_ACCESS_REMOTE_WRITE	IBT_WR_BIND_WRITE

/*
 * MAP CQE status to IBT_WC_*
 */
#define	IB_COMP_ST_SUCCESS		IBT_WC_SUCCESS
#define	IB_COMP_ST_LOCAL_LEN_ERR	IBT_WC_LOCAL_LEN_ERR
#define	IB_COMP_ST_LOCAL_OP_ERR		IBT_WC_LOCAL_CHAN_OP_ERR
#define	IB_COMP_ST_LOCAL_PROTECT_ERR	IBT_WC_LOCAL_PROTECT_ERR
#define	IB_COMP_ST_WR_FLUSHED_ERR	IBT_WC_WR_FLUSHED_ERR
#define	IB_COMP_ST_MW_BIND_ERR		IBT_WC_MEM_WIN_BIND_ERR
#define	IB_COMP_ST_REM_REQ_ERR		IBT_WC_REMOTE_INVALID_REQ_ERR
#define	IB_COMP_ST_REM_ACC_ERR		IBT_WC_REMOTE_ACCESS_ERR
#define	IB_COMP_ST_REM_OP_ERR		IBT_WC_REMOTE_OP_ERR
#define	IB_COMP_ST_TRANSP_COUNTER	IBT_WC_TRANS_TIMEOUT_ERR
#define	IB_COMP_ST_RNR_COUNTER		IBT_WC_RNR_NAK_TIMEOUT_ERR
#define	IB_COMP_ST_BAD_RESPONSE_ERR	IBT_WC_BAD_RESPONSE_ERR

/*
 * CQ NOTIFICATION TYPE
 */
#define	IB_NOTIFY_ON_NEXT_COMP		1
#define	IB_NOTIFY_ON_NEXT_SOLICITED	2
#define	IB_NOTIFY_ON_NEXT_NCOMP		3

/*
 * Connection Manager Defs
 */
#define	IB_CME_CONNECTED			DAPL_IB_CME_CONNECTED
#define	IB_CME_DISCONNECTED			DAPL_IB_CME_DISCONNECTED
#define	IB_CME_CONNECTION_REQUEST_PENDING	\
	DAPL_IB_CME_CONNECTION_REQUEST_PENDING
#define	IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA	\
	DAPL_IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA
#define	IB_CME_DESTINATION_REJECT		DAPL_IB_CME_DESTINATION_REJECT
#define	IB_CME_DESTINATION_REJECT_PRIVATE_DATA	\
	DAPL_IB_CME_DESTINATION_REJECT_PRIVATE_DATA
#define	IB_CME_DESTINATION_UNREACHABLE		\
	DAPL_IB_CME_DESTINATION_UNREACHABLE
#define	IB_CME_TOO_MANY_CONNECTION_REQUESTS	\
	DAPL_IB_CME_TOO_MANY_CONNECTION_REQUESTS
#define	IB_CME_LOCAL_FAILURE			DAPL_IB_CME_LOCAL_FAILURE
#define	IB_CME_TIMED_OUT			DAPL_IB_CME_TIMED_OUT
#define	IB_CME_DISCONNECTED_ON_LINK_DOWN	\
	DAPL_IB_CME_DISCONNECTED_ON_LINK_DOWN
#define	IB_CM_REJ_REASON_CONSUMER_REJ		\
	DAPL_IB_CM_REJ_REASON_CONSUMER_REJ

/*
 * Typedefs to map generic 'ib' types to service provider implementation
 */
typedef	dapl_ib_cm_event_type_t		ib_cm_events_t;
typedef uint64_t			ib_cm_handle_t;
typedef	uint32_t			ib_cqd_handle_t;
typedef	uint64_t			ib_cno_handle_t;

typedef struct dapls_ib_cm_srvc_handle	*ib_cm_srvc_handle_t;
typedef	struct dapls_ib_hca_handle	*ib_hca_handle_t;
typedef	struct dapls_ib_cq_handle	*ib_cq_handle_t;
typedef	struct dapls_ib_qp_handle	*ib_qp_handle_t;
typedef	struct dapls_ib_pd_handle	*ib_pd_handle_t;
typedef	struct dapls_ib_mr_handle	*ib_mr_handle_t;
typedef	struct dapls_ib_mw_handle	*ib_mw_handle_t;
typedef	struct dapls_ib_srq_handle	*ib_srq_handle_t;
typedef	dapl_ib_async_event_t		ib_error_record_t;

typedef char				*IB_HCA_NAME;
typedef	char				ib_hca_name_t[256];
typedef	uint8_t				ib_hca_port_t;
typedef uint32_t			ib_uint32_t;
typedef	boolean_t			ib_bool_t;

typedef	ibt_cep_state_t			ib_qp_state_t;
typedef	ibt_wrc_opcode_t		ib_send_op_type_t;
typedef	ibt_cq_notify_flags_t		ib_notification_type_t;
typedef	ibt_async_handler_t		ib_async_handler_t;
typedef	ibt_cq_hdl_t			ib_comp_handle_t;
typedef	ibt_wr_ds_t			ib_data_segment_t;
typedef ibt_wc_t			ib_work_completion_t;

struct	tavor_hw_uar_s;
typedef	struct tavor_hw_uar_s		*dapls_hw_uar_t;

struct	tavor_hw_cqe_s;
typedef	struct tavor_hw_cqe_s		*dapls_hw_cqe_t;

/* Function prototypes */
extern	DAT_RETURN dapls_convert_error(int errnum, int retval);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_TAVOR_IBTI_H */
