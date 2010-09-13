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

#ifndef	_SYS_IB_IBTL_IBTL_CI_TYPES_H
#define	_SYS_IB_IBTL_IBTL_CI_TYPES_H

/*
 * ibtl_ci_types.h
 * Definitions shared between the IBTL and CI interface.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef	struct ibc_cq_s		*ibt_opaque1_t;
typedef	struct ibc_srq_s	*ibt_opaque2_t;
typedef	struct ibc_rdd_s	*ibt_rdd_hdl_t;	/* ibt_alloc_eec() */


/*
 * Channel Modify flags - ibt_cep_modify_flags_t
 *
 *    Note:
 *	That the IBT_CEP_SET_RESET_INIT, IBT_CEP_SET_INIT_RTR
 *	IBT_CEP_SET_RTR_RTS flags are mutually exclusive. However if one of the
 *	optional attributes associated with these flags is to be modified then
 *	the corresponding modify flag must also be specified. For example if
 *	a client wishes to transit from the INIT to RTR state but additionally
 *	they want to disable atomics, then the modify flags should be:
 *
 *	(IBT_CEP_SET_INIT_RTR | IBT_CEP_SET_ATOMIC)
 *
 *	And the following attributes specified:
 *
 *		- Number of responder resources for RDMA read/atomic ops.
 *		- Primary Path Address Vector Information.
 *		- Destination QPN.
 *		- PSN for ReceiveQ.
 *		- Minimum RNR NAK Timer field value.
 *		- ibt_cep_flags_t set to IBT_CEP_ATOMIC
 *
 */
#define	IBT_CEP_SET_RESET_INIT		IBT_CEP_SET_OPAQUE1
#define	IBT_CEP_SET_INIT_RTR		IBT_CEP_SET_OPAQUE2
#define	IBT_CEP_SET_RTR_RTS		IBT_CEP_SET_OPAQUE3

#define	IBT_CEP_SET_STATE		IBT_CEP_SET_OPAQUE4
#define	IBT_CEP_SET_MTU			IBT_CEP_SET_OPAQUE5

#define	IBT_CEP_SET_TIMEOUT		IBT_CEP_SET_OPAQUE6
#define	IBT_CEP_SET_PKEY_IX		IBT_CEP_SET_OPAQUE7
#define	IBT_CEP_SET_MIG			IBT_CEP_SET_OPAQUE8

/*
 * ibt_async_code_t
 */
#define	IBT_EVENT_PATH_MIGRATED_QP	IBT_EVENT_PATH_MIGRATED
#define	IBT_EVENT_COM_EST_QP		IBT_EVENT_COM_EST
#define	IBT_EVENT_COM_EST_EEC		IBT_ASYNC_OPAQUE2
#define	IBT_ERROR_CATASTROPHIC_QP	IBT_ERROR_CATASTROPHIC_CHAN
#define	IBT_ERROR_INVALID_REQUEST_QP	IBT_ERROR_INVALID_REQUEST_CHAN
#define	IBT_ERROR_ACCESS_VIOLATION_QP	IBT_ERROR_ACCESS_VIOLATION_CHAN
#define	IBT_ERROR_PATH_MIGRATE_REQ_QP	IBT_ERROR_PATH_MIGRATE_REQ
#define	IBT_EVENT_EMPTY_QP		IBT_EVENT_EMPTY_CHAN


/*
 * ibt_adds_vect_t
 */
#define	av_send_grh	av_opaque1	/* flag to specify if GRH is there */
#define	av_dlid		av_opaque2	/* destination LID, or router LID */
#define	av_src_path	av_opaque3	/* Source path bits */
#define	av_sgid_ix	av_opaque4

/*
 * ibt_wc_t
 */
#define	wc_slid		wc_opaque1	/* source LID */
#define	wc_pkey_ix	wc_opaque2	/* The P_Key index, GSI only */
#define	wc_path_bits	wc_opaque4	/* DLID path bits, UD's, RawIPv6 & */
					/* RawEthr only */

/*
 * ibt_mcg_attr_t
 */
#define	mc_mlid		mc_opaque1	/* Multicast LID */

/*
 * ibt_mcg_info_t
 */
#define	mc_pkt_lt	mc_opaque2

/*
 * ibt_hca_flags_t
 */
#define	IBT_HCA_RESIZE_QP	IBT_HCA_RESIZE_CHAN

/*
 * ibt_object_type_t
 */
#define	IBT_HDL_QP	IBT_HDL_CHANNEL
#define	IBT_HDL_AH	IBT_HDL_UD_DEST

/*
 * ibt_hca_attr_t
 */
#define	hca_max_ah	hca_max_ud_dest	/* Max address handles in HCA */
#define	hca_ah_max_ci_priv_sz	hca_ud_dest_max_ci_priv_sz
#define	hca_qp_max_ci_priv_sz	hca_chan_max_ci_priv_sz
#define	hca_max_qp	hca_max_chans	/* Max Channels supported by the HCA */
#define	hca_max_qp_sz	hca_max_chan_sz	/* Max outstanding WRs on any channel */
#define	hca_max_rdma_out_qp	hca_max_rdma_out_chan
#define	hca_max_rdma_in_qp	hca_max_rdma_in_chan
#define	hca_max_mcg_qps		hca_max_mcg_chans
#define	hca_max_qp_per_mcg	hca_max_chan_per_mcg

/*
 * ibt_hca_portinfo_t
 */
#define	p_base_lid	p_opaque1	/* Base LID of the port */


/* Mapping of Verbs defined return status to channel specific. */
#define	IBT_QP_FULL			IBT_CHAN_FULL
#define	IBT_QP_HDL_INVALID		IBT_CHAN_HDL_INVALID
#define	IBT_QP_ATTR_RO			IBT_CHAN_ATTR_RO
#define	IBT_QP_STATE_INVALID		IBT_CHAN_STATE_INVALID
#define	IBT_QP_SRV_TYPE_INVALID		IBT_CHAN_SRV_TYPE_INVALID
#define	IBT_QP_IN_USE			IBT_CHAN_IN_USE
#define	IBT_QP_ATOMICS_NOT_SUPPORTED	IBT_CHAN_ATOMICS_NOT_SUPPORTED
#define	IBT_QP_OP_TYPE_INVALID		IBT_CHAN_OP_TYPE_INVALID
#define	IBT_QP_SGL_FORMAT_INVALID	IBT_CHAN_SGL_FORMAT_INVALID
#define	IBT_QP_SGL_LEN_INVALID		IBT_CHAN_SGL_LEN_INVALID
#define	IBT_QP_APM_STATE_INVALID	IBT_CHAN_APM_STATE_INVALID
#define	IBT_QP_SZ_INSUFFICIENT		IBT_CHAN_SZ_INSUFFICIENT
#define	IBT_QP_SPECIAL_TYPE_INVALID	IBT_CHAN_SPECIAL_TYPE_INVALID
#define	IBT_WC_LOCAL_QP_OP_ERR		IBT_WC_LOCAL_CHAN_OP_ERR
#define	IBT_AH_HDL_INVALID		IBT_UD_DEST_HDL_INVALID
#define	IBT_HCA_MCG_QP_EXCEEDED		IBT_HCA_MCG_CHAN_EXCEEDED
#define	IBT_MC_MLID_INVALID		IBT_MC_OPAQUE
#define	IBT_QP_SRQ			IBT_CHAN_SRQ
#define	IBT_QP_TYPE_2A_MW_BOUND		IBT_CHAN_TYPE_2A_MW_BOUND
#define	IBT_QP_WQE_SZ_INSUFF		IBT_CHAN_WQE_SZ_INSUFF


/*
 * ibt_cep_path_t
 */
#define	cep_timeout	cep_cm_opaque1	/* 6 bits of timeout exponent */
					/* Local ACK timeout for RC */

/*
 * Define an ibt UD Destination struct. This holds all the information
 * needed to reach a UD destination.
 *
 * The ibt_ud_dest_s struct is known by the CI and IBTL.  This structure is
 * referenced by the CI during UD work request processing.  It is defined here
 * here so that IBTL does not need to do any data copying during ibt_post_send.
 */
typedef struct ibt_ud_dest_s {
	ibt_ah_hdl_t		ud_ah;		/* Address handle */
	ib_qpn_t		ud_dst_qpn;	/* Destination QPN */
	ib_qkey_t		ud_qkey;	/* Q_Key */

	/* The following fields are IBTL-only, i.e., opaque to the CI */
	struct ibtl_hca_s	*ud_dest_opaque1;
} ibt_ud_dest_t;

/*
 * Reserved For Future Use
 * RD destination address info.
 */
typedef struct ibt_rd_dest_s {
	ibt_ah_hdl_t	rd_ah;		/* Address handle */
	ib_eecn_t	rd_eecn;	/* Local EEC Number */
	ib_qpn_t	rd_dst_qpn;	/* Destination QP Number */
	ib_qkey_t	rd_dst_qkey;	/* The Q_Key for the destination QP */
} ibt_rd_dest_t;

/*
 * QP Type.
 */
typedef enum ibt_qp_type_e {
	IBT_RC_RQP	= 0,
	IBT_RD_RQP	= 1,	/* Reserved For Future Use */
	IBT_UC_RQP	= 2,	/* Reserved For Future Use */
	IBT_UD_RQP	= 3
} ibt_qp_type_t;

/*
 * Special QP Type.
 */
typedef enum ibt_sqp_type_e {
	IBT_SMI_SQP		= 0,
	IBT_GSI_SQP		= 1,
	IBT_RAWIP_SQP		= 2,	/* Reserved For Future Use */
	IBT_RAWETHER_SQP	= 3	/* Reserved For Future Use */
} ibt_sqp_type_t;

/*
 * QP alloc flags.
 */
typedef enum ibt_qp_alloc_flags_e {
	IBT_QP_NO_FLAGS		= 0,
	IBT_QP_USER_MAP		= (1 << 0),
	IBT_QP_DEFER_ALLOC	= (1 << 1),
	IBT_QP_USES_SRQ		= (1 << 2),
	IBT_QP_USES_RSS		= (1 << 3),

	/* FC variants of UD */
	IBT_QP_USES_RFCI	= (1 << 4),
	IBT_QP_USES_FCMD	= (1 << 5),
	IBT_QP_USES_FEXCH	= (1 << 6)
} ibt_qp_alloc_flags_t;

/*
 * QP Alloc Attributes definition.
 *
 * Contains the QP attributes that are required to create a QP.
 */
typedef struct ibt_qp_alloc_attr_s {
	ibt_qp_alloc_flags_t	qp_alloc_flags;
	ibt_cq_hdl_t		qp_scq_hdl;	/* SQ CQ IBT Hdl */
	ibt_cq_hdl_t		qp_rcq_hdl;	/* RQ CQ IBT Hdl */
	ibt_rdd_hdl_t		qp_rdd_hdl;	/* Reserved */
	ibt_pd_hdl_t		qp_pd_hdl;	/* PD handle. */
	ibt_chan_sizes_t	qp_sizes;	/* Queue and SGL */
	ibt_attr_flags_t	qp_flags;	/* SQ Signaling Type etc */
	ibt_opaque1_t		qp_opaque1;
	ibt_opaque1_t		qp_opaque2;
	ibt_srq_hdl_t		qp_srq_hdl;	/* SRQ ibt hdl */
	ibt_opaque2_t		qp_opaque3;
	ibt_fc_attr_t		qp_fc;
} ibt_qp_alloc_attr_t;


/*
 * QP query info
 */
/* RC transport specific */
typedef struct ibt_qp_rc_attr_s {
	uint32_t		rc_sq_psn:24;	/* SQ PSN */
	uint32_t		rc_rq_psn:24;	/* RQ PSN */
	ib_qpn_t		rc_dst_qpn;	/* Destination QPN */
	ibt_cep_cmstate_t	rc_mig_state;	/* Channel Migration State */
	ibt_rnr_retry_cnt_t	rc_rnr_retry_cnt;
	uint8_t			rc_retry_cnt:3;
	uint8_t			rc_rdma_ra_out;	/* max RDMA-R/Atomic sent */
						/* Number of RDMA RD's & */
						/* Atomics outstanding */
	uint8_t			rc_rdma_ra_in;	/* Incoming RDMA-R/Atomic */
						/* Responder resources for */
						/* handling incoming RDMA */
						/* RD's & Atomics */
	ibt_rnr_nak_time_t	rc_min_rnr_nak;	/* min RNR-NAK timer */
	ib_mtu_t		rc_path_mtu;
	ibt_cep_path_t		rc_path;	/* primary path */
	ibt_cep_path_t		rc_alt_path;	/* alternate path */
} ibt_qp_rc_attr_t;

/*
 * Reserved For Future Use.
 * UC transport specific
 */
typedef struct ibt_qp_uc_attr_s {
	uint32_t		uc_sq_psn:24;	/* SQ PSN */
	uint32_t		uc_rq_psn:24;	/* RQ PSN */
	ib_qpn_t		uc_dst_qpn;	/* destination QPN */
	ibt_cep_cmstate_t	uc_mig_state;	/* Channel Migration State */
	ib_mtu_t		uc_path_mtu;
	ibt_cep_path_t		uc_path;	/* primary path */
	ibt_cep_path_t		uc_alt_path;	/* alternate path */
} ibt_qp_uc_attr_t;

/*
 * Reserved For Future Use.
 * RD transport specific
 */
typedef struct ibt_qp_rd_attr_s {
	ib_qkey_t		rd_qkey;
	ibt_rnr_nak_time_t	rd_min_rnr_nak;	/* min RNR-NAK timer */
} ibt_qp_rd_attr_t;

/* UD transport specific */
typedef struct ibt_qp_ud_attr_s {
	ib_qkey_t	ud_qkey;	/* Q_Key */
	uint32_t	ud_sq_psn:24;	/* SQ PSN */
	uint16_t	ud_pkey_ix;	/* P_Key Index */
	uint8_t		ud_port;	/* port */
	ibt_rss_attr_t	ud_rss;		/* RSS stuff */
	ibt_fc_attr_t	ud_fc;
} ibt_qp_ud_attr_t;

/*
 * Common QP Info
 */
typedef struct ibt_qp_info_s {
	uint_t			qp_sq_sz;	/* SQ WQEs */
	uint_t			qp_rq_sz;	/* RQ WQEs */
	ibt_cep_state_t		qp_state;	/* QP state */
	ibt_cep_state_t		qp_current_state; /* current state for */
						/* modify_qp to RTS state */
	ibt_cep_flags_t		qp_flags;	/* QP flags */
	ibt_tran_srv_t		qp_trans;	/* transport service type */
	union {					/* transport specific */
		ibt_qp_rc_attr_t	rc;
		ibt_qp_rd_attr_t	rd;	/* Reserved For Future Use */
		ibt_qp_uc_attr_t	uc;	/* Reserved For Future Use */
		ibt_qp_ud_attr_t	ud;
	} qp_transport;
} ibt_qp_info_t;

/*
 * QP Query Attributes definition.
 */
typedef struct ibt_qp_query_attr_s {
	ibt_cq_hdl_t		qp_sq_cq;	/* SQ CQ */
	ibt_cq_hdl_t		qp_rq_cq;	/* RQ CQ */
	ibt_rdd_hdl_t		qp_rdd_hdl;	/* Reserved */
	ib_qpn_t		qp_qpn;		/* QPN */
	uint_t			qp_sq_sgl;	/* max SQ SGL */
	uint_t			qp_rq_sgl;	/* max RQ SGL */
	ibt_qp_info_t		qp_info;	/* Modifiable attributes */
	ibt_srq_hdl_t		qp_srq;		/* SRQ hdl or NULL */
	ibt_attr_flags_t	qp_flags;
	ibt_fexch_query_attr_t	qp_query_fexch;	/* FEXCH query only set */
} ibt_qp_query_attr_t;


/*
 * Reserved For Future Use.
 * EEC Info.
 */
typedef struct ibt_eec_info_s {
	uint32_t		eec_sq_psn:24;	/* SQ PSN */
	uint32_t		eec_rq_psn:24;	/* RQ PSN */
	ib_eecn_t		eec_dst_eecn;	/* destination EECN */
	ibt_cep_state_t		eec_state;	/* EEC state */
	ibt_cep_cmstate_t	eec_mig;	/* channel migration state */
	uint8_t			eec_rdma_ra_out;	/* RDMA-R/Atomics out */
	uint8_t			eec_rdma_ra_in;		/* RDMA-R/Atomics in */
	uint8_t			eec_retry_cnt:3;
	ibt_rnr_retry_cnt_t	eec_rnr_retry_cnt;
	ib_mtu_t		eec_path_mtu;
	ibt_cep_path_t		eec_prim_path;	/* primary path */
	ibt_cep_path_t		eec_alt_path;	/* alternate path */
} ibt_eec_info_t;

/*
 * Reserved For Future Use.
 * EEC Query Attributes definition.
 */
typedef struct ibt_eec_query_attr_s {
	ib_eecn_t		eec_eecn;	/* The EEC Number */
	ibt_rdd_hdl_t		eec_rdd_hdl;
	ibt_eec_info_t		eec_info;	/* Modifiable attributes */
} ibt_eec_query_attr_t;


#define	ibt_ah_flags_t	ibt_ud_dest_flags_t
#define	IBT_AH_NO_FLAGS		IBT_UD_DEST_NO_FLAGS
#define	IBT_AH_USER_MAP		IBT_UD_DEST_USER_MAP
#define	IBT_AH_DEFER_ALLOC	IBT_UD_DEST_DEFER_ALLOC


/*
 * ibt_hca_attr_t
 */
#define	hca_max_rdd		hca_opaque2	/* Max RDDs in HCA */
#define	hca_max_eec		hca_opaque3	/* Max EEContexts in HCA */
#define	hca_max_rd_sgl		hca_opaque4	/* Max SGL entries per RD WR */
#define	hca_max_rdma_in_ee	hca_opaque5	/* Max RDMA Reads/Atomics in */
						/* per EEC with HCA as target */
#define	hca_max_rdma_out_ee	hca_opaque6	/* Max RDMA Reads/Atomics out */
						/* per EE by this HCA */
#define	hca_max_ipv6_qp		hca_max_ipv6_chan
#define	hca_max_ether_qp	hca_max_ether_chan
#define	hca_eec_max_ci_priv_sz	hca_opaque7
#define	hca_rdd_max_ci_priv_sz	hca_opaque8
#define	hca_max_map_per_fmr	hca_opaque9

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_IBTL_IBTL_CI_TYPES_H */
