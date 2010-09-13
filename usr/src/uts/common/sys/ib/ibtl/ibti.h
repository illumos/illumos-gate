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

#ifndef	_SYS_IB_IBTL_IBTI_H
#define	_SYS_IB_IBTL_IBTI_H

/*
 * ibti.h
 *
 * This file contains the IBTI prototypes and associated data structures.
 * It is the only header file that should be included by IBTI clients.
 */
#include <sys/ib/ibtl/ibti_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allocate channel flags.
 */
typedef enum ibt_chan_alloc_flags_e {
	IBT_ACHAN_NO_FLAGS		= 0,
	IBT_ACHAN_CLONE			= (1 << 0),
	IBT_ACHAN_USER_MAP		= (1 << 1),
	IBT_ACHAN_DEFER_ALLOC		= (1 << 2),
	IBT_ACHAN_USES_SRQ		= (1 << 3),
	IBT_ACHAN_USES_RSS		= (1 << 4),

	/* UD variants for FC support */
	IBT_ACHAN_USES_RFCI		= (1 << 5),	/* from RFCI pool */
	IBT_ACHAN_USES_FCMD		= (1 << 6),
	IBT_ACHAN_USES_FEXCH		= (1 << 7)	/* from FEXCH pool */
} ibt_chan_alloc_flags_t;


/*
 * Allocate RC channel ibt_alloc_rc_channel() argument.
 */
typedef struct ibt_rc_chan_alloc_args_s {
	ibt_attr_flags_t	rc_flags;	/* Signal type etc */
	ibt_cep_flags_t		rc_control;
	uint8_t			rc_hca_port_num;
	ibt_chan_sizes_t	rc_sizes;
	ibt_cq_hdl_t		rc_scq;	/* Send CQ */
	ibt_cq_hdl_t		rc_rcq;	/* Recv CQ */
	ibt_pd_hdl_t		rc_pd;	/* PD */
	ibt_channel_hdl_t	rc_clone_chan;	/* Optional Clone handle */
	ibt_srq_hdl_t		rc_srq;		/* Optional Shared Rcv Queue */
} ibt_rc_chan_alloc_args_t;

/*
 * RC channel query attributes structure.
 */
typedef struct ibt_rc_chan_query_attr_s {
	ib_guid_t		rc_hca_guid;	/* Local HCA GUID */
	ibt_cq_hdl_t		rc_scq;		/* SendCQ handle */
	ibt_cq_hdl_t		rc_rcq;		/* RecvCQ handle */
	ibt_pd_hdl_t		rc_pd;		/* PD Handle. */
	ibt_cep_state_t		rc_state;	/* Channel state */
	ib_mtu_t		rc_path_mtu;
	uint8_t			rc_path_retry_cnt:3;
	ibt_rnr_retry_cnt_t	rc_path_rnr_retry_cnt;
	ibt_rnr_nak_time_t	rc_min_rnr_nak;	/* min RNR-NAK timer */
	ibt_cep_path_t		rc_prim_path;
	ibt_cep_path_t		rc_alt_path;
	ibt_chan_sizes_t	rc_chan_sizes;	/* Queue/SGL sizes */
	uint8_t			rc_rdma_ra_out;	/* max RDMA-Reads/Atomics out */
	uint8_t			rc_rdma_ra_in;	/* max RDMA-Reads/Atomics in */
	ibt_attr_flags_t	rc_flags;	/* SQ Signaling Type etc */
	ibt_cep_flags_t		rc_control;	/* Control Flags */
	ibt_cep_cmstate_t	rc_mig_state;
	ib_qpn_t		rc_qpn;		/* Local QPN */
	ib_qpn_t		rc_dst_qpn;	/* Destination QPN */
	ibt_srq_hdl_t		rc_srq;		/* Optional Shared Rcv Queue */
} ibt_rc_chan_query_attr_t;

/*
 * RC Channel Modify Attributes definition.
 *
 * It is only possible to modify a channel that has previously been
 * opened. The channel must either be in operational state (IBT_STATE_RTS)
 * or paused (IBT_STATE_SQD). If channel is in paused state, then a modify
 * operation will unpause the channel.
 *
 * See the ibt_modify_rc_channel() for details of the required corresponding
 * modify flags.
 * Not specified attributes should be set to "NULL" or "0".
 */
typedef struct ibt_rc_chan_modify_attr_s {
	ibt_cep_flags_t		rc_control;	/* Channel Control Flags */
	uint_t			rc_sq_sz;	/* Set SQ Max outstanding WRs */
	uint_t			rc_rq_sz;	/* Set RQ Max outstanding WRs */

	ibt_adds_vect_t		rc_prim_adds_vect; /* Primary Path Address */
	ibt_adds_vect_t		rc_alt_adds_vect; /* Alternate Path Address */
	uint8_t			rc_path_retry_cnt:3;
	ibt_rnr_retry_cnt_t	rc_path_rnr_retry_cnt;
	ibt_rnr_nak_time_t	rc_min_rnr_nak;	/* min RNR-NAK timer */
	uint8_t			rc_prim_port_num; /* Port of Primary Path */
	uint8_t			rc_alt_port_num; /* Port of Alternate Path */
	uint8_t			rc_rdma_ra_out;	/* Initiator Depth, Number of */
						/* RDMA RD's & Atomics */
						/* outstanding. */
	uint8_t			rc_rdma_ra_in; /* Responder resources for */
						/* handling incoming RDMA rds */
						/* and Atomics. */
} ibt_rc_chan_modify_attr_t;

/*
 * UD remote destination query attributes
 */
typedef struct ibt_ud_dest_query_attr_s {
	ibt_hca_hdl_t		ud_hca_hdl;	/* Local HCA Handle */
	ib_qpn_t		ud_dst_qpn;	/* Destination QPN */
	ib_qkey_t		ud_qkey;	/* Q_Key */
	ibt_adds_vect_t 	ud_addr_vect;	/* Address Information */
	ibt_pd_hdl_t		ud_pd;
} ibt_ud_dest_query_attr_t;

/*
 * Allocate UD channel ibt_alloc_ud_channel() arguments; see below at
 * ibt_alloc_ud_channel() for a description of what's required and optional.
 */
typedef struct ibt_ud_chan_alloc_args_s {
	ibt_attr_flags_t	ud_flags;	/* Sig type etc */
	uint8_t			ud_hca_port_num;
	uint16_t		ud_pkey_ix;	/* P_Key Index */
	ibt_chan_sizes_t	ud_sizes;
	ib_qkey_t		ud_qkey;	/* Q_Key */
	ibt_cq_hdl_t		ud_scq;		/* Send CQ */
	ibt_cq_hdl_t		ud_rcq;		/* Recv CQ */
	ibt_pd_hdl_t		ud_pd;		/* PD */
	ibt_channel_hdl_t	ud_clone_chan;	/* Optional clone handle */
	ibt_srq_hdl_t		ud_srq;		/* Optional Shared Rcv Queue */
	ibt_rss_attr_t		ud_rss;
	ibt_fc_attr_t		ud_fc;
} ibt_ud_chan_alloc_args_t;

/*
 * UD channel query attributes.
 */
typedef struct ibt_ud_chan_query_attr_s {
	ib_qpn_t		ud_qpn;			/* QPN */
	ib_guid_t		ud_hca_guid;		/* Local HCA GUID */
	ibt_cq_hdl_t		ud_scq;			/* SendCQ handle. */
	ibt_cq_hdl_t		ud_rcq;			/* RecvCQ handle. */
	ibt_pd_hdl_t		ud_pd;			/* PD Handle. */
	uint8_t			ud_hca_port_num;	/* Local HCA port */
	ibt_cep_state_t		ud_state;		/* Channel state */
	uint16_t		ud_pkey_ix;		/* P_Key Index */
	ib_qkey_t		ud_qkey;		/* Q_Key */
	ibt_chan_sizes_t	ud_chan_sizes;		/* Queue/SGL sizes */
	ibt_attr_flags_t	ud_flags;		/* Signaling Type etc */
	ibt_srq_hdl_t		ud_srq;		/* Optional Shared Rcv Queue */
	ibt_rss_attr_t		ud_rss;
	ibt_fc_attr_t		ud_fc;
	ibt_fexch_query_attr_t	ud_query_fc;	/* query only set */
} ibt_ud_chan_query_attr_t;

/*
 * UD Channel Modify Attributes definition.
 *
 * It is only possible to modify a channel that is either in the operational
 * state (IBT_STATE_RTS) or paused (IBT_STATE_SQD). If channel is in paused
 * state, then a modify operation will unpause the channel.
 *
 * See the ibt_modify_ud_channel() for details of the required corresponding
 * modify flags.
 */
typedef struct ibt_ud_chan_modify_attr_s {
	uint_t			ud_sq_sz;	/* Set SQ Max outstanding WRs */
	uint_t			ud_rq_sz;	/* Set RQ Max outstanding WRs */
	ib_qkey_t		ud_qkey;	/* Set Q_Key */
	ibt_rss_attr_t		ud_rss;		/* Set RSS stuff */
	ibt_fc_attr_t		ud_fc;
} ibt_ud_chan_modify_attr_t;


/*
 * FUNCTION PROTOTYPES
 */

/*
 * CONNECTION ESTABLISHMENT/TEAR DOWN FUNCTIONS.
 */

/*
 * ibt_alloc_rc_channel
 * 	Allocates a RC communication channels that satisfy the specified
 *	channel attributes.
 */
ibt_status_t ibt_alloc_rc_channel(ibt_hca_hdl_t hca_hdl,
    ibt_chan_alloc_flags_t flags, ibt_rc_chan_alloc_args_t *args,
    ibt_channel_hdl_t *rc_chan_p, ibt_chan_sizes_t *sizes);

/*
 * ibt_flush_channel
 *	Flush the specified channel. Outstanding work requests are flushed
 *	so that the client can do the associated clean up. After that, the
 *	client will usually deregister the previously registered memory,
 *	then free the channel by calling ibt_free_channel().  RC channels
 *	that have been successfully opened will fail this call, as they
 *	need to instead be handled by ibt_close_rc_channel().
 */
ibt_status_t ibt_flush_channel(ibt_channel_hdl_t chan);

/*
 * ibt_free_channel
 *	Releases the resources associated with the specified channel
 */
ibt_status_t ibt_free_channel(ibt_channel_hdl_t chan);

/*
 * ibt_query_rc_channel
 *	Query an RC channel's attributes. Should only be called on an
 *	opened RC channel. If called on a channel before it is opened,
 *	some channel attributes may change when the channel is opened.
 */
ibt_status_t ibt_query_rc_channel(ibt_channel_hdl_t rc_chan,
    ibt_rc_chan_query_attr_t *chan_attrs);

/*
 * ibt_modify_rc_channel()
 * 	Modifies a previous opened operational or paused RC channel's
 *	attributes.
 *
 * NOTE:
 *	It is only possible to modify a channel that has previously been opened.
 *	The channel must either be in operational state (IBT_STATE_RTS) or
 *	paused (IBT_STATE_SQD). If channel is in paused state, then a modify
 *	operation will will unpause the channel.
 */
ibt_status_t ibt_modify_rc_channel(ibt_channel_hdl_t rc_chan,
    ibt_cep_modify_flags_t flags, ibt_rc_chan_modify_attr_t *attrs,
    ibt_queue_sizes_t *actual_sz);

/*
 * ibt_alloc_ud_channel
 *	Allocate UD channels that satisfy the specified channel attributes.
 */
ibt_status_t ibt_alloc_ud_channel(ibt_hca_hdl_t hca_hdl,
    ibt_chan_alloc_flags_t flags, ibt_ud_chan_alloc_args_t *args,
    ibt_channel_hdl_t *ud_chan_p, ibt_chan_sizes_t *sizes);

/*
 * ibt_alloc_ud_channel_range
 *	Allocate a range of UD channels that have consecutive QPNs for RSS.
 */
ibt_status_t ibt_alloc_ud_channel_range(ibt_hca_hdl_t hca_hdl,
    uint_t log2, ibt_chan_alloc_flags_t flags,
    ibt_ud_chan_alloc_args_t *args, ibt_cq_hdl_t *send_cq_p,
    ibt_cq_hdl_t *recv_cq_p, ib_qpn_t *base_qpn_p,
    ibt_channel_hdl_t *ud_chan_p, ibt_chan_sizes_t *sizes);

/*
 * ibt_query_ud_channel
 *	Query a UD channel's attributes.
 */
ibt_status_t ibt_query_ud_channel(ibt_channel_hdl_t ud_chan,
    ibt_ud_chan_query_attr_t *ud_chan_attrs);

/*
 * ibt_modify_ud_channel()
 * 	Modifies an UD channel's attributes, as specified by a
 *	ibt_cep_modify_flags_t parameter to those specified in the
 *	ibt_ud_chan_modify_attr_t structure.
 *
 * NOTE:
 *	It is only possible to modify a channel that is either in the
 *	operational state (IBT_STATE_RTS) or paused (IBT_STATE_SQD). If
 *	channel is in paused state, then a modify operation will unpause the
 *	channel.
 */
ibt_status_t ibt_modify_ud_channel(ibt_channel_hdl_t ud_chan,
    ibt_cep_modify_flags_t flags, ibt_ud_chan_modify_attr_t *attrs,
    ibt_queue_sizes_t *actual_sz);

/*
 * ibt_recover_ud_channel()
 *	Recover an UD Channel which has transitioned to SQ Error state. The
 *	ibt_recover_ud_channel() transitions the channel from SQ Error state
 *	to Ready-To-Send channel state.
 *
 *	If a work request posted to a UD channel's send queue completes with
 *	an error (see ibt_wc_status_t), the channel gets transitioned to SQ
 *	Error state. In order to reuse this channel, ibt_recover_ud_channel()
 *	can be used to recover the channel to a usable (Ready-to-Send) state.
 */
ibt_status_t ibt_recover_ud_channel(ibt_channel_hdl_t ud_chan);


/*
 * ibt_alloc_ud_dest
 *	Allocate a UD destination handle.  This allocates local resources
 *	that will need subsequent modification/initialization before use
 *	(in send work requests).  Functions that can be used to do this are
 *	ibt_modify_ud_dest (data supplied by caller), ibt_modify_reply_ud_dest
 *	(data supplied from a successfully completed receive work request),
 *	and ibt_request_ud_dest (data retrieved using SIDR protocol).
 */
ibt_status_t ibt_alloc_ud_dest(ibt_hca_hdl_t hca_hdl,
    ibt_ud_dest_flags_t flags, ibt_pd_hdl_t pd, ibt_ud_dest_hdl_t *ud_dest_p);

/*
 * ibt_modify_ud_dest
 *	Modify a previously allocated UD destination handle from the
 *	argument data.  After the ud_dest has already been made usable,
 *	the adds_vect argument to this function is optional (NULL).
 */
ibt_status_t ibt_modify_ud_dest(ibt_ud_dest_hdl_t ud_dest, ib_qkey_t qkey,
    ib_qpn_t dest_qpn, ibt_adds_vect_t *adds_vect);

/*
 * ibt_modify_reply_ud_dest
 *	Modify a previously allocated UD destination handle, so that it
 *	can be used to reply to the sender of the datagram contained in the
 *	specified work request completion.
 */
ibt_status_t ibt_modify_reply_ud_dest(ibt_channel_hdl_t ud_chan,
    ibt_ud_dest_hdl_t ud_dest, ib_qkey_t qkey, ibt_wc_t *wc,
    ib_vaddr_t recv_buf);

/*
 * ibt_request_ud_dest
 *	Modify a previously allocated UD destination handle based on the
 *	data retrieved by making an SIDR request.
 */
ibt_status_t ibt_request_ud_dest(ibt_ud_dest_hdl_t ud_dest,
    ibt_execution_mode_t mode, ibt_ud_dest_attr_t *dest_attrs,
    ibt_ud_returns_t *ud_ret_args);

/*
 * ibt_free_ud_dest
 *	Releases the resources associated with the specified UD destination
 *	handle.
 */
ibt_status_t ibt_free_ud_dest(ibt_ud_dest_hdl_t ud_dest);

/*
 * ibt_query_ud_dest
 *	Query a UD destination's attributes.
 */
ibt_status_t ibt_query_ud_dest(ibt_ud_dest_hdl_t ud_dest,
    ibt_ud_dest_query_attr_t *dest_attrs);


/*
 * ibt_is_privileged_ud_dest
 *	Determine if a UD destination Handle is a privileged handle.
 */
boolean_t ibt_is_privileged_ud_dest(ibt_ud_dest_hdl_t ud_dest);


/*
 * ibt_update_channel_qkey
 *
 * ibt_update_channel_qkey() set's the Qkey in the specified channel context
 * to the Qkey in the specified destination handle. This function can be used
 * to enable sends to a privileged destination. All posted Send Work Requests
 * that contain a privileged destination handle now use the Qkey in the
 * channel context.
 *
 * ibt_update_channel_qkey() can also be used to enable the caller to receive
 * from the specified remote destination on the specified channel.
 *
 */
ibt_status_t ibt_update_channel_qkey(ibt_channel_hdl_t ud_chan,
    ibt_ud_dest_hdl_t ud_dest);


/*
 * ibt_set_chan_private()
 * ibt_get_chan_private()
 * 	Set/get a pointer to client private data.
 *	Applicable for both RC and UD channels.
 */
void ibt_set_chan_private(ibt_channel_hdl_t chan, void *clnt_private);

void *ibt_get_chan_private(ibt_channel_hdl_t chan);

/*
 * ibt_channel_to_hca_guid()
 *
 *	A helper function to retrieve HCA GUID for the specified Channel.
 */
ib_guid_t ibt_channel_to_hca_guid(ibt_channel_hdl_t chan);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBTI_H */
