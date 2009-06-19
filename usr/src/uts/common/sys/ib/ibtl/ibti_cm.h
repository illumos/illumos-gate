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

#ifndef	_SYS_IB_IBTL_IBTI_CM_H
#define	_SYS_IB_IBTL_IBTI_CM_H

/*
 * ibti_cm.h
 *
 * This file contains the data structure definitions for the IBTI
 * communication manager (CM). It is only included in ibti.h
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Defines.
 */
#define	IBT_MAX_PRIV_DATA_SZ		224
#define	IBT_DREP_PRIV_DATA_SZ		224
#define	IBT_RTU_PRIV_DATA_SZ		224
#define	IBT_MRA_PRIV_DATA_SZ		222
#define	IBT_DREQ_PRIV_DATA_SZ		220
#define	IBT_REP_PRIV_DATA_SZ		196
#define	IBT_LAP_PRIV_DATA_SZ		168
#define	IBT_APR_PRIV_DATA_SZ		148
#define	IBT_REJ_PRIV_DATA_SZ		148
#define	IBT_REQ_PRIV_DATA_SZ		92
#define	IBT_SIDR_REQ_PRIV_DATA_SZ	216
#define	IBT_SIDR_REP_PRIV_DATA_SZ	136
#define	IBT_IP_HDR_PRIV_DATA_SZ		36

#define	IBT_CM_ADDL_REJ_LEN	72	/* Additional Rej Info len */
					/* This is the max consumer addl */
					/* reject info len */
#define	IBT_CM_SIDR_CP_LEN	72	/* SIDR REP Class Port Info len */
#define	IBT_CM_APR_ADDL_LEN	72	/* Additional Info len in APR message */

typedef	uint8_t	ibt_priv_data_len_t;

/*
 * CM channel handler reject reasons.
 *
 * Refer to InfiniBand Architecture Release Volume 1 Rev 1.0a:
 * Section 12.6.7.2 Rejection Reason, and RDMA IP CM Service Annex
 *
 * Note:
 *	When a REJ happens for an RDMA-aware ULP, a consumer reject code
 *	indicating an IP CM Service reject or a RDMA-Aware ULP reject can
 *	be returned. In the IBTA spec both use the consumer reject code, but
 *	are distinguished by the REJ layer byte (table 3 of the annex 11).
 *	The IBTF CM can thus tell what type of reject has been returned. When
 *	a RDMA ULP issues a consumer REJ to an RDMA REQ then the CM will
 *	return an IBT_CM_CONSUMER ibt_cm_reason_t. The ARI data is returned
 *	in an ibt_ari_con_t struct accessed by the 'ari_consumer' member of
 *	the ibt_arej_info_t. However the consumer reject data begins at
 *	'ari_consumer.rej_ari[1]', and is of length
 *	'ari_consumer.rej_ari_len - 1' (the first byte is the REJ layer byte),
 *	where as for a non RDMA-aware ULP consumer REJ, the ARI data begins
 *	at 'ari_consumer.rej_ari[0]' and is of length 'ari_consumer.rej_ari_len'
 *
 *	If an RDMA-aware ULP REQ is rejected by the IP CM Service layer, the
 *	CM will return the new IBT_CM_RDMA_IP ibt_cm_reason_t, and the
 *	private data is returned in an ibt_ari_ip_t struct accessed via the
 *	'ari_ip' member of the ibt_arej_info_t struct.
 *
 *	If an RDMA IP CM REQ is sent to a non RDMA-aware ULP consumer, then
 *	the REQ is Rejected with an IBT_CM_INVALID_SID ibt_cm_reason_t.
 */
typedef enum ibt_cm_reason_e {
	IBT_CM_SUCCESS		= 0,	/* Success */
	IBT_CM_NO_CHAN		= 1,	/* Remote unable to allocate a CHAN */
	IBT_CM_NO_EEC		= 2,	/* Remote unable to allocate an EEC */
	IBT_CM_NO_RESC		= 3,	/* Remote unable to allocate resource */
	IBT_CM_TIMEOUT		= 4,	/* CM protocol timed out waiting for */
					/* a msg */
	IBT_CM_NOT_SUPPORTED 	= 5,	/* Request not supported */
	IBT_CM_INVALID_CID 	= 6,	/* Local CID or Remote CID invalid */
	IBT_CM_INVALID_COMM_INS	= 7,	/* Local CID, Remote CID, Channel */
					/* does not refer to a valid */
					/* communication Instance. */
	IBT_CM_INVALID_SID 	= 8,	/* Service not supported or not */
					/* recognized */
	IBT_CM_INVALID_SRV_TYPE	= 9,	/* Invalid transport service type */
	IBT_CM_CONN_STALE 	= 10,	/* Stale connection */
	IBT_CM_INVALID_RDC 	= 11,	/* RDC does not exist */
	IBT_CM_PRIM_GID 	= 12,	/* Primary remote port gid rejected. */
	IBT_CM_PRIM_LID 	= 13,	/* Primary remote port lid rejected. */
	IBT_CM_INVALID_PRIM_SL 	= 14,	/* Primary Requested SL not supported */
	IBT_CM_INVALID_PRIM_TC 	= 15,	/* Primary Requested traffic class */
					/* not supported */
	IBT_CM_INVALID_PRIM_HOP	= 16,	/* Primary Requested hop limit not */
					/* accepted */
	IBT_CM_INVALID_PRIM_RATE = 17,	/* Primary Packet rate not accepted */
	IBT_CM_ALT_GID 		= 18,	/* Alternate remote port gid rejected */
	IBT_CM_ALT_LID 		= 19,	/* Alternate remote port lid rejected */
	IBT_CM_INVALID_ALT_SL 	= 20,	/* Alternate Requested SL not */
					/* supported */
	IBT_CM_INVALID_ALT_TC 	= 21,	/* Alternate Requested traffic class */
					/* not supported */
	IBT_CM_INVALID_ALT_HOP 	= 22,	/* Alternate Requested hop limit */
					/* accepted */
	IBT_CM_INVALID_ALT_RATE = 23,	/* Alternate Packet rate not accepted */
	IBT_CM_REDIRECT_CM 	= 24,	/* Port & CM redirected */
	IBT_CM_PORT_REDIRECT 	= 25,	/* Port redirected */
	IBT_CM_INVALID_MTU 	= 26,	/* Path MTU not supported */
	IBT_CM_INSUFF_RESOURCE	= 27,	/* Insufficient responder resources */
	IBT_CM_CONSUMER 	= 28,	/* Consumer rejected connection */
	IBT_CM_RNR_RETRY_CNT_REJ = 29,	/* RNR NAK retry count rejected */
	IBT_CM_DUP_COM_ID	= 30,	/* Local CID in REQ is duplicated */
	IBT_CM_CLASS_NO_SUPPORT	= 31,	/* Class version not supported */
	IBT_CM_INVALID_PRIM_FLOW = 32,	/* Invalid primary flow label */
	IBT_CM_INVALID_ALT_FLOW = 33,	/* Invalid alternate flow label */
	IBT_CM_DUP_CONN_REQ	= 1000, /* Duplicate connection request */
	IBT_CM_ABORT		= 1001,	/* Connection aborted */
	IBT_CM_CI_FAILURE	= 1002,	/* A call to CI failed, could be */
					/* query/modify channel */
	IBT_CM_CHAN_INVALID_STATE = 1003, /* Passive's QP is not in Init */
					/* state */
	IBT_CM_RDMA_IP		= 1004 /* RDMA IP CM reject */
} ibt_cm_reason_t;

/*
 * CM flags.
 */
typedef uint8_t ibt_cm_flags_t;

#define	IBT_CM_NO_FLAGS		0x0
#define	IBT_CM_FLOW_CONTROL	0x1
#define	IBT_CM_SRQ_EXISTS	0x2


/*
 * The CM Handler function return values.
 */
typedef enum ibt_cm_status_e {
	IBT_CM_ACCEPT		= 0,
	IBT_CM_REJECT		= 1,
	IBT_CM_REDIRECT_PORT	= 2,	/* Redirect port */
	IBT_CM_REDIRECT		= 3,	/* Redirect port and CM */
	IBT_CM_NO_CHANNEL	= 4,	/* Unable to allocate a channel */
	IBT_CM_NO_RESOURCE	= 5,	/* Unable to allocate a resource */
	IBT_CM_DEFAULT		= 6,	/* Do the default action */
	IBT_CM_DEFER		= 7	/* Can't complete processing now */
} ibt_cm_status_t;			/* will call ibt_cm_proceed() */
					/* later */

/*
 * SIDR_REP status type
 */
typedef enum ibt_sidr_status_e {
	IBT_CM_SREP_CHAN_VALID	= 0,
	IBT_CM_SREP_SID_INVALID	= 1,	/* Service ID not supported */
	IBT_CM_SREP_REJ		= 2,	/* Service provider reject */
	IBT_CM_SREP_NO_CHAN	= 3,	/* No channel available */
	IBT_CM_SREP_REDIRECT	= 4,	/* Redirect request */
	IBT_CM_SREP_CL_INVALID	= 5,	/* Class Version is invalid */
	IBT_CM_SREP_TIMEOUT	= 1000	/* No SIDR_REP received */
} ibt_sidr_status_t;

/*
 * Alternate path status type
 * The implementation defined status codes begin from 20. The status codes
 * below 20 are based on apr_status in the APR mad.
 */
typedef enum ibt_ap_status_e {
	IBT_CM_AP_LOADED	= 0,	/* AP loaded successfully */
	IBT_CM_AP_INVALID_COMMID = 1,	/* Invalid communication instance */
	IBT_CM_AP_NOT_SUPPORTED	= 2,	/* Alternate paths not supported */
	IBT_CM_AP_REJECT	= 3,	/* Failover port rejected */
	IBT_CM_AP_REDIRECT	= 4,	/* Reject - redirect */
	IBT_CM_AP_MATCH_PRIM	= 5,	/* AP matches primary path */
	IBT_CM_AP_QPNEECN_INVALID = 6,	/* AP QPN/EECN does not match */
	IBT_CM_AP_RLID_REJECTED	= 7,	/* AP remote port lid rejected */
	IBT_CM_AP_RGID_REJECTED	= 8,	/* AP remote port gid rejected */
	IBT_CM_AP_FLOW_REJECTED	= 9,	/* AP flow label rejected */
	IBT_CM_AP_TCLASS_REJECTED = 10,	/* AP traffic class rejected */
	IBT_CM_AP_HOP_REJECTED	= 11,	/* AP hop limit rejected */
	IBT_CM_AP_RATE_REJECTED	= 12,	/* AP static packet rate rejected */
	IBT_CM_AP_SL_REJECTED	= 13,	/* AP service level rejected */
	IBT_CM_AP_TIMEOUT	= 1000,	/* LAP timed out */
	IBT_CM_AP_ABORT		= 1001	/* ibt_set_alternate_path returned */
					/* earlier because of connection */
					/* getting closed */
} ibt_ap_status_t;

/*
 * Communication event types.
 */
typedef enum ibt_cm_event_type_e {
	IBT_CM_EVENT_REQ_RCV	= 0x1,
	IBT_CM_EVENT_REP_RCV,
	IBT_CM_EVENT_MRA_RCV,
	IBT_CM_EVENT_LAP_RCV,
	IBT_CM_EVENT_APR_RCV,
	IBT_CM_EVENT_CONN_EST,		/* RTU has been sent/recvd and it is */
					/* OK to use the connection */
	IBT_CM_EVENT_CONN_CLOSED,	/* Connection has been closed and it */
					/* is OK to free resources associated */
					/* with the connection. */
	IBT_CM_EVENT_FAILURE		/* The CM Failure see cf_code in the */
					/* ibt_cm_conn_failed_t struct for */
					/* details of the failure */
} ibt_cm_event_type_t;

/*
 * CM and Port redirect information.
 */
typedef struct ibt_redirect_info_s {
	ib_gid_t	rdi_gid;
	uint8_t		rdi_tclass;
	uint8_t		rdi_sl:4;
	uint_t		rdi_flow:20;
	ib_lid_t	rdi_dlid;
	ib_qpn_t	rdi_qpn;
	ib_qkey_t	rdi_qkey;
	ib_pkey_t	rdi_pkey;
} ibt_redirect_info_t;

/*
 * Values for rep_failover_status.
 */
#define	IBT_CM_FAILOVER_ACCEPT		0x00 /* Failover port accepted */
#define	IBT_CM_FAILOVER_REJ_NOTSUPP	0x01 /* Failover not supported */
#define	IBT_CM_FAILOVER_REJ		0x02 /* Failover port rejected */

/*
 * CM REP_RCV event structure.
 */
typedef struct ibt_cm_rep_rcv_s {
	uint8_t		rep_rdma_ra_in;		/* Arbitrated responder */
						/* resources (rdma_ra_in) */
	uint8_t		rep_rdma_ra_out;	/* Arbitrated initiator */
						/* depth (rdma_ra_out) */
	clock_t		rep_service_time;	/* time in clock ticks */
						/* Time to complete */
						/* processing of REP event */
	uint8_t		rep_failover_status;	/* Failover Port status */
	ibt_cm_flags_t	rep_flags;		/* EE flow control, SRQ etc */
} ibt_cm_rep_rcv_t;


/*
 * Values for mra_msg_type.
 */
#define	IBT_CM_MRA_TYPE_REQ	0x00	/* mra_msg values */
#define	IBT_CM_MRA_TYPE_REP	0x01
#define	IBT_CM_MRA_TYPE_LAP	0x02

/*
 * CM MRA_RCV event structure.
 */
typedef struct ibt_cm_mra_rcv_s {
	uint8_t		mra_msg_type;	/* The message being MRA'd */
	clock_t		mra_service_time;	/* timeout in microseconds */
} ibt_cm_mra_rcv_t;

/*
 * CM LAP_RCV event structure.
 */
typedef struct ibt_cm_lap_rcv_s {
	ibt_adds_vect_t	lap_alternate_path;
	clock_t		lap_timeout;		/* timeout in microseconds */
						/* This is the time that the */
						/* Service handler has to */
						/* return to the CM */
} ibt_cm_lap_rcv_t;

#define	IBT_CM_IP_MAJ_VER	0
#define	IBT_CM_IP_MIN_VER	0
#define	IBT_CM_IP_IPV_V4	0x4
#define	IBT_CM_IP_IPV_V6	0x6

/*
 * Consumer defined Additional reject information.
 */
typedef struct ibt_ari_con_s {
	uint8_t		rej_ari_len;			/* Length */
	uint8_t		rej_ari[IBT_CM_ADDL_REJ_LEN];	/* Buffer */
} ibt_ari_con_t;

/*
 * Consumer defined Additional reject information.
 * For RDMA IP CM Service.
 */
typedef uint8_t ibt_ari_ip_reason_t;
#define	IBT_ARI_IP_UNSPECIFIED		0x0
#define	IBT_ARI_IP_MAJOR_VERSION	0x1
#define	IBT_ARI_IP_MINOR_VERSION	0x2
#define	IBT_ARI_IP_IPV			0x3
#define	IBT_ARI_IP_SRC_ADDR		0x4
#define	IBT_ARI_IP_DST_ADDR		0x5
#define	IBT_ARI_IP_UNKNOWN_ADDR		0x6

typedef struct ibt_ari_ip_s {
	ibt_ip_addr_t		ip_suggested_addr;	/* IP_UNKNOWN_ADDR */
	boolean_t		ip_suggested;	/* suggested valid */
	ibt_ari_ip_reason_t	ip_reason;
	uint8_t			ip_suggested_version:4;	/* IP_MAJOR_VERSION */
							/* IP_MINOR_VERSION */
							/* IP_IPV, */
							/* IP_SRC_ADDR, */
							/* IP_DST_ADDR */
} ibt_ari_ip_t;

/*
 * Additional reject information.
 */
typedef union ibt_arej_info_u {
	ibt_ari_con_t		ari_consumer;	/* IBT_CM_CONSUMER */
	ib_gid_t		ari_gid;	/* IBT_CM_PRIM_GID, */
						/* IBT_CM_ALT_GID, */
						/* IBT_CM_PORT_REDIRECT */
	ib_lid_t		ari_lid;	/* IBT_CM_PRIM_LID, */
						/* IBT_CM_ALT_LID */
	uint8_t			ari_sl:4;	/* IBT_CM_INVALID_PRIM_SL, */
						/* IBT_CM_INVALID_ALT_SL */
	uint8_t			ari_tclass;	/* IBT_CM_INVALID_PRIM_TC, */
						/* IBT_CM_INVALID_ALT_TC */
	uint8_t			ari_hop;	/* IBT_CM_INVALID_PRIM_HOP, */
						/* IBT_CM_INVALID_ALT_HOP */
	uint_t			ari_flow:20;	/* IBT_CM_INVALID_PRIM_FLOW, */
						/* IBT_CM_INVALID_ALT_FLOW */
	ibt_srate_t		ari_rate;	/* IBT_CM_INVALID_PRIM_RATE, */
						/* IBT_CM_INVALID_ALT_RATE */
	ib_mtu_t		ari_mtu;	/* IBT_CM_INVALID_MTU */
	ibt_redirect_info_t	ari_redirect;	/* IBT_CM_REDIRECT_CM */
	ibt_ari_ip_t		ari_ip;		/* IBT_CM_RDMA_IP */
} ibt_arej_info_t;

/*
 * CM APR_RCV event structure.
 */
typedef struct ibt_cm_apr_rcv_s {
	ibt_ap_status_t		apr_status;
	boolean_t		apr_arej_info_valid;
	ibt_arej_info_t		apr_arej_info;
} ibt_cm_apr_rcv_t;


/*
 * Connection Failed Message type (values of cf_msg).
 * Identifies the CM message that either timed out or is being rejected.
 */
#define	IBT_CM_FAILURE_REQ	0x00
#define	IBT_CM_FAILURE_REP	0x01
#define	IBT_CM_FAILURE_UNKNOWN	0x02
#define	IBT_CM_FAILURE_LAP	0x03

/*
 * CM Failure code (values of cf_code).
 * Identifies the reason for failure.
 */
#define	IBT_CM_FAILURE_REJ_SENT	0x00
#define	IBT_CM_FAILURE_REJ_RCV	0x01
#define	IBT_CM_FAILURE_TIMEOUT	0x02
#define	IBT_CM_FAILURE_DUP	0x03
#define	IBT_CM_FAILURE_STALE	0x04

/*
 * IBT_CM_EVENT_FAILURE event struct.
 */
typedef struct ibt_cm_conn_failed_s {
	uint8_t		cf_code;	/* Failure Code */
	uint8_t		cf_msg;		/* The message that timed out or is */
					/* being rejected */
	boolean_t	cf_arej_info_valid;	/* Is cf_additional valid? */
	ibt_cm_reason_t	cf_reason;	/* Reject reason */
	ibt_arej_info_t	cf_additional;	/* Additional Reject info */
} ibt_cm_conn_failed_t;


/*
 * CM REQ_RCV event structure.
 *
 * The req_cm_opaque is an IBTF CM opaque (to the client) value, that should
 * be returned to the IBTF CM if the client/server CM handler wishes to call
 * ibt_cm_delay().
 *
 *	prim_addr->av_dgid		Is the GID of the requester.
 *	prim_addr->av_sgid		Is the local GID to which the
 *					requester is attempting to establish
 *					a connection to.
 *	hca_guid			Is the HCA GUID that contains the
 *					prim_addr->av_sgid
 *	prim_hca_port			Is the port on the hca_guid that
 *					prim_addr->av_sgid is on.
 */
typedef struct ibt_cm_req_rcv_s {
	ib_svc_id_t	req_service_id;
	ibt_tran_srv_t	req_transport;
	ib_guid_t	req_hca_guid;
	uint8_t		req_prim_hca_port;
	uint8_t		req_alt_hca_port;
	ibt_adds_vect_t	req_prim_addr;
	ibt_adds_vect_t	req_alt_addr;
	uint8_t		req_rdma_ra_in;   	/* Offered responder */
						/* resources. */
	uint8_t		req_rdma_ra_out; 	/* Offered initiator depth */
	clock_t		req_timeout;		/* timeout in microseconds */
						/* This is the time that the */
						/* Service handler has to */
						/* return to the CM */
	ib_qpn_t	req_remote_qpn;
	ib_qkey_t	req_remote_qkey;
	ib_pkey_t	req_pkey;
	ibt_cm_flags_t	req_flags;		/* EE flow control etc */
	uint8_t		req_retry_cnt:3;
	ibt_rnr_retry_cnt_t	req_rnr_retry_cnt;
	ib_eecn_t	req_opaque1;
	ib_eecn_t	req_opaque2;
} ibt_cm_req_rcv_t;

typedef struct ibt_ofuvcm_req_data_s {
	uint32_t		req_rq_psn:24;
	uint32_t		reserved:8;
	ib_mtu_t		req_path_mtu;
	ibt_rnr_nak_time_t	req_rnr_nak_time;
} ibt_ofuvcm_req_data_t;

/*
 * The IBT_CM_EVENT_CONN_CLOSED event is generated by the CM when a connection
 * has been closed. The reason the connection was closed is given in the
 * "closed" member of the cm_event as one of:
 *
 * A client can only call ibt_free_channel() to free channel resources on
 * receipt of the IBT_CM_EVENT_CONN_CLOSED event.
 */
#define	IBT_CM_CLOSED_DREP_RCVD		0x01
#define	IBT_CM_CLOSED_DREQ_RCVD		0x02
#define	IBT_CM_CLOSED_REJ_RCVD		0x03
#define	IBT_CM_CLOSED_DREQ_TIMEOUT	0x04
#define	IBT_CM_CLOSED_DUP		0x05
#define	IBT_CM_CLOSED_ABORT		0x06
#define	IBT_CM_CLOSED_STALE		0x07
#define	IBT_CM_CLOSED_ALREADY		0x08

/*
 * Operation type in ibt_cm_event_type_t.
 *
 * Note:
 * 	The IBT_CM_EVENT_CONN_EST event has no associated "cm_event"
 *	field in the ibt_cm_event_t structure.
 *
 *	The cm_session_id is a CM opaque (to the client) value, that
 *	should be returned to the CM if the client/server CM handler wishes
 *	to call ibt_cm_delay() or ibt_cm_proceed().
 *
 */
typedef struct ibt_cm_event_s {
	ibt_cm_event_type_t	cm_type;	/* Describes the event */
	void			*cm_session_id;	/* Used by the CM */
	ibt_channel_hdl_t	cm_channel;	/* Event channel. Not valid */
						/* for ibt_cm_req_rcv_t */
	ibt_eec_hdl_t		cm_opaque;
	ibt_priv_data_len_t	cm_priv_data_len;	/* 0 if no private */
	void			*cm_priv_data;		/* data returned */
	union {
		ibt_cm_rep_rcv_t		rep;
		ibt_cm_req_rcv_t 		req;
		ibt_cm_lap_rcv_t		lap;
		ibt_cm_apr_rcv_t		apr;
		ibt_cm_mra_rcv_t		mra;
		ibt_cm_conn_failed_t		failed;
		uint8_t				closed;
	} cm_event;	/* operation specific */
} ibt_cm_event_t;

/*
 * CM Return structure for an incoming REQ
 * Server handler that wishes to accept the connection, fills all the
 * values before returning to CM
 */
typedef struct ibt_cm_ret_rep_s {
	ibt_channel_hdl_t	cm_channel;	/* The channel overwhich the */
						/* connection will be */
						/* established */
						/* can be returned NULL */
						/* if no resources available */
	uint8_t			cm_rdma_ra_out; /* max RDMA-R/Atomic sent */
						/* Number of RDMA RD's & */
						/* Atomics outstanding */
	uint8_t			cm_rdma_ra_in;	/* Incoming RDMA-R/Atomic */
						/* Responder resources for */
						/* handling incoming */
						/* RDMA RD's & Atomics */
	ibt_rnr_retry_cnt_t	cm_rnr_retry_cnt;
} ibt_cm_ret_rep_t;

/*
 * Define an ibt_cm_proceed() argument union.
 *
 * rep is valid when an IBT client cm handler has decided to continue a
 * REQ_RCV, accepting the connection.
 *
 * rej is valid when an IBT client cm handler has decided to continue a
 * REQ_RCV or REP_RCV, rejecting the message.
 *
 * apr is valid when an IBT client cm handler has decided to continue a
 * LAP_RCV, redirecting the lap request.
 */
typedef union ibt_cm_proceed_reply_s {
	ibt_cm_ret_rep_t	rep;	/* Return for REP */
	ibt_arej_info_t		rej;	/* Return for REJ */
	ibt_redirect_info_t	apr;	/* Return for APR */
} ibt_cm_proceed_reply_t;


/*
 * Define a CM handler return arguments structure.
 *
 * cm_ret.rep is returned to the CM when an IBT client cm handler has
 * decided to accept a connection in response to a CM REQ_RCV event.
 *
 * cm_ret.rej is returned to the CM when an IBT client cm handler
 * has decided to reject the connection in response to a CM REQ_RCV event.
 *
 * cm_ret.apr is returned to the CM when an IBT client cm handler
 * has decided to redirect the lap request in response to a CM LAP RCV event.
 *
 * The client/server should update cm_ret_len with number of private data
 * bytes filled in priv_data arg of the cm handler.
 */
typedef struct ibt_cm_return_args_s {
	ibt_priv_data_len_t	cm_ret_len;
	union {
		ibt_cm_ret_rep_t	rep;	/* Return for REP */
		ibt_arej_info_t		rej;	/* Return for REJ */
		ibt_redirect_info_t	apr;	/* Return for APR */
	} cm_ret;	/* reply specific */
} ibt_cm_return_args_t;


/*
 * Communication Manager UD event types.
 */
typedef enum ibt_cm_ud_event_type_e {
	IBT_CM_UD_EVENT_SIDR_REQ	= 1,
	IBT_CM_UD_EVENT_SIDR_REP	= 2
} ibt_cm_ud_event_type_t;

/*
 * CM SIDR_REQ event structure.
 */
typedef struct ibt_cm_sidr_req_s {
	ib_guid_t	sreq_hca_guid;
	uint8_t		sreq_hca_port;
	ib_pkey_t	sreq_pkey;
	ib_svc_id_t	sreq_service_id;
} ibt_cm_sidr_req_t;

/*
 * CM SIDR_REP event structure.
 */
typedef struct ibt_cm_sidr_rep_s {
	ibt_sidr_status_t	srep_status;
	ib_svc_id_t		srep_service_id;
	ib_qkey_t		srep_remote_qkey;
	ib_qpn_t		srep_remote_qpn;
	ibt_redirect_info_t	srep_redirect;	/* Only valid if redirect */
} ibt_cm_sidr_rep_t;

/*
 * Operation type in ibt_cm_ud_event_type_t.
 *
 * The cm_session_id is a CM opaque (to the client) value, that
 * should be returned to the CM if the client/server CM handler
 * wishes to call ibt_cm_ud_proceed().
 */
typedef struct ibt_cm_ud_event_s {
	ibt_cm_ud_event_type_t	cm_type;	/* Describes the event record */
	void			*cm_session_id;	/* Used by the CM */
	ibt_priv_data_len_t	cm_priv_data_len;
	void			*cm_priv_data;
	union {
		ibt_cm_sidr_rep_t	sidr_rep;
		ibt_cm_sidr_req_t	sidr_req;
	} cm_event;				/* operation specific */
} ibt_cm_ud_event_t;


/*
 * Define a CM UD handler return arguments structure.
 *
 * The information here is returned to the CM when an IBT client CM UD
 * handler has decided to communicate (via UD messages) with the requester
 * of the SIDR_REQ_RCV event.
 *
 * The ud_channel encodes the QPN and Q_Key to be placed in the SIDR_REP.
 *
 * CM sets ud_ret_len to 0 before calling the UD CM handler.  If the CM UD
 * handler wishes to send private data back, it needs to update ud_ret_len
 * with the actual number of bytes to be sent back in the SIDR_REP MAD.  It
 * copies said data to the buffer pointed to by the ret_priv_data argument.
 *
 * The ud_redirect structure should only be updated if the UD CM handler is
 * Redirecting a CM request.
 */
typedef struct ibt_cm_ud_return_args_s {
	ibt_priv_data_len_t	ud_ret_len;
	ibt_channel_hdl_t	ud_channel;
	ibt_redirect_info_t	ud_redirect;
} ibt_cm_ud_return_args_t;


/*
 * IBT Client CM Callback function typedefs.
 *
 * ibt_cm_handler_t:
 *
 * The CM event handler function. An IBT client callback that handles
 * CM events. If the handler will exceed the event service timeout
 * then it should call ibt_cm_delay(), specifying the maximum time it
 * will take to complete processing the CM event.
 *
 * Clients are advised not to issue blocking calls from a cm handler, as this
 * would block the CM threads, and could delay or block other client
 * connections.
 *
 * Clients are allowed to make resource clean up/free calls in the CM handler
 * such as ibt_free_cq, ibt_free_rc/ud_channel, etc. on connection failure
 * or tear down.
 *
 * Clients should not call ibt_close_rc_channel in the cm handler for connection
 * failure or tear down events, as these events already perform the processing
 * necessary to close the channel.
 *
 * Clients can call ibt_close_rc_channel only in the non-blocking mode from
 * the cm handler for connection abort.
 */
typedef ibt_cm_status_t (*ibt_cm_handler_t)(void *cm_private,
    ibt_cm_event_t *event, ibt_cm_return_args_t *ret_args,
    void *ret_priv_data, ibt_priv_data_len_t ret_len_max);

/*
 * ibt_cm_ud_handler_t	- Pointer to the CM UD event handler function.
 *			  This function should handle the following CM
 *			  events:
 *				IBT_CM_UD_EVENT_SIDR_REQ
 *				IBT_CM_UD_EVENT_SIDR_REP
 */
typedef ibt_cm_status_t (*ibt_cm_ud_handler_t)(void *ud_cm_private,
    ibt_cm_ud_event_t *event, ibt_cm_ud_return_args_t *ret_args,
    void *ret_priv_data, ibt_priv_data_len_t ret_len_max);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBTI_CM_H */
