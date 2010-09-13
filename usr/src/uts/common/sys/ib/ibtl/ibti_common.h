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

#ifndef	_SYS_IB_IBTL_IBTI_COMMON_H
#define	_SYS_IB_IBTL_IBTI_COMMON_H

/*
 * ibti_common.h
 *
 * This file contains the shared/common transport data types and function
 * prototypes.
 */
#include <sys/types.h>
#include <sys/ib/ib_types.h>
#include <sys/ib/ibtl/ibtl_status.h>
#include <sys/ib/ibtl/ibtl_types.h>
#include <sys/ib/ibtl/ibti_cm.h>
#include <sys/isa_defs.h>
#include <sys/byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Max number of paths that can be requested in an ibt_get_paths() call,
 * if IBT_PATH_PERF or IBT_PATH_AVAIL flag (ibt_path_flags_t) is set.
 */
#define	IBT_MAX_SPECIAL_PATHS	2

/*
 * The name of DDI Event, generated when the properties of IOC device
 * node properties were modified.
 */
#define	IB_PROP_UPDATE_EVENT	"SUNW,IB:IB_PROP_UPDATE"


/* Transport Interface version */
typedef int ibt_version_t;
#define	IBTI_V1		1
#define	IBTI_V2		2
#define	IBTI_V3		3
#define	IBTI_V4		4
#define	IBTI_V_CURR	IBTI_V4

/*
 * Driver class type. Identifies a type of client driver so that
 * "IBTF Policy" decisions can be made on a driver class basis.
 * The last class should always be IBT_CLNT_NUM, and any new classes added
 * must be defined before IBT_CLNT_NUM. The class values must be above 0.
 * Any class values below or equal to 0 shall be invalid
 */
typedef enum ibt_clnt_class_e {
	IBT_STORAGE_DEV = 0x1,	/* SCSI, FC, etc.. */
	IBT_NETWORK_DEV,	/* Network driver with associated client H/W */
	IBT_GENERIC_DEV,	/* Generic client H/W device driver */
	IBT_NETWORK,		/* Network driver with no associated */
				/* client H/W, e.g., IPoIB */
	IBT_GENERIC,		/* A generic IB driver not */
				/* associated with client H/W */
	IBT_USER,		/* A user application IBT interface driver */
	IBT_IBMA,		/* The IBMA Module */
	IBT_CM,			/* The CM Module */
	IBT_DM,			/* The DM Module */
	IBT_DM_AGENT,		/* DM Agent Module */
	IBT_GENERIC_MISC,	/* Generic Misc Module */
	IBT_CLASS_NUM		/* Place holder for class count */
} ibt_clnt_class_t;

#define	IBT_TEST_DEV	999	/* Place holder for modules that test IBTL */

#define	IBT_CLNT_DEVICE_CLASS(class)	((class) == IBT_STORAGE_DEV || \
					(class) == IBT_NETWORK_DEV || \
					(class) == IBT_GENERIC_DEV)

#define	IBT_CLNT_GENERAL_CLASS(class)	((class) == IBT_NETWORK || \
					(class) == IBT_GENERIC || \
					(class) == IBT_DM_AGENT || \
					(class) == IBT_TEST_DEV || \
					(class) == IBT_GENERIC_MISC ||	\
					(class) == IBT_USER)

#define	IBT_CLNT_MGMT_CLASS(class)	((class) == IBT_IBMA || \
					(class) == IBT_CM || \
					(class) == IBT_DM)

/*
 * These are some special client classes which don't have a 'dip' hence have
 * to be handled specially in ibt_attach, where we bypass the check for a valid
 * dip if the client belongs to the class below.
 */
#define	IBT_MISCMOD_CLIENTS(class)	((class) == IBT_IBMA || \
					(class) == IBT_CM || \
					(class) == IBT_DM || \
					(class) == IBT_DM_AGENT || \
					(class) == IBT_GENERIC_MISC ||	\
					(class) == IBT_TEST_DEV)

/*
 * Event record & status returns for asynchronous events and errors.
 */
typedef struct ibt_async_event_s {
	uint64_t		ev_fma_ena;		/* FMA Error data */
	ibt_channel_hdl_t	ev_chan_hdl;		/* Channel handle */
	ibt_cq_hdl_t		ev_cq_hdl;		/* CQ handle */
	ib_guid_t		ev_hca_guid;		/* HCA node GUID */
	ibt_srq_hdl_t		ev_srq_hdl;		/* SRQ handle */
	ibt_port_change_t	ev_port_flags;		/* Port Change flags */
	uint8_t			ev_port;		/* HCA port */
	ibt_fc_syndrome_t	ev_fc;			/* FEXCH syndrome */
} ibt_async_event_t;

/*
 * IBT Client Callback function typedefs.
 *
 * ibt_async_handler_t
 *	Pointer to an async event/error handler function.  This function is
 *	called when an async event/error is detected on a HCA that is being
 *	used by the IBT client driver that registered the function.
 */
typedef void (*ibt_async_handler_t)(void *clnt_private,
    ibt_hca_hdl_t hca_hdl, ibt_async_code_t code, ibt_async_event_t *event);

/*
 * IBT Client Memory Error Callback function typedefs.
 *
 * ibt_memory_handler_t
 *	Pointer to an memory event/error handler function.
 */
typedef void (*ibt_memory_handler_t)(void *clnt_private,
    ibt_hca_hdl_t hca_hdl, ibt_mem_code_t code, ibt_mem_data_t *data);

/*
 * Define a client module information structure. All clients MUST
 * define a global of type ibt_clnt_modinfo_t. A pointer to this global
 * is passed into the IBTF by a client when calling ibt_attach().
 * This struct must persist during the life of the client.
 *
 * The client's mi_async_handler is called when an async event/error is
 * detected on a HCA that is being used by this client.
 */
typedef struct ibt_clnt_modinfo_s {
	ibt_version_t		mi_ibt_version;		/* TI version */
	ibt_clnt_class_t	mi_clnt_class;		/* Type of client */
	ibt_async_handler_t	mi_async_handler;	/* Async Handler */
	ibt_memory_handler_t	mi_reserved;		/* Memory handler */
	char			*mi_clnt_name;		/* Client Name. */
} ibt_clnt_modinfo_t;


/*
 * Definitions for use with ibt_register_subnet_notices()
 */
typedef enum ibt_subnet_event_code_e {
	IBT_SM_EVENT_MCG_CREATED = 1,
	IBT_SM_EVENT_MCG_DELETED = 2,
	IBT_SM_EVENT_AVAILABLE	 = 3,
	IBT_SM_EVENT_UNAVAILABLE = 4,
	IBT_SM_EVENT_GID_AVAIL	 = 5,
	IBT_SM_EVENT_GID_UNAVAIL = 6
} ibt_subnet_event_code_t;

typedef struct ibt_subnet_event_s {
	ib_gid_t sm_notice_gid;
} ibt_subnet_event_t;

typedef void (*ibt_sm_notice_handler_t)(void *private, ib_gid_t gid,
    ibt_subnet_event_code_t code, ibt_subnet_event_t *event);


/*
 * MTU Request type.
 */
typedef struct ibt_mtu_req_s {
	ib_mtu_t	r_mtu;		/* Requested MTU */
	ibt_selector_t	r_selector;	/* Qualifier for r_mtu */
} ibt_mtu_req_t;


/*
 * Qflags, used by ibt_resize_queues().
 */
typedef enum ibt_qflags_e {
	IBT_SEND_Q	= 1 << 0,	/* Op applies to the Send Q */
	IBT_RECV_Q	= 1 << 1	/* Op applies to the Recv Q */
} ibt_qflags_t;


/*
 * ibt_cq_handler_t
 *	Pointer to a work request completion handler function.  This function
 *	is called when a WR completes on a CQ that is being used by the IBTF
 *	client driver that registered the function.
 */
typedef void (*ibt_cq_handler_t)(ibt_cq_hdl_t ibt_cq, void *arg);

/* default CQ handler ID */
#define	IBT_CQ_HID_DEFAULT	(1)

/*
 * Service Data and flags.
 *	(IBTA Spec Release 1.1, Vol-1 Ref: 15.2.5.14.4)
 *
 * The ServiceData8.1 (sb_data8[0]) through ServiceData64.2 (sb_data64[1])
 * components together constitutes a 64-byte area in which any data may be
 * placed. It is intended to be a convenient way for a service to provide its
 * clients with some initial data.
 *
 * In addition, this 64-byte area is formally divided into a total of 30
 * components, 16 8-bit (uint8_t) components, then 8 16-bit (uint16_t)
 * components, then 6 32-bit (uint32_t) components, then 2 64-bit (uint64_t)
 * components,  thereby assigning ComponentMask bits (ibt_srv_data_flags_t) to
 * variously-sized segments of the data. All data are in host endian format.
 * This allows query operations (ibt_get_paths()) to be used which match
 * parts of the Service Data, making it possible, for example, for
 * service-specific parts of the ServiceData to serve as a binary-coded
 * extension to the ServiceName for purposes of lookup.
 */
typedef enum ibt_srv_data_flags_e {
	IBT_NO_SDATA	= 0,

	IBT_SDATA8_0	= (1 << 0),
	IBT_SDATA8_1	= (1 << 1),
	IBT_SDATA8_2	= (1 << 2),
	IBT_SDATA8_3	= (1 << 3),
	IBT_SDATA8_4	= (1 << 4),
	IBT_SDATA8_5	= (1 << 5),
	IBT_SDATA8_6	= (1 << 6),
	IBT_SDATA8_7	= (1 << 7),
	IBT_SDATA8_8	= (1 << 8),
	IBT_SDATA8_9	= (1 << 9),
	IBT_SDATA8_10	= (1 << 10),
	IBT_SDATA8_11	= (1 << 11),
	IBT_SDATA8_12	= (1 << 12),
	IBT_SDATA8_13	= (1 << 13),
	IBT_SDATA8_14	= (1 << 14),
	IBT_SDATA8_15	= (1 << 15),

	IBT_SDATA16_0	= (1 << 16),
	IBT_SDATA16_1	= (1 << 17),
	IBT_SDATA16_2	= (1 << 18),
	IBT_SDATA16_3	= (1 << 19),
	IBT_SDATA16_4	= (1 << 20),
	IBT_SDATA16_5	= (1 << 21),
	IBT_SDATA16_6	= (1 << 22),
	IBT_SDATA16_7	= (1 << 23),

	IBT_SDATA32_0	= (1 << 24),
	IBT_SDATA32_1	= (1 << 25),
	IBT_SDATA32_2	= (1 << 26),
	IBT_SDATA32_3	= (1 << 27),

	IBT_SDATA64_0	= (1 << 28),
	IBT_SDATA64_1	= (1 << 29),

	IBT_SDATA_ALL	= 0x3FFFFFFF
} ibt_srv_data_flags_t;

typedef struct ibt_srv_data_s {
	uint8_t		s_data8[16];	/* 8-bit service data fields. */
	uint16_t	s_data16[8];	/* 16-bit service data fields. */
	uint32_t	s_data32[4];	/* 32-bit service data fields. */
	uint64_t	s_data64[2];	/* 64-bit service data fields. */
} ibt_srv_data_t;

/*
 * Path flags, used in ibt_get_paths()
 */
typedef enum ibt_path_flags_e {
	IBT_PATH_NO_FLAGS	= 0,
	IBT_PATH_APM		= 1 << 0,	/* APM is desired. */
	IBT_PATH_AVAIL		= 1 << 2,
	IBT_PATH_PERF		= 1 << 3,
	IBT_PATH_MULTI_SVC_DEST	= 1 << 4,	/* Multiple ServiceRecords */
	IBT_PATH_HOP		= 1 << 5,	/* pa_hop is specified. */
	IBT_PATH_PKEY		= 1 << 6	/* pa_pkey is specified. */
} ibt_path_flags_t;

/*
 * Path attributes.
 *
 * The ibt_path_attr_t structure is used to specify required attributes in a
 * path from the requesting (source) node to a specified destination node.
 * Attributes that are don't care should be set to NULL or '0'.
 * A destination must be specified, where a destination can be defined as
 * one of the following:
 *
 *	o Service Name
 *	o Service ID (SID)
 *	o Array of DGIDs.
 *	o Service Name and Array of DGIDs.
 */
typedef struct ibt_path_attr_s {
	ib_gid_t		*pa_dgids;	/* Array of DGIDs */
	ib_gid_t		pa_sgid;
	ib_guid_t		pa_hca_guid;
	char			*pa_sname;	/* ASCII Service name  */
						/* NULL Terminated */
	ib_svc_id_t		pa_sid;		/* Service ID */
	ibt_srv_data_flags_t	pa_sd_flags;	/* Service Data flags. */
	ibt_srv_data_t		pa_sdata;	/* Service Data */
	uint8_t			pa_hca_port_num;
	uint8_t			pa_num_dgids;	/* size of pa_dgids array */
	uint8_t			pa_sl:4;
	ibt_mtu_req_t		pa_mtu;
	ibt_srate_req_t		pa_srate;
	ibt_pkt_lt_req_t	pa_pkt_lt;	/* Packet Life Time Request */
	uint_t			pa_flow:20;
	uint8_t			pa_hop;		/* IBT_PATH_HOP */
	uint8_t			pa_tclass;
	ib_pkey_t		pa_pkey;	/* IBT_PATH_PKEY */
} ibt_path_attr_t;

/*
 * Path Information.
 *
 * The ibt_get_paths() performs SA Path record lookups to select a path(s) to
 * a given destination(s), details of selected path(s) are returned in this
 * structure.
 *
 * The ibt_path_info_t contains all the attributes of the best path(s), as
 * as determined by IBTL, to the specified destination(s), including the
 * local HCA and HCA port to use to access the fabric.
 *
 * The Service ID (pi_sid) and Service Data (pi_sdata) are returned only for
 * lookups based on Service ID or/and Service Name.
 */
typedef struct ibt_path_info_s {
	ib_guid_t	pi_hca_guid;		/* Local HCA GUID; 0 implies */
						/* this record is invalid */
	ib_svc_id_t	pi_sid;			/* Service ID */
	ibt_srv_data_t	pi_sdata;		/* Service Data */

	ibt_cep_path_t	pi_prim_cep_path;	/* Contains CEP adds info */
	ibt_cep_path_t	pi_alt_cep_path;	/* RC & UC Only, valid if */
						/* cep_hca_port_num is not */
						/* '0' */
	ib_mtu_t	pi_path_mtu;		/* Common path MTU */
	ib_time_t	pi_prim_pkt_lt;
	ib_time_t	pi_alt_pkt_lt;
} ibt_path_info_t;

/*
 * Optional Alternate Path attributes.
 *
 * The ibt_alt_path_attr_t structure is used to specify additional optional
 * attributes when requesting an alternate path for an existing channel.
 *
 * Attributes that are don't care should be set to NULL or '0'.
 */
typedef struct ibt_alt_path_attr_s {
	ib_gid_t		apa_sgid;
	ib_gid_t		apa_dgid;
	ibt_srate_req_t		apa_srate;
	ibt_pkt_lt_req_t	apa_pkt_lt;	/* Packet Life Time Request */
	uint_t			apa_flow:20;
	uint8_t			apa_sl:4;
	uint8_t			apa_hop;
	uint8_t			apa_tclass;
} ibt_alt_path_attr_t;

/*
 * Path Information for Alternate Path - input to ibt_set_alt_path().
 */
typedef struct ibt_alt_path_info_s {
	ibt_cep_path_t	ap_alt_cep_path;	/* RC & UC Only, valid if */
						/* cep_hca_port_num is not */
						/* '0' */
	ib_time_t	ap_alt_pkt_lt;
} ibt_alt_path_info_t;

/*
 * Open Channel flags, Used in ibt_open_rc_channel call
 */
typedef enum ibt_chan_open_flags_e {
	IBT_OCHAN_NO_FLAGS		= 0,
	IBT_OCHAN_REDIRECTED		= 1 << 0,
	IBT_OCHAN_PORT_REDIRECTED	= 1 << 1,
	IBT_OCHAN_DUP			= 1 << 2,
	IBT_OCHAN_PORT_FIXED		= 1 << 3,
	IBT_OCHAN_OPAQUE1		= 1 << 4,
	IBT_OCHAN_OPAQUE2		= 1 << 5,
	IBT_OCHAN_OPAQUE3		= 1 << 6,
	IBT_OCHAN_OPAQUE4		= 1 << 7,
	IBT_OCHAN_OPAQUE5		= 1 << 8,
	IBT_OCHAN_OPAQUE6		= 1 << 9
} ibt_chan_open_flags_t;

/*
 * Arguments for ibt_open_rc_channel().
 *
 * oc_priv_data should be NULL or point to a buffer allocated by the caller,
 * the size of which should be in oc_priv_data_len, where oc_priv_data_len <=
 * IBT_REQ_PRIV_DATA_SZ.
 *
 * When ibt_open_rc_channel returns with ibt_cm_reason_t of
 * IBT_CM_REDIRECT_PORT, the client can re-issue ibt_open_rc_channel setting
 * new fields as follows:
 *
 * Set (ibt_chan_args_t)->oc_cm_cep_path  =
 *    original (ibt_chan_open_args_t)->oc_path->pi_prim_cep_path.
 * Set (ibt_chan_args_t)->oc_cm_pkt_lt  =
 *    original (ibt_chan_open_args_t)->oc_prim_pkt_lt.
 * Update (ibt_chan_args_t)->oc_path based on path information returned
 * from ibt_get_paths using the gid in the return data below:
 * 	(ibt_rc_returns_t)->rc_arej_info.ari_redirect_info.ari_gid.
 * Set flags to IBT_OCHAN_PORT_REDIRECTED.
 *
 * Note : oc_cm_path is not used for any other scenario, and must be set for
 * IBT_OCHAN_PORT_REDIRECTED.
 *
 * When ibt_open_rc_channel returns with ibt_cm_reason_t of
 * IBT_CM_REDIRECT_CM, the client can re-issue ibt_open_rc_channel setting
 * new fields as follows:
 *
 * Update (ibt_chan_args_t)->oc_path based on path information returned
 * from ibt_get_paths using the return data in
 * (ibt_rc_returns_t)->rc_arej_info.ari_redirect_info.
 *
 * Set (ibt_chan_args_t)->oc_cm_redirect_info =
 *    Returned (ibt_rc_returns_t)->rc_arej_info.ari_redirect_info.
 * Set flags to IBT_OCHAN_REDIRECTED.
 *
 * Note:
 *
 * IBT_OCHAN_PORT_REDIRECTED flag cannot be used to specify a remote CM MAD
 * address, that is on a different subnet than the RC connection itself.
 *
 * Not specified attributes should be set to "NULL" or "0".
 */
typedef struct ibt_chan_open_args_s {
	ibt_path_info_t 	*oc_path;	/* Primary & Alternate */
	ibt_cm_handler_t 	oc_cm_handler;	/* cm_handler - required */
	void			*oc_cm_clnt_private;	/* First argument to */
							/* cm_handler */
	ibt_rnr_retry_cnt_t	oc_path_rnr_retry_cnt;
	uint8_t			oc_path_retry_cnt:3;
	uint8_t			oc_rdma_ra_out;
	uint8_t			oc_rdma_ra_in;
	ibt_priv_data_len_t	oc_priv_data_len;	/* Number of bytes of */
							/* REQ Private data */
	void			*oc_priv_data;		/* REQ private data */
	ibt_channel_hdl_t	oc_dup_channel; 	/* IBT_OCHAN_DUP */
	ibt_redirect_info_t	*oc_cm_redirect_info;	/* Redirect params */
							/* for port and CM */
							/* redirection */
	ibt_cep_path_t		*oc_cm_cep_path;	/* Optional Path for */
							/* CM MADs on */
							/* port redirection */
	ib_time_t		oc_cm_pkt_lt;		/* Pkt life time for */
							/* CM MADs */
	uint32_t		oc_opaque1:4;
	uint32_t		oc_opaque2:24;
	uint32_t		oc_opaque3;
	uint32_t		oc_opaque4;
} ibt_chan_open_args_t;


/*
 * Define an optional RC return arguments structure. This contains return
 * parameters from ibt_open_rc_channel() when called in BLOCKING mode.
 *
 * rc_priv_data should be NULL or point to a buffer allocated by the caller,
 * the size of which should be in rc_priv_data_len, where rc_priv_data_len <=
 * IBT_REP_PRIV_DATA_SZ.
 */
typedef struct ibt_rc_returns_s {
	uint8_t			rc_rdma_ra_in;	/* Arbitrated resp resources */
	uint8_t			rc_rdma_ra_out;	/* Arbitrated initiator depth */
	ibt_arej_info_t		rc_arej_info;
	ibt_cm_reason_t		rc_status;
	uint8_t			rc_failover_status;	/* Failover status */
	ibt_priv_data_len_t	rc_priv_data_len;
	void			*rc_priv_data;
} ibt_rc_returns_t;

/*
 * Define a callback function that can be used in Non-Blocking calls to
 * ibt_recycle_rc().
 */

typedef	void	(*ibt_recycle_handler_t)(ibt_status_t ibt_status, void *arg);

/*
 * Define an optional return arguments structure from ibt_set_alt_path()
 * This contains return parameters, when called in BLOCKING mode.
 *
 * ap_priv_data should be NULL or point to a buffer allocated by the caller,
 * the size of which should be in ap_priv_data_len, where ap_priv_data_len <=
 * IBT_APR_PRIV_DATA_SZ.
 * The private data from APR is returned in ap_priv_data.
 * The caller specifies amount of APR private data to be returned in
 * ap_priv_data_len.
 */
typedef struct ibt_ap_returns_s {
	ibt_ap_status_t		ap_status;
	boolean_t		ap_arej_info_valid;
	ibt_arej_info_t		ap_arej_info;	/* Only valid if redirect */
	ibt_priv_data_len_t	ap_priv_data_len;
	void			*ap_priv_data;
} ibt_ap_returns_t;

/*
 * UD remote destination attributes.
 *
 * ud_sid, ud_addr, ud_pkt_lt and ud_pkey_ix must be specified.
 * These values can be as returned in an ibt_path_info_t struct from an
 * ibt_get_paths() call.
 *
 * ud_priv_data should be NULL or point to a buffer allocated by the caller,
 * the size of which is in ud_priv_data_len, where ud_priv_data_len <=
 * IBT_SIDR_REQ_PRIV_DATA_SZ.
 */
typedef struct ibt_ud_dest_attr_s {
	ib_svc_id_t		ud_sid;		/* Service ID */
	ibt_adds_vect_t		*ud_addr;	/* Address Info */
	uint16_t		ud_pkey_ix;	/* Pkey Index */
	ib_time_t		ud_pkt_lt;
	ibt_cm_ud_handler_t	ud_cm_handler;	/* An optional CM UD event */
						/* which must be NULL */
						/* if not specified. */
	void			*ud_cm_private; /* First arg to ud_cm_handler */
	ibt_priv_data_len_t	ud_priv_data_len;
	void			*ud_priv_data;	/* SIDR REQ private data */
} ibt_ud_dest_attr_t;

/*
 * Define an optional UD return arguments structure.
 *
 * ud_priv_data should be NULL or point to a buffer allocated by the caller,
 * the size of which should be in ud_priv_data_len, where ud_priv_data_len <=
 * IBT_SIDR_REP_PRIV_DATA_SZ.
 */
typedef struct ibt_ud_returns_s {
	ibt_sidr_status_t	ud_status;
	ibt_redirect_info_t	ud_redirect;
	ib_qpn_t		ud_dqpn;	/* Returned destination QPN */
	ib_qkey_t		ud_qkey;	/* Q_Key for destination QPN */
	ibt_priv_data_len_t	ud_priv_data_len;
	void			*ud_priv_data;
} ibt_ud_returns_t;

/*
 * Multicast group attributes
 * Not specified attributes should be set to "NULL" or "0".
 * Used by ibt_join_mcg()/ibt_query_mcg().
 *
 * mc_qkey, mc_pkey, mc_flow, mc_tclass, mc_sl, mc_join_state are required for
 * create - ibt_join_mcg().
 */
typedef struct ibt_mcg_attr_s {
	ib_gid_t		mc_mgid;	/* MGID */
	ib_gid_t		mc_pgid;	/* SGID of the end port being */
						/* added to the MCG. */
	ib_qkey_t		mc_qkey;	/* Q_Key */
	ib_pkey_t		mc_pkey;	/* Partition key for this MCG */
	ibt_mtu_req_t		mc_mtu_req;	/* MTU */
	ibt_srate_req_t		mc_rate_req;	/* Static rate */
	ibt_pkt_lt_req_t	mc_pkt_lt_req;	/* Packet Life Time Request */
	uint_t			mc_flow:20;	/* FlowLabel. */
	uint8_t			mc_hop;		/* HopLimit */
	uint8_t			mc_tclass;	/* Traffic Class. */
	uint8_t			mc_sl:4;	/* Service Level */
	uint8_t			mc_scope:4,	/* Multicast Address Scope */
				mc_join_state:4; /* FULL For create */
	ib_lid_t		mc_opaque1;
} ibt_mcg_attr_t;

/*
 * Multicast group attributes.
 * returned by ibt_join_mcg()/ibt_query_mcg().
 */
typedef struct ibt_mcg_info_s {
	ibt_adds_vect_t		mc_adds_vect;   /* Address information */
	ib_mtu_t		mc_mtu;		/* MTU */
	ib_qkey_t		mc_qkey;	/* Q_Key */
	uint16_t		mc_pkey_ix;	/* Pkey Index */
	uint8_t			mc_scope:4;	/* Multicast Address Scope */
	clock_t			mc_opaque2;
} ibt_mcg_info_t;

/*
 * Define a callback function that can be used in Non-Blocking calls to
 * ibt_join_mcg().
 */
typedef void (*ibt_mcg_handler_t)(void *arg, ibt_status_t retval,
    ibt_mcg_info_t *mcg_info_p);


/*
 * Service Flags - sd_flags
 *
 *    IBT_SRV_PEER_TYPE_SID	Peer-to-peer Service IDs.
 */

typedef enum ibt_service_flags_e {
	IBT_SRV_NO_FLAGS	= 0x0,
	IBT_SRV_PEER_TYPE_SID	= 0x1
} ibt_service_flags_t;

/*
 * Define a Service ID Registration structure.
 */
typedef struct ibt_srv_desc_s {
	ibt_cm_ud_handler_t	sd_ud_handler;	/* UD Service Handler */
	ibt_cm_handler_t	sd_handler;	/* Non-UD Service Handler */
	ibt_service_flags_t	sd_flags;	/* Flags */
} ibt_srv_desc_t;

/*
 * Flag to indicate ibt_bind_service() to or NOT-to clean-up Stale matching
 * Local Service Records with SA prior to binding the new request.
 */
#define	IBT_SBIND_NO_FLAGS	0
#define	IBT_SBIND_NO_CLEANUP	1

/*
 * Define a Service ID Binding structure (data for service records).
 */
typedef struct ibt_srv_bind_s {
	uint64_t	sb_key[2];	/* Service Key */
	char		*sb_name;	/* Service Name (up to 63 chars) */
	uint32_t	sb_lease;	/* Service Lease period (in seconds) */
	ib_pkey_t	sb_pkey;	/* Service P_Key */
	ibt_srv_data_t	sb_data;	/* Service Data */
	uint_t		sb_flag;	/* indicates to/not-to clean-up stale */
					/* matching local service records. */
} ibt_srv_bind_t;

/*
 * ibt_cm_delay() flags.
 *
 * Refer to InfiniBand Architecture Release Volume 1 Rev 1.0a:
 * Section 12.6.6 MRA
 */
typedef enum ibt_cmdelay_flags_e {
	IBT_CM_DELAY_REQ	= 0,
	IBT_CM_DELAY_REP	= 1,
	IBT_CM_DELAY_LAP	= 2
} ibt_cmdelay_flags_t;

/*
 * The payload for DDI events passed on IB_PROP_UPDATE_EVENT.
 * This is passed as the bus nexus data to event_handler(9e).
 */
typedef struct ibt_prop_update_payload_s {
	union {
		struct {
			uint32_t	srv_updated:1;
			uint32_t	gid_updated:1;
		} _ib_prop_update_struct;
		uint32_t	prop_updated;
	} _ib_prop_update_union;
	ibt_status_t		ib_reprobe_status;

#define	ib_srv_prop_updated	\
    _ib_prop_update_union._ib_prop_update_struct.srv_updated
#define	ib_gid_prop_updated	\
    _ib_prop_update_union._ib_prop_update_struct.gid_updated
#define	ib_prop_updated		\
    _ib_prop_update_union.prop_updated
} ibt_prop_update_payload_t;


/*
 * FUNCTION PROTOTYPES.
 */

/*
 * ibt_attach() and ibt_detach():
 *	These are the calls into IBTF used during client driver attach() and
 *	detach().
 *
 *	The IBTF returns an ibt_clnt_hdl_t to the client. This handle is used
 *	to identify this client device in all subsequent calls into the IBTF.
 *
 *	The ibt_detach() routine is called from a client driver's detach()
 *	routine to deregister itself from the IBTF.
 */
ibt_status_t ibt_attach(ibt_clnt_modinfo_t *mod_infop, dev_info_t *arg,
    void *clnt_private, ibt_clnt_hdl_t *ibt_hdl_p);

ibt_status_t ibt_detach(ibt_clnt_hdl_t ibt_hdl);

/*
 * HCA FUNCTIONS
 */

/*
 * ibt_get_hca_list()
 *	Returns the number of HCAs in a system and their node GUIDS.
 *
 *	If hca_list_p is not NULL then the memory for the array of GUIDs is
 *	allocated by the IBTF and should be freed by the caller using
 *	ibt_free_hca_list(). If hca_list_p is NULL then no memory is allocated
 *	by ibt_get_hca_list and only the number of HCAs in a system is returned.
 *
 *	It is assumed that the caller can block in kmem_alloc.
 *
 * ibt_free_hca_list()
 *	Free the memory allocated by ibt_get_hca_list().
 */
uint_t ibt_get_hca_list(ib_guid_t **hca_list_p);

void ibt_free_hca_list(ib_guid_t *hca_list, uint_t entries);

/*
 * ibt_open_hca()	- Open/Close a HCA. HCA can only be opened/closed
 * ibt_close_hca()	  once. ibt_open_hca() takes a client's ibt handle
 *			  and a GUID and returns a unique IBT client HCA
 *			  handle.
 *
 * These routines can not be called from interrupt context.
 */
ibt_status_t ibt_open_hca(ibt_clnt_hdl_t ibt_hdl, ib_guid_t hca_guid,
    ibt_hca_hdl_t *hca_hdl);

ibt_status_t ibt_close_hca(ibt_hca_hdl_t hca_hdl);


/*
 * ibt_query_hca()
 * ibt_query_hca_byguid()
 * 	Returns the static attributes of the specified HCA
 */
ibt_status_t ibt_query_hca(ibt_hca_hdl_t hca_hdl, ibt_hca_attr_t *hca_attrs);

ibt_status_t ibt_query_hca_byguid(ib_guid_t hca_guid,
    ibt_hca_attr_t *hca_attrs);


/*
 * ibt_query_hca_ports()
 * ibt_query_hca_ports_byguid()
 *	Returns HCA port/ports attributes for the specified HCA port/ports.
 *	ibt_query_hca_ports() allocates the memory required for the
 *	ibt_hca_portinfo_t struct as well as the memory required for the SGID
 *	and P_Key tables contained within that struct.
 *
 * ibt_free_portinfo()
 *	Frees the memory allocated for a specified ibt_hca_portinfo_t struct.
 */
ibt_status_t ibt_query_hca_ports(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p);

ibt_status_t ibt_query_hca_ports_byguid(ib_guid_t hca_guid, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p);

void ibt_free_portinfo(ibt_hca_portinfo_t *port_info, uint_t size);

/*
 * ibt_set_hca_private()	- Set/get the client private data.
 * ibt_get_hca_private()
 */
void ibt_set_hca_private(ibt_hca_hdl_t hca_hdl, void *clnt_private);
void *ibt_get_hca_private(ibt_hca_hdl_t hca_hdl);

/*
 * ibt_hca_handle_to_guid()
 *	A helper function to retrieve HCA GUID for the specified handle.
 *	Returns HCA GUID on which the specified Channel is allocated. Valid
 *	if it is non-NULL on return.
 */
ib_guid_t ibt_hca_handle_to_guid(ibt_hca_hdl_t hca);

/*
 * ibt_hca_guid_to_handle()
 *	A helper function to retrieve a hca handle from a HCA GUID.
 */
ibt_status_t ibt_hca_guid_to_handle(ibt_clnt_hdl_t ibt_hdl, ib_guid_t hca_guid,
    ibt_hca_hdl_t *hca_hdl);

/*
 * CONNECTION ESTABLISHMENT/TEAR DOWN FUNCTIONS.
 */

/*
 * ibt_get_paths
 *	Finds the best path to a specified destination (as determined by the
 *	IBTL) that satisfies the requirements specified in an ibt_path_attr_t
 *	struct.
 */
ibt_status_t ibt_get_paths(ibt_clnt_hdl_t ibt_hdl, ibt_path_flags_t flags,
    ibt_path_attr_t *attr, uint8_t max_paths, ibt_path_info_t *paths,
    uint8_t *num_paths_p);


/*
 * Callback function that can be used in ibt_aget_paths(), a Non-Blocking
 * version of ibt_get_paths().
 */
typedef void (*ibt_path_handler_t)(void *arg, ibt_status_t retval,
    ibt_path_info_t *paths, uint8_t num_paths);

/*
 * Find path(s) to a given destination or service asynchronously.
 * ibt_aget_paths() is a Non-Blocking version of ibt_get_paths().
 */
ibt_status_t ibt_aget_paths(ibt_clnt_hdl_t ibt_hdl, ibt_path_flags_t flags,
    ibt_path_attr_t *attr, uint8_t max_paths, ibt_path_handler_t func,
    void  *arg);

/*
 * ibt_get_alt_path
 *	Finds the best alternate path to a specified channel (as determined by
 *	the IBTL) that satisfies the requirements specified in an
 *	ibt_alt_path_attr_t struct.  The specified channel must have been
 *	previously opened successfully using ibt_open_rc_channel.
 */
ibt_status_t ibt_get_alt_path(ibt_channel_hdl_t chan, ibt_path_flags_t flags,
    ibt_alt_path_attr_t *attr, ibt_alt_path_info_t *alt_path);

/*
 * ibt_open_rc_channel
 * 	ibt_open_rc_channel() opens a previously allocated RC communication
 *	channel. The IBTL initiates the channel establishment protocol.
 */
ibt_status_t ibt_open_rc_channel(ibt_channel_hdl_t rc_chan,
    ibt_chan_open_flags_t flags, ibt_execution_mode_t mode,
    ibt_chan_open_args_t *args, ibt_rc_returns_t *returns);

/*
 * ibt_close_rc_channel
 *	Close the specified channel. Outstanding work requests are flushed
 *	so that the client can do the associated clean up. After that, the
 *	client will usually deregister the previously registered memory,
 *	then free the channel by calling ibt_free_rc_channel().
 *
 *	This function will reuse CM event Handler provided in
 *	ibt_open_rc_channel().
 */
ibt_status_t ibt_close_rc_channel(ibt_channel_hdl_t rc_chan,
    ibt_execution_mode_t mode, void *priv_data,
    ibt_priv_data_len_t priv_data_len, uint8_t *ret_status,
    void *ret_priv_data, ibt_priv_data_len_t *ret_priv_data_len_p);

/*
 * ibt_prime_close_rc_channel
 *
 *	Allocates resources required for a close rc channel operation.
 *	Calling ibt_prime_close_rc_channel() allows a channel to be
 *	subsequently closed in interrupt context.
 *
 *	A call is first made to ibt_prime_close_rc_channel in non-interrupt
 *	context, followed by ibt_close_rc_channel in non-blocking mode from
 *	interrupt context
 *
 *	ibt_prime_close_rc_channel() can only be called on a previously opened
 *	channel.
 */
ibt_status_t ibt_prime_close_rc_channel(ibt_channel_hdl_t rc_chan);

/*
 * ibt_recycle_rc
 *
 *      Recycle a RC channel which has transitioned to Error state. The
 *      ibt_recycle_rc() function transitions the channel from Error
 *      state (IBT_STATE_ERROR) to the state ready for use by
 *      ibt_open_rc_channel. Basically, this function is very similar to
 *      ibt_alloc_rc_channel, but reuses an existing RC channel.
 *
 * Clients are allowed to make resource clean up/free calls in the CM handler
 *
 * Client(s) must not invoke blocking version (ie., func specified as NULL) of
 * ibt_recycle_rc from cm callback for IBT_CM_EVENT_CONN_CLOSED
 *
 * Clients are strongly advised not to issue blocking calls from  func, as this
 * would block the CM threads, and could delay or block other client connections
 * and ibtl related API invocations.
 */
ibt_status_t ibt_recycle_rc(ibt_channel_hdl_t rc_chan, ibt_cep_flags_t control,
    uint8_t hca_port_num, ibt_recycle_handler_t func, void *arg);

/*
 * ibt_recycle_ud
 *
 *      Recycle a UD channel which has transitioned to Error state. The
 *      ibt_recycle_ud() function transitions the channel from Error
 *      state (IBT_STATE_ERROR) to a usable state (IBT_STATE_RTS).
 *      Basically, this function is very similar to ibt_alloc_ud_channel,
 *	but reuses an existing UD channel.
 */
ibt_status_t ibt_recycle_ud(ibt_channel_hdl_t ud_chan, uint8_t hca_port_num,
    uint16_t pkey_ix, ib_qkey_t qkey);

/*
 * MODIFY CHANNEL ATTRIBUTE FUNCTIONs.
 */

/*
 * ibt_pause_sendq
 * ibt_unpause_sendq
 *	Place the send queue of the specified channel into the send queue
 *	drained state.
 *	Applicable for both RC and UD channels.
 */
ibt_status_t ibt_pause_sendq(ibt_channel_hdl_t chan,
    ibt_cep_modify_flags_t modify_flags);

ibt_status_t ibt_unpause_sendq(ibt_channel_hdl_t chan);

/*
 * ibt_resize_queues()
 *	Resize the SendQ/RecvQ sizes of a channel.
 *
 *	Applicable for both RC and UD channels.
 */
ibt_status_t ibt_resize_queues(ibt_channel_hdl_t chan, ibt_qflags_t flags,
    ibt_queue_sizes_t *request_sz, ibt_queue_sizes_t *actual_sz);

/*
 * ibt_query_queues()
 *
 *	Query the SendQ/RecvQ sizes of a channel.
 *	Applicable for both RC and UD channels.
 */
ibt_status_t ibt_query_queues(ibt_channel_hdl_t chan,
    ibt_queue_sizes_t *actual_sz);

/*
 * ibt_modify_rdma
 *	Enable/disable RDMA operations.
 *
 *	Applicable for RC channels only.
 */
ibt_status_t ibt_modify_rdma(ibt_channel_hdl_t rc_chan,
    ibt_cep_modify_flags_t modify_flags, ibt_cep_flags_t flags);


/*
 * ibt_set_rdma_resource
 *	Change the number of resources to be used for incoming and outgoing
 *	RDMA reads & Atomics.
 */
ibt_status_t ibt_set_rdma_resource(ibt_channel_hdl_t rc_chan,
    ibt_cep_modify_flags_t modify_flags, uint8_t rdma_ra_out,
    uint8_t rdma_ra_in);

/*
 * ibt_change_port
 *	Change the primary physical port of an RC channel. (This is done only
 *	if HCA supports this capability).  Can only be called on a paused
 *	channel.
 *	Applicable for RC channels only.
 */
ibt_status_t ibt_change_port(ibt_channel_hdl_t rc_chan, uint8_t port_num);


/*
 * SERVICE REGISTRATION FUNCTIONS
 */

/*
 * ibt_register_service()
 * ibt_deregister_service()
 *	Register/deregister a Service (range of Service IDs) with the IBTF.
 *
 * ibt_bind_service()
 * ibt_unbind_service()
 * ibt_unbind_all_services()
 *	Bind a Service to a given port (GID), and optionally create
 *	service record(s) with the SA for ibt_get_paths() to find.
 */
ibt_status_t ibt_register_service(ibt_clnt_hdl_t ibt_hdl,
    ibt_srv_desc_t *service, ib_svc_id_t sid, int num_sids,
    ibt_srv_hdl_t *srv_hdl_p, ib_svc_id_t *ret_sid_p);

ibt_status_t ibt_deregister_service(ibt_clnt_hdl_t ibt_hdl,
    ibt_srv_hdl_t srv_hdl);

ibt_status_t ibt_bind_service(ibt_srv_hdl_t srv_hdl, ib_gid_t gid,
    ibt_srv_bind_t *srv_bind, void *cm_private, ibt_sbind_hdl_t *sb_hdl_p);

ibt_status_t ibt_unbind_service(ibt_srv_hdl_t srv_hdl, ibt_sbind_hdl_t sb_hdl);
ibt_status_t ibt_unbind_all_services(ibt_srv_hdl_t srv_hdl);

/*
 * ibt_cm_delay
 *	A client CM handler/srv_handler function can call this function to
 *	extend its response time to a CM event.
 *	Applicable for RC channels only.
 */
ibt_status_t ibt_cm_delay(ibt_cmdelay_flags_t flags, void *cm_session_id,
    clock_t service_time, void *priv_data, ibt_priv_data_len_t priv_data_len);

/*
 * ibt_cm_proceed
 *
 * An IBT client calls ibt_cm_proceed() to proceed with a connection that
 * previously deferred by the client returning IBT_CM_DEFER on a CM handler
 * callback. CM events that can be deferred and continued with ibt_cm_proceed()
 * are REQ_RCV, REP_RCV, LAP_RCV, and DREQ_RCV.
 *
 * NOTE :
 *
 * Typically CM completes processing of a client's CM handler return, with
 * IBT_CM_DEFER status, before  processing of the corresponding ibt_cm_proceed()
 * is started. However a race exists where by CM may not have completed the
 * client's handler return processing when ibt_cm_proceed() is called by a
 * client. In this case ibt_cm_proceed() will block until processing of the
 * client's CM handler return is complete.
 *
 * A client that returns IBT_CM_DEFER from the cm handler must
 * subsequently make a call to ibt_cm_proceed(). It is illegal to call
 * ibt_cm_proceed() on a channel that has not had the connection
 * establishment deferred.
 *
 * Client cannot call ibt_cm_proceed from the cm handler.
 */
ibt_status_t ibt_cm_proceed(ibt_cm_event_type_t event, void *session_id,
    ibt_cm_status_t status, ibt_cm_proceed_reply_t *cm_event_data,
    void *priv_data, ibt_priv_data_len_t priv_data_len);

/*
 * ibt_cm_ud_proceed
 *
 * An IBT client calls ibt_cm_ud_proceed() to proceed with an
 * IBT_CM_UD_EVENT_SIDR_REQ  UD event that was previously deferred by the
 * client returning IBT_CM_DEFER on a CM UD handler callback.
 * NOTE :
 *
 * Typically CM completes processing of a client's CM handler return, with
 * IBT_CM_DEFER status, before  processing of the corresponding
 * ibt_cm_ud_proceed() is started. However a race exists where by CM may not
 * have completed the client's handler return processing when
 * ibt_cm_ud_proceed() is called by a client. In this case ibt_cm_ud_proceed()
 * will block until processing of the client's CM handler return is complete.
 *
 * A client that returns IBT_CM_DEFER from the cm handler must
 * subsequently make a call to ibt_cm_ud_proceed(). It is illegal to call
 * ibt_cm_ud_proceed() on a channel that has not had the connection
 * establishment deferred.
 *
 * Client cannot call ibt_cm_ud_proceed from the cm handler.
 */
ibt_status_t ibt_cm_ud_proceed(void *session_id, ibt_channel_hdl_t ud_channel,
    ibt_cm_status_t status, ibt_redirect_info_t *redirect_infop,
    void *priv_data, ibt_priv_data_len_t priv_data_len);


/*
 * COMPLETION QUEUES.
 *
 * ibt_alloc_cq_sched()
 *	Reserve CQ scheduling class resources
 *
 * ibt_free_cq_sched()
 *	Free CQ scheduling class resources
 */
ibt_status_t ibt_alloc_cq_sched(ibt_hca_hdl_t hca_hdl,
    ibt_cq_sched_attr_t *attr, ibt_sched_hdl_t *sched_hdl_p);

ibt_status_t ibt_free_cq_sched(ibt_hca_hdl_t hca_hdl,
    ibt_sched_hdl_t sched_hdl);

/*
 * ibt_alloc_cq()
 *	Allocate a completion queue.
 */
ibt_status_t ibt_alloc_cq(ibt_hca_hdl_t hca_hdl, ibt_cq_attr_t *cq_attr,
    ibt_cq_hdl_t *ibt_cq_p, uint_t *real_size);

/*
 * ibt_free_cq()
 *	Free allocated CQ resources.
 */
ibt_status_t ibt_free_cq(ibt_cq_hdl_t ibt_cq);


/*
 * ibt_enable_cq_notify()
 *	Enable notification requests on the specified CQ.
 *	Applicable for both RC and UD channels.
 *
 *	Completion notifications are disabled by setting the completion
 *	handler to NULL by calling ibt_set_cq_handler().
 */
ibt_status_t ibt_enable_cq_notify(ibt_cq_hdl_t ibt_cq,
    ibt_cq_notify_flags_t notify_type);

/*
 * ibt_set_cq_handler()
 *	Register a work request completion handler with the IBTF.
 *	Applicable for both RC and UD channels.
 *
 *	Completion notifications are disabled by setting the completion
 *	handler to NULL. When setting the handler to NULL, no additional
 *	calls to the CQ handler will be initiated.
 *
 *	This function does not otherwise change the state of previous
 *	calls to ibt_enable_cq_notify().
 */
void ibt_set_cq_handler(ibt_cq_hdl_t ibt_cq,
    ibt_cq_handler_t completion_handler, void *arg);

/*
 * ibt_poll_cq()
 *	Poll the specified CQ for the completion of work requests (WRs).
 *	If the CQ contains completed WRs, up to num_wc of them are returned.
 *	Applicable for both RC and UD channels.
 */
ibt_status_t ibt_poll_cq(ibt_cq_hdl_t ibt_cq, ibt_wc_t *work_completions,
    uint_t num_wc, uint_t *num_polled);

/*
 * ibt_query_cq()
 *	Return the total number of entries in the CQ.
 */
ibt_status_t ibt_query_cq(ibt_cq_hdl_t ibt_cq, uint_t *entries,
    uint_t *count_p, uint_t *usec_p, ibt_cq_handler_id_t *hid_p);

/*
 * ibt_query_cq_handler_id()
 *	Return interrupt characteristics of the CQ handler
 */
ibt_status_t ibt_query_cq_handler_id(ibt_hca_hdl_t hca_hdl,
    ibt_cq_handler_id_t hid, ibt_cq_handler_attr_t *attrs);

/*
 * ibt_resize_cq()
 *	Change the size of a CQ.
 */
ibt_status_t ibt_resize_cq(ibt_cq_hdl_t ibt_cq, uint_t new_sz, uint_t *real_sz);

/*
 * ibt_modify_cq()
 *	Change the interrupt moderation values of a CQ.
 *	"count" is number of completions before interrupting.
 *	"usec" is the number of microseconds before interrupting.
 */
ibt_status_t ibt_modify_cq(ibt_cq_hdl_t ibt_cq, uint_t count, uint_t usec,
    ibt_cq_handler_id_t hid);

/*
 * ibt_set_cq_private()
 * ibt_get_cq_private()
 *	Set/get the client private data.
 */
void ibt_set_cq_private(ibt_cq_hdl_t ibt_cq, void *clnt_private);
void *ibt_get_cq_private(ibt_cq_hdl_t ibt_cq);


/*
 * Memory Management Functions.
 *	Applicable for both RC and UD channels.
 *
 * ibt_register_mr()
 * 	Prepares a virtually addressed memory region for use by a HCA. A
 *	description of the registered memory suitable for use in Work Requests
 *	(WRs) is returned in the ibt_mr_desc_t parameter.
 *
 * ibt_register_buf()
 * 	Prepares a memory region described by a buf(9S) struct for use by a
 *	HCA. A description of the registered memory suitable for use in
 *	Work Requests (WRs) is returned in the ibt_mr_desc_t parameter.
 *
 * ibt_query_mr()
 *	Retrieves information about a specified memory region.
 *
 * ibt_deregister_mr()
 *	Remove a memory region from a HCA translation table, and free all
 *	resources associated with the memory region.
 *
 * ibt_reregister_mr()
 * ibt_reregister_buf()
 *	Modify the attributes of an existing memory region.
 *
 * ibt_register_shared_mr()
 *	Given an existing memory region, a new memory region associated with
 *	the same physical locations is created.
 *
 * ibt_sync_mr()
 *	Sync a memory region for either RDMA reads or RDMA writes
 *
 * ibt_alloc_mw()
 *	Allocate a memory window.
 *
 * ibt_query_mw()
 *	Retrieves information about a specified memory window.
 *
 * ibt_free_mw()
 *	De-allocate the Memory Window.
 */
ibt_status_t ibt_register_mr(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_mr_attr_t *mem_attr, ibt_mr_hdl_t *mr_hdl_p, ibt_mr_desc_t *mem_desc);

ibt_status_t ibt_register_buf(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_smr_attr_t *mem_bpattr, struct buf *bp, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mem_desc);

ibt_status_t ibt_query_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_mr_query_attr_t *attr);

ibt_status_t ibt_deregister_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl);

ibt_status_t ibt_reregister_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_mr_attr_t *mem_attr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mem_desc);

ibt_status_t ibt_reregister_buf(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_smr_attr_t *mem_bpattr, struct buf *bp,
    ibt_mr_hdl_t *mr_hdl_p, ibt_mr_desc_t *mem_desc);

ibt_status_t ibt_register_shared_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_smr_attr_t *mem_sattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mem_desc);

ibt_status_t ibt_sync_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_sync_t *mr_segments,
    size_t num_segments);

ibt_status_t ibt_alloc_mw(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_mw_flags_t flags, ibt_mw_hdl_t *mw_hdl_p, ibt_rkey_t *rkey);

ibt_status_t ibt_query_mw(ibt_hca_hdl_t hca_hdl, ibt_mw_hdl_t mw_hdl,
    ibt_mw_query_attr_t *mw_attr_p);

ibt_status_t ibt_free_mw(ibt_hca_hdl_t hca_hdl, ibt_mw_hdl_t mw_hdl);

/*
 * ibt_alloc_lkey()
 * 	Allocates physical buffer list resources for use in memory
 *	registrations.
 *
 *	Applicable for both RC and UD channels.
 */
ibt_status_t ibt_alloc_lkey(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_lkey_flags_t flags, uint_t phys_buf_list_sz, ibt_mr_hdl_t *mr_p,
    ibt_pmr_desc_t *mem_desc_p);


/*
 * Physical Memory Management Functions.
 *	Applicable for both RC and UD channels.
 *
 * ibt_register_phys_mr()
 *	Prepares a physically addressed memory region for use by a HCA.
 *
 * ibt_reregister_phys_mr()
 *	Modify the attributes of an existing memory region.
 */
ibt_status_t ibt_register_phys_mr(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_pmr_attr_t *mem_pattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p);

ibt_status_t ibt_reregister_phys_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_pmr_attr_t *mem_pattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p);


/*
 * Register DMA Memory Region
 */
ibt_status_t ibt_register_dma_mr(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_dmr_attr_t *mem_attr, ibt_mr_hdl_t *mr_hdl_p, ibt_mr_desc_t *mem_desc);


/*
 * Address Translation.
 */

/*
 * ibt_map_mem_area()
 *	Translate a kernel virtual address range into HCA physical addresses.
 *	A set of physical addresses, that can be used with "Reserved L_Key",
 *	register physical,  and "Fast Registration Work Request" operations
 *	is returned.
 */
ibt_status_t ibt_map_mem_area(ibt_hca_hdl_t hca_hdl, ibt_va_attr_t *va_attrs,
    uint_t paddr_list_len, ibt_reg_req_t *reg_req, ibt_ma_hdl_t *ma_hdl_p);

/*
 * ibt_unmap_mem_area()
 *	Un pin physical pages pinned during an ibt_map_mem_area() call.
 */
ibt_status_t ibt_unmap_mem_area(ibt_hca_hdl_t hca_hdl, ibt_ma_hdl_t ma_hdl);

/* ibt_map_mem_iov() */
ibt_status_t ibt_map_mem_iov(ibt_hca_hdl_t hca_hdl,
    ibt_iov_attr_t *iov_attr, ibt_all_wr_t *wr, ibt_mi_hdl_t *mi_hdl);

/* ibt_unmap_mem_iov() */
ibt_status_t ibt_unmap_mem_iov(ibt_hca_hdl_t hca_hdl, ibt_mi_hdl_t mi_hdl);

/*
 * Work Request Functions
 *	Applicable for RC and UD channels.
 *
 * ibt_post_send()
 *	Post send work requests to the specified channel.
 *
 * ibt_post_recv()
 * ibt_post_srq()
 *	Post receive work requests to the specified channel.
 */
ibt_status_t ibt_post_send(ibt_channel_hdl_t chan, ibt_send_wr_t *wr_list,
    uint_t num_wr, uint_t *posted);

ibt_status_t ibt_post_recv(ibt_channel_hdl_t chan, ibt_recv_wr_t *wr_list,
    uint_t num_wr, uint_t *posted);

ibt_status_t ibt_post_srq(ibt_srq_hdl_t srq, ibt_recv_wr_t *wr_list,
    uint_t num_wr, uint_t *posted);


/*
 * Alternate Path Migration Functions.
 *	Applicable for RC channels only.
 *
 *
 * ibt_get_alt_path()
 *	Finds the best alternate path to a specified channel (as determined by
 *	the IBTL) that satisfies the requirements specified in an
 *	ibt_alt_path_attr_t struct.  The specified channel must have been
 *	previously opened successfully using ibt_open_rc_channel.
 *	This function also ensures that the service being accessed by the
 *	channel is available at the selected alternate port.
 *
 *	Note: The apa_dgid must be on the same destination channel adapter,
 *	if specified.
 *
 *
 * ibt_set_alt_path()
 *	Load the specified alternate path. Causes the CM to send an LAP message
 *	to the remote node. If successful, the local channel is updated with
 *	the new alternate path and the channel migration state is set to REARM.
 *	Can only be called on a previously opened RC channel. The channel must
 *	be either in RTS or paused state.
 *
 *
 * ibt_migrate_path()
 *	Force the CI to use the alternate path. The alternate path becomes
 *	the primary path. A new alternate path should be loaded and enabled.
 */
ibt_status_t ibt_get_alt_path(ibt_channel_hdl_t rc_chan, ibt_path_flags_t flags,
    ibt_alt_path_attr_t *attr, ibt_alt_path_info_t *alt_pathp);

ibt_status_t ibt_set_alt_path(ibt_channel_hdl_t rc_chan,
    ibt_execution_mode_t mode, ibt_alt_path_info_t *alt_pinfo, void *priv_data,
    ibt_priv_data_len_t priv_data_len, ibt_ap_returns_t *ret_args);

ibt_status_t ibt_migrate_path(ibt_channel_hdl_t rc_chan);


/*
 * Multicast group Functions.
 *	Applicable for UD channels only.
 */

/*
 * ibt_attach_mcg()
 *	Attaches a UD channel to the specified multicast group. On successful
 *	completion, this channel will be provided with a copy of every
 *	multicast message addressed to the group specified by the MGID
 *	(mcg_info->mc_adds_vect.av_dgid) and received on the HCA port with
 *	which the channel is associated.
 */
ibt_status_t ibt_attach_mcg(ibt_channel_hdl_t ud_chan,
    ibt_mcg_info_t *mcg_info);

/*
 * ibt_detach_mcg()
 *	Detach the specified UD channel from the specified multicast group.
 */
ibt_status_t ibt_detach_mcg(ibt_channel_hdl_t ud_chan,
    ibt_mcg_info_t *mcg_info);

/*
 * ibt_join_mcg()
 *	Join a multicast group.  The first full member "join" causes the MCG
 *	to be created.
 */
ibt_status_t ibt_join_mcg(ib_gid_t rgid, ibt_mcg_attr_t *mcg_attr,
    ibt_mcg_info_t *mcg_info_p,  ibt_mcg_handler_t func, void  *arg);

/*
 * ibt_leave_mcg()
 *	The port associated with the port GID shall be removed from the
 *	multicast group specified by MGID (mc_gid) or from all the multicast
 *	groups of which it is a member if the MGID (mc_gid) is not specified
 *	(i.e. mc_gid.mgid_prefix must have 8-bits of 11111111 at the start of
 *	the GID to identify this as being a multicast GID).
 *
 *	The last full member to leave causes the destruction of the Multicast
 *	Group.
 */
ibt_status_t ibt_leave_mcg(ib_gid_t rgid, ib_gid_t mc_gid, ib_gid_t port_gid,
    uint8_t mc_join_state);

/*
 * ibt_query_mcg()
 *	Request information on multicast groups that match the parameters
 *	specified in mcg_attr. Information on each multicast group is returned
 *	to the caller in the form of an array of ibt_mcg_info_t.
 *	ibt_query_mcg() allocates the memory for this array and returns a
 *	pointer to the array (mcgs_p) and the number of entries in the array
 *	(entries_p). This memory should be freed by the client using
 *	ibt_free_mcg_info().
 */
ibt_status_t ibt_query_mcg(ib_gid_t rgid, ibt_mcg_attr_t *mcg_attr,
    uint_t mcgs_max_num, ibt_mcg_info_t **mcgs_info_p, uint_t *entries_p);

/*
 * ibt_free_mcg_info()
 *	Free the memory allocated by successful ibt_query_mcg()
 */
void ibt_free_mcg_info(ibt_mcg_info_t *mcgs_info, uint_t entries);


/*
 * ibt_register_subnet_notices()
 *	Register a handler to be called for subnet notifications.
 */
void ibt_register_subnet_notices(ibt_clnt_hdl_t ibt_hdl,
    ibt_sm_notice_handler_t sm_notice_handler, void *private);


/*
 * Protection Domain Functions.
 *
 * ibt_alloc_pd()
 * ibt_free_pd()
 * 	Allocate/Release a protection domain
 */
ibt_status_t ibt_alloc_pd(ibt_hca_hdl_t hca_hdl, ibt_pd_flags_t flags,
    ibt_pd_hdl_t *pd);
ibt_status_t ibt_free_pd(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd);

/*
 * P_Key to P_Key Index conversion Functions.
 *
 * ibt_pkey2index_byguid
 * ibt_pkey2index	Convert a P_Key into a P_Key index.
 *
 * ibt_index2pkey_byguid
 * ibt_index2pkey	Convert a P_Key Index into a P_Key.
 */
ibt_status_t ibt_pkey2index(ibt_hca_hdl_t hca_hdl, uint8_t port_num,
    ib_pkey_t pkey, uint16_t *pkey_ix);

ibt_status_t ibt_index2pkey(ibt_hca_hdl_t hca_hdl, uint8_t port_num,
    uint16_t pkey_ix, ib_pkey_t *pkey);

ibt_status_t ibt_pkey2index_byguid(ib_guid_t hca_guid, uint8_t port_num,
    ib_pkey_t pkey, uint16_t *pkey_ix);

ibt_status_t ibt_index2pkey_byguid(ib_guid_t hca_guid, uint8_t port_num,
    uint16_t pkey_ix, ib_pkey_t *pkey);

/*
 *  ibt_ci_data_in()
 *
 *  Pass CI specific userland data for CI objects to the CI.
 */
ibt_status_t ibt_ci_data_in(ibt_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibt_object_handle, void *data_p,
    size_t data_sz);

/*
 *  ibt_ci_data_out()
 *
 *  Obtain CI specific userland data for CI objects.
 */
ibt_status_t ibt_ci_data_out(ibt_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibt_object_handle, void *data_p,
    size_t data_sz);


/*
 * Node Information.
 */

/* Node type : n_node_type */
#define	IBT_NODE_TYPE_CHANNEL_ADAPTER	1	/* HCA or TCA */
#define	IBT_NODE_TYPE_SWITCH		2
#define	IBT_NODE_TYPE_ROUTER		3

typedef struct ibt_node_info_s {
	ib_guid_t	n_sys_img_guid;	/* System Image GUID */
	ib_guid_t	n_node_guid;	/* Node GUID */
	ib_guid_t	n_port_guid;	/* Port GUID */
	uint16_t	n_dev_id;	/* Device ID */
	uint32_t	n_revision;	/* Device Revision */
	uint32_t	n_vendor_id:24;	/* Device Vendor ID */
	uint8_t		n_num_ports;	/* Number of ports on this node. */
	uint8_t		n_port_num;	/* Port number. */
	uint8_t		n_node_type;	/* Node type */
	char		n_description[64]; /* NULL terminated ASCII string */
} ibt_node_info_t;


/*
 * ibt_gid_to_node_info()
 *	Retrieve node information for the specified GID.
 */
ibt_status_t ibt_gid_to_node_info(ib_gid_t gid, ibt_node_info_t *node_info_p);

/*
 * ibt_reprobe_dev
 *	Reprobe properties for IOC device node.
 */
ibt_status_t	ibt_reprobe_dev(dev_info_t *dip);

/*
 * ibt_get_companion_port_gids()
 *
 *	Get list of GID's available on a companion port(s) of the specified
 *	GID or list of GIDs available on a specified Node GUID/System Image
 *	GUID.
 */
ibt_status_t ibt_get_companion_port_gids(ib_gid_t gid, ib_guid_t hca_guid,
    ib_guid_t sysimg_guid, ib_gid_t **gids_p, uint_t *num_gids_p);

/*
 * SHARED RECEIVE QUEUE
 */


/*
 * ibt_alloc_srq()
 *	Allocate a shared receive queue.
 */
ibt_status_t ibt_alloc_srq(ibt_hca_hdl_t hca_hdl, ibt_srq_flags_t flags,
    ibt_pd_hdl_t pd, ibt_srq_sizes_t *sizes, ibt_srq_hdl_t *ibt_srq_p,
    ibt_srq_sizes_t *real_size_p);

/*
 * ibt_free_srq()
 *	Free allocated SRQ resources.
 */
ibt_status_t ibt_free_srq(ibt_srq_hdl_t ibt_srq);

/*
 * ibt_query_srq()
 *	Query a shared receive queue.
 */
ibt_status_t ibt_query_srq(ibt_srq_hdl_t ibt_srq, ibt_pd_hdl_t *pd_p,
    ibt_srq_sizes_t *sizes_p, uint_t *limit_p);

/*
 * ibt_modify_srq()
 *	Modify a shared receive queue.
 */
ibt_status_t ibt_modify_srq(ibt_srq_hdl_t ibt_srq, ibt_srq_modify_flags_t flags,
    uint_t size, uint_t limit, uint_t *real_size_p);

/*
 * ibt_set_srq_private()
 * ibt_get_srq_private()
 *	Set/get the SRQ client private data.
 */
void ibt_set_srq_private(ibt_srq_hdl_t ibt_srq, void *clnt_private);
void *ibt_get_srq_private(ibt_srq_hdl_t ibt_srq);

/*
 * ibt_check_failure()
 * 	Function to test for special case failures
 */
ibt_failure_type_t ibt_check_failure(ibt_status_t status, uint64_t *reserved_p);


/*
 * ibt_hw_is_present() returns 0 when there is no IB hardware actively
 * running.  This is primarily useful for modules like rpcmod which needs a
 * quick check to decide whether or not it should try to use InfiniBand.
 */
int ibt_hw_is_present();

/*
 * Fast Memory Registration (FMR).
 *
 * ibt_create_fmr_pool
 *	Not fast-path.
 *	ibt_create_fmr_pool() verifies that the HCA supports FMR and allocates
 *	and initializes an "FMR pool".  This pool contains state specific to
 *	this registration, including the watermark setting to determine when
 *	to sync, and the total number of FMR regions available within this pool.
 *
 * ibt_destroy_fmr_pool
 *	ibt_destroy_fmr_pool() deallocates all of the FMR regions in a specific
 *	pool.  All state and information regarding the pool are destroyed and
 *	returned as free space once again.  No more use of FMR regions in this
 *	pool are possible without a subsequent call to ibt_create_fmr_pool().
 *
 * ibt_flush_fmr_pool
 *	ibt_flush_fmr_pool forces a flush to occur.  At the client's request,
 *	any unmapped FMR regions (See 'ibt_deregister_mr())') are returned to
 *	a free state.  This function allows for an asynchronous cleanup of
 *	formerly used FMR regions.  Sync operation is also performed internally
 *	by HCA driver, when 'watermark' settings for the number of free FMR
 *	regions left in the "pool" is reached.
 *
 * ibt_register_physical_fmr
 *	ibt_register_physical_fmr() assigns a "free" entry from the FMR Pool.
 *	It first consults the "FMR cache" to see if this is a duplicate memory
 *	registration to something already in use.  If not, then a free entry
 *	in the "pool" is marked used.
 *
 * ibt_deregister_fmr
 *	The ibt_deregister_fmr un-maps the resources reserved from the FMR
 *	pool by ibt_register_physical_fmr().   The ibt_deregister_fmr() will
 *	mark the region as free in the FMR Pool.
 */
ibt_status_t ibt_create_fmr_pool(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_fmr_pool_attr_t *fmr_params, ibt_fmr_pool_hdl_t *fmr_pool_p);

ibt_status_t ibt_destroy_fmr_pool(ibt_hca_hdl_t hca_hdl,
    ibt_fmr_pool_hdl_t fmr_pool);

ibt_status_t ibt_flush_fmr_pool(ibt_hca_hdl_t hca_hdl,
    ibt_fmr_pool_hdl_t fmr_pool);

ibt_status_t ibt_register_physical_fmr(ibt_hca_hdl_t hca_hdl,
    ibt_fmr_pool_hdl_t fmr_pool, ibt_pmr_attr_t *mem_pattr,
    ibt_mr_hdl_t *mr_hdl_p, ibt_pmr_desc_t *mem_desc_p);

ibt_status_t ibt_deregister_fmr(ibt_hca_hdl_t hca, ibt_mr_hdl_t mr_hdl);

/*
 * IP SUPPORT
 */

/*
 * IP get_paths
 * Returns an array (or single) of paths and source IP addresses. In the
 * simplest form just the destination IP address is specified, and one path
 * is requested, then one ibt_path_info_t struct and one source IP.
 *
 * More than one path can be requested to a single destination, in which case
 * the requested number of ibt_path_info_t's are returned, and the same
 * number of SRC IP address, with the first SRC IP address corrosponding
 * to the first ibt_path_info_t, etc.
 *
 * Restrictions on the source end point can be specified, in the form of a
 * source IP address (this implicitly defines the HCA, HCA port and Pkey)
 * HCA, HCA port, and sgid (implicitly defines HCA and HCA port).
 * Combinations are allowed but they  must be consistent.
 *
 * Path attributes can also be specified, these can also affect local HCA
 * selection.
 *
 * ibt_get_ip_paths()  internally does (among other things):
 *
 *   o ibt_get_list_of_ibd_ipaddr_and_macaddr( OUT list_ipaddr_macaddr)
 *
 *   o extract_pkey_and_sgid(IN list_ipaddr_macaddr, OUT list_pkey_and_sgid)
 *
 *   o map_dst_ip_addr(IN dst_ip_addr, OUT dst_pkey, OUT dgid) - See Note
 *
 *   o filter_by_pkey(IN list_pkey_and_sgid, IN dst_pkey, OUT list_of_sgid)
 *
 *   o do_multipath_query(IN list_of_sgid, IN dst_pkey, IN dgid, OUT path_list)
 *
 *   o pick_a_good_path(IN path_list, OUT the_path)
 *
 *   o find_matching_src_ip(IN the_path, IN list_ipaddr_macaddr, OUT src_ip)
 *
 * The ibd instance which got the ARP response is only on one P_Key
 * knowing the ibd instance (or which IPonIB MCG) got the ARP response
 * determins the P_Key associated with a dgid. If the proposedi "ip2mac()"
 * API is used to get an IP to GID translations, then returned 'sockaddr_dl'
 * contains the interface name and index.
 *
 *
 * Example:
 *   ip_path_attr.ipa_dst_ip = dst_ip_addr;
 *   ip_path_attr.ipa_ndst = 1;
 *   ip_path_attr.ipa_max_paths = 1;
 *
 *   status = ibt_get_ip_paths(clnt_hdl, flags, &ip_path_attr, &paths,
 *      &num_paths_p, &src_ip);
 *
 *   sid = ibt_get_ip_sid(protocol_num, dst_port);
 *   path_info->sid = sid;
 *
 *   ip_cm_info.src_addr = src_ip;
 *   ip_cm_info.dst_addr = dst_ip_addr;
 *   ip_cm_info.src_port = src_port
 *
 *   ibt_format_ip_private_data(ip_cm_info, priv_data_len, &priv_data);
 *   ibt_open_rc_channel(chan, private_data);
 */
typedef struct ibt_ip_path_attr_s {
	ibt_ip_addr_t		*ipa_dst_ip;		/* Required */
	ibt_ip_addr_t		ipa_src_ip;		/* Optional */
	ib_guid_t		ipa_hca_guid;		/* Optional */
	uint8_t			ipa_hca_port_num;	/* Optional */
	uint8_t			ipa_max_paths;		/* Required */
	uint8_t			ipa_ndst;		/* Required */
	uint8_t			ipa_sl:4;		/* Optional */
	ibt_mtu_req_t		ipa_mtu;		/* Optional */
	ibt_srate_req_t		ipa_srate;		/* Optional */
	ibt_pkt_lt_req_t	ipa_pkt_lt;		/* Optional */
	uint_t			ipa_flow:20;		/* Optional */
	uint8_t			ipa_hop;		/* Optional */
	uint8_t			ipa_tclass;		/* Optional */
	zoneid_t		ipa_zoneid;	/* Default 0 = Global Zone */
} ibt_ip_path_attr_t;

/*
 * Path SRC IP addresses
 */
typedef struct ibt_path_ip_src_s {
	ibt_ip_addr_t	ip_primary;
	ibt_ip_addr_t	ip_alternate;
} ibt_path_ip_src_t;


ibt_status_t ibt_get_ip_paths(ibt_clnt_hdl_t ibt_hdl, ibt_path_flags_t flags,
    ibt_ip_path_attr_t *attr, ibt_path_info_t *paths_p, uint8_t *num_paths_p,
    ibt_path_ip_src_t *src_ip_p);

/*
 * ibt_get_src_ip()
 *	Get List of IP-Address that matches the parameters specified in
 *	srcip_attr.  As a given MAC address can have both IPv4 and IPv6
 *	addressed configured, caller can optional request to return only
 *	the desired family by specifying the "sip_family" field.  If
 *	"sip_family" is AF_UNSPEC, then all assigned IP address (IPv4
 *	and/or IPv6) will be returned. In case of IPv6 address, scope_id
 *	for that specific address will also be returned.
 *	"sip_zoneid" will specify the zones the user is interested in.
 *
 *	Information on each ip-address is returned to the caller in the
 *	form of an array of ibt_srcip_info_t.  ibt_get_src_ip() allocates the
 *	memory for this array and returns a pointer to the array (src_info_p)
 *	and the number of entries in the array (entries_p). This memory
 *	should be freed by the client using ibt_free_srcip_info().
 *
 * ibt_free_srcip_info()
 *	Free the memory allocated by successful ibt_get_src_ip()
 */
typedef struct ibt_srcip_attr_s {
	ib_gid_t	sip_gid;	/* REQUIRED: Local Port GID */
	zoneid_t	sip_zoneid;	/* Zero means Global Zone */
	ib_pkey_t	sip_pkey;	/* Optional */
	sa_family_t	sip_family;	/* Optional : IPv4 or IPv6 */
} ibt_srcip_attr_t;

/*
 * ip_flag : Flag to indicate whether the returned list of ip-address
 * has any duplicate records.
 */
#define	IBT_IPADDR_NO_FLAGS	0
#define	IBT_IPADDR_DUPLICATE	1

typedef struct ibt_srcip_info_s {
	ibt_ip_addr_t	ip_addr;
	zoneid_t	ip_zoneid;	/* ZoneId of this ip-addr */
	uint_t		ip_flag;	/* Flag to indicate any gotchas */
} ibt_srcip_info_t;

ibt_status_t ibt_get_src_ip(ibt_srcip_attr_t *srcip_attr,
    ibt_srcip_info_t **src_info_p, uint_t *entries_p);

void ibt_free_srcip_info(ibt_srcip_info_t *src_info, uint_t entries);


/*
 * Callback function that can be used in ibt_aget_ip_paths(), a Non-Blocking
 * version of ibt_get_ip_paths().
 */
typedef void (*ibt_ip_path_handler_t)(void *arg, ibt_status_t retval,
    ibt_path_info_t *paths_p, uint8_t num_paths, ibt_path_ip_src_t *src_ip_p);

/*
 * Find path(s) to a given destination or service asynchronously.
 * ibt_aget_ip_paths() is a Non-Blocking version of ibt_get_ip_paths().
 */
ibt_status_t ibt_aget_ip_paths(ibt_clnt_hdl_t ibt_hdl, ibt_path_flags_t flags,
    ibt_ip_path_attr_t *attr, ibt_ip_path_handler_t func, void  *arg);

/*
 * IP RDMA protocol functions
 */

/*
 * IBTF manages the port number space for non well known ports. If a ULP
 * is not using TCP/UDP and a well known port, then ibt_get_ip_sid() returns
 * an sid based on the IP protocol number '0' (reserved) and an IBTF assigned
 * port number.  ibt_release_ip_sid() should be used to release the hold
 * of SID created by ibt_get_ip_sid().
 */
ib_svc_id_t ibt_get_ip_sid(uint8_t protocol_num, in_port_t dst_port);
ibt_status_t ibt_release_ip_sid(ib_svc_id_t sid);

uint8_t ibt_get_ip_protocol_num(ib_svc_id_t sid);
in_port_t ibt_get_ip_dst_port(ib_svc_id_t sid);

/*
 * Functions to format/extract the RDMA IP CM private data
 */
typedef struct ibt_ip_cm_info_s {
	ibt_ip_addr_t	src_addr;
	ibt_ip_addr_t	dst_addr;
	in_port_t	src_port;
} ibt_ip_cm_info_t;

/*
 * If a ULP is using IP addressing as defined by the RDMA IP CM Service IBTA
 * Annex 11, then it must always allocate a private data buffer for use in
 * the ibt_open_rc_channel(9F) call. The minimum size of the buffer is
 * IBT_IP_HDR_PRIV_DATA_SZ, if the ULP has no ULP specific private data.
 * This allows ibt_format_ip_private_data() to place the RDMA IP CM service
 * hello message in the private data of the REQ. If the ULP has some ULP
 * specific private data then it should allocate a buffer big enough to
 * contain that data plus an additional IBT_IP_HDR_PRIV_DATA_SZ bytes.
 * The ULP should place its  ULP specific private data at offset
 * IBT_IP_HDR_PRIV_DATA_SZ in the allocated buffer before calling
 * ibt_format_ip_private_data().
 */
ibt_status_t ibt_format_ip_private_data(ibt_ip_cm_info_t *ip_cm_info,
    ibt_priv_data_len_t priv_data_len, void *priv_data_p);
ibt_status_t ibt_get_ip_data(ibt_priv_data_len_t priv_data_len,
    void *priv_data, ibt_ip_cm_info_t *ip_info_p);

/*
 * The ibt_alt_ip_path_attr_t structure is used to specify additional optional
 * attributes when requesting an alternate path for an existing channel.
 *
 * Attributes that are don't care should be set to NULL or '0'.
 */
typedef struct ibt_alt_ip_path_attr_s {
	ibt_ip_addr_t		apa_dst_ip;
	ibt_ip_addr_t		apa_src_ip;
	ibt_srate_req_t		apa_srate;
	ibt_pkt_lt_req_t	apa_pkt_lt;	/* Packet Life Time Request */
	uint_t			apa_flow:20;
	uint8_t			apa_sl:4;
	uint8_t			apa_hop;
	uint8_t			apa_tclass;
	zoneid_t		apa_zoneid;	/* Default 0 = Global Zone */
} ibt_alt_ip_path_attr_t;

ibt_status_t ibt_get_ip_alt_path(ibt_channel_hdl_t rc_chan,
    ibt_path_flags_t flags, ibt_alt_ip_path_attr_t *attr,
    ibt_alt_path_info_t *alt_path);

/*
 * CONTRACT PRIVATE ONLY INTERFACES
 *
 * DO NOT USE THE FOLLOWING FUNCTIONS WITHOUT SIGNING THE CONTRACT
 * WITH IBTF GROUP.
 */

/* Define an Address Record structure (data for ATS service records). */
typedef struct ibt_ar_s {
	ib_gid_t	ar_gid;		/* GID of local HCA port */
	ib_pkey_t	ar_pkey;	/* P_Key valid on port of ar_gid */
	uint8_t		ar_data[16];	/* Data affiliated with GID/P_Key */
} ibt_ar_t;

/*
 * ibt_register_ar()
 * ibt_deregister_ar()
 *	Register/deregister an Address Record with the SA.
 * ibt_query_ar()
 *	Query the SA for Address Records matching either GID/P_Key or Data.
 */
ibt_status_t ibt_register_ar(ibt_clnt_hdl_t ibt_hdl, ibt_ar_t *arp);

ibt_status_t ibt_deregister_ar(ibt_clnt_hdl_t ibt_hdl, ibt_ar_t *arp);

ibt_status_t ibt_query_ar(ib_gid_t *sgid, ibt_ar_t *queryp, ibt_ar_t *resultp);


/*
 * ibt_modify_system_image()
 * ibt_modify_system_image_byguid()
 *	Modify specified HCA's system image GUID.
 */
ibt_status_t ibt_modify_system_image(ibt_hca_hdl_t hca_hdl, ib_guid_t sys_guid);

ibt_status_t ibt_modify_system_image_byguid(ib_guid_t hca_guid,
    ib_guid_t sys_guid);


/*
 * ibt_modify_port()
 * ibt_modify_port_byguid()
 *	Modify the specified port, or all ports attribute(s).
 */
ibt_status_t ibt_modify_port(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type);

ibt_status_t ibt_modify_port_byguid(ib_guid_t hca_guid, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type);


/*
 * ibt_get_port_state()
 * ibt_get_port_state_byguid()
 *	Return the most commonly requested attributes of an HCA port.
 *	If the link state is not IBT_PORT_ACTIVE, the other returned values
 *	are undefined.
 */
ibt_status_t ibt_get_port_state(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p);

ibt_status_t ibt_get_port_state_byguid(ib_guid_t hca_guid, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p);

/*
 * ibt_alloc_io_mem()
 * ibt_free_io_mem()
 *	Allocate and deallocate dma-able memory.
 */
ibt_status_t ibt_alloc_io_mem(ibt_hca_hdl_t, size_t, ibt_mr_flags_t,
    caddr_t *, ibt_mem_alloc_hdl_t *);

ibt_status_t ibt_free_io_mem(ibt_hca_hdl_t, ibt_mem_alloc_hdl_t);

/*
 * Interfaces to get IB partition information.
 */

typedef struct ibt_part_attr_s {
	datalink_id_t	pa_dlinkid;
	datalink_id_t	pa_plinkid;
	uint8_t		pa_port;
	ib_guid_t	pa_hca_guid;
	ib_guid_t	pa_port_guid;
	ib_pkey_t	pa_pkey;
} ibt_part_attr_t;

void ibt_register_part_attr_cb(
    ibt_status_t (*)(datalink_id_t, ibt_part_attr_t *),
    ibt_status_t (*)(ibt_part_attr_t **, int *));
void ibt_unregister_part_attr_cb(void);

ibt_status_t ibt_get_part_attr(datalink_id_t, ibt_part_attr_t *);
ibt_status_t ibt_get_all_part_attr(ibt_part_attr_t **, int *);
ibt_status_t ibt_free_part_attr(ibt_part_attr_t *, int);


/*
 * ibt_lid_to_node_info()
 *	Retrieve node record information for the specified LID.
 */
ibt_status_t ibt_lid_to_node_info(ib_lid_t lid, ibt_node_info_t *node_info_p);


#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBTI_COMMON_H */
