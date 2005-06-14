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

#ifndef	_SYS_IB_IBTL_IBTI_COMMON_H
#define	_SYS_IB_IBTL_IBTI_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ibti_common.h
 *
 * This file contains the shared/common transport data types and function
 * prototypes.
 */
#include <sys/ib/ibtl/ibtl_types.h>
#include <sys/ib/ibtl/ibti_cm.h>
#include <sys/isa_defs.h>
#include <sys/byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Endian Macros
 *    h2b - host endian to big endian protocol
 *    b2h - big endian protocol to host endian
 *    h2l - host endian to little endian protocol
 *    l2h - little endian protocol to host endian
 */
#if defined(_LITTLE_ENDIAN)
#define	h2b16(x)	(htons(x))
#define	h2b32(x)	(htonl(x))
#define	h2b64(x)	(ddi_swap64(x))
#define	b2h16(x)	(ntohs(x))
#define	b2h32(x)	(ntohl(x))
#define	b2h64(x)	(ddi_swap64(x))

#define	h2l16(x)	(x)
#define	h2l32(x)	(x)
#define	h2l64(x)	(x)
#define	l2h16(x)	(x)
#define	l2h32(x)	(x)
#define	l2h64(x)	(x)

#elif defined(_BIG_ENDIAN)
#define	h2b16(x)	(x)
#define	h2b32(x)	(x)
#define	h2b64(x)	(x)
#define	b2h16(x)	(x)
#define	b2h32(x)	(x)
#define	b2h64(x)	(x)

#define	h2l16(x)	(ddi_swap16(x))
#define	h2l32(x)	(ddi_swap32(x))
#define	h2l64(x)	(ddi_swap64(x))
#define	l2h16(x)	(ddi_swap16(x))
#define	l2h32(x)	(ddi_swap32(x))
#define	l2h64(x)	(ddi_swap64(x))

#else
#error	"what endian is this machine?"
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
typedef enum ibt_version_e {
	IBTI_V1 = 1
} ibt_version_t;

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
	IBT_CLASS_NUM		/* Place holder for class count */
} ibt_clnt_class_t;

#define	IBT_TEST_DEV	999	/* Place holder for modules that test IBTL */

#define	IBT_CLNT_DEVICE_CLASS(class)	((class) == IBT_STORAGE_DEV || \
					(class) == IBT_NETWORK_DEV || \
					(class) == IBT_GENERIC_DEV)

#define	IBT_CLNT_GENERAL_CLASS(class)	((class) == IBT_NETWORK || \
					(class) == IBT_GENERIC || \
					(class) == IBT_USER)

#define	IBT_CLNT_MGMT_CLASS(class)	((class) == IBT_IBMA || \
					(class) == IBT_CM || \
					(class) == IBT_DM || \
					(class) == IBT_TEST_DEV)
/*
 * Event record & status returns for asynchronous events and errors.
 *
 * The table below shows additional details about which async_event
 * struct members are defined.
 *
 *					additional
 *	async_code			async_event fields
 * IBT_EVENT_PATH_MIGRATED		ev_chan_hdl
 * IBT_EVENT_SQD			ev_chan_hdl
 * IBT_ERROR_CATASTROPHIC_CHAN		ev_chan_hdl, ev_fma_ena
 * IBT_ERROR_PATH_MIGRATE_REQ		ev_chan_hdl, ev_fma_ena
 * IBT_ERROR_INVALID_REQUEST_CHAN	ev_chan_hdl, ev_fma_ena
 * IBT_ERROR_ACCESS_VIOLATION_CHAN	ev_chan_hdl, ev_fma_ena
 * IBT_ERROR_CQ				ev_cq_hdl, ev_fma_ena
 * IBT_ERROR_PORT_DOWN			ev_hca_guid, ev_port
 * IBT_EVENT_PORT_UP			ev_hca_guid, ev_port
 * IBT_ERROR_LOCAL_CATASTROPHIC		ev_hca_guid, ev_fma_ena
 * IBT_HCA_ATTACH_EVENT			ev_hca_guid
 * IBT_HCA_DETACH_EVENT			ev_hca_guid
 * IBT_EVENT_LIMIT_REACHED_SRQ		ev_srq_hdl
 * IBT_EVENT_EMPTY_CHAN			ev_chan_hdl
 * IBT_ERROR_CATASTROPHIC_SRQ		ev_srq_hdl, ev_fma_ena
 */
typedef struct ibt_async_event_s {
	uint64_t		ev_fma_ena;		/* FMA Error data */
	ibt_channel_hdl_t	ev_chan_hdl;		/* Channel handle */
	ibt_cq_hdl_t		ev_cq_hdl;		/* CQ handle */
	ib_guid_t		ev_hca_guid;		/* HCA node GUID */
	uint8_t			ev_port;		/* HCA port */
	ibt_srq_hdl_t		ev_srq_hdl;		/* SRQ handle */
} ibt_async_event_t;

/*
 * IBT Client Callback function typedefs.
 *
 * ibt_async_handler_t
 *	Pointer to an async event/error handler function.  This function is
 *	called when an async event/error is detected on a HCA that is being
 *	used by the IBT client driver that registered the function.
 *
 *	clnt_private	An IBTF opaque that is the client handle, and
 *			passed into the IBTF on an ibt_attach() call.
 *			This is likely to be the address of the IBT
 *			client per device soft state structure.
 *
 *	hca_hdl		The IBT handle of the HCA on which the event occurred.
 *
 *	code		Code (ibt_async_code_t) for this async event/error.
 *
 *	event		A pointer to an ibt_async_event_t struct that describes
 *			the event.
 *
 */
typedef void (*ibt_async_handler_t)(void *clnt_private,
    ibt_hca_hdl_t hca_hdl, ibt_async_code_t code, ibt_async_event_t *event);

/*
 * IBT Client Memory Error Callback function typedefs.
 *
 * ibt_memory_handler_t
 *	Pointer to an memory event/error handler function.
 *
 *	clnt_private	An IBTF opaque that is the client handle, and
 *			passed into the IBTF on an ibt_attach() call.
 *			This is likely to be the address of the IBT
 *			client per device soft state structure.
 *
 *	hca_hdl		The IBT handle of the HCA associated with the
 *			memory region or area.
 *
 *	code		Code (ibt_mem_code_t) identifies the event/error
 *			as being associated with a memory region or memory
 *			area.
 *
 *	data		A pointer to an ibt_mem_data_t struct that contains
 *			error information.
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
 * CQ priorities
 * The IBTF will attempt to implement a coarse 3 level priority scheme
 * (IBT_CQ_LOW, IBT_CQ_MEDIUM, IBT_CQ_HIGH) based on the class of client
 * driver. The requested priority is not guaranteed. If a CI implementation
 * has the ability to implement priority CQs, then the IBTF will take advantage
 * of that when calling the CI to create a CQ by passing a priority indicator
 * to the CI.
 */
typedef enum ibt_cq_priority_e {
	IBT_CQ_DEFAULT		= 0x0,
	IBT_CQ_LOW		= 0x1,
	IBT_CQ_MEDIUM		= 0x2,
	IBT_CQ_HIGH		= 0x3,
	IBT_CQ_OPAQUE_1		= 0x4,
	IBT_CQ_OPAQUE_2		= 0x5,
	IBT_CQ_OPAQUE_3		= 0x6,
	IBT_CQ_OPAQUE_4		= 0x7,
	IBT_CQ_OPAQUE_5		= 0x8,
	IBT_CQ_OPAQUE_6		= 0x9,
	IBT_CQ_OPAQUE_7		= 0xA,
	IBT_CQ_OPAQUE_8		= 0xB,
	IBT_CQ_OPAQUE_9		= 0xC,
	IBT_CQ_OPAQUE_10	= 0xD,
	IBT_CQ_OPAQUE_11	= 0xE,
	IBT_CQ_OPAQUE_12	= 0xF,
	IBT_CQ_OPAQUE_13	= 0x10,
	IBT_CQ_OPAQUE_14	= 0x11,
	IBT_CQ_OPAQUE_15	= 0x12,
	IBT_CQ_OPAQUE_16	= 0x13
} ibt_cq_priority_t;

/*
 * Attributes when creating a Completion Queue Scheduling Handle.
 */
typedef struct ibt_cq_sched_attr_s {
	ibt_cq_sched_flags_t	cqs_flags;
	ibt_cq_priority_t	cqs_priority;
	uint_t			cqs_load;
	ibt_sched_hdl_t		cqs_affinity_hdl;
} ibt_cq_sched_attr_t;


/*
 * ibt_cq_handler_t
 *	Pointer to a work request completion handler function.  This function
 *	is called when a WR completes on a CQ that is being used by the IBTF
 *	client driver that registered the function.
 *
 * 	ibt_cq		The IBT CQ handle upon which the completion occurred.
 *
 *	arg		The IBTF client private argument that was specified
 *			when the handler was registered via
 *			ibt_set_cq_handler()
 */
typedef void (*ibt_cq_handler_t)(ibt_cq_hdl_t ibt_cq, void *arg);

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
	IBT_OCHAN_OPAQUE5		= 1 << 8
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
 *	detach(). The ibt_attach() routine takes three input arguments:
 *
 *	mod_infop	Points to the client's module information struct,
 *			which contains amongst other things an
 *			ibt_clnt_class_t that identifies the type of
 *			client, see the definition of ibt_clnt_class_t
 *			for valid classes.
 *
 *	arg		If the Client driver is associated with a device node
 *			then this is the pointer to its device information
 *			structure.  Otherwise this is NULL.
 *
 *	clnt_private	A client private data pointer (probably the client
 *			device soft state struct). This pointer is returned
 *			back to the client in all client callbacks.  This
 *			value is used as the first argument of async callbacks.
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
 *	hca_list_p	NULL or points to an array of ib_guid_t's allocated
 *			by the IBTF.
 *
 *	return value	The number of valid ib_guid_t's returned.
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
 *
 *	hca_list	Pointer to an array of ib_guid_t's allocated by the
 *			IBTF during ibt_get_hca_list().
 *
 *	entries		The number of entries in hca_list (return value
 *			from previous call to ibt_get_hca_list()).
 */
uint_t ibt_get_hca_list(ib_guid_t **hca_list_p);

void ibt_free_hca_list(ib_guid_t *hca_list, uint_t entries);

/*
 * ibt_open_hca()	- Open/Close a HCA. HCA can only be opened/closed
 * ibt_close_hca()	  once. ibt_open_hca() takes a client's ibt handle
 *			  and a GUID and returns a unique IBT client HCA
 *			  handle.
 *
 *	ibt_hdl		The handle returned to the client by the IBTF from
 *			an ibt_attach() call.
 *
 *	hca_guid	The HCA' s node GUID.
 *
 *	hca_hdl		The returned ibt_hca_hdl_t.
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
 *
 *	hca_hdl		Is the HCA handle.
 *
 *	hca_guid	Is the HCA Node GUID.
 *
 *	hca_attrs	Is a pointer to a ibt_hca_attr_t allocated by the
 *			caller, into which the hca attributes are copied.
 *
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
 *	hca_hdl		Is the HCA handle.
 *
 *	hca_guid	Is the HCA Node GUID.
 *
 *	port		Port number to query. If port is 0, all ports are
 *			queried.
 *
 *	port_info_p	Is the address of a pointer to an array of
 *			ibt_hca_portinfo_t structs.
 *
 *	ports_p		The number of ibt_hca_portinfo_t structs returned,
 *			which are pointed to by the returned "port_info_p".
 *
 *	size_p		Size of the memory allocated by IBTF for port_info_p,
 *			to be freed by calling ibt_free_portinfo().
 *
 * ibt_free_portinfo()
 *	Frees the memory allocated for a specified ibt_hca_portinfo_t struct.
 *
 *	port_info	Is the a pointer to an array of ibt_hca_portinfo_t
 *			structs.
 *
 *	size		Memory Size as returned from ibt_query_hca_ports().
 */
ibt_status_t ibt_query_hca_ports(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p);

ibt_status_t ibt_query_hca_ports_byguid(ib_guid_t hca_guid, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p);

void ibt_free_portinfo(ibt_hca_portinfo_t *port_info, uint_t size);

/*
 * ibt_set_hca_private()	- Set/get the client private data.
 * ibt_get_hca_private()
 *
 *	hca_hdl		The ibt_hca_hdl_t of the opened HCA.
 *
 *	clnt_private	The client private data.
 */
void ibt_set_hca_private(ibt_hca_hdl_t hca_hdl, void *clnt_private);
void *ibt_get_hca_private(ibt_hca_hdl_t hca_hdl);

/*
 * ibt_hca_handle_to_guid()
 *	A helper function to retrieve HCA GUID for the specified handle.
 *	Returns HCA GUID on which the specified Channel is allocated. Valid
 *	if it is non-NULL on return.
 *
 *	hca		HCA Handle.
 */
ib_guid_t ibt_hca_handle_to_guid(ibt_hca_hdl_t hca);

/*
 * ibt_hca_guid_to_handle()
 *	A helper function to retrieve a hca handle from a HCA GUID.
 *
 *	ibt_hdl		The handle returned to the client by the IBTF from
 *			an ibt_attach() call.
 *
 *	hca_guid	HCA GUID
 *
 *	hca_hdl		Returned ibt_hca_hdl_t IBT HCA Handle.
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
 *	This function also ensures that the service being accessed by the
 *	channel is available at the selected alternate port.
 *
 *	chan		Existing channel for which alternate path needs
 *			to be found.
 *
 *	flags 		IBT_PATH_NO_FLAGS	If no flags specified, IBTL
 *						assumes IBT_PATH_AVAIL.
 *			IBT_PATH_AVAIL		IBTF will attempt to select
 *						an alternate path that is most
 *						unique to the primary path of
 *						the channel specified, ensuring
 *						that the local port selected
 *						shall be on the local hca of
 *						the existing channel, and the
 *						remote 	port shall be on the
 *						remote hca of the existing
 *						channel.
 *			IBT_PATH_PERF		The IBTF will attempt to select
 *						an alternate path that is
 *						having highest performance
 *						attributes, between the local
 *						hca and remote hca of the
 *						existing channel, but not same
 *						as the primary path of the
 *						existing channel.
 *						IBT_PATH_AVAIL and
 *						IBT_PATH_PERF cannot be
 *						selected together.
 *
 *	attr		Points to an ibt_alt_path_attr_t struct that contains
 *			required and optional attributes.
 *
 *	alt_path	An ibt_alt_path_info_t struct filled in by
 *			ibt_get_alt_path() as output parameters.
 *
 *			pi_alt_cep_path		Alternate Path info.
 *			pi_alt_pkt_lt		Alternate Path Pkt lifetime.
 *
 * A client can specify various desired attributes for the alternate paths,
 * but must specify an existing channel.
 *
 * Required and optional attributes are:
 *
 * Required:
 *	chan		Existing channel for which alternate path needs
 *			to be found.
 *
 * Optional:
 *	flags		optional flags to influence IBTF alternate path
 *			selection.
 *	apa_sgid	Local HCA GID.
 *	apa_dgid	Remote HCA GID.
 *	apa_srate	Static rate.
 *	apa_flow	FlowLabel.
 *	apa_hop		HopLimit.
 *	apa_tclass	Traffic Class.
 *	apa_sl		Service level.
 * Note:
 *	The pa_dgid must be on the same destination channel adapter,
 *	if specified.
 *
 */
ibt_status_t ibt_get_alt_path(ibt_channel_hdl_t chan, ibt_path_flags_t flags,
    ibt_alt_path_attr_t *attr, ibt_alt_path_info_t *alt_path);

/*
 * ibt_open_rc_channel
 * 	ibt_open_rc_channel() opens a previously allocated RC communication
 *	channel. The IBTL initiates the channel establishment protocol.
 *
 *	rc_chan		The opaque channel handle returned in a previous call
 *			to ibt_alloc_rc_channel(), specifies the channel to
 *			open.
 *
 *	flags		Open RC Channel flags - ibt_chan_open_flags_t
 *
 *			IBT_OCHAN_NO_FLAGS
 *			IBT_OCHAN_REDIRECTED
 *						Reopen a channel that was
 *						previously redirected with a
 *						IBT_CM_REDIRECT_CM status.
 *			IBT_OCHAN_PORT_REDIRECTED
 *						Reopen a channel that was
 *						previously redirected with a
 *						IBT_CM_REDIRECT_PORT status.
 *			IBT_OCHAN_DUP		Duplicate a connection.
 *						Connect rc_chan to the same
 *						destination, with the same
 *						channel attributes as the
 *						args->rc_dup_channel.
 *			IBT_OCHAN_RETRY		Indicates that
 *						optional->rc_cm_retry_cnt is
 *						used instead of the CM default.
 *
 *	mode		IBT_BLOCKING		Do not return until CM protocol
 *						is completed. Client would be
 *						notified about CM protocol
 *						progress via the oc_cm_handler.
 *
 *			IBT_NONBLOCKING		Return as soon as possible,
 *						after initiating the CM
 *						protocol. Client would be
 *						notified about CM protocol
 *						progress via the oc_cm_handler.
 *
 *	args		Address of an ibt_chan_open_args_s struct.
 *
 *			oc_path			A pointer to an ibt_path_info_t
 *						struct (normally filled in by a
 *						call to ibt_get_paths()), that
 *						contains both primary and
 *						alternate path (optional)
 *						details.
 *			oc_path_retry_cnt	The number of times the remote
 *						side should retry timeout,
 *						packet sequence, etc errors
 *						before posting a completion
 *						error.
 *			oc_path_rnr_retry_cnt	The number of times that the
 *						remote side should retry RNR NAK
 *						errors before posting a
 *						completion.
 *			oc_cm_handler		Handler for CM callbacks. A
 *						handler that minimally supports
 *						the IBT_CM_EVENT_CONN_CLOSED
 *						CM event must be supplied.
 *			oc_cm_clnt_private	First argument to cm_handler
 *						callbacks.
 *			oc_priv_data_len	The length (in bytes) of the
 *						buffer pointed to by
 *						rc_priv_data.
 *			oc_priv_data		Vendor specific data to be sent
 *						in a REQ message.
 *
 *			The following parameters are enabled by corresponding
 *			bits in the "flags" argument.
 *
 *			oc_redirected_gid	If a previous call to open
 *						channel resulted in an
 *						IBT_CM_REDIRECT_PORT rc_status
 *						returned, then the channel
 *						should be reopened with the
 *						rc_redirected_gid set to the
 *						returned gid.
 *						(ibt_arej_info_t->ari_gid).
 *			oc_rdma_ra_out		The max RDMA-R/Atomic sent.
 *						Number of RDMA RD's & Atomics
 *						outstanding.
 *			oc_rdma_ra_in		The Incoming RDMA-R/Atomic
 *						Responder resources for handling
 *						incoming RDMA RD's & Atomics.
 *			oc_dup_channel		Duplicate this channel.
 *			oc_cm_redirect_qpn	If a previous call to open
 *			oc_cm_redirect_qkey	channel resulted in an
 *						IBT_CM_REDIRECT_CM rc_status
 *						returned, then ibt_get_paths()
 *						should be called to obtain a
 *						path to the redirected node as
 *						specified in the returned
 *						ibt_arej_info_t->ari_redirect
 *						struct. The channel should then
 *						be re-opened with
 *						oc_cm_redirect_qp set to
 *						ibt_arej_info_t->ari_redirect.
 *						rdi_qpn. And oc_cm_redirect_qkey
 *						to ibt_arej_info_t->ari_redirect
 *						.ari_qkey.
 *
 *	returns		An optional pointer to a ibt_rc_return_s struct. Should
 *			be set if ibt_open_rc_channel() is called in blocking
 *			mode, contains:
 *
 *			rc_rdma_ra_in		Arbitrated responder resources.
 *			rc_rdma_ra_out		Arbitrated initiator depth.
 *			rc_arej_info		Valid for some cm status returns
 *						(see ibt_arej_info_t definition)
 *						contains additional error
 *						information.
 *			rc_status		Indicates if the channel was
 *						opened successfully. If the
 *						channel was not opened the
 *						status code gives an indication
 *						why.
 *			rc_failover_status	Failover Port status:
 *						  IBT_CM_FAILOVER_ACCEPT
 *						  IBT_CM_FAILOVER_REJ_NOTSUPP
 *						  IBT_CM_FAILOVER_REJ
 *						Only valid if an alternate path
 *						was supplied.
 *			rc_priv_data_len	The length (in bytes) of the
 *						buffer pointed to by
 *						rc_priv_data.
 *			rc_priv_data		REP private data.
 *
 *	This function can execute in blocking or non blocking modes. In non
 *	blocking mode the function returns immediately. An IBT client channel
 *	handler function is called with a status code that indicates if the
 *	channel was opened successfully. If the channel was not opened, the
 *	status code gives an indication why. For blocking mode the function
 *	does not return until the channel is either opened successfully or the
 *	attempt to open the channel is terminated by the IBTF.
 *
 *	If ibt_open_rc_channel() returns with an IBT_CM_FAILURE status
 *	and rc_status is IBT_CM_DUP_CONN_REQ then remote node is initiating a
 * 	simultaneous duplicate connection to this host, and that CM has
 *	deferred to it. The local host cm handler will be called with a
 *	REQ RCVD event.
 *
 *	If connection establishment is successful, then channel is returned
 *	in IBT_STATE_RTS Operational (ie., RTS) state. If connection
 *	establishment fails, then the channel is returned either in
 *	IBT_STATE_INIT or IBT_STATE_ERROR state. If channel is returned in
 *	IBT_STATE_INIT, then client can attempt to reopen the channel based
 *	on failure status and returned error data. If the channel is returned
 *	in IBT_STATE_ERROR, then it is not possible to attempt a reopen. The
 *	channel is returned in IBT_STATE_ERROR for the following rc_status
 *	codes:
 *		IBT_CM_CI_FAILURE
 *		IBT_CM_CHAN_INVALID_STATE
 *
 *	Note : Aborting a connection establishment by calling
 *	ibt_close_rc_channel() results in the channel being returned in
 *	IBT_STATE_ERROR.
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
 *
 *	rc_chan			The opaque RC channel handle.
 *
 *	mode			IBT_BLOCKING	Do not return until completed.
 *				IBT_NONBLOCKING	Return as soon as possible. The
 *						oc_cm_handler is called with
 *						the IBT_CM_EVENT_CONN_CLOSED
 *						event when the close operation
 *						is complete.
 *
 *	priv_data		A Pointer to a byte array that contains the
 *				data that to be placed in the DREQ.
 *
 *	priv_data_len		The length (in bytes) of the buffer pointed to
 *				by priv_data. Should be less or equal to
 *				IBT_DREQ_PRIV_DATA_SZ
 *
 *	ret_status		Close status can be one of:
 *					IBT_CM_CLOSED_DREP_RCVD
 *					IBT_CM_CLOSED_TIMEOUT
 *					IBT_CM_CLOSED_DUP
 *					IBT_CM_CLOSED_ABORT
 *
 *	ret_priv_data		Only valid if called in IBT_BLOCKING mode.
 *				Should be NULL if the caller does not require
 *				return private data, otherwise should point to
 *				a byte array which is <= IBT_DREP_PRIV_DATA_SZ.
 *
 *	ret_priv_data_len_p	Only valid if called in IBT_BLOCKING mode.
 *				On input, the maximum number of bytes of
 *				private data to be copied into ret_priv_data.
 *				Upon return, this value is updated to the
 *				actual number of bytes copied (may be 0
 *				because of a DREQ timeout or DREQ crossover).
 *
 * If ibt_close_rc_channel() is called  with mode set to IBT_NONBLOCKING,
 * then it returns immediately, and the caller's CM handler function is called
 * to indicate completion of the channel close operation. The cm handler may be
 * called before returning from a NON-BLOCKING ibt_close_rc_channel.
 *
 * If ibt_close_rc_channel is called before connection is established, then
 * CM shall attempt to abort the connection establishment process. If CM could
 * successfully abort the connection establishment that is in progress, the
 * client would be notified via cm handler as well as from the return status
 * of a blocking ibt_open_rc-Channel.
 *
 * Client must not call ibt_close_rc_channel from cm callback either to close
 * an established channel or to abort an in-progress connection establishment.
 *
 * If channel is associated with a valid connection and connection closure is
 * successful, then channel is returned in error state.
 *
 * ibt_close_rc_channel may return failure, if client has already been notified
 * about connection closure via cm handler.
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
 *
 *	rc_chan		The opaque RC channel handle.
 *
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
 *      rc_chan      A channel handle returned from
 *                   ibt_alloc_rc_channel.
 *
 *      control      Control flags. Enables RDMA read, RDMA write and atomic
 *                   operations.  Each flag needs to explicitly be set to
 *                   enable the operation  (IBT_CEP_RDMA_RD, IBT_CEP_RDMA_WR
 *                   or IBT_CEP_ATOMIC). If none of these are desired,
 *                   IBT_CEP_NO_FLAGS can be specified.
 *
 *      hca_port_num HCA port number. Specifies the HCA port to associate
 *                   the recycled channel with. This should be set to the
 *                   port indicated in the pi_prim_cep_path of the
 *                   ibt_path_info_t returned by ibt_get_paths for a
 *                   destination to be reached using this channel.
 *
 *     func          NULL or a pointer to an ibt_recycle_handler_t function
 *                   to call when ibt_recycle_rc() completes. If
 *                   'func' is not NULL then ibt_recycle_rc() will
 *                   return as soon as possible after initiating the
 *                   recycling process. 'func' is then called when the
 *                   process completes. An ibt_recycle_handler_t function is
 *                   defined as:
 *
 *                   void func(ibt_status_t ibt_status, void *arg)
 *
 *     			ibt_status	The operation status for ibt_recycle_rc.
 *
 *     arg           The argument to 'func'.
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
 *
 *      ud_chan		A channel handle returned from ibt_alloc_ud_channel.
 *
 *      hca_port_num	HCA port number. Specifies the HCA port to associate
 *			the recycled channel with. This should be set to the
 *			port indicated in the pi_prim_cep_path of the
 *			ibt_path_info_t returned by ibt_get_paths() for a
 *			destination to be reached using this channel.
 *
 *	pkey_ix		Partition key index.
 *
 *	qkey		Queue Key (Q_Key).
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
 *
 *	chan		A previously allocated channel handle.
 *
 *	modify_flags	Channel End Point (CEP) Modify Flags.
 *
 *			IBT_CEP_SET_SQD_EVENT	When this is set, a call to
 *						the client's async handler is
 *						made after the Send Queue has
 *						Drained.
 */
ibt_status_t ibt_pause_sendq(ibt_channel_hdl_t chan,
    ibt_cep_modify_flags_t modify_flags);

ibt_status_t ibt_unpause_sendq(ibt_channel_hdl_t chan);

/*
 * ibt_resize_queues()
 *	Resize the SendQ/RecvQ sizes of a channel.
 *
 *	Applicable for both RC and UD channels.
 *
 *	chan		A previously allocated channel handle.
 *
 *	flags
 *			IBT_SEND_Q	Operation applies to the SendQ
 *			IBT_RECV_Q	Operation applies to the RecvQ
 *
 *	request_sz	This is the address of an ibt_queue_size_s struct that
 *			contains:
 *			sq_sz		Requested new SendQ size.
 *			rq_sz		Requested new RecvQ size.
 *
 *	actual_sz	NULL or a pointer to ibt_queue_size_s struct to
 *			return new queue sizes.
 *			sq_sz		Returned new SendQ size.
 *			rq_sz		Returned new RecvQ size.
 */
ibt_status_t ibt_resize_queues(ibt_channel_hdl_t chan, ibt_qflags_t flags,
    ibt_queue_sizes_t *request_sz, ibt_queue_sizes_t *actual_sz);

/*
 * ibt_query_queues()
 *
 *	Query the SendQ/RecvQ sizes of a channel.
 *	Applicable for both RC and UD channels.
 *
 *	chan		A previously allocated channel handle.
 *
 *	actual_sz	The address of a ibt_queue_size_s struct where
 *			queue sizes are returned.
 *			sq_sz		Returned new SendQ size.
 *			rq_sz		Returned new RecvQ size.
 */
ibt_status_t ibt_query_queues(ibt_channel_hdl_t chan,
    ibt_queue_sizes_t *actual_sz);

/*
 * ibt_modify_rdma
 *	Enable/disable RDMA operations.
 *
 *	Applicable for RC channels only.
 *
 *	rc_chan		A previously allocated channel handle.
 *
 *	modify_flags	Flags that identify which flags in the "flags"
 *			argument are to be modified.
 *
 *			IBT_CEP_SET_RDMA_R	Enable/Disable RDMA RD
 *			IBT_CEP_SET_RDMA_W	Enable/Disable RDMA WR
 *			IBT_CEP_SET_ATOMIC	Enable/Disable Atomics
 *
 *	flags		Channel End Point (CEP) Disable Flags.
 *			A flag that is not specified means "enable".
 *
 *			IBT_CEP_RDMA_RD	Enable incoming RDMA RD's
 *			IBT_CEP_RDMA_WR	Enable incoming RDMA WR's
 *			IBT_CEP_ATOMIC	Enable incoming Atomics.
 */
ibt_status_t ibt_modify_rdma(ibt_channel_hdl_t rc_chan,
    ibt_cep_modify_flags_t modify_flags, ibt_cep_flags_t flags);


/*
 * ibt_set_rdma_resource
 *	Change the number of resources to be used for incoming and outgoing
 *	RDMA reads & Atomics.
 *
 *	rc_chan		A previously allocated channel handle.
 *
 *	modify_flags	Identifies which attribute of the channel is to be
 *			modified, one or both of:
 *
 *			IBT_CEP_SET_RDMARA_OUT
 *			IBT_CEP_SET_RDMARA_IN
 *
 *	rdma_ra_out	Outgoing RDMA Reads/Atomics
 *
 *	rdma_ra_in	Incoming RDMA Reads/Atomics
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
 *
 *	rc_chan		A previously allocated RC channel handle.
 *
 *	port_num	New HCA port
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
 *
 *	flags		Indicates what CM message processing is being delayed
 *			by the CM handler, valid values are:
 *				IBT_CM_DELAY_REQ
 *				IBT_CM_DELAY_REP
 *				IBT_CM_DELAY_LAP
 *
 *	cm_session_id	The session ID that was passed to the
 *			client srv_handler by the CM.
 *
 *	service_time	The extended service time in microseconds.
 *
 *	priv_data	Optional private data for the MRA MAD.
 *
 *	priv_data_len	Number of bytes in priv_data.
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
 *  Arguments:
 *
 *	event		The event being continued, valid values are:
 *
 *				IBT_CM_EVENT_REQ_RCV
 *				IBT_CM_EVENT_REP_RCV
 *				IBT_CM_EVENT_LAP_RCV
 *				IBT_CM_EVENT_DREQ_RCV
 *
 *	cm_session_id	The session ID that was passed to the client srv_handler
 *			by the CM.
 *
 *	status		Indicates if the client is accepting/rejecting the CM
 *			event, valid values are:
 *
 *			  IBT_CM_ACCEPT		The CM handler function accepts
 *						the specified event.
 *			  IBT_CM_REJECT		The CM handler rejects the
 *						specified event. The CM should
 *						issue a REJ message with a
 *						reason of IBT_CM_REJ_CONSUMER.
 *			  IBT_CM_REDIRECT	The CM handler is redirecting a
 *						REQ indicating that the service
 *						is provided at another port.
 *			  IBT_CM_NO_CHANNEL	Unable to allocate a channel.
 *
 *	cm_event_data	A pointer to a ibt_cm_proceed_reply_t union that
 *			contains:
 *
 *			  rep	should only be updated for a cm_event of
 *				REQ_RCV if the client/server accepts the
 *				connection, contains:
 *
 *				channel		An ibt_channel_hdl_t. The
 *						service handler function, if it
 *						decides to accept the
 *						connection request, should
 *						allocate a ibt_channel_hdl_t
 *						over which the connection will
 *						be established and return the
 *						handle to the CM via this
 *						parameter.
 *				rdma_ra_out	Initiator depth - the max
 *						RDMA-R/Atomic sent Number of
 *						RDMA RD's & Atomics outstanding
 *				rdma_ra_in   	Responder resources - Incoming
 *						RDMA-R/Atomics.
 *
 *			  rej	should only be updated for cm_event of REQ_RCV
 *				or REP_RCV if the client/server rejects the
 *				connection. Contains Additional reject
 *				information.
 *
 *			  apr	Should be updated for cm_event of LAP_RCV.
 *				Contains Alternate path response data
 *
 *	priv_data	A pointer to optional private data to be placed in the
 *			next reply message generated by CM. Should be NULL if
 *			there is no private data.
 *
 *	priv_data_len	The Number of bytes in priv_data. Should be 0 if
 *			priv_data is NULL.
 *
 * NOTE :
 *
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
 *
 *  Arguments:
 *
 *	cm_session_id	The session ID that was passed to the client CM handler
 *			by the CM.
 *
 *	ud_channel	If the client handler has decided to accept the service
 *			request, ud_channel is the destination channel to which
 *			the remote node should use to communicate with the
 *			service.
 *
 *	status		Indicates if the client is accepting/rejecting the CM
 *			event, valid values are:
 *
 *			  IBT_CM_ACCEPT		The CM handler function accepts
 *						the specified event.
 *			  IBT_CM_REJECT		The CM handler rejects the
 *						specified event. The CM should
 *						issue a REJ message with a
 *						reason of IBT_CM_REJ_CONSUMER.
 *			  IBT_CM_REDIRECT	The CM handler is redirecting a
 *						REQ indicating that the service
 *						is provided at another port.
 *			  IBT_CM_NO_CHANNEL	Unable to allocate a channel.
 *
 *	redirect_infop	A pointer to a ibt_redirect_info_t structure that
 *			should only be updated if the client is Redirecting
 *			the IBT_CM_UD_EVENT_SIDR_REQ request.
 *
 *	priv_data	A pointer to optional private data to be placed in the
 *			next reply message generated by CM. Should be NULL if
 *			there is no private data.
 *
 *	priv_data_len	The Number of bytes in priv_data. Should be 0 if
 *			priv_data is NULL.
 *
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
 * 	hca_hdl		The HCA handle.
 *
 *	attr		A pointer to a ibt_cq_sched_attr_t that contains:
 *
 *			flags
 *			    IBT_CQS_NO_FLAGS, IBT_CQS_USER_MAP,
 *			    IBT_CQS_DEFER_ALLOC, IBT_CQS_WARM_CACHE,
 *			    IBT_CQS_AFFINITY or IBT_CQS_SCHED_GROUP
 *
 *			priority
 *			    The IBTF will attempt to implement a coarse 3 level
 *			    priority scheme (IBT_CQ_LOW, IBT_CQ_MEDIUM,
 *			    IBT_CQ_HIGH) based on the class of client driver.
 *			    This parameter is optional and should be specified
 *			    as IBT_CQ_DEFAULT if a default indicator is desired.
 *
 *			load
 *			    Expected CQ load in class. 0 = unspecified If not
 *			    zero, is increasing the expected CQ load.
 *
 *			affinity_hdl
 *			    Valid if IBT_CQ_AFFINITY set.
 *
 *	sched_hdl_p	Returned scheduling handle.
 *
 * ibt_free_cq_sched()
 *	Free CQ scheduling class resources
 *
 * 	hca_hdl		The HCA handle.
 *	sched_hdl	Scheduling handle returned from ibt_alloc_cq_sched.
 *	load		CQ load being removed
 */
ibt_status_t ibt_alloc_cq_sched(ibt_hca_hdl_t hca_hdl,
    ibt_cq_sched_attr_t *attr, ibt_sched_hdl_t *sched_hdl_p);

ibt_status_t ibt_free_cq_sched(ibt_hca_hdl_t hca_hdl,
    ibt_sched_hdl_t sched_hdl, uint_t load);

/*
 * ibt_alloc_cq()
 *	Allocate a completion queue.
 *
 *	hca_hdl		The CQ's HCA
 *
 *	cq_attr		- cq_size	The minimum acceptable size of the CQ.
 *			- cq_sched	The scheduling class hint from
 *					ibt_alloc_cq_sched(), NULL if not
 *					specified.
 *			- cq_flags	IBT_CQ_NO_FLAGS,
 *					IBT_CQ_HANDLER_IN_THREAD,
 *					IBT_CQ_USER_MAP or IBT_CQ_DEFER_ALLOC.
 *
 * 	ibt_cq_p	Address for the CQ handle return value.
 *
 * 	real_size	The actual size (number of entries) of the CQ.
 *
 */
ibt_status_t ibt_alloc_cq(ibt_hca_hdl_t hca_hdl, ibt_cq_attr_t *cq_attr,
    ibt_cq_hdl_t *ibt_cq_p, uint_t *real_size);

/*
 * ibt_free_cq()
 *	Free allocated CQ resources.
 *
 * 	ibt_cq		A CQ handle returned from an ibt_alloc_cq() call.
 */
ibt_status_t ibt_free_cq(ibt_cq_hdl_t ibt_cq);


/*
 * ibt_enable_cq_notify()
 *	Enable notification requests on the specified CQ.
 *	Applicable for both RC and UD channels.
 *
 * 	ibt_cq		The CQ handle.
 *
 *	notify_type 	Enable notifications for all (IBT_NEXT_COMPLETION)
 * 			completions, or the next Solicited completion
 *			(IBT_NEXT_SOLICITED) only.
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
 * 	ibt_cq			The CQ handle.
 *
 *	completion_handler	The completion handler.
 *
 *	arg			The IBTF client private argument to be passed
 *				back to the client when calling the CQ
 *				completion handler.
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
 *
 * 	ibt_cq			The CQ handle.
 *
 *	work_completions	Address of the array of work completions.
 *
 *	num_wc			Size of the work_completions array, which
 *				is the maximum number of WCs to be returned.
 *
 *	num_polled		Address to store the number of completions
 *				successfully returned.  "num_polled" may be
 *				NULL when "num_wc" is 1 because the number
 *				of returned WCs can be deduced from the
 *				function's return value (IBT_SUCCESS implies 1,
 *				otherwise 0 WCs were returned).
 */
ibt_status_t ibt_poll_cq(ibt_cq_hdl_t ibt_cq, ibt_wc_t *work_completions,
    uint_t num_wc, uint_t *num_polled);

/*
 * ibt_query_cq()
 *	Return the total number of entries in the CQ.
 *
 *	ibt_cq		The CQ handle.
 *
 *	entries		Address to return the size of the CQ.
 *
 */
ibt_status_t ibt_query_cq(ibt_cq_hdl_t ibt_cq, uint_t *entries);

/*
 * ibt_resize_cq()
 *	Change the size of a CQ.
 *
 *	ibt_cq		The CQ handle.
 *
 *	new_sz		Requested size of CQ on a resize operation.
 *
 *	real_sz		The actual size of the resized CQ.
 */
ibt_status_t ibt_resize_cq(ibt_cq_hdl_t ibt_cq, uint_t new_sz, uint_t *real_sz);

/*
 * ibt_set_cq_private()
 * ibt_get_cq_private()
 *	Set/get the client private data.
 *
 *	ibt_cq		The ibt_cq_hdl_t of the allocated CQ.
 *
 *	clnt_private	The client private data.
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
 *
 *	hca_hdl		Is the HCA handle.
 *
 *	pd		A protection domain handle.
 *
 *	bp		A pointer to a buf(9S) struct.
 *
 *	mem_attr	Requested memory region attributes, contains:
 *			  mr_vaddr	The virtual address of the first byte
 *					of the region to be registered.
 *			  mr_len	The length of the region to be
 *					registered.
 *			  as		A pointer to an address space structure.
 *					This parameter should be set to NULL,
 *					which implies kernel address space.
 *			  mr_flags	Access control & reregister flags.
 *
 *	mem_sattr	Requested memory region shared attributes, contains:
 *			  mr_vaddr	The virtual address of the first byte
 *					of the region to be registered.
 *			  mr_flags	Access control & reregister flags.
 *
 *	mem_bpattr	Additional requested memory region attributes used
 *			during ibt_register_buf() and ibt_reregister_buf() are:
 *			  mr_vaddr	The requested IOVA.
 *			  mr_flags	Access control & reregister flags.
 *					If mr_vaddr is supplied, then it should
 *					be indicated by IBT_MR_PHYS_IOVA flag.
 *
 *	mem_desc	Returned memory descriptor, contains:
 *			  md_vaddr	The IOVA of the memory region. For
 *					ibt_register_mr() &
 *					ibt_reregister_mr() this will be the
 *					same as the mem_attr->vaddr.
 *			  md_lkey	The L_Key used for local access.
 *			  md_rkey	The R_Key used for remote access, NULL
 *					if remote access was not requested.
 *
 *	mr_hdl_p	The memory region IBT handle returned from a memory
 *			register call.
 *
 *	rkey		The IBT R_Key handle returned from ibt_alloc_mw.
 *
 *	mr_hdl		IBT Memory Region handle.
 *
 *	mw_hdl		IBT Memory Window handle.
 *
 *	attr		Memory region attributes, returned by
 *			ibt_query_mr(), contains:
 *
 *			  mr_lkey	The L_Key used for local access.
 *			  mr_rkey	The R_Key used for remote access, NULL
 *					if remote access was not requested.
 *			  mr_lbounds	Actual local protection bounds enforced
 *					by the CI.
 *			  mr_rbounds	Actual local protection bounds enforced
 *					by the CI.
 *			  mr_access	Access control flags.
 *	flags		Memory Window alloc flags.
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
 *
 *	hca_hdl		Is the HCA handle.
 *
 *	pd		A protection domain handle.
 *
 *	flags		Access control, specify IBT_LKEY_REMOTE to request
 *			remote access (R_Key returned).
 *
 *	phys_buf_list_sz Requested size of Physical Buffer List (PBL) resources
 *			to be allocated.
 *
 *	mr_hdl_p	The returned IBT memory region IBT handle.
 *
 *	mem_desc_p	Returned memory descriptor, contains:
 *			  pmd_iova		Ignore, returned as NULL.
 *			  pmd_sync_required	Ignore, returned as B_FALSE.
 *			  pmd_lkey		The L_Key used for local access.
 *			  pmd_rkey		The R_Key used for remote
 *						access, NULL if remote access
 *						was not requested.
 *			  pmd_phys_buf_list_sz	Actual size of PBL resources
 *						allocated.
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
 *
 *	hca_hdl		Is the HCA handle.
 *
 *	pd		A protection domain handle.
 *
 *	mem_pattr	Requested memory region physical attributes, contains:
 *			   pmr_iova	The requested IOVA.
 *			   pmr_len	The length of the region to be
 *					registered.
 *			   pmr_offset	Offset of the regions starting iova.
 *					within the 1st physical buffer.
 *			   pmr_flags	Access control & reregister flags.
 *			   pmr_lkey	Reregister only.
 *			   pmr_rkey	Reregister only.
 *			   pmr_num_buf	Num of entries in the mr_buf_list.
 *			   pmr_buf_list	List of physical buffers accessed
 *					as an array.
 *
 *	mr_hdl_p	The returned IBT memory region handle.
 *
 *	mem_desc_p	Returned memory descriptor, contains:
 *			  pmd_iova		Ignore, returned as NULL.
 *			  pmd_sync_required	Ignore, returned as B_FALSE.
 *			  pmd_lkey		The L_Key used for local access.
 *			  pmd_rkey		The R_Key used for remote
 *						access, NULL if remote access
 *						was not requested.
 *			  pmd_phys_buf_list_sz	Actual size of PBL resources
 *						allocated.
 */
ibt_status_t ibt_register_phys_mr(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_pmr_attr_t *mem_pattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p);

ibt_status_t ibt_reregister_phys_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_pmr_attr_t *mem_pattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p);


/*
 * Address Translation.
 */

/*
 * ibt_map_mem_area()
 *	Translate a kernel virtual address range into HCA physical addresses.
 *	A set of physical addresses, that can be used with "Reserved L_Key",
 *	register physical,  and "Fast Registration Work Request" operations
 *	is returned.
 *
 *	hca_hdl		HCA Handle.
 *
 *	va_attrs	A pointer to an ibt_va_attr_t that describes the VA
 *			to be translated.
 *
 *	paddr_list_len	The number of entries in the 'paddr_list_p' array.
 *
 *	paddr_list_p	Array of ibt_phys_buf_t (allocated by the caller), in
 *			which the physical buffers that map the virtual buffer
 *			are returned.
 *
 *	num_paddr_p	The actual number of ibt_phys_buf_t that were returned
 *			in the 'paddr_list_p' array.
 *
 *	ma_hdl_p	Memory Area Handle
 *
 */
ibt_status_t ibt_map_mem_area(ibt_hca_hdl_t hca_hdl, ibt_va_attr_t *va_attrs,
    uint_t paddr_list_len, ibt_phys_buf_t *paddr_list_p, uint_t *num_paddr_p,
    ibt_ma_hdl_t *ma_hdl_p);

/*
 * ibt_unmap_mem_area()
 *	Un pin physical pages pinned during an ibt_map_mem_area() call.
 */
ibt_status_t ibt_unmap_mem_area(ibt_hca_hdl_t hca_hdl, ibt_ma_hdl_t ma_hdl);

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
 *
 *	chan		The opaque channel handle returned in a previous
 *			call to ibt_alloc_rc_channel() & ibt_alloc_ud_channel()
 *
 *	srq		A Shared Receive Queue handle.
 *
 *	wr_list		A pointer to an array of WRs to be posted to the
 *			specified channel.
 *
 *	num_wr		The size of the WR array, which must be greater than 0.
 *
 *	posted		Address to store the number of WRs successfully posted.
 *			When "num_wr" is 1, it can make sense for "posted" to
 *			be NULL because the number of WRs successfully posted
 *			can be deduced from the function's return value
 *			(IBT_SUCCESS implies 1, otherwise 0 WRs were posted).
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
 *
 *	ud_chan		An UD channel handle, obtained from
 *			ibt_alloc_ud_channel(). This is the UD channel handle,
 *			that is to be used to receive data sent to the
 *			multicast group.
 *
 *	mcg_info	A pointer to an ibt_mcg_info_t struct returned from an
 *			ibt_join_mcg() or ibt_query_mcg() call, that identifies
 *			the multicast group to attach this channel to.
 */
ibt_status_t ibt_attach_mcg(ibt_channel_hdl_t ud_chan,
    ibt_mcg_info_t *mcg_info);

/*
 * ibt_detach_mcg()
 *	Detach the specified UD channel from the specified multicast group.
 *
 *	ud_chan		An UD channel handle returned from
 *			ibt_alloc_ud_channel().
 *
 *	mcg_info	A pointer to an ibt_mcg_info_t struct returned from an
 *			ibt_join_mcg() or ibt_query_mcg() call, that identifies
 *			the multicast group to detach this channel from.
 */
ibt_status_t ibt_detach_mcg(ibt_channel_hdl_t ud_chan,
    ibt_mcg_info_t *mcg_info);

/*
 * ibt_join_mcg()
 *	Join a multicast group.  The first full member "join" causes the MCG
 *	to be created.
 *
 *	rgid		The request GID that defines the HCA port from which a
 *			contact to SA Access is performed to add the specified
 *			endport GID ((mcg_attr->mc_pgid) to a multicast group.
 *			If mcg_attr->mc_pgid is null, then this (rgid) will be
 *			treated as endport GID that is to be added to the
 *			multicast group.
 *
 *	mcg_attr	A pointer to an ibt_mcg_attr_t structure that defines
 *			the attributes of the desired multicast group to be
 *			created or joined.
 *
 *	mcg_info_p	A pointer to the ibt_mcg_info_t structure, allocated
 *			by the caller, where the attributes of the created or
 *			joined multicast group are copied.
 *
 *	func		NULL or a pointer to a function to call when
 *			ibt_join_mcg() completes. If 'func' is not NULL then
 *			ibt_join_mcg() will return as soon as possible after
 *			initiating the multicast group join/create process.
 *			'func' is then called when the process completes.
 *
 *	arg		 Argument to the 'func'.
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
 *
 *	rgid		The request GID that defines the HCA port upon which
 *			to send the request to the Subnet Administrator, to
 *			remove the specified port (port_gid) from the multicast
 *			group.  If 'port_gid' is the Reserved GID (i.e.
 *			port_gid.gid_prefix = 0 and port_gid.gid_guid = 0),
 *			then the end-port associated with 'rgid' is removed
 *			from the multicast group.
 *
 *	mc_gid		A multicast group GID as returned from ibt_join_mcg()
 *			call.  This is optional, if not specified (i.e.
 *			mc_gid.mgid_prefix must have 8-bits of 11111111 at the
 *			start of the GID to identify this as being a multicast
 *			GID), then the port is removed from all the multicast
 *			groups of which it is a member.
 *
 *	port_gid	This is optional, if not the Reserved GID (gid_prefix
 *			and gid_guid not equal to 0), then this specifies the
 *			endport GID of the multicast group member being deleted
 *			from the group. If it is the Reserved GID (gid_prefix
 *			and gid_guid equal to 0) then the member endport GID is
 *			determined from 'rgid'.
 *
 *	mc_join_state	The Join State attribute used when the group was joined
 *			using ibt_join_mcg(). This Join State component must
 *			contains at least one bit set to 1 in the same position
 *			as that used during ibt_join_mcg(). i.e. the logical
 *			AND of the two JoinState components is not all zeros.
 *			This Join State component must not have some bits set
 *			which are not set using ibt_join_mcg().
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
 *
 *	rgid		The request GID that defines the HCA port upon which
 *			to send the request to the Subnet Administrator, to
 *			retrieve Multicast Records matching attributes as
 *			specified through 'mcg_attr' argument.
 *
 *	mcg_attr	NULL or a pointer to an ibt_mcg_attr_t structure that
 *			specifies MCG attributes that are to be matched.
 *			Attributes that are not required can be wild carded
 *			by specifying as '0'.
 *
 *	mcgs_max_num	The maximum number of matching multicast groups to
 *			return.  If zero, then all available matching multicast
 *			groups are returned.
 *
 *	mcgs_info_p	The address of an ibt_mcg_info_t pointer, where
 *			multicast group information is returned.  The actual
 *			number of entries filled in the array is returned in
 *			entries_p.
 *
 *	entries_p	The number of ibt_mcg_attr_t entries returned.
 */
ibt_status_t ibt_query_mcg(ib_gid_t rgid, ibt_mcg_attr_t *mcg_attr,
    uint_t mcgs_max_num, ibt_mcg_info_t **mcgs_info_p, uint_t *entries_p);

/*
 * ibt_free_mcg_info()
 *	Free the memory allocated by successful ibt_query_mcg()
 *
 *	mcgs_info	Pointer returned by ibt_query_mcg().
 *
 *	entries		The number of ibt_mcg_info_t entries to free.
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
 *
 *	hca_hdl		The IBT HCA handle.
 *	flags		IBT_PD_NO_FLAGS, IBT_PD_USER_MAP or IBT_PD_DEFER_ALLOC
 *	pd		The IBT PD handle.
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
 *
 *	hca_hdl		HCA Handle.
 *
 *	hca_guid	The HCA Node GUID.
 *
 *	port_num	Port number defining the P_Key table.
 *
 *	pkey		The input P_Key for ibt_pkey2index() or the returned
 *			P_Key for ibt_index2pkey().
 *
 *	pkey_ix		The input P_Key Index for ibt_index2pkey() or
 *			the returned P_Key index for ibt_pkey2index().
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
 *
 *	hca			Identifies the HCA.
 *
 *	flags			IBT_CI_COMPLETE_ALLOC
 *				Finish a deferred alloc.
 *
 *	object			Identifies the type object pointed to by
 *				ibt_object_handle.
 *
 *	ibt_object_handle	The handle of the object to be associated with
 *				the data in.
 *
 *	data_p			Pointer to data passed in to the CI. The buffer
 *				should be allocated by the caller.
 *
 *	data_sz			The size of the buffer pointed to by
 *				data_p.
 */
ibt_status_t ibt_ci_data_in(ibt_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibt_object_handle, void *data_p,
    size_t data_sz);

/*
 *  ibt_ci_data_out()
 *
 *  Obtain CI specific userland data for CI objects.
 *
 *	hca			Identifies the HCA.
 *
 *	flags			IBT_CI_NO_FLAGS.
 *
 *	object			Identifies the type object pointed to by
 *				ibt_object_handle.
 *
 *	ibt_object_handle	The handle of the object to be associated with
 *				the data in.
 *
 *	data_p			Pointer a data buffer in which to return CI
 *				private data. The buffer should be allocated
 *				by the caller.
 *
 *	data_sz			The size of the buffer pointed to by
 *				data_p.
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
 *
 *	gid		Identifies the IB Node and port for which to obtain
 *			node information.
 *
 *	node_info_p	A pointer to an ibt_node_info_t structure (allocated
 *			by the caller) in which to return the node information.
 */
ibt_status_t ibt_gid_to_node_info(ib_gid_t gid, ibt_node_info_t *node_info_p);

/*
 * ibt_reprobe_dev
 *	Reprobe properties for IOC device node.
 *
 *	dip		IBTF Client dip
 *
 * Returns :
 *	IBT_SUCCESS	Successfully initiated a reprobe for device
 *	IBT_NOT_SUPPORTED
 *			Returned for HCA port, VPPA or Pseudo IBTF client
 *	IBT_INSUFF_KERNEL_RESOURCE
 *			Resource allocation failed
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
 *
 *	hca_hdl		The SRQ's HCA
 *
 *	flags		IBT_SRQ_NO_FLAGS, IBT_SRQ_USER_MAP or
 *			IBT_SRQ_DEFER_ALLOC.
 *
 *	pd		A protection domain handle.
 *
 *	sizes		Pointer to an ibt_srq_sizes_t struct, that contains the
 *			SRQ size and max length of SGL of WRs posted to the SRQ.
 *
 * 	ibt_srq_p	Address for the SRQ handle return value.
 *
 * 	real_size_p	Pointer to an ibt_srq_sizes_t struct, that contains the
 *			returned actual SRQ size and max length of SGL of WRs
 *                      posted to the SRQ.
 */
ibt_status_t ibt_alloc_srq(ibt_hca_hdl_t hca_hdl, ibt_srq_flags_t flags,
    ibt_pd_hdl_t pd, ibt_srq_sizes_t *sizes, ibt_srq_hdl_t *ibt_srq_p,
    ibt_srq_sizes_t *real_size_p);

/*
 * ibt_free_srq()
 *	Free allocated SRQ resources.
 *
 * 	ibt_srq		An SRQ handle returned from an ibt_alloc_srq() call.
 */
ibt_status_t ibt_free_srq(ibt_srq_hdl_t ibt_srq);

/*
 * ibt_query_srq()
 *	Query a shared receive queue.
 *
 * 	ibt_srq		An SRQ handle returned from an ibt_alloc_srq() call.
 *
 *	pd_p		The PD associated with the SRQ.
 *
 *	sizes_p		Pointer to an ibt_srq_sizes_t struct, that contains the
 *			SRQ size and max length of SGL of WRs posted to the SRQ.
 *
 *	limit_p		The SRQ WR limit.
 */
ibt_status_t ibt_query_srq(ibt_srq_hdl_t ibt_srq, ibt_pd_hdl_t *pd_p,
    ibt_srq_sizes_t *sizes_p, uint_t *limit_p);

/*
 * ibt_modify_srq()
 *	Modify a shared receive queue.
 *
 * 	ibt_srq		An SRQ handle returned from an ibt_alloc_srq() call.
 *
 *	flags		Modify flags, specifies if SRQ size or SRQ Limit, or
 *			both are to be modified.
 *
 *	size		SRQ size.
 *
 *	limit		The SRQ WR limit.
 *
 *	real_size_p	The returned real size.
 */
ibt_status_t ibt_modify_srq(ibt_srq_hdl_t ibt_srq, ibt_srq_modify_flags_t flags,
    uint_t size, uint_t limit, uint_t *real_size_p);

/*
 * ibt_set_srq_private()
 * ibt_get_srq_private()
 *	Set/get the SRQ client private data.
 *
 *	ibt_srq		The ibt_srq_hdl_t of the allocated SRQ.
 *
 *	clnt_private	The client private data.
 */
void ibt_set_srq_private(ibt_srq_hdl_t ibt_srq, void *clnt_private);
void *ibt_get_srq_private(ibt_srq_hdl_t ibt_srq);

/*
 * ibt_check_failure()
 * 	Function to test for special case failures
 *
 *	status		An ibt_status_t returned from an IBTF function call.
 *
 *	reserved_p	Reserved for future use - set to NULL.
 */
ibt_failure_type_t ibt_check_failure(ibt_status_t status, uint64_t *reserved_p);


/*
 * ibt_hw_is_present() returns 0 when there is no IB hardware actively
 * running.  This is primarily useful for modules like rpcmod which needs a
 * quick check to decide whether or not it should try to use InfiniBand.
 */
int ibt_hw_is_present();


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
 *
 *	hca_hdl		Is the HCA handle.
 *
 *	hca_guid	Is the HCA Node GUID.
 *
 *	sys_guid	Is the New system image GUID.
 *
 */
ibt_status_t ibt_modify_system_image(ibt_hca_hdl_t hca_hdl, ib_guid_t sys_guid);

ibt_status_t ibt_modify_system_image_byguid(ib_guid_t hca_guid,
    ib_guid_t sys_guid);


/*
 * ibt_modify_port()
 * ibt_modify_port_byguid()
 *	Modify the specified port, or all ports attribute(s).
 *
 *	hca_hdl		Is the HCA handle.
 *
 *	hca_guid	Is the HCA Node GUID.
 *
 *	port		Specifies the port to modify.
 *
 *	flags		Specifies which attribute of the port to modify.
 *
 *	init_type	Optional value only required if IBT_PORT_SET_INIT_TYPE
 *			is set in flags.  See IBT_PINIT_* definitions.
 *
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
 *
 *	hca_hdl		The HCA handle.
 *
 *	hca_guid	The HCA Node GUID.
 *
 *	port		Port number (1 to N) to query.
 *
 *	sgid_p		Returned sgid[0], NULL implies no return value.
 *			Note: sgid[0] contains the subnet prefix and the
 *			GUID for the port.
 *
 *	base_lid_p	Returned base_lid, NULL implies no return value.
 */
ibt_status_t ibt_get_port_state(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p);

ibt_status_t ibt_get_port_state_byguid(ib_guid_t hca_guid, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IBTI_COMMON_H */
