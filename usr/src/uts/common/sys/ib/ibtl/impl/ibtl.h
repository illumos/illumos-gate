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

#ifndef _SYS_IB_IBTL_IMPL_IBTL_H
#define	_SYS_IB_IBTL_IMPL_IBTL_H

/*
 * ibtl.h
 *
 * All data structures and function prototypes that are specific to the
 * IBTL implementation.
 */
#include <sys/note.h>
#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibci.h>
#include <sys/ib/ibtl/impl/ibtl_util.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Define a per IBT Client state structure. Its address is returned
 * to the IBT client as an opaque IBT Client Handle - ibt_clnt_hdl_t.
 *
 * ibt_attach() allocates one of these structures.
 *
 * For each IBT Client registered with the IBTL, we maintain a list
 * of HCAs, clnt_hca_list, that this IBT Client is using.
 *
 * This list is updated by ibt_open_hca().
 */
typedef struct ibtl_clnt_s {
	char			clnt_name[8];	/* (just a debugging aid) */
	ibt_clnt_modinfo_t	*clnt_modinfop;	/* Pointer to IBT client's */
						/* module information */
	void			*clnt_private;	/* IBT Client's private ptr */
	dev_info_t		*clnt_dip;	/* IBT Client's dip */
	struct	ibtl_clnt_s	*clnt_list_link;
	uint32_t		clnt_async_cnt;
	uint32_t		clnt_srv_cnt;	/* Service resource counter */
	struct	ibtl_hca_s	*clnt_hca_list;	/* HCAs this client is using. */
						/* link is ha_hca_link */
	ibt_sm_notice_handler_t	clnt_sm_trap_handler; /* may be NULL */
	void			*clnt_sm_trap_handler_arg;
} ibtl_clnt_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_clnt_s::{clnt_name clnt_modinfop
    clnt_private clnt_dip}))

/* HCA Device State. */
typedef enum ibtl_hca_state_e {
	IBTL_HCA_DEV_ATTACHED	= 1,	/* new HCA attached */
	IBTL_HCA_DEV_DETACHED	= 2,	/* detached */
	IBTL_HCA_DEV_DETACHING	= 3	/* not detached yet */
} ibtl_hca_state_t;

/*
 * Define a type to record hca async PORT_UP and PORT_DOWN events for
 * processing by async thread(s). At the time an async is made by an
 * HCA driver (presumably at interrupt level), a call is made to IBTL.
 * IBTL marks this field, and wakes up an async thread for delivery
 * to IBT clients as appropriate.
 */

typedef enum ibtl_async_port_status_e {
	IBTL_HCA_PORT_UNKNOWN		= 0x000,	/* initial state */
	IBTL_HCA_PORT_UP		= 0x001,
	IBTL_HCA_PORT_DOWN		= 0x002,
	IBTL_HCA_PORT_CHG		= 0x004,
	IBTL_HCA_PORT_ASYNC_CLNT_REREG	= 0x008,
} ibtl_async_port_status_t;

/*
 * Define a type to record the PORT async events and port change flags.
 */
typedef struct ibtl_async_port_event_s {
	ibtl_async_port_status_t	status;
	ibt_port_change_t		flags;
} ibtl_async_port_event_t;

/*
 * Bit definition(s) for {qp,cq,eec,hd,ha,srq}_async_flags.
 *
 *	IBTL_ASYNC_PENDING	This structure is known by the async_threads.
 *				It will be checked for additional async work
 *				before this bit is cleared, so new async
 *				events/errors do not require this structure
 *				to be linked onto its async list.
 *
 *	IBTL_ASYNC_FREE_OBJECT  Client has called ibt_free_*, and the
 *				the structure should be kmem_freed when
 *				the outstanding asyncs complete.
 */
typedef enum ibtl_async_flags_e {
	IBTL_ASYNC_PENDING	= 0x1,
	IBTL_ASYNC_FREE_OBJECT	= 0x2
} ibtl_async_flags_t;

/*
 * Keeps track of all data associated with HCA port kstats.
 */
typedef struct ibtl_hca_port_kstat_s {
	struct ibtl_hca_devinfo_s *pks_hca_devp;
	uint_t			pks_port_num;
	struct kstat		*pks_stats_ksp;
	struct kstat		*pks_pkeys_ksp;
} ibtl_hca_port_kstat_t;

/*
 * Define a per CI HCA Device structure. Its address is returned
 * to the CI as an opaque IBTL HCA Handle - ibc_hdl_t.
 *
 * ibc_ci_attach() allocates one of these and adds it to ibtl_hca_list.
 *
 * The hd_hca_dev_link is the link for the ibtl_hca_list. It is the
 * list of HCA devices registered with the IBTL.
 *
 * The hd_clnt_list is a list of IBT Clients using this HCA.
 * The hd_clnt_list->l_head points to the ha_clnt_link field of a client's
 * ibtl_hca_s structure.
 *
 * This list is updated by ibt_open_hca().
 */
typedef struct ibtl_hca_devinfo_s {
	struct ibtl_hca_devinfo_s *hd_hca_dev_link; /* Next HCA Device */
	ibtl_hca_state_t	hd_state;	/* HCA device state: */
						/* attached/detached */
	uint_t			hd_portinfo_len; /* #bytes of portinfo */
	ibt_hca_portinfo_t	*hd_portinfop;	/* ptr to portinfo cache */
	struct ibtl_hca_s	*hd_clnt_list;	/* IBT Client using this HCA. */
	ibc_hca_hdl_t		hd_ibc_hca_hdl;	/* CI HCA handle */
	ibc_operations_t	*hd_ibc_ops;	/* operations vector */
	ibt_hca_attr_t		*hd_hca_attr;	/* hca attributes */
	dev_info_t		*hd_hca_dip;	/* HCA devinfo pointer */
	struct ibtl_hca_devinfo_s *hd_async_link; /* async list link */
	kcondvar_t		hd_portinfo_cv;	/* waiting for ibc_query */
	int			hd_portinfo_waiters; /* any waiters */
	uint8_t			hd_portinfo_locked_port;
						/* port whose info is queried */
	kcondvar_t		hd_async_busy_cv; /* wakeup when #clients = 0 */
	int			hd_async_busy;	/* only 1 async at a time */
	ibt_async_code_t	hd_async_codes;	/* all codes for this HCA */
	ibt_async_code_t	hd_async_code;	/* current code being run */
	ibt_async_event_t	hd_async_event;	/* current event being run */
	ibtl_async_flags_t	hd_async_flags;	/* see *_async_flags above */
	uint64_t		hd_fma_ena;	/* FMA data for LOCAL CATASTR */
	uint32_t		hd_async_task_cnt; /* #clients doing asyncs */
	kcondvar_t		hd_async_task_cv; /* wakeup when #clients = 0 */
	uint_t			hd_multism;	/* 1 - MultiSM, 0 - Single SM */
	ibtl_hca_port_kstat_t	*hd_hca_port_ks_info;	/* port kstat ptr */
	uint_t			hd_hca_port_ks_info_len; /* port kstat size */
		/* The following must be at the end of this struct */
	ibtl_async_port_event_t hd_async_port[1]; /* per-port async data */
} ibtl_hca_devinfo_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_hca_devinfo_s::hd_ibc_ops))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_hca_devinfo_s::hd_ibc_hca_hdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_hca_devinfo_s::hd_hca_attr))
_NOTE(SCHEME_PROTECTS_DATA("hd_async_busy and hd_async_busy_cv",
    ibtl_hca_devinfo_s::{hd_async_code hd_async_event}))

/*
 * Define a HCA info structure.
 *
 * The IBTL function ibt_open_hca() allocates one of these.
 *
 * For each client instance registered with the IBTL, we maintain a list
 * of HCAs that it is using.  The elements of that list include the
 * address of the CI HCA device structure, a pointer to the client
 * structure, and reference counts of HCA resources that this client
 * device is using.
 *
 * Note: ha_qpn_cnt is protected by a global mutex to deal with a client
 * trying to open the HCA while it is actively being closed.
 *
 * ha_hca_link is the link to the next HCA info struct that this client is
 * using.
 *
 * ha_clnt_link is the link to the next IBT client (ibtl_clnt_t) that is using
 * the same CI HCA (ibtl_hca_devinfo_t). The link points to that client's
 * ibtl_hca_t because an IBT client can use more than one CI HCA.
 */
typedef struct ibtl_hca_s {
	struct ibtl_hca_s	*ha_hca_link;	/* Next HCA used by client */
	struct ibtl_hca_s	*ha_clnt_link;	/* Next client using same HCA */
	ibtl_hca_devinfo_t	*ha_hca_devp;	/* CI HCA device structure. */
	ibtl_clnt_t		*ha_clnt_devp;	/* Client state struct */
	void			*ha_clnt_private;
	int			ha_flags;	/* misc. flags */

	/* The following counters are accessed with atomic operations. */
	uint32_t		ha_qp_cnt;	/* QP resource counter */
	uint32_t		ha_eec_cnt;	/* EEC resource counter */
	uint32_t		ha_cq_cnt;	/* CQ resource counter */
	uint32_t		ha_pd_cnt;	/* PD resource counter */
	uint32_t		ha_ah_cnt;	/* AH resource counter */
	uint32_t		ha_mr_cnt;	/* Mem Region resource count */
	uint32_t		ha_mw_cnt;	/* Mem Window resource count */
	uint32_t		ha_qpn_cnt;	/* QPN resource counter */
	uint32_t		ha_srq_cnt;	/* SRQ resource counter */
	ibtl_async_flags_t	ha_async_flags;	/* see *_async_flags above */
	uint32_t		ha_async_cnt;	/* #asyncs in progress */
	uint32_t		ha_fmr_pool_cnt; /* FMR Pool resource count */
} ibtl_hca_t;

/* ha_flags values */
#define	IBTL_HA_CLOSING	1	/* In process of closing, so don't allow open */

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_hca_s::ha_clnt_devp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_hca_s::ha_hca_devp))

/*
 * Bit definition(s) for cq_impl_flags.
 *
 *	IBTL_CQ_PENDING		This CQ is known by the ibtl_cq_threads,
 *				and it will be checked for additional work
 *				before this bit is cleared, so new work
 *				will be seen without this cq being added
 *				to the cq list.
 *
 *	IBTL_CQ_CALL_CLIENT	Mark that the HCA driver has called
 *				ibc_cq_handler with new work on this CQ,
 *				so IBTL should call the client handler
 *				again before it is considered done.
 *
 *	IBTL_CQ_FREE		Mark that ibt_free_cq is sleeping until
 *				ibtl_cq_threads is done with this CQ.
 */
typedef enum ibtl_cq_impl_flags_e {
	IBTL_CQ_PENDING		= 0x1,
	IBTL_CQ_CALL_CLIENT	= 0x2,
	IBTL_CQ_FREE		= 0x4
} ibtl_cq_impl_flags_t;


/*
 * Define a per CQ state structure.
 *
 * The ibt_alloc_cq() allocates one of these. A CQ is associated with a
 * particular HCA, whose handle is recorded in the cq_hca field.
 * The cq_ibc_cq_hdl field is initialized with the CI CQ handle returned
 * from the ibc_alloc_cq() call to the HCA driver.
 *
 * In order to set/get the client's private data, cq_clnt_private, clients
 * need to use ibt_set_cq_private() and ibt_get_cq_private() calls.
 *
 * An IBT client registers a CQ completion handler callback and private
 * callback argument (probably the client instance soft state structure) using
 * the ibt_set_cq_handler() IBT routine. The comp_handler, arg fields of the
 * structure are initialized with the values passed in by the IBTL client.
 * These two fields are the only fields protected by the cq_mutex.
 *
 * When a completion event is posted to an IBT client, the
 * client completion handler is called with the following arguments:
 *
 *	- The Client Handle, that is passed into the IBTL on ibt_attach call.
 *	- The CQ Handle upon which the completion occurred.
 *	- The private client argument, set during handler registration via
 *	  ibt_set_cq_handler() call.
 *
 * The address of the ibtl_cq_s structure is passed in as the ibt_cq_hdl_t
 * (callback arg) in the CI ibc_alloc_cq() function. Thus when a CI calls
 * the IBTL completion handler (ibc_ci_cq_handler()) we can de-mux
 * directly to the targeted IBT client.
 *
 */
typedef struct ibtl_cq_s {
	ibc_cq_hdl_t		cq_ibc_cq_hdl;	/* CI CQ handle */
	ibtl_hca_t		*cq_hca;	/* IBTL HCA hdl */
	ibt_cq_handler_t	cq_comp_handler; /* Completion handler */
	void			*cq_arg;	/* CQ handler's argument */
	kmutex_t		cq_mutex;	/* Mutex. */
	void			*cq_clnt_private; /* Client's Private. */
	struct ibtl_cq_s	*cq_link;	/* link for queuing cq to */
						/* to be handled in a thread */
	struct ibtl_cq_s	*cq_async_link;	/* list link for asyncs */
	ibtl_cq_impl_flags_t	cq_impl_flags;	/* dynamic bits if cq */
						/* handler runs in a thread */
	int			cq_in_thread;	/* mark if cq handler is to */
						/* be called in a thread */
	ibt_async_code_t	cq_async_codes;
	ibtl_async_flags_t	cq_async_flags;	/* see *_async_flags above */
	uint64_t		cq_fma_ena;	/* FMA data */
} ibtl_cq_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(ibtl_cq_s::{cq_in_thread cq_hca
    cq_ibc_cq_hdl}))

/*
 * Define a per SRQ state structure.
 *
 * ibt_alloc_srq() allocates one of these. A SRQ is associated with a
 * particular HCA, whose handle is recorded in the srq_hca field.
 * The srq_ibc_srq_hdl field is initialized with the CI SRQ handle returned
 * from the ibc_alloc_srq() call to the HCA driver.
 *
 * In order to set/get the client's private data, srq_clnt_private, clients
 * need to use ibt_set_srq_private() and ibt_get_srq_private() calls.
 *
 * The address of the ibtl_srq_s structure is passed in as the ibt_srq_hdl_t
 * (callback arg) in the CI ibc_alloc_srq() function.
 */
typedef struct ibtl_srq_s {
	ibc_srq_hdl_t		srq_ibc_srq_hdl;	/* CI SRQ handle */
	ibtl_hca_t		*srq_hca;		/* IBTL HCA hdl */
	void			*srq_clnt_private;	/* Client's Private. */
	struct ibtl_srq_s	*srq_async_link;	/* Async Link list */
	ibt_async_code_t	srq_async_codes;
	ibtl_async_flags_t	srq_async_flags;	/* Async_flags */
	uint64_t		srq_fma_ena;		/* FMA data */
} ibtl_srq_t;

/*
 * Define a per QP state structure.
 *
 * The qp_hca field is initialized with the ibtl_hca_hdl_t of the HCA in
 * which the QP was allocated. The qp_ibc_qp_hdl field is initialized with
 * the CI QP handle.
 *
 * The ibtl_qp_t structure also maintains a channel connection state
 * structure that is only valid for RC and RD QP's. The information about
 * the respective Send and Receive CQ, the RDD and PD Handles are also stored.
 *
 * The IBTA spec does not include the signal type or PD on a QP query
 * operation. In order to implement the "CLONE" feature of the alloc rc|ud
 * channel functions we need to cache these values.
 */
typedef struct ibtl_qp_s {
	ibt_tran_srv_t		qp_type;	/* QP type */
	ibt_attr_flags_t	qp_flags;
	ibc_qp_hdl_t		qp_ibc_qp_hdl;	/* CI QP handle */
	ibc_pd_hdl_t		qp_pd_hdl;	/* CI PD Hdl */
	ibtl_hca_t		*qp_hca;	/* IBTL HCA handle */
	ibtl_cq_t		*qp_send_cq;	/* IBTL CQ handle */
	ibtl_cq_t		*qp_recv_cq;	/* IBTL CQ handle */
	struct ibtl_qp_s	*qp_async_link;	/* async list link */
	ibt_async_code_t	qp_async_codes;
	ibtl_async_flags_t	qp_async_flags;	/* see *_async_flags above */
	uint64_t		qp_cat_fma_ena;	/* FMA data */
	uint64_t		qp_pth_fma_ena;	/* FMA data */
	uint64_t		qp_inv_fma_ena;	/* FMA data */
	uint64_t		qp_acc_fma_ena;	/* FMA data */
} ibtl_qp_t;


/*
 * Define a per EEC state structure.
 *
 * The ibt_alloc_eec() allocates an ibt_eec_s structure and initializes
 * the eec_hca field with the ibtl_hca_hdl_t of the HCA in which the EEC
 * was allocated. The eec_ibc_eec_hdl field is initialized with the
 * CI EEC handle.
 *
 * The information about CI's RDD Handle and channel connection state structure
 * is also maintained.
 */
typedef struct ibtl_eec_s {
	ibc_eec_hdl_t		eec_ibc_eec_hdl;	/* CI EEC Handle. */
	ibtl_hca_t		*eec_hca;		/* IBTL HCA Hdl */
	ibc_rdd_hdl_t		eec_ibc_rdd_hdl;	/* CI RDD Handle. */
	struct ibtl_channel_s	*eec_channel;
	struct ibtl_eec_s	*eec_async_link;	/* async list link */
	ibt_async_code_t	eec_async_codes;
	ibtl_async_flags_t	eec_async_flags;
	uint64_t		eec_cat_fma_ena;	/* FMA data */
	uint64_t		eec_pth_fma_ena;	/* FMA data */
} ibtl_eec_t;

/*
 * Define an ibt RD communication channel struct. This holds information
 * specific to an RD QP.
 */
typedef struct ibtl_rd_chan_s {
	ibtl_eec_t		*rd_eec;	/* point to the EEC */
} ibtl_rd_chan_t;

/*
 * Define an ibt UD communication channel struct. This holds information
 * specific to a UD QP.
 */
typedef struct ibtl_ud_chan_s {
	uint8_t			ud_port_num;	/* track the port number for */
						/* ibt_modify_reply_ud_dest() */
	ib_qkey_t		ud_qkey;	/* track the qkey */
} ibtl_ud_chan_t;

/*
 * Define an ibt RC communication channel struct. This holds information
 * specific to an RC QP.
 */
typedef struct ibtl_rc_chan_s {
	int			rc_free_flags;	/* Track connection state as */
						/* we will need to delay for */
						/* TIMEWAIT before freeing. */
	ibc_qpn_hdl_t		rc_qpn_hdl;	/* Store qpn_hdl while in */
						/* TIMEWAIT delay. */
} ibtl_rc_chan_t;

/* bit definitions for rc_free_flags */
#define	IBTL_RC_QP_CONNECTED	0x1
#define	IBTL_RC_QP_CLOSING	0x2
#define	IBTL_RC_QP_CLOSED	0x4
#define	IBTL_RC_QP_FREED	0x8
#define	IBTL_RC_QP_CONNECTING	0x10

/*
 * Define a per Channel state structure.
 *
 * A ibtl_channel_s is allocated each time a TI client calls a
 * channel allocation routine ibt_alloc_rc_channel() or ibt_alloc_ud_channel()
 * or VTI client calls ibt_alloc_qp() or ibt_alloc_special_qp().
 *
 * In order to set/get the client's private data, ch_clnt_private,
 * TI client's need to use ibt_set_chan_private() and ibt_get_chan_private()
 * or VTI clients need to use ibt_set_qp_private() and ibt_get_qp_private().
 */
typedef struct ibtl_channel_s {
	/* The ibtl_qp_t must be at the first of this struct */
	ibtl_qp_t		ch_qp;		/* IBTL QP handle */
	union {					/* transport specific */
		ibtl_rc_chan_t	rc;		/* RC Channel specific */
		ibtl_rd_chan_t	rd;		/* RD Channel specific */
		ibtl_ud_chan_t	ud;		/* UD Channel specific */
	} ch_transport;
	ibt_cep_state_t		ch_current_state; /* track the current state */
	void			*ch_clnt_private; /* Client's Private data */
	kmutex_t		ch_cm_mutex;	/* for ch_cm_private, etc. */
	kcondvar_t		ch_cm_cv;	/* for recycle_rc */
	void			*ch_cm_private;	/* Ptr to CM state */
} ibtl_channel_t;

_NOTE(SCHEME_PROTECTS_DATA("client managed", ibtl_channel_s))

/*
 * MACROS
 */
#define	IBTL_CHAN2QP(ibt_chan)		(&(ibt_chan)->ch_qp)
#define	IBTL_CHAN2HCA(ibt_chan)		(ibt_chan)->ch_qp.qp_hca

#define	IBTL_CHAN2CIQP(ibt_chan)	(ibt_chan->ch_qp.qp_ibc_qp_hdl)

#define	IBTL_QP2CHAN(ibtl_qp)		(ibtl_channel_t *)(ibtl_qp)
#define	IBTL_EEC2CHAN(ibtl_eec)		(ibtl_eec)->eec_channel

/*
 * Get IBC HCA Handle from IBT Handles.
 */
#define	IBTL_HDIP2CIHCA(hca_devp)	(hca_devp)->hd_ibc_hca_hdl
#define	IBTL_HCA2CIHCA(ibtl_hca)	IBTL_HDIP2CIHCA(ibtl_hca->ha_hca_devp)
#define	IBTL_ECC2CIHCA(ibtl_eec)	IBTL_HCA2CIHCA((ibtl_eec)->eec_hca)
#define	IBTL_CQ2CIHCA(ibtl_cq)		IBTL_HCA2CIHCA((ibtl_cq)->cq_hca)
#define	IBTL_CHAN2CIHCA(ibt_chan)	IBTL_HCA2CIHCA((ibt_chan)->ch_qp.qp_hca)
#define	IBTL_SRQ2CIHCA(ibtl_srq)	IBTL_HCA2CIHCA((ibtl_srq)->srq_hca)

/*
 * Get a pointer to the HCA ops structure from IBT handles.
 */
#define	IBTL_HDIP2CIHCAOPS_P(hca_devp)	(hca_devp)->hd_ibc_ops
#define	IBTL_HCA2CIHCAOPS_P(ibtl_hca)	\
	IBTL_HDIP2CIHCAOPS_P(ibtl_hca->ha_hca_devp)
#define	IBTL_CQ2CIHCAOPS_P(ibtl_cq)	IBTL_HCA2CIHCAOPS_P((ibtl_cq)->cq_hca)
#define	IBTL_CHAN2CIHCAOPS_P(ibt_chan)	\
	IBTL_HCA2CIHCAOPS_P((ibt_chan)->ch_qp.qp_hca)
#define	IBTL_SRQ2CIHCAOPS_P(ibtl_srq)	\
	IBTL_HCA2CIHCAOPS_P((ibtl_srq)->srq_hca)

/*
 * Get Client Handle from IBT Handles.
 */
#define	IBTL_HCA2CLNT(ibtl_hca)		(ibtl_hca)->ha_clnt_devp
#define	IBTL_ECC2CLNT(ibtl_eec)		IBTL_HCA2CLNT((ibtl_eec)->eec_hca)
#define	IBTL_CQ2CLNT(ibtl_cq)		IBTL_HCA2CLNT((ibtl_cq)->cq_hca)
#define	IBTL_CHAN2CLNT(ibt_chan)	IBTL_HCA2CLNT((ibt_chan)->ch_qp.qp_hca)

/*
 * Get a Pointer to the client modinfo from IBT Handles.
 */
#define	IBTL_HCA2MODI_P(ibtl_hca)	\
	((IBTL_HCA2CLNT(ibtl_hca))->clnt_modinfop)

#define	IBTL_EEC2MODI_P(ibtl_eec)	\
	((IBTL_EEC2CLNT(ibtl_eec))->clnt_modinfop)

#define	IBTL_CQ2MODI_P(ibtl_cq)		((IBTL_CQ2CLNT(ibtl_cq))->clnt_modinfop)

#define	IBTL_CHAN2MODI_P(chan)		((IBTL_CHAN2CLNT(chan))->clnt_modinfop)

/*
 * Using HCA Device Info Pointer, access HCA Attributes values for
 *	Max SGID Table Size, Max PKEY Table Size.
 */
#define	IBTL_HDIP2SGIDTBLSZ(hca)	\
		(hca)->hd_hca_attr->hca_max_port_sgid_tbl_sz
#define	IBTL_HDIP2PKEYTBLSZ(hca)	\
		(hca)->hd_hca_attr->hca_max_port_pkey_tbl_sz

/*
 * Using IBTL HCA Handle, access HCA Attributes values.
 *			viz.	HCA Node GUID,
 *				Number of Ports on this HCA Device,
 *				Max SGID Table Size
 *				Max PKEY Table Size
 */
#define	IBTL_HCA2HCAGUID(hca_hdl) \
	(hca_hdl)->ha_hca_devp->hd_hca_attr->hca_node_guid
#define	IBTL_HCA2NPORTS(hca_hdl) \
	(hca_hdl)->ha_hca_devp->hd_hca_attr->hca_nports
#define	IBTL_HCA2SGIDTBLSZ(hca_hdl) \
	(hca_hdl)->ha_hca_devp->hd_hca_attr->hca_max_port_sgid_tbl_sz
#define	IBTL_HCA2PKEYTBLSZ(hca_hdl) \
	(hca_hdl)->ha_hca_devp->hd_hca_attr->hca_max_port_pkey_tbl_sz

/* possible strlen of a IB driver's name */
#define	IBTL_DRVNAME_LEN	40

/* strings passed to ib_dprintfN() are this long */
#define	IBTL_PRINT_BUF_LEN	4096

/* Check if client isn't CM/DM/IBMA */
#define	IBTL_GENERIC_CLIENT(clntp) \
	(((clntp)->clnt_modinfop->mi_clnt_class != IBT_CM) && \
	    ((clntp)->clnt_modinfop->mi_clnt_class != IBT_DM) && \
	    ((clntp)->clnt_modinfop->mi_clnt_class != IBT_IBMA))

/*
 * Function Prototypes that are specific to the IBTL implementation.
 */
ibtl_hca_devinfo_t *ibtl_get_hcadevinfo(ib_guid_t hca_guid);
ibt_status_t ibtl_init_hca_portinfo(ibtl_hca_devinfo_t *hca_devp);
void	ibtl_reinit_hca_portinfo(ibtl_hca_devinfo_t *hca_devp, uint8_t port);

void	ibtl_init_cep_states(void);
void	ibtl_ib2usec_init(void);
void	ibtl_logging_initialization(void);
void	ibtl_logging_destroy(void);
void	ibtl_thread_init(void);
void	ibtl_thread_init2(void);
void	ibtl_thread_fini(void);
void	ibtl_announce_new_hca(ibtl_hca_devinfo_t *hca_devp);
void	ibtl_another_cq_handler_in_thread(void);
int	ibtl_detach_all_clients(ibtl_hca_devinfo_t *hcap);
void	ibtl_qp_flow_control_enter(void);
void	ibtl_qp_flow_control_exit(void);

/* synchronization of asyncs when freeing an object */
void	ibtl_free_qp_async_check(ibtl_qp_t *ibtl_qp);
void	ibtl_free_cq_async_check(ibtl_cq_t *ibtl_cq);
void	ibtl_free_srq_async_check(ibtl_srq_t *ibtl_srq);
void	ibtl_free_eec_async_check(ibtl_eec_t *ibtl_eec);
void	ibtl_free_hca_async_check(ibt_hca_hdl_t ibt_hca);
void	ibtl_free_clnt_async_check(ibtl_clnt_t *clntp);

/* synchronization of cq_handler callbacks and free_cq */
void	ibtl_free_cq_check(ibtl_cq_t *ibtl_cq);

/* release_qpn and close_hca synchronization */
void	ibtl_close_hca_check(ibt_hca_hdl_t ibt_hca);

/* Global List of HCA devices, and associated lock. */
extern struct ibtl_hca_devinfo_s *ibtl_hca_list; /* link is hd_hca_dev_link */

/* Global List of IBT Client Instances, and associated lock. */
extern struct ibtl_clnt_s *ibtl_clnt_list; /* link is clnt_list_link */
extern kmutex_t ibtl_clnt_list_mutex;

/* Lock for the race between the client and CM to free QPs. */
extern kmutex_t ibtl_free_qp_mutex;

/* Lock for the race between the client closing the HCA and QPN being freed. */
extern kcondvar_t ibtl_close_hca_cv;

/* Limit the flow of QP verb calls */
extern kmutex_t ibtl_qp_mutex;
extern kcondvar_t ibtl_qp_cv;

/* Async handlers and client private for well known clients of IBTL */
extern ibt_async_handler_t ibtl_cm_async_handler;
extern ibt_async_handler_t ibtl_dm_async_handler;
extern ibt_async_handler_t ibtl_ibma_async_handler;
extern void *ibtl_cm_clnt_private;
extern void *ibtl_dm_clnt_private;
extern void *ibtl_ibma_clnt_private;

/* cache for fast GID => portinfo lookup */
extern boolean_t ibtl_fast_gid_cache_valid;


/* The following structs are used to pass info in and out of the APIs */
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_rc_chan_alloc_args_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_rc_chan_query_attr_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_rc_chan_modify_attr_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_ud_dest_query_attr_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_ud_chan_alloc_args_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_ud_chan_query_attr_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_ud_chan_modify_attr_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_ud_dest_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_qp_alloc_attr_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_qp_info_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_hca_portinfo_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_adds_vect_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_cep_path_s))
_NOTE(SCHEME_PROTECTS_DATA("client managed", ibt_mr_desc_s))
_NOTE(SCHEME_PROTECTS_DATA("GIDs are transient", ib_gid_s))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IMPL_IBTL_H */
