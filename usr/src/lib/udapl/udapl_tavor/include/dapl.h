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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *
 * HEADER: dapl.h
 *
 * PURPOSE: defines common data structures for the DAPL reference implemenation
 *
 * Description: This file describes the working data structures used within
 *              DAPL RI.
 *
 */

#ifndef _DAPL_H_
#define	_DAPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/byteorder.h>

#include <dat/udat.h>
#include <dat/dat_registry.h>
#include "dapl_osd.h"
#include "dapl_debug.h"
#include "dapl_tavor_ibtf.h"


/*
 * The HTOBE_xx() macro converts data from host order to big endian
 * order and hence uses the BE_xx macros to do the byte swapping.
 *
 * The BETOH_xx() macro converts data from big endian order to host
 * order. This is used when data is read from CQs or QPs. Due to the
 * self-inversing nature of byte swapping routines BE_xx macros have
 * the effect of converting big endian to host byte order which can
 * be big endian or little endian.
 * eg.	On i386 BE_64(val64_be) = val64_le
 *	On sparc BE_64(val64_be) = val64_be.
 *
 * Tavor is a big endian device, all the buffer manipulation for
 * QPs, CQs and the doorbell page needs to be aware of this.
 *
 */
#if defined(__amd64) || defined(__i386)
/* use inline code to get performance of bswap* instructions */

#if !defined(__lint) && defined(__GNUC__)
/* use GNU inline */
	/* works for both i386 and amd64 */
	static __inline__ uint32_t dapls_byteswap32(uint32_t value)
	{
		__asm__("bswap %0" : "+r" (value));
		return (value);
	}

#if defined(__amd64)

	static __inline__ uint64_t dapls_byteswap64(uint64_t value)
	{
		__asm__("bswapq %0" : "+r" (value));
		return (value);
	}

#else /* defined(__i386) */

	static __inline__ uint64_t dapls_byteswap64(uint64_t value)
	{
		union {
			struct { uint32_t a, b; } s;
			uint64_t u;
		} v;
		v.u = value;
		__asm__("bswap %0 ; bswap %1 ; xchgl %0,%1"
		    : "=r" (v.s.a), "=r" (v.s.b)
		    : "0" (v.s.a), "1" (v.s.b));
		return (v.u);
	}
#endif
#endif	/* !defined(__lint) && defined(__GNUC__) */

#define	HTOBE_64(x)	dapls_byteswap64(x)
#define	HTOBE_32(x)	dapls_byteswap32(x)
#define	BETOH_64(x)	dapls_byteswap64(x)
#define	BETOH_32(x)	dapls_byteswap32(x)

#else	/* defined(__amd64) || defined(__i386) */

/* These are identity (do nothing) on big-endian machines. */

#define	HTOBE_64(x)	BE_64((x))
#define	HTOBE_32(x)	BE_32((x))
#define	BETOH_64(x)	BE_64((x))
#define	BETOH_32(x)	BE_32((x))

#endif	/* defined(__amd64) || defined(__i386) */

/*
 *
 * Enumerations
 *
 */

typedef enum dapl_magic {
	/* magic number values for verification & debug */
	DAPL_MAGIC_IA = 0x1afeF00d,
	DAPL_MAGIC_EVD = 0x2eedFace,
	DAPL_MAGIC_EP = 0x3eadBabe,
	DAPL_MAGIC_LMR = 0x4eefCafe,
	DAPL_MAGIC_RMR = 0x5BadCafe,
	DAPL_MAGIC_PZ = 0x6eafBeef,
	DAPL_MAGIC_PSP = 0x7eadeD0c,
	DAPL_MAGIC_RSP = 0x1ab4Feed,
	DAPL_MAGIC_CR = 0x2e12Cee1,
	DAPL_MAGIC_CR_DESTROYED = 0x312bDead,
	DAPL_MAGIC_CNO = 0x4eadF00d,
	DAPL_MAGIC_EP_EXIT = 0x5abeDead,
	DAPL_MAGIC_SRQ = 0x5eedFace,
	DAPL_MAGIC_INVALID = 0x6FFFFFFF
} DAPL_MAGIC;

typedef enum dapl_evd_state {
	DAPL_EVD_STATE_TERMINAL,
	DAPL_EVD_STATE_INITIAL,
	DAPL_EVD_STATE_OPEN,
	DAPL_EVD_STATE_WAITED,
	DAPL_EVD_STATE_DEAD = 0xDEAD
} DAPL_EVD_STATE;

typedef enum dapl_evd_completion {
	DAPL_EVD_STATE_INIT,
	DAPL_EVD_STATE_SOLICITED_WAIT,
	DAPL_EVD_STATE_THRESHOLD,
	DAPL_EVD_STATE_UNSIGNALLED
} DAPL_EVD_COMPLETION;

typedef enum dapl_cno_state {
	DAPL_CNO_STATE_UNTRIGGERED,
	DAPL_CNO_STATE_TRIGGERED,
	DAPL_CNO_STATE_DEAD = 0x7eadFeed
} DAPL_CNO_STATE;

typedef enum dapl_qp_state {
	DAPL_QP_STATE_UNCONNECTED,
	DAPL_QP_STATE_RESERVED,
	DAPL_QP_STATE_PASSIVE_CONNECTION_PENDING,
	DAPL_QP_STATE_ACTIVE_CONNECTION_PENDING,
	DAPL_QP_STATE_TENTATIVE_CONNECTION_PENDING,
	DAPL_QP_STATE_CONNECTED,
	DAPL_QP_STATE_DISCONNECT_PENDING,
	DAPL_QP_STATE_ERROR,
	DAPL_QP_STATE_NOT_REUSABLE,
	DAPL_QP_STATE_FREE
} DAPL_QP_STATE;


/*
 *
 * Constants
 *
 */

/*
 * number of HCAs allowed
 */
#define	DAPL_MAX_HCA_COUNT		4

/*
 * Configures the RMR bind evd restriction
 */
#define	DAPL_RMR_BIND_EVD_RESTRICTION	DAT_RMR_EVD_SAME_AS_REQUEST_EVD

/*
 * special qp_state indicating the EP does not have a QP attached yet
 */
#define	DAPL_QP_STATE_UNATTACHED	0xFFF0

/*
 *
 * Macros
 *
 */

/*
 * Simple macro to verify a handle is bad.
 * - pointer's magic number is wrong
 * - both pointer is NULL and not word aligned checked by the registry
 */
#define	DAPL_BAD_HANDLE(h, magicNum) (				\
	    (((DAPL_HEADER *)(h))->magic != (magicNum)))

#define	DAPL_MIN(a, b)		(((a) < (b)) ? (a) : (b))
#define	DAPL_MAX(a, b)		(((a) > (b)) ? (a) : (b))

#define	DAT_ERROR(Type, SubType) \
	((DAT_RETURN)(DAT_CLASS_ERROR | (Type) | (SubType)))

/*
 *
 * Typedefs
 *
 */

typedef	struct dapl_llist_entry DAPL_LLIST_ENTRY;
typedef	DAPL_LLIST_ENTRY *DAPL_LLIST_HEAD;
typedef	struct dapl_ring_buffer DAPL_RING_BUFFER;
typedef	struct dapl_cookie_buffer DAPL_COOKIE_BUFFER;

typedef	struct dapl_hash_table DAPL_HASH_TABLE;
typedef	struct dapl_hash_table *DAPL_HASH_TABLEP;
typedef	DAT_UINT64 DAPL_HASH_KEY;
typedef	void *DAPL_HASH_DATA;

typedef	struct dapl_hca DAPL_HCA;

typedef	struct dapl_header DAPL_HEADER;

typedef	struct dapl_ia DAPL_IA;
typedef	struct dapl_cno DAPL_CNO;
typedef	struct dapl_evd DAPL_EVD;
typedef	struct dapl_ep DAPL_EP;
typedef	struct dapl_pz DAPL_PZ;
typedef	struct dapl_lmr DAPL_LMR;
typedef	struct dapl_rmr DAPL_RMR;
typedef	struct dapl_sp DAPL_SP;
typedef	struct dapl_cr DAPL_CR;
typedef struct dapl_srq DAPL_SRQ;

typedef	struct dapl_cookie DAPL_COOKIE;
typedef	struct dapl_dto_cookie DAPL_DTO_COOKIE;
typedef	struct dapl_rmr_cookie DAPL_RMR_COOKIE;

typedef	void (*DAPL_CONNECTION_STATE_HANDLER)(IN DAPL_EP *,
	IN ib_cm_events_t,
	IN const void *,
	OUT DAT_EVENT *);


/*
 *
 * Structures
 *
 */

struct dapl_llist_entry {
	struct dapl_llist_entry *flink;
	struct dapl_llist_entry *blink;
	void *data;
	DAPL_LLIST_HEAD *list_head;	/* for consistency checking */
};

struct dapl_ring_buffer {
	void **base;		/* base of element array */
	DAT_COUNT lim;		/* mask, number of entries - 1 */
	DAPL_ATOMIC head;	/* head pointer index */
	DAPL_ATOMIC tail;	/* tail pointer index */
	DAPL_OS_LOCK lock;	/* lock */
};

struct dapl_cookie_buffer {
	DAPL_COOKIE *pool;
	DAT_COUNT pool_size;
	DAPL_ATOMIC head;
	DAPL_ATOMIC tail;
};

typedef DAT_RETURN (*DAPL_POST_SEND)(DAPL_EP *, ibt_send_wr_t *, boolean_t);
typedef DAT_RETURN (*DAPL_POST_RECV)(DAPL_EP *, ibt_recv_wr_t *, boolean_t);
typedef DAT_RETURN (*DAPL_POST_SRQ)(DAPL_SRQ *, ibt_recv_wr_t *, boolean_t);
typedef void (*DAPL_CQ_PEEK)(ib_cq_handle_t, int *);
typedef DAT_RETURN
	(*DAPL_CQ_POLL)(ib_cq_handle_t, ibt_wc_t *, uint_t, uint_t *);
typedef DAT_RETURN (*DAPL_CQ_POLL_ONE)(ib_cq_handle_t, ibt_wc_t *);
typedef DAT_RETURN (*DAPL_CQ_NOTIFY)(ib_cq_handle_t, int, uint32_t);
typedef void (*DAPL_SRQ_FLUSH)(ib_qp_handle_t);
typedef void (*DAPL_QP_INIT)(ib_qp_handle_t);
typedef void (*DAPL_CQ_INIT)(ib_cq_handle_t);
typedef void (*DAPL_SRQ_INIT)(ib_srq_handle_t);

struct dapl_hca {
	DAPL_OS_LOCK lock;
	DAPL_LLIST_HEAD ia_list_head;
	DAPL_EVD *async_evd;
	DAPL_EVD *async_error_evd;
	DAT_SOCK_ADDR6 hca_address;	/* local address of HCA */
	/* Values specific to IB OS API */
	IB_HCA_NAME name;
	ib_hca_handle_t ib_hca_handle;
	DAPL_ATOMIC handle_ref_count;	/* count of ia_opens on handle */
	ib_uint32_t port_num;	/* number of physical port */
	ib_uint32_t partition_max;
	ib_uint32_t partition_key;
	ib_uint32_t tavor_idx;
	ib_guid_t node_GUID;
	ib_lid_t lid;
	int max_inline_send;
	/* CQ support thread */
	ib_cqd_handle_t ib_cqd_handle;		/* cq domain handle */
	ib_cq_handle_t null_ib_cq_handle;	/* CQ handle with 0 entries */
	/* Memory Subsystem Support */
	DAPL_HASH_TABLE *lmr_hash_table;
	/* Limits & useful HCA attributes */
	DAT_IA_ATTR ia_attr;
	struct dapl_hca *hca_next;
	DAPL_POST_SEND post_send;
	DAPL_POST_RECV post_recv;
	DAPL_POST_SRQ post_srq;
	DAPL_CQ_PEEK cq_peek;
	DAPL_CQ_POLL cq_poll;
	DAPL_CQ_POLL_ONE cq_poll_one;
	DAPL_CQ_NOTIFY cq_notify;
	DAPL_SRQ_FLUSH srq_flush;
	DAPL_QP_INIT qp_init;
	DAPL_CQ_INIT cq_init;
	DAPL_SRQ_INIT srq_init;
	int hermon_resize_cq;
};

#define	DAPL_SEND(x)	(x->header.owner_ia->hca_ptr->post_send)
#define	DAPL_RECV(x)	(x->header.owner_ia->hca_ptr->post_recv)
#define	DAPL_SRECV(x)	(x->header.owner_ia->hca_ptr->post_srq)
#define	DAPL_PEEK(x)	(x->header.owner_ia->hca_ptr->cq_peek)
#define	DAPL_POLL(x)	(x->header.owner_ia->hca_ptr->cq_poll)
#define	DAPL_POLL1(x)	(x->header.owner_ia->hca_ptr->cq_poll_one)
#define	DAPL_NOTIFY(x)	(x->header.owner_ia->hca_ptr->cq_notify)
#define	DAPL_FLUSH(x)	(x->header.owner_ia->hca_ptr->srq_flush)
#define	DAPL_INIT_QP(x)	(x->hca_ptr->qp_init)
#define	DAPL_INIT_CQ(x)	(x->hca_ptr->cq_init)
#define	DAPL_INIT_SRQ(x) (x->hca_ptr->srq_init)

extern void dapls_init_funcs_tavor(DAPL_HCA *);
extern void dapls_init_funcs_arbel(DAPL_HCA *);
extern void dapls_init_funcs_hermon(DAPL_HCA *);

/* DAPL Objects always have the following header */
struct dapl_header {
	DAT_PROVIDER *provider;		/* required by DAT - must be first */
	DAPL_MAGIC magic;		/* magic number for verification */
	DAT_HANDLE_TYPE handle_type;	/* struct type */
	DAPL_IA *owner_ia;		/* ia which owns this struct */
	DAPL_LLIST_ENTRY ia_list_entry;	/* link entry on ia struct */
	DAT_CONTEXT user_context;	/* user context - opaque to DAPL */
	DAPL_OS_LOCK lock;		/* lock - in header for easier macros */
};

enum DAPL_IA_FLAGS {
	DAPL_DISABLE_RO	= 1		/* Disable relaxed ordering */
};

/* DAPL_IA maps to DAT_IA_HANDLE */
struct dapl_ia {
	DAPL_HEADER header;
	DAPL_HCA *hca_ptr;
	DAPL_EVD *async_error_evd;
	DAT_BOOLEAN cleanup_async_error_evd;

	DAPL_LLIST_ENTRY hca_ia_list_entry;	/* HCAs list of IAs */
	DAPL_LLIST_HEAD ep_list_head;		/* EP queue */
	DAPL_LLIST_HEAD lmr_list_head;		/* LMR queue */
	DAPL_LLIST_HEAD rmr_list_head;		/* RMR queue */
	DAPL_LLIST_HEAD pz_list_head;		/* PZ queue */
	DAPL_LLIST_HEAD evd_list_head;		/* EVD queue */
	DAPL_LLIST_HEAD cno_list_head;		/* CNO queue */
	DAPL_LLIST_HEAD psp_list_head;		/* PSP queue */
	DAPL_LLIST_HEAD rsp_list_head;		/* RSP queue */
	DAPL_LLIST_HEAD srq_list_head;		/* SRQ queue */

	enum DAPL_IA_FLAGS dapl_flags;		/* state flags, see above */
};

/* DAPL_CNO maps to DAT_CNO_HANDLE */
struct dapl_cno {
	DAPL_HEADER header;

	/* A CNO cannot be freed while it is referenced elsewhere.  */
	DAPL_ATOMIC cno_ref_count;
	DAPL_CNO_STATE cno_state;

	DAT_COUNT cno_waiters;
	DAPL_EVD *cno_evd_triggered;
	DAT_OS_WAIT_PROXY_AGENT cno_wait_agent;

	DAPL_OS_WAIT_OBJECT cno_wait_object;
	DAPL_LLIST_HEAD evd_list_head;
	ib_cno_handle_t ib_cno_handle;
};

/* DAPL_EVD maps to DAT_EVD_HANDLE */
struct dapl_evd {
	DAPL_HEADER header;

	DAPL_EVD_STATE evd_state;
	DAT_EVD_FLAGS evd_flags;
	DAT_BOOLEAN evd_enabled;	/* For attached CNO.  */
	DAT_BOOLEAN evd_waitable;	/* EVD state.  */

	/* Derived from evd_flags; see dapls_evd_internal_create.  */
	DAT_BOOLEAN evd_producer_locking_needed;

	/* Every EVD has a CQ unless it is a SOFTWARE_EVENT only EVD */
	ib_cq_handle_t ib_cq_handle;

	/*
	 * Mellanox Specific completion handle for
	 * registration/de-registration
	 */
	ib_comp_handle_t ib_comp_handle;

	/*
	 * An Event Dispatcher cannot be freed while
	 * it is referenced elsewhere.
	 */
	DAPL_ATOMIC evd_ref_count;

	/* Set if there has been a catastrophic overflow */
	DAT_BOOLEAN catastrophic_overflow;

	/* the actual events */
	DAT_COUNT qlen;
	DAT_EVENT *events;
	DAPL_RING_BUFFER free_event_queue;
	DAPL_RING_BUFFER pending_event_queue;

	/*
	 * CQ Completions are not placed into 'deferred_events'
	 * rather they are simply left on the Completion Queue
	 * and the fact that there was a notification is flagged.
	 */
	DAT_BOOLEAN cq_notified;
	DAPL_OS_TICKS cq_notified_when;

	DAT_COUNT cno_active_count;
	DAPL_CNO *cno_ptr;

	DAPL_OS_WAIT_OBJECT wait_object;
	DAT_COUNT threshold;
	DAPL_LLIST_ENTRY cno_list_entry;
	DAPL_EVD_COMPLETION	completion_type;
};

/* DAPL_EP maps to DAT_EP_HANDLE */
struct dapl_ep {
	DAPL_HEADER header;
	/* What the DAT Consumer asked for */
	DAT_EP_PARAM param;

	/* The RC Queue Pair (IBM OS API) */
	ib_qp_handle_t qp_handle;
	unsigned int qpn;		/* qp number */
	ib_qp_state_t qp_state;

	/* communications manager handle (IBM OS API) */
	ib_cm_handle_t cm_handle;
	/*
	 * store the remote IA address here, reference from the param
	 * struct which only has a pointer, no storage
	 */
	DAT_SOCK_ADDR6 remote_ia_address;

	/* For passive connections we maintain a back pointer to the CR */
	void *cr_ptr;

	/* private data container */
	unsigned char private_data[DAPL_MAX_PRIVATE_DATA_SIZE];

	/* DTO data */
	DAPL_ATOMIC req_count;
	DAPL_ATOMIC recv_count;

	DAPL_COOKIE_BUFFER req_buffer;
	DAPL_COOKIE_BUFFER recv_buffer;

	DAT_BOOLEAN		srq_attached;
};

/* DAPL_PZ maps to DAT_PZ_HANDLE */
struct dapl_pz {
	DAPL_HEADER header;
	ib_pd_handle_t pd_handle;
	DAPL_ATOMIC pz_ref_count;
};

/* DAPL_LMR maps to DAT_LMR_HANDLE */
struct dapl_lmr {
	DAPL_HEADER header;
	DAT_LMR_PARAM param;
	ib_mr_handle_t mr_handle;
	DAPL_ATOMIC lmr_ref_count;
};

/* DAPL_RMR maps to DAT_RMR_HANDLE */
struct dapl_rmr {
	DAPL_HEADER header;
	DAT_RMR_PARAM param;
	DAPL_EP *ep;
	DAPL_PZ *pz;
	DAPL_LMR *lmr;
	ib_mw_handle_t mw_handle;
};

/* SP types, indicating the state and queue */
typedef enum dapl_sp_state {
	DAPL_SP_STATE_FREE,
	DAPL_SP_STATE_PSP_LISTENING,
	DAPL_SP_STATE_PSP_PENDING,
	DAPL_SP_STATE_RSP_LISTENING,
	DAPL_SP_STATE_RSP_PENDING
} DAPL_SP_STATE;

/* DAPL_SP maps to DAT_PSP_HANDLE and DAT_RSP_HANDLE */
struct dapl_sp {
	DAPL_HEADER header;
	DAPL_SP_STATE state;	/* type and queue of the SP */

	/* PSP/RSP PARAM fields */
	DAT_IA_HANDLE ia_handle;
	DAT_CONN_QUAL conn_qual;
	DAT_EVD_HANDLE evd_handle;
	DAT_PSP_FLAGS psp_flags;
	DAT_EP_HANDLE ep_handle;

	/* maintenence fields */
	DAT_BOOLEAN listening;		/* PSP is registered & active */
	ib_cm_srvc_handle_t cm_srvc_handle;	/* Used by Mellanox CM */
	DAPL_LLIST_HEAD cr_list_head;	/* CR pending queue */
	DAT_COUNT cr_list_count;	/* count of CRs on queue */
};

/* DAPL_CR maps to DAT_CR_HANDLE */
struct dapl_cr {
	DAPL_HEADER header;

	/*
	 * for convenience the data is kept as a DAT_CR_PARAM.
	 * however, the "local_endpoint" field is always NULL
	 * so this wastes a pointer. This is probably ok to
	 * simplify code, espedially dat_cr_query.
	 */
	DAT_CR_PARAM param;
	/* IB specific fields */
	ib_cm_handle_t ib_cm_handle;

	DAT_SOCK_ADDR6 remote_ia_address;
	/*
	 * Assuming that the maximum private data size is small.
	 * If it gets large, use of a pointer may be appropriate.
	 */
	unsigned char private_data[DAPL_MAX_PRIVATE_DATA_SIZE];
	/*
	 * Need to be able to associate the CR back to the PSP for
	 * dapl_cr_reject.
	 */
	DAPL_SP *sp_ptr;
};

/* DAPL_SRQ maps to DAT_SRQ_HANDLE */
struct dapl_srq {
	DAPL_HEADER		header;
	DAT_SRQ_PARAM		param;
	/* SRQ cannot be freed till EPs attached to srq are freed */
	DAPL_ATOMIC		srq_ref_count;
	ib_srq_handle_t		srq_handle;
	/* DTO data */
	DAPL_ATOMIC		recv_count;
	DAPL_COOKIE_BUFFER	recv_buffer;
};

typedef enum dapl_dto_type {
	DAPL_DTO_TYPE_SEND,
	DAPL_DTO_TYPE_RECV,
	DAPL_DTO_TYPE_RDMA_WRITE,
	DAPL_DTO_TYPE_RDMA_READ
} DAPL_DTO_TYPE;

typedef enum dapl_cookie_type {
	DAPL_COOKIE_TYPE_NULL,
	DAPL_COOKIE_TYPE_DTO,
	DAPL_COOKIE_TYPE_RMR
} DAPL_COOKIE_TYPE;

/* DAPL_DTO_COOKIE used as context for DTO WQEs */
struct dapl_dto_cookie {
	DAPL_DTO_TYPE type;
	DAT_DTO_COOKIE cookie;
	DAT_COUNT size;		/* used for SEND and RDMA write */
};

/* DAPL_RMR_COOKIE used as context for bind WQEs */
struct dapl_rmr_cookie {
	DAPL_RMR *rmr;
	DAT_RMR_COOKIE cookie;
};

typedef enum dapl_cookie_queue_type {
	DAPL_COOKIE_QUEUE_EP,
	DAPL_COOKIE_QUEUE_SRQ
} DAPL_COOKIE_QUEUE_TYPE;

/* DAPL_COOKIE used as context for WQEs */
struct dapl_cookie {
	DAPL_COOKIE_TYPE type;	/* Must be first, to define struct.  */
	DAPL_COOKIE_QUEUE_TYPE	 queue_type;
	union {
		void		*ptr;
		DAPL_EP		*ep;
		DAPL_SRQ	*srq;
	} queue;
	DAT_COUNT index;
	union {
		DAPL_DTO_COOKIE dto;
		DAPL_RMR_COOKIE rmr;
	} val;
};

/*
 * Generic HCA name field
 */
#define	DAPL_HCA_NAME_MAX_LEN 260
typedef char DAPL_HCA_NAME[DAPL_HCA_NAME_MAX_LEN + 1];

#if defined(IBHOSTS_NAMING)

/*
 * Simple mapping table to match IP addresses to GIDs. Loaded
 * by dapl_init.
 */
typedef struct _dapl_gid_map_table {
	uint32_t ip_address;
	ib_gid_t gid;
} DAPL_GID_MAP;

#endif /* IBHOSTS_NAMING */

/*
 *
 * Function Prototypes
 *
 */

/*
 * DAT Mandated functions
 */
extern DAT_RETURN
dapl_ia_open(
	IN const DAT_NAME_PTR,	/* name */
	IN DAT_COUNT,		/* asynch_evd_qlen */
	INOUT DAT_EVD_HANDLE *,	/* asynch_evd_handle */
	OUT DAT_IA_HANDLE *,	/* ia_handle */
	IN	boolean_t);	/* ro_aware_client */

extern DAT_RETURN
dapl_ia_close(
	IN DAT_IA_HANDLE,	/* ia_handle */
	IN DAT_CLOSE_FLAGS);	/* ia_flags */


extern DAT_RETURN
dapl_ia_query(
	IN DAT_IA_HANDLE,		/* ia handle */
	OUT DAT_EVD_HANDLE *,		/* async_evd_handle */
	IN DAT_IA_ATTR_MASK,		/* ia_params_mask */
	OUT DAT_IA_ATTR *,		/* ia_params */
	IN DAT_PROVIDER_ATTR_MASK,	/* provider_params_mask */
	OUT DAT_PROVIDER_ATTR *);	/* provider_params */


/* helper functions */
extern DAT_RETURN
dapl_set_consumer_context(
	IN DAT_HANDLE,		/* dat handle */
	IN DAT_CONTEXT);	/* context */

extern DAT_RETURN
dapl_get_consumer_context(
	IN DAT_HANDLE,		/* dat handle */
	OUT DAT_CONTEXT *);	/* context */

extern DAT_RETURN
dapl_get_handle_type(
	IN DAT_HANDLE,
	OUT DAT_HANDLE_TYPE *);


/* CNO functions */
extern DAT_RETURN
dapl_cno_create(
	IN DAT_IA_HANDLE,		/* ia_handle */
	IN DAT_OS_WAIT_PROXY_AGENT,	/* agent */
	OUT DAT_CNO_HANDLE *);		/* cno_handle */

extern DAT_RETURN
dapl_cno_modify_agent(
	IN DAT_CNO_HANDLE,		/* cno_handle */
	IN DAT_OS_WAIT_PROXY_AGENT);	/* agent */

extern DAT_RETURN
dapl_cno_query(
	IN DAT_CNO_HANDLE,	/* cno_handle */
	IN DAT_CNO_PARAM_MASK,	/* cno_param_mask */
	OUT DAT_CNO_PARAM *);	/* cno_param */

extern DAT_RETURN
dapl_cno_free(IN DAT_CNO_HANDLE);	/* cno_handle */

extern DAT_RETURN
dapl_cno_wait(
	IN DAT_CNO_HANDLE,	/* cno_handle */
	IN DAT_TIMEOUT,		/* timeout */
	OUT DAT_EVD_HANDLE *);	/* evd_handle */


/* CR Functions */
extern DAT_RETURN
dapl_cr_query(
	IN DAT_CR_HANDLE,	/* cr_handle */
	IN DAT_CR_PARAM_MASK,	/* cr_args_mask */
	OUT DAT_CR_PARAM *);	/* cwr_args */

extern DAT_RETURN
dapl_cr_accept(
	IN DAT_CR_HANDLE,	/* cr_handle */
	IN DAT_EP_HANDLE,	/* ep_handle */
	IN DAT_COUNT,		/* private_data_size */
	IN const DAT_PVOID);	/* private_data */

extern DAT_RETURN
dapl_cr_reject(IN DAT_CR_HANDLE);

extern DAT_RETURN
dapl_cr_handoff(
	IN DAT_CR_HANDLE,	/* cr_handle */
	IN DAT_CONN_QUAL);	/* handoff */

/* EVD Functions */
extern DAT_RETURN
dapl_evd_create(
	IN DAT_IA_HANDLE,	/* ia_handle */
	IN DAT_COUNT,		/* evd_min_qlen */
	IN DAT_CNO_HANDLE,	/* cno_handle */
	IN DAT_EVD_FLAGS,	/* evd_flags */
	OUT DAT_EVD_HANDLE *);	/* evd_handle */

extern DAT_RETURN
dapl_evd_query(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_EVD_PARAM_MASK,	/* evd_args_mask */
	OUT DAT_EVD_PARAM *);	/* evd_args */

#if 0				/* kdapl */
extern DAT_RETURN
dapl_evd_modify_upcall(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_UPCALL_POLICY,	/* upcall_policy */
	IN DAT_UPCALL_OBJECT);	/* upcall */
#else

extern DAT_RETURN
dapl_evd_modify_cno(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_CNO_HANDLE);	/* cno_handle */

extern DAT_RETURN
dapl_evd_enable(IN DAT_EVD_HANDLE);	/* evd_handle */

extern DAT_RETURN
dapl_evd_disable(IN DAT_EVD_HANDLE);	/* evd_handle */

extern DAT_RETURN
dapl_evd_wait(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_TIMEOUT,		/* timeout */
	IN DAT_COUNT,		/* threshold */
	OUT DAT_EVENT *,	/* event */
	OUT DAT_COUNT *);	/* nmore */
#endif

extern DAT_RETURN
dapl_evd_resize(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_COUNT);		/* evd_qlen */

extern DAT_RETURN
dapl_evd_wait(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_TIMEOUT,		/* timeout */
	IN DAT_COUNT,		/* threshold */
	OUT DAT_EVENT *,	/* event */
	OUT DAT_COUNT *);	/* nmore */

extern DAT_RETURN
dapl_evd_post_se(
	DAT_EVD_HANDLE,		/* evd_handle */
	const DAT_EVENT *);	/* event */

extern DAT_RETURN
dapl_evd_dequeue(
	IN DAT_EVD_HANDLE,	/* evd_handle */
	OUT DAT_EVENT *);	/* event */

extern DAT_RETURN
dapl_evd_free(IN DAT_EVD_HANDLE);

extern DAT_RETURN
dapl_evd_set_unwaitable(IN DAT_EVD_HANDLE evd_handle);

extern DAT_RETURN
dapl_evd_clear_unwaitable(IN DAT_EVD_HANDLE evd_handle);


/* EP functions */
extern DAT_RETURN
dapl_ep_create(
	IN DAT_IA_HANDLE,	/* ia_handle */
	IN DAT_PZ_HANDLE,	/* pz_handle */
	IN DAT_EVD_HANDLE,	/* in_dto_completion_evd_handle */
	IN DAT_EVD_HANDLE,	/* out_dto_completion_evd_handle */
	IN DAT_EVD_HANDLE,	/* connect_evd_handle */
	IN const DAT_EP_ATTR *,	/* ep_parameters */
	OUT DAT_EP_HANDLE *);	/* ep_handle */

extern DAT_RETURN
dapl_ep_query(
	IN DAT_EP_HANDLE,	/* ep_handle */
	IN DAT_EP_PARAM_MASK,	/* ep_args_mask */
	OUT DAT_EP_PARAM *);	/* ep_args */

extern DAT_RETURN
dapl_ep_modify(
	IN DAT_EP_HANDLE,		/* ep_handle */
	IN DAT_EP_PARAM_MASK,		/* ep_args_mask */
	IN const DAT_EP_PARAM *);	/* ep_args */

extern DAT_RETURN
dapl_ep_connect(
	IN DAT_EP_HANDLE,	/* ep_handle */
	IN DAT_IA_ADDRESS_PTR,	/* remote_ia_address */
	IN DAT_CONN_QUAL,	/* remote_conn_qual */
	IN DAT_TIMEOUT,		/* timeout */
	IN DAT_COUNT,		/* private_data_size */
	IN const DAT_PVOID,	/* private_data  */
	IN DAT_QOS,		/* quality_of_service */
	IN DAT_CONNECT_FLAGS);	/* connect_flags */

extern DAT_RETURN
dapl_ep_dup_connect(
	IN DAT_EP_HANDLE,	/* ep_handle */
	IN DAT_EP_HANDLE,	/* ep_dup_handle */
	IN DAT_TIMEOUT,		/* timeout */
	IN DAT_COUNT,		/* private_data_size */
	IN const DAT_PVOID,	/* private_data */
	IN DAT_QOS);		/* quality_of_service */

extern DAT_RETURN
dapl_ep_disconnect(
	IN DAT_EP_HANDLE,	/* ep_handle */
	IN DAT_CLOSE_FLAGS);	/* completion_flags */

extern DAT_RETURN
dapl_ep_post_send(
	IN DAT_EP_HANDLE,		/* ep_handle */
	IN DAT_COUNT,			/* num_segments */
	IN DAT_LMR_TRIPLET *,		/* local_iov */
	IN DAT_DTO_COOKIE,		/* user_cookie */
	IN DAT_COMPLETION_FLAGS);	/* completion_flags */

extern DAT_RETURN
dapl_ep_post_recv(
	IN DAT_EP_HANDLE,		/* ep_handle */
	IN DAT_COUNT,			/* num_segments */
	IN DAT_LMR_TRIPLET *,		/* local_iov */
	IN DAT_DTO_COOKIE,		/* user_cookie */
	IN DAT_COMPLETION_FLAGS);	/* completion_flags */

extern DAT_RETURN
dapl_ep_post_rdma_read(
	IN DAT_EP_HANDLE,		/* ep_handle */
	IN DAT_COUNT,			/* num_segments */
	IN DAT_LMR_TRIPLET *,		/* local_iov */
	IN DAT_DTO_COOKIE,		/* user_cookie */
	IN const DAT_RMR_TRIPLET *,	/* remote_iov */
	IN DAT_COMPLETION_FLAGS);	/* completion_flags */

extern DAT_RETURN
dapl_ep_post_rdma_write(
	IN DAT_EP_HANDLE,		/* ep_handle */
	IN DAT_COUNT,			/* num_segments */
	IN DAT_LMR_TRIPLET *,		/* local_iov */
	IN DAT_DTO_COOKIE,		/* user_cookie */
	IN const DAT_RMR_TRIPLET *,	/* remote_iov */
	IN DAT_COMPLETION_FLAGS);	/* completion_flags */

extern DAT_RETURN
dapl_ep_get_status(
	IN DAT_EP_HANDLE,	/* ep_handle */
	OUT DAT_EP_STATE *,	/* ep_state */
	OUT DAT_BOOLEAN *,	/* in_dto_idle */
	OUT DAT_BOOLEAN *);	/* out_dto_idle */

extern DAT_RETURN
dapl_ep_free(IN DAT_EP_HANDLE);		/* ep_handle */

extern DAT_RETURN
dapl_ep_reset(IN DAT_EP_HANDLE);	/* ep_handle */


/* LMR functions */
extern DAT_RETURN
dapl_lmr_create(
	IN DAT_IA_HANDLE,		/* ia_handle */
	IN DAT_MEM_TYPE,		/* mem_type */
	IN DAT_REGION_DESCRIPTION,	/* region_description */
	IN DAT_VLEN,			/* length */
	IN DAT_PZ_HANDLE,		/* pz_handle */
	IN DAT_MEM_PRIV_FLAGS,		/* privileges */
	OUT DAT_LMR_HANDLE *,		/* lmr_handle */
	OUT DAT_LMR_CONTEXT *,		/* lmr_context */
	OUT DAT_RMR_CONTEXT *,		/* rmr_context */
	OUT DAT_VLEN *,			/* registered_length */
	OUT DAT_VADDR *);		/* registered_address */

extern DAT_RETURN
dapl_lmr_query(
	IN DAT_LMR_HANDLE,
	IN DAT_LMR_PARAM_MASK,
	OUT DAT_LMR_PARAM *);

extern DAT_RETURN
dapl_lmr_free(IN DAT_LMR_HANDLE);


/* RMR Functions */
extern DAT_RETURN
dapl_rmr_create(
	IN DAT_PZ_HANDLE,	/* pz_handle */
	OUT DAT_RMR_HANDLE *);	/* rmr_handle */

extern DAT_RETURN
dapl_rmr_query(
	IN DAT_RMR_HANDLE,	/* rmr_handle */
	IN DAT_RMR_PARAM_MASK,	/* rmr_args_mask */
	OUT DAT_RMR_PARAM *);	/* rmr_args */

extern DAT_RETURN
dapl_rmr_bind(
	IN DAT_RMR_HANDLE,		/* rmr_handle */
	IN const DAT_LMR_TRIPLET *,	/* lmr_triplet */
	IN DAT_MEM_PRIV_FLAGS,		/* mem_priv */
	IN DAT_EP_HANDLE,		/* ep_handle */
	IN DAT_RMR_COOKIE,		/* user_cookie */
	IN DAT_COMPLETION_FLAGS,	/* completion_flags */
	INOUT DAT_RMR_CONTEXT *);	/* context */

extern DAT_RETURN
dapl_rmr_free(IN DAT_RMR_HANDLE);


/* PSP Functions */
extern DAT_RETURN
dapl_psp_create(
	IN DAT_IA_HANDLE,	/* ia_handle */
	IN DAT_CONN_QUAL,	/* conn_qual */
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_PSP_FLAGS,	/* psp_flags */
	OUT DAT_PSP_HANDLE *);	/* psp_handle */

extern DAT_RETURN
dapl_psp_create_any(
	IN DAT_IA_HANDLE,	/* ia_handle */
	OUT DAT_CONN_QUAL *,	/* conn_qual */
	IN DAT_EVD_HANDLE,	/* evd_handle */
	IN DAT_PSP_FLAGS,	/* psp_flags */
	OUT DAT_PSP_HANDLE *);	/* psp_handle */

extern DAT_RETURN
dapl_psp_query(
	IN DAT_PSP_HANDLE,
	IN DAT_PSP_PARAM_MASK,
	OUT DAT_PSP_PARAM *);

extern DAT_RETURN
dapl_psp_free(IN DAT_PSP_HANDLE);	/* psp_handle */


/* RSP Functions */
extern DAT_RETURN
dapl_rsp_create(
	IN DAT_IA_HANDLE,	/* ia_handle */
	IN DAT_CONN_QUAL,	/* conn_qual */
	IN DAT_EP_HANDLE,	/* ep_handle */
	IN DAT_EVD_HANDLE,	/* evd_handle */
	OUT DAT_RSP_HANDLE *);	/* rsp_handle */

extern DAT_RETURN
dapl_rsp_query(
	IN DAT_RSP_HANDLE,
	IN DAT_RSP_PARAM_MASK,
	OUT DAT_RSP_PARAM *);

extern DAT_RETURN
dapl_rsp_free(IN DAT_RSP_HANDLE);	/* rsp_handle */


/* PZ Functions */
extern DAT_RETURN
dapl_pz_create(
	IN DAT_IA_HANDLE,	/* ia_handle */
	OUT DAT_PZ_HANDLE *);	/* pz_handle */

extern DAT_RETURN
dapl_pz_query(
	IN DAT_PZ_HANDLE,	/* pz_handle */
	IN DAT_PZ_PARAM_MASK,	/* pz_args_mask */
	OUT DAT_PZ_PARAM *);	/* pz_args */

extern DAT_RETURN
dapl_pz_free(IN DAT_PZ_HANDLE);	/* pz_handle */

/* Non-coherent memory fucntions */

extern DAT_RETURN dapl_lmr_sync_rdma_read(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	const DAT_LMR_TRIPLET *, /* local_segments	*/
	IN	DAT_VLEN);		/* num_segments		*/

extern DAT_RETURN dapl_lmr_sync_rdma_write(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	const DAT_LMR_TRIPLET *, /* local_segments	*/
	IN	DAT_VLEN);		/* num_segments		*/

/*
 * SRQ functions
 */
extern DAT_RETURN dapl_ep_create_with_srq(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_PZ_HANDLE,		/* pz_handle		*/
	IN	DAT_EVD_HANDLE,		/* recv_evd_handle	*/
	IN	DAT_EVD_HANDLE,		/* request_evd_handle	*/
	IN	DAT_EVD_HANDLE,		/* connect_evd_handle	*/
	IN	DAT_SRQ_HANDLE,		/* srq_handle		*/
	IN	const DAT_EP_ATTR *,	/* ep_attributes	*/
	OUT	DAT_EP_HANDLE *);	/* ep_handle		*/

extern DAT_RETURN dapl_ep_recv_query(
	IN	DAT_EP_HANDLE,		/* ep_handle		*/
	OUT	DAT_COUNT *,		/* nbufs_allocated	*/
	OUT	DAT_COUNT *);		/* bufs_alloc_span	*/

extern DAT_RETURN dapl_ep_set_watermark(
	IN	DAT_EP_HANDLE,		/* ep_handle		*/
	IN	DAT_COUNT,		/* soft_high_watermark	*/
	IN	DAT_COUNT);		/* hard_high_watermark	*/

extern DAT_RETURN dapl_srq_create(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_PZ_HANDLE,		/* pz_handle		*/
	IN	DAT_SRQ_ATTR *,		/* srq_attr		*/
	OUT	DAT_SRQ_HANDLE *);	/* srq_handle		*/

extern DAT_RETURN dapl_srq_free(
	IN	DAT_SRQ_HANDLE);	/* srq_handle		*/

extern DAT_RETURN dapl_srq_post_recv(
	IN	DAT_SRQ_HANDLE,		/* srq_handle		*/
	IN	DAT_COUNT,		/* num_segments		*/
	IN	DAT_LMR_TRIPLET *,	/* local_iov		*/
	IN	DAT_DTO_COOKIE);	/* user_cookie		*/

extern DAT_RETURN dapl_srq_query(
	IN	DAT_SRQ_HANDLE,		/* srq_handle		*/
	IN	DAT_SRQ_PARAM_MASK,	/* srq_param_mask	*/
	OUT	DAT_SRQ_PARAM *);	/* srq_param		*/

extern DAT_RETURN dapl_srq_resize(
	IN	DAT_SRQ_HANDLE,		/* srq_handle		*/
	IN	DAT_COUNT);		/* srq_max_recv_dto	*/

extern DAT_RETURN dapl_srq_set_lw(
	IN	DAT_SRQ_HANDLE,		/* srq_handle		*/
	IN	DAT_COUNT);		/* low_watermark	*/


/*
 * DAPL internal utility function prototpyes
 */
extern void
dapl_llist_init_head(DAPL_LLIST_HEAD *head);

extern void
dapl_llist_init_entry(DAPL_LLIST_ENTRY *entry);

extern DAT_BOOLEAN
dapl_llist_is_empty(DAPL_LLIST_HEAD *head);

extern void
dapl_llist_add_head(
	DAPL_LLIST_HEAD *head,
	DAPL_LLIST_ENTRY *entry,
	void *data);

extern void
dapl_llist_add_tail(
	DAPL_LLIST_HEAD *head,
	DAPL_LLIST_ENTRY *entry,
	void *data);

extern void
dapl_llist_add_entry(
	DAPL_LLIST_HEAD *head,
	DAPL_LLIST_ENTRY *entry,
	DAPL_LLIST_ENTRY *new_entry,
	void *data);

extern void *
dapl_llist_remove_head(DAPL_LLIST_HEAD *head);

extern void *
dapl_llist_remove_tail(DAPL_LLIST_HEAD *head);

extern void *
dapl_llist_remove_entry(DAPL_LLIST_HEAD *head,
	DAPL_LLIST_ENTRY *entry);

extern void *
dapl_llist_peek_head(DAPL_LLIST_HEAD *head);

extern void *
dapl_llist_next_entry(
	IN DAPL_LLIST_HEAD *head,
	IN DAPL_LLIST_ENTRY *cur_ent);

extern void
dapl_llist_debug_print_list(DAPL_LLIST_HEAD *head);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_H_ */
