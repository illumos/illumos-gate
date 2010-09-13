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

#ifndef	_DAPL_H_
#define	_DAPL_H_

#ifdef __cplusplus
extern "C" {
#endif

#define	DAPLKA_VERSION		(1)
#define	DAPLKA_TQ_NTHREADS	16
#define	DAPLKA_STATE_DETACHED	0x0000
#define	DAPLKA_STATE_ATTACHED	0x0001

/*
 * HCA structure
 */
typedef struct daplka_hca {
	ib_guid_t		hca_guid;
	ibt_hca_hdl_t		hca_hdl;
	ibt_hca_attr_t		hca_attr;
	uint32_t		hca_nports;
	ibt_hca_portinfo_t	*hca_ports;
	size_t			hca_pinfosz;
	uint32_t		hca_qp_count;
	uint32_t		hca_cq_count;
	uint32_t		hca_pd_count;
	uint32_t		hca_mw_count;
	uint32_t		hca_mr_count;
	uint32_t		hca_srq_count;
	int			hca_ref_cnt;
	struct daplka_hca	*hca_next;
} daplka_hca_t;
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_hca))

/*
 * Per-Device instance state information.
 */
typedef struct daplka {
	kmutex_t		daplka_mutex;
	dev_info_t		*daplka_dip;
	ibt_clnt_hdl_t		daplka_clnt_hdl;
	daplka_hca_t		*daplka_hca_list_head;
	uint32_t		daplka_status;
} daplka_t;

/*
 * generic hash table
 */
typedef struct daplka_hash_entry {
	uint64_t			he_hkey;
	void				*he_objp;
	struct daplka_hash_entry	*he_next;
} daplka_hash_entry_t;

typedef struct daplka_hash_bucket {
	uint32_t			hb_count;
	daplka_hash_entry_t		*hb_entries;
} daplka_hash_bucket_t;

typedef struct daplka_hash_table {
	boolean_t			ht_initialized;
	uint32_t			ht_count;
	uint32_t			ht_nbuckets;
	uint64_t			ht_next_hkey;
	krwlock_t			ht_table_lock;
	kmutex_t			ht_key_lock;
	daplka_hash_bucket_t		*ht_buckets;
	void				(*ht_free_func)(void *);
	void				(*ht_lookup_func)(void *);
} daplka_hash_table_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_hash_entry))
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_hash_bucket))
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_hash_table))
_NOTE(MUTEX_PROTECTS_DATA(daplka_hash_table::ht_key_lock,
    daplka_hash_table::ht_next_hkey))
_NOTE(RWLOCK_PROTECTS_DATA(daplka_hash_table::ht_table_lock,
    daplka_hash_table::ht_buckets
    daplka_hash_table::ht_count))

/*
 * resource structure header
 */
typedef struct daplka_resource {
	uint_t			rs_type;
	minor_t			rs_rnum;
	kmutex_t 		rs_reflock;
	uint32_t		rs_refcnt;
	uint32_t		rs_charged;
	int			(*rs_free)(struct daplka_resource *);
} daplka_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_resource))
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_resource::rs_charged))
_NOTE(MUTEX_PROTECTS_DATA(daplka_resource::rs_reflock,
    daplka_resource::rs_refcnt))

#define	DAPLKA_EP_HTBL_SZ	128
#define	DAPLKA_MR_HTBL_SZ	64
#define	DAPLKA_MW_HTBL_SZ	64
#define	DAPLKA_PD_HTBL_SZ	32
#define	DAPLKA_SP_HTBL_SZ	32
#define	DAPLKA_EVD_HTBL_SZ	32
#define	DAPLKA_G_SP_HTBL_SZ	512
#define	DAPLKA_TIMER_HTBL_SZ	512
#define	DAPLKA_CNO_HTBL_SZ	16
#define	DAPLKA_SRQ_HTBL_SZ	32

typedef struct daplka_async_evd_hkey_s {
	struct daplka_async_evd_hkey_s	*aeh_next;
	uint64_t			aeh_evd_hkey;
} daplka_async_evd_hkey_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_async_evd_hkey_s))

/*
 * Various states IA can be in, this is primarily for handling race
 * between MW allocation and MR cleanup callback.
 */
typedef enum daplka_ia_state_e {
	DAPLKA_IA_INIT = 0,
	DAPLKA_IA_MW_ALLOC_IN_PROGRESS,
	DAPLKA_IA_MW_FREEZE_IN_PROGRESS,
	DAPLKA_IA_MW_FROZEN
} daplka_ia_state_t;

typedef struct daplka_ia_resource {
	daplka_resource_t	header;
	kmutex_t		ia_lock;
	kcondvar_t		ia_cv;
	daplka_ia_state_t	ia_state;
	ibt_hca_hdl_t		ia_hca_hdl;
	ib_gid_t		ia_hca_sgid;
	daplka_hca_t		*ia_hca;
	uint8_t			ia_port_num;
	uint32_t		ia_port_pkey;
	pid_t			ia_pid;
	uint32_t		ia_mw_alloccnt; /* # mw allocs in progress */
	daplka_async_evd_hkey_t	*ia_async_evd_hkeys; /* hash key of async evd */
	daplka_hash_table_t	ia_ep_htbl;
	daplka_hash_table_t	ia_mr_htbl;
	daplka_hash_table_t	ia_mw_htbl;
	daplka_hash_table_t	ia_pd_htbl;
	daplka_hash_table_t	ia_evd_htbl;
	daplka_hash_table_t	ia_sp_htbl;
	daplka_hash_table_t	ia_cno_htbl;
	daplka_hash_table_t	ia_srq_htbl;
	uint8_t			ia_sadata[DAPL_ATS_NBYTES]; /* SA data */
	boolean_t		ia_ar_registered;
} daplka_ia_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_ia_resource))
_NOTE(MUTEX_PROTECTS_DATA(daplka_ia_resource::ia_lock,
    daplka_ia_resource::ia_cv
    daplka_ia_resource::ia_async_evd_hkeys
    daplka_ia_resource::ia_mw_alloccnt
    daplka_ia_resource::ia_state
    daplka_async_evd_hkey_s))

typedef struct daplka_pd_resource {
	daplka_resource_t	header;
	daplka_hca_t		*pd_hca;
	ibt_hca_hdl_t		pd_hca_hdl;
	ibt_pd_hdl_t		pd_hdl;
} daplka_pd_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_pd_resource))

/*
 * Passive side EP cookies - this is generated at the connection request
 * time and unique for every CR. It gets associated with the EP that
 * is passed to the CR accept.
 *
 * daplka_psep_cookie contains the following information
 *   - 48 bit timestamp (unit = 1/10us)
 *   - 16 bit index in the psp backlog array corr to this CR event
 * this makes it unique for every CR.
 */
typedef uint64_t daplka_psep_cookie_t;
#define	DAPLKA_CREATE_PSEP_COOKIE(index)	\
			((uint64_t)((gethrtime()/100)<<16 | (index)))
#define	DAPLKA_GET_PSEP_INDEX(cookie)					\
					((uint16_t)((uint64_t)(cookie) &\
						0xffff))

/*
 * daplka_evd_cme_t defines connection manager events that can be
 * chained to the daplka_evd_cme_list_t.
 */
typedef struct daplka_evd_cme_s {
	dapl_ib_cm_event_type_t	ec_cm_ev_type;
	/* ec_cm_cookie is the SP(passive)/EP(active) cookie */
	uint64_t		ec_cm_cookie;
	/* ec_cm_ev_session_id is the cookie for DEFER processing */
	void			*ec_cm_ev_session_id;
	/* true - passive side event, false - active side event */
	boolean_t		ec_cm_is_passive;
	daplka_psep_cookie_t	ec_cm_psep_cookie;
	ib_gid_t		ec_cm_req_prim_addr; /* requestor gid */
	ibt_priv_data_len_t	ec_cm_ev_priv_data_len;
	void			*ec_cm_ev_priv_data;
} daplka_evd_cme_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_evd_cme_s))

typedef enum daplka_evd_event_type_e {
	DAPLKA_EVD_NO_EVENTS = 0x00,
	DAPLKA_EVD_ULAND_EVENTS = 0x01, /* userland events ie. CQ or SE */
	DAPLKA_EVD_CM_EVENTS = 0x02,
	DAPLKA_EVD_ASYNC_EVENTS = 0x04
} daplka_evd_event_type_t;

/*
 * daplka_evd_event_t defines elements in the event list - this is
 * used for both async as well as connection manager events
 */
typedef struct daplka_evd_event_s {
	struct daplka_evd_event_s	*ee_next;
	union {
		dapl_ib_async_event_t		aev;
		daplka_evd_cme_t		cmev;
	} ee_event;
#define	ee_aev	ee_event.aev
#define	ee_cmev	ee_event.cmev
} daplka_evd_event_t;

typedef struct daplka_evd_event_list_s {
	daplka_evd_event_type_t	eel_event_type;
	uint32_t		eel_num_elements;
	daplka_evd_event_t	*eel_head;
	daplka_evd_event_t	*eel_tail;
} daplka_evd_event_list_t;

typedef struct daplka_evd_resource {
	daplka_resource_t	header;
	kmutex_t		evd_lock;
	kcondvar_t		evd_cv;
	DAT_EVD_FLAGS		evd_flags;
	daplka_evd_event_type_t	evd_newevents; /* DAPLKA_EVD_*_EVENTS */
	ibt_cq_hdl_t		evd_cq_hdl;
	uint32_t		evd_cq_real_size;
	daplka_evd_event_list_t	evd_cr_events; /* connect request event */
	daplka_evd_event_list_t	evd_conn_events; /* connection events */
	daplka_evd_event_list_t	evd_async_events; /* aysnc events list */
	ibt_hca_hdl_t		evd_hca_hdl;
	daplka_hca_t		*evd_hca;
	uint32_t		evd_waiters;
	uint64_t		evd_cookie;
	struct daplka_cno_resource	*evd_cno_res;
} daplka_evd_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_evd_event_s))
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_evd_event_s))
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_evd_event_list_s))
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_evd_resource))
_NOTE(MUTEX_PROTECTS_DATA(daplka_evd_resource::evd_lock,
    daplka_evd_resource::evd_cv
    daplka_evd_resource::evd_flags
    daplka_evd_resource::evd_newevents
    daplka_evd_resource::evd_cr_events
    daplka_evd_resource::evd_conn_events
    daplka_evd_resource::evd_async_events
    daplka_evd_resource::evd_waiters))

typedef struct daplka_srq_resource {
	daplka_resource_t	header;
	kmutex_t		srq_lock;
	daplka_hca_t		*srq_hca;
	ibt_hca_hdl_t		srq_hca_hdl;
	daplka_pd_resource_t	*srq_pd_res;
	ibt_srq_hdl_t		srq_hdl;
	uint32_t		srq_real_size;
} daplka_srq_resource_t;
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_srq_resource))

#define	DAPLKA_EP_STATE_CLOSED		0x0001
#define	DAPLKA_EP_STATE_CONNECTING	0x0002
#define	DAPLKA_EP_STATE_ACCEPTING	0x0003
#define	DAPLKA_EP_STATE_CONNECTED	0x0004
#define	DAPLKA_EP_STATE_DISCONNECTING	0x0005
#define	DAPLKA_EP_STATE_ABORTING	0x0006
#define	DAPLKA_EP_STATE_DISCONNECTED	0x0007
#define	DAPLKA_EP_STATE_TRANSITIONING	0x0008
#define	DAPLKA_EP_STATE_FREED		0x0009

typedef struct daplka_ep_resource {
	daplka_resource_t	header;
	kmutex_t		ep_lock;
	kcondvar_t		ep_cv;
	uint64_t		ep_cookie; /* userland ep pointer */
	daplka_hca_t		*ep_hca;
	ibt_channel_hdl_t	ep_chan_hdl;
	daplka_evd_resource_t	*ep_snd_evd;
	daplka_evd_resource_t	*ep_rcv_evd;
	daplka_evd_resource_t	*ep_conn_evd;
	daplka_evd_resource_t	*ep_bind_evd;
	daplka_pd_resource_t	*ep_pd_res;
	daplka_srq_resource_t	*ep_srq_res;
	uint32_t		ep_state;
	uint64_t		ep_timer_hkey;
	daplka_psep_cookie_t	ep_psep_cookie; /* passive side ep cookie */
	ibt_priv_data_len_t	ep_priv_len;
	uint8_t			ep_priv_data[IBT_REP_PRIV_DATA_SZ];
	ib_gid_t		ep_sgid;
	ib_gid_t		ep_dgid;
} daplka_ep_resource_t;
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_ep_resource))

typedef struct daplka_timer_info {
	daplka_ep_resource_t	*ti_ep_res;
	timeout_id_t		ti_tmo_id;
} daplka_timer_info_t;
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_timer_info))

typedef struct daplka_mr_resource {
	daplka_resource_t		header;
	daplka_pd_resource_t		*mr_pd_res;
	daplka_hca_t			*mr_hca;
	ibt_hca_hdl_t			mr_hca_hdl;
	ibt_mr_hdl_t			mr_hdl;
	ibt_mr_attr_t			mr_attr;
	ibt_mr_desc_t			mr_desc;
	kmutex_t			mr_lock;
	struct daplka_mr_resource	*mr_next;
	struct daplka_shared_mr		*mr_shared_mr;
} daplka_mr_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_mr_resource))
_NOTE(MUTEX_PROTECTS_DATA(daplka_mr_resource::mr_lock,
    daplka_mr_resource::mr_shared_mr))

typedef struct daplka_mw_resource {
	daplka_resource_t	header;
	daplka_pd_resource_t	*mw_pd_res;
	daplka_hca_t		*mw_hca;
	ibt_hca_hdl_t		mw_hca_hdl;
	ibt_mw_hdl_t		mw_hdl;
	kmutex_t		mw_lock;
} daplka_mw_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_mw_resource))

/*
 * This describes the elements in a connection pending list that each SP
 * maintains. Fields are protected using the sp_lock.
 */
typedef enum {
	DAPLKA_SPCP_INIT = 0,
	DAPLKA_SPCP_PENDING
} daplka_spcp_state_t;

typedef struct daplka_sp_conn_pend_s {
	daplka_spcp_state_t	spcp_state;
	void			*spcp_sid; /* session id for cm_proceed */
	uint32_t		spcp_req_len; /* used by cr_handoff */
	char			spcp_req_data[DAPL_MAX_PRIVATE_DATA_SIZE];
	uint8_t			spcp_rdma_ra_out;
	uint8_t			spcp_rdma_ra_in;
} daplka_sp_conn_pend_t;

#define	DAPLKA_DEFAULT_SP_BACKLOG	256
typedef struct daplka_sp_resource {
	daplka_resource_t	header;
	kmutex_t		sp_lock;
	ibt_srv_hdl_t		sp_srv_hdl;
	ibt_sbind_hdl_t		sp_bind_hdl;
	uint64_t		sp_cookie; /* userland sp pointer */
	int			sp_backlog_size; /* # elements backlog */
	daplka_sp_conn_pend_t	*sp_backlog; /* pending conn backlog array */
	daplka_evd_resource_t	*sp_evd_res;
	ib_svc_id_t		sp_conn_qual;
	uint64_t		sp_global_hkey;
	uid_t			sp_ruid;
} daplka_sp_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_sp_resource))
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_sp_conn_pend_s))
_NOTE(MUTEX_PROTECTS_DATA(daplka_sp_resource::sp_lock,
    daplka_sp_resource::sp_backlog))

typedef struct daplka_cno_resource {
	daplka_resource_t	header;
	kmutex_t		cno_lock;
	kcondvar_t		cno_cv;
	uint64_t		cno_evd_cookie;
} daplka_cno_resource_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_cno_resource))
_NOTE(MUTEX_PROTECTS_DATA(daplka_cno_resource::cno_lock,
    daplka_cno_resource::cno_cv
    daplka_cno_resource::cno_evd_cookie))

#define	DAPLKA_SMR_FREED		0x0000
#define	DAPLKA_SMR_TRANSITIONING	0x0001
#define	DAPLKA_SMR_READY		0x0002
typedef struct daplka_shared_mr {
	avl_node_t		smr_node;
	uint32_t		smr_refcnt;
	uint32_t		smr_state;
	daplka_mr_resource_t	*smr_mr_list;
	kcondvar_t		smr_cv;
	dapl_mr_cookie_t	smr_cookie;
} daplka_shared_mr_t;
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_shared_mr))
_NOTE(SCHEME_PROTECTS_DATA("daplka", daplka_shared_mr::smr_mr_list))

/*
 * resource table data structures
 */
#define	DAPLKA_RC_BLKSZ		16
#define	DAPLKA_RC_RESERVED	0xff
typedef struct daplka_resource_blk {
	int			daplka_rcblk_avail;
	daplka_resource_t	*daplka_rcblk_blks[DAPLKA_RC_BLKSZ];
} daplka_resource_blk_t;

struct daplka_resource_table {
	krwlock_t	daplka_rct_lock;
	int		daplka_rc_len;
	int		daplka_rc_sz;
	int		daplka_rc_cnt;
	ushort_t	daplka_rc_flag;
	daplka_resource_blk_t **daplka_rc_root;
};
_NOTE(DATA_READABLE_WITHOUT_LOCK(daplka_resource_table))
_NOTE(RWLOCK_PROTECTS_DATA(daplka_resource_table::daplka_rct_lock,
    daplka_resource_table::daplka_rc_root))

#ifdef __cplusplus
}
#endif

#endif	/* _DAPL_H_ */
