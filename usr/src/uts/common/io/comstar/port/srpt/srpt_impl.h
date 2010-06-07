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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SRPT_IMPL_H_
#define	_SRPT_IMPL_H_

/*
 * Prototypes and data structures for the SRP Target Port Provider.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/modctl.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>

#include <sys/ib/mgt/ibdma/ibdma.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Format the session identifier */
#define	ALIAS_STR(s, a, b)						\
	((void) snprintf((s), sizeof ((s)), "%016llx:%016llx",		\
	    (u_longlong_t)(a), (u_longlong_t)(b)))

/* Format the EUI name */
#define	EUI_STR(s, a)							\
	((void) snprintf((s), sizeof ((s)), "eui.%016llX", (u_longlong_t)(a)))

/*
 * We should/could consider making some of these values tunables.
 * Specifically, SEND_MSG_SIZE and SEND_MSG_DEPTH.
 */
enum {
	SRPT_DEFAULT_IOC_SRQ_SIZE = 4096,
	SRPT_DEFAULT_SEND_MSG_DEPTH = 128,
	/*
	 * SEND_MSG_SIZE must be a multiple of 64 as it is registered
	 * as memory regions with IB.  To support a scatter/gather table
	 * size of 32, the size must be at not less than 960.  To support
	 * the maximum scatter/gather table size of 255, the IU must
	 * be at least 4160 bytes.
	 */
	SRPT_DEFAULT_SEND_MSG_SIZE = 4160,
	SRPT_DEFAULT_MAX_RDMA_SIZE = 65536,
	SRPT_MIN_T_I_IU_LEN = 52,
	SRPT_EUI_ID_LEN = 20,
	SRPT_RECV_WC_POLL_SIZE = 16,
	SRPT_SEND_WC_POLL_SIZE = 16,
	SRPT_MAX_OUT_IO_PER_CMD = 16,
	SRPT_FENCE_SEND = 1,
	SRPT_NO_FENCE_SEND = 0
};

struct srpt_target_port_s;

#define	SRPT_ALIAS_LEN	(SRP_PORT_ID_LEN * 2 + 2)

/*
 * SRP Session - represents a SCSI I_T_Nexus.
 *
 * Sessions map 1 or more initiator logins to a specific I/O
 * Controller SCSI Target Port.  Targets create sessions
 * at initiator login and release when no longer referenced
 * by a login.
 */
typedef struct srpt_session_s {
	krwlock_t 			ss_rwlock;
	list_node_t			ss_node;

	/*
	 * ADVANCED FEATURE, NOT YET SUPPORTED.
	 * In multi-channel mode, multiple RDMA communication
	 * channels may reference the same SCSI session.  When
	 * a channel releases its reference to the SCSI session,
	 * it should have no tasks associated with the session.
	 *
	 * If multi-channel is implemented, add a channel list
	 * to this object instead of tracking it on the target.
	 *
	 * Will also need a session state & mode.  Mode is to
	 * track if the session is MULTI or SINGLE channel.
	 */

	stmf_scsi_session_t		*ss_ss;
	struct srpt_target_port_s	*ss_tgt;
	list_t				ss_task_list;

	/*
	 * SRP Initiator and target identifiers are 128-bit.
	 *
	 * The specification defines the initiator to be 64-bits of
	 * ID extension and 64 bits of GUID, but these are really
	 * just a recommendation.  Generally the extension is used
	 * to create unique I_T_Nexus from the same initiator and
	 * target.  Initiators are inconsistent on the GUID they
	 * use, some use the HCA Node, some the HCA port.
	 *
	 * The specification defines the target to be 64-bits of
	 * service ID followed by 64-bits of I/O Controller GUID.
	 * In the case where there is a single default target
	 * service, they will be the same (our default).
	 */
	uint8_t				ss_i_id[SRP_PORT_ID_LEN];
	uint8_t				ss_t_id[SRP_PORT_ID_LEN];

	/* So we can see the full 128-bit initiator login from stmfadm */
	char				ss_i_alias[SRPT_ALIAS_LEN];
	uint8_t				ss_hw_port;

	char				ss_t_alias[SRPT_ALIAS_LEN];
	char				ss_i_name[SRPT_EUI_ID_LEN + 1];
	char				ss_t_name[SRPT_EUI_ID_LEN + 1];
	char				ss_i_gid[SRPT_ALIAS_LEN];
	char				ss_t_gid[SRPT_ALIAS_LEN];
} srpt_session_t;

/*
 * Send work request types.
 */
typedef enum srpt_swqe_type_e {
	SRPT_SWQE_TYPE_DATA = 1,
	SRPT_SWQE_TYPE_RESP
} srpt_swqe_type_t;

typedef struct srpt_swqe_s {
	srpt_swqe_type_t	sw_type;
	void			*sw_addr;
	ibt_wrid_t		sw_next;
} srpt_swqe_t;

/*
 * SRP Channel - the RDMA communications channel associated with
 * a specific SRP login.
 */
typedef enum srpt_channel_state_e {
	SRPT_CHANNEL_CONNECTING = 0,
	SRPT_CHANNEL_CONNECTED,
	SRPT_CHANNEL_DISCONNECTING
} srpt_channel_state_t;

typedef struct srpt_channel_s {
	krwlock_t 			ch_rwlock;

	kmutex_t			ch_reflock;
	uint_t				ch_refcnt;
	kcondvar_t			ch_cv_complete;
	uint_t				ch_cv_waiters;

	list_node_t			ch_stp_node;
	srpt_channel_state_t		ch_state;
	ibt_cq_hdl_t			ch_scq_hdl;
	ibt_cq_hdl_t			ch_rcq_hdl;
	ibt_channel_hdl_t		ch_chan_hdl;
	ibt_chan_sizes_t		ch_sizes;

	uint32_t			ch_req_lim_delta;
	uint32_t			ch_ti_iu_len;
	struct srpt_target_port_s	*ch_tgt;
	srpt_session_t			*ch_session;

	/*
	 * Map IB send WQE request IDs to the
	 * apporpriate operation type (for errors).
	 */
	kmutex_t			ch_swqe_lock;
	srpt_swqe_t			*ch_swqe;
	uint32_t			ch_num_swqe;
	uint32_t			ch_head;
	uint32_t			ch_tail;
	uint32_t			ch_swqe_posted;
} srpt_channel_t;

/*
 * SRP Information Unit (IU).  Each IU structure contains
 * the buffer for the IU itself (received over the RC
 * channel), and all of the context required by the target
 * to process this request represented by the IU.
 * Available IU structures are managed on the I/O Controller
 * shared receive queue.
 */
enum {
	SRPT_IU_STMF_ABORTING	= 1 << 0,	/* STMF called abort */
	SRPT_IU_SRP_ABORTING	= 1 << 1,	/* SRP initiator aborting */
	SRPT_IU_ABORTED		= 1 << 2,	/* Task has been aborted */
	SRPT_IU_RESP_SENT	= 1 << 3	/* Response queued */
};

typedef struct srpt_iu_s {
	/*
	 * The buffer for the IU itself.  When unused (a
	 * reference count of zero), this buffer is posted
	 * on the I/O Controllers SRPT SRQ.
	 */
	void			*iu_buf;
	ibt_wr_ds_t		iu_sge;
	struct srpt_ioc_s	*iu_ioc;
	uint_t			iu_pool_ndx;
	kmutex_t		iu_lock;

	/*
	 * The following are reset for each IU request
	 * processed by this buffer.
	 */
	list_node_t		iu_ss_task_node;
	srpt_channel_t		*iu_ch;

	uint_t			iu_num_rdescs;
	srp_direct_desc_t	*iu_rdescs;
	uint_t			iu_tot_xfer_len;

	uint64_t		iu_tag;
	uint_t			iu_flags;
	uint32_t		iu_sq_posted_cnt;
	scsi_task_t		*iu_stmf_task;
} srpt_iu_t;

/*
 * SRP SCSI Target Port.  By default each HCA creates a single
 * SCSI Target Port based on the associated I/O Controller
 * (HCA) node GUID and made available through each physical
 * hardware port of the I/O Controller.
 */
typedef enum srpt_target_state_e {
	SRPT_TGT_STATE_OFFLINE = 0,
	SRPT_TGT_STATE_ONLINING,
	SRPT_TGT_STATE_ONLINE,
	SRPT_TGT_STATE_OFFLINING
} srpt_target_state_t;

typedef struct srpt_hw_port_s {
	ibt_sbind_hdl_t		hwp_bind_hdl;
	ib_gid_t		hwp_gid;
} srpt_hw_port_t;

typedef struct srpt_target_port_s {
	stmf_local_port_t	*tp_lport;
	struct srpt_ioc_s	*tp_ioc;

	kmutex_t		tp_lock;
	srpt_target_state_t	tp_state;
	kcondvar_t		tp_offline_complete;
	uint_t			tp_drv_disabled;

	/*
	 * We are using a simple list for channels right now, we
	 * probably should  switch this over to the AVL
	 * implementation eventually (but lookups are not done
	 * in the data path so this is not urgent).
	 */
	kmutex_t		tp_ch_list_lock;
	list_t			tp_ch_list;

	/*
	 * A list of active sessions.  Session lifetime is
	 * determined by having active channels, but track
	 * them here for easier determination to when a
	 * target can truly be offlined, and as a step toward
	 * being session-focused rather than channel-focused.
	 * If we ever truly support multi-channel, move the
	 * channels to be part of the session object.
	 *
	 * Sessions should remain on this list until they
	 * are deregistered from STMF.  This allows the target
	 * to properly track when it can consider itself 'offline'.
	 */
	kmutex_t		tp_sess_list_lock;
	kcondvar_t		tp_sess_complete;
	list_t			tp_sess_list;

	uint_t			tp_srp_enabled;
	ibt_srv_hdl_t		tp_ibt_svc_hdl;
	ibt_srv_desc_t		tp_ibt_svc_desc;
	ib_svc_id_t		tp_ibt_svc_id;
	scsi_devid_desc_t	*tp_scsi_devid;
	uint8_t			tp_srp_port_id[SRP_PORT_ID_LEN];

	uint_t			tp_nports;
	srpt_hw_port_t		*tp_hw_port;
	/*
	 * track the number of active ports so we can offline the target if
	 * none
	 */
	uint32_t		tp_num_active_ports;
	/* state STMF wants the target in.  We may be offline due to no ports */
	srpt_target_state_t	tp_requested_state;
} srpt_target_port_t;

/*
 * SRP Target hardware device.  A SRP Target hardware device
 * is an IB HCA.  All ports of the HCA comprise a single
 * I/O Controller that is registered with the IB Device
 * Managment Agent.
 */
typedef struct srpt_ioc_s {
	list_node_t			ioc_node;

	krwlock_t 			ioc_rwlock;
	ibt_hca_hdl_t			ioc_ibt_hdl;
	ibt_hca_attr_t			ioc_attr;
	ib_guid_t			ioc_guid;

	/*
	 * By default each HCA is a single SRP.T10 service based on
	 * the HCA GUID.  We have implemented the target here as a
	 * pointer to facilitate moving to a list of targets if
	 * appropriate down the road.
	 */
	srpt_target_port_t		*ioc_tgt_port;


	/*
	 * Each HCA registers a single I/O Controller with the
	 * IB Device Management Agent.
	 */
	ibdma_hdl_t			ioc_ibdma_hdl;
	ib_dm_ioc_ctrl_profile_t	ioc_profile;
	ib_dm_srv_t			ioc_svc;

	ibt_pd_hdl_t			ioc_pd_hdl;
	ibt_srq_sizes_t			ioc_srq_attr;
	ibt_srq_hdl_t			ioc_srq_hdl;

	/*
	 * The I/O Controller pool of IU resources allocated
	 * at controller creation.
	 */
	uint32_t			ioc_num_iu_entries;
	srpt_iu_t			*ioc_iu_pool;
	ibt_mr_hdl_t			ioc_iu_mr_hdl;
	void				*ioc_iu_bufs;  /* iu buffer space */

	/*
	 * Each I/O Controller has it's own data buffer
	 * vmem arena.  Pool is created at controller creation,
	 * and expanded as required.  This keeps IB memory
	 * registrations to a minimum in the data path.
	 */
	struct srpt_vmem_pool_s		*ioc_dbuf_pool;
	stmf_dbuf_store_t		*ioc_stmf_ds;
} srpt_ioc_t;

/*
 * Memory regions
 */
typedef struct srpt_mr_s {
	ibt_mr_hdl_t			mr_hdl;
	ib_vaddr_t			mr_va;
	ib_memlen_t			mr_len;
	ibt_lkey_t			mr_lkey;
	ibt_rkey_t			mr_rkey;
	avl_node_t			mr_avl;
} srpt_mr_t;

/*
 * SRP Target vmem arena definition
 */
typedef struct srpt_vmem_pool_s {
	srpt_ioc_t		*svp_ioc;
	ib_memlen_t		svp_chunksize;
	vmem_t			*svp_vmem;
	uint64_t		svp_total_size;
	uint64_t		svp_max_size;
	avl_tree_t		svp_mr_list;
	krwlock_t		svp_lock;
	ibt_mr_flags_t		svp_flags;
} srpt_vmem_pool_t;

/*
 * SRP port provider data buffer, allocated and freed
 * via calls to the IOC datastore.
 */
typedef struct srpt_ds_dbuf_s {
	stmf_data_buf_t			*db_stmf_buf;
	srpt_ioc_t			*db_ioc;
	ibt_mr_hdl_t			db_mr_hdl;
	ibt_wr_ds_t			db_sge;
	srpt_iu_t			*db_iu;
} srpt_ds_dbuf_t;

/*
 * SRP Target service state
 */
typedef enum {
	SRPT_SVC_DISABLED,
	SRPT_SVC_ENABLED
} srpt_svc_state_t;

typedef struct {
	ddi_modhandle_t		ibdmah;
	ibdma_hdl_t		(*ibdma_register)(ib_guid_t,
				    ib_dm_ioc_ctrl_profile_t *, ib_dm_srv_t *);
	ibdma_status_t		(*ibdma_unregister)(ibdma_hdl_t);
	ibdma_status_t		(*ibdma_update)(ibdma_hdl_t,
				    ib_dm_ioc_ctrl_profile_t *, ib_dm_srv_t *);
} srpt_ibdma_ops_t;

/*
 * SRP Target protocol driver context data structure, maintaining
 * the global state of the protocol.
 */
typedef struct srpt_ctxt_s {
	dev_info_t			*sc_dip;
	krwlock_t			sc_rwlock;
	srpt_svc_state_t		sc_svc_state;

	ibt_clnt_hdl_t			sc_ibt_hdl;

	/*
	 * SRP Target I/O Controllers. Each IBT HCA represents an
	 * I/O Controller.  Must hold rwlock as a writer to update.
	 */
	list_t				sc_ioc_list;
	uint_t				sc_num_iocs;

	/* Back-end COMSTAR port provider interface. */
	stmf_port_provider_t		*sc_pp;

	/* IBDMA entry points */
	srpt_ibdma_ops_t		sc_ibdma_ops;

	/*
	 *  List of explicitly configured HCAs and their configurable
	 *  attributes.
	 */
	nvlist_t			*sc_cfg_hca_nv;
} srpt_ctxt_t;

typedef struct srpt_iu_data_s {
	union {
		uint8_t			srp_op;
		srp_cmd_req_t		srp_cmd;
		srp_tsk_mgmt_t		srp_tsk_mgmt;
		srp_i_logout_t		srp_i_logout;
		srp_rsp_t		srp_rsp;
	} rx_iu;
} srpt_iu_data_t;

extern srpt_ctxt_t *srpt_ctxt;

/*
 * For Non recoverable or Major Errors
 */
#define	SRPT_LOG_L0	0

/*
 * For additional information on Non recoverable errors and
 * warnings/informational message for sys-admin types.
 */
#define	SRPT_LOG_L1	1

/*
 * debug only
 * for more verbose trace than L1, for e.g. recoverable errors,
 * or intersting trace
 */
#define	SRPT_LOG_L2	2

/*
 * debug only
 * for more verbose trace than L2, for e.g. printing function entries....
 */
#define	SRPT_LOG_L3	3

/*
 * debug only
 * for more verbose trace than L3, for e.g. printing minor function entries...
 */
#define	SRPT_LOG_L4	4

/*
 * srpt_errlevel can be set in the debugger to enable additional logging.
 * You can also add set srpt:srpt_errlevel={0,1,2,3,4} in /etc/system.
 * The default log level is L1.
 */
#define	SRPT_LOG_DEFAULT_LEVEL SRPT_LOG_L1

extern uint_t srpt_errlevel;


#define	SRPT_DPRINTF_L0(...) cmn_err(CE_WARN, __VA_ARGS__)
#define	SRPT_DPRINTF_L1(...) cmn_err(CE_NOTE, __VA_ARGS__)
#define	SRPT_DPRINTF_L2(...)	if (srpt_errlevel >= SRPT_LOG_L2) { \
					cmn_err(CE_NOTE, __VA_ARGS__);\
				}
#ifdef	DEBUG
#define	SRPT_DPRINTF_L3(...)	if (srpt_errlevel >= SRPT_LOG_L3) { \
					cmn_err(CE_NOTE, __VA_ARGS__);\
				}
#define	SRPT_DPRINTF_L4(...)	if (srpt_errlevel >= SRPT_LOG_L4) { \
					cmn_err(CE_NOTE, __VA_ARGS__);\
				}
#else
#define	SRPT_DPRINTF_L3		0 &&
#define	SRPT_DPRINTF_L4		0 &&
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SRPT_IMPL_H_ */
