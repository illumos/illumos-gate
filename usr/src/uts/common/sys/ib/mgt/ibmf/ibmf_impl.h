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

#ifndef _SYS_IB_MGT_IBMF_IBMF_IMPL_H
#define	_SYS_IB_MGT_IBMF_IBMF_IMPL_H


/*
 * This file contains the IBMF implementation dependent structures and defines.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/taskq.h>
#include <sys/sunddi.h>
#include <sys/disp.h>
#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/mgt/ibmf/ibmf.h>
#include <sys/ib/mgt/ibmf/ibmf_rmpp.h>
#include <sys/ib/mgt/ibmf/ibmf_kstat.h>
#include <sys/ib/mgt/ibmf/ibmf_trace.h>

#define	IBMF_MEM_PER_WQE		(IBMF_MAD_SIZE + sizeof (ib_grh_t))
#define	IBMF_MAX_SQ_WRE			64
#define	IBMF_MAX_RQ_WRE			64
#define	IBMF_MAX_POSTED_RQ_PER_QP	512
#define	IBMF_MAX_POSTED_SQ_PER_QP	512
#define	IBMF_MAX_SQ_WR_SGL_ELEMENTS	1
#define	IBMF_MAX_RQ_WR_SGL_ELEMENTS	1
#define	IBMF_MGMT_Q_KEY			0x80010000
#define	IBMF_P_KEY_DEF_FULL		0xFFFF
#define	IBMF_P_KEY_DEF_LIMITED		0x7FFF
#define	IBMF_P_KEY_BASE_MASK		0x7FFF
#define	IBMF_PKEY_MEMBERSHIP_MASK	0x8000

#define	IBMF_TASKQ_1THREAD		1
#define	IBMF_TASKQ_NTHREADS		128

/*
 * Work request ID format used for receive requests.
 *
 *  bit 0 set to 1
 */
#define	IBMF_RCV_CQE			0x1

/*
 * Convenience macro used in the RMPP protocol to obtain R_Method field
 * of MAD header with Response bit flipped.
 */
#define	IBMF_FLIP_RESP_BIT(r_method)					\
	(((r_method & 0x80) ^ 0x80) | (r_method & 0x7F))

/* Work Request ID macros */
#define	IBMF_IS_RECV_WR_ID(id)				\
	(((uint64_t)(id) & IBMF_RCV_CQE) ? B_TRUE : B_FALSE)
#define	IBMF_IS_SEND_WR_ID(id)				\
	(!(IBMF_IS_RECV_WR_ID((id))))

/* Decrement IBMF message reference count */
#define	IBMF_MSG_DECR_REFCNT(msg)			{	\
	ASSERT(MUTEX_HELD(&(msg)->im_mutex));			\
	(msg)->im_ref_count--;					\
}

/* Increment IBMF message reference count */
#define	IBMF_MSG_INCR_REFCNT(msg)				\
	(msg)->im_ref_count++;

/* Callback setup/cleanup macros */
#define	IBMF_RECV_CB_SETUP(clp)				{	\
	ASSERT(MUTEX_HELD(&(clp)->ic_mutex));			\
	(clp)->ic_flags |= IBMF_CLIENT_RECV_CB_ACTIVE;		\
	(clp)->ic_recvs_active++;				\
	mutex_enter(&(clp)->ic_kstat_mutex);			\
	IBMF_ADD32_KSTATS((clp), recvs_active, 1);		\
	mutex_exit(&(clp)->ic_kstat_mutex);			\
}

#define	IBMF_RECV_CB_CLEANUP(clp)			{		\
	ASSERT(MUTEX_HELD(&(clp)->ic_mutex));				\
	(clp)->ic_recvs_active--;					\
	mutex_enter(&(clp)->ic_kstat_mutex);				\
	IBMF_SUB32_KSTATS((clp), recvs_active, 1);			\
	mutex_exit(&(clp)->ic_kstat_mutex);				\
	if ((clp)->ic_recvs_active == 0)				\
		(clp)->ic_flags &= ~IBMF_CLIENT_RECV_CB_ACTIVE;		\
	if ((((clp)->ic_flags & IBMF_CLIENT_RECV_CB_ACTIVE) == 0) &&	\
	    (((clp)->ic_flags & IBMF_CLIENT_TEAR_DOWN_CB) != 0))	\
		cv_signal(&(clp)->ic_recv_cb_teardown_cv);		\
}

#define	IBMF_ALT_RECV_CB_SETUP(altqp)			{		\
	ASSERT(MUTEX_HELD(&(altqp)->isq_mutex));			\
	(altqp)->isq_flags |= IBMF_CLIENT_RECV_CB_ACTIVE;		\
	(altqp)->isq_recvs_active++;					\
	mutex_enter(&(altqp)->isq_client_hdl->ic_kstat_mutex);		\
	IBMF_ADD32_KSTATS((altqp)->isq_client_hdl, recvs_active, 1);	\
	mutex_exit(&(altqp)->isq_client_hdl->ic_kstat_mutex);		\
}

#define	IBMF_ALT_RECV_CB_CLEANUP(altqp)			{		\
	ASSERT(MUTEX_HELD(&(altqp)->isq_mutex));			\
	(altqp)->isq_recvs_active--;					\
	mutex_enter(&(altqp)->isq_client_hdl->ic_kstat_mutex);		\
	IBMF_SUB32_KSTATS((altqp)->isq_client_hdl, recvs_active, 1);	\
	mutex_exit(&(altqp)->isq_client_hdl->ic_kstat_mutex);		\
	if ((altqp)->isq_recvs_active == 0)				\
		(altqp)->isq_flags &= ~IBMF_CLIENT_RECV_CB_ACTIVE;	\
	if ((((altqp)->isq_flags & IBMF_CLIENT_RECV_CB_ACTIVE) == 0) &&	\
	    (((altqp)->isq_flags & IBMF_CLIENT_TEAR_DOWN_CB) != 0))	\
		cv_signal(&(altqp)->isq_recv_cb_teardown_cv);		\
}

/* warlock annotations for ibmf.h and ibmf_msg.h structures */
_NOTE(READ_ONLY_DATA(_ibmf_msg::im_msgbufs_send.im_bufs_cl_data
	_ibmf_msg::im_msgbufs_send.im_bufs_cl_data_len
	_ibmf_msg::im_msgbufs_send.im_bufs_cl_hdr
	_ibmf_msg::im_msgbufs_send.im_bufs_cl_hdr_len
	_ibmf_msg::im_msgbufs_send.im_bufs_mad_hdr
	_ib_mad_hdr_t))

/*
 * WQE pool management contexts
 */
typedef struct _ibmf_wqe_mgt {
	struct _ibmf_wqe_mgt	*wqe_mgt_next; /* next wqe management entry */
	void			*wqes_kmem;	/* kmem allocated for WQEs */
	uint64_t		wqes_kmem_sz; /* sizeof WQE kmem allocated */
	ib_vaddr_t		wqes_ib_mem;	/* Registered memory */
	ibt_lkey_t		wqes_ib_lkey;	/* Lkey that goes with it */
	ibt_mr_hdl_t		wqes_ib_mem_hdl; /* IB mem handle */
	kmutex_t		wqes_mutex;	/* WQE mgt context mutex */
} ibmf_wqe_mgt_t;
_NOTE(MUTEX_PROTECTS_DATA(ibmf_wqe_mgt_t::wqes_mutex,
    ibmf_wqe_mgt_t::wqes_kmem
    ibmf_wqe_mgt_t::wqes_kmem_sz
    ibmf_wqe_mgt_t::wqes_ib_mem
    ibmf_wqe_mgt_t::wqes_ib_lkey
    ibmf_wqe_mgt_t::wqes_ib_mem_hdl))

/*
 * structure used to keep track of qp handles
 */
typedef struct _ibmf_qp_t {
	struct _ibmf_qp_t	*iq_next;	/* next in the list */
	ibt_qp_hdl_t		iq_qp_handle;	/* qp handle from IB xport */
	int			iq_port_num;	/* port num for this qp */
	int			iq_qp_num;	/* qp num */
	int			iq_qp_ref;	/* no. of clients using this */
	uint_t			iq_flags;	/* for implementing state m/c */
	uint_t			iq_rwqes_posted; /* posted receive wqes */
	kmutex_t		iq_mutex;	/* mutex for some fields */
} ibmf_qp_t;
_NOTE(READ_ONLY_DATA(ibmf_qp_t::iq_port_num ibmf_qp_t::iq_qp_handle))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_qp_t::iq_mutex,
    ibmf_qp_t::iq_rwqes_posted))

/* defines for iq_flags */
#define	IBMF_QP_FLAGS_INVALID				0x0001
#define	IBMF_QP_FLAGS_INITING				0x0002
#define	IBMF_QP_FLAGS_INITED				0x0004
#define	IBMF_QP_FLAGS_UNINITING				0x0008

/*
 * structure used to keep track of qp handles for qps other than
 * the special qps
 */
typedef struct _ibmf_alt_qp_t {
	struct _ibmf_alt_qp_t	*isq_next;	/* next qp ctx on list */
	ibt_qp_hdl_t		isq_qp_handle;	/* qp handle from IB xport */
	ibt_chan_sizes_t	isq_qp_sizes;	/* qp sizes returned by alloc */
	struct _ibmf_client	*isq_client_hdl; /* associated client handle */
	ibmf_msg_cb_t		isq_recv_cb;	/* recv callback for this qp */
	void			*isq_recv_cb_arg; /* arg for recv cb */
	kcondvar_t		isq_recv_cb_teardown_cv; /* wait on teardown */
	kmutex_t		isq_mutex;		/* qp context mutex */
	int			isq_flags;	/* to keep track of state */
	int			isq_sends_active; /* outstanding sends */
	int			isq_recvs_active; /* outstanding recvs */
	ib_qpn_t		isq_qpn;	/* qp number */
	ib_pkey_t		isq_pkey;	/* qp's partition key */
	ib_qkey_t		isq_qkey;	/* qp's queue keye */
	int			isq_port_num;	/* port num for this qp */
	boolean_t		isq_supports_rmpp; /* qp supports rmpp */
	kcondvar_t		isq_sqd_cv; 	/* wait on SQD event */
	int			isq_wqes_alloced; /* wqes allocated for QP */
	kcondvar_t		isq_wqes_cv; 	/* wait on wqes destruction */
	uint_t			isq_rwqes_posted; /* posted receive wqes */

	/* Manage Send/Receive WQEs for Special QPs */
	struct kmem_cache	*isq_send_wqes_cache; /* Send WQE cache */
	struct kmem_cache	*isq_recv_wqes_cache; /* Receive WQE cache */
	vmem_t			*isq_wqe_ib_vmem; /* IB virtual address arena */
	kmutex_t		isq_wqe_mutex;	/* WQE management list mutex */
	ibmf_wqe_mgt_t		*isq_wqe_mgt_list; /* WQE management list */
} ibmf_alt_qp_t;
_NOTE(MUTEX_PROTECTS_DATA(ibmf_alt_qp_t::isq_mutex,
    ibmf_alt_qp_t::isq_sends_active
    ibmf_alt_qp_t::isq_recvs_active
    ibmf_alt_qp_t::isq_pkey
    ibmf_alt_qp_t::isq_qkey
    ibmf_alt_qp_t::isq_recv_cb
    ibmf_alt_qp_t::isq_recv_cb_arg
    ibmf_alt_qp_t::isq_flags
    ibmf_alt_qp_t::isq_rwqes_posted))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_alt_qp_t::isq_wqe_mutex,
    ibmf_alt_qp_t::isq_wqe_mgt_list))
_NOTE(READ_ONLY_DATA(ibmf_alt_qp_t::isq_port_num))

#define	IBMF_MSG_FLAGS_QUEUED		0x00001000	/* in the ib xport */
#define	IBMF_MSG_FLAGS_DONE		0x00002000	/* xport done */
#define	IBMF_MSG_FLAGS_BLOCKING		0x00004000	/* sync command */

/*
 * This structure is used to keep track of IBT returned ibt_ud_dest_t
 * structures.
 */
typedef struct ibmf_ud_dest_s {
	ibt_ud_dest_t		ud_dest;
	struct ibmf_ud_dest_s	*ud_next;
} ibmf_ud_dest_t;

/*
 * ibmf_msg_impl definition
 *	The IBMF client initializes various members of the msg while sending
 *	the message. IBMF fills in the various members of the msg when a message
 *	is received.
 */
typedef struct _ibmf_msg_impl {
	ibmf_addr_info_t	im_local_addr;	/* local addressing info */
	ibmf_global_addr_info_t	im_global_addr;	/* global addressing info */
	int32_t			im_msg_status;	/* completion status */
	uint32_t		im_msg_flags;	/* flags */
	size_t			im_msg_sz_limit; /* max. message size */
	ibmf_msg_bufs_t		im_msgbufs_send; /* input data to ibmf */
	ibmf_msg_bufs_t		im_msgbufs_recv; /* output data from ibmf */
	struct _ibmf_msg_impl	*im_msg_next;	/* next message on the list */
	struct _ibmf_msg_impl	*im_msg_prev;	/* prev message on the list */
	void			*im_client;	/* client that allocd the pkt */
	ibmf_qp_handle_t	im_qp_hdl;	/* qp handle */
	ibt_ud_dest_t		*im_ud_dest;	/* ptr to the pkt's ud_dest */
	ibmf_ud_dest_t		*im_ibmf_ud_dest; /* ptr to the pkt's ud_dest */
	ibmf_msg_cb_t		im_trans_cb;	/* transaction completion cb */
	void			*im_trans_cb_arg; /* arg for completion cb */
	uint64_t		im_tid;		/* transaction ID */
	uint8_t			im_mgt_class; 	/* management class */
	kmutex_t		im_mutex;	/* protects trans context */
	uint32_t		im_state;	/* message state */
	uint32_t		im_transp_op_flags; /* transaction operation */
	uint32_t		im_flags;	/* message flags */
	uint32_t		im_trans_state_flags;	/* state flags */
	kcondvar_t		im_trans_cv;	/* wait for op completion */
	ibmf_rmpp_ctx_t		im_rmpp_ctx; 	/* RMPP context */
	ibmf_retrans_t		im_retrans;	/* retransmission info */
	timeout_id_t		im_rp_timeout_id; /* response timeout ID */
	timeout_id_t		im_tr_timeout_id; /* transaction timeout ID */
	timeout_id_t		im_rp_unset_timeout_id; /* id for untimeout() */
	timeout_id_t		im_tr_unset_timeout_id; /* id for untimeout() */
	int			im_ref_count;	/* reference count */
	boolean_t		im_unsolicited; /* msg was unsolicited recv */
	int			im_pending_send_compls; /* send completions */
} ibmf_msg_impl_t;
_NOTE(READ_ONLY_DATA(ibmf_msg_impl_t::im_trans_cb
    ibmf_msg_impl_t::im_trans_cb_arg
    ibmf_msg_impl_t::im_transp_op_flags
    ibmf_msg_impl_t::im_local_addr
    ibmf_msg_impl_t::im_unsolicited
    ibmf_msg_impl_t::im_client))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_msg_impl_t::im_mutex,
    ibmf_msg_impl_t::im_flags
    ibmf_msg_impl_t::im_trans_state_flags
    ibmf_msg_impl_t::im_msgbufs_recv
    ibmf_msg_impl_t::im_msg_status
    ibmf_msg_impl_t::im_rmpp_ctx))

/* im_flags */
#define	IBMF_MSG_FLAGS_SEQUENCED	0x1
#define	IBMF_MSG_FLAGS_SEND_RMPP	0x2
#define	IBMF_MSG_FLAGS_RECV_RMPP	0x4
#define	IBMF_MSG_FLAGS_NOT_RMPP		0x8
#define	IBMF_MSG_FLAGS_BUSY		0x10
#define	IBMF_MSG_FLAGS_FREE		0x20
#define	IBMF_MSG_FLAGS_ON_LIST		0x40
#define	IBMF_MSG_FLAGS_SET_TERMINATION	0x80
#define	IBMF_MSG_FLAGS_TERMINATION	0x100

/* retransmission parameter defaults for im_retrans field */
#define	IBMF_RETRANS_DEF_RTV		4000000		/* 4 seconds */
#define	IBMF_RETRANS_DEF_RTTV		100000		/* 100 milliseconds */
#define	IBMF_RETRANS_DEF_TRANS_TO	40000000	/* 40 seconds */
#define	IBMF_RETRANS_DEF_RETRIES	0

/*
 * Transaction state flags (im_trans_state_flags) definitions
 * Don't use 0x0 as a flag value since clients OR and AND the flags
 */
#define	IBMF_TRANS_STATE_FLAG_UNINIT		0x1
#define	IBMF_TRANS_STATE_FLAG_INIT		0x2
#define	IBMF_TRANS_STATE_FLAG_WAIT		0x4
#define	IBMF_TRANS_STATE_FLAG_DONE		0x8
#define	IBMF_TRANS_STATE_FLAG_SIGNALED		0x10
#define	IBMF_TRANS_STATE_FLAG_TIMEOUT		0x20
#define	IBMF_TRANS_STATE_FLAG_RECV_ACTIVE	0x40
#define	IBMF_TRANS_STATE_FLAG_RECV_DONE		0x80
#define	IBMF_TRANS_STATE_FLAG_SEND_DONE		0x100

/* Timer types */
typedef	enum _ibmf_timer_t {
	IBMF_RESP_TIMER			= 1,
	IBMF_TRANS_TIMER		= 2
} ibmf_timer_t;

/*
 * structure to hold specific client info taken from ibmf_register_info_t
 * since we can register for more than one client at a time, but each specific
 * ibmf_client_t only holds one client itself.
 */
typedef struct _ibmf_client_info {
	ib_guid_t		ci_guid;
	uint_t			port_num;
	ibmf_client_type_t	client_class;
} ibmf_client_info_t;

/*
 * Defines for the client type (agent/manager/agent+manager)
 * Bits 16-19 of the client_class specify the client type.
 */
#define	IBMF_AGENT_ID			0x00010000
#define	IBMF_MANAGER_ID			0x00020000
#define	IBMF_AGENT_MANAGER_ID		0x00030000

/*
 * structure used to keep track of clients
 */
typedef struct _ibmf_client {
	void			*ic_client_sig;	/* set for valid handles */
	struct _ibmf_ci		*ic_myci;	/* pointer to CI */
	struct _ibmf_client	*ic_next;	/* next client on list */
	struct _ibmf_client	*ic_prev;	/* previous client on list */

	taskq_t			*ic_send_taskq;	/* taskq for send cb */
	taskq_t			*ic_recv_taskq;	/* taskq for receive cb */
	uint_t			ic_init_state_class; /* taskq initialization */

	ibmf_msg_impl_t		*ic_msg_list; /* protected by ic_mutex */
	ibmf_msg_impl_t		*ic_msg_last; /* last message on list */
	ibmf_msg_impl_t		*ic_term_msg_list; /* termination loop mesgs */
	ibmf_msg_impl_t		*ic_term_msg_last; /* last message on list */
	kmutex_t		ic_msg_mutex; /* protect the message list */

	/* IBTL asynchronous event callback (eg. HCA offline) */
	ibmf_async_event_cb_t	ic_async_cb; /* async/unsolicited handling */
	void			*ic_async_cb_arg; /* args for async cb */

	/* Asynchronous/Unsolicited message handler */
	ibmf_msg_cb_t		ic_recv_cb;
	void			*ic_recv_cb_arg;
	kcondvar_t		ic_recv_cb_teardown_cv; /* wait on teardown */

	ibmf_client_info_t	ic_client_info; /* client registration info */
	ibmf_qp_t		*ic_qp;		/* special qp context */
	ibt_hca_hdl_t		ic_ci_handle;	/* == ic_myci->ic_ci_handle */
	kmutex_t		ic_mutex;	/* prot the client struct */
	int			ic_flags;	/* to keep track of state */
	int			ic_reg_flags;	/* flags specified during */
						/* registration */

	/* Statistics */
	int			ic_msgs_alloced; /* no. msgs alloced by/for */
	int			ic_msgs_active; /* no. msgs active */
	int			ic_trans_active; /* outstanding transacts  */
	int			ic_sends_active; /* outstanding sends */
	int			ic_recvs_active; /* outstanding recvs */

	ib_lid_t		ic_base_lid;	/* used to calculate pathbits */
	kmutex_t		ic_kstat_mutex;	/* protect the kstat */
	struct kstat		*ic_kstatp;	/* kstats for client */
} ibmf_client_t;
_NOTE(READ_ONLY_DATA(ibmf_client_t::ic_ci_handle
    ibmf_client_t::ic_client_info
    ibmf_client_t::ic_client_sig))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_client_t::ic_msg_mutex,
    ibmf_client_t::ic_msg_list
    ibmf_client_t::ic_msg_last
    ibmf_client_t::ic_term_msg_list
    ibmf_client_t::ic_term_msg_last))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_client_t::ic_mutex,
    ibmf_client_t::ic_msgs_alloced
    ibmf_client_t::ic_flags
    ibmf_client_t::ic_recv_cb
    ibmf_client_t::ic_recv_cb_arg))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_client_t::ic_kstat_mutex,
    ibmf_client_t::ic_kstatp))

#define	IBMF_CLIENT_RECV_CB_ACTIVE		0x00000001 /* rcv CB active */
#define	IBMF_CLIENT_SEND_CB_ACTIVE		0x00000010 /* send CB active */
#define	IBMF_CLIENT_TEAR_DOWN_CB		0x00000100 /* client wants to */
							    /* remove recv_cb */

/* IBMF_MAD_ONLY is used by the alternate QP context only (isq_flags) */
#define	IBMF_MAD_ONLY				0x00002000
#define	IBMF_RAW_ONLY				0x00004000

#define	IBMF_REG_MSG_LIST	0
#define	IBMF_TERM_MSG_LIST	1

/*
 * Send WQE context
 */
typedef struct _ibmf_send_wqe {
	struct _ibmf_send_wqe	*send_wqe_next;
	ibt_send_wr_t		send_wr;	/* IBT send work request */
	ibmf_client_t		*send_client;	/* client that sent this */
	void			*send_mem;	/* memory used in send */
	ib_vaddr_t		send_sg_mem;	/* registered memory */
	ibt_lkey_t		send_sg_lkey;	/* Lkey that goes with it */
	ibt_mr_hdl_t		send_mem_hdl;	/* == ci_send_mr_handle in ci */
	uint_t			send_wqe_flags;
	uchar_t			send_port_num;	/* port this is posted to */
	ibt_qp_hdl_t		send_qp_handle;	/* qp handle for this wqe */
	ibmf_qp_handle_t	send_ibmf_qp_handle; /* ibmf qp handle */
	ibmf_msg_impl_t		*send_msg;	/* message context */
	uint32_t		send_status;	/* completion status */
	uint32_t		send_rmpp_segment; /* rmpp segment */
} ibmf_send_wqe_t;

/*
 * Receive WQE context
 */
typedef struct _ibmf_recv_wqe {
	struct _ibmf_recv_wqe	*recv_wqe_next;
	ibt_recv_wr_t		recv_wr;
	ibmf_client_t		*recv_client;	/* client that received this */
	void			*recv_mem;	/* memory used in WQEs */
	ibmf_qp_t		*recv_qpp;	/* qp this is posted */
	ibt_wc_t		recv_wc;	/* corresponding  cqe */
	ib_vaddr_t		recv_sg_mem;	/* registered mem */
	ibt_lkey_t		recv_sg_lkey;	/* Lkey that goes with it */
	ibt_mr_hdl_t		recv_mem_hdl;	/* == ci_recv_mr_handle in ci */
	uint_t			recv_wqe_flags;
	uchar_t			recv_port_num;	/* port this is posted to */
	ibt_qp_hdl_t		recv_qp_handle;	/* ibt qp handle for this wqe */
	ibmf_qp_handle_t	recv_ibmf_qp_handle; /* ibmf qp handle */
	ibmf_msg_impl_t		*recv_msg;	/* message context */
} ibmf_recv_wqe_t;

#define	IBMF_RECV_WQE_FREE		0x00000001	/* WQE is free */

/*
 * Struct that keeps track of the underlying IB channel interface. There
 * is one per CI. Each clients on a given ci gets a reference to the CI.
 * References are tracked used ci_ref field; when ci_ref drops to 0, the
 * structure can be freed.
 */
typedef struct _ibmf_ci {
	struct _ibmf_ci		*ci_next;
	kmutex_t		ci_mutex;	/* protects the CI struct */
	ibmf_client_t		*ci_clients;	/* list of clients;head */
	ibmf_client_t		*ci_clients_last; /* tail */
	kmutex_t		ci_clients_mutex; /* protect the client list */
	ib_guid_t		ci_node_guid;	/* node GUID */
	ibt_hca_hdl_t		ci_ci_handle;	/* HCA handle */
	ibt_pd_hdl_t		ci_pd;		/* protection domain */
	ibmf_qp_t		*ci_qp_list;	/* sp. QP list for all ports */
	ibmf_qp_t		*ci_qp_list_tail;
	kcondvar_t		ci_qp_cv;	/* wait for QP valid state */
	ibt_cq_hdl_t		ci_cq_handle;	/* CQ handle for sp. QPs */
	ibt_cq_hdl_t		ci_alt_cq_handle; /* CQ handle for alt. QPs */
	ibmf_alt_qp_t		*ci_alt_qp_list; /* alternate QP list */

	/* UD destination resources */
	uint32_t		ci_ud_dest_list_count; /* resources in pool */
	kmutex_t		ci_ud_dest_list_mutex; /* UD dest list mutex */
	ibmf_ud_dest_t		*ci_ud_dest_list_head; /* start of list */

	/* Send/Receive WQEs for Special QPs */
	struct kmem_cache	*ci_send_wqes_cache; /* Send WQE cache */
	struct kmem_cache	*ci_recv_wqes_cache; /* Receive WQE cache */
	vmem_t			*ci_wqe_ib_vmem; /* IB virtual address arena */
	kmutex_t		ci_wqe_mutex;	/* WQE management list mutex */
	ibmf_wqe_mgt_t		*ci_wqe_mgt_list; /* WQE management list */

	uint_t			ci_nports;	/* num ports on the CI */
	uint32_t		ci_vendor_id:24; /* HCA vendor ID */
	uint16_t		ci_device_id;	/* HCA device ID */
	uint_t			ci_ref;		/* reference count */
	uint16_t		ci_state;	/* CI context state */
	uint16_t		ci_state_flags;	/* CI context state flags */
	kcondvar_t		ci_state_cv;	/* wait on a state change */
	uint_t			ci_init_state;	/* used in cleanup */

	/* free QP synchronization with WQE completion processing */
	int			ci_wqes_alloced; /* wqes alloced for sp QPs */
	kcondvar_t		ci_wqes_cv; 	/* wait on wqes destruction */

	/* port kstats */
	struct kstat		*ci_port_kstatp;	/* kstats for client */
} ibmf_ci_t;
_NOTE(MUTEX_PROTECTS_DATA(ibmf_ci_t::ci_ud_dest_list_mutex,
    ibmf_ci_t::ci_ud_dest_list_count
    ibmf_ci_t::ci_ud_dest_list_head))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_ci_t::ci_mutex,
    ibmf_ci_t::ci_state
    ibmf_ci_t::ci_port_kstatp))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_ci_t::ci_clients_mutex,
    ibmf_ci_t::ci_clients
    ibmf_ci_t::ci_clients_last))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_ci_t::ci_mutex,
    ibmf_qp_t::iq_next
    ibmf_qp_t::iq_flags))
_NOTE(MUTEX_PROTECTS_DATA(ibmf_ci_t::ci_wqe_mutex,
    ibmf_ci_t::ci_wqe_mgt_list))
_NOTE(READ_ONLY_DATA(ibmf_ci_t::ci_cq_handle))

#define	IBMF_CI_BLOCKED_ON_SEND_WQE		0x00000001 /* blockers on wqe */

/* defines for ci_init_state */
#define	IBMF_CI_INIT_HCA_INITED				0x0001
#define	IBMF_CI_INIT_MUTEX_CV_INITED			0x0002
#define	IBMF_CI_INIT_SEND_TASKQ_DONE			0x0004
#define	IBMF_CI_INIT_RECV_TASKQ_DONE			0x0008
#define	IBMF_CI_INIT_CQ_INITED				0x0010
#define	IBMF_CI_INIT_WQES_ALLOCED			0x0020
#define	IBMF_CI_INIT_HCA_LINKED				0x0040
#define	IBMF_CI_INIT_QP_LIST_INITED			0x0080

/* defines for ci_state */
#define	IBMF_CI_STATE_PRESENT				0x0001
#define	IBMF_CI_STATE_INITED				0x0002
#define	IBMF_CI_STATE_GONE				0x0003

/* defines for ci_state_flags */
#define	IBMF_CI_STATE_INIT_WAIT				0x0001
#define	IBMF_CI_STATE_UNINIT_WAIT			0x0002
#define	IBMF_CI_STATE_VALIDATE_WAIT			0x0004

#define	IBMF_CI_STATE_INVALIDATING			0x0100
#define	IBMF_CI_STATE_VALIDATING			0x0200
#define	IBMF_CI_STATE_UNINITING				0x0400
#define	IBMF_CI_STATE_INITING				0x0800

/*
 * for keeping track of ibmf state
 */
typedef struct _ibmf_state {
	struct _ibmf_ci		*ibmf_ci_list;
	struct _ibmf_ci		*ibmf_ci_list_tail;
	ibt_clnt_hdl_t		ibmf_ibt_handle;
	ibt_cq_handler_t	ibmf_cq_handler;
	kmutex_t		ibmf_mutex;
	ibt_clnt_modinfo_t	ibmf_ibt_modinfo;
	taskq_t			*ibmf_taskq;	/* taskq for MAD processing */
						/* for classes not registered */
} ibmf_state_t;
_NOTE(MUTEX_PROTECTS_DATA(ibmf_state_t::ibmf_mutex,
    ibmf_ci_t::ci_next))

/* UD Destination resource cache definitions */
/*
 * It is preferred that the difference between the hi and lo water
 * marks be only a few ud_dest resources. The intent is that a
 * thread that needs to run ibmf_i_populate_ud_dest_list() does not
 * spend too much time in this ud_dest resource population process
 * before it returns to its caller. A benefit of a higher lo water
 * mark is that the larger available pool of resources supports high
 * stress scenarios better.
 */
#define	IBMF_UD_DEST_HI_WATER_MARK	512
#define	IBMF_UD_DEST_LO_WATER_MARK	500

/*
 * Prototypes
 */
/* ci related functions */
int ibmf_i_validate_ci_guid_and_port(ib_guid_t hca_guid, uint8_t port_num);
int ibmf_i_get_ci(ibmf_register_info_t *client_infop, ibmf_ci_t **cipp);
void ibmf_i_release_ci(ibmf_ci_t *cip);

/* client related functions */
int ibmf_i_validate_classes_and_port(ibmf_ci_t *ibmf_cip,
    ibmf_register_info_t *client_infop);
int ibmf_i_validate_class_mask(ibmf_register_info_t *client_infop);
int ibmf_i_alloc_client(ibmf_register_info_t *client_infop, uint_t flags,
    ibmf_client_t **clientpp);
void ibmf_i_add_client(ibmf_ci_t *ibmf_ci, ibmf_client_t *ibmf_clientp);

void ibmf_i_free_client(ibmf_client_t *clientp);
void ibmf_i_delete_client(ibmf_ci_t *ibmf_ci, ibmf_client_t *ibmf_clientp);
int ibmf_i_lookup_client_by_mgmt_class(ibmf_ci_t *ibmf_cip, int port_num,
    ibmf_client_type_t class, ibmf_client_t **clientpp);

/* qp related functions */
int ibmf_i_get_qp(ibmf_ci_t *ibmf_cip, uint_t port_num,
    ibmf_client_type_t class, ibmf_qp_t **qppp);
void ibmf_i_release_qp(ibmf_ci_t *ibmf_cip, ibmf_qp_t **qpp);
int ibmf_i_alloc_qp(ibmf_client_t *clientp, ib_pkey_t p_key,
    ib_qkey_t q_key, uint_t flags, ibmf_qp_handle_t *ibmf_qp_handlep);
int ibmf_i_free_qp(ibmf_qp_handle_t ibmf_qp_handle, uint_t flags);
int ibmf_i_query_qp(ibmf_qp_handle_t ibmf_qp_handle, uint_t flags,
    uint_t *qp_nump, ib_pkey_t *p_keyp, ib_qkey_t *q_keyp, uint8_t *portnump);
int ibmf_i_modify_qp(ibmf_qp_handle_t ibmf_qp_handle, ib_pkey_t p_key,
    ib_qkey_t q_key, uint_t flags);
int ibmf_i_get_pkeyix(ibt_hca_hdl_t hca_handle, ib_pkey_t pkey,
    uint8_t port, ib_pkey_t *pkeyixp);
int ibmf_i_pkey_ix_to_key(ibmf_ci_t *cip, uint_t port_num, uint_t pkey_ix,
    ib_pkey_t *pkeyp);

/* pkt related functions */
int ibmf_i_issue_pkt(ibmf_client_t *clientp, ibmf_msg_impl_t *msgp,
    ibmf_qp_handle_t ibmf_qp_handle, ibmf_send_wqe_t *send_wqep);
int ibmf_i_alloc_ud_dest(ibmf_client_t *clientp,
    ibmf_msg_impl_t *msgimplp, ibt_ud_dest_hdl_t *ud_dest_p, boolean_t block);
void ibmf_i_free_ud_dest(ibmf_client_t *clientp,
    ibmf_msg_impl_t *msgimplp);
void ibmf_i_init_ud_dest(ibmf_ci_t *cip);
void ibmf_i_fini_ud_dest(ibmf_ci_t *cip);
ibmf_ud_dest_t *ibmf_i_get_ud_dest(ibmf_ci_t *cip);
void ibmf_i_put_ud_dest(ibmf_ci_t *cip, ibmf_ud_dest_t *ud_dest);
void ibmf_i_pop_ud_dest_thread(void *argp);
void ibmf_i_clean_ud_dest_list(ibmf_ci_t *cip, boolean_t all);
int ibmf_i_alloc_send_resources(ibmf_ci_t *cip, ibmf_msg_impl_t *msgp,
    boolean_t block, ibmf_send_wqe_t **swqepp);
void ibmf_i_free_send_resources(ibmf_ci_t *cip, ibmf_msg_impl_t *msgimplp,
    ibmf_send_wqe_t *swqep);
int ibmf_i_post_recv_buffer(ibmf_ci_t *cip, ibmf_qp_t *qpp, boolean_t block,
    ibmf_qp_handle_t ibmf_qp_handle);
int ibmf_i_is_ibmf_handle_valid(ibmf_handle_t ibmf_handle);
int ibmf_i_is_qp_handle_valid(ibmf_handle_t ibmf_handle,
    ibmf_qp_handle_t ibmf_qp_handle);
int ibmf_i_check_for_loopback(ibmf_msg_impl_t *msgimplp, ibmf_msg_cb_t msgp,
    void *msg_cb_args, ibmf_retrans_t *retrans, boolean_t *loopback);
int ibmf_i_ibt_to_ibmf_status(ibt_status_t ibt_status);
int ibmf_i_ibt_wc_to_ibmf_status(ibt_wc_status_t ibt_wc_status);
int ibmf_i_send_pkt(ibmf_client_t *clientp, ibmf_qp_handle_t ibmf_qp_handle,
    ibmf_msg_impl_t *msgimplp, int block);
int ibmf_i_send_single_pkt(ibmf_client_t *clientp,
    ibmf_qp_handle_t ibmf_qp_handle, ibmf_msg_impl_t *msgimplp, int block);

/* WQE related functions */
int ibmf_i_init_wqes(ibmf_ci_t *cip);
void ibmf_i_fini_wqes(ibmf_ci_t *cip);
void ibmf_i_init_send_wqe(ibmf_client_t *clientp,
    ibmf_msg_impl_t *msgimplp, ibt_wr_ds_t *sglp, ibmf_send_wqe_t *wqep,
    ibt_ud_dest_hdl_t ud_dest, ibt_qp_hdl_t ibt_qp_handle,
    ibmf_qp_handle_t ibmf_qp_handle);
void ibmf_i_init_recv_wqe(ibmf_qp_t *qpp, ibt_wr_ds_t *sglp,
    ibmf_recv_wqe_t *wqep, ibt_qp_hdl_t ibt_qp_handle,
    ibmf_qp_handle_t ibmf_qp_handle);
void ibmf_i_mad_completions(ibt_cq_hdl_t cq_handle, void *arg);
#ifdef DEBUG
void ibmf_i_dump_wcp(ibmf_ci_t *cip, ibt_wc_t *wcp, ibmf_recv_wqe_t *recv_wqep);
#endif

void ibmf_ibt_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event);

/* msg related functions */
void ibmf_i_init_msg(ibmf_msg_impl_t *msgimplp, ibmf_msg_cb_t trans_cb,
    void *trans_cb_arg, ibmf_retrans_t *retrans, boolean_t block);
void ibmf_i_client_add_msg(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp);
void ibmf_i_client_rem_msg(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    uint_t *refcnt);
int ibmf_i_alloc_msg(ibmf_client_t *clientp, ibmf_msg_impl_t **msgp,
    int km_flags);
void ibmf_i_free_msg(ibmf_msg_impl_t *msgimplp);
int ibmf_i_msg_transport(ibmf_client_t *clientp,
    ibmf_qp_handle_t ibmf_qp_handle, ibmf_msg_impl_t *msgimplp, int blocking);
void ibmf_i_decrement_ref_count(ibmf_msg_impl_t *msgimplp);
void ibmf_i_handle_send_completion(ibmf_ci_t *cip, ibt_wc_t *wcp);
void ibmf_i_handle_recv_completion(ibmf_ci_t *cip, ibt_wc_t *wcp);
int ibmf_setup_recvbuf_on_error(ibmf_msg_impl_t *msgimplp, uchar_t *mad);

/* transaction related functions */
void ibmf_i_terminate_transaction(ibmf_client_t *clientp,
    ibmf_msg_impl_t *msgimplp, uint32_t status);
void ibmf_i_notify_client(ibmf_msg_impl_t *msgimplp);
void ibmf_i_notify_sequence(ibmf_client_t *clientp, ibmf_msg_impl_t *msgimplp,
    int msg_flags);

/* timer related functions */
void ibmf_i_set_timer(void (*func)(void *), ibmf_msg_impl_t *msgimplp,
    ibmf_timer_t type);
void ibmf_i_unset_timer(ibmf_msg_impl_t *msgimplp, ibmf_timer_t type);
void ibmf_i_recv_timeout(void *argp);
void ibmf_i_send_timeout(void *argp);
void ibmf_i_err_terminate_timeout(void *msgp);

/* rmpp related functions */
boolean_t ibmf_i_find_msg_client(ibmf_client_t *cl, ibmf_msg_impl_t *msgimplp,
    boolean_t inc_refcnt);
boolean_t ibmf_i_is_rmpp(ibmf_client_t *clientp,
    ibmf_qp_handle_t ibmf_qp_handle);
void ibmf_i_mgt_class_to_hdr_sz_off(uint32_t mgt_class, uint32_t *szp,
    uint32_t *offp);
ibmf_msg_impl_t *ibmf_i_find_msg(ibmf_client_t *clientp, uint64_t tid,
    uint8_t mgt_class, uint8_t r_method, ib_lid_t lid, ib_gid_t *gid,
    boolean_t gid_pr, ibmf_rmpp_hdr_t *rmpp_hdr, boolean_t msg_list);
#ifdef NOTDEF
ibmf_msg_impl_t *ibmf_i_find_term_msg(ibmf_client_t *clientp, uint64_t tid,
    uint8_t mgt_class, ib_lid_t lid, ib_gid_t *gid, boolean_t gid_pr,
    ibmf_rmpp_hdr_t *rmpp_hd);
#endif
void ibmf_i_handle_rmpp(ibmf_client_t *clientp, ibmf_qp_handle_t qp_hdl,
    ibmf_msg_impl_t *msgimpl, uchar_t *madp);
int ibmf_i_send_rmpp(ibmf_msg_impl_t *msgimplp, uint8_t rmpp_type,
    uint8_t rmpp_status, uint32_t segno, uint32_t nwl, int block);
int ibmf_i_send_rmpp_pkts(ibmf_client_t *clientp,
    ibmf_qp_handle_t ibmf_qp_handle, ibmf_msg_impl_t *msgimplp, boolean_t isDS,
    int block);
void ibmf_i_send_rmpp_window(ibmf_msg_impl_t *msgimplp, int block);
int ibmf_setup_term_ctx(ibmf_client_t *clientp, ibmf_msg_impl_t *regmsgimplp);

/* Alternate QP WQE cache functions */
int ibmf_altqp_send_wqe_cache_constructor(void *buf, void *cdrarg,
    int kmflags);
void ibmf_altqp_send_wqe_cache_destructor(void *buf, void *cdrarg);
int ibmf_altqp_recv_wqe_cache_constructor(void *buf, void *cdrarg,
    int kmflags);
void ibmf_altqp_recv_wqe_cache_destructor(void *buf, void *cdrarg);
int ibmf_i_init_altqp_wqes(ibmf_alt_qp_t *qp_ctx);
void ibmf_i_fini_altqp_wqes(ibmf_alt_qp_t *qp_ctx);
int ibmf_i_extend_wqe_cache(ibmf_ci_t *cip, ibmf_qp_handle_t ibmf_qp_handle,
    boolean_t block);

/* Receive callback functions */
void ibmf_i_recv_cb_setup(ibmf_client_t *clientp);
void ibmf_i_recv_cb_cleanup(ibmf_client_t *clientp);
void ibmf_i_alt_recv_cb_setup(ibmf_alt_qp_t *qpp);
void ibmf_i_alt_recv_cb_cleanup(ibmf_alt_qp_t *qpp);

/* UD Dest population thread */
int ibmf_ud_dest_tq_disp(ibmf_ci_t *cip);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_IMPL_H */
