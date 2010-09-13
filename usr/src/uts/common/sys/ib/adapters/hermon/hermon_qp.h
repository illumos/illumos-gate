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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_QP_H
#define	_SYS_IB_ADAPTERS_HERMON_QP_H

/*
 * hermon_qp.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for all of the Queue Pair Processing routines.
 *    Specifically it contains the various flags, structures used for managing
 *    Hermon queue pairs, and prototypes for many of the functions consumed by
 *    other parts of the Hermon driver (including those routines directly
 *    exposed through the IBTF CI interface).
 *
 *    Most of the values defined below establish default values which,
 *    where indicated, can be controlled via their related patchable values,
 *    if 'hermon_alt_config_enable' is set.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines the default number of Queue Pairs. This value is
 * controlled via the "hermon_log_num_qp" configuration variables.
 * We also have a define for the minimum size of a QP.  QPs allocated
 * with size 0, 1, 2, or 3 will always get back a QP of size 4.
 *
 * Note: Increasing #QPs from 64K to 256K for reserved ranges for FCoIB.
 */
#define	HERMON_NUM_QP_SHIFT		0x12
#define	HERMON_NUM_QPS			(1 << HERMON_NUM_QP_SHIFT) /* 256K */
#define	HERMON_QP_MIN_SIZE		0xf

/*
 * The following defines the default number of Hermon RDMA Remote read
 * database (RDB) entries per QP.  This value is controllable through the
 * "hermon_log_num_rdb_per_qp" configuration variable.
 */
#define	HERMON_LOG_NUM_RDB_PER_QP	0x4

/*
 * This defines the maximum number of SGLs per WQE.  This value is
 * controllable through the "hermon_wqe_max_sgl" configuration variable
 * (but should not be set larger than this value).
 */
#define	HERMON_NUM_SGL_PER_WQE		0x10

/*
 * Maximum QP number mask (QP number is 24 bits).
 * We reserve the most significant bit to indicate an "XRC" QP
 * as recommended by the PRM.  All XRC QPs will have this bit set.
 */
#define	HERMON_QP_MAXNUMBER_MSK		0x7FFFFF
#define	HERMON_QP_XRC_MSK		0x800000

/*
 * This define and the following macro are used to find a schedule queue for
 * a new QP based on its queue pair number.  Note:  This is a rather simple
 * method that we use today.  We simply choose from the schedule queue based
 * on the 4 least significant bits of the QP number.
 */

/*
 * The following defines are used to indicate whether a QP is special or
 * not (and what type it is).  They are used in the "qp_is_special" field
 * below in qp_state.  If "qp_is_special" == 0 then an ordinary data qp.
 */

/*
 * The sl is selected based on the qpnum as it was for Tavor/Arbel, except for
 * QP0, which is defined as being 0xF
 */

#define	HERMON_QP_SMI			0x1
#define	HERMON_QP_GSI			0x2

#define	HERMON_DEF_SCHED_POLICY		0x03
#define	HERMON_DEF_SCHED_SELECTION	0x0F

#define	HERMON_QP_SCHEDQ_GET(port, sl, issmi)   \
	(HERMON_DEF_SCHED_POLICY 		\
	| (issmi == HERMON_QP_SMI ? (HERMON_DEF_SCHED_SELECTION << 2) : \
	((issmi == HERMON_QP_GSI ? 0 : (sl & 0XF)) << 2)) \
	| ((port & 0x01) << 6) \
	| ((issmi == HERMON_QP_SMI ? 0 : 1) << 7))


/*
 * This define determines the frequency with which the AckReq bit will be
 * set in outgoing RC packets.  By default it is set to five (5) or 2^5 = 32.
 * So AckReq will be set once every 32 packets sent.  This value is
 * controllable through the "hermon_qp_ackreq_freq" configuration variable.
 */
#define	HERMON_QP_ACKREQ_FREQ		0x5

/*
 * Define the maximum message size (log 2).  Note: This value corresponds
 * to the maximum allowable message sized as defined by the IBA spec.
 */
#define	HERMON_QP_LOG_MAX_MSGSZ		0x1F

/*
 * This macro is used to determine if the hermon QP type (qp_serv) is the
 * same as the caller passed in IBT type (qp_trans).  This is used in QP modify
 * to ensure the types match.
 */
#define	HERMON_QP_TYPE_VALID(qp_trans, qp_serv)				\
	((qp_trans == IBT_RC_SRV && qp_serv == HERMON_QP_RC) ||		\
	(qp_trans == IBT_UD_SRV && (qp_serv == HERMON_QP_UD ||		\
	qp_serv == HERMON_QP_RFCI || qp_serv == HERMON_QP_FCMND ||	\
	qp_serv == HERMON_QP_FEXCH)) ||					\
	(qp_trans == IBT_UC_SRV && qp_serv == HERMON_QP_UC))

/*
 * The following enumerated type is used to capture all the various types
 * of Hermon work queue types. It is specifically used as an argument to the
 * to the hermon_qp_sgl_to_logwqesz() routine to determine the amount of
 * overhead (in WQE header size) consumed by each of the types. This
 * information is used to round the WQE size to the next largest power-of-2
 * (and to determine the number of SGLs that are supported for the given WQE
 * type).  There is also a define below used to specify the minimum size for a
 * WQE.  The minimum size is set to 64 bytes (a single cacheline).
 */

typedef enum {
	HERMON_QP_WQ_TYPE_SENDQ_UD,
	HERMON_QP_WQ_TYPE_SENDQ_CONN,
	HERMON_QP_WQ_TYPE_RECVQ,
	HERMON_QP_WQ_TYPE_SENDMLX_QP0,
	HERMON_QP_WQ_TYPE_SENDMLX_QP1
} hermon_qp_wq_type_t;
#define	HERMON_QP_WQE_MLX_SND_HDRS	0x40
#define	HERMON_QP_WQE_MLX_RCV_HDRS	0x00
#define	HERMON_QP_WQE_MLX_SRQ_HDRS	0x10
#define	HERMON_QP_WQE_MLX_QP0_HDRS	0x40
#define	HERMON_QP_WQE_MLX_QP1_HDRS	0x70
#define	HERMON_QP_WQE_LOG_MINIMUM	0x6


/*
 * The hermon_qp_range_t is used to manage a qp_range for RSS and FEXCH.
 * It has a reference count.  When the reference count goes to 0,
 * the qpc resource can be freed.
 */
typedef struct hermon_qp_range_s {
	kmutex_t	hqpr_lock;
	hermon_rsrc_t	*hqpr_qpcrsrc;
	uint_t		hqpr_refcnt;
} hermon_qp_range_t;

/*
 * The hermon_qp_info_t structure is used internally by the Hermon driver to
 * pass information to and from the hermon_qp_alloc() and
 * hermon_special_qp_alloc() routines.  It contains placeholders for all of the
 * potential inputs and outputs that either routine can take.
 */
typedef struct hermon_qp_info_s {
	ibt_qp_alloc_attr_t	*qpi_attrp;
	uint_t			qpi_type;
	uint_t			qpi_port;
	ibtl_qp_hdl_t		qpi_ibt_qphdl;
	ibt_chan_sizes_t	*qpi_queueszp;
	ib_qpn_t		*qpi_qpn;
	hermon_qphdl_t		qpi_qphdl;
} hermon_qp_info_t;

/*
 * The QPN entry which is stored in the AVL tree
 */
typedef struct hermon_qpn_entry_s {
	avl_node_t		qpn_avlnode;
	uint_t			qpn_refcnt;
	uint_t			qpn_counter;
	uint_t			qpn_indx;
	hermon_rsrc_t		*qpn_qpc;
} hermon_qpn_entry_t;
#define	HERMON_QPN_NOFLAG		0x0
#define	HERMON_QPN_RELEASE		0x1
#define	HERMON_QPN_FREE_ONLY		0x2

#define	HERMON_QP_OH_SIZE		0x0800
/*
 * 2KB, fixed per Mnox PRM 0.35c & conversation w/Mnox technical Sep 5, 2007
 */

/*
 * The hermon_sw_qp_s structure is also referred to using the "hermon_qphdl_t"
 * typedef (see hermon_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, query, modify, and
 * (later) free both normal QP and special QP.
 *
 * Specifically, it has a lock to ensure single threaded access to the QP.
 * It has QP state, type, and number, pointers to the PD, MR, and CQ handles
 * associated with the QP, and pointers to the buffer where the work queues
 * come from.
 *
 * It has two pointers (one per work queue) to the workQ headers for the WRID
 * list, as well as pointers to the last WQE on each chain (used when
 * connecting a new chain of WQEs to a previously executing chain - see
 * hermon_wr.c).  It's also got the real WQE size, real number of SGL per WQE,
 * and the size of each of the work queues (in number of WQEs).
 *
 * Additionally, it has pointers to the resources associated with the QP,
 * including the obligatory backpointer to the resource for the QP handle
 * itself.  But it also has some flags, like "qp_forward_sqd_event" and
 * "qp_sqd_still_draining" (which are used to indicate whether a Send Queue
 * Drained Event should be forwarded to the IBTF) or "qp_is_special",
 * "qp_portnum", and "qp_pkeyindx" (which are used by special QP to store
 * necessary information about the type of the QP, which port it's connected
 * to, and what its current PKey index is set to).
 */
struct hermon_sw_qp_s {
	kmutex_t		qp_lock;
	uint_t			qp_state;
	uint32_t		qp_qpnum;
	hermon_pdhdl_t		qp_pdhdl;
	uint_t			qp_serv_type;
	ibt_qp_type_t		qp_type;
	uint_t			qp_sl;		/* service level */
	hermon_mrhdl_t		qp_mrhdl;
	uint_t			qp_sq_sigtype;
	uint_t			qp_is_special;
	ibt_qp_alloc_flags_t	qp_alloc_flags;
	uint32_t		qp_uarpg;
	devmap_cookie_t		qp_umap_dhp;
	uint_t			qp_portnum;	/* port 0/1 for HCA */
	uint_t			qp_portnum_alt;	/* port 0/1 for HCA */
	uint_t			qp_pkeyindx;
	uint_t			qp_no_prefetch;
				/* prefetch == 0, none == 1, for headroom */
	uint_t			qp_rlky;	/* using reserved lkey */

	/* Send Work Queue */
	kmutex_t		qp_sq_lock;
	hermon_cqhdl_t		qp_sq_cqhdl;
	hermon_workq_avl_t	qp_sq_wqavl;
	hermon_workq_hdr_t	*qp_sq_wqhdr;
	uint32_t		*qp_sq_buf;
	uint32_t		qp_sq_bufsz;
	uint32_t		qp_sq_logqsz;	/* used to check owner valid */
	uint32_t		qp_sq_log_wqesz;
	uint32_t		qp_sq_headroom; /* #bytes needed for headroom */
	uint32_t		qp_sq_hdrmwqes;	/* # wqes needed for headroom */
	uint32_t		qp_sq_baseaddr;
	uint32_t		qp_sq_sgl;
	uint_t			qp_uses_lso;
	uint32_t		qp_ring;
	uint_t			qp_state_for_post_send; /* copy of qp_state */

	/* Receive Work Queue - not used when SRQ is used */
	hermon_cqhdl_t		qp_rq_cqhdl;
	hermon_workq_avl_t	qp_rq_wqavl;	/* needed for srq */
	hermon_workq_hdr_t	*qp_rq_wqhdr;
	uint32_t		*qp_rq_buf;
	uint32_t		qp_rq_bufsz;
	uint32_t		qp_rq_logqsz;	/* used to check owner valid */
	uint32_t		qp_rq_log_wqesz;
	uint32_t		qp_rq_wqecntr;
	uint32_t		qp_rq_baseaddr;
	uint32_t		qp_rq_sgl;

	/* DoorBell Record information */
	ddi_acc_handle_t	qp_rq_dbr_acchdl;
	hermon_dbr_t		*qp_rq_vdbr;
	uint64_t		qp_rq_pdbr;
	uint64_t		qp_rdbr_mapoffset;	/* user mode access */

	uint64_t		qp_desc_off;

	hermon_rsrc_t		*qp_qpcrsrcp;
	hermon_rsrc_t		*qp_rsrcp;
	void			*qp_hdlrarg;
	uint_t			qp_forward_sqd_event;
	uint_t			qp_sqd_still_draining;

	/* Shared Receive Queue */
	hermon_srqhdl_t		qp_srqhdl;

	/* Refcnt of QP belongs to an MCG */
	uint_t			qp_mcg_refcnt;

	/* save the mtu from init2rtr for future use */
	uint_t			qp_save_mtu;
	hermon_qpn_entry_t	*qp_qpn_hdl;

	struct hermon_qalloc_info_s qp_wqinfo;

	ibt_fc_attr_t		qp_fc_attr;

	struct hermon_qp_range_s *qp_rangep;

	/* Beware: 8-byte alignment needed here */

	struct hermon_hw_qpc_s qpc;
};
_NOTE(READ_ONLY_DATA(hermon_sw_qp_s::qp_qpnum
    hermon_sw_qp_s::qp_sq_buf
    hermon_sw_qp_s::qp_sq_log_wqesz
    hermon_sw_qp_s::qp_sq_bufsz
    hermon_sw_qp_s::qp_sq_sgl
    hermon_sw_qp_s::qp_rq_buf
    hermon_sw_qp_s::qp_rq_log_wqesz
    hermon_sw_qp_s::qp_rq_bufsz
    hermon_sw_qp_s::qp_rq_sgl
    hermon_sw_qp_s::qp_desc_off
    hermon_sw_qp_s::qp_mrhdl
    hermon_sw_qp_s::qp_wqinfo
    hermon_sw_qp_s::qp_qpcrsrcp
    hermon_sw_qp_s::qp_rsrcp
    hermon_sw_qp_s::qp_hdlrarg
    hermon_sw_qp_s::qp_pdhdl
    hermon_sw_qp_s::qp_sq_cqhdl
    hermon_sw_qp_s::qp_rq_cqhdl
    hermon_sw_qp_s::qp_sq_sigtype
    hermon_sw_qp_s::qp_serv_type
    hermon_sw_qp_s::qp_is_special
    hermon_sw_qp_s::qp_alloc_flags
    hermon_sw_qp_s::qp_uarpg
    hermon_sw_qp_s::qp_sq_wqhdr
    hermon_sw_qp_s::qp_rq_wqhdr
    hermon_sw_qp_s::qp_qpn_hdl))
_NOTE(MUTEX_PROTECTS_DATA(hermon_sw_qp_s::qp_lock,
    hermon_sw_qp_s::qp_state
    hermon_sw_qp_s::qpc
    hermon_sw_qp_s::qp_forward_sqd_event
    hermon_sw_qp_s::qp_sqd_still_draining
    hermon_sw_qp_s::qp_mcg_refcnt
    hermon_sw_qp_s::qp_save_mtu
    hermon_sw_qp_s::qp_umap_dhp))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
    hermon_sw_qp_s::qp_pkeyindx
    hermon_sw_qp_s::qp_portnum))

#define	HERMON_SET_QP_POST_SEND_STATE(qp, state)			\
	mutex_enter(&qp->qp_sq_lock);					\
	qp->qp_state_for_post_send = state;				\
	mutex_exit(&qp->qp_sq_lock)

/* Defined in hermon_qp.c */
int hermon_qp_alloc(hermon_state_t *state, hermon_qp_info_t *qpinfo,
    uint_t sleepflag);
int hermon_special_qp_alloc(hermon_state_t *state, hermon_qp_info_t *qpinfo,
    uint_t sleepflag);
int hermon_qp_alloc_range(hermon_state_t *state, uint_t log2,
    hermon_qp_info_t *qpinfo, ibtl_qp_hdl_t *ibtl_qp_p, ibc_cq_hdl_t *send_cq_p,
    ibc_cq_hdl_t *recv_cq_p, hermon_qphdl_t *qp_p, uint_t sleepflag);
int hermon_qp_free(hermon_state_t *state, hermon_qphdl_t *qphdl,
    ibc_free_qp_flags_t free_qp_flags, ibc_qpn_hdl_t *qpnh, uint_t sleepflag);
int hermon_qp_query(hermon_state_t *state, hermon_qphdl_t qphdl,
    ibt_qp_query_attr_t *attr_p);
hermon_qphdl_t hermon_qphdl_from_qpnum(hermon_state_t *state, uint_t qpnum);
void hermon_qp_release_qpn(hermon_state_t *state, hermon_qpn_entry_t *entry,
    int flags);
void hermon_qpn_avl_init(hermon_state_t *state);
void hermon_qpn_avl_fini(hermon_state_t *state);

/* Defined in hermon_qpmod.c */
int hermon_qp_modify(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p,
    ibt_queue_sizes_t *actual_sz);
int hermon_qp_to_reset(hermon_state_t *state, hermon_qphdl_t qp);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_QP_H */
