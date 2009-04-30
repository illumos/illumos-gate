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

#ifndef	_SYS_IB_ADAPTERS_TAVOR_QP_H
#define	_SYS_IB_ADAPTERS_TAVOR_QP_H

/*
 * tavor_qp.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for all of the Queue Pair Processing routines.
 *    Specifically it contains the various flags, structures used for managing
 *    Tavor queue pairs, and prototypes for many of the functions consumed by
 *    other parts of the Tavor driver (including those routines directly
 *    exposed through the IBTF CI interface).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * The following defines specify the default number of Queue Pairs (QP) and
 * their maximum size.  Settings exist for the supported DDR DIMM sizes of
 * 128MB and 256MB.  If a DIMM greater than 256 is found, then the 256MB
 * profile is used.  See tavor_cfg.c for more discussion on config profiles.
 *
 * For manual configuration (not using config profiles), these values are
 * controllable through the "tavor_log_max_qp_sz" and "tavor_log_num_qp"
 * configuration variables, respectively. To override config profile settings
 * the 'tavor_alt_config_enable' configuration variable must first be set.
 *
 * Note: We also have a define for the minimum size of a QP.  QPs allocated
 * with size 0, 1, 2, or 3 will always get back a QP of size 4.  This is the
 * smallest size that Tavor hardware and software can correctly handle.
 */
#define	TAVOR_NUM_QP_SHIFT_128		0x10
#define	TAVOR_NUM_QP_SHIFT_256		0x11
#define	TAVOR_QP_SZ_SHIFT		0x10
#define	TAVOR_QP_SZ			(1 << TAVOR_QP_SZ_SHIFT)
#define	TAVOR_QP_MIN_SIZE		0x4

/*
 * Minimal configuration values.
 */
#define	TAVOR_NUM_QP_SHIFT_MIN		0xD
#define	TAVOR_QP_SZ_SHIFT_MIN		0x9

/*
 * The following macro determines whether the contents of QP memory (WQEs)
 * need to be sync'd (with ddi_dma_sync()).  This decision is based on whether
 * the QP memory is in DDR memory (no sync) or system memory (sync required).
 * And it also supports the possibility that if a CQ in system memory is mapped
 * DDI_DMA_CONSISTENT, it can be configured to not be sync'd because of the
 * "sync override" parameter in the config profile.
 */
#define	TAVOR_QP_IS_SYNC_REQ(state, wqinfo)				\
	((((((state)->ts_cfg_profile->cp_streaming_consistent) &&	\
	((state)->ts_cfg_profile->cp_consistent_syncoverride))) ||	\
	((wqinfo).qa_location == TAVOR_QUEUE_LOCATION_INDDR))		\
	? 0 : 1)

/*
 * The following defines specify the size of the individual Queue Pair
 * Context (QPC) entries.  Below we also specify the size of the "Extended
 * QPC entries as well.
 */
#define	TAVOR_QPC_SIZE_SHIFT		0x8
#define	TAVOR_QPC_SIZE			(1 << TAVOR_QPC_SIZE_SHIFT)
#define	TAVOR_EQPC_SIZE_SHIFT		0x5
#define	TAVOR_EQPC_SIZE			(1 << TAVOR_EQPC_SIZE_SHIFT)

/*
 * The following defines specify the default number of Tavor RDMA Backing
 * entries (RDB).  Settings exist for the supported DDR DIMM sizes of 128MB and
 * 256MB.  If a DIMM greater than 256 is found, then the 256MB profile is used.
 * See tavor_cfg.c for more discussion on config profiles.
 *
 * For manual configuration (not using config profiles), this value is
 * controllable through the "tavor_log_num_rdb" configuration variable.  To
 * override config profile settings the 'tavor_alt_config_enable' configuration
 * variable must first be set.
 *
 * Below we also include the defines that are used to specify four (4)
 * outstanding RDMA Reads/Atomics per QP.
 */

#define	TAVOR_NUM_RDB_SHIFT_128		0x12
#define	TAVOR_NUM_RDB_SHIFT_256		0x13

#define	TAVOR_HCA_MAX_RDMA_IN_QP	0x4
#define	TAVOR_HCA_MAX_RDMA_OUT_QP	0x4

/*
 * Minimal configuration value.
 */
#define	TAVOR_NUM_RDB_SHIFT_MIN		0xC

/*
 * The following defines specify the size of the individual RDMA Backing
 * entries (RDB).
 */
#define	TAVOR_RDB_SIZE_SHIFT		0x5
#define	TAVOR_RDB_SIZE			(1 << TAVOR_RDB_SIZE_SHIFT)

/*
 * This defines the maximum number of SGLs per WQE.  This value is
 * controllable through the "tavor_wqe_max_sgl" configuration variable (but
 * should not be set larger than this value).
 */
#define	TAVOR_NUM_WQE_SGL		0x10

/* Define for maximum QP number mask (QP number is 24 bits) */
#define	TAVOR_QP_MAXNUMBER_MSK		0xFFFFFF

/*
 * This define and the following macro are used to find a schedule queue for
 * a new QP based on its queue pair number.  Note:  This is a rather simple
 * method that we use today.  We simply choose from the schedule queue based
 * on the 4 least significant bits of the QP number.
 */
#define	TAVOR_QP_TO_SCHEDQ_MASK		0xF
#define	TAVOR_QP_SCHEDQ_GET(qpnum)	((qpnum) & TAVOR_QP_TO_SCHEDQ_MASK)

/*
 * This define determines the frequency with which the AckReq bit will be
 * set in outgoing RC packets.  By default it is set to five (5) or 2^5 = 32.
 * So AckReq will be set once every 32 packets sent.  This value is
 * controllable through the "tavor_qp_ackreq_freq" configuration variable.
 */
#define	TAVOR_QP_ACKREQ_FREQ		0x5

/*
 * Define the maximum message size (log 2).  Note: This value corresponds
 * to the maximum allowable message sized as defined by the IBA spec.
 */
#define	TAVOR_QP_LOG_MAX_MSGSZ		0x1F

/*
 * This macro is used to determine the appropriate alignment for a Tavor
 * work queue (see tavor_qp_alloc() and tavor_special_qp_alloc()).  Note:
 * Tavor work queues are aligned on their combined size (i.e. combined size
 * of send queue and receive queue) because of certain hardware limitations
 * (i.e. work queue memory cannot cross a 32-bit boundary).
 */
#define	TAVOR_QP_WQ_ALIGN(qp_size)					\
	(1 << ((((qp_size) & ((qp_size) - 1)) == 0) ?			\
	highbit((qp_size)) - 1 : highbit((qp_size))))

/*
 * This macro is used to determine if the tavor known QP type (qp_serv) is the
 * same as the caller passed in IBT type (qp_trans).  This is used in QP modify
 * to ensure the types match.
 */
#define	TAVOR_QP_TYPE_VALID(qp_trans, qp_serv)				\
	((qp_trans == IBT_UD_SRV && qp_serv == TAVOR_QP_UD) ||		\
	(qp_trans == IBT_RC_SRV && qp_serv == TAVOR_QP_RC) ||		\
	(qp_trans == IBT_UC_SRV && qp_serv == TAVOR_QP_UC))

/*
 * The following enumerated type is used to capture all the various types
 * of Tavor work queue types.  Note: It is specifically used as an argument
 * to the tavor_qp_sgl_to_logwqesz() routine.
 * The defines below are also used by the tavor_qp_sgl_to_logwqesz() routine
 * they indicate the amount of overhead (in WQE header size) consumed by
 * each of the following types of WQEs.  This information is used to round
 * the WQE size to the next largest power-of-2 (and to determine the number
 * of SGLs that are supported for the given WQE type).  There is also a define
 * below used to specify the minimum size for a WQE.  The minimum size is set
 * to 64 bytes (a single cacheline).
 */
typedef enum {
	TAVOR_QP_WQ_TYPE_SENDQ,
	TAVOR_QP_WQ_TYPE_RECVQ,
	TAVOR_QP_WQ_TYPE_SENDMLX_QP0,
	TAVOR_QP_WQ_TYPE_SENDMLX_QP1
} tavor_qp_wq_type_t;
#define	TAVOR_QP_WQE_MAX_SIZE		0x3F0
#define	TAVOR_QP_WQE_MLX_SND_HDRS	0x40
#define	TAVOR_QP_WQE_MLX_RCV_HDRS	0x10
#define	TAVOR_QP_WQE_MLX_QP0_HDRS	0x40
#define	TAVOR_QP_WQE_MLX_QP1_HDRS	0x70
#define	TAVOR_QP_WQE_LOG_MINIMUM	0x6


/*
 * The tavor_qp_info_t structure is used internally by the Tavor driver to
 * pass information to and from the tavor_qp_alloc() and
 * tavor_special_qp_alloc() routines.  It contains placeholders for all of the
 * potential inputs and outputs that either routine can take.
 */
typedef struct tavor_qp_info_s {
	ibt_qp_alloc_attr_t	*qpi_attrp;
	uint_t			qpi_type;
	uint_t			qpi_port;
	ibtl_qp_hdl_t		qpi_ibt_qphdl;
	ibt_chan_sizes_t	*qpi_queueszp;
	ib_qpn_t		*qpi_qpn;
	tavor_qphdl_t		qpi_qphdl;
} tavor_qp_info_t;

/*
 * The QPN entry which is stored in the AVL tree
 */
typedef struct tavor_qpn_entry_s {
	avl_node_t		qpn_avlnode;
	uint_t			qpn_refcnt;
	uint_t			qpn_counter;
	uint_t			qpn_indx;
	tavor_rsrc_t		*qpn_qpc;
} tavor_qpn_entry_t;
#define	TAVOR_QPN_NOFLAG		0x0
#define	TAVOR_QPN_RELEASE		0x1
#define	TAVOR_QPN_FREE_ONLY		0x2

/*
 * The tavor_sw_qp_s structure is also referred to using the "tavor_qphdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
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
 * tavor_wr.c).  It's also got the real WQE size, real number of SGL per WQE,
 * and the size of each of the work queues (in number of WQEs).
 *
 * Additionally, it has pointers to the resources associated with the QP
 * (including the obligatory backpointer to the resource for the QP handle
 * itself.  But it also has some flags, like "qp_forward_sqd_event" and
 * "qp_sqd_still_draining" (which are used to indicate whether a Send Queue
 * Drained Event should be forwarded to the IBTF) or "qp_is_special",
 * "qp_portnum", and "qp_pkeyindx" (which are used by special QP to store
 * necessary information about the type of the QP, which port it's connected
 * to, and what its current PKey index is set to).
 */
struct tavor_sw_qp_s {
	kmutex_t		qp_lock;
	uint_t			qp_state;
	uint32_t		qp_qpnum;
	tavor_pdhdl_t		qp_pdhdl;
	uint_t			qp_serv_type;
	uint_t			qp_sync;
	tavor_mrhdl_t		qp_mrhdl;
	uint_t			qp_sq_sigtype;
	uint_t			qp_is_special;
	uint_t			qp_is_umap;
	uint32_t		qp_uarpg;
	devmap_cookie_t		qp_umap_dhp;
	uint_t			qp_portnum;
	uint_t			qp_pkeyindx;

	/* Send Work Queue */
	tavor_cqhdl_t		qp_sq_cqhdl;
	uint64_t		*qp_sq_lastwqeaddr;
	tavor_workq_hdr_t	*qp_sq_wqhdr;
	uint32_t		*qp_sq_buf;
	uint32_t		qp_sq_bufsz;
	uint32_t		qp_sq_log_wqesz;
	uint32_t		qp_sq_sgl;

	/* Receive Work Queue */
	tavor_cqhdl_t		qp_rq_cqhdl;
	uint64_t		*qp_rq_lastwqeaddr;
	tavor_workq_hdr_t	*qp_rq_wqhdr;
	uint32_t		*qp_rq_buf;
	uint32_t		qp_rq_bufsz;
	uint32_t		qp_rq_log_wqesz;
	uint32_t		qp_rq_sgl;

	uint64_t		qp_desc_off;

	tavor_rsrc_t		*qp_qpcrsrcp;
	tavor_rsrc_t		*qp_rsrcp;
	void			*qp_hdlrarg;
	tavor_rsrc_t		*qp_rdbrsrcp;
	uint64_t		qp_rdb_ddraddr;
	uint_t			qp_forward_sqd_event;
	uint_t			qp_sqd_still_draining;

	/* Shared Receive Queue */
	tavor_srqhdl_t		qp_srqhdl;
	uint_t			qp_srq_en;

	/* Refcnt of QP belongs to an MCG */
	uint_t			qp_mcg_refcnt;

	/* save the mtu & srate from init2rtr for future use */
	uint_t			qp_save_mtu;
	ibt_srate_t		qp_save_srate;
	tavor_qpn_entry_t	*qp_qpn_hdl;

	struct tavor_qalloc_info_s qp_wqinfo;

	struct tavor_hw_qpc_s qpc;
};
_NOTE(READ_ONLY_DATA(tavor_sw_qp_s::qp_qpnum
    tavor_sw_qp_s::qp_sync
    tavor_sw_qp_s::qp_sq_buf
    tavor_sw_qp_s::qp_sq_log_wqesz
    tavor_sw_qp_s::qp_sq_bufsz
    tavor_sw_qp_s::qp_sq_sgl
    tavor_sw_qp_s::qp_rq_buf
    tavor_sw_qp_s::qp_rq_log_wqesz
    tavor_sw_qp_s::qp_rq_bufsz
    tavor_sw_qp_s::qp_rq_sgl
    tavor_sw_qp_s::qp_desc_off
    tavor_sw_qp_s::qp_mrhdl
    tavor_sw_qp_s::qp_wqinfo
    tavor_sw_qp_s::qp_qpcrsrcp
    tavor_sw_qp_s::qp_rsrcp
    tavor_sw_qp_s::qp_hdlrarg
    tavor_sw_qp_s::qp_pdhdl
    tavor_sw_qp_s::qp_sq_cqhdl
    tavor_sw_qp_s::qp_rq_cqhdl
    tavor_sw_qp_s::qp_sq_sigtype
    tavor_sw_qp_s::qp_serv_type
    tavor_sw_qp_s::qp_is_special
    tavor_sw_qp_s::qp_is_umap
    tavor_sw_qp_s::qp_uarpg
    tavor_sw_qp_s::qp_portnum
    tavor_sw_qp_s::qp_qpn_hdl))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_qp_s::qp_lock,
    tavor_sw_qp_s::qp_sq_wqhdr
    tavor_sw_qp_s::qp_sq_lastwqeaddr
    tavor_sw_qp_s::qp_rq_wqhdr
    tavor_sw_qp_s::qp_rq_lastwqeaddr
    tavor_sw_qp_s::qp_state
    tavor_sw_qp_s::qp_rdbrsrcp
    tavor_sw_qp_s::qp_rdb_ddraddr
    tavor_sw_qp_s::qpc
    tavor_sw_qp_s::qp_forward_sqd_event
    tavor_sw_qp_s::qp_sqd_still_draining
    tavor_sw_qp_s::qp_mcg_refcnt
    tavor_sw_qp_s::qp_save_mtu
    tavor_sw_qp_s::qp_umap_dhp))

/*
 * The following defines are used to indicate whether a QP is special or
 * not (and what type it is).  They are used in the "qp_is_special" field
 * above.
 */
#define	TAVOR_QP_SMI			0x1
#define	TAVOR_QP_GSI			0x2

/*
 * The tavor_qp_options_t structure is used in the Tavor QP allocation
 * routines to provide additional option functionality.  When a NULL pointer
 * is passed in place of a pointer to this struct, it is a way of specifying
 * the "default" behavior.  Using this structure, however, is a way of
 * controlling any extended behavior.
 *
 * Currently, the only defined "extended" behavior is for specifying whether
 * a given QP's work queues should be allocated from kernel system memory
 * (TAVOR_QUEUE_LOCATION_NORMAL) or should be allocated from local DDR memory
 * (TAVOR_QUEUE_LOCATION_INDDR).  This defaults today to always allocating
 * from kernel system memory but can be changed by using the
 * "tavor_qp_wq_inddr" configuration variable.
 */
typedef struct tavor_qp_options_s {
	uint_t			qpo_wq_loc;
} tavor_qp_options_t;


/* Defined in tavor_qp.c */
int tavor_qp_alloc(tavor_state_t *state, tavor_qp_info_t *qpinfo,
    uint_t sleepflag, tavor_qp_options_t *op);
int tavor_special_qp_alloc(tavor_state_t *state, tavor_qp_info_t *qpinfo,
    uint_t sleepflag, tavor_qp_options_t *op);
int tavor_qp_free(tavor_state_t *state, tavor_qphdl_t *qphdl,
    ibc_free_qp_flags_t free_qp_flags, ibc_qpn_hdl_t *qpnh, uint_t sleepflag);
int tavor_qp_query(tavor_state_t *state, tavor_qphdl_t qphdl,
    ibt_qp_query_attr_t *attr_p);
tavor_qphdl_t tavor_qphdl_from_qpnum(tavor_state_t *state, uint_t qpnum);
void tavor_qp_release_qpn(tavor_state_t *state, tavor_qpn_entry_t *entry,
    int flags);
void tavor_qpn_avl_init(tavor_state_t *state);
void tavor_qpn_avl_fini(tavor_state_t *state);

/* Defined in tavor_qpmod.c */
int tavor_qp_modify(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p,
    ibt_queue_sizes_t *actual_sz);
int tavor_qp_to_reset(tavor_state_t *state, tavor_qphdl_t qp);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_QP_H */
