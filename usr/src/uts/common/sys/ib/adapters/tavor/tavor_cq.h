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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_CQ_H
#define	_SYS_IB_ADAPTERS_TAVOR_CQ_H

/*
 * tavor_cq.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Completion Queue Processing routines.
 *    Specifically it contains the various completion types, flags,
 *    structures used for managing Tavor completion queues, and prototypes
 *    for many of the functions consumed by other parts of the Tavor driver
 *    (including those routines directly exposed through the IBTF CI
 *    interface).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/adapters/tavor/tavor_misc.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines specify the default number of Completion Queues (CQ)
 * their maximum size.  Settings exist for the supported DDR DIMM sizes of
 * 128MB and 256MB.  If a DIMM greater than 256 is found, then the 256MB
 * profile is used.  See tavor_cfg.c for more discussion on config profiles.
 *
 * For manual configuration (not using config profiles), these values are
 * controllable through the "tavor_log_max_cq_sz" and "tavor_log_num_cq"
 * configuration variables, respectively. To override config profile settings
 * the 'tavor_alt_config_enable' configuration variable must first be set.
 *
 * Note: We also have a define for the minimum size of a CQ.  CQs allocated
 * with size 0, 1, 2, or 3 will always get back a CQ of size 4.  This is the
 * smallest size that Tavor hardware and software can correctly handle.
 */
#define	TAVOR_NUM_CQ_SHIFT_128		0x10
#define	TAVOR_NUM_CQ_SHIFT_256		0x11
#define	TAVOR_CQ_SZ_SHIFT		0x10
#define	TAVOR_CQ_SZ			(1 << TAVOR_CQ_SZ_SHIFT)
#define	TAVOR_CQ_MIN_SIZE		0x3

/*
 * Minimal configuration values.
 */
#define	TAVOR_NUM_CQ_SHIFT_MIN		0xC
#define	TAVOR_CQ_SZ_SHIFT_MIN		0xC

/*
 * The following macro determines whether the contents of CQ memory (CQEs)
 * need to be sync'd (with ddi_dma_sync()).  This decision is based on whether
 * the CQ memory is in DDR memory (no sync) or system memory (sync required).
 * Note: It doesn't make much sense to put CQEs in DDR memory (since they are
 * primarily written by HW and read by the CPU), but the driver does support
 * that possibility.  And it also supports the possibility that if a CQ in
 * system memory is mapped DDI_DMA_CONSISTENT, it can be configured to not be
 * sync'd because of the "sync override" parameter in the config profile.
 */
#define	TAVOR_CQ_IS_SYNC_REQ(state, cqinfo)				\
	((((((state)->ts_cfg_profile->cp_streaming_consistent) &&	\
	((state)->ts_cfg_profile->cp_consistent_syncoverride))) ||      \
	((cqinfo).qa_location == TAVOR_QUEUE_LOCATION_INDDR))    \
	? 0 : 1)

/*
 * The following defines specify the size of the individual Completion Queue
 * Context (CQC) entries
 */
#define	TAVOR_CQC_SIZE_SHIFT		0x6
#define	TAVOR_CQC_SIZE			(1 << TAVOR_CQC_SIZE_SHIFT)

/*
 * These are the defines for the Tavor CQ completion statuses.  They are
 * specified by the Tavor register specification.
 */
#define	TAVOR_CQE_SUCCESS		0x0
#define	TAVOR_CQE_LOC_LEN_ERR		0x1
#define	TAVOR_CQE_LOC_OP_ERR		0x2
#define	TAVOR_CQE_LOC_EEC_ERR		0x3	/* unsupported: RD */
#define	TAVOR_CQE_LOC_PROT_ERR		0x4
#define	TAVOR_CQE_WR_FLUSHED_ERR	0x5
#define	TAVOR_CQE_MW_BIND_ERR		0x6
#define	TAVOR_CQE_BAD_RESPONSE_ERR	0x10
#define	TAVOR_CQE_LOCAL_ACCESS_ERR	0x11
#define	TAVOR_CQE_REM_INV_REQ_ERR	0x12
#define	TAVOR_CQE_REM_ACC_ERR		0x13
#define	TAVOR_CQE_REM_OP_ERR		0x14
#define	TAVOR_CQE_TRANS_TO_ERR		0x15
#define	TAVOR_CQE_RNRNAK_TO_ERR		0x16
#define	TAVOR_CQE_LOCAL_RDD_VIO_ERR	0x20	/* unsupported: RD */
#define	TAVOR_CQE_REM_INV_RD_REQ_ERR	0x21	/* unsupported: RD */
#define	TAVOR_CQE_EEC_REM_ABORTED_ERR	0x22	/* unsupported: RD */
#define	TAVOR_CQE_INV_EEC_NUM_ERR	0x23	/* unsupported: RD */
#define	TAVOR_CQE_INV_EEC_STATE_ERR	0x24	/* unsupported: RD */

/*
 * These are the defines for the Tavor CQ entry types.  They are also
 * specified by the Tavor register specification.  They indicate what type
 * of work request is completing (for successful completions).  Note: The
 * "SND" or "RCV" in each define is used to indicate whether the completion
 * work request was from the Send work queue or the Receive work queue on
 * the associated QP.
 */
#define	TAVOR_CQE_SND_RDMAWR		0x8
#define	TAVOR_CQE_SND_RDMAWR_IMM	0x9
#define	TAVOR_CQE_SND_SEND		0xA
#define	TAVOR_CQE_SND_SEND_IMM		0xB
#define	TAVOR_CQE_SND_RDMARD		0x10
#define	TAVOR_CQE_SND_ATOMIC_CS		0x11
#define	TAVOR_CQE_SND_ATOMIC_FA		0x12
#define	TAVOR_CQE_SND_BIND_MW		0x18
#define	TAVOR_CQE_RCV_RECV_IMM		0x3
#define	TAVOR_CQE_RCV_RECV_IMM2		0x5
#define	TAVOR_CQE_RCV_RECV		0x2
#define	TAVOR_CQE_RCV_RECV2		0x4
#define	TAVOR_CQE_RCV_RDMAWR_IMM	0x9
#define	TAVOR_CQE_RCV_RDMAWR_IMM2	0xB

/* Define for maximum CQ number mask (CQ number is 24 bits) */
#define	TAVOR_CQ_MAXNUMBER_MSK		0xFFFFFF

/*
 * This define and the following macro are used to find an event queue for a
 * new CQ based on its completion queue number.  Note:  This is a rather
 * simple method that we use today.  We simply choose from one of the first
 * 32 EQs based on the 5 least significant bits of the CQ number.
 */
#define	TAVOR_CQ_TO_EQ_MASK		0x1F
#define	TAVOR_CQ_EQNUM_GET(cqnum)	((cqnum) & TAVOR_CQ_TO_EQ_MASK)

/*
 * The following macro is even simpler than the above one.  This is used to
 * find an event queue for CQ errors for a new CQ.  In theory we could do this
 * based on the CQ's number (as we do above).  Today, however, all CQ error
 * events go to one specific EQ (i.e. EQ #32).
 */
#define	TAVOR_CQ_ERREQNUM_GET(cqnum)	0x20

/*
 * The following defines are used for Tavor CQ error handling.  Note: For
 * CQEs which correspond to error events, the Tavor device requires some
 * special handling by software.  These defines are used to identify and
 * extract the necessary information from each error CQE, including status
 * code (above), doorbell count, and whether a error completion is for a
 * send or receive work request.
 */
#define	TAVOR_CQE_ERR_STATUS_SHIFT	24
#define	TAVOR_CQE_ERR_STATUS_MASK	0xFF
#define	TAVOR_CQE_ERR_DBDCNT_MASK	0xFFFF
#define	TAVOR_CQE_SEND_ERR_OPCODE	0xFF
#define	TAVOR_CQE_RECV_ERR_OPCODE	0xFE
#define	TAVOR_CQ_SYNC_AND_DB		0
#define	TAVOR_CQ_RECYCLE_ENTRY		1

/* Defines for tracking whether a CQ is being used with special QP or not */
#define	TAVOR_CQ_IS_NORMAL		0
#define	TAVOR_CQ_IS_SPECIAL		1

/*
 * The tavor_sw_cq_s structure is also referred to using the "tavor_cqhdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, initialize, poll, resize,
 * and (later) free a completion queue (CQ).
 *
 * Specifically, it has a consumer index and a lock to ensure single threaded
 * access to it.  It has pointers to the various resources allocated for the
 * completion queue, i.e. a CQC resource and the memory for the completion
 * queue itself.  It has flags to indicate whether the CQ requires
 * ddi_dma_sync() ("cq_sync").  It also has a reference count and the number(s)
 * of the EQs to which it is associated (for success and for errors).
 *
 * Additionally, it has a pointer to the associated MR handle (for the mapped
 * queue memory) and a void pointer that holds the argument that should be
 * passed back to the IBTF when events are generated on the CQ.
 *
 * We also have the always necessary backpointer to the resource for the
 * CQ handle structure itself.  But we also have pointers to the "Work Request
 * ID" processing lists (both the lock and the regular list, as well as the
 * head and tail for the "reapable" list).  See tavor_wrid.c for more details.
 */
struct tavor_sw_cq_s {
	kmutex_t		cq_lock;
	uint32_t		cq_consindx;
	uint32_t		cq_cqnum;
	tavor_hw_cqe_t		*cq_buf;
	tavor_mrhdl_t		cq_mrhdl;
	uint32_t		cq_bufsz;
	uint_t			cq_sync;
	uint_t			cq_refcnt;
	uint32_t		cq_eqnum;
	uint32_t		cq_erreqnum;
	uint_t			cq_is_special;
	uint_t			cq_is_umap;
	uint32_t		cq_uarpg;
	devmap_cookie_t		cq_umap_dhp;
	tavor_rsrc_t		*cq_cqcrsrcp;
	tavor_rsrc_t		*cq_rsrcp;

	void			*cq_hdlrarg;

	/* For Work Request ID processing */
	kmutex_t		cq_wrid_wqhdr_lock;
	avl_tree_t		cq_wrid_wqhdr_avl_tree;
	tavor_wrid_list_hdr_t	*cq_wrid_reap_head;
	tavor_wrid_list_hdr_t	*cq_wrid_reap_tail;

	struct tavor_qalloc_info_s cq_cqinfo;
};
_NOTE(READ_ONLY_DATA(tavor_sw_cq_s::cq_cqnum
    tavor_sw_cq_s::cq_eqnum
    tavor_sw_cq_s::cq_erreqnum
    tavor_sw_cq_s::cq_cqcrsrcp
    tavor_sw_cq_s::cq_rsrcp
    tavor_sw_cq_s::cq_hdlrarg
    tavor_sw_cq_s::cq_is_umap
    tavor_sw_cq_s::cq_uarpg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(tavor_sw_cq_s::cq_bufsz
    tavor_sw_cq_s::cq_cqinfo))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_cq_s::cq_lock,
    tavor_sw_cq_s::cq_consindx
    tavor_sw_cq_s::cq_buf
    tavor_sw_cq_s::cq_mrhdl
    tavor_sw_cq_s::cq_sync 
    tavor_sw_cq_s::cq_refcnt
    tavor_sw_cq_s::cq_is_special
    tavor_sw_cq_s::cq_umap_dhp))

int tavor_cq_alloc(tavor_state_t *state, ibt_cq_hdl_t ibt_cqhdl,
    ibt_cq_attr_t *attr_p, uint_t *actual_size, tavor_cqhdl_t *cqhdl,
    uint_t sleepflag);
int tavor_cq_free(tavor_state_t *state, tavor_cqhdl_t *cqhdl,
    uint_t sleepflag);
int tavor_cq_resize(tavor_state_t *state, tavor_cqhdl_t cqhdl,
    uint_t req_size, uint_t *actual_size, uint_t sleepflag);
int tavor_cq_notify(tavor_state_t *state, tavor_cqhdl_t cqhdl,
    ibt_cq_notify_flags_t flags);
int tavor_cq_poll(tavor_state_t *state, tavor_cqhdl_t cqhdl, ibt_wc_t *wc_p,
    uint_t num_wc, uint_t *num_polled);
int tavor_cq_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe);
int tavor_cq_err_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe);
int tavor_cq_refcnt_inc(tavor_cqhdl_t cq, uint_t is_special);
void tavor_cq_refcnt_dec(tavor_cqhdl_t cq);
tavor_cqhdl_t tavor_cqhdl_from_cqnum(tavor_state_t *state, uint_t cqnum);
void tavor_cq_srq_entries_flush(tavor_state_t *state, tavor_qphdl_t qp);
#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_CQ_H */
