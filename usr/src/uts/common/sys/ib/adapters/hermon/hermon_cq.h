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

#ifndef	_SYS_IB_ADAPTERS_HERMON_CQ_H
#define	_SYS_IB_ADAPTERS_HERMON_CQ_H

/*
 * hermon_cq.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Completion Queue Processing routines.
 *    Specifically it contains the various completion types, flags,
 *    structures used for managing Hermon completion queues, and prototypes
 *    for many of the functions consumed by other parts of the Hermon driver
 *    (including those routines directly exposed through the IBTF CI
 *    interface).
 *
 *    Most of the values defined below establish default values which,
 *    where indicated, can be controlled via their related patchable values,
 *    if 'hermon_alt_config_enable' is set.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/adapters/hermon/hermon_misc.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines the default number of Completion Queues. This
 * is controllable via the "hermon_log_num_cq" configuration variable.
 * We also have a define for the minimum size of a CQ.  CQs allocated
 * with size "less than a page" will always get back a page.
 */
#define	HERMON_NUM_CQ_SHIFT		0x12

#define	HERMON_CQ_MIN_SIZE	((PAGESIZE / 32) - 1)

/*
 * These are the defines for the Hermon CQ completion statuses.
 */
#define	HERMON_CQE_SUCCESS		0x0
#define	HERMON_CQE_LOC_LEN_ERR		0x1
#define	HERMON_CQE_LOC_OP_ERR		0x2
#define	HERMON_CQE_LOC_PROT_ERR		0x4
#define	HERMON_CQE_WR_FLUSHED_ERR	0x5
#define	HERMON_CQE_MW_BIND_ERR		0x6
#define	HERMON_CQE_BAD_RESPONSE_ERR	0x10
#define	HERMON_CQE_LOCAL_ACCESS_ERR	0x11
#define	HERMON_CQE_REM_INV_REQ_ERR	0x12
#define	HERMON_CQE_REM_ACC_ERR		0x13
#define	HERMON_CQE_REM_OP_ERR		0x14
#define	HERMON_CQE_TRANS_TO_ERR		0x15
#define	HERMON_CQE_RNRNAK_TO_ERR	0x16
#define	HERMON_CQE_EEC_REM_ABORTED_ERR	0x22

/*
 * These are the defines for the Hermon CQ entry types. They indicate what type
 * of work request is completing (for successful completions).  Note: The
 * "SND" or "RCV" in each define is used to indicate whether the completion
 * work request was from the Send work queue or the Receive work queue on
 * the associated QP.
 */
#define	HERMON_CQE_SND_NOP		0x0
#define	HERMON_CQE_SND_SEND_INV		0x1
#define	HERMON_CQE_SND_RDMAWR		0x8
#define	HERMON_CQE_SND_RDMAWR_IMM	0x9
#define	HERMON_CQE_SND_SEND		0xA
#define	HERMON_CQE_SND_SEND_IMM		0xB
#define	HERMON_CQE_SND_LSO		0xE
#define	HERMON_CQE_SND_RDMARD		0x10
#define	HERMON_CQE_SND_ATOMIC_CS	0x11
#define	HERMON_CQE_SND_ATOMIC_FA	0x12
#define	HERMON_CQE_SND_ATOMIC_CS_EX	0x14
#define	HERMON_CQE_SND_ATOMIC_FC_EX	0x15
#define	HERMON_CQE_SND_FRWR		0x19
#define	HERMON_CQE_SND_LCL_INV		0x1B
#define	HERMON_CQE_SND_CONFIG		0x1F
#define	HERMON_CQE_SND_BIND_MW		0x18

#define	HERMON_CQE_RCV_RDMAWR_IMM	0x00
#define	HERMON_CQE_RCV_SEND		0x01
#define	HERMON_CQE_RCV_SEND_IMM		0x02
#define	HERMON_CQE_RCV_SEND_INV		0x03
#define	HERMON_CQE_RCV_ERROR_CODE	0x1E
#define	HERMON_CQE_RCV_RESIZE_CODE	0x16


/* Define for maximum CQ number mask (CQ number is 24 bits) */
#define	HERMON_CQ_MAXNUMBER_MSK		0xFFFFFF

/*
 * CQ Sched Management
 *
 *	Each hermon_cq_sched struct defines a range of cq handler_id's
 *	assigned to the cq_sched instance.  Also, the "next_alloc"
 *	member is used to allocate handler_id's in a round robin fashion.
 *
 *	Valid cq handler_id's are in the range of 1 to hs_intrmsi_allocd.
 *	They are indexes into the hs_intrmsi_hdl array.
 */
#define	HERMON_CQH_MAX	32
typedef struct hermon_cq_sched_s {
	char	cqs_name[HERMON_CQH_MAX];
	uint_t	cqs_start_hid;
	uint_t	cqs_len;
	uint_t	cqs_next_alloc;
	uint_t	cqs_desired;
	uint_t	cqs_minimum;
	uint_t	cqs_refcnt;	/* could be alloc'ed more than once */
} hermon_cq_sched_t;

/*
 * new EQ mgmt - per domain (when it gets there).
 * The first hs_rsvd_eqs are reserved by the firmware.
 * The next hs_intrmsi_allocd are for CQ Completions.
 * Each of these "completion" EQs has a unique interrupt vector.
 * The EQs following that are:
 *
 *	1 for CQ Errors
 *	1 for Asyncs and Command Completions, and finally
 *	1 for All Other events.
 *
 * share the last of the interrupt vectors.
 */
#define	HERMON_CQSCHED_NEXT_HID(cq_schedp)				\
	((atomic_inc_uint_nv(&(cq_schedp)->cqs_next_alloc) %		\
	    (cq_schedp)->cqs_len) + (cq_schedp)->cqs_start_hid)

#define	HERMON_HID_TO_EQNUM(state, hid)					\
	((state)->hs_rsvd_eqs + (hid) - 1)

#define	HERMON_HID_VALID(state, hid)					\
	((uint_t)((hid) - 1) < (state)->hs_intrmsi_allocd)

#define	HERMON_EQNUM_TO_HID(state, eqnum)				\
	((eqnum) - (state)->hs_rsvd_eqs + 1)

#define	HERMON_CQ_ERREQNUM_GET(state)					\
	(state)->hs_cq_erreqnum

/*
 * The following defines are used for Hermon CQ error handling.  Note: For
 * CQEs which correspond to error events, the Hermon device requires some
 * special handling by software.  These defines are used to identify and
 * extract the necessary information from each error CQE, including status
 * code (above), doorbell count, and whether a error completion is for a
 * send or receive work request.
 */
#define	HERMON_CQE_ERR_STATUS_SHIFT	0
#define	HERMON_CQE_ERR_STATUS_MASK	0xFF
#define	HERMON_CQE_ERR_DBDCNT_MASK	0xFFFF
#define	HERMON_CQE_SEND_ERR_OPCODE	0x1E
#define	HERMON_CQE_RECV_ERR_OPCODE	0x1E

/* Defines for tracking whether a CQ is being used with special QP or not */
#define	HERMON_CQ_IS_NORMAL		0
#define	HERMON_CQ_IS_SPECIAL		1

/*
 * The hermon_sw_cq_s structure is also referred to using the "hermon_cqhdl_t"
 * typedef (see hermon_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, initialize, poll, resize,
 * and (later) free a completion queue (CQ).
 *
 * Specifically, it has a consumer index and a lock to ensure single threaded
 * access to it.  It has pointers to the various resources allocated for the
 * completion queue, i.e. a CQC resource and the memory for the completion
 * queue itself. It also has a reference count and the number(s) of the EQs
 * to which it is associated (for success and for errors).
 *
 * Additionally, it has a pointer to the associated MR handle (for the mapped
 * queue memory) and a void pointer that holds the argument that should be
 * passed back to the IBTF when events are generated on the CQ.
 *
 * We also have the always necessary backpointer to the resource for the
 * CQ handle structure itself.  But we also have pointers to the "Work Request
 * ID" processing lists (both the lock and the regular list, as well as the
 * head and tail for the "reapable" list).  See hermon_wrid.c for more details.
 */

#define	HERMON_CQ_DEF_UAR_DOORBELL	0x11	/* cmd_sn = 1, req solicited */
#define	HERMON_CD_DEF_UAR_DB_SHIFT	0x38	/* decimal 56 */

struct hermon_sw_cq_s {
	kmutex_t		cq_lock;
	struct hermon_sw_cq_s 	*cq_resize_hdl; /* points to tranistory hdl */
	uint32_t		cq_consindx;
	uint32_t		cq_cqnum;
	hermon_hw_cqe_t		*cq_buf;
	hermon_mrhdl_t		cq_mrhdl;
	uint32_t		cq_bufsz;
	uint32_t		cq_log_cqsz;
	uint_t			cq_refcnt;
	uint32_t		cq_eqnum;
	uint32_t		cq_erreqnum;
	uint_t			cq_is_special;
	uint_t			cq_is_umap;
	uint32_t		cq_uarpg;
	devmap_cookie_t		cq_umap_dhp;
	hermon_rsrc_t		*cq_cqcrsrcp;
	hermon_rsrc_t		*cq_rsrcp;
	uint_t			cq_intmod_count;
	uint_t			cq_intmod_usec;

	/* DoorBell Record Information */
	ddi_acc_handle_t	cq_arm_ci_dbr_acchdl;
	hermon_dbr_t		*cq_arm_ci_vdbr;
	uint64_t		cq_arm_ci_pdbr;
	uint64_t		cq_dbr_mapoffset;	/* user mode access */

	void			*cq_hdlrarg;

	/* For Work Request ID processing */
	avl_tree_t		cq_wrid_wqhdr_avl_tree;

	struct hermon_qalloc_info_s cq_cqinfo;
};
_NOTE(READ_ONLY_DATA(hermon_sw_cq_s::cq_cqnum
    hermon_sw_cq_s::cq_erreqnum
    hermon_sw_cq_s::cq_cqcrsrcp
    hermon_sw_cq_s::cq_rsrcp
    hermon_sw_cq_s::cq_hdlrarg
    hermon_sw_cq_s::cq_is_umap
    hermon_sw_cq_s::cq_uarpg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hermon_sw_cq_s::cq_bufsz
    hermon_sw_cq_s::cq_consindx
    hermon_sw_cq_s::cq_cqinfo))
_NOTE(MUTEX_PROTECTS_DATA(hermon_sw_cq_s::cq_lock,
    hermon_sw_cq_s::cq_buf
    hermon_sw_cq_s::cq_eqnum
    hermon_sw_cq_s::cq_mrhdl
    hermon_sw_cq_s::cq_refcnt
    hermon_sw_cq_s::cq_is_special
    hermon_sw_cq_s::cq_umap_dhp))
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
    hermon_sw_cq_s::cq_intmod_count
    hermon_sw_cq_s::cq_intmod_usec
    hermon_sw_cq_s::cq_resize_hdl))

int hermon_cq_alloc(hermon_state_t *state, ibt_cq_hdl_t ibt_cqhdl,
    ibt_cq_attr_t *attr_p, uint_t *actual_size, hermon_cqhdl_t *cqhdl,
    uint_t sleepflag);
int hermon_cq_free(hermon_state_t *state, hermon_cqhdl_t *cqhdl,
    uint_t sleepflag);
int hermon_cq_resize(hermon_state_t *state, hermon_cqhdl_t cqhdl,
    uint_t req_size, uint_t *actual_size, uint_t sleepflag);
int hermon_cq_modify(hermon_state_t *state, hermon_cqhdl_t cqhdl,
    uint_t count, uint_t usec, ibt_cq_handler_id_t hid, uint_t sleepflag);
int hermon_cq_notify(hermon_state_t *state, hermon_cqhdl_t cqhdl,
    ibt_cq_notify_flags_t flags);
int hermon_cq_poll(hermon_state_t *state, hermon_cqhdl_t cqhdl, ibt_wc_t *wc_p,
    uint_t num_wc, uint_t *num_polled);
int hermon_cq_sched_alloc(hermon_state_t *state, ibt_cq_sched_attr_t *attr,
    hermon_cq_sched_t **cq_sched_pp);
int hermon_cq_sched_free(hermon_state_t *state, hermon_cq_sched_t *cq_schedp);
int hermon_cq_handler(hermon_state_t *state, hermon_eqhdl_t eq,
    hermon_hw_eqe_t *eqe);
int hermon_cq_err_handler(hermon_state_t *state, hermon_eqhdl_t eq,
    hermon_hw_eqe_t *eqe);
int hermon_cq_refcnt_inc(hermon_cqhdl_t cq, uint_t is_special);
void hermon_cq_refcnt_dec(hermon_cqhdl_t cq);
hermon_cqhdl_t hermon_cqhdl_from_cqnum(hermon_state_t *state, uint_t cqnum);
void hermon_cq_entries_flush(hermon_state_t *state, hermon_qphdl_t qp);
void hermon_cq_resize_helper(hermon_state_t *state, hermon_cqhdl_t cq);
int hermon_cq_sched_init(hermon_state_t *state);
void hermon_cq_sched_fini(hermon_state_t *state);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_CQ_H */
