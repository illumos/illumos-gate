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

#ifndef	_SYS_IB_ADAPTERS_HERMON_SRQ_H
#define	_SYS_IB_ADAPTERS_HERMON_SRQ_H

/*
 * hermon_srq.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Shared Receive Queue Processing routines.
 *
 *    (including those routines directly exposed through the IBTF CI
 *    interface).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following defines the default number of Shared Receive Queues (SRQ).
 * This value is controllable via the "hermon_log_num_srq" configuration
 * variable.
 * We also have a define for the minimum size of a SRQ.  SRQs allocated with
 * size 0, 1, 2, or 3 will always get back a SRQ of size 4.
 */
#define	HERMON_NUM_SRQ_SHIFT		0x10
#define	HERMON_SRQ_MIN_SIZE		0x4

/*
 * The hermon firmware currently limits an SRQ to maximum of 31 SGL
 * per WQE (WQE size is 512 bytes or less).  With a WQE size of 256
 * (SGL 15 or less) no problems are seen.  We set SRQ_MAX_SGL size here, for
 * use in the config profile to be 0xF.
 */
#define	HERMON_SRQ_MAX_SGL		0xF

/*
 * SRQ States as defined by Hermon.
 */
#define	HERMON_SRQ_STATE_SW_OWNER	0xF
#define	HERMON_SRQ_STATE_HW_OWNER	0x0
#define	HERMON_SRQ_STATE_ERROR		0x1

/*
 * The hermon_sw_srq_s structure is also referred to using the "hermon_srqhdl_t"
 * typedef (see hermon_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, initialize, query, modify,
 * post, and (later) free a shared receive queue (SRQ).
 */
struct hermon_sw_srq_s {
	kmutex_t		srq_lock;
	uint_t			srq_state;
	uint_t			srq_srqnum;
	hermon_pdhdl_t		srq_pdhdl;
	hermon_mrhdl_t		srq_mrhdl;
	uint_t			srq_is_umap;
	uint32_t		srq_uarpg;
	devmap_cookie_t		srq_umap_dhp;

	ibt_srq_sizes_t		srq_real_sizes;
	hermon_rsrc_t		*srq_srqcrsrcp;
	hermon_rsrc_t		*srq_rsrcp;
	void			*srq_hdlrarg;
	uint_t			srq_refcnt;

	/* Work Queue */
	hermon_workq_hdr_t	*srq_wq_wqhdr;
	uint32_t		*srq_wq_buf;
	uint32_t		srq_wq_bufsz;
	uint32_t		srq_wq_log_wqesz;
	uint32_t		srq_wq_sgl;
	uint32_t		srq_wq_wqecntr;

	/* DoorBell Record information */
	ddi_acc_handle_t	srq_wq_dbr_acchdl;
	hermon_dbr_t		*srq_wq_vdbr;
	uint64_t		srq_wq_pdbr;
	uint64_t		srq_rdbr_mapoffset;	/* user mode access */

	/* For zero-based */
	uint64_t		srq_desc_off;

	/* Queue Memory for SRQ */
	struct hermon_qalloc_info_s	srq_wqinfo;
};
_NOTE(READ_ONLY_DATA(hermon_sw_srq_s::srq_pdhdl
    hermon_sw_srq_s::srq_mrhdl
    hermon_sw_srq_s::srq_srqnum
    hermon_sw_srq_s::srq_wq_sgl
    hermon_sw_srq_s::srq_srqcrsrcp
    hermon_sw_srq_s::srq_rsrcp
    hermon_sw_srq_s::srq_hdlrarg
    hermon_sw_srq_s::srq_is_umap
    hermon_sw_srq_s::srq_uarpg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(hermon_sw_srq_s::srq_wq_bufsz
    hermon_sw_srq_s::srq_wqinfo
    hermon_sw_srq_s::srq_wq_buf
    hermon_sw_srq_s::srq_wq_wqhdr
    hermon_sw_srq_s::srq_desc_off))
_NOTE(MUTEX_PROTECTS_DATA(hermon_sw_srq_s::srq_lock,
    hermon_sw_srq_s::srq_real_sizes
    hermon_sw_srq_s::srq_umap_dhp))

/*
 * The hermon_srq_info_t structure is used internally by the Hermon driver to
 * pass information to and from the hermon_srq_alloc() routine.  It contains
 * placeholders for all of the potential inputs and outputs that this routine
 * can take.
 */
typedef struct hermon_srq_info_s {
	hermon_pdhdl_t		srqi_pd;
	ibt_srq_hdl_t		srqi_ibt_srqhdl;
	ibt_srq_sizes_t		*srqi_sizes;
	ibt_srq_sizes_t		*srqi_real_sizes;
	hermon_srqhdl_t		*srqi_srqhdl;
	uint_t			srqi_flags;
} hermon_srq_info_t;

/*
 * The hermon_srq_options_t structure is used in the Hermon SRQ allocation
 * routines to provide additional option functionality.  When a NULL pointer
 * is passed in place of a pointer to this struct, it is a way of specifying
 * the "default" behavior.  Using this structure, however, is a way of
 * controlling any extended behavior.
 */
typedef struct hermon_srq_options_s {
	uint_t			srqo_wq_loc;
} hermon_srq_options_t;

/*
 * old call
 * int hermon_srq_alloc(hermon_state_t *state, hermon_srq_info_t *srqinfo,
 *  uint_t sleepflag, hermon_srq_options_t *op);
 */

int hermon_srq_alloc(hermon_state_t *state, hermon_srq_info_t *srqinfo,
    uint_t sleepflag);
int hermon_srq_free(hermon_state_t *state, hermon_srqhdl_t *srqhdl,
    uint_t sleepflag);
int hermon_srq_modify(hermon_state_t *state, hermon_srqhdl_t srq,
    uint_t size, uint_t *real_size, uint_t sleepflag);
int hermon_srq_post(hermon_state_t *state, hermon_srqhdl_t srq,
    ibt_recv_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);
void hermon_srq_refcnt_inc(hermon_srqhdl_t srq);
void hermon_srq_refcnt_dec(hermon_srqhdl_t srq);
hermon_srqhdl_t hermon_srqhdl_from_srqnum(hermon_state_t *state, uint_t srqnum);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_SRQ_H */
