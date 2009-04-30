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

#ifndef	_SYS_IB_ADAPTERS_TAVOR_SRQ_H
#define	_SYS_IB_ADAPTERS_TAVOR_SRQ_H

/*
 * tavor_srq.h
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
 * The following defines specify the default number of Shared Receive Queues
 * (SRQ) and their maximum size.  Settings exist for the supported DDR DIMM
 * sizes of 128MB and 256MB.  If a DIMM greater than 256 is found, then the
 * 256MB profile is used.  See tavor_cfg.c for more discussion on config
 * profiles.
 *
 * For manual configuration (not using config profiles), these values are
 * controllable through the "tavor_log_max_srq_sz" and "tavor_log_num_srq"
 * configuration variables, respectively. To override config profile settings
 * the 'tavor_alt_config_enable' configuration variable must first be set.
 *
 * Note: We also have a define for the minimum size of a SRQ.  SRQs allocated
 * with size 0, 1, 2, or 3 will always get back a SRQ of size 4.  This is the
 * smallest size that Tavor hardware and software can correctly handle.
 */
#define	TAVOR_NUM_SRQ_SHIFT_128		0x0A
#define	TAVOR_NUM_SRQ_SHIFT_256		0x0A
#define	TAVOR_SRQ_SZ_SHIFT		0x10
#define	TAVOR_SRQ_SZ			(1 << TAVOR_SRQ_SZ_SHIFT)
#define	TAVOR_SRQ_MIN_SIZE		0x4

/*
 * Minimal configuration values.
 */
#define	TAVOR_NUM_SRQ_SHIFT_MIN		0x8
#define	TAVOR_SRQ_SZ_SHIFT_MIN		0x9

/*
 * XXX The tavor firmware currently has difficulty with an SRQ using more than
 * 15 SGL per WQE (ie: WQE size is 512 or greater).  With a WQE size of 256
 * (SGL 15 or less) no problems are seen.  We set SRQ_MAX_SGL size here, for
 * use in the config profile to be 0xF.  This can still be overridden with the
 * patchable variable in the config profile.
 */
#define	TAVOR_SRQ_MAX_SGL		0xF

/*
 * The following macro determines whether the contents of SRQ memory (WQEs)
 * need to be sync'd (with ddi_dma_sync()).  This decision is based on whether
 * the SRQ memory is in DDR memory (no sync) or system memory (sync required).
 * And it also supports the possibility that if a SRQ in system memory is
 * mapped DDI_DMA_CONSISTENT, it can be configured to not be sync'd because
 * of the "sync override" parameter in the config profile.
 */
#define	TAVOR_SRQ_IS_SYNC_REQ(state, wqinfo)				\
	((((((state)->ts_cfg_profile->cp_streaming_consistent) &&	\
	((state)->ts_cfg_profile->cp_consistent_syncoverride))) ||	\
	((wqinfo).qa_location == TAVOR_QUEUE_LOCATION_INDDR))		\
	? 0 : 1)

/*
 * The following defines specify the size of the individual Shared Receive Queue
 * Context (SRQC) entries
 */
#define	TAVOR_SRQC_SIZE_SHIFT		0x5
#define	TAVOR_SRQC_SIZE			(1 << TAVOR_SRQC_SIZE_SHIFT)

/*
 * SRQ States as defined by Tavor.
 */
#define	TAVOR_SRQ_STATE_SW_OWNER	0xF
#define	TAVOR_SRQ_STATE_HW_OWNER	0x0
#define	TAVOR_SRQ_STATE_ERROR		0x1

/*
 * The tavor_sw_srq_s structure is also referred to using the "tavor_srqhdl_t"
 * typedef (see tavor_typedef.h).  It encodes all the information necessary
 * to track the various resources needed to allocate, initialize, query, modify,
 * post, and (later) free a shared receive queue (SRQ).
 */
struct tavor_sw_srq_s {
	kmutex_t		srq_lock;
	tavor_pdhdl_t		srq_pdhdl;
	tavor_mrhdl_t		srq_mrhdl;
	uint_t			srq_srqnum;
	uint_t			srq_wr_limit;
	uint_t			srq_sync;
	uint_t			srq_refcnt;
	uint_t			srq_state;
	uint32_t		srq_uarpg;
	devmap_cookie_t		srq_umap_dhp;
	ibt_srq_sizes_t		srq_real_sizes;
	tavor_rsrc_t		*srq_srqcrsrcp;
	tavor_rsrc_t		*srq_rsrcp;
	uint_t			srq_is_umap;
	void			*srq_hdlrarg;

	/* Work Queue */
	int			srq_wq_lastwqeindx;
	tavor_workq_hdr_t	*srq_wq_wqhdr;
	uint32_t		*srq_wq_buf;
	uint32_t		srq_wq_bufsz;
	uint32_t		srq_wq_log_wqesz;
	uint32_t		srq_wq_sgl;

	/* For Work Request ID processing */
	tavor_wq_lock_t		*srq_wrid_wql;
	tavor_wrid_list_hdr_t	*srq_wridlist;

	/* For zero-based */
	uint64_t		srq_desc_off;

	/* Queue Memory for SRQ */
	struct tavor_qalloc_info_s	srq_wqinfo;
};
_NOTE(READ_ONLY_DATA(tavor_sw_srq_s::srq_pdhdl
    tavor_sw_srq_s::srq_mrhdl
    tavor_sw_srq_s::srq_srqnum
    tavor_sw_srq_s::srq_wq_sgl
    tavor_sw_srq_s::srq_sync
    tavor_sw_srq_s::srq_srqcrsrcp
    tavor_sw_srq_s::srq_rsrcp
    tavor_sw_srq_s::srq_hdlrarg
    tavor_sw_srq_s::srq_is_umap
    tavor_sw_srq_s::srq_uarpg))
_NOTE(DATA_READABLE_WITHOUT_LOCK(tavor_sw_srq_s::srq_wq_bufsz
    tavor_sw_srq_s::srq_wqinfo
    tavor_sw_srq_s::srq_wq_buf
    tavor_sw_srq_s::srq_desc_off
    tavor_sw_srq_s::srq_wrid_wql))
_NOTE(MUTEX_PROTECTS_DATA(tavor_sw_srq_s::srq_lock,
    tavor_sw_srq_s::srq_wq_wqhdr
    tavor_sw_srq_s::srq_wq_lastwqeindx
    tavor_sw_srq_s::srq_wridlist
    tavor_sw_srq_s::srq_wr_limit
    tavor_sw_srq_s::srq_real_sizes
    tavor_sw_srq_s::srq_umap_dhp))

/*
 * The tavor_srq_info_t structure is used internally by the Tavor driver to
 * pass information to and from the tavor_srq_alloc() routine.  It contains
 * placeholders for all of the potential inputs and outputs that this routine
 * can take.
 */
typedef struct tavor_srq_info_s {
	tavor_pdhdl_t		srqi_pd;
	ibt_srq_hdl_t		srqi_ibt_srqhdl;
	ibt_srq_sizes_t		*srqi_sizes;
	ibt_srq_sizes_t		*srqi_real_sizes;
	tavor_srqhdl_t		*srqi_srqhdl;
	uint_t			srqi_flags;
} tavor_srq_info_t;

/*
 * The tavor_srq_options_t structure is used in the Tavor SRQ allocation
 * routines to provide additional option functionality.  When a NULL pointer
 * is passed in place of a pointer to this struct, it is a way of specifying
 * the "default" behavior.  Using this structure, however, is a way of
 * controlling any extended behavior.
 *
 * Currently, the only defined "extended" behavior is for specifying whether
 * a given SRQ's work queues should be allocated from kernel system memory
 * (TAVOR_QUEUE_LOCATION_NORMAL) or should be allocated from local DDR memory
 * (TAVOR_QUEUE_LOCATION_INDDR).  This defaults today to always allocating
 * from kernel system memory but can be changed by using the
 * "tavor_srq_wq_inddr" configuration variable.
 */
typedef struct tavor_srq_options_s {
	uint_t			srqo_wq_loc;
} tavor_srq_options_t;

int tavor_srq_alloc(tavor_state_t *state, tavor_srq_info_t *srqinfo,
    uint_t sleepflag, tavor_srq_options_t *op);
int tavor_srq_free(tavor_state_t *state, tavor_srqhdl_t *srqhdl,
    uint_t sleepflag);
int tavor_srq_modify(tavor_state_t *state, tavor_srqhdl_t srq,
    uint_t size, uint_t *real_size, uint_t sleepflag);
int tavor_srq_post(tavor_state_t *state, tavor_srqhdl_t srq,
    ibt_recv_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);
void tavor_srq_refcnt_inc(tavor_srqhdl_t srq);
void tavor_srq_refcnt_dec(tavor_srqhdl_t srq);
tavor_srqhdl_t tavor_srqhdl_from_srqnum(tavor_state_t *state, uint_t srqnum);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_SRQ_H */
