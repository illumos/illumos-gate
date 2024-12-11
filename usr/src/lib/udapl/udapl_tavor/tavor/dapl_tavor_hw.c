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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file may contain confidential information of
 * Mellanox Technologies, Ltd. and should not be distributed in source
 * form without approval from Sun Legal.
 */

#include "dapl.h"
#include "dapl_tavor_hw.h"
#include "dapl_tavor_wr.h"
#include "dapl_tavor_ibtf_impl.h"

/*
 * Function signatures
 */
extern uint64_t dapls_tavor_wrid_get_entry(ib_cq_handle_t, tavor_hw_cqe_t *,
    uint_t, uint_t, dapls_tavor_wrid_entry_t *);
extern void dapls_tavor_wrid_cq_reap(ib_cq_handle_t);
extern DAPL_OS_LOCK g_tavor_uar_lock;

#ifndef	_LP64
extern void dapls_atomic_assign_64(uint64_t, uint64_t *);
#endif

static int dapli_tavor_wqe_send_build(ib_qp_handle_t, ibt_send_wr_t *,
    uint64_t *, uint_t *);
static void dapli_tavor_wqe_send_linknext(ibt_send_wr_t *, uint64_t *,
    boolean_t, uint32_t, uint_t, uint64_t *, tavor_sw_wqe_dbinfo_t *);
static DAT_RETURN dapli_tavor_wqe_recv_build(ib_qp_handle_t, ibt_recv_wr_t *,
    uint64_t *, uint_t *);
static void dapli_tavor_wqe_recv_linknext(uint64_t *, boolean_t, uint32_t,
    uint_t, uint64_t *);
static int dapli_tavor_cq_cqe_consume(ib_cq_handle_t, tavor_hw_cqe_t *,
    ibt_wc_t *);
static int dapli_tavor_cq_errcqe_consume(ib_cq_handle_t, tavor_hw_cqe_t *,
    ibt_wc_t *);

/* exported to other HCAs */
extern void dapli_tavor_wrid_add_entry(dapls_tavor_workq_hdr_t *, uint64_t,
    uint32_t, uint_t);
extern void dapli_tavor_wrid_add_entry_srq(ib_srq_handle_t, uint64_t, uint32_t);

/*
 * Note: The 64 bit doorbells need to written atomically.
 * In 32 bit libraries we need to use the special assembly rtn
 * because compiler generated code splits into 2 word writes
 */

#if defined(_LP64) || defined(__lint)
/* use a macro to ensure inlining on S10 amd64 compiler */
#define	dapli_tavor_cq_doorbell(ia_uar, cq_cmd, cqn, cq_param) \
	((tavor_hw_uar_t *)ia_uar)->cq = HTOBE_64( \
	    ((uint64_t)cq_cmd << TAVOR_CQDB_CMD_SHIFT) | \
	    ((uint64_t)cqn << TAVOR_CQDB_CQN_SHIFT) | cq_param)
#else

/*
 * dapli_tavor_cq_doorbell()
 * Takes the specified cq cmd and cq number and rings the cq doorbell
 */
static void
dapli_tavor_cq_doorbell(dapls_hw_uar_t ia_uar, uint32_t cq_cmd, uint32_t cqn,
    uint32_t cq_param)
{
	uint64_t doorbell;

	/* Build the doorbell from the parameters */
	doorbell = ((uint64_t)cq_cmd << TAVOR_CQDB_CMD_SHIFT) |
	    ((uint64_t)cqn << TAVOR_CQDB_CQN_SHIFT) | cq_param;

	/* Write the doorbell to UAR */
#ifdef _LP64
	((tavor_hw_uar_t *)ia_uar)->cq = HTOBE_64(doorbell);
	/* 32 bit version */
#elif defined(i386)
	dapl_os_lock(&g_tavor_uar_lock);
	/*
	 * For 32 bit intel we assign the doorbell in the order
	 * prescribed by the Tavor PRM, lower to upper addresses
	 */
	((tavor_hw_uar32_t *)ia_uar)->cq[0] =
	    (uint32_t)HTOBE_32(doorbell >> 32);
	((tavor_hw_uar32_t *)ia_uar)->cq[1] =
	    (uint32_t)HTOBE_32(doorbell & 0x00000000ffffffff);
	dapl_os_unlock(&g_tavor_uar_lock);
#else
	dapls_atomic_assign_64(HTOBE_64(doorbell),
	    &((tavor_hw_uar_t *)ia_uar)->cq);
#endif
}

#endif	/* _LP64 */

#if defined(_LP64) || defined(__lint)
#define	dapli_tavor_qp_send_doorbell(ia_uar, nda, nds, qpn, fence, nopcode) \
	((tavor_hw_uar_t *)ia_uar)->send = HTOBE_64( \
	    (((uint64_t)nda & TAVOR_QPSNDDB_NDA_MASK) << \
	    TAVOR_QPSNDDB_NDA_SHIFT) | \
	    ((uint64_t)fence << TAVOR_QPSNDDB_F_SHIFT) | \
	    ((uint64_t)nopcode << TAVOR_QPSNDDB_NOPCODE_SHIFT) | \
	    ((uint64_t)qpn << TAVOR_QPSNDDB_QPN_SHIFT) | nds)
#else

/*
 * dapli_tavor_qp_send_doorbell()
 * Takes the specified next descriptor information, qp number, opcode and
 * rings the send doorbell
 */
static void
dapli_tavor_qp_send_doorbell(dapls_hw_uar_t ia_uar, uint32_t nda,
    uint32_t nds, uint32_t qpn, uint32_t fence, uint32_t nopcode)
{
	uint64_t doorbell;

	/* Build the doorbell from the parameters */
	doorbell = (((uint64_t)nda & TAVOR_QPSNDDB_NDA_MASK) <<
	    TAVOR_QPSNDDB_NDA_SHIFT) |
	    ((uint64_t)fence << TAVOR_QPSNDDB_F_SHIFT) |
	    ((uint64_t)nopcode << TAVOR_QPSNDDB_NOPCODE_SHIFT) |
	    ((uint64_t)qpn << TAVOR_QPSNDDB_QPN_SHIFT) | nds;

	/* Write the doorbell to UAR */
#ifdef _LP64
	((tavor_hw_uar_t *)ia_uar)->send = HTOBE_64(doorbell);
#else
#if defined(i386)
	dapl_os_lock(&g_tavor_uar_lock);
	/*
	 * For 32 bit intel we assign the doorbell in the order
	 * prescribed by the Tavor PRM, lower to upper addresses
	 */
	((tavor_hw_uar32_t *)ia_uar)->send[0] =
	    (uint32_t)HTOBE_32(doorbell >> 32);
	((tavor_hw_uar32_t *)ia_uar)->send[1] =
	    (uint32_t)HTOBE_32(doorbell & 0x00000000ffffffff);
	dapl_os_unlock(&g_tavor_uar_lock);
#else
	dapls_atomic_assign_64(HTOBE_64(doorbell),
	    &((tavor_hw_uar_t *)ia_uar)->send);
#endif
#endif
}
#endif	/* _LP64 */

#if defined(_LP64) || defined(__lint)

#define	dapli_tavor_qp_recv_doorbell(ia_uar, nda, nds, qpn, credits) \
	((tavor_hw_uar_t *)ia_uar)->recv = HTOBE_64( \
	    (((uint64_t)nda & TAVOR_QPRCVDB_NDA_MASK) << \
	    TAVOR_QPRCVDB_NDA_SHIFT) | \
	    ((uint64_t)nds << TAVOR_QPRCVDB_NDS_SHIFT) | \
	    ((uint64_t)qpn << TAVOR_QPRCVDB_QPN_SHIFT) | credits)
#else

/*
 * dapli_tavor_qp_recv_doorbell()
 * Takes the specified next descriptor information, qp number and
 * rings the recv doorbell
 */
static void
dapli_tavor_qp_recv_doorbell(dapls_hw_uar_t ia_uar, uint32_t nda,
    uint32_t nds, uint32_t qpn, uint32_t credits)
{
	uint64_t doorbell;

	/* Build the doorbell from the parameters */
	doorbell = (((uint64_t)nda & TAVOR_QPRCVDB_NDA_MASK) <<
	    TAVOR_QPRCVDB_NDA_SHIFT) |
	    ((uint64_t)nds << TAVOR_QPRCVDB_NDS_SHIFT) |
	    ((uint64_t)qpn << TAVOR_QPRCVDB_QPN_SHIFT) | credits;

	/* Write the doorbell to UAR */
#ifdef _LP64
	((tavor_hw_uar_t *)ia_uar)->recv = HTOBE_64(doorbell);
#else
#if defined(i386)
	dapl_os_lock(&g_tavor_uar_lock);
	/*
	 * For 32 bit intel we assign the doorbell in the order
	 * prescribed by the Tavor PRM, lower to upper addresses
	 */
	((tavor_hw_uar32_t *)ia_uar)->recv[0] =
	    (uint32_t)HTOBE_32(doorbell >> 32);
	((tavor_hw_uar32_t *)ia_uar)->recv[1] =
	    (uint32_t)HTOBE_32(doorbell & 0x00000000ffffffff);
	dapl_os_unlock(&g_tavor_uar_lock);
#else
	dapls_atomic_assign_64(HTOBE_64(doorbell),
	    &((tavor_hw_uar_t *)ia_uar)->recv);
#endif
#endif
}
#endif	/* _LP64 */

/*
 * dapls_tavor_max_inline()
 * Return the max inline value that should be used.
 * Env variable DAPL_MAX_INLINE can override the default.
 * If it's not set (or set to -1), default behavior is used.
 * If it's zero or negative (except -1) inline is not done.
 */
int
dapls_tavor_max_inline(void)
{
	static int max_inline_env = -2;

	/* Check the env exactly once, otherwise return previous value. */
	if (max_inline_env != -2)
		return (max_inline_env);

	max_inline_env = dapl_os_get_env_val("DAPL_MAX_INLINE", -1);
	if (max_inline_env != -1)
		if (max_inline_env <= 0)
			max_inline_env = 0;	/* no inlining */
	return (max_inline_env);
}

/*
 * dapls_ib_max_request_iov(), aka, max send sgl size.
 * The send queue's scatter/gather list is used for "inline" data.
 *
 * By default, compute reasonable send queue size based on #iovs, #wqes,
 * max_iovs, and max inline byte count.  If the #wqes is large, then we
 * limit how much the SGL (space for inline data) can take.  The heuristic
 * is to increase the memory for the send queue to a maximum of 32KB:
 *
 *	< 128 wqes	increase to at most 256 minus header
 *	< 256 wqes	increase to at most 128 minus header
 *	>= 256 wqes	use SGL unaltered
 *
 * If the env is supplied (max_inline >= 0), use it without checking.
 */
int
dapls_ib_max_request_iov(int iovs, int wqes, int max_iovs,
    int max_inline_bytes)
{
	int ret_iovs;

	if (max_inline_bytes > 0) {
		ret_iovs = max_inline_bytes / sizeof (tavor_hw_wqe_sgl_t);
	} else if (wqes < 128) {
		max_inline_bytes = 256 - TAVOR_INLINE_HEADER_SIZE_MAX;
		ret_iovs = max_inline_bytes / sizeof (tavor_hw_wqe_sgl_t);
	} else if (wqes < 256) {
		max_inline_bytes = 128 - TAVOR_INLINE_HEADER_SIZE_MAX;
		ret_iovs = max_inline_bytes / sizeof (tavor_hw_wqe_sgl_t);
	} else {
		ret_iovs = iovs;
	}

	if (ret_iovs > max_iovs)	/* do not exceed max */
		ret_iovs = max_iovs;
	if (iovs > ret_iovs)		/* never decrease iovs */
		ret_iovs = iovs;
	return (ret_iovs);
}

/*
 * dapli_tavor_wqe_send_build()
 * Constructs a WQE for a given ibt_send_wr_t
 */
static int
dapli_tavor_wqe_send_build(ib_qp_handle_t qp, ibt_send_wr_t *wr,
    uint64_t *addr, uint_t *size)
{
	tavor_hw_snd_wqe_remaddr_t	*rc;
	tavor_hw_snd_wqe_bind_t		*bn;
	tavor_hw_wqe_sgl_t		*ds;
	ibt_wr_ds_t			*sgl;
	uint32_t			nds;
	uint32_t			len, total_len;
	uint32_t			tavor_num_mpt_mask;
	uint32_t			new_rkey;
	uint32_t			old_rkey;
	int				i, num_ds;
	int				max_inline_bytes = -1;

	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;

	/*
	 * RC is the only supported transport in UDAPL
	 * For RC requests, we allow "Send", "RDMA Read", "RDMA Write"
	 */
	switch (wr->wr_opcode) {
	case IBT_WRC_SEND:
		/*
		 * If this is a Send request, then all we need is
		 * the Data Segment processing below.
		 * Initialize the information for the Data Segments
		 */
		ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)addr +
		    sizeof (tavor_hw_snd_wqe_nextctrl_t));
		if (qp->qp_sq_inline != 0)
			max_inline_bytes =
			    qp->qp_sq_wqesz - TAVOR_INLINE_HEADER_SIZE_SEND;
		break;
	case IBT_WRC_RDMAW:
		if (qp->qp_sq_inline != 0)
			max_inline_bytes =
			    qp->qp_sq_wqesz - TAVOR_INLINE_HEADER_SIZE_RDMAW;
		/* FALLTHROUGH */
	case IBT_WRC_RDMAR:
		if (qp->qp_sq_inline < 0 && wr->wr_opcode == IBT_WRC_RDMAR)
			qp->qp_sq_inline = 0;
		/*
		 * If this is an RDMA Read or RDMA Write request, then fill
		 * in the "Remote Address" header fields.
		 */
		rc = (tavor_hw_snd_wqe_remaddr_t *)((uintptr_t)addr +
		    sizeof (tavor_hw_snd_wqe_nextctrl_t));

		/*
		 * Build the Remote Address Segment for the WQE, using
		 * the information from the RC work request.
		 */
		TAVOR_WQE_BUILD_REMADDR(rc, &wr->wr.rc.rcwr.rdma);

		/* Update "ds" for filling in Data Segments (below) */
		ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)rc +
		    sizeof (tavor_hw_snd_wqe_remaddr_t));
		break;
	case IBT_WRC_BIND:
		/*
		 * Generate a new R_key
		 * Increment the upper "unconstrained" bits and need to keep
		 * the lower "constrained" bits the same it represents
		 * the MPT index.
		 */
		old_rkey = wr->wr.rc.rcwr.bind->bind_rkey;
		tavor_num_mpt_mask = (uint32_t)(1 << qp->qp_num_mpt_shift) - 1;
		new_rkey = (old_rkey >> qp->qp_num_mpt_shift);
		new_rkey++;
		new_rkey = ((new_rkey << qp->qp_num_mpt_shift) |
		    (old_rkey & tavor_num_mpt_mask));

		wr->wr.rc.rcwr.bind->bind_rkey_out = new_rkey;

		bn = (tavor_hw_snd_wqe_bind_t *)((uintptr_t)addr +
		    sizeof (tavor_hw_snd_wqe_nextctrl_t));

		/*
		 * Build the Bind Memory Window Segments for the WQE,
		 * using the information from the RC Bind memory
		 * window work request.
		 */
		TAVOR_WQE_BUILD_BIND(bn, wr->wr.rc.rcwr.bind);

		/*
		 * Update the "ds" pointer.  Even though the "bind"
		 * operation requires no SGLs, this is necessary to
		 * facilitate the correct descriptor size calculations
		 * (below).
		 */
		ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)bn +
		    sizeof (tavor_hw_snd_wqe_bind_t));
		break;
	default:
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapli_tavor_wqe_send_build: invalid wr_opcode=%d\n",
		    wr->wr_opcode);
		return (DAT_INTERNAL_ERROR);
	}

	/*
	 * Now fill in the Data Segments (SGL) for the Send WQE based on
	 * the values setup above (i.e. "sgl", "nds", and the "ds" pointer
	 * Start by checking for a valid number of SGL entries
	 */
	if (nds > qp->qp_sq_sgl) {
		return (DAT_INVALID_PARAMETER);
	}

	/*
	 * For each SGL in the Send Work Request, fill in the Send WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */

	if (max_inline_bytes != -1) {		/* compute total_len */
		total_len = 0;
		for (i = 0; i < nds; i++)
			total_len += sgl[i].ds_len;
		if (total_len > max_inline_bytes)
			max_inline_bytes = -1;	/* too big, do not "inline" */
	}
	if (max_inline_bytes != -1) {		/* do "inline" */
		uint8_t *dst = (uint8_t *)((uint32_t *)ds + 1);
		*(uint32_t *)ds =
		    HTOBE_32(total_len | TAVOR_WQE_SGL_INLINE_MASK);
		for (i = 0; i < nds; i++) {
			if ((len = sgl[i].ds_len) == 0) {
				continue;
			}
			(void) dapl_os_memcpy(dst,
			    (void *)(uintptr_t)sgl[i].ds_va, len);
			dst += len;
		}
		/* Return the size of descriptor (in 16-byte chunks) */
		*size = ((uintptr_t)dst - (uintptr_t)addr + 15) >> 4;
	} else {
		for (i = 0; i < nds; i++) {
			if (sgl[i].ds_len == 0) {
				continue;
			}

			/*
			 * Fill in the Data Segment(s) for the current WQE,
			 * using the information contained in the
			 * scatter-gather list of the work request.
			 */
			TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &sgl[i]);
			num_ds++;
		}

		/* Return the size of descriptor (in 16-byte chunks) */
		*size = ((uintptr_t)&ds[num_ds] - (uintptr_t)addr) >> 4;
	}

	return (DAT_SUCCESS);
}

/*
 * dapli_tavor_wqe_send_linknext()
 * Takes a WQE and links it to the prev WQE chain
 */
static void
dapli_tavor_wqe_send_linknext(ibt_send_wr_t *curr_wr, uint64_t *curr_addr,
    boolean_t ns, uint32_t curr_desc, uint_t curr_descsz, uint64_t *prev_addr,
    tavor_sw_wqe_dbinfo_t *dbinfo)
{
	uint64_t	next, ctrl;
	uint32_t	nopcode, fence;

	next = 0;
	ctrl = 0;

	/* Set the "c" (i.e. "signaled") bit appropriately */
	if (curr_wr->wr_flags & IBT_WR_SEND_SIGNAL) {
		ctrl = ctrl | TAVOR_WQE_SEND_SIGNALED_MASK;
	}

	/* Set the "s" (i.e. "solicited") bit appropriately */
	if (curr_wr->wr_flags & IBT_WR_SEND_SOLICIT) {
		ctrl = ctrl | TAVOR_WQE_SEND_SOLICIT_MASK;
	}
	/* Set the "e" (i.e. "event") bit if notification is needed */
	if (!ns) {
		ctrl = ctrl | TAVOR_WQE_RCV_EVENT_MASK;
	}

	/*
	 * The "i" bit is unused since uDAPL doesn't support
	 * the immediate data
	 */

	/* initialize the ctrl and next fields of the current descriptor */
	TAVOR_WQE_LINKNEXT(curr_addr, ctrl, next);

	/*
	 * Calculate the "next" field of the prev descriptor.  This amounts
	 * to setting up the "next_wqe_addr", "nopcode", "fence", and "nds"
	 * fields (see tavor_hw.h for more).
	 */

	/*
	 * Determine the value for the Tavor WQE "nopcode" field
	 * by using the IBTF opcode from the work request
	 */
	switch (curr_wr->wr_opcode) {
	case IBT_WRC_RDMAW:
		nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAW;
		break;

	case IBT_WRC_SEND:
		nopcode = TAVOR_WQE_SEND_NOPCODE_SEND;
		break;

	case IBT_WRC_RDMAR:
		nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAR;
		break;

	case IBT_WRC_BIND:
		nopcode = TAVOR_WQE_SEND_NOPCODE_BIND;
		break;
	default:
		/* Unsupported opcodes in UDAPL */
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapli_tavor_wqe_send_linknext: invalid nopcode=%d\n",
		    nopcode);
		return;
	}

	next  = ((uint64_t)curr_desc & TAVOR_WQE_NDA_MASK) << 32;
	next  = next | ((uint64_t)nopcode << 32);
	fence = (curr_wr->wr_flags & IBT_WR_SEND_FENCE) ? 1 : 0;
	if (fence) {
		next = next | TAVOR_WQE_SEND_FENCE_MASK;
	}
	next = next | (curr_descsz & TAVOR_WQE_NDS_MASK);

	/*
	 * A send queue doorbell will be rung for the next
	 * WQE on the chain, set the current WQE's "dbd" bit.
	 * Note: We also update the "dbinfo" structure here to pass
	 * back information about what should (later) be included
	 * in the send queue doorbell.
	 */
	next = next | TAVOR_WQE_DBD_MASK;
	dbinfo->db_nopcode = nopcode;
	dbinfo->db_fence   = fence;

	/*
	 * Send queue doorbell will be rung for the next WQE on
	 * the chain, update the prev WQE's "next" field and return.
	 */
	if (prev_addr != NULL) {
		TAVOR_WQE_LINKFIRST(prev_addr, next);
	}
}


/*
 * dapli_tavor_wqe_recv_build()
 * Builds the recv WQE for a given ibt_recv_wr_t
 */
static DAT_RETURN
dapli_tavor_wqe_recv_build(ib_qp_handle_t qp, ibt_recv_wr_t *wr,
    uint64_t *addr, uint_t *size)
{
	tavor_hw_wqe_sgl_t	*ds;
	int			i;
	int			num_ds;

	/* Fill in the Data Segments (SGL) for the Recv WQE */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)addr +
	    sizeof (tavor_hw_rcv_wqe_nextctrl_t));
	num_ds = 0;

	/* Check for valid number of SGL entries */
	if (wr->wr_nds > qp->qp_rq_sgl) {
		return (DAT_INVALID_PARAMETER);
	}

	/*
	 * For each SGL in the Recv Work Request, fill in the Recv WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */
	for (i = 0; i < wr->wr_nds; i++) {
		if (wr->wr_sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the receive WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &wr->wr_sgl[i]);
		num_ds++;
	}

	/* Return the size of descriptor (in 16-byte chunks) */
	*size = ((uintptr_t)&ds[num_ds] - (uintptr_t)addr) >> 0x4;

	return (DAT_SUCCESS);
}


/*
 * dapli_tavor_wqe_recv_linknext()
 * Links a recv WQE to the prev chain
 */
static void
dapli_tavor_wqe_recv_linknext(uint64_t *curr_addr, boolean_t ns,
    uint32_t curr_desc, uint_t curr_descsz, uint64_t *prev_addr)
{
	uint64_t	next;
	uint64_t	ctrl = 0;

	/*
	 * Note: curr_addr is the last WQE (In uDAPL we manipulate 1 WQE
	 * at a time. If there is no next descriptor (i.e. if the current
	 * descriptor is the last WQE on the chain), then set "next" field
	 * to TAVOR_WQE_DBD_MASK.  This is because the Tavor hardware
	 * requires the "dbd" bit to be set to one for all Recv WQEs.
	 * In either case, we must add a single bit in the "reserved" field
	 * (TAVOR_RCV_WQE_NDA0_WA_MASK) following the NDA.  This is the
	 * workaround for a known Tavor errata that can cause Recv WQEs with
	 * zero in the NDA field to behave improperly.
	 *
	 * If notification suppression is not desired then we set
	 * the "E" bit in the ctrl field.
	 */

	next = TAVOR_WQE_DBD_MASK | TAVOR_RCV_WQE_NDA0_WA_MASK;
	if (!ns) { /* notification needed - so set the "E" bit */
		ctrl = TAVOR_WQE_RCV_EVENT_MASK;
	}

	/* update the WQE */
	TAVOR_WQE_LINKNEXT(curr_addr, ctrl, next);

	if (prev_addr != NULL) {
		/*
		 * Calculate the "next" field of the descriptor.  This amounts
		 * to setting up the "next_wqe_addr", "dbd", and "nds" fields
		 * (see tavor_hw.h for more).
		 */
		next = ((uint64_t)curr_desc & TAVOR_WQE_NDA_MASK) << 32;
		next = next | (curr_descsz & TAVOR_WQE_NDS_MASK) |
		    TAVOR_WQE_DBD_MASK | TAVOR_RCV_WQE_NDA0_WA_MASK;

		/*
		 * If this WQE is supposed to be linked to the previous
		 * descriptor, then we need to update not only the previous
		 * WQE's "next" fields but we must not touch this WQE's
		 * "ctrl" fields.
		 */
		TAVOR_WQE_LINKFIRST(prev_addr, next);
	}
}

/*
 * dapli_tavor_wqe_srq_build()
 * Builds the recv WQE for a given ibt_recv_wr_t
 */
static DAT_RETURN
dapli_tavor_wqe_srq_build(ib_srq_handle_t srq, ibt_recv_wr_t *wr,
    uint64_t *addr)
{
	tavor_hw_wqe_sgl_t	*ds;
	ibt_wr_ds_t		end_sgl;
	int			i;
	int			num_ds;

	/* Fill in the Data Segments (SGL) for the Recv WQE */
	ds = (tavor_hw_wqe_sgl_t *)((uintptr_t)addr +
	    sizeof (tavor_hw_rcv_wqe_nextctrl_t));
	num_ds = 0;

	/* Check for valid number of SGL entries */
	if (wr->wr_nds > srq->srq_wq_sgl) {
		return (DAT_INVALID_PARAMETER);
	}

	/*
	 * For each SGL in the Recv Work Request, fill in the Recv WQE's data
	 * segments.  Note: We skip any SGL with zero size because Tavor
	 * hardware cannot handle a zero for "byte_cnt" in the WQE.  Actually
	 * the encoding for zero means a 2GB transfer.  Because of this special
	 * encoding in the hardware, we mask the requested length with
	 * TAVOR_WQE_SGL_BYTE_CNT_MASK (so that 2GB will end up encoded as
	 * zero.)
	 */
	for (i = 0; i < wr->wr_nds; i++) {
		if (wr->wr_sgl[i].ds_len == 0) {
			continue;
		}

		/*
		 * Fill in the Data Segment(s) for the receive WQE, using the
		 * information contained in the scatter-gather list of the
		 * work request.
		 */
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &wr->wr_sgl[i]);
		num_ds++;
	}

	/*
	 * For SRQ, if the number of data segments is less than the maximum
	 * specified at alloc, then we have to fill in a special "key" entry in
	 * the sgl entry after the last valid one in this post request.  We do
	 * that here.
	 */
	if (num_ds < srq->srq_wq_sgl) {
		end_sgl.ds_va  = (ib_vaddr_t)0;
		end_sgl.ds_len = (ib_msglen_t)0;
		end_sgl.ds_key = (ibt_lkey_t)1;
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &end_sgl);
	}

	return (DAT_SUCCESS);
}

/*
 * dapli_tavor_wqe_srq_linknext()
 * Links a srq recv WQE to the prev chain
 */
static void
dapli_tavor_wqe_srq_linknext(uint64_t *curr_addr, boolean_t ns,
    uint32_t curr_desc, uint64_t *prev_addr)
{
	uint64_t	next;
	uint64_t	ctrl = 0;

	/*
	 * Note: curr_addr is the last WQE (In uDAPL we manipulate 1 WQE
	 * at a time. If there is no next descriptor (i.e. if the current
	 * descriptor is the last WQE on the chain), then set "next" field
	 * to TAVOR_WQE_DBD_MASK.  This is because the Tavor hardware
	 * requires the "dbd" bit to be set to one for all Recv WQEs.
	 * In either case, we must add a single bit in the "reserved" field
	 * (TAVOR_RCV_WQE_NDA0_WA_MASK) following the NDA.  This is the
	 * workaround for a known Tavor errata that can cause Recv WQEs with
	 * zero in the NDA field to behave improperly.
	 *
	 * If notification suppression is not desired then we set
	 * the "E" bit in the ctrl field.
	 */

	next = TAVOR_RCV_WQE_NDA0_WA_MASK;
	if (!ns) { /* notification needed - so set the "E" bit */
		ctrl = TAVOR_WQE_RCV_EVENT_MASK;
	}

	/* update the WQE */
	TAVOR_WQE_LINKNEXT(curr_addr, ctrl, next);

	if (prev_addr != NULL) {
		/*
		 * Calculate the "next" field of the descriptor.  This amounts
		 * to setting up the "next_wqe_addr", "dbd", and "nds" fields
		 * (see tavor_hw.h for more).
		 */
		next = ((uint64_t)curr_desc & TAVOR_WQE_NDA_MASK) << 32;
		next = next | TAVOR_WQE_DBD_MASK | TAVOR_RCV_WQE_NDA0_WA_MASK;

		/*
		 * If this WQE is supposed to be linked to the previous
		 * descriptor, then we need to update not only the previous
		 * WQE's "next" fields but we must not touch this WQE's
		 * "ctrl" fields.
		 */
		TAVOR_WQE_LINKFIRST(prev_addr, next);
	}
}

/*
 * dapli_tavor_cq_peek()
 * Peeks into a given CQ to check if there are any events that can be
 * polled. It returns the number of CQEs that can be polled.
 */
static void
dapli_tavor_cq_peek(ib_cq_handle_t cq, int *num_cqe)
{
	tavor_hw_cqe_t		*cqe;
	uint32_t		imm_eth_pkey_cred;
	uint32_t		cons_indx;
	uint32_t		wrap_around_mask;
	uint32_t		polled_cnt;
	uint_t			doorbell_cnt;
	uint_t			opcode;

	/* Get the consumer index */
	cons_indx = cq->cq_consindx;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor completion queues have power-of-2 sizes
	 */
	wrap_around_mask = (cq->cq_size - 1);

	/* Calculate the pointer to the first CQ entry */
	cqe = &cq->cq_addr[cons_indx];

	/*
	 * Count entries in the CQ until we find an entry owned by
	 * the hardware.
	 */
	polled_cnt = 0;
	while (TAVOR_CQE_OWNER_IS_SW(cqe)) {
		opcode = TAVOR_CQE_OPCODE_GET(cqe);
		/* Error CQE map to multiple work completions */
		if ((opcode == TAVOR_CQE_SEND_ERR_OPCODE) ||
		    (opcode == TAVOR_CQE_RECV_ERR_OPCODE)) {
			imm_eth_pkey_cred =
			    TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe);
			doorbell_cnt =
			    imm_eth_pkey_cred & TAVOR_CQE_ERR_DBDCNT_MASK;
			polled_cnt += (doorbell_cnt + 1);
		} else {
			polled_cnt++;
		}
		/* Increment the consumer index */
		cons_indx = (cons_indx + 1) & wrap_around_mask;

		/* Update the pointer to the next CQ entry */
		cqe = &cq->cq_addr[cons_indx];
	}

	*num_cqe = polled_cnt;
}

/*
 * dapli_tavor_cq_poll()
 * This routine polls CQEs out of a CQ and puts them into the ibt_wc_t
 * array that is passed in.
 */
static DAT_RETURN
dapli_tavor_cq_poll(ib_cq_handle_t cq, ibt_wc_t *wc_p, uint_t num_wc,
    uint_t *num_polled)
{
	tavor_hw_cqe_t		*cqe;
	uint32_t		cons_indx;
	uint32_t		wrap_around_mask;
	uint32_t		polled_cnt;
	uint32_t		num_to_increment;
	DAT_RETURN		dat_status;
	int			status;

	/* Get the consumer index */
	cons_indx = cq->cq_consindx;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor completion queues have power-of-2 sizes
	 */
	wrap_around_mask = (cq->cq_size - 1);

	/* Calculate the pointer to the first CQ entry */
	cqe = &cq->cq_addr[cons_indx];

	/*
	 * Keep pulling entries from the CQ until we find an entry owned by
	 * the hardware.  As long as there the CQE's owned by SW, process
	 * each entry by calling dapli_tavor_cq_cqe_consume() and updating the
	 * CQ consumer index.  Note:  We only update the consumer index if
	 * dapli_tavor_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.
	 * Otherwise, it indicates that we are going to "recycle" the CQE
	 * (probably because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	polled_cnt = 0;
	while (TAVOR_CQE_OWNER_IS_SW(cqe)) {
		status = dapli_tavor_cq_cqe_consume(cq, cqe,
		    &wc_p[polled_cnt++]);
		if (status == TAVOR_CQ_SYNC_AND_DB) {
			/* Reset entry to hardware ownership */
			TAVOR_CQE_OWNER_SET_HW(cqe);

			/* Increment the consumer index */
			cons_indx = (cons_indx + 1) & wrap_around_mask;

			/* Update the pointer to the next CQ entry */
			cqe = &cq->cq_addr[cons_indx];
		}

		/*
		 * If we have run out of space to store work completions,
		 * then stop and return the ones we have pulled of the CQ.
		 */
		if (polled_cnt >= num_wc) {
			break;
		}
	}

	dat_status = DAT_SUCCESS;
	/*
	 * Now we only ring the doorbell (to update the consumer index) if
	 * we've actually consumed a CQ entry.  If we have, for example,
	 * pulled from a CQE that we are still in the process of "recycling"
	 * for error purposes, then we would not update the consumer index.
	 */
	if ((polled_cnt != 0) && (cq->cq_consindx != cons_indx)) {
		/*
		 * Post doorbell to update the consumer index.  Doorbell
		 * value indicates number of entries consumed (minus 1)
		 */
		if (cons_indx > cq->cq_consindx) {
			num_to_increment = (cons_indx - cq->cq_consindx) - 1;
		} else {
			num_to_increment = ((cons_indx + cq->cq_size) -
			    cq->cq_consindx) - 1;
		}
		cq->cq_consindx = cons_indx;
		dapli_tavor_cq_doorbell(cq->cq_iauar, TAVOR_CQDB_INCR_CONSINDX,
		    cq->cq_num, num_to_increment);
	} else if (polled_cnt == 0) {
		/*
		 * If the CQ is empty, we can try to free up some of the WRID
		 * list containers.
		 */
		if (cq->cq_wrid_reap_head)	/* look before leaping */
			dapls_tavor_wrid_cq_reap(cq);
		dat_status = DAT_ERROR(DAT_QUEUE_EMPTY, 0);
	}

	if (num_polled != NULL) {
		*num_polled = polled_cnt;
	}

	return (dat_status);
}

/*
 * dapli_tavor_cq_poll_one()
 * This routine polls one CQE out of a CQ and puts ot into the ibt_wc_t
 * that is passed in.  See above for more comments/details.
 */
static DAT_RETURN
dapli_tavor_cq_poll_one(ib_cq_handle_t cq, ibt_wc_t *wc_p)
{
	tavor_hw_cqe_t		*cqe;
	uint32_t		cons_indx;
	DAT_RETURN		dat_status;
	int			status;

	/* Get the consumer index */
	cons_indx = cq->cq_consindx;

	/* Calculate the pointer to the first CQ entry */
	cqe = &cq->cq_addr[cons_indx];

	/*
	 * Keep pulling entries from the CQ until we find an entry owned by
	 * the hardware.  As long as there the CQE's owned by SW, process
	 * each entry by calling dapli_tavor_cq_cqe_consume() and updating the
	 * CQ consumer index.  Note:  We only update the consumer index if
	 * dapli_tavor_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.
	 * Otherwise, it indicates that we are going to "recycle" the CQE
	 * (probably because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	if (TAVOR_CQE_OWNER_IS_SW(cqe)) {
		status = dapli_tavor_cq_cqe_consume(cq, cqe, wc_p);
		if (status == TAVOR_CQ_SYNC_AND_DB) {
			/* Reset entry to hardware ownership */
			TAVOR_CQE_OWNER_SET_HW(cqe);

			/* Increment the consumer index */
			cq->cq_consindx =
			    (cons_indx + 1) & (cq->cq_size - 1);
			dapli_tavor_cq_doorbell(cq->cq_iauar,
			    TAVOR_CQDB_INCR_CONSINDX,
			    cq->cq_num, 0);
		}
		dat_status = DAT_SUCCESS;
	} else {
		if (cq->cq_wrid_reap_head)	/* look before leaping */
			dapls_tavor_wrid_cq_reap(cq);
		dat_status = DAT_ERROR(DAT_QUEUE_EMPTY, 0);
	}
	return (dat_status);
}

/*
 * dapli_tavor_cq_cqe_consume()
 * Converts a given CQE into a ibt_wc_t object
 */
static int
dapli_tavor_cq_cqe_consume(ib_cq_handle_t cqhdl, tavor_hw_cqe_t *cqe,
    ibt_wc_t *wc)
{
	uint_t		flags;
	uint_t		type;
	uint_t		opcode;
	int		status;

	/*
	 * Determine if this is an "error" CQE by examining "opcode".  If it
	 * is an error CQE, then call dapli_tavor_cq_errcqe_consume() and return
	 * whatever status it returns.  Otherwise, this is a successful
	 * completion.
	 */
	opcode = TAVOR_CQE_OPCODE_GET(cqe);
	if ((opcode == TAVOR_CQE_SEND_ERR_OPCODE) ||
	    (opcode == TAVOR_CQE_RECV_ERR_OPCODE)) {
		status = dapli_tavor_cq_errcqe_consume(cqhdl, cqe, wc);
		return (status);
	}

	/*
	 * Fetch the Work Request ID using the information in the CQE.
	 * See tavor_wr.c for more details.
	 */
	wc->wc_id = dapls_tavor_wrid_get_entry(cqhdl, cqe,
	    TAVOR_CQE_SENDRECV_GET(cqe), 0, NULL);
	wc->wc_qpn = TAVOR_CQE_QPNUM_GET(cqe);

	/*
	 * Parse the CQE opcode to determine completion type.  This will set
	 * not only the type of the completion, but also any flags that might
	 * be associated with it (e.g. whether immediate data is present).
	 */
	flags = IBT_WC_NO_FLAGS;
	if (TAVOR_CQE_SENDRECV_GET(cqe) != TAVOR_COMPLETION_RECV) {

		/*
		 * Send CQE
		 *
		 * The following opcodes will not be generated in uDAPL
		 * case TAVOR_CQE_SND_RDMAWR_IMM:
		 * case TAVOR_CQE_SND_SEND_IMM:
		 * case TAVOR_CQE_SND_ATOMIC_CS:
		 * case TAVOR_CQE_SND_ATOMIC_FA:
		 */
		switch (opcode) {
		case TAVOR_CQE_SND_RDMAWR:
			type = IBT_WRC_RDMAW;
			break;

		case TAVOR_CQE_SND_SEND:
			type = IBT_WRC_SEND;
			break;

		case TAVOR_CQE_SND_RDMARD:
			type = IBT_WRC_RDMAR;
			wc->wc_bytes_xfer = TAVOR_CQE_BYTECNT_GET(cqe);
			break;

		case TAVOR_CQE_SND_BIND_MW:
			type = IBT_WRC_BIND;
			break;

		default:
			wc->wc_status = IBT_WC_LOCAL_CHAN_OP_ERR;
			return (TAVOR_CQ_SYNC_AND_DB);
		}
	} else {

		/*
		 * Receive CQE
		 *
		 * The following opcodes will not be generated in uDAPL
		 *
		 * case TAVOR_CQE_RCV_RECV_IMM:
		 * case TAVOR_CQE_RCV_RECV_IMM2:
		 * case TAVOR_CQE_RCV_RDMAWR_IMM:
		 * case TAVOR_CQE_RCV_RDMAWR_IMM2:
		 */
		switch (opcode & 0x1F) {
		case TAVOR_CQE_RCV_RECV:
			/* FALLTHROUGH */
		case TAVOR_CQE_RCV_RECV2:
			type = IBT_WRC_RECV;
			wc->wc_bytes_xfer = TAVOR_CQE_BYTECNT_GET(cqe);
			break;
		default:
			wc->wc_status = IBT_WC_LOCAL_CHAN_OP_ERR;
			return (TAVOR_CQ_SYNC_AND_DB);
		}
	}
	wc->wc_type = type;
	wc->wc_flags = flags;
	/* If we got here, completion status must be success */
	wc->wc_status = IBT_WC_SUCCESS;

	return (TAVOR_CQ_SYNC_AND_DB);
}


/*
 * dapli_tavor_cq_errcqe_consume()
 */
static int
dapli_tavor_cq_errcqe_consume(ib_cq_handle_t cqhdl, tavor_hw_cqe_t *cqe,
    ibt_wc_t *wc)
{
	dapls_tavor_wrid_entry_t	wre;
	uint32_t		next_wqeaddr;
	uint32_t		imm_eth_pkey_cred;
	uint_t			nextwqesize, dbd;
	uint_t			doorbell_cnt, status;
	uint_t			opcode = TAVOR_CQE_OPCODE_GET(cqe);

	dapl_dbg_log(DAPL_DBG_TYPE_EVD, "errcqe_consume:cqe.eth=%x, wqe=%x\n",
	    TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe),
	    TAVOR_CQE_WQEADDRSZ_GET(cqe));

	/*
	 * Fetch the Work Request ID using the information in the CQE.
	 * See tavor_wr.c for more details.
	 */
	wc->wc_id = dapls_tavor_wrid_get_entry(cqhdl, cqe,
	    (opcode == TAVOR_CQE_SEND_ERR_OPCODE) ? TAVOR_COMPLETION_SEND :
	    TAVOR_COMPLETION_RECV, 1, &wre);
	wc->wc_qpn = TAVOR_CQE_QPNUM_GET(cqe);

	/*
	 * Parse the CQE opcode to determine completion type.  We know that
	 * the CQE is an error completion, so we extract only the completion
	 * status here.
	 */
	imm_eth_pkey_cred = TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe);
	status = imm_eth_pkey_cred >> TAVOR_CQE_ERR_STATUS_SHIFT;
	switch (status) {
	case TAVOR_CQE_LOC_LEN_ERR:
		status = IBT_WC_LOCAL_LEN_ERR;
		break;

	case TAVOR_CQE_LOC_OP_ERR:
		status = IBT_WC_LOCAL_CHAN_OP_ERR;
		break;

	case TAVOR_CQE_LOC_PROT_ERR:
		status = IBT_WC_LOCAL_PROTECT_ERR;
		break;

	case TAVOR_CQE_WR_FLUSHED_ERR:
		status = IBT_WC_WR_FLUSHED_ERR;
		break;

	case TAVOR_CQE_MW_BIND_ERR:
		status = IBT_WC_MEM_WIN_BIND_ERR;
		break;

	case TAVOR_CQE_BAD_RESPONSE_ERR:
		status = IBT_WC_BAD_RESPONSE_ERR;
		break;

	case TAVOR_CQE_LOCAL_ACCESS_ERR:
		status = IBT_WC_LOCAL_ACCESS_ERR;
		break;

	case TAVOR_CQE_REM_INV_REQ_ERR:
		status = IBT_WC_REMOTE_INVALID_REQ_ERR;
		break;

	case TAVOR_CQE_REM_ACC_ERR:
		status = IBT_WC_REMOTE_ACCESS_ERR;
		break;

	case TAVOR_CQE_REM_OP_ERR:
		status = IBT_WC_REMOTE_OP_ERR;
		break;

	case TAVOR_CQE_TRANS_TO_ERR:
		status = IBT_WC_TRANS_TIMEOUT_ERR;
		break;

	case TAVOR_CQE_RNRNAK_TO_ERR:
		status = IBT_WC_RNR_NAK_TIMEOUT_ERR;
		break;

	/*
	 * The following error codes are not supported in the Tavor driver
	 * as they relate only to Reliable Datagram completion statuses:
	 *    case TAVOR_CQE_LOCAL_RDD_VIO_ERR:
	 *    case TAVOR_CQE_REM_INV_RD_REQ_ERR:
	 *    case TAVOR_CQE_EEC_REM_ABORTED_ERR:
	 *    case TAVOR_CQE_INV_EEC_NUM_ERR:
	 *    case TAVOR_CQE_INV_EEC_STATE_ERR:
	 *    case TAVOR_CQE_LOC_EEC_ERR:
	 */

	default:
		status = IBT_WC_LOCAL_CHAN_OP_ERR;
		break;
	}
	wc->wc_status = status;
	wc->wc_type = 0;
	/*
	 * Now we do all the checking that's necessary to handle completion
	 * queue entry "recycling"
	 *
	 * It is not necessary here to try to sync the WQE as we are only
	 * attempting to read from the Work Queue (and hardware does not
	 * write to it).
	 */

	/*
	 * We can get doorbell info, WQE address, size for the next WQE
	 * from the "wre" (which was filled in above in the call to the
	 * tavor_wrid_get_entry() routine)
	 */
	dbd = (wre.wr_signaled_dbd & TAVOR_WRID_ENTRY_DOORBELLED) ? 1 : 0;
	next_wqeaddr = wre.wr_wqeaddrsz;
	nextwqesize  = wre.wr_wqeaddrsz & TAVOR_WQE_NDS_MASK;

	/*
	 * Get the doorbell count from the CQE.  This indicates how many
	 * completions this one CQE represents.
	 */
	doorbell_cnt = imm_eth_pkey_cred & TAVOR_CQE_ERR_DBDCNT_MASK;

	/*
	 * Determine if we're ready to consume this CQE yet or not.  If the
	 * next WQE has size zero (i.e. no next WQE) or if the doorbell count
	 * is down to zero, then this is the last/only completion represented
	 * by the current CQE (return TAVOR_CQ_SYNC_AND_DB).  Otherwise, the
	 * current CQE needs to be recycled (see below).
	 */
	if ((nextwqesize == 0) || ((doorbell_cnt == 0) && (dbd == 1))) {
		/*
		 * Consume the CQE
		 *    Return status to indicate that doorbell and sync may be
		 *    necessary.
		 */
		return (TAVOR_CQ_SYNC_AND_DB);

	} else {
		/*
		 * Recycle the CQE for use in the next PollCQ() call
		 *    Decrement the doorbell count, modify the error status,
		 *    and update the WQE address and size (to point to the
		 *    next WQE on the chain.  Put these update entries back
		 *    into the CQE.
		 *    Despite the fact that we have updated the CQE, it is not
		 *    necessary for us to attempt to sync this entry just yet
		 *    as we have not changed the "hardware's view" of the
		 *    entry (i.e. we have not modified the "owner" bit - which
		 *    is all that the Tavor hardware really cares about.
		 */
		doorbell_cnt = doorbell_cnt - dbd;
		TAVOR_CQE_IMM_ETH_PKEY_CRED_SET(cqe,
		    ((TAVOR_CQE_WR_FLUSHED_ERR << TAVOR_CQE_ERR_STATUS_SHIFT) |
		    (doorbell_cnt & TAVOR_CQE_ERR_DBDCNT_MASK)));
		TAVOR_CQE_WQEADDRSZ_SET(cqe,
		    TAVOR_QP_WQEADDRSZ(next_wqeaddr, nextwqesize));
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
		    "errcqe_consume: recycling cqe.eth=%x, wqe=%x\n",
		    TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe),
		    TAVOR_CQE_WQEADDRSZ_GET(cqe));
		return (TAVOR_CQ_RECYCLE_ENTRY);
	}
}

/*
 * dapli_tavor_cq_notify()
 * This function is used for arming the CQ by ringing the CQ doorbell.
 */
static DAT_RETURN
dapli_tavor_cq_notify(ib_cq_handle_t cq, int flags, uint32_t param)
{
	uint32_t	cqnum;

	/*
	 * Determine if we are trying to get the next completion or the next
	 * "solicited" completion.  Then hit the appropriate doorbell.
	 */
	cqnum = cq->cq_num;
	if (flags == IB_NOTIFY_ON_NEXT_COMP) {
		dapli_tavor_cq_doorbell(cq->cq_iauar, TAVOR_CQDB_NOTIFY_CQ,
		    cqnum, TAVOR_CQDB_DEFAULT_PARAM);

	} else if (flags == IB_NOTIFY_ON_NEXT_SOLICITED) {
		dapli_tavor_cq_doorbell(cq->cq_iauar,
		    TAVOR_CQDB_NOTIFY_CQ_SOLICIT, cqnum,
		    TAVOR_CQDB_DEFAULT_PARAM);

	} else if (flags == IB_NOTIFY_ON_NEXT_NCOMP) {
		dapli_tavor_cq_doorbell(cq->cq_iauar, TAVOR_CQDB_NOTIFY_NCQ,
		    cqnum, param);
	} else {
		return (DAT_INVALID_PARAMETER);
	}

	return (DAT_SUCCESS);
}

/*
 * dapli_tavor_post_send()
 */
static DAT_RETURN
dapli_tavor_post_send(DAPL_EP *ep, ibt_send_wr_t *wr, boolean_t ns)
{
	tavor_sw_wqe_dbinfo_t		dbinfo;
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	dapls_tavor_wrid_entry_t	*wre_last;
	uint32_t			desc;
	uint64_t			*wqe_addr;
	uint32_t			desc_sz;
	uint32_t			wqeaddrsz, signaled_dbd;
	uint32_t			head, tail, next_tail, qsize_msk;
	int				status;
	ib_qp_handle_t			qp;

	if ((ep->qp_state == IBT_STATE_RESET) ||
	    (ep->qp_state == IBT_STATE_INIT) ||
	    (ep->qp_state == IBT_STATE_RTR)) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "post_send: invalid qp_state %d\n", ep->qp_state);
		return (DAT_INVALID_STATE);
	}

	qp = ep->qp_handle;

	/* Grab the lock for the WRID list */
	dapl_os_lock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);
	wridlist  = qp->qp_sq_wqhdr->wq_wrid_post;

	/* Save away some initial QP state */
	qsize_msk = qp->qp_sq_wqhdr->wq_size - 1;
	tail	  = qp->qp_sq_wqhdr->wq_tail;
	head	  = qp->qp_sq_wqhdr->wq_head;

	/*
	 * Check for "queue full" condition.  If the queue is already full,
	 * then no more WQEs can be posted, return an error
	 */
	if (qp->qp_sq_wqhdr->wq_full != 0) {
		dapl_os_unlock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	/*
	 * Increment the "tail index" and check for "queue full" condition.
	 * If we detect that the current work request is going to fill the
	 * work queue, then we mark this condition and continue.
	 */
	next_tail = (tail + 1) & qsize_msk;
	if (next_tail == head) {
		qp->qp_sq_wqhdr->wq_full = 1;
	}

	/*
	 * Get the user virtual address of the location where the next
	 * Send WQE should be built
	 */
	wqe_addr = TAVOR_QP_SQ_ENTRY(qp, tail);

	/*
	 * Call tavor_wqe_send_build() to build the WQE at the given address.
	 * This routine uses the information in the ibt_send_wr_t and
	 * returns the size of the WQE when it returns.
	 */
	status = dapli_tavor_wqe_send_build(qp, wr, wqe_addr, &desc_sz);
	if (status != DAT_SUCCESS) {
		dapl_os_unlock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);
		return (status);
	}

	/*
	 * Get the descriptor (io address) corresponding to the location
	 * Send WQE was built.
	 */
	desc = TAVOR_QP_SQ_DESC(qp, tail);

	dapl_os_assert(desc >= qp->qp_sq_desc_addr &&
	    desc <= (qp->qp_sq_desc_addr +
	    qp->qp_sq_numwqe*qp->qp_sq_wqesz));

	/*
	 * Add a WRID entry to the WRID list.  Need to calculate the
	 * "wqeaddrsz" and "signaled_dbd" values to pass to
	 * dapli_tavor_wrid_add_entry()
	 */
	wqeaddrsz = TAVOR_QP_WQEADDRSZ(desc, desc_sz);

	if (wr->wr_flags & IBT_WR_SEND_SIGNAL) {
		signaled_dbd = TAVOR_WRID_ENTRY_SIGNALED;
	}

	dapli_tavor_wrid_add_entry(qp->qp_sq_wqhdr, wr->wr_id, wqeaddrsz,
	    signaled_dbd);

	/*
	 * Now link the wqe to the old chain (if there was one)
	 */
	dapli_tavor_wqe_send_linknext(wr, wqe_addr, ns, desc, desc_sz,
	    qp->qp_sq_lastwqeaddr, &dbinfo);

	/*
	 * Now if the WRID tail entry is non-NULL, then this
	 * represents the entry to which we are chaining the
	 * new entries.  Since we are going to ring the
	 * doorbell for this WQE, we want set its "dbd" bit.
	 *
	 * On the other hand, if the tail is NULL, even though
	 * we will have rung the doorbell for the previous WQE
	 * (for the hardware's sake) it is irrelevant to our
	 * purposes (for tracking WRIDs) because we know the
	 * request must have already completed.
	 */
	wre_last = wridlist->wl_wre_old_tail;
	if (wre_last != NULL) {
		wre_last->wr_signaled_dbd |= TAVOR_WRID_ENTRY_DOORBELLED;
	}

	/* Update some of the state in the QP */
	qp->qp_sq_lastwqeaddr	 = wqe_addr;
	qp->qp_sq_wqhdr->wq_tail = next_tail;

	/* Ring the doorbell */
	dapli_tavor_qp_send_doorbell(qp->qp_iauar, desc, desc_sz,
	    qp->qp_num, dbinfo.db_fence, dbinfo.db_nopcode);

	dapl_os_unlock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_tavor_post_recv()
 */
static DAT_RETURN
dapli_tavor_post_recv(DAPL_EP	*ep, ibt_recv_wr_t *wr, boolean_t ns)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	dapls_tavor_wrid_entry_t	*wre_last;
	ib_qp_handle_t			qp;
	DAT_RETURN			status;
	uint32_t			desc;
	uint64_t			*wqe_addr;
	uint32_t			desc_sz;
	uint32_t			wqeaddrsz;
	uint32_t			head, tail, next_tail, qsize_msk;

	if (ep->qp_state == IBT_STATE_RESET) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "post_recv: invalid qp_state %d\n", ep->qp_state);
		return (DAT_INVALID_STATE);
	}
	qp = ep->qp_handle;

	/* Grab the lock for the WRID list */
	dapl_os_lock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);
	wridlist  = qp->qp_rq_wqhdr->wq_wrid_post;

	/* Save away some initial QP state */
	qsize_msk = qp->qp_rq_wqhdr->wq_size - 1;
	tail	  = qp->qp_rq_wqhdr->wq_tail;
	head	  = qp->qp_rq_wqhdr->wq_head;

	/*
	 * For the ibt_recv_wr_t passed in, parse the request and build a
	 * Recv WQE. Link the WQE with the previous WQE and ring the
	 * door bell.
	 */

	/*
	 * Check for "queue full" condition.  If the queue is already full,
	 * then no more WQEs can be posted. So return an error.
	 */
	if (qp->qp_rq_wqhdr->wq_full != 0) {
		dapl_os_unlock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	/*
	 * Increment the "tail index" and check for "queue
	 * full" condition.  If we detect that the current
	 * work request is going to fill the work queue, then
	 * we mark this condition and continue.
	 */
	next_tail = (tail + 1) & qsize_msk;
	if (next_tail == head) {
		qp->qp_rq_wqhdr->wq_full = 1;
	}

	/* Get the descriptor (IO Address) of the WQE to be built */
	desc = TAVOR_QP_RQ_DESC(qp, tail);
	/* The user virtual address of the WQE to be built */
	wqe_addr = TAVOR_QP_RQ_ENTRY(qp, tail);

	/*
	 * Call tavor_wqe_recv_build() to build the WQE at the given
	 * address. This routine uses the information in the
	 * ibt_recv_wr_t and returns the size of the WQE.
	 */
	status = dapli_tavor_wqe_recv_build(qp, wr, wqe_addr, &desc_sz);
	if (status != DAT_SUCCESS) {
		dapl_os_unlock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);
		return (DAT_INTERNAL_ERROR);
	}

	/*
	 * Add a WRID entry to the WRID list.  Need to calculate the
	 * "wqeaddrsz" and "signaled_dbd" values to pass to
	 * dapli_tavor_wrid_add_entry().
	 * Note: all Recv WQEs are essentially "signaled"
	 */
	wqeaddrsz = TAVOR_QP_WQEADDRSZ(desc, desc_sz);
	dapli_tavor_wrid_add_entry(qp->qp_rq_wqhdr, wr->wr_id, wqeaddrsz,
	    (uint32_t)TAVOR_WRID_ENTRY_SIGNALED);

	/*
	 * Now link the chain to the old chain (if there was one)
	 * and ring the doorbel for the recv work queue.
	 */
	dapli_tavor_wqe_recv_linknext(wqe_addr, ns, desc, desc_sz,
	    qp->qp_rq_lastwqeaddr);

	/*
	 * Now if the WRID tail entry is non-NULL, then this
	 * represents the entry to which we are chaining the
	 * new entries.  Since we are going to ring the
	 * doorbell for this WQE, we want set its "dbd" bit.
	 *
	 * On the other hand, if the tail is NULL, even though
	 * we will have rung the doorbell for the previous WQE
	 * (for the hardware's sake) it is irrelevant to our
	 * purposes (for tracking WRIDs) because we know the
	 * request must have already completed.
	 */
	wre_last = wridlist->wl_wre_old_tail;
	if (wre_last != NULL) {
		wre_last->wr_signaled_dbd |= TAVOR_WRID_ENTRY_DOORBELLED;
	}

	/* Update some of the state in the QP */
	qp->qp_rq_lastwqeaddr	 = wqe_addr;
	qp->qp_rq_wqhdr->wq_tail = next_tail;

	/* Ring the doorbell */
	dapli_tavor_qp_recv_doorbell(qp->qp_iauar, desc, desc_sz,
	    qp->qp_num, 1);

	dapl_os_unlock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_tavor_post_srq()
 */
static DAT_RETURN
dapli_tavor_post_srq(DAPL_SRQ *srqp, ibt_recv_wr_t *wr, boolean_t ns)
{
	ib_srq_handle_t			srq;
	DAT_RETURN			status;
	uint32_t			desc;
	uint64_t			*wqe_addr;
	uint64_t			*last_wqe_addr;
	uint32_t			head, next_head, qsize_msk;
	uint32_t			wqe_index;


	srq = srqp->srq_handle;

	/* Grab the lock for the WRID list */
	dapl_os_lock(&srq->srq_wridlist->wl_lock->wrl_lock);

	/*
	 * For the ibt_recv_wr_t passed in, parse the request and build a
	 * Recv WQE. Link the WQE with the previous WQE and ring the
	 * door bell.
	 */

	/*
	 * Check for "queue full" condition.  If the queue is already full,
	 * ie. there are no free entries, then no more WQEs can be posted.
	 * So return an error.
	 */
	if (srq->srq_wridlist->wl_freel_entries == 0) {
		dapl_os_unlock(&srq->srq_wridlist->wl_lock->wrl_lock);
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	/* Save away some initial SRQ state */
	qsize_msk = srq->srq_wridlist->wl_size - 1;
	head	  = srq->srq_wridlist->wl_freel_head;

	next_head = (head + 1) & qsize_msk;

	/* Get the descriptor (IO Address) of the WQE to be built */
	desc = srq->srq_wridlist->wl_free_list[head];

	wqe_index = TAVOR_SRQ_WQ_INDEX(srq->srq_wq_desc_addr, desc,
	    srq->srq_wq_wqesz);

	/* The user virtual address of the WQE to be built */
	wqe_addr = TAVOR_SRQ_WQ_ENTRY(srq, wqe_index);

	/*
	 * Call dapli_tavor_wqe_srq_build() to build the WQE at the given
	 * address. This routine uses the information in the
	 * ibt_recv_wr_t and returns the size of the WQE.
	 */
	status = dapli_tavor_wqe_srq_build(srq, wr, wqe_addr);
	if (status != DAT_SUCCESS) {
		dapl_os_unlock(&srq->srq_wridlist->wl_lock->wrl_lock);
		return (status);
	}

	/*
	 * Add a WRID entry to the WRID list.
	 */
	dapli_tavor_wrid_add_entry_srq(srq, wr->wr_id, wqe_index);

	if (srq->srq_wq_lastwqeindex == -1) {
		last_wqe_addr = NULL;
	} else {
		last_wqe_addr = TAVOR_SRQ_WQ_ENTRY(srq,
		    srq->srq_wq_lastwqeindex);
	}
	/*
	 * Now link the chain to the old chain (if there was one)
	 * and ring the doorbell for the SRQ.
	 */
	dapli_tavor_wqe_srq_linknext(wqe_addr, ns, desc, last_wqe_addr);

	/* Update some of the state in the SRQ */
	srq->srq_wq_lastwqeindex	 = wqe_index;
	srq->srq_wridlist->wl_freel_head = next_head;
	srq->srq_wridlist->wl_freel_entries--;
	dapl_os_assert(srq->srq_wridlist->wl_freel_entries <=
	    srq->srq_wridlist->wl_size);

	/* Ring the doorbell - for SRQ nds = 0 */
	dapli_tavor_qp_recv_doorbell(srq->srq_iauar, desc, 0,
	    srq->srq_num, 1);

	dapl_os_unlock(&srq->srq_wridlist->wl_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_tavor_wrid_add_entry()
 */
extern void
dapli_tavor_wrid_add_entry(dapls_tavor_workq_hdr_t *wq, uint64_t wrid,
    uint32_t wqeaddrsz, uint_t signaled_dbd)
{
	dapls_tavor_wrid_entry_t	*wre_tmp;
	uint32_t			head, tail, size;

	/*
	 * Find the entry in the container pointed to by the "tail" index.
	 * Add all of the relevant information to that entry, including WRID,
	 * "wqeaddrsz" parameter, and whether it was signaled/unsignaled
	 * and/or doorbelled.
	 */
	head = wq->wq_wrid_post->wl_head;
	tail = wq->wq_wrid_post->wl_tail;
	size = wq->wq_wrid_post->wl_size;
	wre_tmp = &wq->wq_wrid_post->wl_wre[tail];
	wre_tmp->wr_wrid	  = wrid;
	wre_tmp->wr_wqeaddrsz	  = wqeaddrsz;
	wre_tmp->wr_signaled_dbd  = signaled_dbd;

	/*
	 * Update the "wrid_old_tail" pointer to point to the entry we just
	 * inserted into the queue.  By tracking this pointer (the pointer to
	 * the most recently inserted entry) it will possible later in the
	 * PostSend() and PostRecv() code paths to find the entry that needs
	 * its "doorbelled" flag set (see comment in tavor_post_recv() and/or
	 * tavor_post_send()).
	 */
	wq->wq_wrid_post->wl_wre_old_tail = wre_tmp;

	/* Update the tail index */
	tail = ((tail + 1) & (size - 1));
	wq->wq_wrid_post->wl_tail = tail;

	/*
	 * If the "tail" index has just wrapped over into the "head" index,
	 * then we have filled the container.  We use the "full" flag to
	 * indicate this condition and to distinguish it from the "empty"
	 * condition (where head and tail are also equal).
	 */
	if (head == tail) {
		wq->wq_wrid_post->wl_full = 1;
	}
}

/*
 * dapli_tavor_wrid_add_entry_srq()
 */
extern void
dapli_tavor_wrid_add_entry_srq(ib_srq_handle_t srq, uint64_t wrid,
    uint32_t wqe_index)
{
	dapls_tavor_wrid_entry_t	*wre;

	/* ASSERT on impossible wqe_index values */
	dapl_os_assert(wqe_index < srq->srq_wq_numwqe);

	/*
	 * Setup the WRE.
	 *
	 * Given the 'wqe_index' value, we store the WRID at this WRE offset.
	 * And we set the WRE to be signaled_dbd so that on poll CQ we can find
	 * this information and associate the WRID to the WQE found on the CQE.
	 * Note: all Recv WQEs are essentially "signaled"
	 */
	wre = &srq->srq_wridlist->wl_wre[wqe_index];
	wre->wr_wrid = wrid;
	wre->wr_signaled_dbd = (uint32_t)TAVOR_WRID_ENTRY_SIGNALED;
}

/*
 * dapli_tavor_cq_srq_entries_flush()
 */
static void
dapli_tavor_cq_srq_entries_flush(ib_qp_handle_t qp)
{
	ib_cq_handle_t		cq;
	dapls_tavor_workq_hdr_t	*wqhdr;
	tavor_hw_cqe_t		*cqe;
	tavor_hw_cqe_t		*next_cqe;
	uint32_t		cons_indx, tail_cons_indx, wrap_around_mask;
	uint32_t		new_indx, check_indx, indx;
	uint32_t		num_to_increment;
	int			cqe_qpnum, cqe_type;
	int			outstanding_cqes, removed_cqes;
	int			i;

	/* ASSERT(MUTEX_HELD(&qp->qp_rq_cqhdl->cq_lock)); */

	cq = qp->qp_rq_cqhdl;
	wqhdr = qp->qp_rq_wqhdr;

	dapl_os_assert(wqhdr->wq_wrid_post != NULL);
	dapl_os_assert(wqhdr->wq_wrid_post->wl_srq_en != 0);

	/* Get the consumer index */
	cons_indx = cq->cq_consindx;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor completion queues have power-of-2 sizes
	 */
	wrap_around_mask = (cq->cq_size - 1);

	/* Calculate the pointer to the first CQ entry */
	cqe = &cq->cq_addr[cons_indx];

	/*
	 * Loop through the CQ looking for entries owned by software.  If an
	 * entry is owned by software then we increment an 'outstanding_cqes'
	 * count to know how many entries total we have on our CQ.  We use this
	 * value further down to know how many entries to loop through looking
	 * for our same QP number.
	 */
	outstanding_cqes = 0;
	tail_cons_indx = cons_indx;
	while (TAVOR_CQE_OWNER_IS_SW(cqe)) {
		/* increment total cqes count */
		outstanding_cqes++;

		/* increment the consumer index */
		tail_cons_indx = (tail_cons_indx + 1) & wrap_around_mask;

		/* update the pointer to the next cq entry */
		cqe = &cq->cq_addr[tail_cons_indx];
	}

	/*
	 * Using the 'tail_cons_indx' that was just set, we now know how many
	 * total CQEs possible there are.  Set the 'check_indx' and the
	 * 'new_indx' to the last entry identified by 'tail_cons_indx'
	 */
	check_indx = new_indx = (tail_cons_indx - 1) & wrap_around_mask;

	for (i = 0; i < outstanding_cqes; i++) {
		cqe = &cq->cq_addr[check_indx];

		/* Grab QP number from CQE */
		cqe_qpnum = TAVOR_CQE_QPNUM_GET(cqe);
		cqe_type = TAVOR_CQE_SENDRECV_GET(cqe);

		/*
		 * If the QP number is the same in the CQE as the QP that we
		 * have on this SRQ, then we must free up the entry off the
		 * SRQ.  We also make sure that the completion type is of the
		 * 'TAVOR_COMPLETION_RECV' type.  So any send completions on
		 * this CQ will be left as-is.  The handling of returning
		 * entries back to HW ownership happens further down.
		 */
		if (cqe_qpnum == qp->qp_num &&
		    cqe_type == TAVOR_COMPLETION_RECV) {
			/* Add back to SRQ free list */
			(void) dapli_tavor_wrid_find_match_srq(
			    wqhdr->wq_wrid_post, cqe);
		} else {
			/* Do Copy */
			if (check_indx != new_indx) {
				next_cqe = &cq->cq_addr[new_indx];
				/*
				 * Copy the CQE into the "next_cqe"
				 * pointer.
				 */
				(void) dapl_os_memcpy(next_cqe, cqe,
				    sizeof (tavor_hw_cqe_t));
			}
			new_indx = (new_indx - 1) & wrap_around_mask;
		}
		/* Move index to next CQE to check */
		check_indx = (check_indx - 1) & wrap_around_mask;
	}

	/* Initialize removed cqes count */
	removed_cqes = 0;

	/* If an entry was removed */
	if (check_indx != new_indx) {

		/*
		 * Set current pointer back to the beginning consumer index.
		 * At this point, all unclaimed entries have been copied to the
		 * index specified by 'new_indx'.  This 'new_indx' will be used
		 * as the new consumer index after we mark all freed entries as
		 * having HW ownership.  We do that here.
		 */

		/* Loop through all entries until we reach our new pointer */
		for (indx = cons_indx; indx <= new_indx;
		    indx = (indx + 1) & wrap_around_mask) {
			removed_cqes++;
			cqe = &cq->cq_addr[indx];

			/* Reset entry to hardware ownership */
			TAVOR_CQE_OWNER_SET_HW(cqe);
		}
	}

	/*
	 * Update consumer index to be the 'new_indx'.  This moves it past all
	 * removed entries.  Because 'new_indx' is pointing to the last
	 * previously valid SW owned entry, we add 1 to point the cons_indx to
	 * the first HW owned entry.
	 */
	cons_indx = (new_indx + 1) & wrap_around_mask;

	/*
	 * Now we only ring the doorbell (to update the consumer index) if
	 * we've actually consumed a CQ entry.  If we found no QP number
	 * matches above, then we would not have removed anything.  So only if
	 * something was removed do we ring the doorbell.
	 */
	if ((removed_cqes != 0) && (cq->cq_consindx != cons_indx)) {
		/*
		 * Post doorbell to update the consumer index.  Doorbell
		 * value indicates number of entries consumed (minus 1)
		 */
		if (cons_indx > cq->cq_consindx) {
			num_to_increment = (cons_indx - cq->cq_consindx) - 1;
		} else {
			num_to_increment = ((cons_indx + cq->cq_size) -
			    cq->cq_consindx) - 1;
		}
		cq->cq_consindx = cons_indx;

		dapli_tavor_cq_doorbell(cq->cq_iauar, TAVOR_CQDB_INCR_CONSINDX,
		    cq->cq_num, num_to_increment);
	}
}

/* ARGSUSED */
static void
dapli_tavor_qp_init(ib_qp_handle_t qp)
{
}

/* ARGSUSED */
static void
dapli_tavor_cq_init(ib_cq_handle_t cq)
{
}

/* ARGSUSED */
static void
dapli_tavor_srq_init(ib_srq_handle_t srq)
{
}

void
dapls_init_funcs_tavor(DAPL_HCA *hca_ptr)
{
	hca_ptr->post_send = dapli_tavor_post_send;
	hca_ptr->post_recv = dapli_tavor_post_recv;
	hca_ptr->post_srq = dapli_tavor_post_srq;
	hca_ptr->cq_peek = dapli_tavor_cq_peek;
	hca_ptr->cq_poll = dapli_tavor_cq_poll;
	hca_ptr->cq_poll_one = dapli_tavor_cq_poll_one;
	hca_ptr->cq_notify = dapli_tavor_cq_notify;
	hca_ptr->srq_flush = dapli_tavor_cq_srq_entries_flush;
	hca_ptr->qp_init = dapli_tavor_qp_init;
	hca_ptr->cq_init = dapli_tavor_cq_init;
	hca_ptr->srq_init = dapli_tavor_srq_init;
	hca_ptr->hermon_resize_cq = 0;
}
