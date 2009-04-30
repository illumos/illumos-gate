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

#include "dapl.h"
#include "dapl_tavor_hw.h"
#include "dapl_tavor_wr.h"
#include "dapl_tavor_ibtf_impl.h"

#define	bt_debug	0

enum arbel_db_type_e {
	ARBEL_DBR_CQ_SET_CI	= 0x1 << 5,
	ARBEL_DBR_CQ_ARM	= 0x2 << 5,
	ARBEL_DBR_SQ		= 0x3 << 5,
	ARBEL_DBR_RQ		= 0x4 << 5,
	ARBEL_DBR_SRQ		= 0x5 << 5
};

#define	ARBEL_WQE_SGL_INVALID_LKEY	0x00000100
#define	ARBEL_WQE_SEND_SIGNALED_MASK	0x0000000800000000ull
#define	ARBEL_WQE_SEND_SOLICIT_MASK	0x0000000200000000ull
#define	ARBEL_WQE_CTRL_REQBIT_MASK	0x0000000100000000ull
#define	ARBEL_WQE_NEXT_REQBIT_MASK	0x80
#define	ARBEL_WQE_SETCTRL(qp, desc, ctrl) \
	((uint64_t *)(desc))[1] = HTOBE_64(ctrl)
#define	ARBEL_WQE_SETNEXT(qp, desc, nda_op, ee_nds) \
	{ \
		((uint32_t *)(desc))[0] = HTOBE_32(nda_op); \
		((uint32_t *)(desc))[1] = HTOBE_32(ee_nds); \
	}
#define	ARBEL_WQE_SEND_FENCE_MASK	0x40
#define	ARBEL_WQE_SEND_NOPCODE_RDMAW	0x8
#define	ARBEL_WQE_SEND_NOPCODE_SEND	0xA
#define	ARBEL_WQE_SEND_NOPCODE_RDMAR	0x10
#define	ARBEL_WQE_SEND_NOPCODE_BIND	0x18
#define	ARBEL_WQE_NDA_MASK		0x00000000FFFFFFC0ull
#define	ARBEL_WQE_NDS_MASK		0x3F
#define	ARBEL_QPSNDDB_WQE_CNT_SHIFT	0x38
#define	ARBEL_QPSNDDB_WQE_COUNTER_SHIFT	0x28
#define	ARBEL_QPSNDDB_F_SHIFT		0x25
#define	ARBEL_QPSNDDB_NOPCODE_SHIFT	0x20
#define	ARBEL_QPSNDDB_QPN_SHIFT		0x8
#define	ARBEL_DBR_QP_WQE_COUNTER_SHIFT	0x20
#define	ARBEL_DBR_QN_SHIFT		0x8

#define	ARBEL_CQDB_NOTIFY_CQ_SOLICIT	0x1
#define	ARBEL_CQDB_NOTIFY_CQ		0x2

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

static int dapli_arbel_wqe_send_build(ib_qp_handle_t, ibt_send_wr_t *,
    uint64_t *, uint_t *);
static DAT_RETURN dapli_arbel_wqe_recv_build(ib_qp_handle_t, ibt_recv_wr_t *,
    uint64_t *, uint_t *);
static int dapli_arbel_cq_cqe_consume(ib_cq_handle_t, tavor_hw_cqe_t *,
    ibt_wc_t *);
static int dapli_arbel_cq_errcqe_consume(ib_cq_handle_t, tavor_hw_cqe_t *,
    ibt_wc_t *);
extern void dapli_tavor_wrid_add_entry(dapls_tavor_workq_hdr_t *, uint64_t,
    uint32_t, uint_t);
extern void dapli_tavor_wrid_add_entry_srq(ib_srq_handle_t, uint64_t, uint32_t);

/*
 * Note: The 64 bit doorbells need to written atomically.
 * In 32 bit libraries we need to use the special assembly rtn
 * because compiler generated code splits into 2 word writes
 */

/*
 * dapli_arbel_cq_doorbell()
 * Takes the specified cq cmd and cq number and rings the cq doorbell
 */
static void
dapli_arbel_cq_doorbell(dapls_hw_uar_t ia_uar, uint32_t cq_cmd, uint32_t cqn,
    uint32_t cmd_sn, uint32_t cq_param)
{
	uint64_t doorbell;

	/* Build the doorbell from the parameters */
	doorbell = (cmd_sn << 4) | cq_cmd;
	doorbell = (doorbell << 24) | cqn;
	doorbell = (doorbell << 32) | cq_param;

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

/*
 * dapli_arbel_qp_send_doorbell()
 * Takes the specified next descriptor information, qp number, opcode and
 * rings the send doorbell
 */
static void
dapli_arbel_sq_dbrec(ib_qp_handle_t qp, uint16_t wqe_counter)
{
	qp->qp_sq_dbp[0] = HTOBE_32((wqe_counter + 1) & 0xffff);
}

static void
dapli_arbel_sq_dbreg(dapls_hw_uar_t ia_uar, uint32_t qpn, uint32_t fence,
    uint32_t nopcode, uint16_t wqe_counter, uint32_t nds)
{
	uint64_t doorbell;

	doorbell = ((uint64_t)1 << ARBEL_QPSNDDB_WQE_CNT_SHIFT) |
	    ((uint64_t)wqe_counter << ARBEL_QPSNDDB_WQE_COUNTER_SHIFT) |
	    ((uint64_t)fence << ARBEL_QPSNDDB_F_SHIFT) |
	    ((uint64_t)nopcode << ARBEL_QPSNDDB_NOPCODE_SHIFT) |
	    (qpn << ARBEL_QPSNDDB_QPN_SHIFT) | nds;

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

/*
 * dapli_arbel_wqe_send_build()
 * Constructs a WQE for a given ibt_send_wr_t
 */
static int
dapli_arbel_wqe_send_build(ib_qp_handle_t qp, ibt_send_wr_t *wr,
    uint64_t *addr, uint_t *size)
{
	tavor_hw_snd_wqe_remaddr_t	*rc;
	tavor_hw_snd_wqe_bind_t		*bn;
	tavor_hw_wqe_sgl_t		*ds;
	ibt_wr_ds_t			*sgl;
	uint32_t			nds;
	uint32_t			len, total_len;
	uint32_t			new_rkey;
	uint32_t			old_rkey;
	int				i, num_ds;
	int				max_inline_bytes = -1;
	uint64_t			ctrl;

	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;
	ctrl = ((wr->wr_flags & IBT_WR_SEND_SIGNAL) ?
	    ARBEL_WQE_SEND_SIGNALED_MASK : 0) |
	    ((wr->wr_flags & IBT_WR_SEND_SOLICIT) ?
	    ARBEL_WQE_SEND_SOLICIT_MASK : 0) |
	    ARBEL_WQE_CTRL_REQBIT_MASK;

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
#if 0
	/* XXX - need equiv of "arbel_wr_bind_check(state, wr);" */
	/* XXX - uses arbel_mr_keycalc - what about Sinai vs. Arbel??? */
#endif
		old_rkey = wr->wr.rc.rcwr.bind->bind_rkey;
		new_rkey = old_rkey >> 8;	/* index */
		old_rkey = ((old_rkey & 0xff) + 1) & 0xff; /* incremented key */
		new_rkey = (new_rkey << 8) | old_rkey;

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
		nds = 0;
		break;
	default:
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapli_arbel_wqe_send_build: invalid wr_opcode=%d\n",
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
	ARBEL_WQE_SETCTRL(qp, addr, ctrl);

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_wqe_send_linknext()
 * Takes a WQE and links it to the prev WQE chain
 */
static void
dapli_arbel_wqe_send_linknext(ibt_send_wr_t *curr_wr,
    uint32_t curr_desc, uint_t curr_descsz, uint64_t *prev_addr,
    tavor_sw_wqe_dbinfo_t *dbinfo)
{
	uint32_t	nopcode, fence, nda_op, ee_nds;

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
		nopcode = ARBEL_WQE_SEND_NOPCODE_RDMAW;
		break;

	case IBT_WRC_SEND:
		nopcode = ARBEL_WQE_SEND_NOPCODE_SEND;
		break;

	case IBT_WRC_RDMAR:
		nopcode = ARBEL_WQE_SEND_NOPCODE_RDMAR;
		break;

	case IBT_WRC_BIND:
		nopcode = ARBEL_WQE_SEND_NOPCODE_BIND;
		break;
	default:
		/* Unsupported opcodes in UDAPL */
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapli_arbel_wqe_send_linknext: invalid nopcode=%d\n",
		    nopcode);
		return;
	}

	fence = (curr_wr->wr_flags & IBT_WR_SEND_FENCE) ? 1 : 0;
	nda_op = ((uintptr_t)curr_desc & ARBEL_WQE_NDA_MASK) | nopcode;
	ee_nds = ((fence == 1) ? ARBEL_WQE_SEND_FENCE_MASK : 0) |
	    (curr_descsz & ARBEL_WQE_NDS_MASK) |
	    ARBEL_WQE_NEXT_REQBIT_MASK;

	/*
	 * A send queue doorbell will be rung for the next
	 * WQE on the chain, set the current WQE's "dbd" bit.
	 * Note: We also update the "dbinfo" structure here to pass
	 * back information about what should (later) be included
	 * in the send queue doorbell.
	 */
	dbinfo->db_nopcode = nopcode;
	dbinfo->db_fence   = fence;

	ARBEL_WQE_SETNEXT(qp, prev_addr, nda_op, ee_nds);
}


/*
 * dapli_arbel_wqe_recv_build()
 * Builds the recv WQE for a given ibt_recv_wr_t
 */
static DAT_RETURN
dapli_arbel_wqe_recv_build(ib_qp_handle_t qp, ibt_recv_wr_t *wr,
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
	if (i < qp->qp_rq_sgl) {
		ibt_wr_ds_t sgl;
		sgl.ds_va  = (ib_vaddr_t)0;
		sgl.ds_len = (ib_msglen_t)0;
		sgl.ds_key = (ibt_lkey_t)ARBEL_WQE_SGL_INVALID_LKEY;
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &sgl);
	}

	/* Return the size of descriptor (in 16-byte chunks) */
	*size = qp->qp_rq_wqesz >> 4;

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_wqe_srq_build()
 * Builds the recv WQE for a given ibt_recv_wr_t
 */
static DAT_RETURN
dapli_arbel_wqe_srq_build(ib_srq_handle_t srq, ibt_recv_wr_t *wr,
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
		end_sgl.ds_key = (ibt_lkey_t)ARBEL_WQE_SGL_INVALID_LKEY;
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &end_sgl);
	}

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_cq_peek()
 * Peeks into a given CQ to check if there are any events that can be
 * polled. It returns the number of CQEs that can be polled.
 */
static void
dapli_arbel_cq_peek(ib_cq_handle_t cq, int *num_cqe)
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

#define	dapli_arbel_cq_update_ci(cq, dbp) \
	(dbp)[0] = HTOBE_32(cq->cq_consindx)

/*
 * dapli_arbel_cq_poll()
 * This routine polls CQEs out of a CQ and puts them into the ibt_wc_t
 * array that is passed in.
 */
static DAT_RETURN
dapli_arbel_cq_poll(ib_cq_handle_t cq, ibt_wc_t *wc_p, uint_t num_wc,
    uint_t *num_polled)
{
	tavor_hw_cqe_t		*cqe;
	uint32_t		cons_indx;
	uint32_t		wrap_around_mask;
	uint32_t		polled_cnt;
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
	 * each entry by calling dapli_arbel_cq_cqe_consume() and updating the
	 * CQ consumer index.  Note:  We only update the consumer index if
	 * dapli_arbel_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.
	 * Otherwise, it indicates that we are going to "recycle" the CQE
	 * (probably because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	polled_cnt = 0;
	while (TAVOR_CQE_OWNER_IS_SW(cqe)) {
		status = dapli_arbel_cq_cqe_consume(cq, cqe,
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
		 * Update the consumer index in both the CQ handle and the
		 * doorbell record.
		 */
		cq->cq_consindx = cons_indx;
		dapli_arbel_cq_update_ci(cq, cq->cq_poll_dbp);
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
 * dapli_arbel_cq_poll_one()
 * This routine polls one CQE out of a CQ and puts ot into the ibt_wc_t
 * that is passed in.  See above for more comments/details.
 */
static DAT_RETURN
dapli_arbel_cq_poll_one(ib_cq_handle_t cq, ibt_wc_t *wc_p)
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
	 * each entry by calling dapli_arbel_cq_cqe_consume() and updating the
	 * CQ consumer index.  Note:  We only update the consumer index if
	 * dapli_arbel_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.
	 * Otherwise, it indicates that we are going to "recycle" the CQE
	 * (probably because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	if (TAVOR_CQE_OWNER_IS_SW(cqe)) {
		status = dapli_arbel_cq_cqe_consume(cq, cqe, wc_p);
		if (status == TAVOR_CQ_SYNC_AND_DB) {
			/* Reset entry to hardware ownership */
			TAVOR_CQE_OWNER_SET_HW(cqe);

			/* Increment the consumer index */
			cq->cq_consindx =
			    (cons_indx + 1) & (cq->cq_size - 1);
			dapli_arbel_cq_update_ci(cq, cq->cq_poll_dbp);
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
 * dapli_arbel_cq_cqe_consume()
 * Converts a given CQE into a ibt_wc_t object
 */
static int
dapli_arbel_cq_cqe_consume(ib_cq_handle_t cqhdl, tavor_hw_cqe_t *cqe,
    ibt_wc_t *wc)
{
	uint_t		flags;
	uint_t		type;
	uint_t		opcode;
	int		status;

	/* strip off the size in wqeaddrsz */
	TAVOR_CQE_WQEADDRSZ_SET(cqe, TAVOR_CQE_WQEADDRSZ_GET(cqe) &
	    ~ARBEL_WQE_NDS_MASK);

	/*
	 * Determine if this is an "error" CQE by examining "opcode".  If it
	 * is an error CQE, then call dapli_arbel_cq_errcqe_consume() and return
	 * whatever status it returns.  Otherwise, this is a successful
	 * completion.
	 */
	opcode = TAVOR_CQE_OPCODE_GET(cqe);
	if ((opcode == TAVOR_CQE_SEND_ERR_OPCODE) ||
	    (opcode == TAVOR_CQE_RECV_ERR_OPCODE)) {
		status = dapli_arbel_cq_errcqe_consume(cqhdl, cqe, wc);
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
 * dapli_arbel_cq_errcqe_consume()
 */
static int
dapli_arbel_cq_errcqe_consume(ib_cq_handle_t cqhdl, tavor_hw_cqe_t *cqe,
    ibt_wc_t *wc)
{
	dapls_tavor_wrid_entry_t	wre;
	uint32_t		imm_eth_pkey_cred;
	uint_t			status;
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
	 * Consume the CQE
	 *    Return status to indicate that doorbell and sync may be
	 *    necessary.
	 */
	return (TAVOR_CQ_SYNC_AND_DB);
}

/*
 * dapli_arbel_cq_notify()
 * This function is used for arming the CQ by ringing the CQ doorbell.
 *
 * Note: there is something very subtle here.  This code assumes a very
 * specific behavior of the kernel driver.  The cmd_sn field of the
 * arm_dbr is updated by the kernel driver whenever a notification
 * event for the cq is received.  This code extracts the cmd_sn field
 * from the arm_dbr to know the right value to use.  The arm_dbr is
 * always updated atomically so that neither the kernel driver nor this
 * will get confused about what the other is doing.
 *
 * Note: param is not used here.  It is necessary for arming a CQ for
 * N completions (param is N), but no uDAPL API supports this for now.
 * Thus, we declare ARGSUSED to make lint happy.
 */
/*ARGSUSED*/
static DAT_RETURN
dapli_arbel_cq_notify(ib_cq_handle_t cq, int flags, uint32_t param)
{
	uint32_t	cqnum;
	uint32_t	*target;
	uint32_t	old_cmd, cmp, new, tmp, cmd_sn;

	/*
	 * Determine if we are trying to get the next completion or the next
	 * "solicited" completion.  Then hit the appropriate doorbell.
	 */
	dapli_arbel_cq_update_ci(cq, cq->cq_arm_dbp);
	cqnum = cq->cq_num;
	target = cq->cq_arm_dbp + 1;
retry:
	cmp = *target;
	tmp = HTOBE_32(cmp);
	old_cmd = tmp & 0x7;
	cmd_sn = (tmp & 0x18) >> 3;

	if (flags == IB_NOTIFY_ON_NEXT_COMP) {
		if (old_cmd != ARBEL_CQDB_NOTIFY_CQ) {
			new = HTOBE_32((tmp & ~0x7) | ARBEL_CQDB_NOTIFY_CQ);
			tmp = atomic_cas_32(target, cmp, new);
			if (tmp != cmp)
				goto retry;
			dapli_arbel_cq_doorbell(cq->cq_iauar,
			    ARBEL_CQDB_NOTIFY_CQ, cqnum,
			    cmd_sn, cq->cq_consindx);
		} /* else it's already armed */
	} else if (flags == IB_NOTIFY_ON_NEXT_SOLICITED) {
		if (old_cmd != ARBEL_CQDB_NOTIFY_CQ &&
		    old_cmd != ARBEL_CQDB_NOTIFY_CQ_SOLICIT) {
			new = HTOBE_32((tmp & ~0x7) |
			    ARBEL_CQDB_NOTIFY_CQ_SOLICIT);
			tmp = atomic_cas_32(target, cmp, new);
			if (tmp != cmp)
				goto retry;
			dapli_arbel_cq_doorbell(cq->cq_iauar,
			    ARBEL_CQDB_NOTIFY_CQ_SOLICIT, cqnum,
			    cmd_sn, cq->cq_consindx);
		} /* else it's already armed */
	} else {
		return (DAT_INVALID_PARAMETER);
	}

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_post_send()
 */
/* ARGSUSED */
static DAT_RETURN
dapli_arbel_post_send(DAPL_EP *ep, ibt_send_wr_t *wr, boolean_t ns)
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
	status = dapli_arbel_wqe_send_build(qp, wr, wqe_addr, &desc_sz);
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
	 * "wqeaddr" to pass to dapli_tavor_wrid_add_entry().
	 * signaled_dbd is still calculated, but ignored.
	 */
	wqeaddrsz = TAVOR_QP_WQEADDRSZ(desc, 0);

	if (wr->wr_flags & IBT_WR_SEND_SIGNAL) {
		signaled_dbd = TAVOR_WRID_ENTRY_SIGNALED;
	}

	dapli_tavor_wrid_add_entry(qp->qp_sq_wqhdr, wr->wr_id, wqeaddrsz,
	    signaled_dbd);

	/*
	 * Now link the wqe to the old chain (if there was one)
	 */
	dapli_arbel_wqe_send_linknext(wr, desc, desc_sz,
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

	/* Set the doorbell decord */
	dapli_arbel_sq_dbrec(qp, qp->qp_sq_counter);

	/* Ring the doorbell */
	dapli_arbel_sq_dbreg(qp->qp_iauar, qp->qp_num, dbinfo.db_fence,
	    dbinfo.db_nopcode, qp->qp_sq_counter, desc_sz);
	qp->qp_sq_counter++;

	dapl_os_unlock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_post_recv()
 */
/* ARGSUSED */
static DAT_RETURN
dapli_arbel_post_recv(DAPL_EP	*ep, ibt_recv_wr_t *wr, boolean_t ns)
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
	status = dapli_arbel_wqe_recv_build(qp, wr, wqe_addr, &desc_sz);
	if (status != DAT_SUCCESS) {
		dapl_os_unlock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);
		return (DAT_INTERNAL_ERROR);
	}

	/*
	 * Add a WRID entry to the WRID list.  Need to calculate the
	 * "wqeaddr" and "signaled_dbd" values to pass to
	 * dapli_tavor_wrid_add_entry().
	 * Note: all Recv WQEs are essentially "signaled"
	 */
	wqeaddrsz = TAVOR_QP_WQEADDRSZ(desc, 0);
	dapli_tavor_wrid_add_entry(qp->qp_rq_wqhdr, wr->wr_id, wqeaddrsz,
	    (uint32_t)TAVOR_WRID_ENTRY_SIGNALED);

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

	/* Update the doorbell record */
	qp->qp_rq_counter++;
	(qp->qp_rq_dbp)[0] = HTOBE_32(qp->qp_rq_counter);

	dapl_os_unlock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_post_srq()
 */
/* ARGSUSED */
static DAT_RETURN
dapli_arbel_post_srq(DAPL_SRQ *srqp, ibt_recv_wr_t *wr, boolean_t ns)
{
	ib_srq_handle_t			srq;
	DAT_RETURN			status;
	uint32_t			desc;
	uint64_t			*wqe_addr;
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
	 * Call dapli_arbel_wqe_srq_build() to build the WQE at the given
	 * address. This routine uses the information in the
	 * ibt_recv_wr_t and returns the size of the WQE.
	 */
	status = dapli_arbel_wqe_srq_build(srq, wr, wqe_addr);
	if (status != DAT_SUCCESS) {
		dapl_os_unlock(&srq->srq_wridlist->wl_lock->wrl_lock);
		return (status);
	}

	/*
	 * Add a WRID entry to the WRID list.
	 */
	dapli_tavor_wrid_add_entry_srq(srq, wr->wr_id, wqe_index);

#if 0
	if (srq->srq_wq_lastwqeindex == -1) {
		last_wqe_addr = NULL;
	} else {
		last_wqe_addr = TAVOR_SRQ_WQ_ENTRY(srq,
		    srq->srq_wq_lastwqeindex);
	}
	/*
	 * Now link the chain to the old chain (if there was one)
	 * and update the wqe_counter in the doorbell record.
	 */
XXX
	dapli_tavor_wqe_srq_linknext(wqe_addr, ns, desc, last_wqe_addr);
#endif

	/* Update some of the state in the SRQ */
	srq->srq_wq_lastwqeindex	 = wqe_index;
	srq->srq_wridlist->wl_freel_head = next_head;
	srq->srq_wridlist->wl_freel_entries--;
	dapl_os_assert(srq->srq_wridlist->wl_freel_entries <=
	    srq->srq_wridlist->wl_size);

	/* Update the doorbell record */
	srq->srq_counter++;
	(srq->srq_dbp)[0] = HTOBE_32(srq->srq_counter);

	dapl_os_unlock(&srq->srq_wridlist->wl_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_arbel_cq_srq_entries_flush()
 */
static void
dapli_arbel_cq_srq_entries_flush(ib_qp_handle_t qp)
{
	ib_cq_handle_t		cq;
	dapls_tavor_workq_hdr_t	*wqhdr;
	tavor_hw_cqe_t		*cqe;
	tavor_hw_cqe_t		*next_cqe;
	uint32_t		cons_indx, tail_cons_indx, wrap_around_mask;
	uint32_t		new_indx, check_indx, indx;
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
		 * Update the consumer index in both the CQ handle and the
		 * doorbell record.
		 */
		cq->cq_consindx = cons_indx;
		dapli_arbel_cq_update_ci(cq, cq->cq_poll_dbp);
	}
}

static void
dapli_arbel_rq_prelink(caddr_t first, uint32_t desc_off, uint32_t wqesz,
    uint32_t numwqe, uint32_t nds)
{
	int i;
	uint32_t *p = (uint32_t *)(uintptr_t)first;
	uint32_t off = desc_off;
	uint32_t pincr = wqesz / sizeof (uint32_t);
	ibt_wr_ds_t sgl;

	sgl.ds_va = (ib_vaddr_t)0;
	sgl.ds_key = ARBEL_WQE_SGL_INVALID_LKEY;
	sgl.ds_len = (ib_msglen_t)0;

	for (i = 0; i < numwqe - 1; i++, p += pincr) {
		off += wqesz;
		p[0] = HTOBE_32(off);	/* link curr to next */
		p[1] = nds;		/* nds is 0 for SRQ */
		TAVOR_WQE_BUILD_DATA_SEG((void *)&p[2], &sgl);
	}
	p[0] = HTOBE_32(desc_off); /* link last to first */
	p[1] = nds;
	TAVOR_WQE_BUILD_DATA_SEG((void *)&p[2], &sgl);
}

static void
dapli_arbel_sq_prelink(caddr_t first, uint32_t desc_off, uint32_t wqesz,
    uint32_t numwqe)
{
	int i;
	uint32_t *p = (uint32_t *)(uintptr_t)first;
	uint32_t off = desc_off;
	uint32_t pincr = wqesz / sizeof (uint32_t);

	for (i = 0; i < numwqe - 1; i++, p += pincr) {
		off += wqesz;
		p[0] = HTOBE_32(off);	/* link curr to next */
	}
	p[0] = HTOBE_32(desc_off); /* link last to first */
}

static void
dapli_arbel_qp_init(ib_qp_handle_t qp)
{
	(qp->qp_sq_dbp)[1] = HTOBE_32((qp->qp_num << 8) | ARBEL_DBR_SQ);
	if (qp->qp_srq_enabled == 0) {
		(qp->qp_rq_dbp)[1] = HTOBE_32((qp->qp_num << 8) | ARBEL_DBR_RQ);

		/* pre-link the whole receive queue */
		dapli_arbel_rq_prelink(qp->qp_rq_buf, qp->qp_rq_desc_addr,
		    qp->qp_rq_wqesz, qp->qp_rq_numwqe,
		    HTOBE_32(qp->qp_rq_wqesz >> 4));
	}
	dapli_arbel_sq_prelink(qp->qp_sq_buf, qp->qp_sq_desc_addr,
	    qp->qp_sq_wqesz, qp->qp_sq_numwqe);
	qp->qp_sq_lastwqeaddr = (uint64_t *)((uintptr_t)qp->qp_sq_buf +
	    ((qp->qp_sq_numwqe - 1) * qp->qp_sq_wqesz));
	qp->qp_rq_counter = 0;
	qp->qp_sq_counter = 0;
}

static void
dapli_arbel_cq_init(ib_cq_handle_t cq)
{
	(cq->cq_poll_dbp)[1] =
	    HTOBE_32((cq->cq_num << 8) | ARBEL_DBR_CQ_SET_CI);
	(cq->cq_arm_dbp)[1] =
	    HTOBE_32((cq->cq_num << 8) | ARBEL_DBR_CQ_ARM | 0x8);
	/* cq_resize -- needs testing */
}

static void
dapli_arbel_srq_init(ib_srq_handle_t srq)
{
	(srq->srq_dbp)[1] =
	    HTOBE_32((srq->srq_num << 8) | ARBEL_DBR_SRQ);

	/* pre-link the whole shared receive queue */
	dapli_arbel_rq_prelink(srq->srq_addr, srq->srq_wq_desc_addr,
	    srq->srq_wq_wqesz, srq->srq_wq_numwqe, 0);
	srq->srq_counter = 0;

	/* needs testing */
}

void
dapls_init_funcs_arbel(DAPL_HCA *hca_ptr)
{
	hca_ptr->post_send = dapli_arbel_post_send;
	hca_ptr->post_recv = dapli_arbel_post_recv;
	hca_ptr->post_srq = dapli_arbel_post_srq;
	hca_ptr->cq_peek = dapli_arbel_cq_peek;
	hca_ptr->cq_poll = dapli_arbel_cq_poll;
	hca_ptr->cq_poll_one = dapli_arbel_cq_poll_one;
	hca_ptr->cq_notify = dapli_arbel_cq_notify;
	hca_ptr->srq_flush = dapli_arbel_cq_srq_entries_flush;
	hca_ptr->qp_init = dapli_arbel_qp_init;
	hca_ptr->cq_init = dapli_arbel_cq_init;
	hca_ptr->srq_init = dapli_arbel_srq_init;
	hca_ptr->hermon_resize_cq = 0;
}
