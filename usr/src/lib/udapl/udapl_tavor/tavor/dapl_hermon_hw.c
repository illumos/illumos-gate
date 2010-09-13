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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dapl.h"
#include "dapl_tavor_hw.h"
#include "dapl_tavor_wr.h"
#include "dapl_tavor_ibtf_impl.h"

#define	HERMON_WQE_SGL_INVALID_LKEY	0x00000100
#define	HERMON_WQE_SEND_FENCE_MASK	0x40
#define	HERMON_WQE_NDS_MASK		0x3F

#define	HERMON_CQDB_NOTIFY_CQ_SOLICIT	(0x1 << 24)
#define	HERMON_CQDB_NOTIFY_CQ		(0x2 << 24)

#define	HERMON_CQE_RCV_SEND		0x1
#define	HERMON_CQE_ERR_OPCODE		0x1E
#define	HERMON_CQE_RESIZE_OPCODE	0x16
#define	HERMON_CQE_OPCODE_GET(cqe)	(((uint8_t *)cqe)[31] & 0x1F)
#define	HERMON_CQE_SENDRECV_GET(cqe)	(((uint8_t *)cqe)[31] & 0x40)
#define	HERMON_CQE_OWNER_IS_SW(cq, cqe)	((((uint8_t *)cqe)[31] >> 7) == \
			((cq->cq_consindx & cq->cq_size) >> cq->cq_log_cqsz))

#define	HERMON_QP_WQEADDRSZ(wcnt)	((uint32_t)(wcnt << 6))

#define	HERMON_WQE_SEND_SIGNALED_MASK	0x0000000C00000000ull
#define	HERMON_WQE_SEND_SOLICIT_MASK	0x0000000200000000ull
#define	HERMON_WQE_SETCTRL(desc, ctrl)	\
	((uint64_t *)(desc))[1] = HTOBE_64(ctrl)
#define	HERMON_WQE_SETNEXT(desc, nopcode, size, fence)			\
	((uint64_t *)(desc))[0] = HTOBE_64((nopcode) | (size) | (fence) | \
	(((uint64_t)((uint8_t *)desc)[0] &0x80) << 56))
#define	HERMON_WQE_BUILD_DATA_SEG(ds, sgl)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ds);					\
	tmp[1]	= HTOBE_64((sgl)->ds_va);				\
	((uint32_t *)tmp)[1] = HTOBE_32((sgl)->ds_key);			\
	membar_producer();						\
	((uint32_t *)tmp)[0] = HTOBE_32((sgl)->ds_len);			\
}


/* handy macro, useful because of cq_resize dynamics */
#define	cq_wrap_around_mask	(cq->cq_size - 1)

pthread_spinlock_t hermon_bf_lock;

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

static int dapli_hermon_wqe_send_build(ib_qp_handle_t, ibt_send_wr_t *,
    uint64_t *, uint_t *);
static DAT_RETURN dapli_hermon_wqe_recv_build(ib_qp_handle_t, ibt_recv_wr_t *,
    uint64_t *, uint_t *);
static int dapli_hermon_cq_cqe_consume(ib_cq_handle_t, uint32_t *, ibt_wc_t *);
static int dapli_hermon_cq_errcqe_consume(ib_cq_handle_t, uint32_t *,
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
 * dapli_hermon_cq_doorbell()
 * Takes the specified cq cmd and cq number and rings the cq doorbell
 */
static void
dapli_hermon_cq_doorbell(dapls_hw_uar_t ia_uar, uint32_t cq_cmd, uint32_t cqn,
    uint32_t cmd_sn, uint32_t cq_param)
{
	uint64_t doorbell;

	/* Build the doorbell from the parameters */
	doorbell = (cmd_sn | cq_cmd | cqn);
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
 * dapli_hermon_qp_send_doorbell()
 * Takes the specified qp number and rings the send doorbell.
 */
static void
dapli_hermon_sq_dbreg(dapls_hw_uar_t ia_uar, uint32_t qpn)
{
	uint64_t doorbell;

	doorbell = qpn << 8;

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
 * dapli_hermon_wqe_send_build()
 * Constructs a WQE for a given ibt_send_wr_t
 */
static int
dapli_hermon_wqe_send_build(ib_qp_handle_t qp, ibt_send_wr_t *wr,
    uint64_t *addr, uint_t *size)
{
	tavor_hw_snd_wqe_remaddr_t	*rc;
	tavor_hw_snd_wqe_bind_t		*bn;
	tavor_hw_wqe_sgl_t		*ds;
	ibt_wr_ds_t			*sgl;
	uint8_t				*src, *dst, *maxdst;
	uint32_t			nds;
	int				len, thislen, maxlen;
	uint32_t			new_rkey;
	uint32_t			old_rkey;
	int				i, num_ds;
	int				max_inline_bytes = -1;
	uint64_t			ctrl;
	uint64_t			nopcode;
	uint_t				my_size;

	nds = wr->wr_nds;
	sgl = wr->wr_sgl;
	num_ds = 0;
	ctrl = ((wr->wr_flags & IBT_WR_SEND_SIGNAL) ?
	    HERMON_WQE_SEND_SIGNALED_MASK : 0) |
	    ((wr->wr_flags & IBT_WR_SEND_SOLICIT) ?
	    HERMON_WQE_SEND_SOLICIT_MASK : 0);

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
		nopcode = TAVOR_WQE_SEND_NOPCODE_SEND;
		break;
	case IBT_WRC_RDMAW:
		if (qp->qp_sq_inline != 0)
			max_inline_bytes =
			    qp->qp_sq_wqesz - TAVOR_INLINE_HEADER_SIZE_RDMAW;
		nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAW;
		/* FALLTHROUGH */
	case IBT_WRC_RDMAR:
		if (wr->wr_opcode == IBT_WRC_RDMAR) {
			if (qp->qp_sq_inline < 0)
				qp->qp_sq_inline = 0;
			nopcode = TAVOR_WQE_SEND_NOPCODE_RDMAR;
		}
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
	/* XXX - need equiv of "hermon_wr_bind_check(state, wr);" */
	/* XXX - uses hermon_mr_keycalc - what about Sinai vs. Arbel??? */
#endif
		old_rkey = wr->wr.rc.rcwr.bind->bind_rkey;
		new_rkey = old_rkey >> 8;	/* index */
		old_rkey = (old_rkey + 1) & 0xff; /* incremented key */
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
		nopcode = TAVOR_WQE_SEND_NOPCODE_BIND;
		break;
	default:
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapli_hermon_wqe_send_build: invalid wr_opcode=%d\n",
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
		len = 0;
		for (i = 0; i < nds; i++)
			len += sgl[i].ds_len;
		if (len == 0)
			max_inline_bytes = -1; /* do not inline */
		else {
			/* need to reduce the length by dword "len" fields */
			max_inline_bytes -= (len / 64) * sizeof (uint32_t);
			if (len > max_inline_bytes)
				max_inline_bytes = -1;	/* too big for inline */
		}
	}
	if (max_inline_bytes != -1) {		/* do "inline" */

		dst = (uint8_t *)((uint32_t *)ds + 1);
		maxdst = (uint8_t *)(((uintptr_t)dst + 64) & ~(64 - 1));
		maxlen = maxdst - dst;
		thislen = 0;
		i = 0;
		src = (uint8_t *)(uintptr_t)sgl[i].ds_va;
		len = sgl[i].ds_len;
		do {
			/* if this sgl overflows the inline segment */
			if (len > maxlen) {
				if (maxlen) /* might be 0 */
					(void) dapl_os_memcpy(dst,
					    src, maxlen);
				membar_producer();
				*(uint32_t *)ds =
				    HTOBE_32((thislen + maxlen) |
				    TAVOR_WQE_SGL_INLINE_MASK);
				thislen = 0;
				len -= maxlen;
				src += maxlen;
				dst = maxdst + sizeof (uint32_t);
				ds = (tavor_hw_wqe_sgl_t *)(void *)maxdst;
				maxdst += 64;
				maxlen = 64 - sizeof (uint32_t);
			} else { /* this sgl fully fits */
				(void) dapl_os_memcpy(dst,
				    src, len);
				maxlen -= len;  /* room left */
				thislen += len;
				dst += len;
				while (++i < nds)
					if (sgl[i].ds_len)
						break;
				if (i >= nds)
					break;
				src = (uint8_t *)(uintptr_t)sgl[i].ds_va;
				len = sgl[i].ds_len;
			}
		} while (i < nds);
		membar_producer();
		*(uint32_t *)ds = HTOBE_32(thislen |
		    TAVOR_WQE_SGL_INLINE_MASK);

		/* Return the size of descriptor (in 16-byte chunks) */
		my_size = ((uintptr_t)dst - (uintptr_t)addr + 15) >> 4;
		if (my_size <= (256 >> 4))
			*size = my_size;	/* use Hermon Blueflame */
		else
			*size = 0;
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
			HERMON_WQE_BUILD_DATA_SEG(&ds[num_ds], &sgl[i]);
			num_ds++;
		}

		/* Return the size of descriptor (in 16-byte chunks) */
		my_size = ((uintptr_t)&ds[num_ds] - (uintptr_t)addr) >> 4;
		*size = 0;	/* do not use Hermon Blueflame */
	}
	HERMON_WQE_SETCTRL(addr, ctrl);
	membar_producer();
	HERMON_WQE_SETNEXT(addr, nopcode << 32, my_size,
	    (wr->wr_flags & IBT_WR_SEND_FENCE) ?
	    HERMON_WQE_SEND_FENCE_MASK : 0);

	return (DAT_SUCCESS);
}

/*
 * dapli_hermon_wqe_recv_build()
 * Builds the recv WQE for a given ibt_recv_wr_t
 */
static DAT_RETURN
dapli_hermon_wqe_recv_build(ib_qp_handle_t qp, ibt_recv_wr_t *wr,
    uint64_t *addr, uint_t *size)
{
	tavor_hw_wqe_sgl_t	*ds;
	int			i;
	int			num_ds;

	/* Fill in the Data Segments (SGL) for the Recv WQE */
	ds = (tavor_hw_wqe_sgl_t *)addr;
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
		sgl.ds_key = (ibt_lkey_t)HERMON_WQE_SGL_INVALID_LKEY;
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &sgl);
	}

	/* Return the size of descriptor (in 16-byte chunks) */
	*size = qp->qp_rq_wqesz >> 4;

	return (DAT_SUCCESS);
}

/*
 * dapli_hermon_wqe_srq_build()
 * Builds the recv WQE for a given ibt_recv_wr_t
 */
static DAT_RETURN
dapli_hermon_wqe_srq_build(ib_srq_handle_t srq, ibt_recv_wr_t *wr,
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
		end_sgl.ds_key = (ibt_lkey_t)HERMON_WQE_SGL_INVALID_LKEY;
		TAVOR_WQE_BUILD_DATA_SEG(&ds[num_ds], &end_sgl);
	}

	return (DAT_SUCCESS);
}

/*
 * dapli_hermon_cq_peek()
 * Peeks into a given CQ to check if there are any events that can be
 * polled. It returns the number of CQEs that can be polled.
 */
static void
dapli_hermon_cq_peek(ib_cq_handle_t cq, int *num_cqe)
{
	uint32_t		*cqe;
	uint32_t		imm_eth_pkey_cred;
	uint32_t		cons_indx;
	int			polled_cnt;
	uint_t			doorbell_cnt;
	uint_t			opcode;

	/* Get the consumer index */
	cons_indx = cq->cq_consindx & cq_wrap_around_mask;

	/* Calculate the pointer to the first CQ entry */
	cqe = (uint32_t *)&cq->cq_addr[cons_indx];

	/*
	 * Count entries in the CQ until we find an entry owned by
	 * the hardware.
	 */
	polled_cnt = 0;
	while (HERMON_CQE_OWNER_IS_SW(cq, cqe)) {
		opcode = HERMON_CQE_OPCODE_GET(cqe);
		/* Error CQE map to multiple work completions */
		if (opcode == HERMON_CQE_ERR_OPCODE) {
			imm_eth_pkey_cred =
			    TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe);
			doorbell_cnt =
			    imm_eth_pkey_cred & TAVOR_CQE_ERR_DBDCNT_MASK;
			polled_cnt += (doorbell_cnt + 1);
		} else {
			polled_cnt++;
		}
		/* Increment the consumer index */
		cons_indx = (cons_indx + 1) & cq_wrap_around_mask;

		/* Update the pointer to the next CQ entry */
		cqe = (uint32_t *)&cq->cq_addr[cons_indx];
	}

	*num_cqe = polled_cnt;
}

#define	dapli_hermon_cq_update_ci(cq, dbp) \
	(dbp)[0] = HTOBE_32(cq->cq_consindx & 0xFFFFFF)

/*
 * dapli_hermon_cq_resize_helper()
 * This routine switches from the pre-cq_resize buffer to the new buffer.
 */
static int
dapli_hermon_cq_resize_helper(ib_cq_handle_t cq)
{
	int i;

	if ((cq->cq_resize_addr == 0) ||
	    (munmap((char *)cq->cq_addr, cq->cq_map_len) < 0)) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "cq_resize_helper: "
		    "munmap(%p:0x%llx) failed(%d)\n", cq->cq_addr,
		    cq->cq_map_len, errno);
		return (1);	/* FAILED */
	}
	cq->cq_addr		= cq->cq_resize_addr;
	cq->cq_map_offset	= cq->cq_resize_map_offset;
	cq->cq_map_len		= cq->cq_resize_map_len;
	cq->cq_size		= cq->cq_resize_size;
	cq->cq_cqesz		= cq->cq_resize_cqesz;
	cq->cq_resize_addr	= 0;
	cq->cq_resize_map_offset = 0;
	cq->cq_resize_map_len	= 0;
	cq->cq_resize_size	= 0;
	cq->cq_resize_cqesz	= 0;
	for (i = 0; (1 << i) < cq->cq_size; i++)
		;
	cq->cq_log_cqsz = i;

	cq->cq_consindx++;	/* consume the RESIZE cqe */

	return (0);	/* SUCCESS */
}

/*
 * dapli_hermon_cq_poll()
 * This routine polls CQEs out of a CQ and puts them into the ibt_wc_t
 * array that is passed in.
 */
static DAT_RETURN
dapli_hermon_cq_poll(ib_cq_handle_t cq, ibt_wc_t *wc_p, uint_t num_wc,
    uint_t *num_polled)
{
	uint32_t		*cqe;
	uint32_t		cons_indx;
	uint32_t		polled_cnt;
	DAT_RETURN		dat_status;
	int			status;

	/* Get the consumer index */
	cons_indx = cq->cq_consindx & cq_wrap_around_mask;

	/* Calculate the pointer to the first CQ entry */
	cqe = (uint32_t *)&cq->cq_addr[cons_indx];

	/*
	 * Keep pulling entries from the CQ until we find an entry owned by
	 * the hardware.  As long as there the CQE's owned by SW, process
	 * each entry by calling dapli_hermon_cq_cqe_consume() and updating the
	 * CQ consumer index.  Note:  We only update the consumer index if
	 * dapli_hermon_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.
	 * Otherwise, it indicates that we are going to "recycle" the CQE
	 * (probably because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	polled_cnt = 0;
	while (HERMON_CQE_OWNER_IS_SW(cq, cqe)) {
		if (HERMON_CQE_OPCODE_GET(cqe) == HERMON_CQE_RESIZE_OPCODE) {
			if (dapli_hermon_cq_resize_helper(cq))
				return (DAT_ERROR(DAT_INTERNAL_ERROR, 0));
			cons_indx = cq->cq_consindx & cq_wrap_around_mask;
			cqe = (uint32_t *)&cq->cq_addr[cons_indx];
			continue;
		}
		status = dapli_hermon_cq_cqe_consume(cq, cqe,
		    &wc_p[polled_cnt++]);
		if (status == TAVOR_CQ_SYNC_AND_DB) {
			/* Reset to hardware ownership is implicit in Hermon */
			cq->cq_consindx++;	/* incr the total counter */

			/* Increment the consumer index */
			cons_indx = (cons_indx + 1) & cq_wrap_around_mask;

			/* Update the pointer to the next CQ entry */
			cqe = (uint32_t *)&cq->cq_addr[cons_indx];
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
	if (polled_cnt != 0) {
		/*
		 * Update the consumer index in both the CQ handle and the
		 * doorbell record.
		 */
		dapli_hermon_cq_update_ci(cq, cq->cq_poll_dbp);
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
 * dapli_hermon_cq_poll_one()
 * This routine polls one CQE out of a CQ and puts ot into the ibt_wc_t
 * that is passed in.  See above for more comments/details.
 */
static DAT_RETURN
dapli_hermon_cq_poll_one(ib_cq_handle_t cq, ibt_wc_t *wc_p)
{
	uint32_t		*cqe;
	uint32_t		cons_indx;
	DAT_RETURN		dat_status;
	int			status;

start_over:
	/* Get the consumer index */
	cons_indx = cq->cq_consindx & cq_wrap_around_mask;

	/* Calculate the pointer to the first CQ entry */
	cqe = (uint32_t *)&cq->cq_addr[cons_indx];

	/*
	 * Keep pulling entries from the CQ until we find an entry owned by
	 * the hardware.  As long as there the CQE's owned by SW, process
	 * each entry by calling dapli_hermon_cq_cqe_consume() and updating the
	 * CQ consumer index.  Note:  We only update the consumer index if
	 * dapli_hermon_cq_cqe_consume() returns TAVOR_CQ_SYNC_AND_DB.
	 * Otherwise, it indicates that we are going to "recycle" the CQE
	 * (probably because it is a error CQE and corresponds to more than one
	 * completion).
	 */
	if (HERMON_CQE_OWNER_IS_SW(cq, cqe)) {
		if (HERMON_CQE_OPCODE_GET(cqe) == HERMON_CQE_RESIZE_OPCODE) {
			if (dapli_hermon_cq_resize_helper(cq))
				return (DAT_ERROR(DAT_INTERNAL_ERROR, 0));
			goto start_over;
		}
		status = dapli_hermon_cq_cqe_consume(cq, cqe, wc_p);
		if (status == TAVOR_CQ_SYNC_AND_DB) {
			/* Reset to hardware ownership is implicit in Hermon */

			/* Increment the consumer index */
			cq->cq_consindx++;
			dapli_hermon_cq_update_ci(cq, cq->cq_poll_dbp);
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
 * dapli_hermon_cq_cqe_consume()
 * Converts a given CQE into a ibt_wc_t object
 */
static int
dapli_hermon_cq_cqe_consume(ib_cq_handle_t cqhdl, uint32_t *cqe,
    ibt_wc_t *wc)
{
	uint_t		flags;
	uint_t		type;
	uint_t		opcode;
	int		status;

	/*
	 * Determine if this is an "error" CQE by examining "opcode".  If it
	 * is an error CQE, then call dapli_hermon_cq_errcqe_consume() and
	 * return whatever status it returns.  Otherwise, this is a successful
	 * completion.
	 */
	opcode = HERMON_CQE_OPCODE_GET(cqe);
	if (opcode == HERMON_CQE_ERR_OPCODE) {
		status = dapli_hermon_cq_errcqe_consume(cqhdl, cqe, wc);
		return (status);
	}
	TAVOR_CQE_WQEADDRSZ_SET(cqe, (HTOBE_32(cqe[6]) >> 10) &
	    ~HERMON_WQE_NDS_MASK);

	/*
	 * Fetch the Work Request ID using the information in the CQE.
	 * See tavor_wr.c for more details.
	 */
	wc->wc_id = dapls_tavor_wrid_get_entry(cqhdl, (tavor_hw_cqe_t *)cqe,
	    HERMON_CQE_SENDRECV_GET(cqe) >> 6, 0, NULL);
	wc->wc_qpn = TAVOR_CQE_QPNUM_GET(cqe);

	/*
	 * Parse the CQE opcode to determine completion type.  This will set
	 * not only the type of the completion, but also any flags that might
	 * be associated with it (e.g. whether immediate data is present).
	 */
	flags = IBT_WC_NO_FLAGS;
	if (HERMON_CQE_SENDRECV_GET(cqe) != TAVOR_COMPLETION_RECV) {

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
		switch (opcode) {
		case HERMON_CQE_RCV_SEND:
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
 * dapli_hermon_cq_errcqe_consume()
 */
static int
dapli_hermon_cq_errcqe_consume(ib_cq_handle_t cqhdl, uint32_t *cqe,
    ibt_wc_t *wc)
{
	dapls_tavor_wrid_entry_t	wre;
	uint_t			status;
	uint_t			send_or_recv;

	dapl_dbg_log(DAPL_DBG_TYPE_EVD, "errcqe_consume:cqe.eth=%x, wqe=%x\n",
	    TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cqe),
	    TAVOR_CQE_WQEADDRSZ_GET(cqe));

	status = ((uint8_t *)cqe)[0x1B];
	TAVOR_CQE_WQEADDRSZ_SET(cqe, (HTOBE_32(cqe[6]) >> 10) &
	    ~HERMON_WQE_NDS_MASK);
	if (HERMON_CQE_SENDRECV_GET(cqe) == 0) {
		send_or_recv = 0;
	} else {
		send_or_recv = 1;
	}

	/*
	 * Fetch the Work Request ID using the information in the CQE.
	 * See tavor_wr.c for more details.
	 */
	wc->wc_id = dapls_tavor_wrid_get_entry(cqhdl, (tavor_hw_cqe_t *)cqe,
	    send_or_recv, 1, &wre);
	wc->wc_qpn = TAVOR_CQE_QPNUM_GET(cqe);

	/*
	 * Parse the CQE opcode to determine completion type.  We know that
	 * the CQE is an error completion, so we extract only the completion
	 * status here.
	 */
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
 * dapli_hermon_cq_notify()
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
dapli_hermon_cq_notify(ib_cq_handle_t cq, int flags, uint32_t param)
{
	uint32_t	cqnum;
	uint32_t	*target;
	uint32_t	old_cmd, cmp, new, tmp, cmd_sn;

	/*
	 * Determine if we are trying to get the next completion or the next
	 * "solicited" completion.  Then hit the appropriate doorbell.
	 */
	cqnum = cq->cq_num;
	target = cq->cq_arm_dbp;
retry:
	cmp = *target;
	tmp = HTOBE_32(cmp);
	old_cmd = tmp & (0x7 << 24);
	cmd_sn = tmp & (0x3 << 28);

	if (flags == IB_NOTIFY_ON_NEXT_COMP) {
		if (old_cmd != HERMON_CQDB_NOTIFY_CQ) {
			new = HTOBE_32(cmd_sn | HERMON_CQDB_NOTIFY_CQ |
			    (cq->cq_consindx & 0xFFFFFF));
			tmp = atomic_cas_32(target, cmp, new);
			if (tmp != cmp)
				goto retry;
			dapli_hermon_cq_doorbell(cq->cq_iauar,
			    HERMON_CQDB_NOTIFY_CQ, cqnum,
			    cmd_sn, cq->cq_consindx);
		} /* else it's already armed */
	} else if (flags == IB_NOTIFY_ON_NEXT_SOLICITED) {
		if (old_cmd != HERMON_CQDB_NOTIFY_CQ &&
		    old_cmd != HERMON_CQDB_NOTIFY_CQ_SOLICIT) {
			new = HTOBE_32(cmd_sn | HERMON_CQDB_NOTIFY_CQ_SOLICIT |
			    (cq->cq_consindx & 0xFFFFFF));
			tmp = atomic_cas_32(target, cmp, new);
			if (tmp != cmp)
				goto retry;
			dapli_hermon_cq_doorbell(cq->cq_iauar,
			    HERMON_CQDB_NOTIFY_CQ_SOLICIT, cqnum,
			    cmd_sn, cq->cq_consindx);
		} /* else it's already armed */
	} else {
		return (DAT_INVALID_PARAMETER);
	}

	return (DAT_SUCCESS);
}

/*
 * Since uDAPL posts 1 wqe per request, we
 * only need to do stores for the last one.
 */
static void
dapli_hermon_wqe_headroom(ib_qp_handle_t qp, uint32_t start)
{
	uint32_t *wqe_start, *wqe_top, *wqe_base, qsize, invalue;
	int hdrmwqes, wqesizebytes, sectperwqe, i, j;

	qsize = qp->qp_sq_numwqe;
	wqesizebytes = qp->qp_sq_wqesz;
	sectperwqe = wqesizebytes >> 6;
	hdrmwqes = qp->qp_sq_headroom;
	wqe_base = (uint32_t *)TAVOR_QP_SQ_ENTRY(qp, 0);
	wqe_top = (uint32_t *)TAVOR_QP_SQ_ENTRY(qp, qsize);
	wqe_start = (uint32_t *)TAVOR_QP_SQ_ENTRY(qp, start);

	for (i = 0; i < hdrmwqes - 1; i++) {
		wqe_start += sectperwqe * 16;
		if (wqe_start == wqe_top)
			wqe_start = wqe_base;
	}
	invalue = HTOBE_32(*wqe_start);
	invalue |= 0x7FFFFFFF;
	*wqe_start = HTOBE_32(invalue);
	wqe_start += 16;
	for (j = 1; j < sectperwqe; j++) {
		*wqe_start = 0xFFFFFFFF;
		wqe_start += 16;
	}
}

/*
 * dapli_hermon_post_send()
 */
/* ARGSUSED */
static DAT_RETURN
dapli_hermon_post_send(DAPL_EP *ep, ibt_send_wr_t *wr, boolean_t ns)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	dapls_tavor_wrid_entry_t	*wre_last;
	uint64_t			*desc;
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
	status = dapli_hermon_wqe_send_build(qp, wr, wqe_addr, &desc_sz);
	if (status != DAT_SUCCESS) {
		dapl_os_unlock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);
		return (status);
	}

	/*
	 * Get the descriptor (io address) corresponding to the location
	 * Send WQE was built.
	 */
	desc = TAVOR_QP_SQ_ENTRY(qp, tail);

	/*
	 * Add a WRID entry to the WRID list.  Need to calculate the
	 * "wqeaddr" to pass to dapli_tavor_wrid_add_entry().
	 * signaled_dbd is still calculated, but ignored.
	 */
	wqeaddrsz = HERMON_QP_WQEADDRSZ(qp->qp_sq_counter);

	if (wr->wr_flags & IBT_WR_SEND_SIGNAL) {
		signaled_dbd = TAVOR_WRID_ENTRY_SIGNALED;
	}

	dapli_tavor_wrid_add_entry(qp->qp_sq_wqhdr, wr->wr_id, wqeaddrsz,
	    signaled_dbd);

	dapli_hermon_wqe_headroom(qp, next_tail);
	*(uint8_t *)desc ^= 0x80;	/* set owner bit */

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

	if (desc_sz && qp->qp_ia_bf != NULL) {	/* use Hermon Blueflame */
		uint64_t *bf_dest, *src64;
		uint8_t *src8;
		int i;

		(void) pthread_spin_lock(&hermon_bf_lock);

		src8 = (uint8_t *)desc;
		src8[1] = (uint8_t)(qp->qp_sq_counter >> 8);
		src8[2] = (uint8_t)qp->qp_sq_counter;
		src8[4] = (uint8_t)(qp->qp_num >> 16);
		src8[5] = (uint8_t)(qp->qp_num >> 8);
		src8[6] = (uint8_t)qp->qp_num;

		src64 = (uint64_t *)desc;
		bf_dest = (uint64_t *)((uintptr_t)qp->qp_ia_bf +
		    *qp->qp_ia_bf_toggle);
		*qp->qp_ia_bf_toggle ^= 256;	/* 2 256-byte buffers */
		for (i = 0; i < desc_sz * 2; i += 8) {
			bf_dest[i] = src64[i];
			bf_dest[i + 1] = src64[i + 1];
			bf_dest[i + 2] = src64[i + 2];
			bf_dest[i + 3] = src64[i + 3];
			bf_dest[i + 4] = src64[i + 4];
			bf_dest[i + 5] = src64[i + 5];
			bf_dest[i + 6] = src64[i + 6];
			bf_dest[i + 7] = src64[i + 7];
		}
		(void) pthread_spin_unlock(&hermon_bf_lock);
	} else {
		/* Ring the doorbell */
		dapli_hermon_sq_dbreg(qp->qp_iauar, qp->qp_num);
	}
	qp->qp_sq_counter++;

	dapl_os_unlock(&qp->qp_sq_wqhdr->wq_wrid_lock->wrl_lock);

	return (DAT_SUCCESS);
}

/*
 * dapli_hermon_post_recv()
 */
/* ARGSUSED */
static DAT_RETURN
dapli_hermon_post_recv(DAPL_EP	*ep, ibt_recv_wr_t *wr, boolean_t ns)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	dapls_tavor_wrid_entry_t	*wre_last;
	ib_qp_handle_t			qp;
	DAT_RETURN			status;
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

	/* The user virtual address of the WQE to be built */
	wqe_addr = TAVOR_QP_RQ_ENTRY(qp, tail);

	/*
	 * Call tavor_wqe_recv_build() to build the WQE at the given
	 * address. This routine uses the information in the
	 * ibt_recv_wr_t and returns the size of the WQE.
	 */
	status = dapli_hermon_wqe_recv_build(qp, wr, wqe_addr, &desc_sz);
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
	wqeaddrsz = HERMON_QP_WQEADDRSZ(qp->qp_rq_counter);
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
 * dapli_hermon_post_srq()
 */
/* ARGSUSED */
static DAT_RETURN
dapli_hermon_post_srq(DAPL_SRQ *srqp, ibt_recv_wr_t *wr, boolean_t ns)
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
	 * Call dapli_hermon_wqe_srq_build() to build the WQE at the given
	 * address. This routine uses the information in the
	 * ibt_recv_wr_t and returns the size of the WQE.
	 */
	status = dapli_hermon_wqe_srq_build(srq, wr, wqe_addr);
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
 * dapli_hermon_cq_srq_entries_flush()
 */
static void
dapli_hermon_cq_srq_entries_flush(ib_qp_handle_t qp)
{
	ib_cq_handle_t		cq;
	dapls_tavor_workq_hdr_t	*wqhdr;
	tavor_hw_cqe_t		*cqe;
	tavor_hw_cqe_t		*next_cqe;
	uint32_t		cons_indx, tail_cons_indx;
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
		tail_cons_indx = (tail_cons_indx + 1) & cq_wrap_around_mask;

		/* update the pointer to the next cq entry */
		cqe = &cq->cq_addr[tail_cons_indx];
	}

	/*
	 * Using the 'tail_cons_indx' that was just set, we now know how many
	 * total CQEs possible there are.  Set the 'check_indx' and the
	 * 'new_indx' to the last entry identified by 'tail_cons_indx'
	 */
	check_indx = new_indx = (tail_cons_indx - 1) & cq_wrap_around_mask;

	for (i = 0; i < outstanding_cqes; i++) {
		cqe = &cq->cq_addr[check_indx];

		/* Grab QP number from CQE */
		cqe_qpnum = TAVOR_CQE_QPNUM_GET(cqe);
		cqe_type = HERMON_CQE_SENDRECV_GET(cqe);

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
			new_indx = (new_indx - 1) & cq_wrap_around_mask;
		}
		/* Move index to next CQE to check */
		check_indx = (check_indx - 1) & cq_wrap_around_mask;
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
		    indx = (indx + 1) & cq_wrap_around_mask) {
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
	cons_indx = (new_indx + 1) & cq_wrap_around_mask;

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
		dapli_hermon_cq_update_ci(cq, cq->cq_poll_dbp);
	}
}

static void
dapli_hermon_rq_prelink(caddr_t first, uint32_t desc_off, uint32_t wqesz,
    uint32_t numwqe, uint32_t nds)
{
	int i;
	uint32_t *p = (uint32_t *)(uintptr_t)first;
	uint32_t off = desc_off;
	uint32_t pincr = wqesz / sizeof (uint32_t);
	ibt_wr_ds_t sgl;

	sgl.ds_va = (ib_vaddr_t)0;
	sgl.ds_key = HERMON_WQE_SGL_INVALID_LKEY;
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
dapli_hermon_sq_init(caddr_t first, uint32_t wqesz, uint32_t numwqe)
{
	int i, j;
	uint64_t *wqe = (uint64_t *)(uintptr_t)first;

	for (i = 0; i < numwqe; i++) {
		for (j = 0; j < wqesz; j += 64, wqe += 8)
			*(uint32_t *)wqe = 0xFFFFFFFF;
	}
}

static void
dapli_hermon_qp_init(ib_qp_handle_t qp)
{
	dapli_hermon_sq_init(qp->qp_sq_buf, qp->qp_sq_wqesz, qp->qp_sq_numwqe);
	qp->qp_rq_counter = 0;
	qp->qp_sq_counter = 0;
}

static void
dapli_hermon_cq_init(ib_cq_handle_t cq)
{
	uint32_t i;

	(cq->cq_arm_dbp)[0] = HTOBE_32(1 << 28);
	for (i = 0; (1 << i) < cq->cq_size; i++)
		;
	cq->cq_log_cqsz = i;
	cq->cq_consindx = 0;

	/* cq_resize -- needs testing */
}

static void
dapli_hermon_srq_init(ib_srq_handle_t srq)
{
	/* pre-link the whole shared receive queue */
	dapli_hermon_rq_prelink(srq->srq_addr, srq->srq_wq_desc_addr,
	    srq->srq_wq_wqesz, srq->srq_wq_numwqe, 0);
	srq->srq_counter = 0;

	/* needs testing */
}

void
dapls_init_funcs_hermon(DAPL_HCA *hca_ptr)
{
	hca_ptr->post_send = dapli_hermon_post_send;
	hca_ptr->post_recv = dapli_hermon_post_recv;
	hca_ptr->post_srq = dapli_hermon_post_srq;
	hca_ptr->cq_peek = dapli_hermon_cq_peek;
	hca_ptr->cq_poll = dapli_hermon_cq_poll;
	hca_ptr->cq_poll_one = dapli_hermon_cq_poll_one;
	hca_ptr->cq_notify = dapli_hermon_cq_notify;
	hca_ptr->srq_flush = dapli_hermon_cq_srq_entries_flush;
	hca_ptr->qp_init = dapli_hermon_qp_init;
	hca_ptr->cq_init = dapli_hermon_cq_init;
	hca_ptr->srq_init = dapli_hermon_srq_init;
	hca_ptr->hermon_resize_cq = 1;

	(void) pthread_spin_init(&hermon_bf_lock, 0);
}
