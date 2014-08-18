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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Source file containing the Receive Path handling
 * functions
 */
#include <oce_impl.h>


void oce_rx_pool_free(char *arg);
static void oce_rqb_dtor(oce_rq_bdesc_t *rqbd);
static int oce_rqb_ctor(oce_rq_bdesc_t *rqbd, struct oce_rq *rq,
    size_t size, int flags);

static inline mblk_t *oce_rx(struct oce_dev *dev, struct oce_rq *rq,
    struct oce_nic_rx_cqe *cqe);
static inline mblk_t *oce_rx_bcopy(struct oce_dev *dev,
	struct oce_rq *rq, struct oce_nic_rx_cqe *cqe);
static int oce_rq_charge(struct oce_rq *rq, uint32_t nbufs, boolean_t repost);
static void oce_rx_insert_tag(mblk_t *mp, uint16_t vtag);
static void oce_set_rx_oflags(mblk_t *mp, struct oce_nic_rx_cqe *cqe);
static inline void oce_rx_drop_pkt(struct oce_rq *rq,
    struct oce_nic_rx_cqe *cqe);
static oce_rq_bdesc_t *oce_rqb_alloc(struct oce_rq *rq);
static void oce_rqb_free(struct oce_rq *rq, oce_rq_bdesc_t *rqbd);
static void oce_rq_post_buffer(struct oce_rq *rq, int nbufs);

#pragma	inline(oce_rx)
#pragma	inline(oce_rx_bcopy)
#pragma	inline(oce_rq_charge)
#pragma	inline(oce_rx_insert_tag)
#pragma	inline(oce_set_rx_oflags)
#pragma	inline(oce_rx_drop_pkt)
#pragma	inline(oce_rqb_alloc)
#pragma	inline(oce_rqb_free)
#pragma inline(oce_rq_post_buffer)

static ddi_dma_attr_t oce_rx_buf_attr = {
	DMA_ATTR_V0,		/* version number */
	0x0000000000000000ull,	/* low address */
	0xFFFFFFFFFFFFFFFFull,	/* high address */
	0x00000000FFFFFFFFull,	/* dma counter max */
	OCE_DMA_ALIGNMENT,	/* alignment */
	0x000007FF,		/* burst sizes */
	0x00000001,		/* minimum transfer size */
	0x00000000FFFFFFFFull,	/* maximum transfer size */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	1,			/* scatter/gather list length */
	0x00000001,		/* granularity */
	DDI_DMA_FLAGERR|DDI_DMA_RELAXED_ORDERING		/* DMA flags */
};

/*
 * function to create a DMA buffer pool for RQ
 *
 * dev - software handle to the device
 * num_items - number of buffers in the pool
 * item_size - size of each buffer
 *
 * return DDI_SUCCESS => success, DDI_FAILURE otherwise
 */
int
oce_rqb_cache_create(struct oce_rq *rq, size_t buf_size)
{
	int size;
	int cnt;
	int ret;
	oce_rq_bdesc_t *rqbd;

	_NOTE(ARGUNUSED(buf_size));
	rqbd = rq->rq_bdesc_array;
	size = rq->cfg.frag_size + OCE_RQE_BUF_HEADROOM;
	for (cnt = 0; cnt < rq->cfg.nbufs; cnt++, rqbd++) {
		rq->rqb_freelist[cnt] = rqbd;
		ret = oce_rqb_ctor(rqbd, rq,
		    size, (DDI_DMA_RDWR|DDI_DMA_STREAMING));
		if (ret != DDI_SUCCESS) {
			goto rqb_fail;
		}
	}
	rq->rqb_free = rq->cfg.nbufs;
	rq->rqb_rc_head = 0;
	rq->rqb_next_free = 0;
	return (DDI_SUCCESS);

rqb_fail:
	oce_rqb_cache_destroy(rq);
	return (DDI_FAILURE);
} /* oce_rqb_cache_create */

/*
 * function to Destroy RQ DMA buffer cache
 *
 * rq - pointer to rq structure
 *
 * return none
 */
void
oce_rqb_cache_destroy(struct oce_rq *rq)
{
	oce_rq_bdesc_t *rqbd = NULL;
	int cnt;

	rqbd = rq->rq_bdesc_array;
	for (cnt = 0; cnt < rq->cfg.nbufs; cnt++, rqbd++) {
		oce_rqb_dtor(rqbd);
	}
} /* oce_rqb_cache_destroy */

/*
 * RQ buffer destructor function
 *
 * rqbd - pointer to rq buffer descriptor
 *
 * return none
 */
static	void
oce_rqb_dtor(oce_rq_bdesc_t *rqbd)
{
	if ((rqbd == NULL) || (rqbd->rq == NULL)) {
		return;
	}
	if (rqbd->mp != NULL) {
		rqbd->fr_rtn.free_arg = NULL;
		freemsg(rqbd->mp);
		rqbd->mp = NULL;
	}
	oce_free_dma_buffer(rqbd->rq->parent, rqbd->rqb);
} /* oce_rqb_dtor */

/*
 * RQ buffer constructor function
 *
 * rqbd - pointer to rq buffer descriptor
 * rq - pointer to RQ structure
 * size - size of the buffer
 * flags - KM_SLEEP OR KM_NOSLEEP
 *
 * return DDI_SUCCESS => success, DDI_FAILURE otherwise
 */
static int
oce_rqb_ctor(oce_rq_bdesc_t *rqbd, struct oce_rq *rq, size_t size, int flags)
{
	struct oce_dev *dev;
	oce_dma_buf_t *dbuf;

	dev = rq->parent;

	dbuf  = oce_alloc_dma_buffer(dev, size, &oce_rx_buf_attr, flags);
	if (dbuf == NULL) {
		return (DDI_FAILURE);
	}

	/* Set the call back function parameters */
	rqbd->fr_rtn.free_func = (void (*)())oce_rx_pool_free;
	rqbd->fr_rtn.free_arg = (caddr_t)(void *)rqbd;
	rqbd->mp = desballoc((uchar_t *)(dbuf->base),
	    dbuf->size, 0, &rqbd->fr_rtn);
	if (rqbd->mp == NULL) {
		oce_free_dma_buffer(dev, dbuf);
		return (DDI_FAILURE);
	}
	rqbd->rqb = dbuf;
	rqbd->rq = rq;
	rqbd->frag_addr.dw.addr_lo = ADDR_LO(dbuf->addr + OCE_RQE_BUF_HEADROOM);
	rqbd->frag_addr.dw.addr_hi = ADDR_HI(dbuf->addr + OCE_RQE_BUF_HEADROOM);
	rqbd->mp->b_rptr = (uchar_t *)rqbd->rqb->base + OCE_RQE_BUF_HEADROOM;

	return (DDI_SUCCESS);
} /* oce_rqb_ctor */

/*
 * RQ buffer allocator function
 *
 * rq - pointer to RQ structure
 *
 * return pointer to RQ buffer descriptor
 */
static inline oce_rq_bdesc_t *
oce_rqb_alloc(struct oce_rq *rq)
{
	oce_rq_bdesc_t *rqbd;
	uint32_t free_index;
	free_index = rq->rqb_next_free;
	rqbd = rq->rqb_freelist[free_index];
	rq->rqb_freelist[free_index] = NULL;
	rq->rqb_next_free = GET_Q_NEXT(free_index, 1, rq->cfg.nbufs);
	return (rqbd);
} /* oce_rqb_alloc */

/*
 * function to free the RQ buffer
 *
 * rq - pointer to RQ structure
 * rqbd - pointer to recieve buffer descriptor
 *
 * return none
 */
static inline void
oce_rqb_free(struct oce_rq *rq, oce_rq_bdesc_t *rqbd)
{
	uint32_t free_index;
	mutex_enter(&rq->rc_lock);
	free_index = rq->rqb_rc_head;
	rq->rqb_freelist[free_index] = rqbd;
	rq->rqb_rc_head = GET_Q_NEXT(free_index, 1, rq->cfg.nbufs);
	mutex_exit(&rq->rc_lock);
	atomic_inc_32(&rq->rqb_free);
} /* oce_rqb_free */




static void oce_rq_post_buffer(struct oce_rq *rq, int nbufs)
{
	pd_rxulp_db_t rxdb_reg;
	int count;
	struct oce_dev *dev =  rq->parent;


	rxdb_reg.dw0 = 0;
	rxdb_reg.bits.qid = rq->rq_id & DB_RQ_ID_MASK;

	for (count = nbufs/OCE_MAX_RQ_POSTS; count > 0; count--) {
		rxdb_reg.bits.num_posted = OCE_MAX_RQ_POSTS;
		OCE_DB_WRITE32(dev, PD_RXULP_DB, rxdb_reg.dw0);
		rq->buf_avail += OCE_MAX_RQ_POSTS;
		nbufs -= OCE_MAX_RQ_POSTS;
	}
	if (nbufs > 0) {
		rxdb_reg.bits.num_posted = nbufs;
		OCE_DB_WRITE32(dev, PD_RXULP_DB, rxdb_reg.dw0);
		rq->buf_avail += nbufs;
	}
}
/*
 * function to charge a given rq with buffers from a pool's free list
 *
 * dev - software handle to the device
 * rq - pointer to the RQ to charge
 * nbufs - numbers of buffers to be charged
 *
 * return number of rqe's charges.
 */
static inline int
oce_rq_charge(struct oce_rq *rq, uint32_t nbufs, boolean_t repost)
{
	struct oce_nic_rqe *rqe;
	oce_rq_bdesc_t *rqbd;
	oce_rq_bdesc_t **shadow_rq;
	int cnt;
	int cur_index;
	oce_ring_buffer_t *ring;

	shadow_rq = rq->shadow_ring;
	ring = rq->ring;
	cur_index = ring->cidx;

	for (cnt = 0; cnt < nbufs; cnt++) {
		if (!repost) {
			rqbd = oce_rqb_alloc(rq);
		} else {
			/* just repost the buffers from shadow ring */
			rqbd = shadow_rq[cur_index];
			cur_index = GET_Q_NEXT(cur_index, 1, ring->num_items);
		}
		/* fill the rqes */
		rqe = RING_GET_PRODUCER_ITEM_VA(rq->ring,
		    struct oce_nic_rqe);
		rqe->u0.s.frag_pa_lo = rqbd->frag_addr.dw.addr_lo;
		rqe->u0.s.frag_pa_hi = rqbd->frag_addr.dw.addr_hi;
		shadow_rq[rq->ring->pidx] = rqbd;
		DW_SWAP(u32ptr(rqe), sizeof (struct oce_nic_rqe));
		RING_PUT(rq->ring, 1);
	}

	return (cnt);
} /* oce_rq_charge */

/*
 * function to release the posted buffers
 *
 * rq - pointer to the RQ to charge
 *
 * return none
 */
void
oce_rq_discharge(struct oce_rq *rq)
{
	oce_rq_bdesc_t *rqbd;
	oce_rq_bdesc_t **shadow_rq;

	shadow_rq = rq->shadow_ring;
	/* Free the posted buffer since RQ is destroyed already */
	while ((int32_t)rq->buf_avail > 0) {
		rqbd = shadow_rq[rq->ring->cidx];
		oce_rqb_free(rq, rqbd);
		RING_GET(rq->ring, 1);
		rq->buf_avail--;
	}
}
/*
 * function to process a single packet
 *
 * dev - software handle to the device
 * rq - pointer to the RQ to charge
 * cqe - Pointer to Completion Q entry
 *
 * return mblk pointer =>  success, NULL  => error
 */
static inline mblk_t *
oce_rx(struct oce_dev *dev, struct oce_rq *rq, struct oce_nic_rx_cqe *cqe)
{
	mblk_t *mp;
	int pkt_len;
	int32_t frag_cnt = 0;
	mblk_t **mblk_tail;
	mblk_t	*mblk_head;
	int frag_size;
	oce_rq_bdesc_t *rqbd;
	uint16_t cur_index;
	oce_ring_buffer_t *ring;
	int i;

	frag_cnt  = cqe->u0.s.num_fragments & 0x7;
	mblk_head = NULL;
	mblk_tail = &mblk_head;

	ring = rq->ring;
	cur_index = ring->cidx;

	/* Get the relevant Queue pointers */
	pkt_len = cqe->u0.s.pkt_size;
	for (i = 0; i < frag_cnt; i++) {
		rqbd = rq->shadow_ring[cur_index];
		if (rqbd->mp == NULL) {
			rqbd->mp = desballoc((uchar_t *)rqbd->rqb->base,
			    rqbd->rqb->size, 0, &rqbd->fr_rtn);
			if (rqbd->mp == NULL) {
				return (NULL);
			}

			rqbd->mp->b_rptr =
			    (uchar_t *)rqbd->rqb->base + OCE_RQE_BUF_HEADROOM;
		}

		mp = rqbd->mp;
		frag_size  = (pkt_len > rq->cfg.frag_size) ?
		    rq->cfg.frag_size : pkt_len;
		mp->b_wptr = mp->b_rptr + frag_size;
		pkt_len   -= frag_size;
		mp->b_next = mp->b_cont = NULL;
		/* Chain the message mblks */
		*mblk_tail = mp;
		mblk_tail = &mp->b_cont;
		(void) DBUF_SYNC(rqbd->rqb, DDI_DMA_SYNC_FORCPU);
		cur_index = GET_Q_NEXT(cur_index, 1, ring->num_items);
	}

	if (mblk_head == NULL) {
		oce_log(dev, CE_WARN, MOD_RX, "%s", "oce_rx:no frags?");
		return (NULL);
	}

	/* replace the buffer with new ones */
	(void) oce_rq_charge(rq, frag_cnt, B_FALSE);
	atomic_add_32(&rq->pending, frag_cnt);
	return (mblk_head);
} /* oce_rx */

static inline mblk_t *
oce_rx_bcopy(struct oce_dev *dev, struct oce_rq *rq, struct oce_nic_rx_cqe *cqe)
{
	mblk_t *mp;
	int pkt_len;
	int alloc_len;
	int32_t frag_cnt = 0;
	int frag_size;
	oce_rq_bdesc_t *rqbd;
	unsigned char  *rptr;
	uint32_t cur_index;
	oce_ring_buffer_t *ring;
	oce_rq_bdesc_t **shadow_rq;
	int cnt = 0;

	_NOTE(ARGUNUSED(dev));

	shadow_rq = rq->shadow_ring;
	pkt_len = cqe->u0.s.pkt_size;
	alloc_len = pkt_len + OCE_RQE_BUF_HEADROOM;
	frag_cnt = cqe->u0.s.num_fragments & 0x7;

	mp = allocb(alloc_len, BPRI_HI);
	if (mp == NULL) {
		return (NULL);
	}

	mp->b_rptr += OCE_RQE_BUF_HEADROOM;
	rptr = mp->b_rptr;
	mp->b_wptr = mp->b_rptr + pkt_len;
	ring = rq->ring;

	cur_index = ring->cidx;
	for (cnt = 0; cnt < frag_cnt; cnt++) {
		rqbd = shadow_rq[cur_index];
		frag_size  = (pkt_len > rq->cfg.frag_size) ?
		    rq->cfg.frag_size : pkt_len;
		(void) DBUF_SYNC(rqbd->rqb, DDI_DMA_SYNC_FORCPU);
		bcopy(rqbd->rqb->base + OCE_RQE_BUF_HEADROOM, rptr, frag_size);
		rptr += frag_size;
		pkt_len   -= frag_size;
		cur_index = GET_Q_NEXT(cur_index, 1, ring->num_items);
	}
	(void) oce_rq_charge(rq, frag_cnt, B_TRUE);
	return (mp);
}

static inline void
oce_set_rx_oflags(mblk_t *mp, struct oce_nic_rx_cqe *cqe)
{
	int csum_flags = 0;

	/* set flags */
	if (cqe->u0.s.ip_cksum_pass) {
		csum_flags |= HCK_IPV4_HDRCKSUM_OK;
	}

	if (cqe->u0.s.l4_cksum_pass) {
		csum_flags |= (HCK_FULLCKSUM | HCK_FULLCKSUM_OK);
	}

	if (csum_flags) {
		(void) mac_hcksum_set(mp, 0, 0, 0, 0, csum_flags);
	}
}

static inline void
oce_rx_insert_tag(mblk_t *mp, uint16_t vtag)
{
	struct ether_vlan_header *ehp;

	(void) memmove(mp->b_rptr - VTAG_SIZE,
	    mp->b_rptr, 2 * ETHERADDRL);
	mp->b_rptr -= VTAG_SIZE;
	ehp = (struct ether_vlan_header *)voidptr(mp->b_rptr);
	ehp->ether_tpid = htons(ETHERTYPE_VLAN);
	ehp->ether_tci = LE_16(vtag);
}

static inline void
oce_rx_drop_pkt(struct oce_rq *rq, struct oce_nic_rx_cqe *cqe)
{
	int frag_cnt;
	oce_rq_bdesc_t *rqbd;
	oce_rq_bdesc_t  **shadow_rq;
	shadow_rq = rq->shadow_ring;
	for (frag_cnt = 0; frag_cnt < cqe->u0.s.num_fragments; frag_cnt++) {
		rqbd = shadow_rq[rq->ring->cidx];
		oce_rqb_free(rq, rqbd);
		RING_GET(rq->ring, 1);
	}
}


/*
 * function to process a Recieve queue
 *
 * arg - pointer to the RQ to charge
 *
 * return number of cqes processed
 */
uint16_t
oce_drain_rq_cq(void *arg)
{
	struct oce_nic_rx_cqe *cqe;
	struct oce_rq *rq;
	mblk_t *mp = NULL;
	mblk_t *mblk_head;
	mblk_t **mblk_tail;
	uint16_t num_cqe = 0;
	struct oce_cq  *cq;
	struct oce_dev *dev;
	int32_t frag_cnt;
	uint32_t nbufs = 0;

	rq = (struct oce_rq *)arg;
	dev = rq->parent;
	cq = rq->cq;
	mblk_head = NULL;
	mblk_tail = &mblk_head;

	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_nic_rx_cqe);

	(void) DBUF_SYNC(cq->ring->dbuf, DDI_DMA_SYNC_FORKERNEL);
	/* dequeue till you reach an invalid cqe */
	while (RQ_CQE_VALID(cqe)) {
		DW_SWAP(u32ptr(cqe), sizeof (struct oce_nic_rx_cqe));
		frag_cnt = cqe->u0.s.num_fragments & 0x7;
		/* if insufficient buffers to charge then do copy */
		if ((cqe->u0.s.pkt_size < dev->rx_bcopy_limit) ||
		    (oce_atomic_reserve(&rq->rqb_free, frag_cnt) < 0)) {
			mp = oce_rx_bcopy(dev, rq, cqe);
		} else {
			mp = oce_rx(dev, rq, cqe);
			if (mp == NULL) {
				atomic_add_32(&rq->rqb_free, frag_cnt);
				mp = oce_rx_bcopy(dev, rq, cqe);
			}
		}
		if (mp != NULL) {
			if (dev->function_mode & FLEX10_MODE) {
				if (cqe->u0.s.vlan_tag_present &&
				    cqe->u0.s.qnq) {
					oce_rx_insert_tag(mp, cqe->u0.s.vlan_tag);
				}
			} else if (cqe->u0.s.vlan_tag_present) {
				oce_rx_insert_tag(mp, cqe->u0.s.vlan_tag);
			}
			oce_set_rx_oflags(mp, cqe);

			*mblk_tail = mp;
			mblk_tail = &mp->b_next;
		} else {
			(void) oce_rq_charge(rq, frag_cnt, B_TRUE);
		}
		RING_GET(rq->ring, frag_cnt);
		rq->buf_avail -= frag_cnt;
		nbufs += frag_cnt;

		oce_rq_post_buffer(rq, frag_cnt);
		RQ_CQE_INVALIDATE(cqe);
		RING_GET(cq->ring, 1);
		cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring,
		    struct oce_nic_rx_cqe);
		num_cqe++;
		/* process max ring size */
		if (num_cqe > dev->rx_pkt_per_intr) {
			break;
		}
	} /* for all valid CQEs */

	if (mblk_head) {
		mac_rx(dev->mac_handle, NULL, mblk_head);
	}
	oce_arm_cq(dev, cq->cq_id, num_cqe, B_TRUE);
	return (num_cqe);
} /* oce_drain_rq_cq */

/*
 * function to free mblk databuffer to the RQ pool
 *
 * arg - pointer to the receive buffer descriptor
 *
 * return none
 */
void
oce_rx_pool_free(char *arg)
{
	oce_rq_bdesc_t *rqbd;
	struct oce_rq  *rq;

	/* During destroy, arg will be NULL */
	if (arg == NULL) {
		return;
	}

	/* retrieve the pointers from arg */
	rqbd = (oce_rq_bdesc_t *)(void *)arg;
	rq = rqbd->rq;
	rqbd->mp = desballoc((uchar_t *)rqbd->rqb->base,
	    rqbd->rqb->size, 0, &rqbd->fr_rtn);

	if (rqbd->mp) {
		rqbd->mp->b_rptr =
		    (uchar_t *)rqbd->rqb->base + OCE_RQE_BUF_HEADROOM;
	}

	oce_rqb_free(rq, rqbd);
	(void) atomic_dec_32(&rq->pending);
} /* rx_pool_free */

/*
 * function to stop the RX
 *
 * rq - pointer to RQ structure
 *
 * return none
 */
void
oce_clean_rq(struct oce_rq *rq)
{
	uint16_t num_cqe = 0;
	struct oce_cq  *cq;
	struct oce_dev *dev;
	struct oce_nic_rx_cqe *cqe;
	int32_t ti = 0;

	dev = rq->parent;
	cq = rq->cq;
	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_nic_rx_cqe);
	/* dequeue till you reach an invalid cqe */
	for (ti = 0; ti < DEFAULT_DRAIN_TIME; ti++) {

		while (RQ_CQE_VALID(cqe)) {
			DW_SWAP(u32ptr(cqe), sizeof (struct oce_nic_rx_cqe));
			oce_rx_drop_pkt(rq, cqe);
			atomic_add_32(&rq->buf_avail,
			    -(cqe->u0.s.num_fragments & 0x7));
			oce_arm_cq(dev, cq->cq_id, 1, B_TRUE);
			RQ_CQE_INVALIDATE(cqe);
			RING_GET(cq->ring, 1);
			cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring,
			    struct oce_nic_rx_cqe);
			num_cqe++;
		}
		OCE_MSDELAY(1);
	}
} /* oce_clean_rq */

/*
 * function to start  the RX
 *
 * rq - pointer to RQ structure
 *
 * return number of rqe's charges.
 */
int
oce_start_rq(struct oce_rq *rq)
{
	int ret = 0;
	int to_charge = 0;
	struct oce_dev *dev = rq->parent;
	to_charge = rq->cfg.q_len - rq->buf_avail;
	to_charge = min(to_charge, rq->rqb_free);
	atomic_add_32(&rq->rqb_free, -to_charge);
	(void) oce_rq_charge(rq, to_charge, B_FALSE);
	/* ok to do it here since Rx has not even started */
	oce_rq_post_buffer(rq, to_charge);
	oce_arm_cq(dev, rq->cq->cq_id, 0, B_TRUE);
	return (ret);
} /* oce_start_rq */

/* Checks for pending rx buffers with Stack */
int
oce_rx_pending(struct oce_dev *dev, struct oce_rq *rq, int32_t timeout)
{
	int ti;
	_NOTE(ARGUNUSED(dev));

	for (ti = 0; ti < timeout; ti++) {
		if (rq->pending > 0) {
			OCE_MSDELAY(10);
			continue;
		} else {
			rq->pending = 0;
			break;
		}
	}
	return (rq->pending);
}
