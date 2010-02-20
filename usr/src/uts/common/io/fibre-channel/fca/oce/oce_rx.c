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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the Recieve Path handling
 * functions
 */
#include <oce_impl.h>


static void rx_pool_free(char *arg);
static inline mblk_t *oce_rx(struct oce_dev *dev, struct oce_rq *rq,
    struct oce_nic_rx_cqe *cqe);
static inline mblk_t *oce_rx_bcopy(struct oce_dev *dev,
	struct oce_rq *rq, struct oce_nic_rx_cqe *cqe);
static int oce_rq_charge(struct oce_dev *dev, struct oce_rq *rq,
    uint32_t nbufs);
static oce_rq_bdesc_t *oce_rqb_alloc(struct oce_rq *rq);
static void oce_rqb_free(struct oce_rq *rq, oce_rq_bdesc_t *rqbd);
static void oce_rqb_dtor(oce_rq_bdesc_t *rqbd);
static int oce_rqb_ctor(oce_rq_bdesc_t *rqbd, struct oce_rq *rq,
    size_t size, int flags);
static void oce_rx_insert_tag(mblk_t *mp, uint16_t vtag);
static void oce_set_rx_oflags(mblk_t *mp, struct oce_nic_rx_cqe *cqe);
static inline void oce_rx_drop_pkt(struct oce_rq *rq,
    struct oce_nic_rx_cqe *cqe);


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
	struct oce_dev *dev = rq->parent;
	int size;
	int cnt;
	int ret;
	int nitems;

	nitems = rq->cfg.nbufs;
	size = nitems * sizeof (oce_rq_bdesc_t);
	rq->rq_bdesc_array = kmem_zalloc(size, KM_SLEEP);

	/* Create the free buffer list */
	OCE_LIST_CREATE(&rq->rq_buf_list, DDI_INTR_PRI(dev->intr_pri));

	for (cnt = 0; cnt < nitems; cnt++) {
		ret = oce_rqb_ctor(&rq->rq_bdesc_array[cnt],
		    rq, buf_size, DDI_DMA_STREAMING);
		if (ret != DDI_SUCCESS) {
			goto rqb_fail;
		}
		OCE_LIST_INSERT_TAIL(&rq->rq_buf_list,
		    &(rq->rq_bdesc_array[cnt].link));
	}
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

	while ((rqbd = (oce_rq_bdesc_t *)OCE_LIST_REM_HEAD(&rq->rq_buf_list))
	    != NULL) {
		oce_rqb_dtor(rqbd);
	}
	kmem_free(rq->rq_bdesc_array,
	    rq->cfg.nbufs * sizeof (oce_rq_bdesc_t));
	OCE_LIST_DESTROY(&rq->rq_buf_list);
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
	oce_free_dma_buffer(rqbd->rq->parent, rqbd->rqb);
	if (rqbd->mp != NULL) {
		/* Buffer is already free  */
		rqbd->fr_rtn.free_arg = NULL;
		freeb(rqbd->mp);
	}
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

	dbuf  = oce_alloc_dma_buffer(dev, size, flags);
	if (dbuf == NULL) {
		return (DDI_FAILURE);
	}

	/* override usable length */
	rqbd->rqb = dbuf;
	rqbd->rq = rq;
	rqbd->frag_addr.dw.addr_lo = ADDR_LO(dbuf->addr + OCE_RQE_BUF_HEADROOM);
	rqbd->frag_addr.dw.addr_hi = ADDR_HI(dbuf->addr + OCE_RQE_BUF_HEADROOM);
	rqbd->fr_rtn.free_func = (void (*)())rx_pool_free;
	rqbd->fr_rtn.free_arg = (caddr_t)(void *)rqbd;
	rqbd->mp = desballoc((uchar_t *)(rqbd->rqb->base),
	    rqbd->rqb->size, 0, &rqbd->fr_rtn);
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
	rqbd = OCE_LIST_REM_HEAD(&rq->rq_buf_list);
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
	OCE_LIST_INSERT_TAIL(&rq->rq_buf_list, rqbd);
} /* oce_rqb_free */


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
oce_rq_charge(struct oce_dev *dev,
    struct oce_rq *rq, uint32_t nbufs)
{
	struct oce_nic_rqe *rqe;
	oce_rq_bdesc_t *rqbd;
	struct rq_shadow_entry	*shadow_rq;
	int32_t num_bufs = 0;
	int32_t total_bufs = 0;
	pd_rxulp_db_t rxdb_reg;
	uint32_t cnt;

	shadow_rq = rq->shadow_ring;
	/* check number of slots free and recharge */
	nbufs = ((rq->buf_avail + nbufs) > rq->cfg.q_len) ?
	    (rq->cfg.q_len - rq->buf_avail) : nbufs;
	for (cnt = 0; cnt < nbufs; cnt++) {
		rqbd = oce_rqb_alloc(rq);
		if (rqbd == NULL) {
			oce_log(dev, CE_NOTE, MOD_RX, "%s %x",
			    "rqb pool empty @ ticks",
			    (uint32_t)ddi_get_lbolt());
			break;
		}
		if (rqbd->mp == NULL) {
			rqbd->mp = desballoc((uchar_t *)(rqbd->rqb->base),
			    rqbd->rqb->size, 0, &rqbd->fr_rtn);
			if (rqbd->mp != NULL) {
				rqbd->mp->b_rptr =
				    (uchar_t *)rqbd->rqb->base +
				    OCE_RQE_BUF_HEADROOM;
			}

			/*
			 * Failed again put back the buffer and continue
			 * loops for nbufs so its a finite loop
			 */

			if (rqbd->mp == NULL) {
				oce_rqb_free(rq, rqbd);
				continue;
			}
		}

		/* fill the rqes */
		rqe = RING_GET_PRODUCER_ITEM_VA(rq->ring,
		    struct oce_nic_rqe);
		rqe->u0.s.frag_pa_lo = rqbd->frag_addr.dw.addr_lo;
		rqe->u0.s.frag_pa_hi = rqbd->frag_addr.dw.addr_hi;
		shadow_rq[rq->ring->pidx].rqbd = rqbd;
		DW_SWAP(u32ptr(rqe), sizeof (struct oce_nic_rqe));
		RING_PUT(rq->ring, 1);

		/* if we have reached the max allowed posts, post */
		if (cnt && !(cnt % OCE_MAX_RQ_POSTS)) {
			rxdb_reg.dw0 = 0;
			rxdb_reg.bits.num_posted = num_bufs;
			rxdb_reg.bits.qid = rq->rq_id & DB_RQ_ID_MASK;
			OCE_DB_WRITE32(dev, PD_RXULP_DB, rxdb_reg.dw0);
			num_bufs = 0;
		}
		num_bufs++;
		total_bufs++;
	}

	/* post pending bufs */
	if (num_bufs) {
		rxdb_reg.dw0 = 0;
		rxdb_reg.bits.num_posted = num_bufs;
		rxdb_reg.bits.qid = rq->rq_id & DB_RQ_ID_MASK;
		OCE_DB_WRITE32(dev, PD_RXULP_DB, rxdb_reg.dw0);
	}
	atomic_add_32(&rq->buf_avail, total_bufs);
	return (total_bufs);
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
	struct rq_shadow_entry *shadow_rq;

	shadow_rq = rq->shadow_ring;
	/* Free the posted buffer since RQ is destroyed already */
	while ((int32_t)rq->buf_avail > 0) {
		rqbd = shadow_rq[rq->ring->cidx].rqbd;
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
	mblk_t *mblk_prev = NULL;
	mblk_t	*mblk_head = NULL;
	int frag_size;
	struct rq_shadow_entry *shadow_rq;
	struct rq_shadow_entry *shadow_rqe;
	oce_rq_bdesc_t *rqbd;

	/* Get the relevant Queue pointers */
	shadow_rq = rq->shadow_ring;
	pkt_len = cqe->u0.s.pkt_size;
	for (; frag_cnt < cqe->u0.s.num_fragments; frag_cnt++) {
		shadow_rqe = &shadow_rq[rq->ring->cidx];
		rqbd = shadow_rqe->rqbd;
		mp = rqbd->mp;
		if (mp == NULL)
			return (NULL);
		frag_size  = (pkt_len > rq->cfg.frag_size) ?
		    rq->cfg.frag_size : pkt_len;
		mp->b_wptr = mp->b_rptr + frag_size;
		pkt_len   -= frag_size;
		/* Chain the message mblks */
		if (mblk_head == NULL) {
			mblk_head = mblk_prev = mp;
		} else {
			mblk_prev->b_cont = mp;
			mblk_prev = mp;
		}
		(void) ddi_dma_sync(rqbd->rqb->dma_handle, 0, frag_size,
		    DDI_DMA_SYNC_FORKERNEL);
		RING_GET(rq->ring, 1);
	}

	if (mblk_head == NULL) {
		oce_log(dev, CE_WARN, MOD_RX, "%s", "oce_rx:no frags?");
		return (NULL);
	}
	atomic_add_32(&rq->pending, (cqe->u0.s.num_fragments & 0x7));
	mblk_head->b_next = NULL;
	return (mblk_head);
} /* oce_rx */

/* ARGSUSED */
static inline mblk_t *
oce_rx_bcopy(struct oce_dev *dev, struct oce_rq *rq, struct oce_nic_rx_cqe *cqe)
{
	mblk_t *mp;
	int pkt_len;
	int alloc_len;
	int32_t frag_cnt = 0;
	int frag_size;
	struct rq_shadow_entry *shadow_rq;
	struct rq_shadow_entry *shadow_rqe;
	oce_rq_bdesc_t *rqbd;
	boolean_t tag_present =  B_FALSE;
	unsigned char  *rptr;

	shadow_rq = rq->shadow_ring;
	pkt_len = cqe->u0.s.pkt_size;
	alloc_len = pkt_len;

	/* Hardware always Strips Vlan tag so insert it back */
	if (cqe->u0.s.vlan_tag_present) {
		alloc_len += VLAN_TAGSZ;
		tag_present = B_TRUE;
	}
	mp = allocb(alloc_len, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	if (tag_present) {
		/* offset the read pointer by 4 bytes to insert tag */
		mp->b_rptr += VLAN_TAGSZ;
	}
	rptr = mp->b_rptr;
	mp->b_wptr = mp->b_wptr + alloc_len;

	for (frag_cnt = 0; frag_cnt < cqe->u0.s.num_fragments; frag_cnt++) {
		shadow_rqe = &shadow_rq[rq->ring->cidx];
		rqbd = shadow_rqe->rqbd;
		frag_size  = (pkt_len > rq->cfg.frag_size) ?
		    rq->cfg.frag_size : pkt_len;
		(void) ddi_dma_sync(rqbd->rqb->dma_handle, 0, frag_size,
		    DDI_DMA_SYNC_FORKERNEL);
		bcopy(rqbd->rqb->base + OCE_RQE_BUF_HEADROOM,
		    rptr, frag_size);
		rptr += frag_size;
		pkt_len   -= frag_size;
		oce_rqb_free(rq, rqbd);
		RING_GET(rq->ring, 1);
	}
	return (mp);
}

static inline void
oce_set_rx_oflags(mblk_t *mp, struct oce_nic_rx_cqe *cqe)
{
	int csum_flags = 0;

	/* set flags */
	if (cqe->u0.s.ip_cksum_pass) {
		csum_flags |= HCK_IPV4_HDRCKSUM;
	}

	if (cqe->u0.s.l4_cksum_pass) {
		csum_flags |= (HCK_FULLCKSUM | HCK_FULLCKSUM_OK);
	}

	if (csum_flags) {
		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0,
		    csum_flags, 0);
	}
}

static inline void
oce_rx_insert_tag(mblk_t *mp, uint16_t vtag)
{
	struct ether_vlan_header *ehp;

	(void) memmove(mp->b_rptr - VLAN_TAGSZ,
	    mp->b_rptr, 2 * ETHERADDRL);
	mp->b_rptr -= VLAN_TAGSZ;
	ehp = (struct ether_vlan_header *)voidptr(mp->b_rptr);
	ehp->ether_tpid = htons(ETHERTYPE_VLAN);
	ehp->ether_tci = LE_16(vtag);
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
	mblk_t *mblk_head  = NULL;
	mblk_t *mblk_prev  = NULL;
	uint16_t num_cqe = 0;
	struct oce_cq  *cq;
	struct oce_dev *dev;

	if (arg == NULL)
		return (0);

	rq = (struct oce_rq *)arg;
	dev = rq->parent;
	cq = rq->cq;
	mutex_enter(&rq->rx_lock);
	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_nic_rx_cqe);

	/* dequeue till you reach an invalid cqe */
	while (RQ_CQE_VALID(cqe) && (num_cqe < rq->cfg.q_len)) {
		DW_SWAP(u32ptr(cqe), sizeof (struct oce_nic_rx_cqe));
		/* if insufficient buffers to charge then do copy */
		if (cqe->u0.s.pkt_size < dev->rx_bcopy_limit ||
		    OCE_LIST_SIZE(&rq->rq_buf_list) < cqe->u0.s.num_fragments) {
			mp = oce_rx_bcopy(dev, rq, cqe);
		} else {
			mp = oce_rx(dev, rq, cqe);
		}
		if (mp != NULL) {
			if (cqe->u0.s.vlan_tag_present) {
				oce_rx_insert_tag(mp, cqe->u0.s.vlan_tag);
			}
			oce_set_rx_oflags(mp, cqe);
			if (mblk_head == NULL) {
				mblk_head = mblk_prev  = mp;
			} else {
				mblk_prev->b_next = mp;
				mblk_prev = mp;
			}

		} else {
			oce_rx_drop_pkt(rq, cqe);
		}
		atomic_add_32(&rq->buf_avail, -(cqe->u0.s.num_fragments & 0x7));
		(void) oce_rq_charge(dev, rq,
		    (cqe->u0.s.num_fragments & 0x7));
		RQ_CQE_INVALIDATE(cqe);
		RING_GET(cq->ring, 1);
		cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring,
		    struct oce_nic_rx_cqe);
		num_cqe++;
	} /* for all valid CQEs */
	mutex_exit(&rq->rx_lock);
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
static void
rx_pool_free(char *arg)
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

	rqbd->mp = desballoc((uchar_t *)(rqbd->rqb->base),
	    rqbd->rqb->size, 0, &rqbd->fr_rtn);
	if (rqbd->mp != NULL) {
		rqbd->mp->b_rptr = (uchar_t *)rqbd->rqb->base +
		    OCE_RQE_BUF_HEADROOM;
	}
	oce_rqb_free(rq, rqbd);
	(void) atomic_add_32(&rq->pending, -1);
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
#if 0
	if (num_cqe) {
		oce_arm_cq(dev, cq->cq_id, num_cqe, B_FALSE);
	}
	/* Drain the Event queue now */
	oce_drain_eq(rq->cq->eq);
	return (num_cqe);
#endif
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
	struct oce_dev *dev = rq->parent;

	(void) oce_rq_charge(dev, rq, rq->cfg.q_len);
	oce_arm_cq(dev, rq->cq->cq_id, 0, B_TRUE);
	return (ret);
} /* oce_start_rq */

/* Checks for pending rx buffers with Stack */
int
oce_rx_pending(struct oce_dev *dev)
{
	int ti;

	for (ti = 0; ti < 200; ti++) {
		if (dev->rq[0]->pending > 0) {
			OCE_MSDELAY(1);
			continue;
		} else {
			dev->rq[0]->pending = 0;
			break;
		}
	}
	return (dev->rq[0]->pending);
}

static inline void
oce_rx_drop_pkt(struct oce_rq *rq, struct oce_nic_rx_cqe *cqe)
{
	int frag_cnt;
	oce_rq_bdesc_t *rqbd;
	struct rq_shadow_entry *shadow_rq;
	shadow_rq = rq->shadow_ring;
	for (frag_cnt = 0; frag_cnt < cqe->u0.s.num_fragments; frag_cnt++) {
		rqbd = shadow_rq[rq->ring->cidx].rqbd;
		oce_rqb_free(rq, rqbd);
		RING_GET(rq->ring, 1);
	}
}
