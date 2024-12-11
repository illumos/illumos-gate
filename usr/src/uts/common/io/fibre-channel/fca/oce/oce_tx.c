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
 * Source file containing the implementation of the Transmit
 * Path
 */

#include <oce_impl.h>

static void oce_free_wqed(struct oce_wq *wq,  oce_wqe_desc_t *wqed);
static int oce_map_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed,
    mblk_t *mp, uint32_t pkt_len);
static int oce_bcopy_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed, mblk_t *mp,
    uint32_t pkt_len);
static void oce_wqb_dtor(struct oce_wq *wq, oce_wq_bdesc_t *wqbd);
static int oce_wqb_ctor(oce_wq_bdesc_t *wqbd, struct oce_wq *wq,
    size_t size, int flags);
static inline oce_wq_bdesc_t *oce_wqb_alloc(struct oce_wq *wq);
static void oce_wqb_free(struct oce_wq *wq, oce_wq_bdesc_t *wqbd);

static void oce_wqmd_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd);
static void oce_wqm_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd);
static oce_wq_mdesc_t *oce_wqm_alloc(struct oce_wq *wq);
static int oce_wqm_ctor(oce_wq_mdesc_t *wqmd, struct oce_wq *wq);
static void oce_wqm_dtor(struct oce_wq *wq, oce_wq_mdesc_t *wqmd);
static void oce_fill_ring_descs(struct oce_wq *wq, oce_wqe_desc_t *wqed);
static void oce_remove_vtag(mblk_t *mp);
static void oce_insert_vtag(mblk_t  *mp, uint16_t vlan_tag);
static inline int oce_process_tx_compl(struct oce_wq *wq, boolean_t rearm);


static ddi_dma_attr_t tx_map_dma_attr = {
	DMA_ATTR_V0,		/* version number */
	0x0000000000000000ull,	/* low address */
	0xFFFFFFFFFFFFFFFFull,	/* high address */
	0x0000000000010000ull,	/* dma counter max */
	OCE_TXMAP_ALIGN,	/* alignment */
	0x7FF,			/* burst sizes */
	0x00000001,		/* minimum transfer size */
	0x00000000FFFFFFFFull,	/* maximum transfer size */
	0xFFFFFFFFFFFFFFFFull,	/* maximum segment size */
	OCE_MAX_TXDMA_COOKIES,	/* scatter/gather list length */
	0x00000001,		/* granularity */
	DDI_DMA_FLAGERR		/* dma_attr_flags */
};


ddi_dma_attr_t oce_tx_dma_buf_attr = {
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
	DDI_DMA_FLAGERR		/* dma_attr_flags */
};

/*
 * WQ map handle destructor
 *
 * wq - Pointer to WQ structure
 * wqmd - pointer to WQE mapping handle descriptor
 *
 * return none
 */

static void
oce_wqm_dtor(struct oce_wq *wq, oce_wq_mdesc_t *wqmd)
{
	_NOTE(ARGUNUSED(wq));
	/* Free the DMA handle */
	if (wqmd->dma_handle != NULL)
		(void) ddi_dma_free_handle(&(wqmd->dma_handle));
	wqmd->dma_handle = NULL;
} /* oce_wqm_dtor */

/*
 * WQ map handles contructor
 *
 * wqmd - pointer to WQE mapping handle descriptor
 * wq - Pointer to WQ structure
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
static int
oce_wqm_ctor(oce_wq_mdesc_t *wqmd, struct oce_wq *wq)
{
	struct oce_dev *dev;
	int ret;

	dev = wq->parent;
	/* Allocate DMA handle */
	ret = ddi_dma_alloc_handle(dev->dip, &tx_map_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &wqmd->dma_handle);

	return (ret);
} /* oce_wqm_ctor */

/*
 * function to create WQ mapping handles cache
 *
 * wq - pointer to WQ structure
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
int
oce_wqm_cache_create(struct oce_wq *wq)
{
	struct oce_dev *dev = wq->parent;
	int size;
	int cnt;
	int ret;

	size = wq->cfg.nhdl * sizeof (oce_wq_mdesc_t);
	wq->wq_mdesc_array = kmem_zalloc(size, KM_NOSLEEP);
	if (wq->wq_mdesc_array == NULL) {
		return (DDI_FAILURE);
	}

	/* Create the free buffer list */
	OCE_LIST_CREATE(&wq->wq_mdesc_list, DDI_INTR_PRI(dev->intr_pri));

	for (cnt = 0; cnt < wq->cfg.nhdl; cnt++) {
		ret = oce_wqm_ctor(&wq->wq_mdesc_array[cnt], wq);
		if (ret != DDI_SUCCESS) {
			goto wqm_fail;
		}
		OCE_LIST_INSERT_TAIL(&wq->wq_mdesc_list,
		    &wq->wq_mdesc_array[cnt]);
	}
	return (DDI_SUCCESS);

wqm_fail:
	oce_wqm_cache_destroy(wq);
	return (DDI_FAILURE);
}

/*
 * function to destroy WQ mapping handles cache
 *
 * wq - pointer to WQ structure
 *
 * return none
 */
void
oce_wqm_cache_destroy(struct oce_wq *wq)
{
	oce_wq_mdesc_t *wqmd;

	while ((wqmd = OCE_LIST_REM_HEAD(&wq->wq_mdesc_list)) != NULL) {
		oce_wqm_dtor(wq, wqmd);
	}

	kmem_free(wq->wq_mdesc_array,
	    wq->cfg.nhdl * sizeof (oce_wq_mdesc_t));

	OCE_LIST_DESTROY(&wq->wq_mdesc_list);
}

/*
 * function to create  WQ buffer cache
 *
 * wq - pointer to WQ structure
 * buf_size - size of the buffer
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
int
oce_wqb_cache_create(struct oce_wq *wq, size_t buf_size)
{
	struct oce_dev *dev = wq->parent;
	int size;
	int cnt;
	int ret;

	size = wq->cfg.nbufs * sizeof (oce_wq_bdesc_t);
	wq->wq_bdesc_array = kmem_zalloc(size, KM_NOSLEEP);
	if (wq->wq_bdesc_array == NULL) {
		return (DDI_FAILURE);
	}

	/* Create the free buffer list */
	OCE_LIST_CREATE(&wq->wq_buf_list, DDI_INTR_PRI(dev->intr_pri));

	for (cnt = 0; cnt <  wq->cfg.nbufs; cnt++) {
		ret = oce_wqb_ctor(&wq->wq_bdesc_array[cnt],
		    wq, buf_size, DDI_DMA_STREAMING);
		if (ret != DDI_SUCCESS) {
			goto wqb_fail;
		}
		OCE_LIST_INSERT_TAIL(&wq->wq_buf_list,
		    &wq->wq_bdesc_array[cnt]);
	}
	return (DDI_SUCCESS);

wqb_fail:
	oce_wqb_cache_destroy(wq);
	return (DDI_FAILURE);
}

/*
 * function to destroy WQ buffer cache
 *
 * wq - pointer to WQ structure
 *
 * return none
 */
void
oce_wqb_cache_destroy(struct oce_wq *wq)
{
	oce_wq_bdesc_t *wqbd;
	while ((wqbd = OCE_LIST_REM_HEAD(&wq->wq_buf_list)) != NULL) {
		oce_wqb_dtor(wq, wqbd);
	}
	kmem_free(wq->wq_bdesc_array,
	    wq->cfg.nbufs * sizeof (oce_wq_bdesc_t));
	OCE_LIST_DESTROY(&wq->wq_buf_list);
}

/*
 * WQ buffer constructor
 *
 * wqbd - pointer to WQ buffer descriptor
 * wq - pointer to WQ structure
 * size - size of the buffer
 * flags - KM_SLEEP or KM_NOSLEEP
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
static int
oce_wqb_ctor(oce_wq_bdesc_t *wqbd, struct oce_wq *wq, size_t size, int flags)
{
	struct oce_dev *dev;
	dev = wq->parent;

	wqbd->wqb = oce_alloc_dma_buffer(dev, size, &oce_tx_dma_buf_attr,
	    flags);
	if (wqbd->wqb == NULL) {
		return (DDI_FAILURE);
	}
	wqbd->frag_addr.dw.addr_lo = ADDR_LO(wqbd->wqb->addr);
	wqbd->frag_addr.dw.addr_hi = ADDR_HI(wqbd->wqb->addr);
	return (DDI_SUCCESS);
}

/*
 * WQ buffer destructor
 *
 * wq - pointer to WQ structure
 * wqbd - pointer to WQ buffer descriptor
 *
 * return none
 */
static void
oce_wqb_dtor(struct oce_wq *wq, oce_wq_bdesc_t *wqbd)
{
	oce_free_dma_buffer(wq->parent, wqbd->wqb);
}

/*
 * function to alloc   WQE buffer descriptor
 *
 * wq - pointer to WQ structure
 *
 * return pointer to WQE buffer descriptor
 */
static inline oce_wq_bdesc_t *
oce_wqb_alloc(struct oce_wq *wq)
{
	return (OCE_LIST_REM_HEAD(&wq->wq_buf_list));
}

/*
 * function to free   WQE buffer descriptor
 *
 * wq - pointer to WQ structure
 * wqbd - pointer to WQ buffer descriptor
 *
 * return none
 */
static inline void
oce_wqb_free(struct oce_wq *wq, oce_wq_bdesc_t *wqbd)
{
	OCE_LIST_INSERT_TAIL(&wq->wq_buf_list, wqbd);
} /* oce_wqb_free */

/*
 * function to allocate   WQE mapping descriptor
 *
 * wq - pointer to WQ structure
 *
 * return pointer to WQE mapping descriptor
 */
static inline oce_wq_mdesc_t *
oce_wqm_alloc(struct oce_wq *wq)
{
	return (OCE_LIST_REM_HEAD(&wq->wq_mdesc_list));
} /* oce_wqm_alloc */

/*
 * function to insert	WQE mapping descriptor to the list
 *
 * wq - pointer to WQ structure
 * wqmd - Pointer to WQ mapping descriptor
 *
 * return none
 */
static inline void
oce_wqm_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd)
{
	OCE_LIST_INSERT_TAIL(&wq->wq_mdesc_list, wqmd);
}

/*
 * function to free  WQE mapping descriptor
 *
 * wq - pointer to WQ structure
 * wqmd - Pointer to WQ mapping descriptor
 *
 * return none
 */
static void
oce_wqmd_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd)
{
	if (wqmd == NULL) {
		return;
	}
	(void) ddi_dma_unbind_handle(wqmd->dma_handle);
	oce_wqm_free(wq, wqmd);
}

/*
 * WQED kmem_cache constructor
 *
 * buf - pointer to WQE descriptor
 *
 * return DDI_SUCCESS
 */
int
oce_wqe_desc_ctor(void *buf, void *arg, int kmflags)
{
	_NOTE(ARGUNUSED(buf));
	_NOTE(ARGUNUSED(arg));
	_NOTE(ARGUNUSED(kmflags));

	return (DDI_SUCCESS);
}

/*
 * WQED kmem_cache destructor
 *
 * buf - pointer to WQE descriptor
 *
 * return none
 */
void
oce_wqe_desc_dtor(void *buf, void *arg)
{
	_NOTE(ARGUNUSED(buf));
	_NOTE(ARGUNUSED(arg));
}

/*
 * function to choose a WQ given a mblk depending on priority, flowID etc.
 *
 * dev - software handle to device
 * mp - the mblk to send
 *
 * return pointer to the WQ selected
 */
static uint8_t oce_tx_hash_policy = 0x4;
struct oce_wq *
oce_get_wq(struct oce_dev *dev, mblk_t *mp)
{
	struct oce_wq *wq;
	int qidx = 0;
	if (dev->nwqs > 1) {
		qidx = mac_pkt_hash(DL_ETHER, mp, oce_tx_hash_policy, B_TRUE);
		qidx = qidx % dev->nwqs;

	} else {
		qidx = 0;
	}
	wq = dev->wq[qidx];
	/* for the time being hardcode */
	return (wq);
} /* oce_get_wq */

/*
 * function to populate the single WQE
 *
 * wq - pointer to wq
 * wqed - pointer to WQ entry  descriptor
 *
 * return none
 */
static void
oce_fill_ring_descs(struct oce_wq *wq, oce_wqe_desc_t *wqed)
{

	struct oce_nic_frag_wqe *wqe;
	int i;
	/* Copy the precreate WQE descs to the ring desc */
	for (i = 0; i < wqed->wqe_cnt; i++) {
		wqe = RING_GET_PRODUCER_ITEM_VA(wq->ring,
		    struct oce_nic_frag_wqe);

		bcopy(&wqed->frag[i], wqe, NIC_WQE_SIZE);
		RING_PUT(wq->ring, 1);
	}
} /* oce_fill_ring_descs */

/*
 * function to copy the packet to preallocated Tx buffer
 *
 * wq - pointer to WQ
 * wqed - Pointer to WQE descriptor
 * mp - Pointer to packet chain
 * pktlen - Size of the packet
 *
 * return 0=>success, error code otherwise
 */
static int
oce_bcopy_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed, mblk_t *mp,
    uint32_t pkt_len)
{
	oce_wq_bdesc_t *wqbd;
	caddr_t buf_va;
	struct oce_dev *dev = wq->parent;
	int len = 0;

	wqbd = oce_wqb_alloc(wq);
	if (wqbd == NULL) {
		atomic_inc_32(&dev->tx_noxmtbuf);
		oce_log(dev, CE_WARN, MOD_TX, "%s",
		    "wqb pool empty");
		return (ENOMEM);
	}

	/* create a fragment wqe for the packet */
	wqed->frag[wqed->frag_idx].u0.s.frag_pa_hi = wqbd->frag_addr.dw.addr_hi;
	wqed->frag[wqed->frag_idx].u0.s.frag_pa_lo = wqbd->frag_addr.dw.addr_lo;
	buf_va = DBUF_VA(wqbd->wqb);

	/* copy pkt into buffer */
	for (len = 0; mp != NULL && len < pkt_len; mp = mp->b_cont) {
		bcopy(mp->b_rptr, buf_va, MBLKL(mp));
		buf_va += MBLKL(mp);
		len += MBLKL(mp);
	}

	(void) ddi_dma_sync(DBUF_DHDL(wqbd->wqb), 0, pkt_len,
	    DDI_DMA_SYNC_FORDEV);

	if (oce_fm_check_dma_handle(dev, DBUF_DHDL(wqbd->wqb))) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		/* Free the buffer */
		oce_wqb_free(wq, wqbd);
		return (EIO);
	}
	wqed->frag[wqed->frag_idx].u0.s.frag_len   =  pkt_len;
	wqed->hdesc[wqed->nhdl].hdl = (void *)(wqbd);
	wqed->hdesc[wqed->nhdl].type = COPY_WQE;
	wqed->frag_cnt++;
	wqed->frag_idx++;
	wqed->nhdl++;
	return (0);
} /* oce_bcopy_wqe */

/*
 * function to copy the packet or dma map on the fly depending on size
 *
 * wq - pointer to WQ
 * wqed - Pointer to WQE descriptor
 * mp - Pointer to packet chain
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
static  int
oce_map_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed, mblk_t *mp,
    uint32_t pkt_len)
{
	ddi_dma_cookie_t cookie;
	oce_wq_mdesc_t *wqmd;
	uint32_t ncookies;
	int ret;
	struct oce_dev *dev = wq->parent;

	wqmd = oce_wqm_alloc(wq);
	if (wqmd == NULL) {
		oce_log(dev, CE_WARN, MOD_TX, "%s",
		    "wqm pool empty");
		return (ENOMEM);
	}

	ret = ddi_dma_addr_bind_handle(wqmd->dma_handle,
	    (struct as *)0, (caddr_t)mp->b_rptr,
	    pkt_len, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, &cookie, &ncookies);
	if (ret != DDI_DMA_MAPPED) {
		oce_log(dev, CE_WARN, MOD_TX, "MAP FAILED %d",
		    ret);
		/* free the last one */
		oce_wqm_free(wq, wqmd);
		return (ENOMEM);
	}
	do {
		wqed->frag[wqed->frag_idx].u0.s.frag_pa_hi =
		    ADDR_HI(cookie.dmac_laddress);
		wqed->frag[wqed->frag_idx].u0.s.frag_pa_lo =
		    ADDR_LO(cookie.dmac_laddress);
		wqed->frag[wqed->frag_idx].u0.s.frag_len =
		    (uint32_t)cookie.dmac_size;
		wqed->frag_cnt++;
		wqed->frag_idx++;
		if (--ncookies > 0)
			ddi_dma_nextcookie(wqmd->dma_handle,
			    &cookie);
			else break;
	} while (ncookies > 0);

	wqed->hdesc[wqed->nhdl].hdl = (void *)wqmd;
	wqed->hdesc[wqed->nhdl].type = MAPPED_WQE;
	wqed->nhdl++;
	return (0);
} /* oce_map_wqe */

static inline int
oce_process_tx_compl(struct oce_wq *wq, boolean_t rearm)
{
	struct oce_nic_tx_cqe *cqe;
	uint16_t num_cqe = 0;
	struct oce_cq *cq;
	oce_wqe_desc_t *wqed;
	int wqe_freed = 0;
	struct oce_dev *dev;

	cq  = wq->cq;
	dev = wq->parent;
	(void) ddi_dma_sync(cq->ring->dbuf->dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);

	mutex_enter(&wq->txc_lock);
	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_nic_tx_cqe);
	while (WQ_CQE_VALID(cqe)) {

		DW_SWAP(u32ptr(cqe), sizeof (struct oce_nic_tx_cqe));

		/* update stats */
		if (cqe->u0.s.status != 0) {
			atomic_inc_32(&dev->tx_errors);
		}

		/* complete the WQEs */
		wqed = OCE_LIST_REM_HEAD(&wq->wqe_desc_list);

		wqe_freed = wqed->wqe_cnt;
		oce_free_wqed(wq, wqed);
		RING_GET(wq->ring, wqe_freed);
		atomic_add_32(&wq->wq_free, wqe_freed);
		/* clear the valid bit and progress cqe */
		WQ_CQE_INVALIDATE(cqe);
		RING_GET(cq->ring, 1);
		cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring,
		    struct oce_nic_tx_cqe);
		num_cqe++;
	} /* for all valid CQE */
	mutex_exit(&wq->txc_lock);
	if (num_cqe)
		oce_arm_cq(wq->parent, cq->cq_id, num_cqe, rearm);
	return (num_cqe);
} /* oce_process_tx_completion */

/*
 * function to drain a TxCQ and process its CQEs
 *
 * dev - software handle to the device
 * cq - pointer to the cq to drain
 *
 * return the number of CQEs processed
 */
uint16_t
oce_drain_wq_cq(void *arg)
{
	uint16_t num_cqe = 0;
	struct oce_dev *dev;
	struct oce_wq *wq;

	wq = (struct oce_wq *)arg;
	dev = wq->parent;

	/* do while we do not reach a cqe that is not valid */
	num_cqe = oce_process_tx_compl(wq, B_FALSE);

	/* check if we need to restart Tx */
	if (wq->resched && num_cqe) {
		wq->resched = B_FALSE;
		mac_tx_update(dev->mac_handle);
	}

	return (num_cqe);
} /* oce_process_wq_cqe */

/*
 * function to insert vtag to packet
 *
 * mp - mblk pointer
 * vlan_tag - tag to be inserted
 *
 * return none
 */
static inline void
oce_insert_vtag(mblk_t *mp, uint16_t vlan_tag)
{
	struct ether_vlan_header  *evh;
	(void) memmove(mp->b_rptr - VTAG_SIZE,
	    mp->b_rptr, 2 * ETHERADDRL);
	mp->b_rptr -= VTAG_SIZE;
	evh = (struct ether_vlan_header *)(void *)mp->b_rptr;
	evh->ether_tpid = htons(VLAN_TPID);
	evh->ether_tci = htons(vlan_tag);
}

/*
 * function to strip  vtag from packet
 *
 * mp - mblk pointer
 *
 * return none
 */

static inline void
oce_remove_vtag(mblk_t *mp)
{
	(void) memmove(mp->b_rptr + VTAG_SIZE, mp->b_rptr,
	    ETHERADDRL * 2);
	mp->b_rptr += VTAG_SIZE;
}

/*
 * function to xmit  Single packet over the wire
 *
 * wq - pointer to WQ
 * mp - Pointer to packet chain
 *
 * return pointer to the packet
 */
mblk_t *
oce_send_packet(struct oce_wq *wq, mblk_t *mp)
{
	struct oce_nic_hdr_wqe *wqeh;
	struct oce_dev *dev;
	struct ether_header *eh;
	struct ether_vlan_header *evh;
	int32_t num_wqes;
	uint16_t etype;
	uint32_t ip_offset;
	uint32_t csum_flags = 0;
	boolean_t use_copy = B_FALSE;
	boolean_t tagged   = B_FALSE;
	uint16_t  vlan_tag;
	uint32_t  reg_value = 0;
	oce_wqe_desc_t *wqed = NULL;
	mblk_t *nmp = NULL;
	mblk_t *tmp = NULL;
	uint32_t pkt_len = 0;
	int num_mblks = 0;
	int ret = 0;
	uint32_t mss = 0;
	uint32_t flags = 0;
	int len = 0;

	/* retrieve the adap priv struct ptr */
	dev = wq->parent;

	/* check if we have enough free slots */
	if (wq->wq_free < dev->tx_reclaim_threshold) {
		(void) oce_process_tx_compl(wq, B_FALSE);
	}
	if (wq->wq_free < OCE_MAX_TX_HDL) {
		return (mp);
	}

	/* check if we should copy */
	for (tmp = mp; tmp != NULL; tmp = tmp->b_cont) {
		pkt_len += MBLKL(tmp);
		num_mblks++;
	}

	if (pkt_len == 0 || num_mblks == 0) {
		freemsg(mp);
		return (NULL);
	}

	/* retrieve LSO information */
	mac_lso_get(mp, &mss, &flags);

	/* get the offload flags */
	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &csum_flags);

	/* restrict the mapped segment to wat we support */
	if (num_mblks  > OCE_MAX_TX_HDL) {
		nmp = msgpullup(mp, -1);
		if (nmp == NULL) {
			atomic_inc_32(&wq->pkt_drops);
			freemsg(mp);
			return (NULL);
		}
		/* Reset it to new collapsed mp */
		freemsg(mp);
		mp = nmp;
	}

	/* Get the packet descriptor for Tx */
	wqed = kmem_cache_alloc(wq->wqed_cache, KM_NOSLEEP);
	if (wqed == NULL) {
		atomic_inc_32(&wq->pkt_drops);
		freemsg(mp);
		return (NULL);
	}
	eh = (struct ether_header *)(void *)mp->b_rptr;
	if (ntohs(eh->ether_type) == VLAN_TPID) {
		evh = (struct ether_vlan_header *)(void *)mp->b_rptr;
		tagged = B_TRUE;
		etype = ntohs(evh->ether_type);
		ip_offset = sizeof (struct ether_vlan_header);
		pkt_len -= VTAG_SIZE;
		vlan_tag = ntohs(evh->ether_tci);
		oce_remove_vtag(mp);
	} else {
		etype = ntohs(eh->ether_type);
		ip_offset = sizeof (struct ether_header);
	}

	/* Save the WQ pointer */
	wqed->wq = wq;
	wqed->frag_idx = 1; /* index zero is always header */
	wqed->frag_cnt = 0;
	wqed->nhdl = 0;
	wqed->mp = NULL;
	OCE_LIST_LINK_INIT(&wqed->link);

	/* If entire packet is less than the copy limit  just do copy */
	if (pkt_len < dev->tx_bcopy_limit) {
		use_copy = B_TRUE;
		ret = oce_bcopy_wqe(wq, wqed, mp, pkt_len);
	} else {
		/* copy or dma map the individual fragments */
		for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
			len = MBLKL(nmp);
			if (len == 0) {
				continue;
			}
			if (len < dev->tx_bcopy_limit) {
				ret = oce_bcopy_wqe(wq, wqed, nmp, len);
			} else {
				ret = oce_map_wqe(wq, wqed, nmp, len);
			}
			if (ret != 0)
				break;
		}
	}

	/*
	 * Any failure other than insufficient Q entries
	 * drop the packet
	 */
	if (ret != 0) {
		oce_free_wqed(wq, wqed);
		atomic_inc_32(&wq->pkt_drops);
		freemsg(mp);
		return (NULL);
	}

	wqeh = (struct oce_nic_hdr_wqe *)&wqed->frag[0];
	bzero(wqeh, sizeof (struct oce_nic_hdr_wqe));

	/* fill rest of wqe header fields based on packet */
	if (flags & HW_LSO) {
		wqeh->u0.s.lso = B_TRUE;
		wqeh->u0.s.lso_mss = mss;
	}
	if (csum_flags & HCK_FULLCKSUM) {
		uint8_t *proto;
		if (etype == ETHERTYPE_IP) {
			proto = (uint8_t *)(void *)
			    (mp->b_rptr + ip_offset);
			if (proto[9] == 6)
				/* IPPROTO_TCP */
				wqeh->u0.s.tcpcs = B_TRUE;
			else if (proto[9] == 17)
				/* IPPROTO_UDP */
				wqeh->u0.s.udpcs = B_TRUE;
		}
	}

	if (csum_flags & HCK_IPV4_HDRCKSUM)
		wqeh->u0.s.ipcs = B_TRUE;
	if (tagged) {
		wqeh->u0.s.vlan = B_TRUE;
		wqeh->u0.s.vlan_tag = vlan_tag;
	}

	wqeh->u0.s.complete = B_TRUE;
	wqeh->u0.s.event = B_TRUE;
	wqeh->u0.s.crc = B_TRUE;
	wqeh->u0.s.total_length = pkt_len;

	num_wqes = wqed->frag_cnt + 1;

	/* h/w expects even no. of WQEs */
	if (num_wqes & 0x1) {
		bzero(&wqed->frag[num_wqes], sizeof (struct oce_nic_frag_wqe));
		num_wqes++;
	}
	wqed->wqe_cnt = (uint16_t)num_wqes;
	wqeh->u0.s.num_wqe = num_wqes;
	DW_SWAP(u32ptr(&wqed->frag[0]), (wqed->wqe_cnt * NIC_WQE_SIZE));

	mutex_enter(&wq->tx_lock);
	if (num_wqes > wq->wq_free) {
		atomic_inc_32(&wq->tx_deferd);
		mutex_exit(&wq->tx_lock);
		goto wqe_fail;
	}
	atomic_add_32(&wq->wq_free, -num_wqes);

	/* fill the wq for adapter */
	oce_fill_ring_descs(wq, wqed);

	/* Set the mp pointer in the wqe descriptor */
	if (use_copy == B_FALSE) {
		wqed->mp = mp;
	}
	/* Add the packet desc to list to be retrieved during cmpl */
	OCE_LIST_INSERT_TAIL(&wq->wqe_desc_list,  wqed);
	(void) ddi_dma_sync(wq->ring->dbuf->dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	/* ring tx doorbell */
	reg_value = (num_wqes << 16) | wq->wq_id;
	/* Ring the door bell  */
	OCE_DB_WRITE32(dev, PD_TXULP_DB, reg_value);
	mutex_exit(&wq->tx_lock);
	if (oce_fm_check_acc_handle(dev, dev->db_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}

	/* free mp if copied or packet chain collapsed */
	if (use_copy == B_TRUE) {
		freemsg(mp);
	}
	return (NULL);

wqe_fail:

	if (tagged) {
		oce_insert_vtag(mp, vlan_tag);
	}
	oce_free_wqed(wq, wqed);
	return (mp);
} /* oce_send_packet */

/*
 * function to free the WQE descriptor
 *
 * wq - pointer to WQ
 * wqed - Pointer to WQE descriptor
 *
 * return none
 */
static void
oce_free_wqed(struct oce_wq *wq, oce_wqe_desc_t *wqed)
{
	int i = 0;
	if (wqed == NULL) {
		return;
	}

	for (i = 0; i < wqed->nhdl; i++) {
		if (wqed->hdesc[i].type == COPY_WQE) {
			oce_wqb_free(wq, wqed->hdesc[i].hdl);
		} else if (wqed->hdesc[i].type == MAPPED_WQE) {
			oce_wqmd_free(wq, wqed->hdesc[i].hdl);
		}
	}
	if (wqed->mp)
		freemsg(wqed->mp);
	kmem_cache_free(wq->wqed_cache, wqed);
} /* oce_free_wqed */

/*
 * function to start the WQ
 *
 * wq - pointer to WQ
 *
 * return DDI_SUCCESS
 */

int
oce_start_wq(struct oce_wq *wq)
{
	_NOTE(ARGUNUSED(wq));
	return (DDI_SUCCESS);
} /* oce_start_wq */

/*
 * function to stop  the WQ
 *
 * wq - pointer to WQ
 *
 * return none
 */
void
oce_clean_wq(struct oce_wq *wq)
{
	oce_wqe_desc_t *wqed;
	int ti;

	/* Wait for already posted Tx to complete */

	for (ti = 0; ti < DEFAULT_DRAIN_TIME; ti++) {
		(void) oce_process_tx_compl(wq, B_FALSE);
		OCE_MSDELAY(1);
	}

	/* Free the remaining descriptors */
	while ((wqed = OCE_LIST_REM_HEAD(&wq->wqe_desc_list)) != NULL) {
		atomic_add_32(&wq->wq_free, wqed->wqe_cnt);
		oce_free_wqed(wq, wqed);
	}
	oce_drain_eq(wq->cq->eq);
} /* oce_stop_wq */

/*
 * function to set the tx mapping handle fma attr
 *
 * fm_caps - capability flags
 *
 * return none
 */

void
oce_set_tx_map_dma_fma_flags(int fm_caps)
{
	if (fm_caps == DDI_FM_NOT_CAPABLE) {
		return;
	}

	if (DDI_FM_DMA_ERR_CAP(fm_caps)) {
		tx_map_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
	} else {
		tx_map_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	}
} /* oce_set_tx_map_dma_fma_flags */
