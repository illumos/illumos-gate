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

#include "nge.h"

#undef	NGE_DBG
#define	NGE_DBG		NGE_DBG_RECV

#define	RXD_END		0x20000000
#define	RXD_ERR		0x40000000
#define	RXD_OWN		0x80000000
#define	RXD_CSUM_MSK	0x1C000000
#define	RXD_BCNT_MSK	0x00003FFF

#define	RXD_CK8G_NO_HSUM	0x0
#define	RXD_CK8G_TCP_SUM_ERR	0x04000000
#define	RXD_CK8G_UDP_SUM_ERR	0x08000000
#define	RXD_CK8G_IP_HSUM_ERR	0x0C000000
#define	RXD_CK8G_IP_HSUM	0x10000000
#define	RXD_CK8G_TCP_SUM	0x14000000
#define	RXD_CK8G_UDP_SUM	0x18000000
#define	RXD_CK8G_RESV		0x1C000000

extern ddi_device_acc_attr_t nge_data_accattr;

/*
 * Callback code invoked from STREAMs when the recv data buffer is free for
 * recycling.
 *
 * The following table describes function behaviour:
 *
 *                      | mac stopped | mac running
 * ---------------------------------------------------
 * buffer delivered     | free buffer | recycle buffer
 * buffer not delivered | do nothing  | recycle buffer (*)
 *
 * Note (*):
 *   Recycle buffer only if mac state did not change during execution of
 *   function. Otherwise if mac state changed, set buffer delivered & re-enter
 *   function by calling freemsg().
 */

void
nge_recv_recycle(caddr_t arg)
{
	boolean_t val;
	boolean_t valid;
	nge_t *ngep;
	dma_area_t *bufp;
	buff_ring_t *brp;
	nge_sw_statistics_t *sw_stp;

	bufp = (dma_area_t *)arg;
	ngep = (nge_t *)bufp->private;
	brp = ngep->buff;
	sw_stp = &ngep->statistics.sw_statistics;

	/*
	 * Free the buffer directly if the buffer was allocated
	 * previously or mac was stopped.
	 */
	if (bufp->signature != brp->buf_sign) {
		if (bufp->rx_delivered == B_TRUE) {
			nge_free_dma_mem(bufp);
			kmem_free(bufp, sizeof (dma_area_t));
			val = nge_atomic_decrease(&brp->rx_hold, 1);
			ASSERT(val == B_TRUE);
		}
		return;
	}

	/*
	 * recycle the data buffer again and fill them in free ring
	 */
	bufp->rx_recycle.free_func = nge_recv_recycle;
	bufp->rx_recycle.free_arg = (caddr_t)bufp;

	bufp->mp = desballoc(DMA_VPTR(*bufp),
	    ngep->buf_size + NGE_HEADROOM, 0, &bufp->rx_recycle);

	if (bufp->mp == NULL) {
		sw_stp->mp_alloc_err++;
		sw_stp->recy_free++;
		nge_free_dma_mem(bufp);
		kmem_free(bufp, sizeof (dma_area_t));
		val = nge_atomic_decrease(&brp->rx_hold, 1);
		ASSERT(val == B_TRUE);
	} else {

		mutex_enter(brp->recycle_lock);
		if (bufp->signature != brp->buf_sign)
			valid = B_TRUE;
		else
			valid = B_FALSE;
		bufp->rx_delivered = valid;
		if (bufp->rx_delivered == B_FALSE)  {
			bufp->next = brp->recycle_list;
			brp->recycle_list = bufp;
		}
		mutex_exit(brp->recycle_lock);
		if (valid == B_TRUE)
			/* call nge_rx_recycle again to free it */
			freemsg(bufp->mp);
		else {
			val = nge_atomic_decrease(&brp->rx_hold, 1);
			ASSERT(val == B_TRUE);
		}
	}
}

/*
 * Checking the rx's BDs (one or more) to receive
 * one complete packet.
 * start_index: the start indexer of BDs for one packet.
 * end_index: the end indexer of BDs for one packet.
 */
static mblk_t *nge_recv_packet(nge_t *ngep, uint32_t start_index, size_t len);
#pragma	inline(nge_recv_packet)

static mblk_t *
nge_recv_packet(nge_t *ngep, uint32_t start_index, size_t len)
{
	uint8_t *rptr;
	uint32_t minsize;
	uint32_t maxsize;
	mblk_t *mp;
	buff_ring_t *brp;
	sw_rx_sbd_t *srbdp;
	dma_area_t *bufp;
	nge_sw_statistics_t *sw_stp;
	void *hw_bd_p;

	brp = ngep->buff;
	minsize = ETHERMIN;
	maxsize = ngep->max_sdu;
	sw_stp = &ngep->statistics.sw_statistics;
	mp = NULL;

	srbdp = &brp->sw_rbds[start_index];
	DMA_SYNC(*srbdp->bufp, DDI_DMA_SYNC_FORKERNEL);
	hw_bd_p = DMA_VPTR(srbdp->desc);

	/*
	 * First check the free_list, if it is NULL,
	 * make the recycle_list be free_list.
	 */
	if (brp->free_list == NULL) {
		mutex_enter(brp->recycle_lock);
		brp->free_list = brp->recycle_list;
		brp->recycle_list = NULL;
		mutex_exit(brp->recycle_lock);
	}
	bufp = brp->free_list;
	/* If it's not a qualified packet, delete it */
	if (len > maxsize || len < minsize) {
		ngep->desc_attr.rxd_fill(hw_bd_p, &srbdp->bufp->cookie,
		    srbdp->bufp->alength);
		srbdp->flags = CONTROLER_OWN;
		return (NULL);
	}

	/*
	 * If receive packet size is smaller than RX bcopy threshold,
	 * or there is no available buffer in free_list or recycle list,
	 * we use bcopy directly.
	 */
	if (len <= ngep->param_rxbcopy_threshold || bufp == NULL)
		brp->rx_bcopy = B_TRUE;
	else
		brp->rx_bcopy = B_FALSE;

	if (brp->rx_bcopy) {
		mp = allocb(len + NGE_HEADROOM, 0);
		if (mp == NULL) {
			sw_stp->mp_alloc_err++;
			ngep->desc_attr.rxd_fill(hw_bd_p, &srbdp->bufp->cookie,
			    srbdp->bufp->alength);
			srbdp->flags = CONTROLER_OWN;
			return (NULL);
		}
		rptr = DMA_VPTR(*srbdp->bufp);
		mp->b_rptr = mp->b_rptr + NGE_HEADROOM;
		bcopy(rptr + NGE_HEADROOM, mp->b_rptr, len);
		mp->b_wptr = mp->b_rptr + len;
	} else {
		mp = srbdp->bufp->mp;
		/*
		 * Make sure the packet *contents* 4-byte aligned
		 */
		mp->b_rptr += NGE_HEADROOM;
		mp->b_wptr = mp->b_rptr + len;
		mp->b_next = mp->b_cont = NULL;
		srbdp->bufp->rx_delivered = B_TRUE;
		srbdp->bufp = NULL;
		nge_atomic_increase(&brp->rx_hold, 1);

		/* Fill the buffer from free_list */
		srbdp->bufp = bufp;
		brp->free_list = bufp->next;
		bufp->next = NULL;
	}

	/* replenish the buffer for hardware descriptor */
	ngep->desc_attr.rxd_fill(hw_bd_p, &srbdp->bufp->cookie,
	    srbdp->bufp->alength);
	srbdp->flags = CONTROLER_OWN;
	sw_stp->rbytes += len;
	sw_stp->recv_count++;

	return (mp);
}


#define	RX_HW_ERR	0x01
#define	RX_SUM_NO	0x02
#define	RX_SUM_ERR	0x04

/*
 * Statistic the rx's error
 * and generate a log msg for these.
 * Note:
 * RXE, Parity Error, Symbo error, CRC error
 * have been recored by nvidia's  hardware
 * statistics part (nge_statistics). So it is uncessary to record them by
 * driver in this place.
 */
static uint32_t
nge_rxsta_handle(nge_t *ngep, uint32_t stflag, uint32_t *pflags);
#pragma	inline(nge_rxsta_handle)

static uint32_t
nge_rxsta_handle(nge_t *ngep,  uint32_t stflag, uint32_t *pflags)
{
	uint32_t errors;
	uint32_t err_flag;
	nge_sw_statistics_t *sw_stp;

	err_flag = 0;
	sw_stp = &ngep->statistics.sw_statistics;

	if ((RXD_END & stflag) == 0)
		return (RX_HW_ERR);

	errors = stflag & RXD_CSUM_MSK;
	switch (errors) {
	default:
	break;

	case RXD_CK8G_TCP_SUM:
	case RXD_CK8G_UDP_SUM:
		*pflags |= HCK_IPV4_HDRCKSUM_OK;
		*pflags |= HCK_FULLCKSUM_OK;
		break;

	case RXD_CK8G_TCP_SUM_ERR:
	case RXD_CK8G_UDP_SUM_ERR:
		sw_stp->tcp_hwsum_err++;
		*pflags |= HCK_IPV4_HDRCKSUM_OK;
		break;

	case RXD_CK8G_IP_HSUM:
		*pflags |= HCK_IPV4_HDRCKSUM_OK;
		break;

	case RXD_CK8G_NO_HSUM:
		err_flag |= RX_SUM_NO;
		break;

	case RXD_CK8G_IP_HSUM_ERR:
		sw_stp->ip_hwsum_err++;
		err_flag |=  RX_SUM_ERR;
		break;
	}

	if ((stflag & RXD_ERR) != 0)	{

		err_flag |= RX_HW_ERR;
		NGE_DEBUG(("Receive desc error, status: 0x%x", stflag));
	}

	return (err_flag);
}

static mblk_t *
nge_recv_ring(nge_t *ngep)
{
	uint32_t stflag;
	uint32_t flag_err;
	uint32_t sum_flags;
	size_t len;
	uint64_t end_index;
	uint64_t sync_start;
	mblk_t *mp;
	mblk_t **tail;
	mblk_t *head;
	recv_ring_t *rrp;
	buff_ring_t *brp;
	sw_rx_sbd_t *srbdp;
	void * hw_bd_p;
	nge_mode_cntl mode_cntl;

	mp = NULL;
	head = NULL;
	tail = &head;
	rrp = ngep->recv;
	brp = ngep->buff;

	end_index = sync_start = rrp->prod_index;
	/* Sync the descriptor for kernel */
	if (sync_start + ngep->param_recv_max_packet <= ngep->rx_desc) {
		(void) ddi_dma_sync(rrp->desc.dma_hdl,
		    sync_start * ngep->desc_attr.rxd_size,
		    ngep->param_recv_max_packet * ngep->desc_attr.rxd_size,
		    DDI_DMA_SYNC_FORKERNEL);
	} else {
		(void) ddi_dma_sync(rrp->desc.dma_hdl,
		    sync_start * ngep->desc_attr.rxd_size,
		    0,
		    DDI_DMA_SYNC_FORKERNEL);
		(void) ddi_dma_sync(rrp->desc.dma_hdl,
		    0,
		    (ngep->param_recv_max_packet + sync_start - ngep->rx_desc) *
		    ngep->desc_attr.rxd_size,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	/*
	 * Looking through the rx's ring to find the good packets
	 * and try to receive more and more packets in rx's ring
	 */
	for (;;) {
		sum_flags = 0;
		flag_err = 0;
		end_index = rrp->prod_index;
		srbdp = &brp->sw_rbds[end_index];
		hw_bd_p = DMA_VPTR(srbdp->desc);
		stflag = ngep->desc_attr.rxd_check(hw_bd_p, &len);
		/*
		 * If there is no packet in receving ring
		 * break the loop
		 */
		if ((stflag & RXD_OWN) != 0 || HOST_OWN == srbdp->flags)
			break;

		ngep->recv_count++;
		flag_err = nge_rxsta_handle(ngep, stflag, &sum_flags);
		if ((flag_err & RX_HW_ERR) == 0) {
			srbdp->flags = NGE_END_PACKET;
			mp = nge_recv_packet(ngep, end_index, len);
		} else {
			/* Hardware error, re-use the buffer */
			ngep->desc_attr.rxd_fill(hw_bd_p, &srbdp->bufp->cookie,
			    srbdp->bufp->alength);
			srbdp->flags = CONTROLER_OWN;
		}
		if (mp != NULL) {
			if (!(flag_err & (RX_SUM_NO | RX_SUM_ERR))) {
				mac_hcksum_set(mp, 0, 0, 0, 0, sum_flags);
			}
			*tail = mp;
			tail = &mp->b_next;
			mp = NULL;
		}
		rrp->prod_index = NEXT(end_index, rrp->desc.nslots);
		if (ngep->recv_count >= ngep->param_recv_max_packet)
			break;
	}

	/* Sync the descriptors for device */
	if (sync_start + ngep->recv_count <= ngep->rx_desc) {
		(void) ddi_dma_sync(rrp->desc.dma_hdl,
		    sync_start * ngep->desc_attr.rxd_size,
		    ngep->recv_count * ngep->desc_attr.rxd_size,
		    DDI_DMA_SYNC_FORDEV);
	} else {
		(void) ddi_dma_sync(rrp->desc.dma_hdl,
		    sync_start * ngep->desc_attr.rxd_size,
		    0,
		    DDI_DMA_SYNC_FORDEV);
		(void) ddi_dma_sync(rrp->desc.dma_hdl,
		    0,
		    (ngep->recv_count + sync_start - ngep->rx_desc) *
		    ngep->desc_attr.rxd_size,
		    DDI_DMA_SYNC_FORDEV);
	}
	mode_cntl.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);
	mode_cntl.mode_bits.rxdm = NGE_SET;
	mode_cntl.mode_bits.tx_rcom_en = NGE_SET;
	nge_reg_put32(ngep, NGE_MODE_CNTL, mode_cntl.mode_val);

	return (head);
}

void
nge_receive(nge_t *ngep)
{
	mblk_t *mp;
	recv_ring_t *rrp;
	rrp = ngep->recv;

	mp = nge_recv_ring(ngep);
	mutex_exit(ngep->genlock);
	if (mp != NULL)
		mac_rx(ngep->mh, rrp->handle, mp);
	mutex_enter(ngep->genlock);
}

void
nge_hot_rxd_fill(void *hwd, const ddi_dma_cookie_t *cookie, size_t len)
{
	uint64_t dmac_addr;
	hot_rx_bd * hw_bd_p;

	hw_bd_p = (hot_rx_bd *)hwd;
	dmac_addr = cookie->dmac_laddress + NGE_HEADROOM;

	hw_bd_p->cntl_status.cntl_val = 0;

	hw_bd_p->host_buf_addr_hi = dmac_addr >> 32;
	hw_bd_p->host_buf_addr_lo = (uint32_t)dmac_addr;
	hw_bd_p->cntl_status.control_bits.bcnt = len - 1;

	membar_producer();
	hw_bd_p->cntl_status.control_bits.own = NGE_SET;
}

void
nge_sum_rxd_fill(void *hwd, const ddi_dma_cookie_t *cookie, size_t len)
{
	sum_rx_bd * hw_bd_p;

	hw_bd_p = hwd;

	hw_bd_p->cntl_status.cntl_val = 0;

	hw_bd_p->host_buf_addr =
	    (uint32_t)(cookie->dmac_address + NGE_HEADROOM);
	hw_bd_p->cntl_status.control_bits.bcnt = len - 1;

	membar_producer();
	hw_bd_p->cntl_status.control_bits.own = NGE_SET;
}

uint32_t
nge_hot_rxd_check(const void *hwd, size_t *len)
{
	uint32_t err_flag;
	const hot_rx_bd * hrbdp;

	hrbdp = hwd;
	err_flag = hrbdp->cntl_status.cntl_val;
	*len = err_flag & RXD_BCNT_MSK;
	return (err_flag);
}

uint32_t
nge_sum_rxd_check(const void *hwd, size_t *len)
{
	uint32_t err_flag;
	const sum_rx_bd * hrbdp;

	hrbdp = hwd;

	err_flag = hrbdp->cntl_status.cntl_val;
	*len = err_flag & RXD_BCNT_MSK;
	return (err_flag);
}
