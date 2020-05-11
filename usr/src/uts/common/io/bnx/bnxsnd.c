/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnxsnd.h"


/* Low water marks for transmit credits. */
#define	BNX_DCOPY_ALIGN			32
#define	BNX_XMIT_INIT_FAIL_THRESH	1
#define	BNX_PDWM_THRESHOLD		8


#ifndef NUM_TX_CHAIN
#error NUM_TX_CHAIN is not defined.
#else
/*
 * Range check NUM_TX_CHAIN.  Technically the LM controls this definition,
 * but it makes sense to use what the LM uses.
 */
#if NUM_TX_CHAIN < 0
#error Invalid NUM_TX_CHAIN definition.
#elif NUM_TX_CHAIN > 1
#warning NUM_TX_CHAIN is greater than 1.
#endif
#endif


static ddi_dma_attr_t bnx_snd_dma_attrib = {
	DMA_ATTR_V0,			/* dma_attr_version */
	0,				/* dma_attr_addr_lo */
	0xffffffffffffffff,		/* dma_attr_addr_hi */
	0x0ffffff,			/* dma_attr_count_max */
	BNX_DMA_ALIGNMENT,		/* dma_attr_align */
	0xffffffff,			/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	0x00ffffff,			/* dma_attr_maxxfer */
	0xffffffff,			/* dma_attr_seg */
	BNX_MAX_SGL_ENTRIES,		/* dma_attr_sgllen */
	BNX_MIN_BYTES_PER_FRAGMENT,	/* dma_attr_granular */
	0,				/* dma_attr_flags */
};

/*
 * Description:  This function will map the fragments of the message block
 *
 * Return:  DDI_DMA_MAPPED:   Success
 *          DDI_DMA_INUSE:    Another I/O transaction is using the DMA handle
 *          DDI_DMA_NORESOURCES: No resources are available at the present time
 *          DDI_DMA_NOMAPPING: The object cannot be reached by the device
 *                             requesting the resources.
 *          DDI_DMA_TOOBIG:   The object is too big. A request of this size can
 *                            never be satisfied on this particular system.
 *                            The maximum size varies depending on machine
 *                            and configuration.
 */
static int
bnx_xmit_frag_map(mblk_t *mp, ddi_dma_handle_t *handle,
    lm_frag_list_t *fraglist)
{
	int i;
	uint_t ccount;
	ddi_dma_cookie_t cookie;
	lm_frag_t *fragment;

	if (fraglist->cnt >= BNX_MAX_SGL_ENTRIES) {
		return (DDI_DMA_NOMAPPING);
	}

	i = ddi_dma_addr_bind_handle(*handle, NULL,
	    (caddr_t)mp->b_rptr, mp->b_wptr - mp->b_rptr,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
	    &cookie, &ccount);
	if (i != DDI_DMA_MAPPED) {
		return (i);
	}

	/*
	 * It looks strange at first, but the below check is needed.
	 * ddi_dma_addr_bind_handle() correctly returns an error if
	 * the physical fragment count exceeds the maximum fragment
	 * count specified in the ddi_dma_attrib structure for the
	 * current mp.  However, a packet can span multiple mp's.
	 * The purpose of the check below is to make sure we do not
	 * overflow the global fragment count limit.
	 */
	if (fraglist->cnt + ccount > BNX_MAX_SGL_ENTRIES) {
		/* We hit our fragment count limit. */
		(void) ddi_dma_unbind_handle(*handle);

		return (DDI_DMA_NOMAPPING);
	}

	fragment = &(fraglist->frag_arr[fraglist->cnt]);
	fraglist->cnt += ccount;

	for (i = 0; i < ccount-1; i++) {
		fragment->addr.as_u64 = cookie.dmac_laddress;
		fragment->size = cookie.dmac_size;

		fragment++;

		ddi_dma_nextcookie(*handle, &cookie);
	}

	fragment->addr.as_u64 = cookie.dmac_laddress;
	fragment->size = cookie.dmac_size;

	return (0);
}

static void
bnx_xmit_pkt_unmap(um_txpacket_t * const umpacket)
{
	int i;

	for (i = 0; i < umpacket->num_handles; i++) {
		(void) ddi_dma_unbind_handle(umpacket->dma_handle[i]);
	}

	umpacket->num_handles = 0;
}

int
bnx_xmit_pkt_map(um_txpacket_t * const umpacket, mblk_t * mp)
{
	int rc;
	u32_t num_dma_handle;

	num_dma_handle = umpacket->num_handles;

	if (num_dma_handle == BNX_MAX_SGL_ENTRIES) {
		return (BNX_TX_RESOURCES_TOO_MANY_FRAGS);
	}

	rc = bnx_xmit_frag_map(mp, &umpacket->dma_handle[num_dma_handle++],
	    &(umpacket->frag_list));
	if (rc) {
		return (BNX_TX_RESOURCES_NO_OS_DMA_RES);
	}

	umpacket->num_handles = num_dma_handle;

	return (0);
}

static void
bnx_xmit_pkt_cpy(um_device_t * const umdevice, um_txpacket_t * const umpacket)
{
	size_t msgsize;
	u32_t cpysize;
	lm_frag_t *cpyfrag;
	boolean_t map_enable;
	mblk_t *mp;
	int rc;

	map_enable = B_TRUE;
	cpysize = 0;
	cpyfrag = NULL;

	for (mp = umpacket->mp; mp; mp = mp->b_cont) {
		msgsize = MBLKL(mp);

		if (msgsize == 0)
			continue;

		if (map_enable && msgsize > umdevice->tx_copy_threshold) {
			rc = bnx_xmit_pkt_map(umpacket, mp);
			if (rc == 0) {
				cpyfrag = NULL;
				continue;
			} else {
				map_enable = B_FALSE;
			}
		}

		ASSERT(cpysize + msgsize <= umdevice->dev_var.mtu +
		    sizeof (struct ether_vlan_header));

		bcopy(mp->b_rptr, (char *)umpacket->cpymem + cpysize, msgsize);

		if (cpyfrag != NULL) {
			cpyfrag->size += msgsize;
		} else {
			cpyfrag = &umpacket->frag_list.frag_arr[
			    umpacket->frag_list.cnt++];
			ASSERT(umpacket->frag_list.cnt <= BNX_MAX_SGL_ENTRIES +
			    1);
			cpyfrag->size = msgsize;

			cpyfrag->addr.as_u64 = umpacket->cpyphy.as_u64 +
			    cpysize;
		}

		cpysize += msgsize;
	}

	if (cpysize > 0) {
		(void) ddi_dma_sync(*(umpacket->cpyhdl), umpacket->cpyoff,
		    cpysize, DDI_DMA_SYNC_FORDEV);
	}

	if (umpacket->num_handles == 0) {
		freemsg(umpacket->mp);
		umpacket->mp = NULL;
	}

}

static int
bnx_xmit_pkt_init(um_device_t * const umdevice, um_txpacket_t * const umpacket,
    int num, lm_u64_t memphys)
{
	int i;
	int rc;
	um_xmit_qinfo * xmitinfo;

	xmitinfo = &_TX_QINFO(umdevice, 0);

	for (i = 0; i < BNX_MAX_SGL_ENTRIES; i++) {
		rc = ddi_dma_alloc_handle(umdevice->os_param.dip,
		    &bnx_snd_dma_attrib, DDI_DMA_DONTWAIT,
		    (void *)0, &umpacket->dma_handle[i]);
		if (rc != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s:%s failed. (errno=%d)",
			    umdevice->dev_name, __func__, rc);
			goto error;
		}
	}

	/* Init the relavant informations in the packet structure */
	umpacket->mp = NULL;
	umpacket->num_handles = 0;
	umpacket->frag_list.cnt = 0;

	umpacket->cpyhdl = &(xmitinfo->dcpyhndl);
	umpacket->cpyoff = num * xmitinfo->dcpyhard;
	umpacket->cpymem = xmitinfo->dcpyvirt + umpacket->cpyoff;
	umpacket->cpyphy = memphys;

	return (rc);

error:
	for (i--; i >= 0; i--) {
		ddi_dma_free_handle(&umpacket->dma_handle[i]);
	}

	return (-1);
}

static void
bnx_xmit_pkt_fini(um_txpacket_t * const umpacket)
{
	int i;

	for (i = BNX_MAX_SGL_ENTRIES - 1; i >= 0; i--) {
		ddi_dma_free_handle(&umpacket->dma_handle[i]);
	}

	umpacket->mp = NULL;
	umpacket->num_handles = 0;
	umpacket->frag_list.cnt = 0;

	umpacket->cpyhdl = NULL;
	umpacket->cpyoff = 0;
	umpacket->cpymem = NULL;
}

static int
bnx_xmit_packet(um_device_t * const umdevice, const unsigned int ringidx,
    um_txpacket_t * const umpacket)
{
	int rc;
	s_list_t *waitq;
	lm_tx_chain_t *txq;
	lm_packet_t *lmpacket;
	lm_device_t *lmdevice;
	lm_frag_list_t *lmfraglist;

	lmdevice = &(umdevice->lm_dev);
	lmpacket = &(umpacket->lm_pkt);

	lmfraglist = &(umpacket->frag_list);
	txq = &lmdevice->tx_info.chain[ringidx];

	/* Try to recycle, if available bd is lower than threshold */
	if (txq->bd_left < BNX_MAX_SGL_ENTRIES) {
		s_list_t xmitpkts;

		s_list_init(&xmitpkts, NULL, NULL, 0);

		rc = lm_get_packets_sent(lmdevice, ringidx, 0, &xmitpkts);

		if (rc) {
			bnx_xmit_ring_reclaim(umdevice, ringidx, &xmitpkts);
		}
	}

	waitq = &_TXQ_RESC_DESC(umdevice, ringidx);
	if (s_list_is_empty(waitq) && txq->bd_left >= lmfraglist->cnt) {
		(void) lm_send_packet(lmdevice, ringidx, lmpacket, lmfraglist);

		return (BNX_SEND_GOODXMIT);
	}

	s_list_push_tail(waitq, &umpacket->lm_pkt.link);

	if (txq->bd_left >= BNX_MAX_SGL_ENTRIES) {
		rc = bnx_xmit_ring_xmit_qpkt(umdevice, ringidx);
		if (rc == BNX_SEND_GOODXMIT) {
			return (BNX_SEND_GOODXMIT);
		}
	}

	umdevice->no_tx_credits |= BNX_TX_RESOURCES_NO_CREDIT;

	return (BNX_SEND_DEFERPKT);
}

static int
bnx_xmit_ring_cpybuf_alloc(um_device_t * const umdevice,
    um_xmit_qinfo * const xmitinfo,
    unsigned int buffsize)
{
	int rc;
	size_t actualsize;
	unsigned int alignedsize;
	unsigned int count;
	ddi_dma_cookie_t cookie;

	ASSERT(buffsize > 0);

	alignedsize = buffsize;
	alignedsize += (BNX_DCOPY_ALIGN - 1);
	alignedsize &= ~((unsigned int)(BNX_DCOPY_ALIGN - 1));

	/* We want double copy buffers to be completely contiguous. */
	rc = ddi_dma_alloc_handle(umdevice->os_param.dip, &bnx_std_dma_attrib,
	    DDI_DMA_DONTWAIT, (void *)0, &xmitinfo->dcpyhndl);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: %s: Failed to alloc phys dma handle.\n",
		    umdevice->dev_name, __func__);
		return (-1);
	}

	rc = ddi_dma_mem_alloc(xmitinfo->dcpyhndl,
	    alignedsize * xmitinfo->desc_cnt, &bnxAccessAttribBUF,
	    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, (void *)0,
	    &xmitinfo->dcpyvirt, &actualsize, &xmitinfo->dcpyahdl);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: %s: Failed to alloc phys memory.\n",
		    umdevice->dev_name, __func__);
		goto error1;
	}

	rc = ddi_dma_addr_bind_handle(xmitinfo->dcpyhndl,
	    (struct as *)0, xmitinfo->dcpyvirt, actualsize,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, (void *)0,
	    &cookie, &count);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: %s: Failed to bind DMA address.\n",
		    umdevice->dev_name, __func__);
		goto error2;
	}

	xmitinfo->dcpyhard = alignedsize;
	xmitinfo->dcpyphys.as_u64 = (u64_t)cookie.dmac_laddress;

	return (0);

error2:
	ddi_dma_mem_free(&xmitinfo->dcpyahdl);

error1:
	ddi_dma_free_handle(&xmitinfo->dcpyhndl);

	return (-1);
}

static void
bnx_xmit_ring_cpybuf_free(um_device_t * const umdevice,
    um_xmit_qinfo * const xmitinfo)
{
	(void) ddi_dma_unbind_handle(xmitinfo->dcpyhndl);
	ddi_dma_mem_free(&xmitinfo->dcpyahdl);
	ddi_dma_free_handle(&xmitinfo->dcpyhndl);

	xmitinfo->dcpyvirt = NULL;
	xmitinfo->dcpyphys.as_u64 = 0;
	xmitinfo->dcpyhard = 0;
}

static int
bnx_xmit_ring_init(um_device_t * const umdevice, const unsigned int ringidx)
{
	int i;
	size_t memsize;
	void *memvirt;
	s_list_t *freeq;
	lm_u64_t memphys;
	um_txpacket_t *umpacket;
	um_xmit_qinfo *xmitinfo;

	xmitinfo = &_TX_QINFO(umdevice, ringidx);

	s_list_init(&_TXQ_FREE_DESC(umdevice, ringidx), NULL, NULL, 0);
	s_list_init(&_TXQ_RESC_DESC(umdevice, ringidx), NULL, NULL, 0);

	if (xmitinfo->desc_cnt == 0) {
		return (0);
	}

	xmitinfo->thresh_pdwm = BNX_PDWM_THRESHOLD;

	memsize = xmitinfo->desc_cnt * sizeof (um_txpacket_t);
	memvirt = kmem_zalloc(memsize, KM_NOSLEEP);
	if (memvirt == NULL) {
		cmn_err(CE_WARN, "%s: Failed to allocate TX packet "
		    "descriptor memory (%d).\n", umdevice->dev_name, ringidx);
		return (-1);
	}

	xmitinfo->desc_mem.addr = memvirt;
	xmitinfo->desc_mem.size = memsize;

	if (bnx_xmit_ring_cpybuf_alloc(umdevice, xmitinfo,
	    umdevice->dev_var.mtu + sizeof (struct ether_vlan_header))) {
		kmem_free(xmitinfo->desc_mem.addr, xmitinfo->desc_mem.size);
		xmitinfo->desc_mem.addr = NULL;
		xmitinfo->desc_mem.size = 0;

		return (-1);
	}

	/*
	 * Driver successfully allocated memory for this transmit queue, now
	 * link them together and place them in the free pool.
	 */

	freeq = &_TXQ_FREE_DESC(umdevice, ringidx);
	umpacket = (um_txpacket_t *)memvirt;

	memphys = xmitinfo->dcpyphys;

	for (i = 0; i < xmitinfo->desc_cnt; i++) {
		if (bnx_xmit_pkt_init(umdevice, umpacket, i, memphys)) {
			break;
		}

		LM_INC64(&memphys, xmitinfo->dcpyhard);

		s_list_push_tail(freeq, &umpacket->lm_pkt.link);

		umpacket++;
	}

	mutex_init(&xmitinfo->free_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(umdevice->intrPriority));

	return (0);
}

void
bnx_xmit_ring_reclaim(um_device_t * const umdevice,
    const unsigned int ringidx, s_list_t *srcq)
{
	s_list_t *freeq;
	s_list_entry_t *lmpacket;
	um_txpacket_t *umpacket;
	um_xmit_qinfo *xmitinfo;

	if (s_list_entry_cnt(srcq) ==  0) {
		return;
	}

	for (lmpacket = s_list_peek_head(srcq); lmpacket;
	    lmpacket = s_list_next_entry(lmpacket)) {

		umpacket = (um_txpacket_t *)lmpacket;

		if (umpacket->num_handles > 0) {
			bnx_xmit_pkt_unmap(umpacket);
		}

		if (umpacket->mp != NULL) {
			freemsg(umpacket->mp);
			umpacket->mp = NULL;
		}
	}

	freeq = &_TXQ_FREE_DESC(umdevice, ringidx);
	xmitinfo = &_TX_QINFO(umdevice, ringidx);

	mutex_enter(&xmitinfo->free_mutex);
	s_list_add_tail(freeq, srcq);
	mutex_exit(&xmitinfo->free_mutex);

}

int
bnx_xmit_ring_xmit_qpkt(um_device_t * const umdevice,
    const unsigned int ringidx)
{
	s_list_t *waitq;
	lm_tx_chain_t *txq;
	lm_packet_t *lmpacket;
	lm_device_t *lmdevice;
	lm_frag_list_t *lmfraglist;
	um_txpacket_t *umpacket;
	int rc = 0;

	lmdevice = &(umdevice->lm_dev);
	waitq = &_TXQ_RESC_DESC(umdevice, ringidx);
	txq = &lmdevice->tx_info.chain[ringidx];

	while (s_list_entry_cnt(waitq)) {
		umpacket = (um_txpacket_t *)s_list_peek_head(waitq);
		lmfraglist = &(umpacket->frag_list);

		if (lmfraglist->cnt > txq->bd_left) {
			rc = BNX_SEND_DEFERPKT;
			break;
		}

		umpacket = (um_txpacket_t *)s_list_pop_head(waitq);
		lmpacket = &(umpacket->lm_pkt);

		/*
		 * The main way that this can fail is in the check we just
		 * performed around the fragment list versus txq, so we ignore
		 * the return value.
		 */
		(void) lm_send_packet(lmdevice, ringidx, lmpacket, lmfraglist);
	}

	return (rc);
}

int
bnx_xmit_ring_xmit_mblk(um_device_t * const umdevice,
    const unsigned int ringidx, mblk_t *mp)
{
	int rc;
	uint32_t pflags;
	s_list_t *txfreeq;
	lm_packet_t *lmpacket;
	um_txpacket_t *umpacket;
	um_xmit_qinfo *xmitinfo;

	xmitinfo = &_TX_QINFO(umdevice, ringidx);

	txfreeq = &_TXQ_FREE_DESC(umdevice, ringidx);

	mutex_enter(&xmitinfo->free_mutex);
	umpacket = (um_txpacket_t *)s_list_pop_head(txfreeq);
	mutex_exit(&xmitinfo->free_mutex);

	/* Try to recycle, if no more packet available */
	if (umpacket == NULL) {
		s_list_t  xmitpkts;
		lm_device_t *lmdevice;

		lmdevice = &(umdevice->lm_dev);

		s_list_init(&xmitpkts, NULL, NULL, 0);

		mutex_enter(&umdevice->os_param.xmit_mutex);
		rc = lm_get_packets_sent(lmdevice, ringidx, 0, &xmitpkts);
		if (rc == 0) {
			umdevice->no_tx_credits |= BNX_TX_RESOURCES_NO_DESC;

			mutex_exit(&umdevice->os_param.xmit_mutex);
			return (BNX_SEND_HDWRFULL);
		}
		mutex_exit(&umdevice->os_param.xmit_mutex);

		umpacket = (um_txpacket_t *)s_list_pop_head(&xmitpkts);
		if (umpacket->num_handles > 0) {
			bnx_xmit_pkt_unmap(umpacket);
		}
		if (umpacket->mp != NULL) {
			freemsg(umpacket->mp);
			umpacket->mp = NULL;
		}

		/* clean up resources */
		bnx_xmit_ring_reclaim(umdevice, ringidx, &xmitpkts);
	}

	umpacket->lm_pkt.link.next = NULL;
	ASSERT(umpacket->mp == NULL);
	ASSERT(umpacket->num_handles == 0);
	umpacket->frag_list.cnt = 0;
	umpacket->mp = mp;

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &pflags);

	bnx_xmit_pkt_cpy(umdevice, umpacket);

	lmpacket = &(umpacket->lm_pkt);

	lmpacket->u1.tx.flags   = 0;
	lmpacket->u1.tx.lso_mss = 0;

	lmpacket->u1.tx.vlan_tag = 0;

	if (pflags & HCK_IPV4_HDRCKSUM) {
		lmpacket->u1.tx.flags |= LM_TX_FLAG_COMPUTE_IP_CKSUM;
	}

	if (pflags & HCK_FULLCKSUM) {
		lmpacket->u1.tx.flags |= LM_TX_FLAG_COMPUTE_TCP_UDP_CKSUM;
	}

	mutex_enter(&umdevice->os_param.xmit_mutex);
	rc = bnx_xmit_packet(umdevice, ringidx, umpacket);
	mutex_exit(&umdevice->os_param.xmit_mutex);

	return (rc);
}

void
bnx_xmit_ring_intr(um_device_t * const umdevice, const unsigned int ringidx)
{
	u32_t rc;
	s_list_t xmitpkts;
	lm_device_t *lmdevice;

	lmdevice = &(umdevice->lm_dev);

	s_list_init(&xmitpkts, NULL, NULL, 0);

	mutex_enter(&umdevice->os_param.xmit_mutex);

	rc = lm_get_packets_sent(lmdevice, ringidx, 0, &xmitpkts);

	mutex_exit(&umdevice->os_param.xmit_mutex);

	if (rc) {
		bnx_xmit_ring_reclaim(umdevice, ringidx, &xmitpkts);
	}
}

void
bnx_xmit_ring_post(um_device_t * const umdevice, const unsigned int ringidx)
{
	int rc;
	s_list_t *freeq;
	lm_device_t *lmdevice;
	um_xmit_qinfo *xmitinfo;
	lm_tx_chain_t *lmtxring;

	if (umdevice->no_tx_credits != 0) {
		if (umdevice->no_tx_credits & BNX_TX_RESOURCES_NO_CREDIT) {
			rc = bnx_xmit_ring_xmit_qpkt(umdevice, ringidx);

			if (rc == BNX_SEND_GOODXMIT) {
				lmdevice = &(umdevice->lm_dev);
				lmtxring = &(lmdevice->tx_info.chain[ringidx]);

				if (lmtxring->bd_left >= BNX_MAX_SGL_ENTRIES) {
					umdevice->no_tx_credits &=
					    ~BNX_TX_RESOURCES_NO_CREDIT;
				}
			}
		}

		if (umdevice->no_tx_credits & BNX_TX_RESOURCES_NO_DESC) {
			freeq = &_TXQ_FREE_DESC(umdevice, ringidx);
			xmitinfo = &_TX_QINFO(umdevice, ringidx);

			if (s_list_entry_cnt(freeq) > xmitinfo->thresh_pdwm) {
				umdevice->no_tx_credits &=
				    ~BNX_TX_RESOURCES_NO_DESC;
			}
		}

		if (umdevice->no_tx_credits == 0) {
			mac_tx_update(umdevice->os_param.macp);
		}
	}
}

static void
bnx_xmit_ring_fini(um_device_t * const umdevice, const unsigned int ringidx)
{
	s_list_t *srcq;
	um_txpacket_t *umpacket;
	um_xmit_qinfo *xmitinfo;

	xmitinfo = &_TX_QINFO(umdevice, ringidx);

	mutex_destroy(&xmitinfo->free_mutex);

	srcq = &_TXQ_FREE_DESC(umdevice, ringidx);

	/* CONSTANTCONDITION */
	/* Pop all the packet descriptors off the free list and discard them. */
	while (1) {
		umpacket = (um_txpacket_t *)s_list_pop_head(srcq);
		if (umpacket == NULL) {
			break;
		}

		bnx_xmit_pkt_fini(umpacket);
	}

	bnx_xmit_ring_cpybuf_free(umdevice, xmitinfo);

	kmem_free(xmitinfo->desc_mem.addr, xmitinfo->desc_mem.size);
	xmitinfo->desc_mem.addr = NULL;
	xmitinfo->desc_mem.size = 0;
}

int
bnx_txpkts_init(um_device_t * const umdevice)
{
	int i;
	int alloccnt;
	um_xmit_qinfo *xmitinfo;

	xmitinfo = &_TX_QINFO(umdevice, 0);

	mutex_init(&umdevice->os_param.xmit_mutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(umdevice->intrPriority));

	alloccnt = 0;

	/* Allocate packet descriptors for the TX queue. */
	for (i = TX_CHAIN_IDX0; i < NUM_TX_CHAIN; i++) {
		int desc_cnt;

		if (bnx_xmit_ring_init(umdevice, i)) {
			goto error;
		}

		desc_cnt = s_list_entry_cnt(&_TXQ_FREE_DESC(umdevice, i));

		if (desc_cnt != xmitinfo->desc_cnt) {
			cmn_err(CE_NOTE,
			    "%s: %d tx buffers requested.  %d allocated.\n",
			    umdevice->dev_name, xmitinfo->desc_cnt, desc_cnt);
		}

		alloccnt += desc_cnt;
	}

	/* FIXME -- Review TX buffer allocation failure threshold. */
	if (alloccnt < BNX_XMIT_INIT_FAIL_THRESH) {
		cmn_err(CE_WARN,
		    "%s: Failed to allocate minimum number of TX buffers.\n",
		    umdevice->dev_name);

		goto error;
	}

	return (0);

error:
	for (i--; i >= TX_CHAIN_IDX0; i--) {
		bnx_xmit_ring_fini(umdevice, i);
	}

	mutex_destroy(&umdevice->os_param.xmit_mutex);

	return (-1);
}

void
bnx_txpkts_flush(um_device_t * const umdevice)
{
	int i;
	boolean_t notx_fl = B_FALSE;

	for (i = NUM_TX_CHAIN - 1; i >= TX_CHAIN_IDX0; i--) {
		lm_abort(&(umdevice->lm_dev), ABORT_OP_TX_CHAIN, i);

		bnx_xmit_ring_reclaim(umdevice, i,
		    &_TXQ_RESC_DESC(umdevice, i));

		s_list_init(&_TXQ_RESC_DESC(umdevice, i), NULL, NULL, 0);

		if (umdevice->no_tx_credits & BNX_TX_RESOURCES_NO_CREDIT) {
			umdevice->no_tx_credits &= ~BNX_TX_RESOURCES_NO_CREDIT;
			notx_fl = B_TRUE;
		}
		if (umdevice->no_tx_credits & BNX_TX_RESOURCES_NO_DESC) {
			umdevice->no_tx_credits &= ~BNX_TX_RESOURCES_NO_DESC;
			notx_fl = B_TRUE;
		}
		if (umdevice->no_tx_credits == 0 && notx_fl == B_TRUE) {
			mac_tx_update(umdevice->os_param.macp);
		}
	}
}

void
bnx_txpkts_intr(um_device_t * const umdevice)
{
	int i;

	for (i = TX_CHAIN_IDX0; i < NUM_TX_CHAIN; i++) {
		bnx_xmit_ring_post(umdevice, i);
	}
}

void
bnx_txpkts_fini(um_device_t * const umdevice)
{
	int i;

	for (i = NUM_TX_CHAIN - 1; i >= TX_CHAIN_IDX0; i--) {
		bnx_xmit_ring_fini(umdevice, i);
	}

	mutex_destroy(&umdevice->os_param.xmit_mutex);
}
