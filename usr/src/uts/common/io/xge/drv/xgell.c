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

/*
 *  Copyright (c) 2002-2009 Neterion, Inc.
 *  All right Reserved.
 *
 *  FileName :    xgell.c
 *
 *  Description:  Xge Link Layer data path implementation
 *
 */

#include "xgell.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define	XGELL_MAX_FRAME_SIZE(hldev)	((hldev)->config.mtu +	\
    sizeof (struct ether_vlan_header))

#define	HEADROOM		2	/* for DIX-only packets */

void header_free_func(void *arg) { }
frtn_t header_frtn = {header_free_func, NULL};

/* DMA attributes used for Tx side */
static struct ddi_dma_attr tx_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	0x0ULL,				/* dma_attr_addr_lo */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_addr_hi */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_count_max */
#if defined(__sparc)
	0x2000,				/* dma_attr_align */
#else
	0x1000,				/* dma_attr_align */
#endif
	0xFC00FC,			/* dma_attr_burstsizes */
	0x1,				/* dma_attr_minxfer */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_seg */
	18,				/* dma_attr_sgllen */
	(unsigned int)1,		/* dma_attr_granular */
	0				/* dma_attr_flags */
};

/*
 * DMA attributes used when using ddi_dma_mem_alloc to
 * allocat HAL descriptors and Rx buffers during replenish
 */
static struct ddi_dma_attr hal_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr_version */
	0x0ULL,				/* dma_attr_addr_lo */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_addr_hi */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_count_max */
#if defined(__sparc)
	0x2000,				/* dma_attr_align */
#else
	0x1000,				/* dma_attr_align */
#endif
	0xFC00FC,			/* dma_attr_burstsizes */
	0x1,				/* dma_attr_minxfer */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFULL,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	(unsigned int)1,		/* dma_attr_sgllen */
	DDI_DMA_RELAXED_ORDERING	/* dma_attr_flags */
};

struct ddi_dma_attr *p_hal_dma_attr = &hal_dma_attr;

static int		xgell_m_stat(void *, uint_t, uint64_t *);
static int		xgell_m_start(void *);
static void		xgell_m_stop(void *);
static int		xgell_m_promisc(void *, boolean_t);
static int		xgell_m_multicst(void *, boolean_t, const uint8_t *);
static void		xgell_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t	xgell_m_getcapab(void *, mac_capab_t, void *);

#define	XGELL_M_CALLBACK_FLAGS	(MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t xgell_m_callbacks = {
	XGELL_M_CALLBACK_FLAGS,
	xgell_m_stat,
	xgell_m_start,
	xgell_m_stop,
	xgell_m_promisc,
	xgell_m_multicst,
	NULL,
	NULL,
	NULL,
	xgell_m_ioctl,
	xgell_m_getcapab
};

/*
 * xge_device_poll
 *
 * Timeout should call me every 1s. xge_callback_event_queued should call me
 * when HAL hope event was rescheduled.
 */
/*ARGSUSED*/
void
xge_device_poll(void *data)
{
	xgelldev_t *lldev = xge_hal_device_private(data);

	mutex_enter(&lldev->genlock);
	if (lldev->is_initialized) {
		xge_hal_device_poll(data);
		lldev->timeout_id = timeout(xge_device_poll, data,
		    XGE_DEV_POLL_TICKS);
	} else if (lldev->in_reset == 1) {
		lldev->timeout_id = timeout(xge_device_poll, data,
		    XGE_DEV_POLL_TICKS);
	} else {
		lldev->timeout_id = 0;
	}
	mutex_exit(&lldev->genlock);
}

/*
 * xge_device_poll_now
 *
 * Will call xge_device_poll() immediately
 */
void
xge_device_poll_now(void *data)
{
	xgelldev_t *lldev = xge_hal_device_private(data);

	mutex_enter(&lldev->genlock);
	if (lldev->is_initialized) {
		xge_hal_device_poll(data);
	}
	mutex_exit(&lldev->genlock);
}

/*
 * xgell_callback_link_up
 *
 * This function called by HAL to notify HW link up state change.
 */
void
xgell_callback_link_up(void *userdata)
{
	xgelldev_t *lldev = (xgelldev_t *)userdata;

	mac_link_update(lldev->mh, LINK_STATE_UP);
}

/*
 * xgell_callback_link_down
 *
 * This function called by HAL to notify HW link down state change.
 */
void
xgell_callback_link_down(void *userdata)
{
	xgelldev_t *lldev = (xgelldev_t *)userdata;

	mac_link_update(lldev->mh, LINK_STATE_DOWN);
}

/*
 * xgell_rx_buffer_replenish_all
 *
 * To replenish all freed dtr(s) with buffers in free pool. It's called by
 * xgell_rx_buffer_recycle() or xgell_rx_1b_callback().
 * Must be called with pool_lock held.
 */
static void
xgell_rx_buffer_replenish_all(xgell_rx_ring_t *ring)
{
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;
	xge_hal_dtr_h dtr;
	xgell_rx_buffer_t *rx_buffer;
	xgell_rxd_priv_t *rxd_priv;

	xge_assert(mutex_owned(&bf_pool->pool_lock));

	while ((bf_pool->free > 0) &&
	    (xge_hal_ring_dtr_reserve(ring->channelh, &dtr) == XGE_HAL_OK)) {
		xge_assert(bf_pool->head);

		rx_buffer = bf_pool->head;

		bf_pool->head = rx_buffer->next;
		bf_pool->free--;

		xge_assert(rx_buffer->dma_addr);

		rxd_priv = (xgell_rxd_priv_t *)
		    xge_hal_ring_dtr_private(ring->channelh, dtr);
		xge_hal_ring_dtr_1b_set(dtr, rx_buffer->dma_addr,
		    bf_pool->size);

		rxd_priv->rx_buffer = rx_buffer;
		xge_hal_ring_dtr_post(ring->channelh, dtr);
	}
}

/*
 * xgell_rx_buffer_release
 *
 * The only thing done here is to put the buffer back to the pool.
 * Calling this function need be protected by mutex, bf_pool.pool_lock.
 */
static void
xgell_rx_buffer_release(xgell_rx_buffer_t *rx_buffer)
{
	xgell_rx_ring_t *ring = rx_buffer->ring;
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;

	xge_assert(mutex_owned(&bf_pool->pool_lock));

	/* Put the buffer back to pool */
	rx_buffer->next = bf_pool->head;
	bf_pool->head = rx_buffer;

	bf_pool->free++;
}

/*
 * xgell_rx_buffer_recycle
 *
 * Called by desballoc() to "free" the resource.
 * We will try to replenish all descripters.
 */

/*
 * Previously there were much lock contention between xgell_rx_1b_compl() and
 * xgell_rx_buffer_recycle(), which consumed a lot of CPU resources and had bad
 * effect on rx performance. A separate recycle list is introduced to overcome
 * this. The recycle list is used to record the rx buffer that has been recycled
 * and these buffers will be retuned back to the free list in bulk instead of
 * one-by-one.
 */

static void
xgell_rx_buffer_recycle(char *arg)
{
	xgell_rx_buffer_t *rx_buffer = (xgell_rx_buffer_t *)arg;
	xgell_rx_ring_t *ring = rx_buffer->ring;
	xgelldev_t *lldev = ring->lldev;
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;

	mutex_enter(&bf_pool->recycle_lock);

	rx_buffer->next = bf_pool->recycle_head;
	bf_pool->recycle_head = rx_buffer;
	if (bf_pool->recycle_tail == NULL)
		bf_pool->recycle_tail = rx_buffer;
	bf_pool->recycle++;

	/*
	 * Before finding a good way to set this hiwat, just always call to
	 * replenish_all. *TODO*
	 */
	if ((lldev->is_initialized != 0) && (ring->live) &&
	    (bf_pool->recycle >= XGELL_RX_BUFFER_RECYCLE_CACHE)) {
		mutex_enter(&bf_pool->pool_lock);
		bf_pool->recycle_tail->next = bf_pool->head;
		bf_pool->head = bf_pool->recycle_head;
		bf_pool->recycle_head = bf_pool->recycle_tail = NULL;
		bf_pool->post -= bf_pool->recycle;
		bf_pool->free += bf_pool->recycle;
		bf_pool->recycle = 0;
		xgell_rx_buffer_replenish_all(ring);
		mutex_exit(&bf_pool->pool_lock);
	}

	mutex_exit(&bf_pool->recycle_lock);
}

/*
 * xgell_rx_buffer_alloc
 *
 * Allocate one rx buffer and return with the pointer to the buffer.
 * Return NULL if failed.
 */
static xgell_rx_buffer_t *
xgell_rx_buffer_alloc(xgell_rx_ring_t *ring)
{
	xgelldev_t *lldev = ring->lldev;
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;
	xge_hal_device_t *hldev;
	void *vaddr;
	ddi_dma_handle_t dma_handle;
	ddi_acc_handle_t dma_acch;
	dma_addr_t dma_addr;
	uint_t ncookies;
	ddi_dma_cookie_t dma_cookie;
	size_t real_size;
	extern ddi_device_acc_attr_t *p_xge_dev_attr;
	xgell_rx_buffer_t *rx_buffer;

	hldev = (xge_hal_device_t *)lldev->devh;

	if (ddi_dma_alloc_handle(hldev->pdev, p_hal_dma_attr, DDI_DMA_SLEEP,
	    0, &dma_handle) != DDI_SUCCESS) {
		xge_debug_ll(XGE_ERR, "%s%d: can not allocate DMA handle",
		    XGELL_IFNAME, lldev->instance);
		goto handle_failed;
	}

	/* reserve some space at the end of the buffer for recycling */
	if (ddi_dma_mem_alloc(dma_handle, HEADROOM + bf_pool->size +
	    sizeof (xgell_rx_buffer_t), p_xge_dev_attr, DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, 0, (caddr_t *)&vaddr, &real_size, &dma_acch) !=
	    DDI_SUCCESS) {
		xge_debug_ll(XGE_ERR, "%s%d: can not allocate DMA-able memory",
		    XGELL_IFNAME, lldev->instance);
		goto mem_failed;
	}

	if (HEADROOM + bf_pool->size + sizeof (xgell_rx_buffer_t) >
	    real_size) {
		xge_debug_ll(XGE_ERR, "%s%d: can not allocate DMA-able memory",
		    XGELL_IFNAME, lldev->instance);
		goto bind_failed;
	}

	if (ddi_dma_addr_bind_handle(dma_handle, NULL, (char *)vaddr + HEADROOM,
	    bf_pool->size, DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, 0, &dma_cookie, &ncookies) != DDI_SUCCESS) {
		xge_debug_ll(XGE_ERR, "%s%d: out of mapping for mblk",
		    XGELL_IFNAME, lldev->instance);
		goto bind_failed;
	}

	if (ncookies != 1 || dma_cookie.dmac_size < bf_pool->size) {
		xge_debug_ll(XGE_ERR, "%s%d: can not handle partial DMA",
		    XGELL_IFNAME, lldev->instance);
		goto check_failed;
	}

	dma_addr = dma_cookie.dmac_laddress;

	rx_buffer = (xgell_rx_buffer_t *)((char *)vaddr + real_size -
	    sizeof (xgell_rx_buffer_t));
	rx_buffer->next = NULL;
	rx_buffer->vaddr = vaddr;
	rx_buffer->dma_addr = dma_addr;
	rx_buffer->dma_handle = dma_handle;
	rx_buffer->dma_acch = dma_acch;
	rx_buffer->ring = ring;
	rx_buffer->frtn.free_func = xgell_rx_buffer_recycle;
	rx_buffer->frtn.free_arg = (void *)rx_buffer;

	return (rx_buffer);

check_failed:
	(void) ddi_dma_unbind_handle(dma_handle);
bind_failed:
	XGE_OS_MEMORY_CHECK_FREE(vaddr, 0);
	ddi_dma_mem_free(&dma_acch);
mem_failed:
	ddi_dma_free_handle(&dma_handle);
handle_failed:

	return (NULL);
}

/*
 * xgell_rx_destroy_buffer_pool
 *
 * Destroy buffer pool. If there is still any buffer hold by upper layer,
 * recorded by bf_pool.post, return DDI_FAILURE to reject to be unloaded.
 */
static boolean_t
xgell_rx_destroy_buffer_pool(xgell_rx_ring_t *ring)
{
	xgelldev_t *lldev = ring->lldev;
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;
	xgell_rx_buffer_t *rx_buffer;
	ddi_dma_handle_t  dma_handle;
	ddi_acc_handle_t  dma_acch;
	int i;

	/*
	 * If the pool has been destroied, just return B_TRUE
	 */
	if (!bf_pool->live)
		return (B_TRUE);

	mutex_enter(&bf_pool->recycle_lock);
	if (bf_pool->recycle > 0) {
		mutex_enter(&bf_pool->pool_lock);
		bf_pool->recycle_tail->next = bf_pool->head;
		bf_pool->head = bf_pool->recycle_head;
		bf_pool->recycle_tail = bf_pool->recycle_head = NULL;
		bf_pool->post -= bf_pool->recycle;
		bf_pool->free += bf_pool->recycle;
		bf_pool->recycle = 0;
		mutex_exit(&bf_pool->pool_lock);
	}
	mutex_exit(&bf_pool->recycle_lock);

	/*
	 * If there is any posted buffer, the driver should reject to be
	 * detached. Need notice upper layer to release them.
	 */
	if (bf_pool->post != 0) {
		xge_debug_ll(XGE_ERR,
		    "%s%d has some buffers not be recycled, try later!",
		    XGELL_IFNAME, lldev->instance);
		return (B_FALSE);
	}

	/*
	 * Release buffers one by one.
	 */
	for (i = bf_pool->total; i > 0; i--) {
		rx_buffer = bf_pool->head;
		xge_assert(rx_buffer != NULL);

		bf_pool->head = rx_buffer->next;

		dma_handle = rx_buffer->dma_handle;
		dma_acch = rx_buffer->dma_acch;

		if (ddi_dma_unbind_handle(dma_handle) != DDI_SUCCESS) {
			xge_debug_ll(XGE_ERR, "failed to unbind DMA handle!");
			bf_pool->head = rx_buffer;
			return (B_FALSE);
		}
		ddi_dma_mem_free(&dma_acch);
		ddi_dma_free_handle(&dma_handle);

		bf_pool->total--;
		bf_pool->free--;
	}

	xge_assert(!mutex_owned(&bf_pool->pool_lock));

	mutex_destroy(&bf_pool->recycle_lock);
	mutex_destroy(&bf_pool->pool_lock);
	bf_pool->live = B_FALSE;

	return (B_TRUE);
}

/*
 * xgell_rx_create_buffer_pool
 *
 * Initialize RX buffer pool for all RX rings. Refer to rx_buffer_pool_t.
 */
static boolean_t
xgell_rx_create_buffer_pool(xgell_rx_ring_t *ring)
{
	xgelldev_t *lldev = ring->lldev;
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;
	xge_hal_device_t *hldev;
	xgell_rx_buffer_t *rx_buffer;
	int i;

	if (bf_pool->live)
		return (B_TRUE);

	hldev = (xge_hal_device_t *)lldev->devh;

	bf_pool->total = 0;
	bf_pool->size = XGELL_MAX_FRAME_SIZE(hldev);
	bf_pool->head = NULL;
	bf_pool->free = 0;
	bf_pool->post = 0;
	bf_pool->post_hiwat = lldev->config.rx_buffer_post_hiwat;
	bf_pool->recycle = 0;
	bf_pool->recycle_head = NULL;
	bf_pool->recycle_tail = NULL;
	bf_pool->live = B_TRUE;

	mutex_init(&bf_pool->pool_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hldev->irqh));
	mutex_init(&bf_pool->recycle_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hldev->irqh));

	/*
	 * Allocate buffers one by one. If failed, destroy whole pool by
	 * call to xgell_rx_destroy_buffer_pool().
	 */

	for (i = 0; i < lldev->config.rx_buffer_total; i++) {
		if ((rx_buffer = xgell_rx_buffer_alloc(ring)) == NULL) {
			(void) xgell_rx_destroy_buffer_pool(ring);
			return (B_FALSE);
		}

		rx_buffer->next = bf_pool->head;
		bf_pool->head = rx_buffer;

		bf_pool->total++;
		bf_pool->free++;
	}

	return (B_TRUE);
}

/*
 * xgell_rx_dtr_replenish
 *
 * Replenish descriptor with rx_buffer in RX buffer pool.
 * The dtr should be post right away.
 */
xge_hal_status_e
xgell_rx_dtr_replenish(xge_hal_channel_h channelh, xge_hal_dtr_h dtr, int index,
    void *userdata, xge_hal_channel_reopen_e reopen)
{
	xgell_rx_ring_t *ring = userdata;
	xgell_rx_buffer_pool_t *bf_pool = &ring->bf_pool;
	xgell_rx_buffer_t *rx_buffer;
	xgell_rxd_priv_t *rxd_priv;

	mutex_enter(&bf_pool->pool_lock);
	if (bf_pool->head == NULL) {
		xge_debug_ll(XGE_ERR, "no more available rx DMA buffer!");
		return (XGE_HAL_FAIL);
	}
	rx_buffer = bf_pool->head;
	xge_assert(rx_buffer);
	xge_assert(rx_buffer->dma_addr);

	bf_pool->head = rx_buffer->next;
	bf_pool->free--;
	mutex_exit(&bf_pool->pool_lock);

	rxd_priv = (xgell_rxd_priv_t *)xge_hal_ring_dtr_private(channelh, dtr);
	xge_hal_ring_dtr_1b_set(dtr, rx_buffer->dma_addr, bf_pool->size);

	rxd_priv->rx_buffer = rx_buffer;

	return (XGE_HAL_OK);
}

/*
 * xgell_get_ip_offset
 *
 * Calculate the offset to IP header.
 */
static inline int
xgell_get_ip_offset(xge_hal_dtr_info_t *ext_info)
{
	int ip_off;

	/* get IP-header offset */
	switch (ext_info->frame) {
	case XGE_HAL_FRAME_TYPE_DIX:
		ip_off = XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE;
		break;
	case XGE_HAL_FRAME_TYPE_IPX:
		ip_off = (XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE +
		    XGE_HAL_HEADER_802_2_SIZE +
		    XGE_HAL_HEADER_SNAP_SIZE);
		break;
	case XGE_HAL_FRAME_TYPE_LLC:
		ip_off = (XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE +
		    XGE_HAL_HEADER_802_2_SIZE);
		break;
	case XGE_HAL_FRAME_TYPE_SNAP:
		ip_off = (XGE_HAL_HEADER_ETHERNET_II_802_3_SIZE +
		    XGE_HAL_HEADER_SNAP_SIZE);
		break;
	default:
		ip_off = 0;
		break;
	}

	if ((ext_info->proto & XGE_HAL_FRAME_PROTO_IPV4 ||
	    ext_info->proto & XGE_HAL_FRAME_PROTO_IPV6) &&
	    (ext_info->proto & XGE_HAL_FRAME_PROTO_VLAN_TAGGED)) {
		ip_off += XGE_HAL_HEADER_VLAN_SIZE;
	}

	return (ip_off);
}

/*
 * xgell_rx_hcksum_assoc
 *
 * Judge the packet type and then call to hcksum_assoc() to associate
 * h/w checksum information.
 */
static inline void
xgell_rx_hcksum_assoc(mblk_t *mp, char *vaddr, int pkt_length,
    xge_hal_dtr_info_t *ext_info)
{
	int cksum_flags = 0;

	if (!(ext_info->proto & XGE_HAL_FRAME_PROTO_IP_FRAGMENTED)) {
		if (ext_info->proto & XGE_HAL_FRAME_PROTO_TCP_OR_UDP) {
			if (ext_info->l3_cksum == XGE_HAL_L3_CKSUM_OK) {
				cksum_flags |= HCK_IPV4_HDRCKSUM_OK;
			}
			if (ext_info->l4_cksum == XGE_HAL_L4_CKSUM_OK) {
				cksum_flags |= HCK_FULLCKSUM_OK;
			}
			if (cksum_flags != 0) {
				mac_hcksum_set(mp, 0, 0, 0, 0, cksum_flags);
			}
		}
	} else if (ext_info->proto &
	    (XGE_HAL_FRAME_PROTO_IPV4 | XGE_HAL_FRAME_PROTO_IPV6)) {
		/*
		 * Just pass the partial cksum up to IP.
		 */
		int ip_off = xgell_get_ip_offset(ext_info);
		int start, end = pkt_length - ip_off;

		if (ext_info->proto & XGE_HAL_FRAME_PROTO_IPV4) {
			struct ip *ip =
			    (struct ip *)(vaddr + ip_off);
			start = ip->ip_hl * 4;
		} else {
			start = 40;
		}
		cksum_flags |= HCK_PARTIALCKSUM;
		mac_hcksum_set(mp, start, 0, end,
		    ntohs(ext_info->l4_cksum), cksum_flags);
	}
}

/*
 * xgell_rx_1b_msg_alloc
 *
 * Allocate message header for data buffer, and decide if copy the packet to
 * new data buffer to release big rx_buffer to save memory.
 *
 * If the pkt_length <= XGELL_RX_DMA_LOWAT, call allocb() to allocate
 * new message and copy the payload in.
 */
static mblk_t *
xgell_rx_1b_msg_alloc(xgell_rx_ring_t *ring, xgell_rx_buffer_t *rx_buffer,
    int pkt_length, xge_hal_dtr_info_t *ext_info, boolean_t *copyit)
{
	xgelldev_t *lldev = ring->lldev;
	mblk_t *mp;
	char *vaddr;

	vaddr = (char *)rx_buffer->vaddr + HEADROOM;
	/*
	 * Copy packet into new allocated message buffer, if pkt_length
	 * is less than XGELL_RX_DMA_LOWAT
	 */
	if (*copyit || pkt_length <= lldev->config.rx_dma_lowat) {
		if ((mp = allocb(pkt_length + HEADROOM, 0)) == NULL) {
			return (NULL);
		}
		mp->b_rptr += HEADROOM;
		bcopy(vaddr, mp->b_rptr, pkt_length);
		mp->b_wptr = mp->b_rptr + pkt_length;
		*copyit = B_TRUE;
		return (mp);
	}

	/*
	 * Just allocate mblk for current data buffer
	 */
	if ((mp = (mblk_t *)desballoc((unsigned char *)vaddr, pkt_length, 0,
	    &rx_buffer->frtn)) == NULL) {
		/* Drop it */
		return (NULL);
	}
	/*
	 * Adjust the b_rptr/b_wptr in the mblk_t structure.
	 */
	mp->b_wptr += pkt_length;

	return (mp);
}

/*
 * xgell_rx_1b_callback
 *
 * If the interrupt is because of a received frame or if the receive ring
 * contains fresh as yet un-processed frames, this function is called.
 */
static xge_hal_status_e
xgell_rx_1b_callback(xge_hal_channel_h channelh, xge_hal_dtr_h dtr, u8 t_code,
    void *userdata)
{
	xgell_rx_ring_t *ring = (xgell_rx_ring_t *)userdata;
	xgelldev_t *lldev = ring->lldev;
	xgell_rx_buffer_t *rx_buffer;
	mblk_t *mp_head = NULL;
	mblk_t *mp_end  = NULL;
	int pkt_burst = 0;

	xge_debug_ll(XGE_TRACE, "xgell_rx_1b_callback on ring %d", ring->index);

	mutex_enter(&ring->bf_pool.pool_lock);
	do {
		int pkt_length;
		dma_addr_t dma_data;
		mblk_t *mp;
		boolean_t copyit = B_FALSE;

		xgell_rxd_priv_t *rxd_priv = ((xgell_rxd_priv_t *)
		    xge_hal_ring_dtr_private(channelh, dtr));
		xge_hal_dtr_info_t ext_info;

		rx_buffer = rxd_priv->rx_buffer;

		xge_hal_ring_dtr_1b_get(channelh, dtr, &dma_data, &pkt_length);
		xge_hal_ring_dtr_info_get(channelh, dtr, &ext_info);

		xge_assert(dma_data == rx_buffer->dma_addr);

		if (t_code != 0) {
			xge_debug_ll(XGE_ERR, "%s%d: rx: dtr 0x%"PRIx64
			    " completed due to error t_code %01x", XGELL_IFNAME,
			    lldev->instance, (uint64_t)(uintptr_t)dtr, t_code);

			(void) xge_hal_device_handle_tcode(channelh, dtr,
			    t_code);
			xge_hal_ring_dtr_free(channelh, dtr); /* drop it */
			xgell_rx_buffer_release(rx_buffer);
			continue;
		}

		/*
		 * Sync the DMA memory
		 */
		if (ddi_dma_sync(rx_buffer->dma_handle, 0, pkt_length,
		    DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS) {
			xge_debug_ll(XGE_ERR, "%s%d: rx: can not do DMA sync",
			    XGELL_IFNAME, lldev->instance);
			xge_hal_ring_dtr_free(channelh, dtr); /* drop it */
			xgell_rx_buffer_release(rx_buffer);
			continue;
		}

		/*
		 * Allocate message for the packet.
		 */
		if (ring->bf_pool.post > ring->bf_pool.post_hiwat) {
			copyit = B_TRUE;
		} else {
			copyit = B_FALSE;
		}

		mp = xgell_rx_1b_msg_alloc(ring, rx_buffer, pkt_length,
		    &ext_info, &copyit);

		xge_hal_ring_dtr_free(channelh, dtr);

		/*
		 * Release the buffer and recycle it later
		 */
		if ((mp == NULL) || copyit) {
			xgell_rx_buffer_release(rx_buffer);
		} else {
			/*
			 * Count it since the buffer should be loaned up.
			 */
			ring->bf_pool.post++;
		}
		if (mp == NULL) {
			xge_debug_ll(XGE_ERR,
			    "%s%d: rx: can not allocate mp mblk",
			    XGELL_IFNAME, lldev->instance);
			continue;
		}

		/*
		 * Associate cksum_flags per packet type and h/w
		 * cksum flags.
		 */
		xgell_rx_hcksum_assoc(mp, (char *)rx_buffer->vaddr + HEADROOM,
		    pkt_length, &ext_info);

		ring->rx_pkts++;
		ring->rx_bytes += pkt_length;

		if (mp_head == NULL) {
			mp_head = mp;
			mp_end = mp;
		} else {
			mp_end->b_next = mp;
			mp_end = mp;
		}

		/*
		 * Inlined implemented polling function.
		 */
		if ((ring->poll_mp == NULL) && (ring->poll_bytes > 0)) {
			ring->poll_mp = mp_head;
		}
		if (ring->poll_mp != NULL) {
			if ((ring->poll_bytes -= pkt_length) <= 0) {
				/* have polled enough packets. */
				break;
			} else {
				/* continue polling packets. */
				continue;
			}
		}

		/*
		 * We're not in polling mode, so try to chain more messages
		 * or send the chain up according to pkt_burst.
		 */
		if (++pkt_burst < lldev->config.rx_pkt_burst)
			continue;

		if (ring->bf_pool.post > ring->bf_pool.post_hiwat) {
			/* Replenish rx buffers */
			xgell_rx_buffer_replenish_all(ring);
		}
		mutex_exit(&ring->bf_pool.pool_lock);
		if (mp_head != NULL) {
			mac_rx_ring(lldev->mh, ring->ring_handle, mp_head,
			    ring->ring_gen_num);
		}
		mp_head = mp_end  = NULL;
		pkt_burst = 0;
		mutex_enter(&ring->bf_pool.pool_lock);

	} while (xge_hal_ring_dtr_next_completed(channelh, &dtr, &t_code) ==
	    XGE_HAL_OK);

	/*
	 * Always call replenish_all to recycle rx_buffers.
	 */
	xgell_rx_buffer_replenish_all(ring);
	mutex_exit(&ring->bf_pool.pool_lock);

	/*
	 * If we're not in polling cycle, call mac_rx(), otherwise
	 * just return while leaving packets chained to ring->poll_mp.
	 */
	if ((ring->poll_mp == NULL) && (mp_head != NULL)) {
		mac_rx_ring(lldev->mh, ring->ring_handle, mp_head,
		    ring->ring_gen_num);
	}

	return (XGE_HAL_OK);
}

mblk_t *
xgell_rx_poll(void *arg, int bytes_to_pickup)
{
	xgell_rx_ring_t *ring = (xgell_rx_ring_t *)arg;
	int got_rx = 0;
	mblk_t *mp;

	xge_debug_ll(XGE_TRACE, "xgell_rx_poll on ring %d", ring->index);

	ring->poll_mp = NULL;
	ring->poll_bytes = bytes_to_pickup;
	(void) xge_hal_device_poll_rx_channel(ring->channelh, &got_rx);

	mp = ring->poll_mp;
	ring->poll_bytes = -1;
	ring->polled_bytes += got_rx;
	ring->poll_mp = NULL;

	return (mp);
}

/*
 * xgell_xmit_compl
 *
 * If an interrupt was raised to indicate DMA complete of the Tx packet,
 * this function is called. It identifies the last TxD whose buffer was
 * freed and frees all skbs whose data have already DMA'ed into the NICs
 * internal memory.
 */
static xge_hal_status_e
xgell_xmit_compl(xge_hal_channel_h channelh, xge_hal_dtr_h dtr, u8 t_code,
    void *userdata)
{
	xgell_tx_ring_t *ring = userdata;
	xgelldev_t *lldev = ring->lldev;

	do {
		xgell_txd_priv_t *txd_priv = ((xgell_txd_priv_t *)
		    xge_hal_fifo_dtr_private(dtr));
		int i;

		if (t_code) {
			xge_debug_ll(XGE_TRACE, "%s%d: tx: dtr 0x%"PRIx64
			    " completed due to error t_code %01x", XGELL_IFNAME,
			    lldev->instance, (uint64_t)(uintptr_t)dtr, t_code);

			(void) xge_hal_device_handle_tcode(channelh, dtr,
			    t_code);
		}

		for (i = 0; i < txd_priv->handle_cnt; i++) {
			if (txd_priv->dma_handles[i] != NULL) {
				xge_assert(txd_priv->dma_handles[i]);
				(void) ddi_dma_unbind_handle(
				    txd_priv->dma_handles[i]);
				ddi_dma_free_handle(&txd_priv->dma_handles[i]);
				txd_priv->dma_handles[i] = 0;
			}
		}
		txd_priv->handle_cnt = 0;

		xge_hal_fifo_dtr_free(channelh, dtr);

		if (txd_priv->mblk != NULL) {
			freemsg(txd_priv->mblk);
			txd_priv->mblk = NULL;
		}

	} while (xge_hal_fifo_dtr_next_completed(channelh, &dtr, &t_code) ==
	    XGE_HAL_OK);

	if (ring->need_resched)
		mac_tx_ring_update(lldev->mh, ring->ring_handle);

	return (XGE_HAL_OK);
}

mblk_t *
xgell_ring_tx(void *arg, mblk_t *mp)
{
	xgell_tx_ring_t *ring = (xgell_tx_ring_t *)arg;
	mblk_t *bp;
	xgelldev_t *lldev = ring->lldev;
	xge_hal_device_t *hldev = lldev->devh;
	xge_hal_status_e status;
	xge_hal_dtr_h dtr;
	xgell_txd_priv_t *txd_priv;
	uint32_t hckflags;
	uint32_t lsoflags;
	uint32_t mss;
	int handle_cnt, frag_cnt, ret, i, copied;
	boolean_t used_copy;
	uint64_t sent_bytes;

_begin:
	handle_cnt = frag_cnt = 0;
	sent_bytes = 0;

	if (!lldev->is_initialized || lldev->in_reset)
		return (mp);

	/*
	 * If the free Tx dtrs count reaches the lower threshold,
	 * inform the gld to stop sending more packets till the free
	 * dtrs count exceeds higher threshold. Driver informs the
	 * gld through gld_sched call, when the free dtrs count exceeds
	 * the higher threshold.
	 */
	if (xge_hal_channel_dtr_count(ring->channelh)
	    <= XGELL_TX_LEVEL_LOW) {
		xge_debug_ll(XGE_TRACE, "%s%d: queue %d: err on xmit,"
		    "free descriptors count at low threshold %d",
		    XGELL_IFNAME, lldev->instance,
		    ((xge_hal_channel_t *)ring->channelh)->post_qid,
		    XGELL_TX_LEVEL_LOW);
		goto _exit;
	}

	status = xge_hal_fifo_dtr_reserve(ring->channelh, &dtr);
	if (status != XGE_HAL_OK) {
		switch (status) {
		case XGE_HAL_INF_CHANNEL_IS_NOT_READY:
			xge_debug_ll(XGE_ERR,
			    "%s%d: channel %d is not ready.", XGELL_IFNAME,
			    lldev->instance,
			    ((xge_hal_channel_t *)
			    ring->channelh)->post_qid);
			goto _exit;
		case XGE_HAL_INF_OUT_OF_DESCRIPTORS:
			xge_debug_ll(XGE_TRACE, "%s%d: queue %d: error in xmit,"
			    " out of descriptors.", XGELL_IFNAME,
			    lldev->instance,
			    ((xge_hal_channel_t *)
			    ring->channelh)->post_qid);
			goto _exit;
		default:
			return (mp);
		}
	}

	txd_priv = xge_hal_fifo_dtr_private(dtr);
	txd_priv->mblk = mp;

	/*
	 * VLAN tag should be passed down along with MAC header, so h/w needn't
	 * do insertion.
	 *
	 * For NIC driver that has to strip and re-insert VLAN tag, the example
	 * is the other implementation for xge. The driver can simple bcopy()
	 * ether_vlan_header to overwrite VLAN tag and let h/w insert the tag
	 * automatically, since it's impossible that GLD sends down mp(s) with
	 * splited ether_vlan_header.
	 *
	 * struct ether_vlan_header *evhp;
	 * uint16_t tci;
	 *
	 * evhp = (struct ether_vlan_header *)mp->b_rptr;
	 * if (evhp->ether_tpid == htons(VLAN_TPID)) {
	 *	tci = ntohs(evhp->ether_tci);
	 *	(void) bcopy(mp->b_rptr, mp->b_rptr + VLAN_TAGSZ,
	 *	    2 * ETHERADDRL);
	 *	mp->b_rptr += VLAN_TAGSZ;
	 *
	 *	xge_hal_fifo_dtr_vlan_set(dtr, tci);
	 * }
	 */

	copied = 0;
	used_copy = B_FALSE;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		int mblen;
		uint_t ncookies;
		ddi_dma_cookie_t dma_cookie;
		ddi_dma_handle_t dma_handle;

		/* skip zero-length message blocks */
		mblen = MBLKL(bp);
		if (mblen == 0) {
			continue;
		}

		sent_bytes += mblen;

		/*
		 * Check the message length to decide to DMA or bcopy() data
		 * to tx descriptor(s).
		 */
		if (mblen < lldev->config.tx_dma_lowat &&
		    (copied + mblen) < lldev->tx_copied_max) {
			xge_hal_status_e rc;
			rc = xge_hal_fifo_dtr_buffer_append(ring->channelh,
			    dtr, bp->b_rptr, mblen);
			if (rc == XGE_HAL_OK) {
				used_copy = B_TRUE;
				copied += mblen;
				continue;
			} else if (used_copy) {
				xge_hal_fifo_dtr_buffer_finalize(
				    ring->channelh, dtr, frag_cnt++);
				used_copy = B_FALSE;
			}
		} else if (used_copy) {
			xge_hal_fifo_dtr_buffer_finalize(ring->channelh,
			    dtr, frag_cnt++);
			used_copy = B_FALSE;
		}

		ret = ddi_dma_alloc_handle(lldev->dev_info, &tx_dma_attr,
		    DDI_DMA_DONTWAIT, 0, &dma_handle);
		if (ret != DDI_SUCCESS) {
			xge_debug_ll(XGE_ERR,
			    "%s%d: can not allocate dma handle", XGELL_IFNAME,
			    lldev->instance);
			goto _exit_cleanup;
		}

		ret = ddi_dma_addr_bind_handle(dma_handle, NULL,
		    (caddr_t)bp->b_rptr, mblen,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, 0,
		    &dma_cookie, &ncookies);

		switch (ret) {
		case DDI_DMA_MAPPED:
			/* everything's fine */
			break;

		case DDI_DMA_NORESOURCES:
			xge_debug_ll(XGE_ERR,
			    "%s%d: can not bind dma address",
			    XGELL_IFNAME, lldev->instance);
			ddi_dma_free_handle(&dma_handle);
			goto _exit_cleanup;

		case DDI_DMA_NOMAPPING:
		case DDI_DMA_INUSE:
		case DDI_DMA_TOOBIG:
		default:
			/* drop packet, don't retry */
			xge_debug_ll(XGE_ERR,
			    "%s%d: can not map message buffer",
			    XGELL_IFNAME, lldev->instance);
			ddi_dma_free_handle(&dma_handle);
			goto _exit_cleanup;
		}

		if (ncookies + frag_cnt > hldev->config.fifo.max_frags) {
			xge_debug_ll(XGE_ERR, "%s%d: too many fragments, "
			    "requested c:%d+f:%d", XGELL_IFNAME,
			    lldev->instance, ncookies, frag_cnt);
			(void) ddi_dma_unbind_handle(dma_handle);
			ddi_dma_free_handle(&dma_handle);
			goto _exit_cleanup;
		}

		/* setup the descriptors for this data buffer */
		while (ncookies) {
			xge_hal_fifo_dtr_buffer_set(ring->channelh, dtr,
			    frag_cnt++, dma_cookie.dmac_laddress,
			    dma_cookie.dmac_size);
			if (--ncookies) {
				ddi_dma_nextcookie(dma_handle, &dma_cookie);
			}

		}

		txd_priv->dma_handles[handle_cnt++] = dma_handle;

		if (bp->b_cont &&
		    (frag_cnt + XGE_HAL_DEFAULT_FIFO_FRAGS_THRESHOLD >=
		    hldev->config.fifo.max_frags)) {
			mblk_t *nmp;

			xge_debug_ll(XGE_TRACE,
			    "too many FRAGs [%d], pull up them", frag_cnt);

			if ((nmp = msgpullup(bp->b_cont, -1)) == NULL) {
				/* Drop packet, don't retry */
				xge_debug_ll(XGE_ERR,
				    "%s%d: can not pullup message buffer",
				    XGELL_IFNAME, lldev->instance);
				goto _exit_cleanup;
			}
			freemsg(bp->b_cont);
			bp->b_cont = nmp;
		}
	}

	/* finalize unfinished copies */
	if (used_copy) {
		xge_hal_fifo_dtr_buffer_finalize(ring->channelh, dtr,
		    frag_cnt++);
	}

	txd_priv->handle_cnt = handle_cnt;

	/*
	 * If LSO is required, just call xge_hal_fifo_dtr_mss_set(dtr, mss) to
	 * do all necessary work.
	 */
	mac_lso_get(mp, &mss, &lsoflags);

	if (lsoflags & HW_LSO) {
		xge_assert((mss != 0) && (mss <= XGE_HAL_DEFAULT_MTU));
		xge_hal_fifo_dtr_mss_set(dtr, mss);
	}

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &hckflags);
	if (hckflags & HCK_IPV4_HDRCKSUM) {
		xge_hal_fifo_dtr_cksum_set_bits(dtr,
		    XGE_HAL_TXD_TX_CKO_IPV4_EN);
	}
	if (hckflags & HCK_FULLCKSUM) {
		xge_hal_fifo_dtr_cksum_set_bits(dtr, XGE_HAL_TXD_TX_CKO_TCP_EN |
		    XGE_HAL_TXD_TX_CKO_UDP_EN);
	}

	xge_hal_fifo_dtr_post(ring->channelh, dtr);

	/* Update per-ring tx statistics */
	atomic_inc_64(&ring->tx_pkts);
	atomic_add_64(&ring->tx_bytes, sent_bytes);

	return (NULL);

_exit_cleanup:
	/*
	 * Could not successfully transmit but have changed the message,
	 * so just free it and return NULL
	 */
	for (i = 0; i < handle_cnt; i++) {
		(void) ddi_dma_unbind_handle(txd_priv->dma_handles[i]);
		ddi_dma_free_handle(&txd_priv->dma_handles[i]);
		txd_priv->dma_handles[i] = 0;
	}

	xge_hal_fifo_dtr_free(ring->channelh, dtr);

	freemsg(mp);
	return (NULL);

_exit:
	ring->need_resched = B_TRUE;
	return (mp);
}

/*
 * xgell_ring_macaddr_init
 */
static void
xgell_rx_ring_maddr_init(xgell_rx_ring_t *ring)
{
	int i;
	xgelldev_t *lldev = ring->lldev;
	xge_hal_device_t *hldev = lldev->devh;
	int slot_start;

	xge_debug_ll(XGE_TRACE, "%s", "xgell_rx_ring_maddr_init");

	ring->mmac.naddr = XGE_RX_MULTI_MAC_ADDRESSES_MAX;
	ring->mmac.naddrfree = ring->mmac.naddr;

	/*
	 * For the default rx ring, the first MAC address is the factory one.
	 * This will be set by the framework, so need to clear it for now.
	 */
	(void) xge_hal_device_macaddr_clear(hldev, 0);

	/*
	 * Read the MAC address Configuration Memory from HAL.
	 * The first slot will hold a factory MAC address, contents in other
	 * slots will be FF:FF:FF:FF:FF:FF.
	 */
	slot_start = ring->index * 32;
	for (i = 0; i < ring->mmac.naddr; i++) {
		(void) xge_hal_device_macaddr_get(hldev, slot_start + i,
		    ring->mmac.mac_addr + i);
		ring->mmac.mac_addr_set[i] = B_FALSE;
	}
}

static int xgell_maddr_set(xgelldev_t *, int, uint8_t *);

static int
xgell_addmac(void *arg, const uint8_t *mac_addr)
{
	xgell_rx_ring_t *ring = arg;
	xgelldev_t *lldev = ring->lldev;
	xge_hal_device_t *hldev = lldev->devh;
	int slot;
	int slot_start;

	xge_debug_ll(XGE_TRACE, "%s", "xgell_addmac");

	mutex_enter(&lldev->genlock);

	if (ring->mmac.naddrfree == 0) {
		mutex_exit(&lldev->genlock);
		return (ENOSPC);
	}

	/* First slot is for factory MAC address */
	for (slot = 0; slot < ring->mmac.naddr; slot++) {
		if (ring->mmac.mac_addr_set[slot] == B_FALSE) {
			break;
		}
	}

	ASSERT(slot < ring->mmac.naddr);

	slot_start = ring->index * 32;

	if (xgell_maddr_set(lldev, slot_start + slot, (uint8_t *)mac_addr) !=
	    0) {
		mutex_exit(&lldev->genlock);
		return (EIO);
	}

	/* Simply enable RTS for the whole section. */
	(void) xge_hal_device_rts_section_enable(hldev, slot_start + slot);

	/*
	 * Read back the MAC address from HAL to keep the array up to date.
	 */
	if (xge_hal_device_macaddr_get(hldev, slot_start + slot,
	    ring->mmac.mac_addr + slot) != XGE_HAL_OK) {
		(void) xge_hal_device_macaddr_clear(hldev, slot_start + slot);
		return (EIO);
	}

	ring->mmac.mac_addr_set[slot] = B_TRUE;
	ring->mmac.naddrfree--;

	mutex_exit(&lldev->genlock);

	return (0);
}

static int
xgell_remmac(void *arg, const uint8_t *mac_addr)
{
	xgell_rx_ring_t *ring = arg;
	xgelldev_t *lldev = ring->lldev;
	xge_hal_device_t *hldev = lldev->devh;
	xge_hal_status_e status;
	int slot;
	int slot_start;

	xge_debug_ll(XGE_TRACE, "%s", "xgell_remmac");

	slot = xge_hal_device_macaddr_find(hldev, (uint8_t *)mac_addr);
	if (slot == -1)
		return (EINVAL);

	slot_start = ring->index * 32;

	/*
	 * Adjust slot to the offset in the MAC array of this ring (group).
	 */
	slot -= slot_start;

	/*
	 * Only can remove a pre-set MAC address for this ring (group).
	 */
	if (slot < 0 || slot >= ring->mmac.naddr)
		return (EINVAL);


	xge_assert(ring->mmac.mac_addr_set[slot]);

	mutex_enter(&lldev->genlock);
	if (!ring->mmac.mac_addr_set[slot]) {
		mutex_exit(&lldev->genlock);
		/*
		 * The result will be unexpected when reach here. WARNING!
		 */
		xge_debug_ll(XGE_ERR,
		    "%s%d: caller is trying to remove an unset MAC address",
		    XGELL_IFNAME, lldev->instance);
		return (ENXIO);
	}

	status = xge_hal_device_macaddr_clear(hldev, slot_start + slot);
	if (status != XGE_HAL_OK) {
		mutex_exit(&lldev->genlock);
		return (EIO);
	}

	ring->mmac.mac_addr_set[slot] = B_FALSE;
	ring->mmac.naddrfree++;

	/*
	 * TODO: Disable MAC RTS if all addresses have been cleared.
	 */

	/*
	 * Read back the MAC address from HAL to keep the array up to date.
	 */
	(void) xge_hal_device_macaddr_get(hldev, slot_start + slot,
	    ring->mmac.mac_addr + slot);
	mutex_exit(&lldev->genlock);

	return (0);
}

/*
 * Temporarily calling hal function.
 *
 * With MSI-X implementation, no lock is needed, so that the interrupt
 * handling could be faster.
 */
int
xgell_rx_ring_intr_enable(mac_intr_handle_t ih)
{
	xgell_rx_ring_t *ring = (xgell_rx_ring_t *)ih;

	mutex_enter(&ring->ring_lock);
	xge_hal_device_rx_channel_disable_polling(ring->channelh);
	mutex_exit(&ring->ring_lock);

	return (0);
}

int
xgell_rx_ring_intr_disable(mac_intr_handle_t ih)
{
	xgell_rx_ring_t *ring = (xgell_rx_ring_t *)ih;

	mutex_enter(&ring->ring_lock);
	xge_hal_device_rx_channel_enable_polling(ring->channelh);
	mutex_exit(&ring->ring_lock);

	return (0);
}

static int
xgell_rx_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	xgell_rx_ring_t *rx_ring = (xgell_rx_ring_t *)rh;

	rx_ring->ring_gen_num = mr_gen_num;

	return (0);
}

/*ARGSUSED*/
static void
xgell_rx_ring_stop(mac_ring_driver_t rh)
{
}

/*ARGSUSED*/
static int
xgell_tx_ring_start(mac_ring_driver_t rh, uint64_t useless)
{
	return (0);
}

/*ARGSUSED*/
static void
xgell_tx_ring_stop(mac_ring_driver_t rh)
{
}

/*
 * Callback funtion for MAC layer to register all rings.
 *
 * Xframe hardware doesn't support grouping explicitly, so the driver needs
 * to pretend having resource groups. We may also optionally group all 8 rx
 * rings into a single group for increased scalability on CMT architectures,
 * or group one rx ring per group for maximum virtualization.
 *
 * TX grouping is actually done by framework, so, just register all TX
 * resources without grouping them.
 */
void
xgell_fill_ring(void *arg, mac_ring_type_t rtype, const int rg_index,
    const int index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	xgelldev_t *lldev = (xgelldev_t *)arg;
	mac_intr_t *mintr;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		xgell_rx_ring_t *rx_ring;

		xge_assert(index < lldev->init_rx_rings);
		xge_assert(rg_index < lldev->init_rx_groups);

		/*
		 * Performance vs. Virtualization
		 */
		if (lldev->init_rx_rings == lldev->init_rx_groups)
			rx_ring = lldev->rx_ring + rg_index;
		else
			rx_ring = lldev->rx_ring + index;

		rx_ring->ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)rx_ring;
		infop->mri_start = xgell_rx_ring_start;
		infop->mri_stop = xgell_rx_ring_stop;
		infop->mri_poll = xgell_rx_poll;
		infop->mri_stat = xgell_rx_ring_stat;

		mintr = &infop->mri_intr;
		mintr->mi_handle = (mac_intr_handle_t)rx_ring;
		mintr->mi_enable = xgell_rx_ring_intr_enable;
		mintr->mi_disable = xgell_rx_ring_intr_disable;

		break;
	}
	case MAC_RING_TYPE_TX: {
		xgell_tx_ring_t *tx_ring;

		xge_assert(rg_index == -1);

		xge_assert((index >= 0) && (index < lldev->init_tx_rings));

		tx_ring = lldev->tx_ring + index;
		tx_ring->ring_handle = rh;

		infop->mri_driver = (mac_ring_driver_t)tx_ring;
		infop->mri_start = xgell_tx_ring_start;
		infop->mri_stop = xgell_tx_ring_stop;
		infop->mri_tx = xgell_ring_tx;
		infop->mri_stat = xgell_tx_ring_stat;

		break;
	}
	default:
		break;
	}
}

void
xgell_fill_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	xgelldev_t *lldev = (xgelldev_t *)arg;

	switch (rtype) {
	case MAC_RING_TYPE_RX: {
		xgell_rx_ring_t *rx_ring;

		xge_assert(index < lldev->init_rx_groups);

		rx_ring = lldev->rx_ring + index;

		rx_ring->group_handle = gh;

		infop->mgi_driver = (mac_group_driver_t)rx_ring;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = xgell_addmac;
		infop->mgi_remmac = xgell_remmac;
		infop->mgi_count = lldev->init_rx_rings / lldev->init_rx_groups;

		break;
	}
	case MAC_RING_TYPE_TX:
		xge_assert(0);
		break;
	default:
		break;
	}
}

/*
 * xgell_macaddr_set
 */
static int
xgell_maddr_set(xgelldev_t *lldev, int index, uint8_t *macaddr)
{
	xge_hal_device_t *hldev = lldev->devh;
	xge_hal_status_e status;

	xge_debug_ll(XGE_TRACE, "%s", "xgell_maddr_set");

	xge_debug_ll(XGE_TRACE,
	    "setting macaddr: 0x%02x-%02x-%02x-%02x-%02x-%02x",
	    macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]);

	status = xge_hal_device_macaddr_set(hldev, index, (uchar_t *)macaddr);

	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "%s%d: can not set mac address",
		    XGELL_IFNAME, lldev->instance);
		return (EIO);
	}

	return (0);
}

/*
 * xgell_rx_dtr_term
 *
 * Function will be called by HAL to terminate all DTRs for
 * Ring(s) type of channels.
 */
static void
xgell_rx_dtr_term(xge_hal_channel_h channelh, xge_hal_dtr_h dtrh,
    xge_hal_dtr_state_e state, void *userdata, xge_hal_channel_reopen_e reopen)
{
	xgell_rxd_priv_t *rxd_priv =
	    ((xgell_rxd_priv_t *)xge_hal_ring_dtr_private(channelh, dtrh));
	xgell_rx_buffer_t *rx_buffer = rxd_priv->rx_buffer;

	if (state == XGE_HAL_DTR_STATE_POSTED) {
		xgell_rx_ring_t *ring = rx_buffer->ring;

		mutex_enter(&ring->bf_pool.pool_lock);
		xge_hal_ring_dtr_free(channelh, dtrh);
		xgell_rx_buffer_release(rx_buffer);
		mutex_exit(&ring->bf_pool.pool_lock);
	}
}

/*
 * To open a rx ring.
 */
static boolean_t
xgell_rx_ring_open(xgell_rx_ring_t *rx_ring)
{
	xge_hal_status_e status;
	xge_hal_channel_attr_t attr;
	xgelldev_t *lldev = rx_ring->lldev;
	xge_hal_device_t *hldev = lldev->devh;

	if (rx_ring->live)
		return (B_TRUE);

	/* Create the buffer pool first */
	if (!xgell_rx_create_buffer_pool(rx_ring)) {
		xge_debug_ll(XGE_ERR, "can not create buffer pool for ring: %d",
		    rx_ring->index);
		return (B_FALSE);
	}

	/* Default ring initialization */
	attr.post_qid		= rx_ring->index;
	attr.compl_qid		= 0;
	attr.callback		= xgell_rx_1b_callback;
	attr.per_dtr_space	= sizeof (xgell_rxd_priv_t);
	attr.flags		= 0;
	attr.type		= XGE_HAL_CHANNEL_TYPE_RING;
	attr.dtr_init		= xgell_rx_dtr_replenish;
	attr.dtr_term		= xgell_rx_dtr_term;
	attr.userdata		= rx_ring;

	status = xge_hal_channel_open(lldev->devh, &attr, &rx_ring->channelh,
	    XGE_HAL_CHANNEL_OC_NORMAL);
	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "%s%d: cannot open Rx channel got status "
		    " code %d", XGELL_IFNAME, lldev->instance, status);
		(void) xgell_rx_destroy_buffer_pool(rx_ring);
		return (B_FALSE);
	}

	xgell_rx_ring_maddr_init(rx_ring);

	mutex_init(&rx_ring->ring_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hldev->irqh));

	rx_ring->poll_bytes = -1;
	rx_ring->polled_bytes = 0;
	rx_ring->poll_mp = NULL;
	rx_ring->live = B_TRUE;

	xge_debug_ll(XGE_TRACE, "RX ring [%d] is opened successfully",
	    rx_ring->index);

	return (B_TRUE);
}

static void
xgell_rx_ring_close(xgell_rx_ring_t *rx_ring)
{
	if (!rx_ring->live)
		return;
	xge_hal_channel_close(rx_ring->channelh, XGE_HAL_CHANNEL_OC_NORMAL);
	rx_ring->channelh = NULL;
	/* This may not clean up all used buffers, driver will handle it */
	if (xgell_rx_destroy_buffer_pool(rx_ring))
		rx_ring->live = B_FALSE;

	mutex_destroy(&rx_ring->ring_lock);
}

/*
 * xgell_rx_open
 * @lldev: the link layer object
 *
 * Initialize and open all RX channels.
 */
static boolean_t
xgell_rx_open(xgelldev_t *lldev)
{
	xgell_rx_ring_t *rx_ring;
	int i;

	if (lldev->live_rx_rings != 0)
		return (B_TRUE);

	lldev->live_rx_rings = 0;

	/*
	 * Initialize all rings
	 */
	for (i = 0; i < lldev->init_rx_rings; i++) {
		rx_ring = &lldev->rx_ring[i];
		rx_ring->index = i;
		rx_ring->lldev = lldev;
		rx_ring->live = B_FALSE;

		if (!xgell_rx_ring_open(rx_ring))
			return (B_FALSE);

		lldev->live_rx_rings++;
	}

	return (B_TRUE);
}

static void
xgell_rx_close(xgelldev_t *lldev)
{
	xgell_rx_ring_t *rx_ring;
	int i;

	if (lldev->live_rx_rings == 0)
		return;

	/*
	 * Close all rx rings
	 */
	for (i = 0; i < lldev->init_rx_rings; i++) {
		rx_ring = &lldev->rx_ring[i];

		if (rx_ring->live) {
			xgell_rx_ring_close(rx_ring);
			lldev->live_rx_rings--;
		}
	}

	xge_assert(lldev->live_rx_rings == 0);
}

/*
 * xgell_tx_term
 *
 * Function will be called by HAL to terminate all DTRs for
 * Fifo(s) type of channels.
 */
static void
xgell_tx_term(xge_hal_channel_h channelh, xge_hal_dtr_h dtrh,
    xge_hal_dtr_state_e state, void *userdata, xge_hal_channel_reopen_e reopen)
{
	xgell_txd_priv_t *txd_priv =
	    ((xgell_txd_priv_t *)xge_hal_fifo_dtr_private(dtrh));
	mblk_t *mp = txd_priv->mblk;
	int i;

	/*
	 * for Tx we must clean up the DTR *only* if it has been
	 * posted!
	 */
	if (state != XGE_HAL_DTR_STATE_POSTED) {
		return;
	}

	for (i = 0; i < txd_priv->handle_cnt; i++) {
		xge_assert(txd_priv->dma_handles[i]);
		(void) ddi_dma_unbind_handle(txd_priv->dma_handles[i]);
		ddi_dma_free_handle(&txd_priv->dma_handles[i]);
		txd_priv->dma_handles[i] = 0;
	}

	xge_hal_fifo_dtr_free(channelh, dtrh);

	if (mp) {
		txd_priv->mblk = NULL;
		freemsg(mp);
	}
}

static boolean_t
xgell_tx_ring_open(xgell_tx_ring_t *tx_ring)
{
	xge_hal_status_e status;
	xge_hal_channel_attr_t attr;
	xgelldev_t *lldev = tx_ring->lldev;

	if (tx_ring->live)
		return (B_TRUE);

	attr.post_qid		= tx_ring->index;
	attr.compl_qid		= 0;
	attr.callback		= xgell_xmit_compl;
	attr.per_dtr_space	= sizeof (xgell_txd_priv_t);
	attr.flags		= 0;
	attr.type		= XGE_HAL_CHANNEL_TYPE_FIFO;
	attr.dtr_init		= NULL;
	attr.dtr_term		= xgell_tx_term;
	attr.userdata		= tx_ring;

	status = xge_hal_channel_open(lldev->devh, &attr, &tx_ring->channelh,
	    XGE_HAL_CHANNEL_OC_NORMAL);
	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "%s%d: cannot open Tx channel got status "
		    "code %d", XGELL_IFNAME, lldev->instance, status);
		return (B_FALSE);
	}

	tx_ring->live = B_TRUE;

	return (B_TRUE);
}

static void
xgell_tx_ring_close(xgell_tx_ring_t *tx_ring)
{
	if (!tx_ring->live)
		return;
	xge_hal_channel_close(tx_ring->channelh, XGE_HAL_CHANNEL_OC_NORMAL);
	tx_ring->live = B_FALSE;
}

/*
 * xgell_tx_open
 * @lldev: the link layer object
 *
 * Initialize and open all TX channels.
 */
static boolean_t
xgell_tx_open(xgelldev_t *lldev)
{
	xgell_tx_ring_t *tx_ring;
	int i;

	if (lldev->live_tx_rings != 0)
		return (B_TRUE);

	lldev->live_tx_rings = 0;

	/*
	 * Enable rings by reserve sequence to match the h/w sequences.
	 */
	for (i = 0; i < lldev->init_tx_rings; i++) {
		tx_ring = &lldev->tx_ring[i];
		tx_ring->index = i;
		tx_ring->lldev = lldev;
		tx_ring->live = B_FALSE;

		if (!xgell_tx_ring_open(tx_ring))
			return (B_FALSE);

		lldev->live_tx_rings++;
	}

	return (B_TRUE);
}

static void
xgell_tx_close(xgelldev_t *lldev)
{
	xgell_tx_ring_t *tx_ring;
	int i;

	if (lldev->live_tx_rings == 0)
		return;

	/*
	 * Enable rings by reserve sequence to match the h/w sequences.
	 */
	for (i = 0; i < lldev->init_tx_rings; i++) {
		tx_ring = &lldev->tx_ring[i];
		if (tx_ring->live) {
			xgell_tx_ring_close(tx_ring);
			lldev->live_tx_rings--;
		}
	}
}

static int
xgell_initiate_start(xgelldev_t *lldev)
{
	xge_hal_status_e status;
	xge_hal_device_t *hldev = lldev->devh;
	int maxpkt = hldev->config.mtu;

	/* check initial mtu before enabling the device */
	status = xge_hal_device_mtu_check(lldev->devh, maxpkt);
	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "%s%d: MTU size %d is invalid",
		    XGELL_IFNAME, lldev->instance, maxpkt);
		return (EINVAL);
	}

	/* set initial mtu before enabling the device */
	status = xge_hal_device_mtu_set(lldev->devh, maxpkt);
	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "%s%d: can not set new MTU %d",
		    XGELL_IFNAME, lldev->instance, maxpkt);
		return (EIO);
	}

	/* tune jumbo/normal frame UFC counters */
	hldev->config.ring.queue[XGELL_RX_RING_MAIN].rti.ufc_b =
	    (maxpkt > XGE_HAL_DEFAULT_MTU) ?
	    XGE_HAL_DEFAULT_RX_UFC_B_J :
	    XGE_HAL_DEFAULT_RX_UFC_B_N;

	hldev->config.ring.queue[XGELL_RX_RING_MAIN].rti.ufc_c =
	    (maxpkt > XGE_HAL_DEFAULT_MTU) ?
	    XGE_HAL_DEFAULT_RX_UFC_C_J :
	    XGE_HAL_DEFAULT_RX_UFC_C_N;

	/* now, enable the device */
	status = xge_hal_device_enable(lldev->devh);
	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "%s%d: can not enable the device",
		    XGELL_IFNAME, lldev->instance);
		return (EIO);
	}

	if (!xgell_rx_open(lldev)) {
		status = xge_hal_device_disable(lldev->devh);
		if (status != XGE_HAL_OK) {
			u64 adapter_status;
			(void) xge_hal_device_status(lldev->devh,
			    &adapter_status);
			xge_debug_ll(XGE_ERR, "%s%d: can not safely disable "
			    "the device. adaper status 0x%"PRIx64
			    " returned status %d",
			    XGELL_IFNAME, lldev->instance,
			    (uint64_t)adapter_status, status);
		}
		xgell_rx_close(lldev);
		xge_os_mdelay(1500);
		return (ENOMEM);
	}

	if (!xgell_tx_open(lldev)) {
		status = xge_hal_device_disable(lldev->devh);
		if (status != XGE_HAL_OK) {
			u64 adapter_status;
			(void) xge_hal_device_status(lldev->devh,
			    &adapter_status);
			xge_debug_ll(XGE_ERR, "%s%d: can not safely disable "
			    "the device. adaper status 0x%"PRIx64
			    " returned status %d",
			    XGELL_IFNAME, lldev->instance,
			    (uint64_t)adapter_status, status);
		}
		xgell_tx_close(lldev);
		xgell_rx_close(lldev);
		xge_os_mdelay(1500);
		return (ENOMEM);
	}

	/* time to enable interrupts */
	(void) xge_enable_intrs(lldev);
	xge_hal_device_intr_enable(lldev->devh);

	lldev->is_initialized = 1;

	return (0);
}

static void
xgell_initiate_stop(xgelldev_t *lldev)
{
	xge_hal_status_e status;

	lldev->is_initialized = 0;

	status = xge_hal_device_disable(lldev->devh);
	if (status != XGE_HAL_OK) {
		u64 adapter_status;
		(void) xge_hal_device_status(lldev->devh, &adapter_status);
		xge_debug_ll(XGE_ERR, "%s%d: can not safely disable "
		    "the device. adaper status 0x%"PRIx64" returned status %d",
		    XGELL_IFNAME, lldev->instance,
		    (uint64_t)adapter_status, status);
	}
	xge_hal_device_intr_disable(lldev->devh);
	/* disable OS ISR's */
	xge_disable_intrs(lldev);

	xge_debug_ll(XGE_TRACE, "%s",
	    "waiting for device irq to become quiescent...");
	xge_os_mdelay(1500);

	xge_queue_flush(xge_hal_device_queue(lldev->devh));

	xgell_rx_close(lldev);
	xgell_tx_close(lldev);
}

/*
 * xgell_m_start
 * @arg: pointer to device private strucutre(hldev)
 *
 * This function is called by MAC Layer to enable the XFRAME
 * firmware to generate interrupts and also prepare the
 * driver to call mac_rx for delivering receive packets
 * to MAC Layer.
 */
static int
xgell_m_start(void *arg)
{
	xgelldev_t *lldev = arg;
	xge_hal_device_t *hldev = lldev->devh;
	int ret;

	xge_debug_ll(XGE_TRACE, "%s%d: M_START", XGELL_IFNAME,
	    lldev->instance);

	mutex_enter(&lldev->genlock);

	if (lldev->is_initialized) {
		xge_debug_ll(XGE_ERR, "%s%d: device is already initialized",
		    XGELL_IFNAME, lldev->instance);
		mutex_exit(&lldev->genlock);
		return (EINVAL);
	}

	hldev->terminating = 0;
	if (ret = xgell_initiate_start(lldev)) {
		mutex_exit(&lldev->genlock);
		return (ret);
	}

	lldev->timeout_id = timeout(xge_device_poll, hldev, XGE_DEV_POLL_TICKS);

	mutex_exit(&lldev->genlock);

	return (0);
}

/*
 * xgell_m_stop
 * @arg: pointer to device private data (hldev)
 *
 * This function is called by the MAC Layer to disable
 * the XFRAME firmware for generating any interrupts and
 * also stop the driver from calling mac_rx() for
 * delivering data packets to the MAC Layer.
 */
static void
xgell_m_stop(void *arg)
{
	xgelldev_t *lldev = arg;
	xge_hal_device_t *hldev = lldev->devh;

	xge_debug_ll(XGE_TRACE, "%s", "MAC_STOP");

	mutex_enter(&lldev->genlock);
	if (!lldev->is_initialized) {
		xge_debug_ll(XGE_ERR, "%s", "device is not initialized...");
		mutex_exit(&lldev->genlock);
		return;
	}

	xge_hal_device_terminating(hldev);
	xgell_initiate_stop(lldev);

	/* reset device */
	(void) xge_hal_device_reset(lldev->devh);

	mutex_exit(&lldev->genlock);

	if (lldev->timeout_id != 0) {
		(void) untimeout(lldev->timeout_id);
	}

	xge_debug_ll(XGE_TRACE, "%s", "returning back to MAC Layer...");
}

/*
 * xgell_onerr_reset
 * @lldev: pointer to xgelldev_t structure
 *
 * This function is called by HAL Event framework to reset the HW
 * This function is must be called with genlock taken.
 */
int
xgell_onerr_reset(xgelldev_t *lldev)
{
	int rc = 0;

	if (!lldev->is_initialized) {
		xge_debug_ll(XGE_ERR, "%s%d: can not reset",
		    XGELL_IFNAME, lldev->instance);
		return (rc);
	}

	lldev->in_reset = 1;
	xgell_initiate_stop(lldev);

	/* reset device */
	(void) xge_hal_device_reset(lldev->devh);

	rc = xgell_initiate_start(lldev);
	lldev->in_reset = 0;

	return (rc);
}

/*
 * xgell_m_multicst
 * @arg: pointer to device private strucutre(hldev)
 * @add:
 * @mc_addr:
 *
 * This function is called by MAC Layer to enable or
 * disable device-level reception of specific multicast addresses.
 */
static int
xgell_m_multicst(void *arg, boolean_t add, const uint8_t *mc_addr)
{
	xge_hal_status_e status;
	xgelldev_t *lldev = (xgelldev_t *)arg;
	xge_hal_device_t *hldev = lldev->devh;

	xge_debug_ll(XGE_TRACE, "M_MULTICAST add %d", add);

	mutex_enter(&lldev->genlock);

	if (!lldev->is_initialized) {
		xge_debug_ll(XGE_ERR, "%s%d: can not set multicast",
		    XGELL_IFNAME, lldev->instance);
		mutex_exit(&lldev->genlock);
		return (EIO);
	}

	/* FIXME: missing HAL functionality: enable_one() */

	status = (add) ?
	    xge_hal_device_mcast_enable(hldev) :
	    xge_hal_device_mcast_disable(hldev);

	if (status != XGE_HAL_OK) {
		xge_debug_ll(XGE_ERR, "failed to %s multicast, status %d",
		    add ? "enable" : "disable", status);
		mutex_exit(&lldev->genlock);
		return (EIO);
	}

	mutex_exit(&lldev->genlock);

	return (0);
}


/*
 * xgell_m_promisc
 * @arg: pointer to device private strucutre(hldev)
 * @on:
 *
 * This function is called by MAC Layer to enable or
 * disable the reception of all the packets on the medium
 */
static int
xgell_m_promisc(void *arg, boolean_t on)
{
	xgelldev_t *lldev = (xgelldev_t *)arg;
	xge_hal_device_t *hldev = lldev->devh;

	mutex_enter(&lldev->genlock);

	xge_debug_ll(XGE_TRACE, "%s", "MAC_PROMISC_SET");

	if (!lldev->is_initialized) {
		xge_debug_ll(XGE_ERR, "%s%d: can not set promiscuous",
		    XGELL_IFNAME, lldev->instance);
		mutex_exit(&lldev->genlock);
		return (EIO);
	}

	if (on) {
		xge_hal_device_promisc_enable(hldev);
	} else {
		xge_hal_device_promisc_disable(hldev);
	}

	mutex_exit(&lldev->genlock);

	return (0);
}

/*
 * xgell_m_stat
 * @arg: pointer to device private strucutre(hldev)
 *
 * This function is called by MAC Layer to get network statistics
 * from the driver.
 */
static int
xgell_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	xge_hal_stats_hw_info_t *hw_info;
	xgelldev_t *lldev = (xgelldev_t *)arg;
	xge_hal_device_t *hldev = lldev->devh;

	xge_debug_ll(XGE_TRACE, "%s", "MAC_STATS_GET");

	mutex_enter(&lldev->genlock);

	if (!lldev->is_initialized) {
		mutex_exit(&lldev->genlock);
		return (EAGAIN);
	}

	if (xge_hal_stats_hw(hldev, &hw_info) != XGE_HAL_OK) {
		mutex_exit(&lldev->genlock);
		return (EAGAIN);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = 10000000000ull; /* 10G */
		break;

	case MAC_STAT_MULTIRCV:
		*val = ((u64) hw_info->rmac_vld_mcst_frms_oflow << 32) |
		    hw_info->rmac_vld_mcst_frms;
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = ((u64) hw_info->rmac_vld_bcst_frms_oflow << 32) |
		    hw_info->rmac_vld_bcst_frms;
		break;

	case MAC_STAT_MULTIXMT:
		*val = ((u64) hw_info->tmac_mcst_frms_oflow << 32) |
		    hw_info->tmac_mcst_frms;
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = ((u64) hw_info->tmac_bcst_frms_oflow << 32) |
		    hw_info->tmac_bcst_frms;
		break;

	case MAC_STAT_RBYTES:
		*val = ((u64) hw_info->rmac_ttl_octets_oflow << 32) |
		    hw_info->rmac_ttl_octets;
		break;

	case MAC_STAT_NORCVBUF:
		*val = hw_info->rmac_drop_frms;
		break;

	case MAC_STAT_IERRORS:
		*val = ((u64) hw_info->rmac_discarded_frms_oflow << 32) |
		    hw_info->rmac_discarded_frms;
		break;

	case MAC_STAT_OBYTES:
		*val = ((u64) hw_info->tmac_ttl_octets_oflow << 32) |
		    hw_info->tmac_ttl_octets;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = hw_info->tmac_drop_frms;
		break;

	case MAC_STAT_OERRORS:
		*val = ((u64) hw_info->tmac_any_err_frms_oflow << 32) |
		    hw_info->tmac_any_err_frms;
		break;

	case MAC_STAT_IPACKETS:
		*val = ((u64) hw_info->rmac_vld_frms_oflow << 32) |
		    hw_info->rmac_vld_frms;
		break;

	case MAC_STAT_OPACKETS:
		*val = ((u64) hw_info->tmac_frms_oflow << 32) |
		    hw_info->tmac_frms;
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = hw_info->rmac_fcs_err_frms;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = hw_info->rmac_long_frms;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;

	default:
		mutex_exit(&lldev->genlock);
		return (ENOTSUP);
	}

	mutex_exit(&lldev->genlock);

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
xgell_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	xgell_rx_ring_t	*rx_ring = (xgell_rx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rx_ring->rx_bytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = rx_ring->rx_pkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
xgell_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	xgell_tx_ring_t	*tx_ring = (xgell_tx_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = tx_ring->tx_bytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = tx_ring->tx_pkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * xgell_device_alloc - Allocate new LL device
 */
int
xgell_device_alloc(xge_hal_device_h devh,
    dev_info_t *dev_info, xgelldev_t **lldev_out)
{
	xgelldev_t *lldev;
	xge_hal_device_t *hldev = (xge_hal_device_t *)devh;
	int instance = ddi_get_instance(dev_info);

	*lldev_out = NULL;

	xge_debug_ll(XGE_TRACE, "trying to register etherenet device %s%d...",
	    XGELL_IFNAME, instance);

	lldev = kmem_zalloc(sizeof (xgelldev_t), KM_SLEEP);

	lldev->devh = hldev;
	lldev->instance = instance;
	lldev->dev_info = dev_info;

	*lldev_out = lldev;

	ddi_set_driver_private(dev_info, (caddr_t)hldev);

	return (DDI_SUCCESS);
}

/*
 * xgell_device_free
 */
void
xgell_device_free(xgelldev_t *lldev)
{
	xge_debug_ll(XGE_TRACE, "freeing device %s%d",
	    XGELL_IFNAME, lldev->instance);

	kmem_free(lldev, sizeof (xgelldev_t));
}

/*
 * xgell_ioctl
 */
static void
xgell_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	xgelldev_t *lldev = arg;
	struct iocblk *iocp;
	int err = 0;
	int cmd;
	int need_privilege = 1;
	int ret = 0;


	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;
	xge_debug_ll(XGE_TRACE, "MAC_IOCTL cmd 0x%x", cmd);
	switch (cmd) {
	case ND_GET:
		need_privilege = 0;
		/* FALLTHRU */
	case ND_SET:
		break;
	default:
		xge_debug_ll(XGE_TRACE, "unknown cmd 0x%x", cmd);
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	if (need_privilege) {
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			xge_debug_ll(XGE_ERR,
			    "drv_priv(): rejected cmd 0x%x, err %d",
			    cmd, err);
			miocnak(wq, mp, 0, err);
			return;
		}
	}

	switch (cmd) {
	case ND_GET:
		/*
		 * If nd_getset() returns B_FALSE, the command was
		 * not valid (e.g. unknown name), so we just tell the
		 * top-level ioctl code to send a NAK (with code EINVAL).
		 *
		 * Otherwise, nd_getset() will have built the reply to
		 * be sent (but not actually sent it), so we tell the
		 * caller to send the prepared reply.
		 */
		ret = nd_getset(wq, lldev->ndp, mp);
		xge_debug_ll(XGE_TRACE, "%s", "got ndd get ioctl");
		break;

	case ND_SET:
		ret = nd_getset(wq, lldev->ndp, mp);
		xge_debug_ll(XGE_TRACE, "%s", "got ndd set ioctl");
		break;

	default:
		break;
	}

	if (ret == B_FALSE) {
		xge_debug_ll(XGE_ERR,
		    "nd_getset(): rejected cmd 0x%x, err %d",
		    cmd, err);
		miocnak(wq, mp, 0, EINVAL);
	} else {
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK;
		qreply(wq, mp);
	}
}


static boolean_t
xgell_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	xgelldev_t *lldev = arg;

	xge_debug_ll(XGE_TRACE, "xgell_m_getcapab: %x", cap);

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksum_txflags = cap_data;
		*hcksum_txflags = HCKSUM_INET_FULL_V4 | HCKSUM_INET_FULL_V6 |
		    HCKSUM_IPHDRCKSUM;
		break;
	}
	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (lldev->config.lso_enable) {
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			cap_lso->lso_basic_tcp_ipv4.lso_max = XGELL_LSO_MAXLEN;
			break;
		} else {
			return (B_FALSE);
		}
	}
	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = cap_data;

		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = lldev->init_rx_rings;
			cap_rings->mr_gnum = lldev->init_rx_groups;
			cap_rings->mr_rget = xgell_fill_ring;
			cap_rings->mr_gget = xgell_fill_group;
			break;
		case MAC_RING_TYPE_TX:
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
			cap_rings->mr_rnum = lldev->init_tx_rings;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = xgell_fill_ring;
			cap_rings->mr_gget = NULL;
			break;
		default:
			break;
		}
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

static int
xgell_stats_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	xgelldev_t *lldev = (xgelldev_t *)cp;
	xge_hal_status_e status;
	int count = 0, retsize;
	char *buf;

	buf = kmem_alloc(XGELL_STATS_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}

	status = xge_hal_aux_stats_tmac_read(lldev->devh, XGELL_STATS_BUFSIZE,
	    buf, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_STATS_BUFSIZE);
		xge_debug_ll(XGE_ERR, "tmac_read(): status %d", status);
		return (EINVAL);
	}
	count += retsize;

	status = xge_hal_aux_stats_rmac_read(lldev->devh,
	    XGELL_STATS_BUFSIZE - count,
	    buf+count, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_STATS_BUFSIZE);
		xge_debug_ll(XGE_ERR, "rmac_read(): status %d", status);
		return (EINVAL);
	}
	count += retsize;

	status = xge_hal_aux_stats_pci_read(lldev->devh,
	    XGELL_STATS_BUFSIZE - count, buf + count, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_STATS_BUFSIZE);
		xge_debug_ll(XGE_ERR, "pci_read(): status %d", status);
		return (EINVAL);
	}
	count += retsize;

	status = xge_hal_aux_stats_sw_dev_read(lldev->devh,
	    XGELL_STATS_BUFSIZE - count, buf + count, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_STATS_BUFSIZE);
		xge_debug_ll(XGE_ERR, "sw_dev_read(): status %d", status);
		return (EINVAL);
	}
	count += retsize;

	status = xge_hal_aux_stats_hal_read(lldev->devh,
	    XGELL_STATS_BUFSIZE - count, buf + count, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_STATS_BUFSIZE);
		xge_debug_ll(XGE_ERR, "pci_read(): status %d", status);
		return (EINVAL);
	}
	count += retsize;

	*(buf + count - 1) = '\0'; /* remove last '\n' */
	(void) mi_mpprintf(mp, "%s", buf);
	kmem_free(buf, XGELL_STATS_BUFSIZE);

	return (0);
}

static int
xgell_pciconf_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	xgelldev_t *lldev = (xgelldev_t *)cp;
	xge_hal_status_e status;
	int retsize;
	char *buf;

	buf = kmem_alloc(XGELL_PCICONF_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}
	status = xge_hal_aux_pci_config_read(lldev->devh, XGELL_PCICONF_BUFSIZE,
	    buf, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_PCICONF_BUFSIZE);
		xge_debug_ll(XGE_ERR, "pci_config_read(): status %d", status);
		return (EINVAL);
	}
	*(buf + retsize - 1) = '\0'; /* remove last '\n' */
	(void) mi_mpprintf(mp, "%s", buf);
	kmem_free(buf, XGELL_PCICONF_BUFSIZE);

	return (0);
}

static int
xgell_about_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	xgelldev_t *lldev = (xgelldev_t *)cp;
	xge_hal_status_e status;
	int retsize;
	char *buf;

	buf = kmem_alloc(XGELL_ABOUT_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}
	status = xge_hal_aux_about_read(lldev->devh, XGELL_ABOUT_BUFSIZE,
	    buf, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_ABOUT_BUFSIZE);
		xge_debug_ll(XGE_ERR, "about_read(): status %d", status);
		return (EINVAL);
	}
	*(buf + retsize - 1) = '\0'; /* remove last '\n' */
	(void) mi_mpprintf(mp, "%s", buf);
	kmem_free(buf, XGELL_ABOUT_BUFSIZE);

	return (0);
}

static unsigned long bar0_offset = 0x110; /* adapter_control */

static int
xgell_bar0_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	xgelldev_t *lldev = (xgelldev_t *)cp;
	xge_hal_status_e status;
	int retsize;
	char *buf;

	buf = kmem_alloc(XGELL_IOCTL_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}
	status = xge_hal_aux_bar0_read(lldev->devh, bar0_offset,
	    XGELL_IOCTL_BUFSIZE, buf, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_IOCTL_BUFSIZE);
		xge_debug_ll(XGE_ERR, "bar0_read(): status %d", status);
		return (EINVAL);
	}
	*(buf + retsize - 1) = '\0'; /* remove last '\n' */
	(void) mi_mpprintf(mp, "%s", buf);
	kmem_free(buf, XGELL_IOCTL_BUFSIZE);

	return (0);
}

static int
xgell_bar0_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
{
	unsigned long old_offset = bar0_offset;
	char *end;

	if (value && *value == '0' &&
	    (*(value + 1) == 'x' || *(value + 1) == 'X')) {
		value += 2;
	}

	bar0_offset = mi_strtol(value, &end, 16);
	if (end == value) {
		bar0_offset = old_offset;
		return (EINVAL);
	}

	xge_debug_ll(XGE_TRACE, "bar0: new value %s:%lX", value, bar0_offset);

	return (0);
}

static int
xgell_debug_level_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	char *buf;

	buf = kmem_alloc(XGELL_IOCTL_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}
	(void) mi_mpprintf(mp, "debug_level %d", xge_hal_driver_debug_level());
	kmem_free(buf, XGELL_IOCTL_BUFSIZE);

	return (0);
}

static int
xgell_debug_level_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *credp)
{
	int level;
	char *end;

	level = mi_strtol(value, &end, 10);
	if (level < XGE_NONE || level > XGE_ERR || end == value) {
		return (EINVAL);
	}

	xge_hal_driver_debug_level_set(level);

	return (0);
}

static int
xgell_debug_module_mask_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	char *buf;

	buf = kmem_alloc(XGELL_IOCTL_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}
	(void) mi_mpprintf(mp, "debug_module_mask 0x%08x",
	    xge_hal_driver_debug_module_mask());
	kmem_free(buf, XGELL_IOCTL_BUFSIZE);

	return (0);
}

static int
xgell_debug_module_mask_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
			    cred_t *credp)
{
	u32 mask;
	char *end;

	if (value && *value == '0' &&
	    (*(value + 1) == 'x' || *(value + 1) == 'X')) {
		value += 2;
	}

	mask = mi_strtol(value, &end, 16);
	if (end == value) {
		return (EINVAL);
	}

	xge_hal_driver_debug_module_mask_set(mask);

	return (0);
}

static int
xgell_devconfig_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	xgelldev_t *lldev = (xgelldev_t *)(void *)cp;
	xge_hal_status_e status;
	int retsize;
	char *buf;

	buf = kmem_alloc(XGELL_DEVCONF_BUFSIZE, KM_SLEEP);
	if (buf == NULL) {
		return (ENOSPC);
	}
	status = xge_hal_aux_device_config_read(lldev->devh,
	    XGELL_DEVCONF_BUFSIZE, buf, &retsize);
	if (status != XGE_HAL_OK) {
		kmem_free(buf, XGELL_DEVCONF_BUFSIZE);
		xge_debug_ll(XGE_ERR, "device_config_read(): status %d",
		    status);
		return (EINVAL);
	}
	*(buf + retsize - 1) = '\0'; /* remove last '\n' */
	(void) mi_mpprintf(mp, "%s", buf);
	kmem_free(buf, XGELL_DEVCONF_BUFSIZE);

	return (0);
}

/*
 * xgell_device_register
 * @devh: pointer on HAL device
 * @config: pointer on this network device configuration
 * @ll_out: output pointer. Will be assigned to valid LL device.
 *
 * This function will allocate and register network device
 */
int
xgell_device_register(xgelldev_t *lldev, xgell_config_t *config)
{
	mac_register_t *macp = NULL;
	xge_hal_device_t *hldev = (xge_hal_device_t *)lldev->devh;

	/*
	 * Initialize some NDD interface for internal debug.
	 */
	if (nd_load(&lldev->ndp, "pciconf", xgell_pciconf_get, NULL,
	    (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	if (nd_load(&lldev->ndp, "about", xgell_about_get, NULL,
	    (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	if (nd_load(&lldev->ndp, "stats", xgell_stats_get, NULL,
	    (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	if (nd_load(&lldev->ndp, "bar0", xgell_bar0_get, xgell_bar0_set,
	    (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	if (nd_load(&lldev->ndp, "debug_level", xgell_debug_level_get,
	    xgell_debug_level_set, (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	if (nd_load(&lldev->ndp, "debug_module_mask",
	    xgell_debug_module_mask_get, xgell_debug_module_mask_set,
	    (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	if (nd_load(&lldev->ndp, "devconfig", xgell_devconfig_get, NULL,
	    (caddr_t)lldev) == B_FALSE)
		goto xgell_ndd_fail;

	bcopy(config, &lldev->config, sizeof (xgell_config_t));

	mutex_init(&lldev->genlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hldev->irqh));

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto xgell_register_fail;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = lldev;
	macp->m_dip = lldev->dev_info;
	macp->m_src_addr = hldev->macaddr[0];
	macp->m_callbacks = &xgell_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = hldev->config.mtu;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_v12n = MAC_VIRT_LEVEL1;

	/*
	 * MAC Registration.
	 */
	if (mac_register(macp, &lldev->mh) != 0)
		goto xgell_register_fail;

	/* Always free the macp after register */
	if (macp != NULL)
		mac_free(macp);

	/* Calculate tx_copied_max here ??? */
	lldev->tx_copied_max = hldev->config.fifo.max_frags *
	    hldev->config.fifo.alignment_size *
	    hldev->config.fifo.max_aligned_frags;

	xge_debug_ll(XGE_TRACE, "etherenet device %s%d registered",
	    XGELL_IFNAME, lldev->instance);

	return (DDI_SUCCESS);

xgell_ndd_fail:
	nd_free(&lldev->ndp);
	xge_debug_ll(XGE_ERR, "%s", "unable to load ndd parameter");
	return (DDI_FAILURE);

xgell_register_fail:
	if (macp != NULL)
		mac_free(macp);
	nd_free(&lldev->ndp);
	mutex_destroy(&lldev->genlock);
	xge_debug_ll(XGE_ERR, "%s", "unable to register networking device");
	return (DDI_FAILURE);
}

/*
 * xgell_device_unregister
 * @devh: pointer on HAL device
 * @lldev: pointer to valid LL device.
 *
 * This function will unregister and free network device
 */
int
xgell_device_unregister(xgelldev_t *lldev)
{
	if (mac_unregister(lldev->mh) != 0) {
		xge_debug_ll(XGE_ERR, "unable to unregister device %s%d",
		    XGELL_IFNAME, lldev->instance);
		return (DDI_FAILURE);
	}

	mutex_destroy(&lldev->genlock);

	nd_free(&lldev->ndp);

	xge_debug_ll(XGE_TRACE, "etherenet device %s%d unregistered",
	    XGELL_IFNAME, lldev->instance);

	return (DDI_SUCCESS);
}
