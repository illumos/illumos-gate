/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Inc.  All rights reserved.
 * Copyright (c) 2014, 2016 by Delphix. All rights reserved.
 * Copyright 2021 Joyent, Inc.
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2025 Hans Rosenfeld
 * Copyright 2026 Oxide Computer Company
 */

/* Based on the NetBSD virtio driver by Minoura Makoto. */
/*
 * Copyright (c) 2010 Minoura Makoto.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * VIRTIO NETWORK DRIVER: TRANSMIT PATH
 *
 * Transmit buffer management, frame transmission and descriptor reclamation,
 * including the transmit ring entrypoints that we provide to MAC.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/sysmacros.h>
#include <sys/byteorder.h>
#include <sys/list.h>
#include <sys/pattr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <inet/tcp.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>

#include "virtio.h"
#include "vioif.h"

/*
 * Interval for the periodic TX reclaim.
 */
uint_t vioif_reclaim_ms = 200;

/*
 * DMA attributes for mapping larger transmit buffers from the networking
 * stack.  The requirements are quite loose, but note that the SGL entry length
 * field is 32-bit.
 */
static ddi_dma_attr_t vioif_dma_attr_external = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0x00000000FFFFFFFF,
	.dma_attr_align =		1,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0x00000000FFFFFFFF,
	.dma_attr_seg =			0x00000000FFFFFFFF,
	.dma_attr_sgllen =		VIOIF_MAX_SEGS - 1,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0
};

/*
 * Result of an attempt to map a message for transmission by reference.
 */
typedef enum vioif_txext_result {
	VIOIF_TXEXT_OK,		/* mapped and appended to the chain */
	VIOIF_TXEXT_FAIL,	/* failed; the message has been freed */
	VIOIF_TXEXT_TOOBIG	/* too many segments; message retained */
} vioif_txext_result_t;

static void vioif_reclaim_restart(vioif_txq_t *);

static vioif_txbuf_t *
vioif_txbuf_alloc(vioif_txq_t *txq)
{
	vioif_txbuf_t *tb;

	VERIFY(MUTEX_HELD(&txq->vtq_mutex));

	if ((tb = list_remove_head(&txq->vtq_bufs)) != NULL) {
		txq->vtq_nbufs_alloc++;
	}

	return (tb);
}

static void
vioif_txbuf_free(vioif_txq_t *txq, vioif_txbuf_t *tb)
{
	VERIFY(MUTEX_HELD(&txq->vtq_mutex));

	VERIFY3U(txq->vtq_nbufs_alloc, >, 0);
	txq->vtq_nbufs_alloc--;

	virtio_chain_clear(tb->tb_chain);
	list_insert_head(&txq->vtq_bufs, tb);
}

int
vioif_alloc_txq_bufs(vioif_txq_t *txq)
{
	vioif_t *vif = txq->vtq_vif;

	/*
	 * Allocate one contiguous chunk of memory for the transmit buffer
	 * tracking objects. If the ring is unusually small, we'll reduce
	 * our target buffer count accordingly.
	 */
	txq->vtq_bufs_capacity = MIN(VIRTIO_NET_TX_BUFS,
	    virtio_queue_size(txq->vtq_vq));
	txq->vtq_bufs_mem = kmem_zalloc(
	    sizeof (vioif_txbuf_t) * txq->vtq_bufs_capacity, KM_SLEEP);
	list_create(&txq->vtq_bufs, sizeof (vioif_txbuf_t),
	    offsetof(vioif_txbuf_t, tb_link));

	/*
	 * Put everything in the free list straight away in order to simplify
	 * the use of vioif_free_txq_bufs() for cleanup on allocation failure.
	 */
	for (uint_t i = 0; i < txq->vtq_bufs_capacity; i++) {
		list_insert_tail(&txq->vtq_bufs, &txq->vtq_bufs_mem[i]);
	}

	/*
	 * The transmit inline buffer is small (less than a page), so it's
	 * reasonable to request a single cookie.
	 */
	ddi_dma_attr_t attr = vioif_dma_attr_bufs;
	attr.dma_attr_sgllen = 1;

	for (vioif_txbuf_t *tb = list_head(&txq->vtq_bufs); tb != NULL;
	    tb = list_next(&txq->vtq_bufs, tb)) {
		if ((tb->tb_dma = virtio_dma_alloc(vif->vif_virtio,
		    VIOIF_TX_INLINE_SIZE, &attr,
		    DDI_DMA_STREAMING | DDI_DMA_WRITE, KM_SLEEP)) == NULL) {
			return (ENOMEM);
		}
		VERIFY3U(virtio_dma_ncookies(tb->tb_dma), ==, 1);

		if ((tb->tb_chain = virtio_chain_alloc(txq->vtq_vq,
		    KM_SLEEP)) == NULL) {
			return (ENOMEM);
		}
		virtio_chain_data_set(tb->tb_chain, tb);

		tb->tb_dmaext_capacity = VIOIF_MAX_SEGS - 1;
		tb->tb_dmaext = kmem_zalloc(
		    sizeof (virtio_dma_t *) * tb->tb_dmaext_capacity,
		    KM_SLEEP);
	}

	return (0);
}

void
vioif_free_txq_bufs(vioif_txq_t *txq)
{
	if (txq->vtq_bufs_mem == NULL)
		return;

	VERIFY3U(txq->vtq_nbufs_alloc, ==, 0);
	for (uint_t i = 0; i < txq->vtq_bufs_capacity; i++) {
		vioif_txbuf_t *tb = &txq->vtq_bufs_mem[i];

		/*
		 * Ensure that this txbuf is now in the free list:
		 */
		VERIFY(list_link_active(&tb->tb_link));
		list_remove(&txq->vtq_bufs, tb);

		/*
		 * We should not have an mblk chain at this point.
		 */
		VERIFY3P(tb->tb_mp, ==, NULL);

		if (tb->tb_dma != NULL) {
			virtio_dma_free(tb->tb_dma);
			tb->tb_dma = NULL;
		}

		if (tb->tb_chain != NULL) {
			virtio_chain_free(tb->tb_chain);
			tb->tb_chain = NULL;
		}

		if (tb->tb_dmaext != NULL) {
			for (uint_t j = 0; j < tb->tb_dmaext_capacity; j++) {
				if (tb->tb_dmaext[j] != NULL) {
					virtio_dma_free(tb->tb_dmaext[j]);
					tb->tb_dmaext[j] = NULL;
				}
			}

			kmem_free(tb->tb_dmaext,
			    sizeof (virtio_dma_t *) * tb->tb_dmaext_capacity);
			tb->tb_dmaext = NULL;
			tb->tb_dmaext_capacity = 0;
		}
	}
	VERIFY(list_is_empty(&txq->vtq_bufs));
	list_destroy(&txq->vtq_bufs);

	kmem_free(txq->vtq_bufs_mem,
	    sizeof (vioif_txbuf_t) * txq->vtq_bufs_capacity);
	txq->vtq_bufs_mem = NULL;
	txq->vtq_bufs_capacity = 0;
}

static uint_t
vioif_reclaim_used_tx(vioif_txq_t *txq)
{
	virtio_chain_t *vic;
	uint_t num_reclaimed = 0;

	VERIFY(MUTEX_NOT_HELD(&txq->vtq_mutex));

	while ((vic = virtio_queue_poll(txq->vtq_vq)) != NULL) {
		vioif_txbuf_t *tb = virtio_chain_data(vic);

		if (tb->tb_mp != NULL) {
			/*
			 * Unbind the external mapping.
			 */
			for (uint_t i = 0; i < tb->tb_dmaext_capacity; i++) {
				if (tb->tb_dmaext[i] == NULL) {
					continue;
				}

				virtio_dma_unbind(tb->tb_dmaext[i]);
			}

			freemsg(tb->tb_mp);
			tb->tb_mp = NULL;
		}

		/*
		 * Return this transmit buffer to the free list for reuse.
		 */
		mutex_enter(&txq->vtq_mutex);
		vioif_txbuf_free(txq, tb);
		mutex_exit(&txq->vtq_mutex);

		num_reclaimed++;
	}

	/* Return ring to transmitting state if descriptors were reclaimed. */
	if (num_reclaimed > 0) {
		boolean_t do_update = B_FALSE;

		mutex_enter(&txq->vtq_mutex);
		txq->vtq_stat_tx_reclaim += num_reclaimed;
		if (txq->vtq_corked) {
			/*
			 * TX was corked on a lack of available descriptors.
			 * That dire state has passed so the TX interrupt can
			 * be disabled and MAC can be notified that
			 * transmission is possible again.
			 */
			txq->vtq_corked = false;
			virtio_queue_no_interrupt(txq->vtq_vq, B_TRUE);
			do_update = B_TRUE;
		}

		mutex_exit(&txq->vtq_mutex);
		if (do_update) {
			mac_tx_ring_update(txq->vtq_vif->vif_mac_handle,
			    txq->vtq_ringh);
		}
	}

	return (num_reclaimed);
}

static void
vioif_reclaim_periodic(void *arg)
{
	vioif_txq_t *txq = arg;
	uint_t num_reclaimed;

	num_reclaimed = vioif_reclaim_used_tx(txq);

	mutex_enter(&txq->vtq_mutex);
	txq->vtq_reclaim_tid = 0;
	/*
	 * If used descriptors were reclaimed or TX descriptors appear to be
	 * outstanding, the ring is considered active and periodic reclamation
	 * is necessary for now.
	 */
	if (num_reclaimed != 0 || virtio_queue_nactive(txq->vtq_vq) != 0) {
		/* Do not reschedule if the ring is being drained. */
		if (!txq->vtq_drain) {
			vioif_reclaim_restart(txq);
		}
	}
	mutex_exit(&txq->vtq_mutex);
}

static void
vioif_reclaim_restart(vioif_txq_t *txq)
{
	VERIFY(MUTEX_HELD(&txq->vtq_mutex));
	VERIFY(!txq->vtq_drain);

	if (txq->vtq_reclaim_tid == 0) {
		txq->vtq_reclaim_tid = timeout(vioif_reclaim_periodic, txq,
		    MSEC_TO_TICK_ROUNDUP(vioif_reclaim_ms));
	}
}

void
vioif_tx_drain(vioif_txq_t *txq)
{
	VERIFY(MUTEX_HELD(&txq->vtq_mutex));

	txq->vtq_drain = true;
	/* Put a stop to the periodic reclaim if it is running */
	if (txq->vtq_reclaim_tid != 0) {
		timeout_id_t tid = txq->vtq_reclaim_tid;

		/*
		 * With vtq_drain set, there is no risk that a racing
		 * vioif_reclaim_periodic() call will reschedule itself.
		 *
		 * Being part of the mc_stop hook also guarantees that
		 * vioif_ring_tx() will not be called to restart it.
		 */
		txq->vtq_reclaim_tid = 0;
		mutex_exit(&txq->vtq_mutex);
		(void) untimeout(tid);
		mutex_enter(&txq->vtq_mutex);
	}
	virtio_queue_no_interrupt(txq->vtq_vq, B_TRUE);

	/*
	 * Wait for all of the TX descriptors to be processed by the host so
	 * they can be reclaimed.
	 */
	while (txq->vtq_nbufs_alloc > 0) {
		mutex_exit(&txq->vtq_mutex);
		(void) vioif_reclaim_used_tx(txq);
		delay(5);
		mutex_enter(&txq->vtq_mutex);
	}
	VERIFY(!txq->vtq_corked);
	VERIFY3U(txq->vtq_reclaim_tid, ==, 0);
	VERIFY3U(virtio_queue_nactive(txq->vtq_vq), ==, 0);
}

/*
 * Add the descriptor entry for the virtio net header, which is held at the
 * start of the transmit buffer's inline DMA memory. For legacy devices, and
 * those that have not negotiated VIRTIO_F_ANY_LAYOUT, the header must appear
 * in a separate descriptor entry to the rest of the buffer. We do that for
 * modern devices too.
 */
static int
vioif_tx_header_append(vioif_t *vif, vioif_txbuf_t *tb)
{
	return (virtio_chain_append(tb->tb_chain,
	    virtio_dma_cookie_pa(tb->tb_dma, 0), vif->vif_rxbuf_hdrlen,
	    VIRTIO_DIR_DEVICE_READS));
}

static int
vioif_tx_inline(vioif_txq_t *txq, vioif_txbuf_t *tb, mblk_t *mp,
    size_t msg_size)
{
	VERIFY(MUTEX_NOT_HELD(&txq->vtq_mutex));

	VERIFY3U(msg_size, <=, virtio_dma_size(tb->tb_dma) - VIOIF_HEADER_SKIP);

	/*
	 * Copy the message into the inline buffer and then free the message.
	 */
	mcopymsg(mp, virtio_dma_va(tb->tb_dma, VIOIF_HEADER_SKIP));

	if (virtio_chain_append(tb->tb_chain,
	    virtio_dma_cookie_pa(tb->tb_dma, 0) + VIOIF_HEADER_SKIP,
	    msg_size, VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Map a message for transmission by reference, binding each of its mblks for
 * DMA and appending the resulting cookies to the transmit buffer's
 * descriptor chain. Returns VIOIF_TXEXT_TOOBIG, with the message retained
 * and the chain cleared, if it has more disjoint segments than a chain can
 * carry. The caller may pull the message up into contiguous storage and try
 * again. On any other failure the message is freed.
 */
static vioif_txext_result_t
vioif_tx_external(vioif_txq_t *txq, vioif_txbuf_t *tb, mblk_t *mp,
    size_t msg_size)
{
	vioif_t *vif = txq->vtq_vif;
	vioif_txext_result_t res = VIOIF_TXEXT_FAIL;

	VERIFY(MUTEX_NOT_HELD(&txq->vtq_mutex));

	mblk_t *nmp = mp;
	tb->tb_ndmaext = 0;

	while (nmp != NULL) {
		size_t len;

		if ((len = MBLKL(nmp)) == 0) {
			/*
			 * Skip any zero-length entries in the chain.
			 */
			nmp = nmp->b_cont;
			continue;
		}

		if (tb->tb_ndmaext >= tb->tb_dmaext_capacity) {
			mutex_enter(&txq->vtq_mutex);
			txq->vtq_txfail_indirect_limit++;
			mutex_exit(&txq->vtq_mutex);
			res = VIOIF_TXEXT_TOOBIG;
			goto fail;
		}

		if (tb->tb_dmaext[tb->tb_ndmaext] == NULL) {
			/*
			 * Allocate a DMA handle for this slot.
			 */
			if ((tb->tb_dmaext[tb->tb_ndmaext] =
			    virtio_dma_alloc_nomem(vif->vif_virtio,
			    &vioif_dma_attr_external, KM_SLEEP)) == NULL) {
				mutex_enter(&txq->vtq_mutex);
				txq->vtq_notxbuf++;
				mutex_exit(&txq->vtq_mutex);
				goto fail;
			}
		}
		virtio_dma_t *extdma = tb->tb_dmaext[tb->tb_ndmaext++];

		if (virtio_dma_bind(extdma, nmp->b_rptr, len,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, KM_SLEEP) !=
		    DDI_SUCCESS) {
			mutex_enter(&txq->vtq_mutex);
			txq->vtq_txfail_dma_bind++;
			mutex_exit(&txq->vtq_mutex);
			goto fail;
		}

		for (uint_t n = 0; n < virtio_dma_ncookies(extdma); n++) {
			uint64_t pa = virtio_dma_cookie_pa(extdma, n);
			size_t sz = virtio_dma_cookie_size(extdma, n);

			if (virtio_chain_append(tb->tb_chain, pa, sz,
			    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
				mutex_enter(&txq->vtq_mutex);
				txq->vtq_txfail_indirect_limit++;
				mutex_exit(&txq->vtq_mutex);
				res = VIOIF_TXEXT_TOOBIG;
				goto fail;
			}
		}

		nmp = nmp->b_cont;
	}

	/*
	 * We need to keep the message around until we reclaim the buffer from
	 * the device before freeing it.
	 */
	tb->tb_mp = mp;

	return (VIOIF_TXEXT_OK);

fail:
	for (uint_t n = 0; n < tb->tb_ndmaext; n++) {
		if (tb->tb_dmaext[n] != NULL) {
			virtio_dma_unbind(tb->tb_dmaext[n]);
		}
	}
	tb->tb_ndmaext = 0;

	if (res == VIOIF_TXEXT_TOOBIG) {
		/*
		 * Clear the chain, which will have entries for the virtio net
		 * header and any segments appended before the capacity was
		 * reached, so that the caller can rebuild it and retry with a
		 * pulled up copy of the message. The other failure paths can
		 * leave the chain as it is, since the buffer is going back to
		 * the free list, which clears the chain as part of returning
		 * it.
		 */
		virtio_chain_clear(tb->tb_chain);
	} else {
		freemsg(mp);
	}

	return (res);
}

/*
 * Attempt to transmit a single message on a transmit ring. Returns B_TRUE
 * if the message was consumed, whether it was transmitted or dropped as
 * untransmittable. Returns B_FALSE, with the message retained, only when no
 * transmit buffer is available. The caller may retry the same message once
 * descriptors have been reclaimed.
 */
static boolean_t
vioif_send(vioif_txq_t *txq, mblk_t *mp)
{
	vioif_t *vif = txq->vtq_vif;

	VERIFY(MUTEX_NOT_HELD(&txq->vtq_mutex));

	vioif_txbuf_t *tb = NULL;
	struct virtio_net_hdr *vnh = NULL;
	size_t msg_size = 0;
	uint32_t csum_start;
	uint32_t csum_stuff;
	uint32_t csum_flags;
	uint32_t lso_flags;
	uint32_t lso_mss;
	mblk_t *nmp;
	int ret;
	boolean_t lso_required = B_FALSE;
	struct ether_header *ether = (void *)mp->b_rptr;

	for (nmp = mp; nmp; nmp = nmp->b_cont)
		msg_size += MBLKL(nmp);

	if (vif->vif_tx_tso4 || vif->vif_tx_tso6) {
		mac_lso_get(mp, &lso_mss, &lso_flags);
		lso_required = (lso_flags & HW_LSO) != 0;
	}

	mutex_enter(&txq->vtq_mutex);
	if ((tb = vioif_txbuf_alloc(txq)) == NULL) {
		txq->vtq_notxbuf++;
		mutex_exit(&txq->vtq_mutex);
		return (B_FALSE);
	}
	mutex_exit(&txq->vtq_mutex);

	/*
	 * Use the inline buffer for the virtio net header.  Zero the portion
	 * of our DMA allocation prior to the packet data.
	 */
	vnh = virtio_dma_va(tb->tb_dma, 0);
	bzero(vnh, VIOIF_HEADER_SKIP);

	if (vioif_tx_header_append(vif, tb) != DDI_SUCCESS)
		goto drop;

	mac_hcksum_get(mp, &csum_start, &csum_stuff, NULL, NULL, &csum_flags);

	/*
	 * They want us to do the TCP/UDP csum calculation.
	 */
	if (csum_flags & HCK_PARTIALCKSUM) {
		int eth_hsize;

		/*
		 * Did we ask for it?
		 */
		ASSERT(vif->vif_tx_csum);

		/*
		 * We only asked for partial csum packets.
		 */
		ASSERT(!(csum_flags & HCK_IPV4_HDRCKSUM));
		ASSERT(!(csum_flags & HCK_FULLCKSUM));

		if (ether->ether_type == htons(ETHERTYPE_VLAN)) {
			eth_hsize = sizeof (struct ether_vlan_header);
		} else {
			eth_hsize = sizeof (struct ether_header);
		}

		vnh->vnh_flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		vnh->vnh_csum_start = eth_hsize + csum_start;
		vnh->vnh_csum_offset = csum_stuff - csum_start;
	}

	/*
	 * Setup LSO fields if required.
	 */
	if (lso_required) {
		const mac_ether_offload_flags_t needed =
		    MEOI_L2INFO_SET | MEOI_L3INFO_SET | MEOI_L4INFO_SET;
		mac_ether_offload_info_t meo;
		uint32_t cksum;
		size_t len, hdrs_len;
		tcpha_t *tcpha;

		mac_ether_offload_info(mp, &meo);
		if ((meo.meoi_flags & needed) != needed) {
			goto drop;
		}

		if (meo.meoi_l4proto != IPPROTO_TCP) {
			goto drop;
		}

		if (meo.meoi_l3proto == ETHERTYPE_IP && vif->vif_tx_tso4) {
			vnh->vnh_gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		} else if (meo.meoi_l3proto == ETHERTYPE_IPV6 &&
		    vif->vif_tx_tso6) {
			vnh->vnh_gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		} else {
			goto drop;
		}

		/*
		 * The TCP stack does not include the length in the TCP
		 * pseudo-header when it is performing LSO since hardware
		 * generally asks for it to be removed (as it'll change).
		 * Unfortunately, for virtio, we actually need it. This means we
		 * need to go through and calculate the actual length and fix
		 * things up. Because the virtio spec cares about the ECN flag
		 * and indicating that, at least this means we'll have that
		 * available as well.
		 */
		hdrs_len = meo.meoi_l2hlen + meo.meoi_l3hlen + meo.meoi_l4hlen;
		if (MBLKL(mp) < hdrs_len) {
			mblk_t *pullmp;

			/*
			 * The headers do not all sit within the first mblk.
			 * Replace the message with an equivalent one in which
			 * they do, so that the checksum manipulation below
			 * lands in the message that is transmitted.
			 */
			if ((pullmp = msgpullup(mp, hdrs_len)) == NULL)
				goto drop;
			freemsg(mp);
			mp = pullmp;
			ether = (void *)mp->b_rptr;
		}
		tcpha = (tcpha_t *)(mp->b_rptr + meo.meoi_l2hlen +
		    meo.meoi_l3hlen);

		len = meo.meoi_len - meo.meoi_l2hlen - meo.meoi_l3hlen;
		cksum = ntohs(tcpha->tha_sum) + len;
		cksum = (cksum >> 16) + (cksum & 0xffff);
		cksum = (cksum >> 16) + (cksum & 0xffff);
		tcpha->tha_sum = htons(cksum);

		if (tcpha->tha_flags & TH_CWR) {
			vnh->vnh_gso_type |= VIRTIO_NET_HDR_GSO_ECN;
		}
		vnh->vnh_gso_size = (uint16_t)lso_mss;
		vnh->vnh_hdr_len = hdrs_len;
	}

	/*
	 * The device does not maintain its own statistics about broadcast or
	 * multicast packets, so we have to check the destination address
	 * ourselves.
	 */
	if ((ether->ether_dhost.ether_addr_octet[0] & 0x01) != 0) {
		mutex_enter(&txq->vtq_mutex);
		if (ether_cmp(&ether->ether_dhost, vioif_broadcast) == 0) {
			txq->vtq_brdcstxmt++;
		} else {
			txq->vtq_multixmt++;
		}
		mutex_exit(&txq->vtq_mutex);
	}

	/*
	 * For small packets, copy into the preallocated inline buffer rather
	 * than incur the overhead of mapping.  Note that both of these
	 * functions ensure that "mp" is freed before returning.
	 */
	if (msg_size < vif->vif_txcopy_thresh) {
		ret = vioif_tx_inline(txq, tb, mp, msg_size);
		mp = NULL;
	} else {
		vioif_txext_result_t xres;

		xres = vioif_tx_external(txq, tb, mp, msg_size);
		if (xres == VIOIF_TXEXT_TOOBIG) {
			mblk_t *pulled;

			/*
			 * The message is spread across more disjoint pieces
			 * of memory than a descriptor chain can carry.
			 * Rebuild it as a single contiguous message, re-add
			 * the header descriptor that was lost when the chain
			 * was cleared, and try once more. The copy is
			 * expensive, but better than dropping the frame.
			 */
			if ((pulled = msgpullup(mp, -1)) == NULL)
				goto drop;
			freemsg(mp);
			mp = pulled;

			if (vioif_tx_header_append(vif, tb) != DDI_SUCCESS)
				goto drop;
			xres = vioif_tx_external(txq, tb, mp, msg_size);
		}

		switch (xres) {
		case VIOIF_TXEXT_OK:
			ret = DDI_SUCCESS;
			/*
			 * The message is held in `tb_mp` until reclaim and
			 * we no longer own it.
			 */
			mp = NULL;
			break;
		case VIOIF_TXEXT_FAIL:
			/* The message has already been freed. */
			ret = DDI_FAILURE;
			mp = NULL;
			break;
		case VIOIF_TXEXT_TOOBIG:
		default:
			/*
			 * A single contiguous message cannot exceed the chain
			 * capacity, so this should not recur after the pullup
			 * above. Drop the frame if it somehow does.
			 */
			goto drop;
		}
	}

	if (ret != DDI_SUCCESS) {
		goto drop;
	}

	mutex_enter(&txq->vtq_mutex);
	txq->vtq_opackets++;
	txq->vtq_obytes += msg_size;
	mutex_exit(&txq->vtq_mutex);

	virtio_dma_sync(tb->tb_dma, DDI_DMA_SYNC_FORDEV);
	virtio_chain_submit(tb->tb_chain, B_TRUE);

	return (B_TRUE);

drop:
	/*
	 * This message cannot be transmitted. Consume and drop it, counting
	 * it against the ring's error statistic. Returning it to MAC would
	 * block the ring behind a condition that descriptor reclamation
	 * cannot resolve.
	 */
	freemsg(mp);

	mutex_enter(&txq->vtq_mutex);
	txq->vtq_oerrors++;
	vioif_txbuf_free(txq, tb);
	mutex_exit(&txq->vtq_mutex);

	return (B_TRUE);
}

/*
 * This is the MAC transmit entrypoint for a single transmit ring; MAC hands
 * us one frame at a time. Returning NULL indicates the frame was consumed,
 * whether it was transmitted or dropped; returning the message blocks the
 * ring until we call mac_tx_ring_update().
 */
static mblk_t *
vioif_ring_tx(void *arg, mblk_t *mp)
{
	vioif_txq_t *txq = arg;

	VERIFY3P(mp->b_next, ==, NULL);

	/*
	 * Prior to attempting to send any more frames, do a reclaim to pick up
	 * any descriptors which have been processed by the host.
	 */
	if (virtio_queue_nactive(txq->vtq_vq) != 0) {
		(void) vioif_reclaim_used_tx(txq);
	}

	for (;;) {
		if (vioif_send(txq, mp)) {
			break;
		}

		/*
		 * If there are no descriptors available, try to reclaim some,
		 * allowing a retry of the send if some are found.
		 */
		if (vioif_reclaim_used_tx(txq) != 0) {
			continue;
		}

		mutex_enter(&txq->vtq_mutex);
		if (!list_is_empty(&txq->vtq_bufs)) {
			/*
			 * A racing reclaim returned buffers to the free list
			 * after our own reclaim found nothing. Retry the
			 * send.
			 */
			mutex_exit(&txq->vtq_mutex);
			continue;
		}

		/*
		 * Otherwise, enable the TX ring interrupt so that as soon as
		 * a descriptor becomes available, transmission can begin
		 * again. For safety, make sure the periodic reclaim is
		 * running as well.
		 */
		txq->vtq_corked = true;
		virtio_queue_no_interrupt(txq->vtq_vq, B_FALSE);
		vioif_reclaim_restart(txq);
		mutex_exit(&txq->vtq_mutex);

		/*
		 * Descriptors returned by the device before the interrupt was
		 * enabled above will never raise it. Reclaim once more now.
		 * If anything is found this also clears the cork and notifies
		 * MAC, and the send can be retried immediately.
		 */
		if (vioif_reclaim_used_tx(txq) != 0) {
			continue;
		}

		return (mp);
	}

	/* Ensure the periodic reclaim has been started. */
	mutex_enter(&txq->vtq_mutex);
	vioif_reclaim_restart(txq);
	mutex_exit(&txq->vtq_mutex);

	return (NULL);
}

uint_t
vioif_tx_handler(caddr_t arg0, caddr_t arg1 __unused)
{
	vioif_txq_t *txq = (vioif_txq_t *)arg0;

	/*
	 * The TX interrupt could race with other reclamation activity, so
	 * interpreting the return value is unimportant.
	 */
	(void) vioif_reclaim_used_tx(txq);

	return (DDI_INTR_CLAIMED);
}

static int
vioif_tx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	vioif_txq_t *txq = (vioif_txq_t *)rh;

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = txq->vtq_obytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = txq->vtq_opackets;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

void
vioif_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	vioif_t *vif = arg;
	vioif_txq_t *txq;

	VERIFY3S(rtype, ==, MAC_RING_TYPE_TX);
	/*
	 * We do not provide transmit groups, so the group index here is
	 * expected to be -1.
	 */
	VERIFY3S(group_index, ==, -1);
	VERIFY3S(ring_index, >=, 0);
	VERIFY3U(ring_index, <, vif->vif_nqpairs);

	txq = &vif->vif_txqs[ring_index];
	txq->vtq_ringh = rh;

	infop->mri_driver = (mac_ring_driver_t)txq;
	infop->mri_start = NULL;
	infop->mri_stop = NULL;
	infop->mri_tx = vioif_ring_tx;
	infop->mri_stat = vioif_tx_ring_stat;

	/*
	 * Provide the interrupt handle for the MSI-X vector servicing this
	 * queue, if it has one, so that MAC can retarget the interrupt to
	 * the CPU associated with the ring.
	 */
	infop->mri_intr.mi_ddi_handle = virtio_queue_intr_handle(txq->vtq_vq);
}
