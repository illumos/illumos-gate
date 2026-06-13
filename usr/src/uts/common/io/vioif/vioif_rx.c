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
 * VIRTIO NETWORK DRIVER: RECEIVE PATH
 *
 * Receive buffer management and frame receipt, including the receive ring
 * entrypoints that we provide to MAC.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>

#include "virtio.h"
#include "vioif.h"

static uint_t vioif_add_rx(vioif_rxq_t *);

static vioif_rxbuf_t *
vioif_rxbuf_alloc(vioif_rxq_t *rxq)
{
	vioif_rxbuf_t *rb;

	VERIFY(MUTEX_HELD(&rxq->vrq_mutex));

	if ((rb = list_remove_head(&rxq->vrq_bufs)) != NULL) {
		rxq->vrq_nbufs_alloc++;
	}

	return (rb);
}

void
vioif_rxbuf_free(vioif_rxq_t *rxq, vioif_rxbuf_t *rb)
{
	VERIFY(MUTEX_HELD(&rxq->vrq_mutex));

	VERIFY3U(rxq->vrq_nbufs_alloc, >, 0);
	rxq->vrq_nbufs_alloc--;

	virtio_chain_clear(rb->rb_chain);
	list_insert_head(&rxq->vrq_bufs, rb);
}

static void
vioif_rx_free_callback(caddr_t free_arg)
{
	vioif_rxbuf_t *rb = (vioif_rxbuf_t *)free_arg;
	vioif_rxq_t *rxq = rb->rb_rxq;

	mutex_enter(&rxq->vrq_mutex);

	/*
	 * Return this receive buffer to the free list.
	 */
	vioif_rxbuf_free(rxq, rb);

	VERIFY3U(rxq->vrq_nbufs_onloan, >, 0);
	rxq->vrq_nbufs_onloan--;

	/*
	 * Attempt to replenish the receive queue with at least the buffer we
	 * just freed.  There isn't a great way to deal with failure here,
	 * though because we'll only loan at most half of the buffers there
	 * should always be at least some available even if this fails.
	 */
	(void) vioif_add_rx(rxq);

	mutex_exit(&rxq->vrq_mutex);
}

int
vioif_alloc_rxq_bufs(vioif_rxq_t *rxq)
{
	vioif_t *vif = rxq->vrq_vif;

	rxq->vrq_bufs_capacity = MIN(VIRTIO_NET_RX_BUFS,
	    virtio_queue_size(rxq->vrq_vq));
	rxq->vrq_bufs_mem = kmem_zalloc(
	    sizeof (vioif_rxbuf_t) * rxq->vrq_bufs_capacity, KM_SLEEP);
	list_create(&rxq->vrq_bufs, sizeof (vioif_rxbuf_t),
	    offsetof(vioif_rxbuf_t, rb_link));

	/*
	 * Do not loan more than half of our allocated receive buffers into
	 * the networking stack.
	 */
	rxq->vrq_nbufs_onloan_max = rxq->vrq_bufs_capacity / 2;

	for (uint_t i = 0; i < rxq->vrq_bufs_capacity; i++) {
		list_insert_tail(&rxq->vrq_bufs, &rxq->vrq_bufs_mem[i]);
	}

	/*
	 * The receive buffers are large, and we can tolerate a large number
	 * of segments.  Adjust the SGL entry count, setting aside one segment
	 * for the virtio net header.
	 */
	ddi_dma_attr_t attr = vioif_dma_attr_bufs;
	attr.dma_attr_sgllen = VIOIF_MAX_SEGS - 1;

	for (vioif_rxbuf_t *rb = list_head(&rxq->vrq_bufs); rb != NULL;
	    rb = list_next(&rxq->vrq_bufs, rb)) {
		if ((rb->rb_dma = virtio_dma_alloc(vif->vif_virtio,
		    VIOIF_RX_BUF_SIZE, &attr, DDI_DMA_STREAMING | DDI_DMA_READ,
		    KM_SLEEP)) == NULL) {
			return (ENOMEM);
		}

		if ((rb->rb_chain = virtio_chain_alloc(rxq->vrq_vq,
		    KM_SLEEP)) == NULL) {
			return (ENOMEM);
		}
		virtio_chain_data_set(rb->rb_chain, rb);

		/*
		 * Ensure that the first cookie is sufficient to cover the
		 * header skip region plus one byte.
		 */
		VERIFY3U(virtio_dma_cookie_size(rb->rb_dma, 0), >=,
		    VIOIF_HEADER_SKIP + 1);

		/*
		 * Ensure that the frame data begins at a location with a
		 * correctly aligned IP header.
		 */
		VERIFY3U((uintptr_t)virtio_dma_va(rb->rb_dma,
		    VIOIF_HEADER_SKIP) % 4, ==, 2);

		rb->rb_rxq = rxq;
		rb->rb_frtn.free_func = vioif_rx_free_callback;
		rb->rb_frtn.free_arg = (caddr_t)rb;
	}

	return (0);
}

void
vioif_free_rxq_bufs(vioif_rxq_t *rxq)
{
	if (rxq->vrq_bufs_mem == NULL)
		return;

	VERIFY3U(rxq->vrq_nbufs_alloc, ==, 0);
	for (uint_t i = 0; i < rxq->vrq_bufs_capacity; i++) {
		vioif_rxbuf_t *rb = &rxq->vrq_bufs_mem[i];

		/*
		 * Ensure that this rxbuf is now in the free list:
		 */
		VERIFY(list_link_active(&rb->rb_link));
		list_remove(&rxq->vrq_bufs, rb);

		if (rb->rb_dma != NULL) {
			virtio_dma_free(rb->rb_dma);
			rb->rb_dma = NULL;
		}

		if (rb->rb_chain != NULL) {
			virtio_chain_free(rb->rb_chain);
			rb->rb_chain = NULL;
		}
	}
	VERIFY(list_is_empty(&rxq->vrq_bufs));
	list_destroy(&rxq->vrq_bufs);

	kmem_free(rxq->vrq_bufs_mem,
	    sizeof (vioif_rxbuf_t) * rxq->vrq_bufs_capacity);
	rxq->vrq_bufs_mem = NULL;
	rxq->vrq_bufs_capacity = 0;
}

/*
 * The time to wait in vioif_rx_drain() for loaned receive buffers to be
 * returned by the networking stack, in milliseconds.
 */
uint_t vioif_rx_drain_ms = 200;

/*
 * Wait for receive buffers that were loaned to the networking stack to be
 * returned, for up to `vioif_rx_drain_ms` milliseconds. A loaned buffer can
 * be held indefinitely, so this is only a best effort. Returns true if every
 * buffer was returned.
 */
bool
vioif_rx_drain(vioif_t *vif)
{
	const hrtime_t deadline = gethrtime() + MSEC2NSEC(vioif_rx_drain_ms);

	for (;;) {
		bool onloan = false;

		for (uint_t i = 0; i < vif->vif_nqpairs; i++) {
			vioif_rxq_t *rxq = &vif->vif_rxqs[i];

			mutex_enter(&rxq->vrq_mutex);
			if (rxq->vrq_nbufs_onloan > 0)
				onloan = true;
			mutex_exit(&rxq->vrq_mutex);
		}

		if (!onloan)
			return (true);
		if (gethrtime() > deadline)
			return (false);

		delay(drv_usectohz(1000));
	}
}

static uint_t
vioif_add_rx(vioif_rxq_t *rxq)
{
	VERIFY(MUTEX_HELD(&rxq->vrq_mutex));

	if (!rxq->vrq_running) {
		/*
		 * If the ring is not running, do not give the device any
		 * receive buffers.
		 */
		return (0);
	}

	uint_t num_added = 0;

	vioif_t *vif = rxq->vrq_vif;
	vioif_rxbuf_t *rb;
	while ((rb = vioif_rxbuf_alloc(rxq)) != NULL) {
		/*
		 * For legacy devices, and those that have not negotiated
		 * VIRTIO_F_ANY_LAYOUT, the virtio net header must appear in a
		 * separate descriptor entry to the rest of the buffer. We do
		 * the same for modern devices too.
		 */
		if (virtio_chain_append(rb->rb_chain,
		    virtio_dma_cookie_pa(rb->rb_dma, 0), vif->vif_rxbuf_hdrlen,
		    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
			goto fail;
		}

		for (uint_t n = 0; n < virtio_dma_ncookies(rb->rb_dma); n++) {
			uint64_t pa = virtio_dma_cookie_pa(rb->rb_dma, n);
			size_t sz = virtio_dma_cookie_size(rb->rb_dma, n);

			if (n == 0) {
				pa += VIOIF_HEADER_SKIP;
				VERIFY3U(sz, >, VIOIF_HEADER_SKIP);
				sz -= VIOIF_HEADER_SKIP;
			}

			if (virtio_chain_append(rb->rb_chain, pa, sz,
			    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
				goto fail;
			}
		}

		virtio_chain_submit(rb->rb_chain, B_FALSE);
		num_added++;
		continue;

fail:
		vioif_rxbuf_free(rxq, rb);
		rxq->vrq_norecvbuf++;
		break;
	}

	if (num_added > 0) {
		virtio_queue_flush(rxq->vrq_vq);
	}

	return (num_added);
}

/*
 * Collect received frames from a receive queue, returning them as a chain of
 * messages for delivery to MAC. This is called both from the queue interrupt
 * handler and, with a byte budget, on behalf of the MAC poll thread. A
 * "poll_bytes" value of "VIOIF_RX_ALL_BYTES" means no budget; collect
 * everything the device has returned.
 *
 * The queue mutex must be held on entry and is held again on return, but it
 * is dropped around message allocation and the copying of frame data, which
 * for a large frame is a substantial amount of work to perform while holding
 * an interrupt-priority mutex that the buffer free callback also requires.
 */
#define	VIOIF_RX_ALL_BYTES	(-1)

static mblk_t *
vioif_ring_rx(vioif_rxq_t *rxq, int poll_bytes)
{
	vioif_t *vif = rxq->vrq_vif;
	virtio_chain_t *vic;
	mblk_t *mphead = NULL, *lastmp = NULL, *mp;
	size_t nbytes = 0;

	VERIFY(MUTEX_HELD(&rxq->vrq_mutex));

	while ((vic = virtio_queue_poll(rxq->vrq_vq)) != NULL) {
		/*
		 * We have to use the chain received length here, as the device
		 * does not tell us the received frame length any other way.
		 * In a limited survey of hypervisors, virtio network devices
		 * appear to provide the right value here.
		 */
		size_t len = virtio_chain_received_length(vic);
		vioif_rxbuf_t *rb = virtio_chain_data(vic);

		virtio_dma_sync(rb->rb_dma, DDI_DMA_SYNC_FORCPU);

		/*
		 * If the ring is not running, discard any received frames.
		 */
		if (!rxq->vrq_running) {
			vioif_rxbuf_free(rxq, rb);
			continue;
		}

		if (len <= vif->vif_rxbuf_hdrlen) {
			rxq->vrq_rxfail_chain_undersize++;
			rxq->vrq_ierrors++;
			vioif_rxbuf_free(rxq, rb);
			continue;
		}
		len -= vif->vif_rxbuf_hdrlen;

		/*
		 * The received length is under the control of the device and
		 * cannot be trusted. Discard anything that claims to extend
		 * beyond the data region of the receive buffer rather than
		 * publish stray kernel memory to the networking stack.
		 */
		if (len > virtio_dma_size(rb->rb_dma) - VIOIF_HEADER_SKIP) {
			rxq->vrq_rxfail_chain_oversize++;
			rxq->vrq_ierrors++;
			vioif_rxbuf_free(rxq, rb);
			continue;
		}

		/*
		 * We copy small packets that happen to fit into a single
		 * cookie and reuse the buffers. For bigger ones, we loan
		 * the buffers upstream.
		 */
		if (len < vif->vif_rxcopy_thresh ||
		    rxq->vrq_nbufs_onloan >= rxq->vrq_nbufs_onloan_max) {
			mutex_exit(&rxq->vrq_mutex);
			if ((mp = allocb(len, 0)) != NULL) {
				bcopy(virtio_dma_va(rb->rb_dma,
				    VIOIF_HEADER_SKIP), mp->b_rptr, len);
				mp->b_wptr = mp->b_rptr + len;
			}
			mutex_enter(&rxq->vrq_mutex);

			/*
			 * As the packet contents was copied rather than
			 * loaned, we can return the receive buffer resources
			 * to the free list.
			 */
			vioif_rxbuf_free(rxq, rb);

			if (mp == NULL) {
				rxq->vrq_norecvbuf++;
				rxq->vrq_ierrors++;
				continue;
			}
		} else {
			mutex_exit(&rxq->vrq_mutex);
			if ((mp = desballoc(virtio_dma_va(rb->rb_dma,
			    VIOIF_HEADER_SKIP), len, 0,
			    &rb->rb_frtn)) != NULL) {
				mp->b_wptr = mp->b_rptr + len;
			}
			mutex_enter(&rxq->vrq_mutex);

			if (mp == NULL) {
				rxq->vrq_norecvbuf++;
				rxq->vrq_ierrors++;
				vioif_rxbuf_free(rxq, rb);
				continue;
			}

			rxq->vrq_nbufs_onloan++;
		}

		/*
		 * virtio-net does not tell us if this packet is multicast
		 * or broadcast, so we have to check it.
		 */
		if (mp->b_rptr[0] & 0x1) {
			if (bcmp(mp->b_rptr, vioif_broadcast, ETHERADDRL) != 0)
				rxq->vrq_multircv++;
			else
				rxq->vrq_brdcstrcv++;
		}

		rxq->vrq_rbytes += len;
		rxq->vrq_ipackets++;

		if (lastmp == NULL) {
			mphead = mp;
		} else {
			lastmp->b_next = mp;
		}
		lastmp = mp;

		/*
		 * When polling, stop once we have met the byte budget. Any
		 * frames left in the ring will be collected by a subsequent
		 * poll, or by the interrupt handler once MAC has released the
		 * ring from polling.
		 */
		nbytes += len;
		if (poll_bytes != VIOIF_RX_ALL_BYTES &&
		    nbytes >= (size_t)poll_bytes) {
			break;
		}
	}

	return (mphead);
}

/*
 * Collect frames from a receive queue and deliver them to MAC, unless the
 * MAC poll thread currently owns the ring. This is the body of the queue
 * interrupt handler, and is also run from the driver task queue to collect
 * frames that were returned by the device without raising an interrupt.
 */
static void
vioif_rx_collect(vioif_rxq_t *rxq)
{
	mblk_t *mp = NULL;
	uint64_t gen = 0;

	mutex_enter(&rxq->vrq_mutex);
	if (!rxq->vrq_polling) {
		mp = vioif_ring_rx(rxq, VIOIF_RX_ALL_BYTES);

		/*
		 * Attempt to replenish the receive queue. If we cannot add
		 * any descriptors here, it may be because all of the recently
		 * received packets were loaned up to the networking stack.
		 */
		(void) vioif_add_rx(rxq);

		gen = rxq->vrq_gen;
	}
	mutex_exit(&rxq->vrq_mutex);

	if (mp != NULL) {
		mac_rx_ring(rxq->vrq_vif->vif_mac_handle, rxq->vrq_ringh,
		    mp, gen);
	}
}

static void
vioif_rx_collect_task(void *arg)
{
	vioif_rxq_t *rxq = arg;

	/*
	 * Clear the flag before collecting, so that a wakeup arriving during
	 * the collection queues the task entry again rather than being lost.
	 */
	mutex_enter(&rxq->vrq_mutex);
	rxq->vrq_collect_queued = false;
	mutex_exit(&rxq->vrq_mutex);

	vioif_rx_collect(rxq);
}

/*
 * The device makes its virtqueue interrupt suppression decision only at the
 * moment it returns a frame, so no interrupt is ever generated for frames
 * returned while interrupts were suppressed and re-enabling them is not
 * retroactive. We re-enable them when a ring is started and when MAC releases
 * a ring from polled mode. At those points, any frames already in the used
 * ring would otherwise sit there until a future frame arrived and raised an
 * interrupt, or indefinitely if the queue has run out of receive buffers.
 * Collect them from a task queue. We cannot do so directly since MAC calls
 * the interrupt enable entrypoint with SRS locks held that mac_rx_ring()
 * also requires.
 */
static void
vioif_rx_dispatch_collect(vioif_rxq_t *rxq)
{
	if (!virtio_queue_pending(rxq->vrq_vq))
		return;

	/*
	 * Despatch on the pre-allocated task entry, which cannot fail and
	 * does not sleep. The flag prevents the entry from being queued a
	 * second time while it is already waiting to run.
	 */
	mutex_enter(&rxq->vrq_mutex);
	if (!rxq->vrq_collect_queued) {
		rxq->vrq_collect_queued = true;
		taskq_dispatch_ent(rxq->vrq_vif->vif_taskq,
		    vioif_rx_collect_task, rxq, 0, &rxq->vrq_collect_tqent);
	}
	mutex_exit(&rxq->vrq_mutex);
}

uint_t
vioif_rx_handler(caddr_t arg0, caddr_t arg1 __unused)
{
	vioif_rxq_t *rxq = (vioif_rxq_t *)arg0;

	vioif_rx_collect(rxq);

	return (DDI_INTR_CLAIMED);
}

static int
vioif_rx_ring_start(mac_ring_driver_t rh, uint64_t gen)
{
	vioif_rxq_t *rxq = (vioif_rxq_t *)rh;
	mblk_t *mp;

	mutex_enter(&rxq->vrq_mutex);
	rxq->vrq_gen = gen;
	rxq->vrq_polling = false;

	/*
	 * The device may have continued to fill buffers that were left in
	 * the queue while the ring was stopped, without raising an
	 * interrupt. Those frames belong to an earlier incarnation of the
	 * ring, so discard them. Discarding also returns their buffers for
	 * reuse. With `vrq_running` still clear, `vioif_ring_rx()` frees
	 * each frame as it is collected and never allocates a message, so
	 * it cannot return a chain here.
	 */
	mp = vioif_ring_rx(rxq, VIOIF_RX_ALL_BYTES);
	VERIFY3P(mp, ==, NULL);

	rxq->vrq_running = true;

	/*
	 * Add as many receive buffers as we can to the receive queue. If we
	 * cannot add any, it may be because we have stopped and started again
	 * and the descriptors are all in the queue already.
	 */
	(void) vioif_add_rx(rxq);
	mutex_exit(&rxq->vrq_mutex);

	virtio_queue_no_interrupt(rxq->vrq_vq, B_FALSE);

	/*
	 * A frame that the device returned after the drain above, but before
	 * the queue interrupt was re-enabled, will never raise one. Collect
	 * it now. It arrived around the time the ring started, so it is
	 * delivered under the new generation.
	 */
	vioif_rx_dispatch_collect(rxq);

	return (0);
}

static void
vioif_rx_ring_stop(mac_ring_driver_t rh)
{
	vioif_rxq_t *rxq = (vioif_rxq_t *)rh;

	virtio_queue_no_interrupt(rxq->vrq_vq, B_TRUE);

	/*
	 * There is no way to instruct the device to stop using a ring, so
	 * all we can do here is stop collecting from it. The buffers the
	 * device holds cannot be recovered without a full device reset, and
	 * it will continue to fill them with received frames while the ring
	 * is stopped. Those frames are discarded when the ring is next
	 * started, and the buffers are finally recovered in detach.
	 */
	mutex_enter(&rxq->vrq_mutex);
	rxq->vrq_running = false;
	mutex_exit(&rxq->vrq_mutex);
}

static mblk_t *
vioif_rx_ring_poll(void *arg, int nbytes)
{
	vioif_rxq_t *rxq = arg;
	mblk_t *mp;

	if (nbytes <= 0)
		return (NULL);

	mutex_enter(&rxq->vrq_mutex);
	mp = vioif_ring_rx(rxq, nbytes);

	/*
	 * Attempt to replenish the receive queue, as the interrupt path
	 * does. If we cannot add any descriptors here, it may be because
	 * all of the recently received packets were loaned up to the
	 * networking stack.
	 */
	(void) vioif_add_rx(rxq);
	mutex_exit(&rxq->vrq_mutex);

	return (mp);
}

static int
vioif_rx_ring_intr_enable(mac_intr_handle_t ih)
{
	vioif_rxq_t *rxq = (vioif_rxq_t *)ih;

	mutex_enter(&rxq->vrq_mutex);
	rxq->vrq_polling = false;
	mutex_exit(&rxq->vrq_mutex);

	virtio_queue_no_interrupt(rxq->vrq_vq, B_FALSE);

	/*
	 * A frame that the device returned after the final poll, but before
	 * interrupts were re-enabled above, will never raise one. Collect it
	 * now.
	 */
	vioif_rx_dispatch_collect(rxq);

	return (0);
}

static int
vioif_rx_ring_intr_disable(mac_intr_handle_t ih)
{
	vioif_rxq_t *rxq = (vioif_rxq_t *)ih;

	/*
	 * Virtqueue interrupt suppression is only advisory, so the device may
	 * still deliver an interrupt while MAC is polling the ring. The
	 * "vrq_polling" flag stops the interrupt handler from collecting
	 * frames while the flag is set.
	 */
	mutex_enter(&rxq->vrq_mutex);
	rxq->vrq_polling = true;
	mutex_exit(&rxq->vrq_mutex);

	virtio_queue_no_interrupt(rxq->vrq_vq, B_TRUE);

	return (0);
}

static int
vioif_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	vioif_rxq_t *rxq = (vioif_rxq_t *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rxq->vrq_rbytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = rxq->vrq_ipackets;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

void
vioif_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	vioif_t *vif = arg;
	vioif_rxq_t *rxq;
	mac_intr_t *mintr = &infop->mri_intr;

	VERIFY3S(rtype, ==, MAC_RING_TYPE_RX);
	VERIFY3S(group_index, ==, 0);
	VERIFY3S(ring_index, >=, 0);
	VERIFY3U(ring_index, <, vif->vif_nqpairs);

	rxq = &vif->vif_rxqs[ring_index];
	rxq->vrq_ringh = rh;

	infop->mri_driver = (mac_ring_driver_t)rxq;
	infop->mri_start = vioif_rx_ring_start;
	infop->mri_stop = vioif_rx_ring_stop;
	infop->mri_poll = vioif_rx_ring_poll;
	infop->mri_stat = vioif_rx_ring_stat;

	mintr->mi_handle = (mac_intr_handle_t)rxq;
	mintr->mi_enable = vioif_rx_ring_intr_enable;
	mintr->mi_disable = vioif_rx_ring_intr_disable;

	/*
	 * Provide the interrupt handle for the MSI-X vector servicing this
	 * queue, if it has one, so that MAC can retarget the interrupt to
	 * the CPU associated with the ring.
	 */
	mintr->mi_ddi_handle = virtio_queue_intr_handle(rxq->vrq_vq);
}
