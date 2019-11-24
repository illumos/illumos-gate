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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
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
 * VIRTIO NETWORK DRIVER
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/sysmacros.h>
#include <sys/smbios.h>

#include <sys/dlpi.h>
#include <sys/taskq.h>

#include <sys/pattr.h>
#include <sys/strsun.h>

#include <sys/random.h>
#include <sys/containerof.h>
#include <sys/stream.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#include "virtio.h"
#include "vioif.h"


static int vioif_quiesce(dev_info_t *);
static int vioif_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioif_detach(dev_info_t *, ddi_detach_cmd_t);
static boolean_t vioif_has_feature(vioif_t *, uint32_t);
static void vioif_reclaim_restart(vioif_t *);
static int vioif_m_stat(void *, uint_t, uint64_t *);
static void vioif_m_stop(void *);
static int vioif_m_start(void *);
static int vioif_m_multicst(void *, boolean_t, const uint8_t *);
static int vioif_m_setpromisc(void *, boolean_t);
static int vioif_m_unicst(void *, const uint8_t *);
static mblk_t *vioif_m_tx(void *, mblk_t *);
static int vioif_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int vioif_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void vioif_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static boolean_t vioif_m_getcapab(void *, mac_capab_t, void *);
static uint_t vioif_add_rx(vioif_t *);


static struct cb_ops vioif_cb_ops = {
	.cb_rev =			CB_REV,
	.cb_flag =			D_MP | D_NEW,

	.cb_open =			nulldev,
	.cb_close =			nulldev,
	.cb_strategy =			nodev,
	.cb_print =			nodev,
	.cb_dump =			nodev,
	.cb_read =			nodev,
	.cb_write =			nodev,
	.cb_ioctl =			nodev,
	.cb_devmap =			nodev,
	.cb_mmap =			nodev,
	.cb_segmap =			nodev,
	.cb_chpoll =			nochpoll,
	.cb_prop_op =			ddi_prop_op,
	.cb_str =			NULL,
	.cb_aread =			nodev,
	.cb_awrite =			nodev,
};

static struct dev_ops vioif_dev_ops = {
	.devo_rev =			DEVO_REV,
	.devo_refcnt =			0,

	.devo_attach =			vioif_attach,
	.devo_detach =			vioif_detach,
	.devo_quiesce =			vioif_quiesce,

	.devo_cb_ops =			&vioif_cb_ops,

	.devo_getinfo =			NULL,
	.devo_identify =		nulldev,
	.devo_probe =			nulldev,
	.devo_reset =			nodev,
	.devo_bus_ops =			NULL,
	.devo_power =			NULL,
};

static struct modldrv vioif_modldrv = {
	.drv_modops =			&mod_driverops,
	.drv_linkinfo =			"VIRTIO network driver",
	.drv_dev_ops =			&vioif_dev_ops
};

static struct modlinkage vioif_modlinkage = {
	.ml_rev =			MODREV_1,
	.ml_linkage =			{ &vioif_modldrv, NULL }
};

static mac_callbacks_t vioif_mac_callbacks = {
	.mc_getstat =			vioif_m_stat,
	.mc_start =			vioif_m_start,
	.mc_stop =			vioif_m_stop,
	.mc_setpromisc =		vioif_m_setpromisc,
	.mc_multicst =			vioif_m_multicst,
	.mc_unicst =			vioif_m_unicst,
	.mc_tx =			vioif_m_tx,

	.mc_callbacks =			(MC_GETCAPAB | MC_SETPROP |
					    MC_GETPROP | MC_PROPINFO),
	.mc_getcapab =			vioif_m_getcapab,
	.mc_setprop =			vioif_m_setprop,
	.mc_getprop =			vioif_m_getprop,
	.mc_propinfo =			vioif_m_propinfo,
};

static const uchar_t vioif_broadcast[ETHERADDRL] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*
 * Interval for the periodic TX reclaim.
 */
uint_t vioif_reclaim_ms = 200;

/*
 * Allow the operator to override the kinds of interrupts we'll use for
 * vioif.  This value defaults to -1 so that it can be overridden to 0 in
 * /etc/system.
 */
int vioif_allowed_int_types = -1;

/*
 * DMA attribute template for transmit and receive buffers.  The SGL entry
 * count will be modified before using the template.  Note that these
 * allocations are aligned so that VIOIF_HEADER_SKIP places the IP header in
 * received frames at the correct offset for the networking stack.
 */
ddi_dma_attr_t vioif_dma_attr_bufs = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0x00000000FFFFFFFF,
	.dma_attr_align =		VIOIF_HEADER_ALIGN,
	.dma_attr_burstsizes =		1,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0x00000000FFFFFFFF,
	.dma_attr_seg =			0x00000000FFFFFFFF,
	.dma_attr_sgllen =		0,
	.dma_attr_granular =		1,
	.dma_attr_flags =		0
};

/*
 * DMA attributes for mapping larger transmit buffers from the networking
 * stack.  The requirements are quite loose, but note that the SGL entry length
 * field is 32-bit.
 */
ddi_dma_attr_t vioif_dma_attr_external = {
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
 * VIRTIO NET MAC PROPERTIES
 */
#define	VIOIF_MACPROP_TXCOPY_THRESH	"_txcopy_thresh"
#define	VIOIF_MACPROP_TXCOPY_THRESH_DEF	300
#define	VIOIF_MACPROP_TXCOPY_THRESH_MAX	640

#define	VIOIF_MACPROP_RXCOPY_THRESH	"_rxcopy_thresh"
#define	VIOIF_MACPROP_RXCOPY_THRESH_DEF	300
#define	VIOIF_MACPROP_RXCOPY_THRESH_MAX	640

static char *vioif_priv_props[] = {
	VIOIF_MACPROP_TXCOPY_THRESH,
	VIOIF_MACPROP_RXCOPY_THRESH,
	NULL
};


static vioif_txbuf_t *
vioif_txbuf_alloc(vioif_t *vif)
{
	vioif_txbuf_t *tb;

	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	if ((tb = list_remove_head(&vif->vif_txbufs)) != NULL) {
		vif->vif_ntxbufs_alloc++;
	}

	return (tb);
}

static void
vioif_txbuf_free(vioif_t *vif, vioif_txbuf_t *tb)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	VERIFY3U(vif->vif_ntxbufs_alloc, >, 0);
	vif->vif_ntxbufs_alloc--;

	virtio_chain_clear(tb->tb_chain);
	list_insert_head(&vif->vif_txbufs, tb);
}

static vioif_rxbuf_t *
vioif_rxbuf_alloc(vioif_t *vif)
{
	vioif_rxbuf_t *rb;

	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	if ((rb = list_remove_head(&vif->vif_rxbufs)) != NULL) {
		vif->vif_nrxbufs_alloc++;
	}

	return (rb);
}

static void
vioif_rxbuf_free(vioif_t *vif, vioif_rxbuf_t *rb)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	VERIFY3U(vif->vif_nrxbufs_alloc, >, 0);
	vif->vif_nrxbufs_alloc--;

	virtio_chain_clear(rb->rb_chain);
	list_insert_head(&vif->vif_rxbufs, rb);
}

static void
vioif_rx_free_callback(caddr_t free_arg)
{
	vioif_rxbuf_t *rb = (vioif_rxbuf_t *)free_arg;
	vioif_t *vif = rb->rb_vioif;

	mutex_enter(&vif->vif_mutex);

	/*
	 * Return this receive buffer to the free list.
	 */
	vioif_rxbuf_free(vif, rb);

	VERIFY3U(vif->vif_nrxbufs_onloan, >, 0);
	vif->vif_nrxbufs_onloan--;

	/*
	 * Attempt to replenish the receive queue with at least the buffer we
	 * just freed.  There isn't a great way to deal with failure here,
	 * though because we'll only loan at most half of the buffers there
	 * should always be at least some available even if this fails.
	 */
	(void) vioif_add_rx(vif);

	mutex_exit(&vif->vif_mutex);
}

static void
vioif_free_bufs(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	VERIFY3U(vif->vif_ntxbufs_alloc, ==, 0);
	for (uint_t i = 0; i < vif->vif_txbufs_capacity; i++) {
		vioif_txbuf_t *tb = &vif->vif_txbufs_mem[i];

		/*
		 * Ensure that this txbuf is now in the free list:
		 */
		VERIFY(list_link_active(&tb->tb_link));
		list_remove(&vif->vif_txbufs, tb);

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
					virtio_dma_free(
					    tb->tb_dmaext[j]);
					tb->tb_dmaext[j] = NULL;
				}
			}

			kmem_free(tb->tb_dmaext,
			    sizeof (virtio_dma_t *) * tb->tb_dmaext_capacity);
			tb->tb_dmaext = NULL;
			tb->tb_dmaext_capacity = 0;
		}
	}
	VERIFY(list_is_empty(&vif->vif_txbufs));
	if (vif->vif_txbufs_mem != NULL) {
		kmem_free(vif->vif_txbufs_mem,
		    sizeof (vioif_txbuf_t) * vif->vif_txbufs_capacity);
		vif->vif_txbufs_mem = NULL;
		vif->vif_txbufs_capacity = 0;
	}

	VERIFY3U(vif->vif_nrxbufs_alloc, ==, 0);
	for (uint_t i = 0; i < vif->vif_rxbufs_capacity; i++) {
		vioif_rxbuf_t *rb = &vif->vif_rxbufs_mem[i];

		/*
		 * Ensure that this rxbuf is now in the free list:
		 */
		VERIFY(list_link_active(&rb->rb_link));
		list_remove(&vif->vif_rxbufs, rb);

		if (rb->rb_dma != NULL) {
			virtio_dma_free(rb->rb_dma);
			rb->rb_dma = NULL;
		}

		if (rb->rb_chain != NULL) {
			virtio_chain_free(rb->rb_chain);
			rb->rb_chain = NULL;
		}
	}
	VERIFY(list_is_empty(&vif->vif_rxbufs));
	if (vif->vif_rxbufs_mem != NULL) {
		kmem_free(vif->vif_rxbufs_mem,
		    sizeof (vioif_rxbuf_t) * vif->vif_rxbufs_capacity);
		vif->vif_rxbufs_mem = NULL;
		vif->vif_rxbufs_capacity = 0;
	}
}

static int
vioif_alloc_bufs(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	/*
	 * Allocate one contiguous chunk of memory for the transmit and receive
	 * buffer tracking objects.  If the ring is unusually small, we'll
	 * reduce our target buffer count accordingly.
	 */
	vif->vif_txbufs_capacity = MIN(VIRTIO_NET_TX_BUFS,
	    virtio_queue_size(vif->vif_tx_vq));
	vif->vif_txbufs_mem = kmem_zalloc(
	    sizeof (vioif_txbuf_t) * vif->vif_txbufs_capacity, KM_SLEEP);
	list_create(&vif->vif_txbufs, sizeof (vioif_txbuf_t),
	    offsetof(vioif_txbuf_t, tb_link));

	vif->vif_rxbufs_capacity = MIN(VIRTIO_NET_RX_BUFS,
	    virtio_queue_size(vif->vif_rx_vq));
	vif->vif_rxbufs_mem = kmem_zalloc(
	    sizeof (vioif_rxbuf_t) * vif->vif_rxbufs_capacity, KM_SLEEP);
	list_create(&vif->vif_rxbufs, sizeof (vioif_rxbuf_t),
	    offsetof(vioif_rxbuf_t, rb_link));

	/*
	 * Do not loan more than half of our allocated receive buffers into
	 * the networking stack.
	 */
	vif->vif_nrxbufs_onloan_max = vif->vif_rxbufs_capacity / 2;

	/*
	 * Put everything in the free list straight away in order to simplify
	 * the use of vioif_free_bufs() for cleanup on allocation failure.
	 */
	for (uint_t i = 0; i < vif->vif_txbufs_capacity; i++) {
		list_insert_tail(&vif->vif_txbufs, &vif->vif_txbufs_mem[i]);
	}
	for (uint_t i = 0; i < vif->vif_rxbufs_capacity; i++) {
		list_insert_tail(&vif->vif_rxbufs, &vif->vif_rxbufs_mem[i]);
	}

	/*
	 * Start from the DMA attribute template common to both transmit and
	 * receive buffers.  The SGL entry count will be modified for each
	 * buffer type.
	 */
	ddi_dma_attr_t attr = vioif_dma_attr_bufs;

	/*
	 * The transmit inline buffer is small (less than a page), so it's
	 * reasonable to request a single cookie.
	 */
	attr.dma_attr_sgllen = 1;

	for (vioif_txbuf_t *tb = list_head(&vif->vif_txbufs); tb != NULL;
	    tb = list_next(&vif->vif_txbufs, tb)) {
		if ((tb->tb_dma = virtio_dma_alloc(vif->vif_virtio,
		    VIOIF_TX_INLINE_SIZE, &attr,
		    DDI_DMA_STREAMING | DDI_DMA_WRITE, KM_SLEEP)) == NULL) {
			goto fail;
		}
		VERIFY3U(virtio_dma_ncookies(tb->tb_dma), ==, 1);

		if ((tb->tb_chain = virtio_chain_alloc(vif->vif_tx_vq,
		    KM_SLEEP)) == NULL) {
			goto fail;
		}
		virtio_chain_data_set(tb->tb_chain, tb);

		tb->tb_dmaext_capacity = VIOIF_MAX_SEGS - 1;
		tb->tb_dmaext = kmem_zalloc(
		    sizeof (virtio_dma_t *) * tb->tb_dmaext_capacity,
		    KM_SLEEP);
	}

	/*
	 * The receive buffers are larger, and we can tolerate a large number
	 * of segments.  Adjust the SGL entry count, setting aside one segment
	 * for the virtio net header.
	 */
	attr.dma_attr_sgllen = VIOIF_MAX_SEGS - 1;

	for (vioif_rxbuf_t *rb = list_head(&vif->vif_rxbufs); rb != NULL;
	    rb = list_next(&vif->vif_rxbufs, rb)) {
		if ((rb->rb_dma = virtio_dma_alloc(vif->vif_virtio,
		    VIOIF_RX_BUF_SIZE, &attr, DDI_DMA_STREAMING | DDI_DMA_READ,
		    KM_SLEEP)) == NULL) {
			goto fail;
		}

		if ((rb->rb_chain = virtio_chain_alloc(vif->vif_rx_vq,
		    KM_SLEEP)) == NULL) {
			goto fail;
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

		rb->rb_vioif = vif;
		rb->rb_frtn.free_func = vioif_rx_free_callback;
		rb->rb_frtn.free_arg = (caddr_t)rb;
	}

	return (0);

fail:
	vioif_free_bufs(vif);
	return (ENOMEM);
}

static int
vioif_m_multicst(void *arg, boolean_t add, const uint8_t *mcst_addr)
{
	/*
	 * Even though we currently do not have support for programming
	 * multicast filters, or even enabling promiscuous mode, we return
	 * success here to avoid the networking stack falling back to link
	 * layer broadcast for multicast traffic.  Some hypervisors already
	 * pass received multicast frames onto the guest, so at least on those
	 * systems multicast will work as expected anyway.
	 */
	return (0);
}

static int
vioif_m_setpromisc(void *arg, boolean_t on)
{
	/*
	 * Even though we cannot currently enable promiscuous mode, we return
	 * success here to allow tools like snoop(1M) to continue to function.
	 */
	return (0);
}

static int
vioif_m_unicst(void *arg, const uint8_t *mac)
{
	return (ENOTSUP);
}

static uint_t
vioif_add_rx(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	if (vif->vif_runstate != VIOIF_RUNSTATE_RUNNING) {
		/*
		 * If the NIC is not running, do not give the device any
		 * receive buffers.
		 */
		return (0);
	}

	uint_t num_added = 0;

	vioif_rxbuf_t *rb;
	while ((rb = vioif_rxbuf_alloc(vif)) != NULL) {
		/*
		 * For legacy devices, and those that have not negotiated
		 * VIRTIO_F_ANY_LAYOUT, the virtio net header must appear in a
		 * separate descriptor entry to the rest of the buffer.
		 */
		if (virtio_chain_append(rb->rb_chain,
		    virtio_dma_cookie_pa(rb->rb_dma, 0),
		    sizeof (struct virtio_net_hdr),
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
		vioif_rxbuf_free(vif, rb);
		vif->vif_norecvbuf++;
		break;
	}

	if (num_added > 0) {
		virtio_queue_flush(vif->vif_rx_vq);
	}

	return (num_added);
}

static uint_t
vioif_process_rx(vioif_t *vif)
{
	virtio_chain_t *vic;
	mblk_t *mphead = NULL, *lastmp = NULL, *mp;
	uint_t num_processed = 0;

	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	while ((vic = virtio_queue_poll(vif->vif_rx_vq)) != NULL) {
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
		 * If the NIC is not running, discard any received frames.
		 */
		if (vif->vif_runstate != VIOIF_RUNSTATE_RUNNING) {
			vioif_rxbuf_free(vif, rb);
			continue;
		}

		if (len < sizeof (struct virtio_net_hdr)) {
			vif->vif_rxfail_chain_undersize++;
			vif->vif_ierrors++;
			vioif_rxbuf_free(vif, rb);
			continue;
		}
		len -= sizeof (struct virtio_net_hdr);

		/*
		 * We copy small packets that happen to fit into a single
		 * cookie and reuse the buffers. For bigger ones, we loan
		 * the buffers upstream.
		 */
		if (len < vif->vif_rxcopy_thresh ||
		    vif->vif_nrxbufs_onloan >= vif->vif_nrxbufs_onloan_max) {
			mutex_exit(&vif->vif_mutex);
			if ((mp = allocb(len, 0)) == NULL) {
				mutex_enter(&vif->vif_mutex);
				vif->vif_norecvbuf++;
				vif->vif_ierrors++;

				vioif_rxbuf_free(vif, rb);
				continue;
			}

			bcopy(virtio_dma_va(rb->rb_dma, VIOIF_HEADER_SKIP),
			    mp->b_rptr, len);
			mp->b_wptr = mp->b_rptr + len;

			/*
			 * As the packet contents was copied rather than
			 * loaned, we can return the receive buffer resources
			 * to the free list.
			 */
			mutex_enter(&vif->vif_mutex);
			vioif_rxbuf_free(vif, rb);

		} else {
			mutex_exit(&vif->vif_mutex);
			if ((mp = desballoc(virtio_dma_va(rb->rb_dma,
			    VIOIF_HEADER_SKIP), len, 0,
			    &rb->rb_frtn)) == NULL) {
				mutex_enter(&vif->vif_mutex);
				vif->vif_norecvbuf++;
				vif->vif_ierrors++;

				vioif_rxbuf_free(vif, rb);
				continue;
			}
			mp->b_wptr = mp->b_rptr + len;

			mutex_enter(&vif->vif_mutex);
			vif->vif_nrxbufs_onloan++;
		}

		/*
		 * virtio-net does not tell us if this packet is multicast
		 * or broadcast, so we have to check it.
		 */
		if (mp->b_rptr[0] & 0x1) {
			if (bcmp(mp->b_rptr, vioif_broadcast, ETHERADDRL) != 0)
				vif->vif_multircv++;
			else
				vif->vif_brdcstrcv++;
		}

		vif->vif_rbytes += len;
		vif->vif_ipackets++;

		if (lastmp == NULL) {
			mphead = mp;
		} else {
			lastmp->b_next = mp;
		}
		lastmp = mp;
		num_processed++;
	}

	if (mphead != NULL) {
		if (vif->vif_runstate == VIOIF_RUNSTATE_RUNNING) {
			mutex_exit(&vif->vif_mutex);
			mac_rx(vif->vif_mac_handle, NULL, mphead);
			mutex_enter(&vif->vif_mutex);
		} else {
			/*
			 * The NIC was disabled part way through our execution,
			 * so free the messages we allocated.
			 */
			freemsgchain(mphead);
		}
	}

	return (num_processed);
}

static uint_t
vioif_reclaim_used_tx(vioif_t *vif)
{
	virtio_chain_t *vic;
	uint_t num_reclaimed = 0;

	VERIFY(MUTEX_NOT_HELD(&vif->vif_mutex));

	while ((vic = virtio_queue_poll(vif->vif_tx_vq)) != NULL) {
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
		mutex_enter(&vif->vif_mutex);
		vioif_txbuf_free(vif, tb);
		mutex_exit(&vif->vif_mutex);

		num_reclaimed++;
	}

	/* Return ring to transmitting state if descriptors were reclaimed. */
	if (num_reclaimed > 0) {
		boolean_t do_update = B_FALSE;

		mutex_enter(&vif->vif_mutex);
		vif->vif_stat_tx_reclaim += num_reclaimed;
		if (vif->vif_tx_corked) {
			/*
			 * TX was corked on a lack of available descriptors.
			 * That dire state has passed so the TX interrupt can
			 * be disabled and MAC can be notified that
			 * transmission is possible again.
			 */
			vif->vif_tx_corked = B_FALSE;
			virtio_queue_no_interrupt(vif->vif_tx_vq, B_TRUE);
			do_update = B_TRUE;
		}

		if (do_update) {
			mac_tx_update(vif->vif_mac_handle);
		}
		mutex_exit(&vif->vif_mutex);
	}

	return (num_reclaimed);
}

static void
vioif_reclaim_periodic(void *arg)
{
	vioif_t *vif = arg;
	uint_t num_reclaimed;

	num_reclaimed = vioif_reclaim_used_tx(vif);

	mutex_enter(&vif->vif_mutex);
	vif->vif_tx_reclaim_tid = 0;
	/*
	 * If used descriptors were reclaimed or TX descriptors appear to be
	 * outstanding, the ring is considered active and periodic reclamation
	 * is necessary for now.
	 */
	if (num_reclaimed != 0 || virtio_queue_nactive(vif->vif_tx_vq) != 0) {
		/* Do not reschedule if the ring is being drained. */
		if (!vif->vif_tx_drain) {
			vioif_reclaim_restart(vif);
		}
	}
	mutex_exit(&vif->vif_mutex);
}

static void
vioif_reclaim_restart(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));
	VERIFY(!vif->vif_tx_drain);

	if (vif->vif_tx_reclaim_tid == 0) {
		vif->vif_tx_reclaim_tid = timeout(vioif_reclaim_periodic, vif,
		    MSEC_TO_TICK_ROUNDUP(vioif_reclaim_ms));
	}
}

static void
vioif_tx_drain(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));
	VERIFY3S(vif->vif_runstate, ==, VIOIF_RUNSTATE_STOPPING);

	vif->vif_tx_drain = B_TRUE;
	/* Put a stop to the periodic reclaim if it is running */
	if (vif->vif_tx_reclaim_tid != 0) {
		timeout_id_t tid = vif->vif_tx_reclaim_tid;

		/*
		 * With vif_tx_drain set, there is no risk that a racing
		 * vioif_reclaim_periodic() call will reschedule itself.
		 *
		 * Being part of the mc_stop hook also guarantees that
		 * vioif_m_tx() will not be called to restart it.
		 */
		vif->vif_tx_reclaim_tid = 0;
		mutex_exit(&vif->vif_mutex);
		(void) untimeout(tid);
		mutex_enter(&vif->vif_mutex);
	}
	virtio_queue_no_interrupt(vif->vif_tx_vq, B_TRUE);

	/*
	 * Wait for all of the TX descriptors to be processed by the host so
	 * they can be reclaimed.
	 */
	while (vif->vif_ntxbufs_alloc > 0) {
		mutex_exit(&vif->vif_mutex);
		(void) vioif_reclaim_used_tx(vif);
		delay(5);
		mutex_enter(&vif->vif_mutex);
	}
	VERIFY(!vif->vif_tx_corked);
	VERIFY3U(vif->vif_tx_reclaim_tid, ==, 0);
	VERIFY3U(virtio_queue_nactive(vif->vif_tx_vq), ==, 0);
}

static int
vioif_tx_inline(vioif_t *vif, vioif_txbuf_t *tb, mblk_t *mp, size_t msg_size)
{
	VERIFY(MUTEX_NOT_HELD(&vif->vif_mutex));

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

static int
vioif_tx_external(vioif_t *vif, vioif_txbuf_t *tb, mblk_t *mp, size_t msg_size)
{
	VERIFY(MUTEX_NOT_HELD(&vif->vif_mutex));

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
			mutex_enter(&vif->vif_mutex);
			vif->vif_txfail_indirect_limit++;
			vif->vif_notxbuf++;
			mutex_exit(&vif->vif_mutex);
			goto fail;
		}

		if (tb->tb_dmaext[tb->tb_ndmaext] == NULL) {
			/*
			 * Allocate a DMA handle for this slot.
			 */
			if ((tb->tb_dmaext[tb->tb_ndmaext] =
			    virtio_dma_alloc_nomem(vif->vif_virtio,
			    &vioif_dma_attr_external, KM_SLEEP)) == NULL) {
				mutex_enter(&vif->vif_mutex);
				vif->vif_notxbuf++;
				mutex_exit(&vif->vif_mutex);
				goto fail;
			}
		}
		virtio_dma_t *extdma = tb->tb_dmaext[tb->tb_ndmaext++];

		if (virtio_dma_bind(extdma, nmp->b_rptr, len,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, KM_SLEEP) !=
		    DDI_SUCCESS) {
			mutex_enter(&vif->vif_mutex);
			vif->vif_txfail_dma_bind++;
			mutex_exit(&vif->vif_mutex);
			goto fail;
		}

		for (uint_t n = 0; n < virtio_dma_ncookies(extdma); n++) {
			uint64_t pa = virtio_dma_cookie_pa(extdma, n);
			size_t sz = virtio_dma_cookie_size(extdma, n);

			if (virtio_chain_append(tb->tb_chain, pa, sz,
			    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
				mutex_enter(&vif->vif_mutex);
				vif->vif_txfail_indirect_limit++;
				vif->vif_notxbuf++;
				mutex_exit(&vif->vif_mutex);
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

	return (DDI_SUCCESS);

fail:
	for (uint_t n = 0; n < tb->tb_ndmaext; n++) {
		if (tb->tb_dmaext[n] != NULL) {
			virtio_dma_unbind(tb->tb_dmaext[n]);
		}
	}
	tb->tb_ndmaext = 0;

	freemsg(mp);

	return (DDI_FAILURE);
}

static boolean_t
vioif_send(vioif_t *vif, mblk_t *mp)
{
	VERIFY(MUTEX_NOT_HELD(&vif->vif_mutex));

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

	if (vif->vif_tx_tso4) {
		mac_lso_get(mp, &lso_mss, &lso_flags);
		lso_required = (lso_flags & HW_LSO) != 0;
	}

	mutex_enter(&vif->vif_mutex);
	if ((tb = vioif_txbuf_alloc(vif)) == NULL) {
		vif->vif_notxbuf++;
		goto fail;
	}
	mutex_exit(&vif->vif_mutex);

	/*
	 * Use the inline buffer for the virtio net header.  Zero the portion
	 * of our DMA allocation prior to the packet data.
	 */
	vnh = virtio_dma_va(tb->tb_dma, 0);
	bzero(vnh, VIOIF_HEADER_SKIP);

	/*
	 * For legacy devices, and those that have not negotiated
	 * VIRTIO_F_ANY_LAYOUT, the virtio net header must appear in a separate
	 * descriptor entry to the rest of the buffer.
	 */
	if (virtio_chain_append(tb->tb_chain,
	    virtio_dma_cookie_pa(tb->tb_dma, 0), sizeof (struct virtio_net_hdr),
	    VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		mutex_enter(&vif->vif_mutex);
		vif->vif_notxbuf++;
		goto fail;
	}

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
		vnh->vnh_gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		vnh->vnh_gso_size = (uint16_t)lso_mss;
	}

	/*
	 * The device does not maintain its own statistics about broadcast or
	 * multicast packets, so we have to check the destination address
	 * ourselves.
	 */
	if ((ether->ether_dhost.ether_addr_octet[0] & 0x01) != 0) {
		mutex_enter(&vif->vif_mutex);
		if (ether_cmp(&ether->ether_dhost, vioif_broadcast) == 0) {
			vif->vif_brdcstxmt++;
		} else {
			vif->vif_multixmt++;
		}
		mutex_exit(&vif->vif_mutex);
	}

	/*
	 * For small packets, copy into the preallocated inline buffer rather
	 * than incur the overhead of mapping.  Note that both of these
	 * functions ensure that "mp" is freed before returning.
	 */
	if (msg_size < vif->vif_txcopy_thresh) {
		ret = vioif_tx_inline(vif, tb, mp, msg_size);
	} else {
		ret = vioif_tx_external(vif, tb, mp, msg_size);
	}
	mp = NULL;

	mutex_enter(&vif->vif_mutex);

	if (ret != DDI_SUCCESS) {
		goto fail;
	}

	vif->vif_opackets++;
	vif->vif_obytes += msg_size;
	mutex_exit(&vif->vif_mutex);

	virtio_dma_sync(tb->tb_dma, DDI_DMA_SYNC_FORDEV);
	virtio_chain_submit(tb->tb_chain, B_TRUE);

	return (B_TRUE);

fail:
	vif->vif_oerrors++;
	if (tb != NULL) {
		vioif_txbuf_free(vif, tb);
	}
	mutex_exit(&vif->vif_mutex);

	return (mp == NULL);
}

static mblk_t *
vioif_m_tx(void *arg, mblk_t *mp)
{
	vioif_t *vif = arg;
	mblk_t *nmp;

	/*
	 * Prior to attempting to send any more frames, do a reclaim to pick up
	 * any descriptors which have been processed by the host.
	 */
	if (virtio_queue_nactive(vif->vif_tx_vq) != 0) {
		(void) vioif_reclaim_used_tx(vif);
	}

	while (mp != NULL) {
		nmp = mp->b_next;
		mp->b_next = NULL;

		if (!vioif_send(vif, mp)) {
			/*
			 * If there are no descriptors available, try to
			 * reclaim some, allowing a retry of the send if some
			 * are found.
			 */
			mp->b_next = nmp;
			if (vioif_reclaim_used_tx(vif) != 0) {
				continue;
			}

			/*
			 * Otherwise, enable the TX ring interrupt so that as
			 * soon as a descriptor becomes available, transmission
			 * can begin again.  For safety, make sure the periodic
			 * reclaim is running as well.
			 */
			mutex_enter(&vif->vif_mutex);
			vif->vif_tx_corked = B_TRUE;
			virtio_queue_no_interrupt(vif->vif_tx_vq, B_FALSE);
			vioif_reclaim_restart(vif);
			mutex_exit(&vif->vif_mutex);
			return (mp);
		}
		mp = nmp;
	}

	/* Ensure the periodic reclaim has been started. */
	mutex_enter(&vif->vif_mutex);
	vioif_reclaim_restart(vif);
	mutex_exit(&vif->vif_mutex);

	return (NULL);
}

static int
vioif_m_start(void *arg)
{
	vioif_t *vif = arg;

	mutex_enter(&vif->vif_mutex);

	VERIFY3S(vif->vif_runstate, ==, VIOIF_RUNSTATE_STOPPED);
	vif->vif_runstate = VIOIF_RUNSTATE_RUNNING;

	mac_link_update(vif->vif_mac_handle, LINK_STATE_UP);

	virtio_queue_no_interrupt(vif->vif_rx_vq, B_FALSE);

	/*
	 * Starting interrupts on the TX virtqueue is unnecessary at this time.
	 * Descriptor reclamation is handling during transmit, via a periodic
	 * timer, and when resources are tight, via the then-enabled interrupt.
	 */
	vif->vif_tx_drain = B_FALSE;

	/*
	 * Add as many receive buffers as we can to the receive queue.  If we
	 * cannot add any, it may be because we have stopped and started again
	 * and the descriptors are all in the queue already.
	 */
	(void) vioif_add_rx(vif);

	mutex_exit(&vif->vif_mutex);
	return (DDI_SUCCESS);
}

static void
vioif_m_stop(void *arg)
{
	vioif_t *vif = arg;

	mutex_enter(&vif->vif_mutex);

	VERIFY3S(vif->vif_runstate, ==, VIOIF_RUNSTATE_RUNNING);
	vif->vif_runstate = VIOIF_RUNSTATE_STOPPING;

	/* Ensure all TX descriptors have been processed and reclaimed */
	vioif_tx_drain(vif);

	virtio_queue_no_interrupt(vif->vif_rx_vq, B_TRUE);

	vif->vif_runstate = VIOIF_RUNSTATE_STOPPED;
	mutex_exit(&vif->vif_mutex);
}

static int
vioif_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	vioif_t *vif = arg;

	switch (stat) {
	case MAC_STAT_IERRORS:
		*val = vif->vif_ierrors;
		break;
	case MAC_STAT_OERRORS:
		*val = vif->vif_oerrors;
		break;
	case MAC_STAT_MULTIRCV:
		*val = vif->vif_multircv;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = vif->vif_brdcstrcv;
		break;
	case MAC_STAT_MULTIXMT:
		*val = vif->vif_multixmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = vif->vif_brdcstxmt;
		break;
	case MAC_STAT_IPACKETS:
		*val = vif->vif_ipackets;
		break;
	case MAC_STAT_RBYTES:
		*val = vif->vif_rbytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = vif->vif_opackets;
		break;
	case MAC_STAT_OBYTES:
		*val = vif->vif_obytes;
		break;
	case MAC_STAT_NORCVBUF:
		*val = vif->vif_norecvbuf;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = vif->vif_notxbuf;
		break;
	case MAC_STAT_IFSPEED:
		/* always 1 Gbit */
		*val = 1000000000ULL;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		/* virtual device, always full-duplex */
		*val = LINK_DUPLEX_FULL;
		break;

	default:
		return (ENOTSUP);
	}

	return (DDI_SUCCESS);
}

static int
vioif_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	vioif_t *vif = arg;

	switch (pr_num) {
	case MAC_PROP_MTU: {
		int r;
		uint32_t mtu;
		if (pr_valsize < sizeof (mtu)) {
			return (EOVERFLOW);
		}
		bcopy(pr_val, &mtu, sizeof (mtu));

		if (mtu < ETHERMIN || mtu > vif->vif_mtu_max) {
			return (EINVAL);
		}

		mutex_enter(&vif->vif_mutex);
		if ((r = mac_maxsdu_update(vif->vif_mac_handle, mtu)) == 0) {
			vif->vif_mtu = mtu;
		}
		mutex_exit(&vif->vif_mutex);

		return (r);
	}

	case MAC_PROP_PRIVATE: {
		long max, result;
		uint_t *resp;
		char *endptr;

		if (strcmp(pr_name, VIOIF_MACPROP_TXCOPY_THRESH) == 0) {
			max = VIOIF_MACPROP_TXCOPY_THRESH_MAX;
			resp = &vif->vif_txcopy_thresh;
		} else if (strcmp(pr_name, VIOIF_MACPROP_RXCOPY_THRESH) == 0) {
			max = VIOIF_MACPROP_RXCOPY_THRESH_MAX;
			resp = &vif->vif_rxcopy_thresh;
		} else {
			return (ENOTSUP);
		}

		if (pr_val == NULL) {
			return (EINVAL);
		}

		if (ddi_strtol(pr_val, &endptr, 10, &result) != 0 ||
		    *endptr != '\0' || result < 0 || result > max) {
			return (EINVAL);
		}

		mutex_enter(&vif->vif_mutex);
		*resp = result;
		mutex_exit(&vif->vif_mutex);

		return (0);
	}

	default:
		return (ENOTSUP);
	}
}

static int
vioif_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	vioif_t *vif = arg;

	switch (pr_num) {
	case MAC_PROP_PRIVATE: {
		uint_t value;

		if (strcmp(pr_name, VIOIF_MACPROP_TXCOPY_THRESH) == 0) {
			value = vif->vif_txcopy_thresh;
		} else if (strcmp(pr_name, VIOIF_MACPROP_RXCOPY_THRESH) == 0) {
			value = vif->vif_rxcopy_thresh;
		} else {
			return (ENOTSUP);
		}

		if (snprintf(pr_val, pr_valsize, "%u", value) >= pr_valsize) {
			return (EOVERFLOW);
		}

		return (0);
	}

	default:
		return (ENOTSUP);
	}
}

static void
vioif_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	vioif_t *vif = arg;
	char valstr[64];
	int value;

	switch (pr_num) {
	case MAC_PROP_MTU:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prh, ETHERMIN, vif->vif_mtu_max);
		return;

	case MAC_PROP_PRIVATE:
		if (strcmp(pr_name, VIOIF_MACPROP_TXCOPY_THRESH) == 0) {
			value = VIOIF_MACPROP_TXCOPY_THRESH_DEF;
		} else if (strcmp(pr_name, VIOIF_MACPROP_RXCOPY_THRESH) == 0) {
			value = VIOIF_MACPROP_RXCOPY_THRESH_DEF;
		} else {
			/*
			 * We do not recognise this private property name.
			 */
			return;
		}
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		(void) snprintf(valstr, sizeof (valstr), "%d", value);
		mac_prop_info_set_default_str(prh, valstr);
		return;

	default:
		return;
	}
}

static boolean_t
vioif_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	vioif_t *vif = arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		if (!vif->vif_tx_csum) {
			return (B_FALSE);
		}

		*(uint32_t *)cap_data = HCKSUM_INET_PARTIAL;

		return (B_TRUE);
	}

	case MAC_CAPAB_LSO: {
		if (!vif->vif_tx_tso4) {
			return (B_FALSE);
		}

		mac_capab_lso_t *lso = cap_data;
		lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		lso->lso_basic_tcp_ipv4.lso_max = VIOIF_RX_DATA_SIZE;

		return (B_TRUE);
	}

	default:
		return (B_FALSE);
	}
}

static boolean_t
vioif_has_feature(vioif_t *vif, uint32_t feature)
{
	return (virtio_feature_present(vif->vif_virtio, feature));
}

/*
 * Read the primary MAC address from the device if one is provided.  If not,
 * generate a random locally administered MAC address and write it back to the
 * device.
 */
static void
vioif_get_mac(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	if (vioif_has_feature(vif, VIRTIO_NET_F_MAC)) {
		for (uint_t i = 0; i < ETHERADDRL; i++) {
			vif->vif_mac[i] = virtio_dev_get8(vif->vif_virtio,
			    VIRTIO_NET_CONFIG_MAC + i);
		}
		vif->vif_mac_from_host = 1;

		return;
	}

	/* Get a few random bytes */
	(void) random_get_pseudo_bytes(vif->vif_mac, ETHERADDRL);
	/* Make sure it's a unicast MAC */
	vif->vif_mac[0] &= ~1;
	/* Set the "locally administered" bit */
	vif->vif_mac[1] |= 2;

	/*
	 * Write the random MAC address back to the device.
	 */
	for (uint_t i = 0; i < ETHERADDRL; i++) {
		virtio_dev_put8(vif->vif_virtio, VIRTIO_NET_CONFIG_MAC + i,
		    vif->vif_mac[i]);
	}
	vif->vif_mac_from_host = 0;

	dev_err(vif->vif_dip, CE_NOTE, "!Generated a random MAC address: "
	    "%02x:%02x:%02x:%02x:%02x:%02x",
	    (uint_t)vif->vif_mac[0], (uint_t)vif->vif_mac[1],
	    (uint_t)vif->vif_mac[2], (uint_t)vif->vif_mac[3],
	    (uint_t)vif->vif_mac[4], (uint_t)vif->vif_mac[5]);
}

/*
 * Virtqueue interrupt handlers
 */
static uint_t
vioif_rx_handler(caddr_t arg0, caddr_t arg1)
{
	vioif_t *vif = (vioif_t *)arg0;

	mutex_enter(&vif->vif_mutex);
	(void) vioif_process_rx(vif);

	/*
	 * Attempt to replenish the receive queue.  If we cannot add any
	 * descriptors here, it may be because all of the recently received
	 * packets were loaned up to the networking stack.
	 */
	(void) vioif_add_rx(vif);
	mutex_exit(&vif->vif_mutex);

	return (DDI_INTR_CLAIMED);
}

static uint_t
vioif_tx_handler(caddr_t arg0, caddr_t arg1)
{
	vioif_t *vif = (vioif_t *)arg0;

	/*
	 * The TX interrupt could race with other reclamation activity, so
	 * interpreting the return value is unimportant.
	 */
	(void) vioif_reclaim_used_tx(vif);

	return (DDI_INTR_CLAIMED);
}

static void
vioif_check_features(vioif_t *vif)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	vif->vif_tx_csum = 0;
	vif->vif_tx_tso4 = 0;

	if (vioif_has_feature(vif, VIRTIO_NET_F_CSUM)) {
		/*
		 * The host will accept packets with partial checksums from us.
		 */
		vif->vif_tx_csum = 1;

		/*
		 * The legacy GSO feature represents the combination of
		 * HOST_TSO4, HOST_TSO6, and HOST_ECN.
		 */
		boolean_t gso = vioif_has_feature(vif, VIRTIO_NET_F_GSO);
		boolean_t tso4 = vioif_has_feature(vif, VIRTIO_NET_F_HOST_TSO4);
		boolean_t ecn = vioif_has_feature(vif, VIRTIO_NET_F_HOST_ECN);

		/*
		 * Explicit congestion notification (ECN) is configured
		 * globally; see "tcp_ecn_permitted".  As we cannot currently
		 * request that the stack disable ECN on a per interface basis,
		 * we require the device to support the combination of
		 * segmentation offload and ECN support.
		 */
		if (gso || (tso4 && ecn)) {
			vif->vif_tx_tso4 = 1;
		}
	}
}

static int
vioif_select_interrupt_types(void)
{
	id_t id;
	smbios_system_t sys;
	smbios_info_t info;

	if (vioif_allowed_int_types != -1) {
		/*
		 * If this value was tuned via /etc/system or the debugger,
		 * use the provided value directly.
		 */
		return (vioif_allowed_int_types);
	}

	if ((id = smbios_info_system(ksmbios, &sys)) == SMB_ERR ||
	    smbios_info_common(ksmbios, id, &info) == SMB_ERR) {
		/*
		 * The system may not have valid SMBIOS data, so ignore a
		 * failure here.
		 */
		return (0);
	}

	if (strcmp(info.smbi_manufacturer, "Google") == 0 &&
	    strcmp(info.smbi_product, "Google Compute Engine") == 0) {
		/*
		 * An undiagnosed issue with the Google Compute Engine (GCE)
		 * hypervisor exists.  In this environment, no RX interrupts
		 * are received if MSI-X handlers are installed.  This does not
		 * appear to be true for the Virtio SCSI driver.  Fixed
		 * interrupts do appear to work, so we fall back for now:
		 */
		return (DDI_INTR_TYPE_FIXED);
	}

	return (0);
}

static int
vioif_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	vioif_t *vif;
	virtio_t *vio;
	mac_register_t *macp = NULL;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if ((vio = virtio_init(dip, VIRTIO_NET_WANTED_FEATURES, B_TRUE)) ==
	    NULL) {
		return (DDI_FAILURE);
	}

	vif = kmem_zalloc(sizeof (*vif), KM_SLEEP);
	vif->vif_dip = dip;
	vif->vif_virtio = vio;
	vif->vif_runstate = VIOIF_RUNSTATE_STOPPED;
	ddi_set_driver_private(dip, vif);

	if ((vif->vif_rx_vq = virtio_queue_alloc(vio, VIRTIO_NET_VIRTQ_RX,
	    "rx", vioif_rx_handler, vif, B_FALSE, VIOIF_MAX_SEGS)) == NULL ||
	    (vif->vif_tx_vq = virtio_queue_alloc(vio, VIRTIO_NET_VIRTQ_TX,
	    "tx", vioif_tx_handler, vif, B_FALSE, VIOIF_MAX_SEGS)) == NULL) {
		goto fail;
	}

	if (virtio_init_complete(vio, vioif_select_interrupt_types()) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete Virtio init");
		goto fail;
	}

	virtio_queue_no_interrupt(vif->vif_rx_vq, B_TRUE);
	virtio_queue_no_interrupt(vif->vif_tx_vq, B_TRUE);

	mutex_init(&vif->vif_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	mutex_enter(&vif->vif_mutex);

	vioif_get_mac(vif);

	vif->vif_rxcopy_thresh = VIOIF_MACPROP_RXCOPY_THRESH_DEF;
	vif->vif_txcopy_thresh = VIOIF_MACPROP_TXCOPY_THRESH_DEF;

	if (vioif_has_feature(vif, VIRTIO_NET_F_MTU)) {
		vif->vif_mtu_max = virtio_dev_get16(vio, VIRTIO_NET_CONFIG_MTU);
	} else {
		vif->vif_mtu_max = ETHERMTU;
	}

	vif->vif_mtu = ETHERMTU;
	if (vif->vif_mtu > vif->vif_mtu_max) {
		vif->vif_mtu = vif->vif_mtu_max;
	}

	vioif_check_features(vif);

	if (vioif_alloc_bufs(vif) != 0) {
		mutex_exit(&vif->vif_mutex);
		dev_err(dip, CE_WARN, "failed to allocate memory");
		goto fail;
	}

	mutex_exit(&vif->vif_mutex);

	if (virtio_interrupts_enable(vio) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to enable interrupts");
		goto fail;
	}

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		dev_err(dip, CE_WARN, "failed to allocate a mac_register");
		goto fail;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = vif;
	macp->m_dip = dip;
	macp->m_src_addr = vif->vif_mac;
	macp->m_callbacks = &vioif_mac_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = vif->vif_mtu;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = vioif_priv_props;

	if ((ret = mac_register(macp, &vif->vif_mac_handle)) != 0) {
		dev_err(dip, CE_WARN, "mac_register() failed (%d)", ret);
		goto fail;
	}
	mac_free(macp);

	mac_link_update(vif->vif_mac_handle, LINK_STATE_UP);

	return (DDI_SUCCESS);

fail:
	vioif_free_bufs(vif);
	if (macp != NULL) {
		mac_free(macp);
	}
	(void) virtio_fini(vio, B_TRUE);
	kmem_free(vif, sizeof (*vif));
	return (DDI_FAILURE);
}

static int
vioif_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int r;
	vioif_t *vif;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if ((vif = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&vif->vif_mutex);
	if (vif->vif_runstate != VIOIF_RUNSTATE_STOPPED) {
		dev_err(dip, CE_WARN, "!NIC still running, cannot detach");
		mutex_exit(&vif->vif_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * There should be no outstanding transmit buffers once the NIC is
	 * completely stopped.
	 */
	VERIFY3U(vif->vif_ntxbufs_alloc, ==, 0);

	/*
	 * Though we cannot claw back all of the receive buffers until we reset
	 * the device, we must ensure all those loaned to MAC have been
	 * returned before calling mac_unregister().
	 */
	if (vif->vif_nrxbufs_onloan > 0) {
		dev_err(dip, CE_WARN, "!%u receive buffers still loaned, "
		    "cannot detach", vif->vif_nrxbufs_onloan);
		mutex_exit(&vif->vif_mutex);
		return (DDI_FAILURE);
	}

	if ((r = mac_unregister(vif->vif_mac_handle)) != 0) {
		dev_err(dip, CE_WARN, "!MAC unregister failed (%d)", r);
		return (DDI_FAILURE);
	}

	/*
	 * Shut down the device so that we can recover any previously
	 * submitted receive buffers.
	 */
	virtio_shutdown(vif->vif_virtio);
	for (;;) {
		virtio_chain_t *vic;

		if ((vic = virtio_queue_evacuate(vif->vif_rx_vq)) == NULL) {
			break;
		}

		vioif_rxbuf_t *rb = virtio_chain_data(vic);
		vioif_rxbuf_free(vif, rb);
	}

	/*
	 * vioif_free_bufs() must be called before virtio_fini()
	 * as it uses virtio_chain_free() which itself depends on some
	 * virtio data structures still being around.
	 */
	vioif_free_bufs(vif);
	(void) virtio_fini(vif->vif_virtio, B_FALSE);

	mutex_exit(&vif->vif_mutex);
	mutex_destroy(&vif->vif_mutex);

	kmem_free(vif, sizeof (*vif));

	return (DDI_SUCCESS);
}

static int
vioif_quiesce(dev_info_t *dip)
{
	vioif_t *vif;

	if ((vif = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	return (virtio_quiesce(vif->vif_virtio));
}

int
_init(void)
{
	int ret;

	mac_init_ops(&vioif_dev_ops, "vioif");

	if ((ret = mod_install(&vioif_modlinkage)) != DDI_SUCCESS) {
		mac_fini_ops(&vioif_dev_ops);
	}

	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&vioif_modlinkage)) == DDI_SUCCESS) {
		mac_fini_ops(&vioif_dev_ops);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vioif_modlinkage, modinfop));
}
