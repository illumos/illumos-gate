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
#include <inet/tcp.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#include "virtio.h"
#include "vioif.h"

/*
 * While most hypervisors support the control queue, older versions of bhyve
 * on illumos did not. To allow the historic behaviour of the illumos vioif
 * driver, the following tuneable causes us to pretend that the request always
 * succeeds if the underlying virtual device does not have support.
 */
int vioif_fake_promisc_success = 1;

static int vioif_quiesce(dev_info_t *);
static int vioif_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioif_detach(dev_info_t *, ddi_detach_cmd_t);
static boolean_t vioif_has_feature(vioif_t *, uint64_t);
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
static void vioif_get_data(vioif_t *);


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

static vioif_ctrlbuf_t *
vioif_ctrlbuf_alloc(vioif_t *vif)
{
	vioif_ctrlbuf_t *cb;

	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	if ((cb = list_remove_head(&vif->vif_ctrlbufs)) != NULL) {
		vif->vif_nctrlbufs_alloc++;
	}

	return (cb);
}

static void
vioif_ctrlbuf_free(vioif_t *vif, vioif_ctrlbuf_t *cb)
{
	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	VERIFY3U(vif->vif_nctrlbufs_alloc, >, 0);
	vif->vif_nctrlbufs_alloc--;

	virtio_chain_clear(cb->cb_chain);
	list_insert_head(&vif->vif_ctrlbufs, cb);
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

	if (vif->vif_has_ctrlq) {
		VERIFY3U(vif->vif_nctrlbufs_alloc, ==, 0);
		for (uint_t i = 0; i < vif->vif_ctrlbufs_capacity; i++) {
			vioif_ctrlbuf_t *cb = &vif->vif_ctrlbufs_mem[i];

			/*
			 * Ensure that this ctrlbuf is now in the free list
			 */
			VERIFY(list_link_active(&cb->cb_link));
			list_remove(&vif->vif_ctrlbufs, cb);

			if (cb->cb_dma != NULL) {
				virtio_dma_free(cb->cb_dma);
				cb->cb_dma = NULL;
			}

			if (cb->cb_chain != NULL) {
				virtio_chain_free(cb->cb_chain);
				cb->cb_chain = NULL;
			}
		}
		VERIFY(list_is_empty(&vif->vif_ctrlbufs));
		if (vif->vif_ctrlbufs_mem != NULL) {
			kmem_free(vif->vif_ctrlbufs_mem,
			    sizeof (vioif_ctrlbuf_t) *
			    vif->vif_ctrlbufs_capacity);
			vif->vif_ctrlbufs_mem = NULL;
			vif->vif_ctrlbufs_capacity = 0;
		}
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

	if (vif->vif_has_ctrlq) {
		vif->vif_ctrlbufs_capacity = MIN(VIRTIO_NET_CTRL_BUFS,
		    virtio_queue_size(vif->vif_ctrl_vq));
		vif->vif_ctrlbufs_mem = kmem_zalloc(
		    sizeof (vioif_ctrlbuf_t) * vif->vif_ctrlbufs_capacity,
		    KM_SLEEP);
	}
	list_create(&vif->vif_ctrlbufs, sizeof (vioif_ctrlbuf_t),
	    offsetof(vioif_ctrlbuf_t, cb_link));

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
	for (uint_t i = 0; i < vif->vif_ctrlbufs_capacity; i++) {
		list_insert_tail(&vif->vif_ctrlbufs, &vif->vif_ctrlbufs_mem[i]);
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
	 * Control queue buffers are also small (less than a page), so we'll
	 * also request a single cookie for them.
	 */
	for (vioif_ctrlbuf_t *cb = list_head(&vif->vif_ctrlbufs); cb != NULL;
	    cb = list_next(&vif->vif_ctrlbufs, cb)) {
		if ((cb->cb_dma = virtio_dma_alloc(vif->vif_virtio,
		    VIOIF_CTRL_SIZE, &attr,
		    DDI_DMA_STREAMING | DDI_DMA_RDWR, KM_SLEEP)) == NULL) {
			goto fail;
		}
		VERIFY3U(virtio_dma_ncookies(cb->cb_dma), ==, 1);

		if ((cb->cb_chain = virtio_chain_alloc(vif->vif_ctrl_vq,
		    KM_SLEEP)) == NULL) {
			goto fail;
		}
		virtio_chain_data_set(cb->cb_chain, cb);
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
vioif_ctrlq_req(vioif_t *vif, uint8_t class, uint8_t cmd, void *data,
    size_t datalen)
{
	vioif_ctrlbuf_t *cb = NULL;
	virtio_chain_t *vic = NULL;
	uint8_t *p = NULL;
	uint64_t pa = 0;
	uint8_t *ackp = NULL;
	struct virtio_net_ctrlq_hdr hdr = {
		.vnch_class = class,
		.vnch_command = cmd,
	};
	const size_t hdrlen = sizeof (hdr);
	const size_t acklen = 1; /* the ack is always 1 byte */
	size_t totlen = hdrlen + datalen + acklen;
	int r = DDI_SUCCESS;

	/*
	 * We shouldn't be called unless the ctrlq feature has been
	 * negotiated with the host
	 */
	VERIFY(vif->vif_has_ctrlq);

	mutex_enter(&vif->vif_mutex);
	cb = vioif_ctrlbuf_alloc(vif);
	if (cb == NULL) {
		vif->vif_noctrlbuf++;
		mutex_exit(&vif->vif_mutex);
		r = DDI_FAILURE;
		goto done;
	}
	mutex_exit(&vif->vif_mutex);

	if (totlen > virtio_dma_size(cb->cb_dma)) {
		vif->vif_ctrlbuf_toosmall++;
		r = DDI_FAILURE;
		goto done;
	}

	/*
	 * Clear the entire buffer. Technically not necessary, but useful
	 * if trying to troubleshoot an issue, and probably not a bad idea
	 * to not let any old data linger.
	 */
	p = virtio_dma_va(cb->cb_dma, 0);
	bzero(p, virtio_dma_size(cb->cb_dma));

	/*
	 * We currently do not support VIRTIO_F_ANY_LAYOUT. That means,
	 * that we must put the header, the data, and the ack in their
	 * own respective descriptors. Since all the currently supported
	 * control queue commands take _very_ small amounts of data, we
	 * use a single DMA buffer for all of it, but use 3 descriptors to
	 * reference (respectively) the header, the data, and the ack byte
	 * within that memory to adhere to the virtio spec.
	 *
	 * If we add support for control queue features such as custom
	 * MAC filtering tables, which might require larger amounts of
	 * memory, we likely will want to add more sophistication here
	 * and optionally use additional allocated memory to hold that
	 * data instead of a fixed size buffer.
	 *
	 * Copy the header.
	 */
	bcopy(&hdr, p, sizeof (hdr));
	pa = virtio_dma_cookie_pa(cb->cb_dma, 0);
	if ((r = virtio_chain_append(cb->cb_chain,
	    pa, hdrlen, VIRTIO_DIR_DEVICE_READS)) != DDI_SUCCESS) {
		goto done;
	}

	/*
	 * Copy the request data
	 */
	p = virtio_dma_va(cb->cb_dma, hdrlen);
	bcopy(data, p, datalen);
	if ((r = virtio_chain_append(cb->cb_chain,
	    pa + hdrlen, datalen, VIRTIO_DIR_DEVICE_READS)) != DDI_SUCCESS) {
		goto done;
	}

	/*
	 * We already cleared the buffer, so don't need to copy out a 0 for
	 * the ack byte. Just add a descriptor for that spot.
	 */
	ackp = virtio_dma_va(cb->cb_dma, hdrlen + datalen);
	if ((r = virtio_chain_append(cb->cb_chain,
	    pa + hdrlen + datalen, acklen,
	    VIRTIO_DIR_DEVICE_WRITES)) != DDI_SUCCESS) {
		goto done;
	}

	virtio_dma_sync(cb->cb_dma, DDI_DMA_SYNC_FORDEV);
	virtio_chain_submit(cb->cb_chain, B_TRUE);

	/*
	 * Spin waiting for response.
	 */
	mutex_enter(&vif->vif_mutex);
	while ((vic = virtio_queue_poll(vif->vif_ctrl_vq)) == NULL) {
		mutex_exit(&vif->vif_mutex);
		delay(drv_usectohz(1000));
		mutex_enter(&vif->vif_mutex);
	}

	virtio_dma_sync(cb->cb_dma, DDI_DMA_SYNC_FORCPU);
	VERIFY3P(virtio_chain_data(vic), ==, cb);
	mutex_exit(&vif->vif_mutex);

	if (*ackp != VIRTIO_NET_CQ_OK) {
		r = DDI_FAILURE;
	}

done:
	mutex_enter(&vif->vif_mutex);
	vioif_ctrlbuf_free(vif, cb);
	mutex_exit(&vif->vif_mutex);

	return (r);
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
	vioif_t *vif = arg;
	uint8_t val = on ? 1 : 0;

	if (!vif->vif_has_ctrlq_rx) {
		if (vioif_fake_promisc_success)
			return (0);

		return (ENOTSUP);
	}

	return (vioif_ctrlq_req(vif, VIRTIO_NET_CTRL_RX,
	    VIRTIO_NET_CTRL_RX_PROMISC, &val, sizeof (val)));
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

		if (len < vif->vif_rxbuf_hdrlen) {
			vif->vif_rxfail_chain_undersize++;
			vif->vif_ierrors++;
			vioif_rxbuf_free(vif, rb);
			continue;
		}
		len -= vif->vif_rxbuf_hdrlen;

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

		mutex_exit(&vif->vif_mutex);
		if (do_update) {
			mac_tx_update(vif->vif_mac_handle);
		}
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

	if (vif->vif_tx_tso4 || vif->vif_tx_tso6) {
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

	/* We do not support VIRTIO_NET_F_MRG_RXBUF so always pass one buffer */
	if (vif->vif_rxbuf_hdrlen >
	    offsetof(struct virtio_net_hdr, vnh_num_buffers)) {
		vnh->vnh_num_buffers = 1;
	}

	/*
	 * For legacy devices, and those that have not negotiated
	 * VIRTIO_F_ANY_LAYOUT, the virtio net header must appear in a separate
	 * descriptor entry to the rest of the buffer. We do that for modern
	 * devices too.
	 */
	if (virtio_chain_append(tb->tb_chain,
	    virtio_dma_cookie_pa(tb->tb_dma, 0), vif->vif_rxbuf_hdrlen,
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
		mac_ether_offload_flags_t needed;
		mac_ether_offload_info_t meo;
		uint32_t cksum;
		size_t len;
		mblk_t *pullmp = NULL;
		tcpha_t *tcpha;

		mac_ether_offload_info(mp, &meo);
		needed = MEOI_L2INFO_SET | MEOI_L3INFO_SET | MEOI_L4INFO_SET;
		if ((meo.meoi_flags & needed) != needed) {
			goto fail;
		}

		if (meo.meoi_l4proto != IPPROTO_TCP) {
			goto fail;
		}

		if (meo.meoi_l3proto == ETHERTYPE_IP && vif->vif_tx_tso4) {
			vnh->vnh_gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		} else if (meo.meoi_l3proto == ETHERTYPE_IPV6 &&
		    vif->vif_tx_tso6) {
			vnh->vnh_gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		} else {
			goto fail;
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
		if (MBLKL(mp) < vnh->vnh_hdr_len) {
			pullmp = msgpullup(mp, vnh->vnh_hdr_len);
			if (pullmp == NULL)
				goto fail;
			tcpha = (tcpha_t *)(pullmp->b_rptr + meo.meoi_l2hlen +
			    meo.meoi_l3hlen);
		} else {
			tcpha = (tcpha_t *)(mp->b_rptr + meo.meoi_l2hlen +
			    meo.meoi_l3hlen);
		}

		len = meo.meoi_len - meo.meoi_l2hlen - meo.meoi_l3hlen;
		cksum = ntohs(tcpha->tha_sum) + len;
		cksum = (cksum >> 16) + (cksum & 0xffff);
		cksum = (cksum >> 16) + (cksum & 0xffff);
		tcpha->tha_sum = htons(cksum);

		if (tcpha->tha_flags & TH_CWR) {
			vnh->vnh_gso_type |= VIRTIO_NET_HDR_GSO_ECN;
		}
		vnh->vnh_gso_size = (uint16_t)lso_mss;
		vnh->vnh_hdr_len = meo.meoi_l2hlen + meo.meoi_l3hlen +
		    meo.meoi_l4hlen;

		freemsg(pullmp);
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

	vioif_get_data(vif);

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

static link_duplex_t
vioif_spec_to_duplex(uint8_t duplex)
{
	switch (duplex) {
	case VIRTIO_NET_CONFIG_DUPLEX_HALF:
		return (LINK_DUPLEX_HALF);
	case VIRTIO_NET_CONFIG_DUPLEX_FULL:
		return (LINK_DUPLEX_FULL);
	case VIRTIO_NET_CONFIG_DUPLEX_UNKNOWN:
	default:
		return (LINK_DUPLEX_UNKNOWN);
	}
}

static link_state_t
vioif_spec_to_state(uint16_t status)
{
	/* We don't have a way of mapping to LINK_STATE_UNKNOWN */
	return ((status & VIRTIO_NET_CONFIG_STATUS_LINK_UP) ?
	    LINK_STATE_UP : LINK_STATE_DOWN);
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
		if (vif->vif_speed == VIRTIO_NET_CONFIG_SPEED_UNKNOWN)
			*val = 1000000000ULL;	/* 1Gb/s */
		else
			*val = vif->vif_speed * 1000000ULL;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = vioif_spec_to_duplex(vif->vif_duplex);
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
	case MAC_PROP_DUPLEX: {
		link_duplex_t duplex;

		if (pr_valsize < sizeof (link_duplex_t))
			return (EOVERFLOW);
		duplex = vioif_spec_to_duplex(vif->vif_duplex);
		bcopy(&duplex, pr_val, sizeof (link_duplex_t));
		break;
	}
	case MAC_PROP_SPEED: {
		uint64_t speed;

		if (pr_valsize < sizeof (uint64_t))
			return (EOVERFLOW);
		speed = (uint64_t)vif->vif_speed * 1000000ULL;
		bcopy(&speed, pr_val, sizeof (uint64_t));
		break;
	}
	case MAC_PROP_STATUS: {
		link_state_t state;

		if (pr_valsize < sizeof (link_state_t))
			return (EOVERFLOW);
		state = vioif_spec_to_state(vif->vif_status);
		bcopy(&state, pr_val, sizeof (link_state_t));
		break;
	}
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (uint32_t))
			return (EOVERFLOW);
		bcopy(&vif->vif_mtu, pr_val, sizeof (uint32_t));
		break;
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

		break;
	}

	default:
		return (ENOTSUP);
	}

	return (0);
}

static void
vioif_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	vioif_t *vif = arg;
	char valstr[64];
	int value;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_STATUS:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

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
		lso->lso_flags = LSO_TX_BASIC_TCP_IPV4 | LSO_TX_BASIC_TCP_IPV6;
		lso->lso_basic_tcp_ipv4.lso_max = VIOIF_RX_DATA_SIZE;
		lso->lso_basic_tcp_ipv6.lso_max = VIOIF_RX_DATA_SIZE;

		return (B_TRUE);
	}

	default:
		return (B_FALSE);
	}
}

static boolean_t
vioif_has_feature(vioif_t *vif, uint64_t feature)
{
	return (virtio_features_present(vif->vif_virtio, feature));
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
		uint8_t gen = virtio_dev_getgen(vif->vif_virtio);
		do {
			for (uint_t i = 0; i < ETHERADDRL; i++) {
				vif->vif_mac[i] =
				    virtio_dev_get8(vif->vif_virtio,
				    VIRTIO_NET_CONFIG_MAC + i);
			}
		} while (gen != virtio_dev_getgen(vif->vif_virtio));

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

static void
vioif_get_data(vioif_t *vif)
{
	link_state_t orig_state, new_state;

	VERIFY(MUTEX_HELD(&vif->vif_mutex));

	orig_state = vioif_spec_to_state(vif->vif_status);
	if (vioif_has_feature(vif, VIRTIO_NET_F_STATUS)) {
		vif->vif_status = virtio_dev_get16(vif->vif_virtio,
		    VIRTIO_NET_CONFIG_STATUS);
	} else {
		vif->vif_status = VIRTIO_NET_CONFIG_STATUS_LINK_UP;
	}
	new_state = vioif_spec_to_state(vif->vif_status);

	if (new_state == LINK_STATE_UP) {
		if (vioif_has_feature(vif, VIRTIO_NET_F_SPEED_DUPLEX)) {
			vif->vif_speed = virtio_dev_get32(vif->vif_virtio,
			    VIRTIO_NET_CONFIG_SPEED);
			vif->vif_duplex = virtio_dev_get8(vif->vif_virtio,
			    VIRTIO_NET_CONFIG_DUPLEX);
		} else {
			vif->vif_speed = VIRTIO_NET_CONFIG_SPEED_UNKNOWN;
			vif->vif_duplex = VIRTIO_NET_CONFIG_DUPLEX_FULL;
		}
	} else {
		vif->vif_speed = 0;
		vif->vif_duplex = VIRTIO_NET_CONFIG_DUPLEX_UNKNOWN;
	}

	/*
	 * The specification says that speed is valid from [0, INT32_MAX] with
	 * UINT32_MAX used as the unknown value. If we get anything else we map
	 * it to the unknown value.
	 */
	if (vif->vif_speed > INT32_MAX)
		vif->vif_speed = VIRTIO_NET_CONFIG_SPEED_UNKNOWN;

	if (orig_state != new_state)
		mac_link_update(vif->vif_mac_handle, new_state);
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
	vif->vif_tx_tso6 = 0;

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
		boolean_t tso6 = vioif_has_feature(vif, VIRTIO_NET_F_HOST_TSO6);
		boolean_t ecn = vioif_has_feature(vif, VIRTIO_NET_F_HOST_ECN);

		/*
		 * Explicit congestion notification (ECN) is configured
		 * globally; see "tcp_ecn_permitted".  As we cannot currently
		 * request that the stack disable ECN on a per interface basis,
		 * we require the device to support the combination of
		 * segmentation offload and ECN support.
		 */
		if (gso) {
			vif->vif_tx_tso4 = 1;
			vif->vif_tx_tso6 = 1;
		}
		if (tso4 && ecn) {
			vif->vif_tx_tso4 = 1;
		}
		if (tso6 && ecn) {
			vif->vif_tx_tso6 = 1;
		}
	}

	if (vioif_has_feature(vif, VIRTIO_NET_F_CTRL_VQ)) {
		vif->vif_has_ctrlq = 1;

		/*
		 * The VIRTIO_NET_F_CTRL_VQ feature must be enabled if there's
		 * any chance of the VIRTIO_NET_F_CTRL_RX being enabled.
		 */
		if (vioif_has_feature(vif, VIRTIO_NET_F_CTRL_RX))
			vif->vif_has_ctrlq_rx = 1;
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

	if (ksmbios == NULL ||
	    (id = smbios_info_system(ksmbios, &sys)) == SMB_ERR ||
	    smbios_info_common(ksmbios, id, &info) == SMB_ERR) {
		/*
		 * The system may not have valid SMBIOS data, so ignore a
		 * failure here.
		 */
		return (VIRTIO_ANY_INTR_TYPE);
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

	return (VIRTIO_ANY_INTR_TYPE);
}

static uint_t
vioif_cfgchange(caddr_t arg0, caddr_t arg1 __unused)
{
	vioif_t *vif = (vioif_t *)arg0;

	/*
	 * The configuration space of the device has changed in some way;
	 * refresh data.
	 */
	mutex_enter(&vif->vif_mutex);
	vioif_get_data(vif);
	mutex_exit(&vif->vif_mutex);

	return (DDI_INTR_CLAIMED);
}

static int
vioif_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	vioif_t *vif;
	virtio_t *vio;
	mac_register_t *macp = NULL;
	uint64_t features;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if ((vio = virtio_init(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	features = VIRTIO_NET_WANTED_FEATURES;
	if (virtio_modern(vio))
		features |= VIRTIO_NET_WANTED_FEATURES_MODERN;

	if (!virtio_init_features(vio, features, B_TRUE)) {
		virtio_fini(vio, B_TRUE);
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
		goto fail_virtio;
	}

	if (vioif_has_feature(vif, VIRTIO_NET_F_CTRL_VQ) &&
	    (vif->vif_ctrl_vq = virtio_queue_alloc(vio,
	    VIRTIO_NET_VIRTQ_CONTROL, "ctrlq", NULL, vif,
	    B_FALSE, VIOIF_MAX_SEGS)) == NULL) {
		goto fail_virtio;
	}

	virtio_register_cfgchange_handler(vio, vioif_cfgchange, vif);

	if (virtio_init_complete(vio, vioif_select_interrupt_types()) !=
	    DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete Virtio init");
		goto fail_virtio;
	}

	virtio_queue_no_interrupt(vif->vif_rx_vq, B_TRUE);
	virtio_queue_no_interrupt(vif->vif_tx_vq, B_TRUE);
	if (vif->vif_ctrl_vq != NULL)
		virtio_queue_no_interrupt(vif->vif_ctrl_vq, B_TRUE);

	mutex_init(&vif->vif_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	mutex_enter(&vif->vif_mutex);

	vioif_get_mac(vif);
	vif->vif_duplex = VIRTIO_NET_CONFIG_DUPLEX_UNKNOWN;
	vif->vif_speed = VIRTIO_NET_CONFIG_SPEED_UNKNOWN;

	vif->vif_rxcopy_thresh = VIOIF_MACPROP_RXCOPY_THRESH_DEF;
	vif->vif_txcopy_thresh = VIOIF_MACPROP_TXCOPY_THRESH_DEF;
	vif->vif_rxbuf_hdrlen = VIRTIO_NET_HDR_LEN(virtio_modern(vio));

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
		goto fail_virtio;
	}

	mutex_exit(&vif->vif_mutex);

	if (virtio_interrupts_enable(vio) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to enable interrupts");
		goto fail_bufs;
	}

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		dev_err(dip, CE_WARN, "failed to allocate a mac_register");
		goto fail_bufs;
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
		goto fail_mac;
	}
	mac_free(macp);

	mutex_enter(&vif->vif_mutex);
	vioif_get_data(vif);
	mutex_exit(&vif->vif_mutex);

	return (DDI_SUCCESS);

fail_mac:
	mac_free(macp);
fail_bufs:
	mutex_enter(&vif->vif_mutex);
	vioif_free_bufs(vif);
	mutex_exit(&vif->vif_mutex);
fail_virtio:
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
