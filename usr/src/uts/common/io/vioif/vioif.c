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
 * ---------------------
 *
 * The vioif driver provides support for the virtio network device, a
 * paravirtualised NIC offered by many hypervisors, including QEMU/KVM and
 * bhyve. The behaviour of the device and driver is described by the VirtIO
 * specification.
 *
 * The driver supports legacy, transitional and modern devices, binding to
 * the following PCI IDs:
 *
 *    o pci1af4,1	-- legacy and transitional devices
 *    o pci1af4,1000,p	-- transitional devices
 *    o pci1af4,1041,p	-- modern devices
 *
 * The machinery common to all virtio device types -- device discovery,
 * feature negotiation, virtqueue management, descriptor chains, DMA memory
 * and interrupt allocation -- is provided by the virtio framework; see the
 * theory statement in uts/common/io/virtio/virtio.h for a description of
 * that interface.
 *
 * ------------
 * Organisation
 * ------------
 *
 * The driver is split across the following files:
 *
 *  vioif.h		Device definitions from the specification, driver
 *			tuneables, and the per-instance (vioif_t) and
 *			per-queue (vioif_rxq_t, vioif_txq_t) structures.
 *
 *  vioif.c		Attach and detach, feature negotiation, control queue
 *			requests, and the device-level mac(9E) entrypoints.
 *
 *  vioif_rx.c		Receive buffer management and frame receipt, and the
 *			receive ring entrypoints provided to MAC.
 *
 *  vioif_tx.c		Transmit buffer management, frame transmission and
 *			descriptor reclamation, and the transmit ring
 *			entrypoints provided to MAC.
 *
 * -------------------------------
 * Virtqueues and multi-queue (MQ)
 * -------------------------------
 *
 * A virtio network device provides at least one pair of virtqueues: a
 * receive queue and a transmit queue. If the device offers VIRTIO_NET_F_MQ
 * we negotiate it, and may then use up to the number of pairs the device
 * reports in the "max_virtqueue_pairs" configuration field. The number of
 * pairs we use is the smallest of: the device maximum, the number of CPUs,
 * the "vioif_max_qpairs" tuneable, and the number of pairs for which MSI-X
 * vectors are available. Each virtqueue requires its own MSI-X vector, with
 * one more needed for configuration change notifications. If MSI-X is not
 * available we use a single pair serviced by a shared fixed interrupt.
 *
 * The device will not use any pair beyond the first until we send a
 * VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET command on the control queue, which we do
 * during attach. If that request fails we fall back to using a single pair,
 * and the additional queues remain allocated but unused; "vif_nqpairs"
 * tracks the pairs in use while "vif_nqpairs_alloc" tracks those allocated.
 *
 * The control queue, present when VIRTIO_NET_F_CTRL_VQ is negotiated,
 * always follows all of the pairs provided by the device, regardless of
 * how many are actually used. It has no interrupt handler and is instead
 * polled for completion of the synchronous requests submitted by
 * vioif_ctrlq_req().
 *
 * -------------------------
 * MAC rings and ring groups
 * -------------------------
 *
 * The queue pairs are exposed to MAC through the MAC_CAPAB_RINGS capability,
 * as one receive ring and one transmit ring per pair. The receive rings are
 * collected into a single static group, while the transmit rings have no
 * explicit group, which causes MAC to create a pseudo-group for each. MAC
 * performs flow classification and fanout across the rings, and transmits
 * on a particular ring through vioif_ring_tx().
 *
 * The device filters received frames on its own primary MAC address, so our
 * group "addmac" entrypoint accepts that address alone, and returns ENOSPC
 * for any other. MAC responds to ENOSPC by enabling promiscuous mode on the
 * device and falling back to software classification, which is how VNICs
 * and other additional unicast addresses are supported.
 *
 * MAC may take a receive ring out of interrupt mode and poll it. Virtqueue
 * interrupt suppression is only advisory and the device may continue to
 * deliver interrupts, so each receive queue also has a "vrq_polling" flag,
 * set for as long as MAC owns the ring. The interrupt handler does not
 * collect frames while it is set; the poll thread gathers them through
 * vioif_rx_ring_poll() instead, up to the byte budget that MAC specifies.
 *
 * -----------------
 * Buffer management
 * -----------------
 *
 * Each queue has a fixed pool of buffers, allocated up front at attach
 * time, sized by VIRTIO_NET_RX_BUFS/VIRTIO_NET_TX_BUFS or by the virtqueue
 * size if that is smaller. Note that the receive pool is a significant
 * allocation, and is one of the costs of an additional queue pair; see the
 * commentary around VIOIF_MAX_QPAIRS in vioif.h.
 *
 * Received frames smaller than the "_rxcopy_thresh" private MAC property
 * are copied into a freshly allocated message; larger frames are loaned to
 * the networking stack with desballoc(9F) and recovered through a free
 * callback. To keep the receive ring stocked we never loan more than half
 * of a queue's buffers at once.
 *
 * Transmitted frames smaller than the "_txcopy_thresh" private MAC property
 * are copied into the preallocated inline buffer that also carries the
 * virtio net header. Larger frames are mapped for DMA directly from the
 * storage loaned to us by the networking stack, in which case the message
 * is held until the device returns the descriptors.
 *
 * Transmit descriptors are reclaimed lazily: on each transmit, from a
 * periodic timeout while a queue is active, and from the queue interrupt
 * when a queue runs out of descriptors. In that last case the ring is
 * "corked": MAC stops transmitting on it, the queue interrupt is enabled,
 * and MAC is notified with mac_tx_ring_update() once descriptors have been
 * reclaimed.
 *
 * -------
 * Locking
 * -------
 *
 * Each receive queue and each transmit queue has its own mutex
 * ("vrq_mutex", "vtq_mutex") protecting its buffer free list, accounting,
 * flags and statistics; the queues operate independently of one another.
 * Device-wide state (the run state, link state and the control queue
 * buffers) is protected by "vif_mutex".
 *
 * A queue mutex may be held while calling into the virtio framework, which
 * has a per-virtqueue mutex of its own. The framework enters the driver only
 * through the registered interrupt handlers, and never does so while holding
 * a virtqueue mutex, so the reverse ordering never occurs. No path requires
 * holding more than one of the driver's mutexes at once.
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
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/sysmacros.h>
#include <sys/smbios.h>
#include <sys/dlpi.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/random.h>
#include <sys/list.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

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

/*
 * The time to wait for the device to complete a control queue request, in
 * milliseconds, before concluding that it will never respond.
 */
uint_t vioif_ctrlq_timeout_ms = 5000;

static int vioif_quiesce(dev_info_t *);
static int vioif_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioif_detach(dev_info_t *, ddi_detach_cmd_t);
static boolean_t vioif_has_feature(vioif_t *, uint64_t);
static int vioif_m_stat(void *, uint_t, uint64_t *);
static void vioif_m_stop(void *);
static int vioif_m_start(void *);
static int vioif_m_multicst(void *, boolean_t, const uint8_t *);
static int vioif_m_setpromisc(void *, boolean_t);
static int vioif_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int vioif_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void vioif_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static boolean_t vioif_m_getcapab(void *, mac_capab_t, void *);
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

/*
 * Note that there are no "mc_unicst" or "mc_tx" entrypoints; we supply
 * receive and transmit rings to MAC via the MAC_CAPAB_RINGS capability,
 * and unicast address filtering and transmission are managed through the
 * ring and group entrypoints instead.
 */
static mac_callbacks_t vioif_mac_callbacks = {
	.mc_getstat =			vioif_m_stat,
	.mc_start =			vioif_m_start,
	.mc_stop =			vioif_m_stop,
	.mc_setpromisc =		vioif_m_setpromisc,
	.mc_multicst =			vioif_m_multicst,

	.mc_callbacks =			(MC_GETCAPAB | MC_SETPROP |
					    MC_GETPROP | MC_PROPINFO),
	.mc_getcapab =			vioif_m_getcapab,
	.mc_setprop =			vioif_m_setprop,
	.mc_getprop =			vioif_m_getprop,
	.mc_propinfo =			vioif_m_propinfo,
};

const uchar_t vioif_broadcast[ETHERADDRL] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*
 * The maximum number of receive and transmit virtqueue pairs we will use,
 * when the device supports VIRTIO_NET_F_MQ. The number of pairs is further
 * limited by the device, the number of CPUs and the number of available
 * MSI-X interrupt vectors.
 */
uint_t vioif_max_qpairs = VIOIF_MAX_QPAIRS;

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
	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		vioif_free_txq_bufs(&vif->vif_txqs[i]);
		vioif_free_rxq_bufs(&vif->vif_rxqs[i]);
	}

	if (vif->vif_ctrlbufs_mem != NULL) {
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
		list_destroy(&vif->vif_ctrlbufs);

		kmem_free(vif->vif_ctrlbufs_mem,
		    sizeof (vioif_ctrlbuf_t) * vif->vif_ctrlbufs_capacity);
		vif->vif_ctrlbufs_mem = NULL;
		vif->vif_ctrlbufs_capacity = 0;
	}
}

static int
vioif_alloc_ctrl_bufs(vioif_t *vif)
{
	if (!vif->vif_has_ctrlq)
		return (0);

	vif->vif_ctrlbufs_capacity = MIN(VIRTIO_NET_CTRL_BUFS,
	    virtio_queue_size(vif->vif_ctrl_vq));
	vif->vif_ctrlbufs_mem = kmem_zalloc(
	    sizeof (vioif_ctrlbuf_t) * vif->vif_ctrlbufs_capacity, KM_SLEEP);
	list_create(&vif->vif_ctrlbufs, sizeof (vioif_ctrlbuf_t),
	    offsetof(vioif_ctrlbuf_t, cb_link));

	for (uint_t i = 0; i < vif->vif_ctrlbufs_capacity; i++) {
		list_insert_tail(&vif->vif_ctrlbufs, &vif->vif_ctrlbufs_mem[i]);
	}

	/*
	 * Control queue buffers are small (less than a page), so we'll
	 * request a single cookie for them.
	 */
	ddi_dma_attr_t attr = vioif_dma_attr_bufs;
	attr.dma_attr_sgllen = 1;

	for (vioif_ctrlbuf_t *cb = list_head(&vif->vif_ctrlbufs); cb != NULL;
	    cb = list_next(&vif->vif_ctrlbufs, cb)) {
		if ((cb->cb_dma = virtio_dma_alloc(vif->vif_virtio,
		    VIOIF_CTRL_SIZE, &attr,
		    DDI_DMA_STREAMING | DDI_DMA_RDWR, KM_SLEEP)) == NULL) {
			return (ENOMEM);
		}
		VERIFY3U(virtio_dma_ncookies(cb->cb_dma), ==, 1);

		if ((cb->cb_chain = virtio_chain_alloc(vif->vif_ctrl_vq,
		    KM_SLEEP)) == NULL) {
			return (ENOMEM);
		}
		virtio_chain_data_set(cb->cb_chain, cb);
	}

	return (0);
}

static int
vioif_alloc_bufs(vioif_t *vif)
{
	if (vioif_alloc_ctrl_bufs(vif) != 0)
		goto fail;

	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		if (vioif_alloc_txq_bufs(&vif->vif_txqs[i]) != 0 ||
		    vioif_alloc_rxq_bufs(&vif->vif_rxqs[i]) != 0) {
			goto fail;
		}
	}

	return (0);

fail:
	vioif_free_bufs(vif);
	return (ENOMEM);
}

/*
 * Submit a request on the control queue and spin awaiting its completion.
 * Returns 0 on success; EBUSY if no request buffer is available, which
 * includes the case where an earlier request timed out; EIO if the request
 * could not be constructed or the device rejected it; and ETIMEDOUT if the
 * device did not respond within "vioif_ctrlq_timeout_ms".
 *
 * The buffer pool intentionally contains a single entry
 * (VIRTIO_NET_CTRL_BUFS), which also serialises requests. Only one request
 * can be outstanding at a time, so the response collected in the wait loop
 * below can only belong to this request.
 */
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
	int r = 0;

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
		return (EBUSY);
	}

	if (totlen > virtio_dma_size(cb->cb_dma)) {
		vif->vif_ctrlbuf_toosmall++;
		vioif_ctrlbuf_free(vif, cb);
		mutex_exit(&vif->vif_mutex);
		return (EIO);
	}
	mutex_exit(&vif->vif_mutex);

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
	if (virtio_chain_append(cb->cb_chain,
	    pa, hdrlen, VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		r = EIO;
		goto done;
	}

	/*
	 * Copy the request data
	 */
	p = virtio_dma_va(cb->cb_dma, hdrlen);
	bcopy(data, p, datalen);
	if (virtio_chain_append(cb->cb_chain,
	    pa + hdrlen, datalen, VIRTIO_DIR_DEVICE_READS) != DDI_SUCCESS) {
		r = EIO;
		goto done;
	}

	/*
	 * We already cleared the buffer, so don't need to copy out a 0 for
	 * the ack byte. Just add a descriptor for that spot.
	 */
	ackp = virtio_dma_va(cb->cb_dma, hdrlen + datalen);
	if (virtio_chain_append(cb->cb_chain,
	    pa + hdrlen + datalen, acklen,
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		r = EIO;
		goto done;
	}

	virtio_dma_sync(cb->cb_dma, DDI_DMA_SYNC_FORDEV);
	virtio_chain_submit(cb->cb_chain, B_TRUE);

	/*
	 * Spin waiting for the response, for up to
	 * "vioif_ctrlq_timeout_ms" milliseconds.
	 */
	const hrtime_t deadline = gethrtime() +
	    MSEC2NSEC(vioif_ctrlq_timeout_ms);

	mutex_enter(&vif->vif_mutex);
	while ((vic = virtio_queue_poll(vif->vif_ctrl_vq)) == NULL) {
		if (gethrtime() > deadline) {
			mutex_exit(&vif->vif_mutex);
			dev_err(vif->vif_dip, CE_WARN, "!control queue "
			    "request (class %u, command %u) timed out",
			    (uint_t)class, (uint_t)cmd);

			/*
			 * The buffer has been submitted to the device and
			 * there is no way to revoke it, so it cannot be
			 * returned to the free list. It is recovered once
			 * the device has been reset during detach. Until
			 * then, with the buffer pool exhausted, further
			 * control queue requests fail with EBUSY.
			 */
			return (ETIMEDOUT);
		}
		mutex_exit(&vif->vif_mutex);
		delay(drv_usectohz(1000));
		mutex_enter(&vif->vif_mutex);
	}

	virtio_dma_sync(cb->cb_dma, DDI_DMA_SYNC_FORCPU);

	/*
	 * The single-entry buffer pool serialises requests, so the completion
	 * collected above can only be for this request.
	 */
	VERIFY3P(virtio_chain_data(vic), ==, cb);
	mutex_exit(&vif->vif_mutex);

	if (*ackp != VIRTIO_NET_CQ_OK) {
		r = EIO;
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

/*
 * Ask the device to use the given number of virtqueue pairs. Until this
 * command completes, a device with VIRTIO_NET_F_MQ negotiated only uses the
 * first pair.
 */
static int
vioif_set_mq_pairs(vioif_t *vif, uint16_t npairs)
{
	struct virtio_net_ctrl_mq mq = {
		.vncm_pairs = LE_16(npairs),
	};

	return (vioif_ctrlq_req(vif, VIRTIO_NET_CTRL_MQ,
	    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, &mq, sizeof (mq)));
}

static int
vioif_m_start(void *arg)
{
	vioif_t *vif = arg;

	mutex_enter(&vif->vif_mutex);

	VERIFY3S(vif->vif_runstate, ==, VIOIF_RUNSTATE_STOPPED);
	vif->vif_runstate = VIOIF_RUNSTATE_RUNNING;

	vioif_get_data(vif);

	mutex_exit(&vif->vif_mutex);

	/*
	 * Starting interrupts on the TX virtqueues is unnecessary at this
	 * time. Descriptor reclamation is handled during transmit, via a
	 * periodic timer, and when resources are tight, via the then-enabled
	 * interrupt.
	 *
	 * Receive queue interrupts are enabled, and the queues populated with
	 * buffers, when MAC starts the individual receive rings.
	 */
	for (uint_t i = 0; i < vif->vif_nqpairs; i++) {
		vioif_txq_t *txq = &vif->vif_txqs[i];

		mutex_enter(&txq->vtq_mutex);
		txq->vtq_drain = false;
		mutex_exit(&txq->vtq_mutex);
	}

	return (DDI_SUCCESS);
}

static void
vioif_m_stop(void *arg)
{
	vioif_t *vif = arg;

	mutex_enter(&vif->vif_mutex);
	VERIFY3S(vif->vif_runstate, ==, VIOIF_RUNSTATE_RUNNING);
	vif->vif_runstate = VIOIF_RUNSTATE_STOPPING;
	mutex_exit(&vif->vif_mutex);

	/*
	 * MAC has already stopped the receive rings. Wait briefly for
	 * receive buffers loaned to the networking stack to be returned.
	 * They can be held indefinitely, so this is a best effort and the
	 * check in detach remains the backstop.
	 */
	(void) vioif_rx_drain(vif);

	/*
	 * Ensure all TX descriptors have been processed and reclaimed.
	 */
	for (uint_t i = 0; i < vif->vif_nqpairs; i++) {
		vioif_txq_t *txq = &vif->vif_txqs[i];

		mutex_enter(&txq->vtq_mutex);
		vioif_tx_drain(txq);
		mutex_exit(&txq->vtq_mutex);
	}

	mutex_enter(&vif->vif_mutex);
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

/*
 * Sum a per-receive queue or per-transmit queue statistic across the queues in
 * use. Each statistic is a naturally aligned uint64_t with a single writer,
 * which updates it while holding the queue mutex. The sums here are taken
 * without entering the queue mutexes which relies on a naturally aligned
 * 64-bit load not tearing, which is true for most 64-bit architectures. A port
 * to an architecture without this property would need to take the mutexes
 * here, or switch the counters to atomic operations. The alignment is asserted
 * below.
 */
#define	VIOIF_RXQ_STAT_SUM(vif, field)					\
	vioif_rxq_stat_sum((vif), offsetof(vioif_rxq_t, field))
#define	VIOIF_TXQ_STAT_SUM(vif, field)					\
	vioif_txq_stat_sum((vif), offsetof(vioif_txq_t, field))

static uint64_t
vioif_rxq_stat_sum(const vioif_t *vif, size_t offset)
{
	uint64_t sum = 0;

	ASSERT(IS_P2ALIGNED(offset, sizeof (uint64_t)));

	for (uint_t i = 0; i < vif->vif_nqpairs; i++) {
		const char *base = (const char *)&vif->vif_rxqs[i];

		ASSERT(IS_P2ALIGNED(base + offset, sizeof (uint64_t)));
		sum += *(const uint64_t *)(base + offset);
	}

	return (sum);
}

static uint64_t
vioif_txq_stat_sum(const vioif_t *vif, size_t offset)
{
	uint64_t sum = 0;

	ASSERT(IS_P2ALIGNED(offset, sizeof (uint64_t)));

	for (uint_t i = 0; i < vif->vif_nqpairs; i++) {
		const char *base = (const char *)&vif->vif_txqs[i];

		ASSERT(IS_P2ALIGNED(base + offset, sizeof (uint64_t)));
		sum += *(const uint64_t *)(base + offset);
	}

	return (sum);
}

static int
vioif_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	vioif_t *vif = arg;

	switch (stat) {
	case MAC_STAT_IERRORS:
		*val = VIOIF_RXQ_STAT_SUM(vif, vrq_ierrors);
		break;
	case MAC_STAT_OERRORS:
		*val = VIOIF_TXQ_STAT_SUM(vif, vtq_oerrors);
		break;
	case MAC_STAT_MULTIRCV:
		*val = VIOIF_RXQ_STAT_SUM(vif, vrq_multircv);
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = VIOIF_RXQ_STAT_SUM(vif, vrq_brdcstrcv);
		break;
	case MAC_STAT_MULTIXMT:
		*val = VIOIF_TXQ_STAT_SUM(vif, vtq_multixmt);
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = VIOIF_TXQ_STAT_SUM(vif, vtq_brdcstxmt);
		break;
	case MAC_STAT_IPACKETS:
		*val = VIOIF_RXQ_STAT_SUM(vif, vrq_ipackets);
		break;
	case MAC_STAT_RBYTES:
		*val = VIOIF_RXQ_STAT_SUM(vif, vrq_rbytes);
		break;
	case MAC_STAT_OPACKETS:
		*val = VIOIF_TXQ_STAT_SUM(vif, vtq_opackets);
		break;
	case MAC_STAT_OBYTES:
		*val = VIOIF_TXQ_STAT_SUM(vif, vtq_obytes);
		break;
	case MAC_STAT_NORCVBUF:
		*val = VIOIF_RXQ_STAT_SUM(vif, vrq_norecvbuf);
		break;
	case MAC_STAT_NOXMTBUF:
		*val = VIOIF_TXQ_STAT_SUM(vif, vtq_notxbuf);
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

/*
 * The device always delivers frames destined for its own primary MAC
 * address, so we accept that one and report that we are out of filter
 * resources for anything else. MAC responds to ENOSPC by enabling
 * promiscuous mode on the device and using software classification.
 */
static int
vioif_group_addmac(void *arg, const uint8_t *mac_addr)
{
	vioif_t *vif = arg;

	if (bcmp(mac_addr, vif->vif_mac, ETHERADDRL) == 0)
		return (0);

	return (ENOSPC);
}

static int
vioif_group_remmac(void *arg, const uint8_t *mac_addr)
{
	vioif_t *vif = arg;

	if (bcmp(mac_addr, vif->vif_mac, ETHERADDRL) == 0)
		return (0);

	return (ENOENT);
}

static void
vioif_fill_rx_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	vioif_t *vif = arg;

	VERIFY3S(rtype, ==, MAC_RING_TYPE_RX);
	VERIFY3S(index, ==, 0);

	vif->vif_rx_grouph = gh;

	infop->mgi_driver = (mac_group_driver_t)vif;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = vioif_group_addmac;
	infop->mgi_remmac = vioif_group_remmac;
	infop->mgi_count = vif->vif_nqpairs;
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
		mac_capab_lso_t *lso = cap_data;

		/*
		 * Advertise large send offload for each protocol separately.
		 * The device may have offered segmentation offload for only
		 * one of them.
		 */
		lso->lso_flags = 0;
		if (vif->vif_tx_tso4) {
			lso->lso_flags |= LSO_TX_BASIC_TCP_IPV4;
			lso->lso_basic_tcp_ipv4.lso_max = VIOIF_RX_DATA_SIZE;
		}
		if (vif->vif_tx_tso6) {
			lso->lso_flags |= LSO_TX_BASIC_TCP_IPV6;
			lso->lso_basic_tcp_ipv6.lso_max = VIOIF_RX_DATA_SIZE;
		}

		return (lso->lso_flags != 0);
	}

	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = cap_data;

		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;

		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_RX:
			cap_rings->mr_rnum = vif->vif_nqpairs;
			cap_rings->mr_gnum = 1;
			cap_rings->mr_rget = vioif_fill_rx_ring;
			cap_rings->mr_gget = vioif_fill_rx_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;

		case MAC_RING_TYPE_TX:
			/*
			 * Providing transmit rings without any groups causes
			 * MAC to create a pseudo-group for each ring.
			 */
			cap_rings->mr_rnum = vif->vif_nqpairs;
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rget = vioif_fill_tx_ring;
			cap_rings->mr_gget = NULL;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;

		default:
			return (B_FALSE);
		}

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
	link_state_t new_state;

	VERIFY(MUTEX_HELD(&vif->vif_mutex));

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

	/*
	 * Report any change in the link state to MAC. The handle is not set
	 * until mac_register() has completed, and a configuration change
	 * interrupt can arrive before that. In that case the state is
	 * reported once the handle has been set, when this data is next
	 * refreshed at the end of attach.
	 */
	if (vif->vif_mac_handle != NULL &&
	    new_state != vif->vif_link_state) {
		mac_link_update(vif->vif_mac_handle, new_state);
		vif->vif_link_state = new_state;
	}
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

/*
 * Determine the number of virtqueue pairs to use, and return the number of
 * pairs provided by the device through "maxpairsp"; the latter determines the
 * index of the control queue and may be larger than the number of pairs we
 * elect to use. Returns 0 if the device configuration is unusable, in which
 * case attach must fail.
 */
static uint_t
vioif_calculate_qpairs(vioif_t *vif, int itypes, uint16_t *maxpairsp)
{
	dev_info_t *dip = vif->vif_dip;
	uint16_t maxpairs;
	uint_t npairs, ncpu;
	int types, navail;

	*maxpairsp = 1;

	if (!vioif_has_feature(vif, VIRTIO_NET_F_MQ | VIRTIO_NET_F_CTRL_VQ))
		return (1);

	/*
	 * With VIRTIO_NET_F_MQ negotiated, the device places the control
	 * queue after all of the queue pairs it provides, and so a device
	 * that reports an unusable pair count leaves us with no way to
	 * locate the control queue that the negotiated feature set requires
	 * us to use. Such a device violates the specification. Refuse to
	 * attach to it.
	 */
	maxpairs = virtio_dev_get16(vif->vif_virtio,
	    VIRTIO_NET_CONFIG_MAX_VQ_PAIRS);
	if (maxpairs < VIRTIO_NET_CTRL_MQ_PAIRS_MIN ||
	    maxpairs > VIRTIO_NET_CTRL_MQ_PAIRS_MAX) {
		dev_err(dip, CE_WARN, "invalid max_virtqueue_pairs (%u)",
		    (uint_t)maxpairs);
		return (0);
	}
	if (VIRTIO_NET_VIRTQ_CONTROL(maxpairs) > UINT16_MAX) {
		/*
		 * The pair count is valid per the specification, but the
		 * index of the control queue that follows the pairs cannot
		 * be represented in the 16-bit queue selector of the PCI
		 * transport.
		 */
		dev_err(dip, CE_WARN, "cannot support %u virtqueue pairs; "
		    "the control queue index is out of range",
		    (uint_t)maxpairs);
		return (0);
	}
	*maxpairsp = maxpairs;

	/*
	 * There is no benefit in using more queue pairs than we have CPUs.
	 * Once every CPU can be servicing a different pair, additional pairs
	 * only divide the same flows across more rings, while each one costs
	 * an interrupt vector and a significant amount of receive buffer
	 * memory. The operator may have constrained us further.
	 */
	ncpu = ddi_ncpus_expected();
	npairs = MIN(maxpairs, ncpu);
	npairs = MIN(npairs, vioif_max_qpairs);

	/*
	 * Each virtqueue requires its own MSI-X vector, and we need one more
	 * for configuration change notifications. If there are not enough
	 * vectors available we use a single pair rather than have the virtio
	 * framework fall back to a shared fixed interrupt for every queue.
	 */
	if (ddi_intr_get_supported_types(dip, &types) != DDI_SUCCESS)
		return (1);
	if (itypes != VIRTIO_ANY_INTR_TYPE)
		types &= itypes;
	if ((types & DDI_INTR_TYPE_MSIX) == 0 ||
	    ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSIX, &navail) !=
	    DDI_SUCCESS) {
		return (1);
	}
	if (navail < 3)
		return (1);
	npairs = MIN(npairs, (uint_t)(navail - 1) / 2);

	return (MAX(npairs, 1));
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
	int itypes;
	vioif_t *vif;
	virtio_t *vio;
	mac_register_t *macp = NULL;
	uint64_t features;
	uint16_t maxpairs;
	char tqname[32];
	bool mutexes_init = false;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if ((vio = virtio_init(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	features = VIRTIO_NET_WANTED_FEATURES;
	if (virtio_modern(vio))
		features |= VIRTIO_NET_WANTED_FEATURES_MODERN;

	/*
	 * VIRTIO_NET_F_MQ requires VIRTIO_NET_F_CTRL_VQ, and we must not
	 * accept a feature whose dependencies the device has not offered.
	 * Between virtio_init() and virtio_init_features() the framework
	 * reports the features offered by the device.
	 */
	if (!virtio_features_present(vio, VIRTIO_NET_F_CTRL_VQ))
		features &= ~VIRTIO_NET_F_MQ;

	/*
	 * Similarly, the transmit offload features depend on
	 * VIRTIO_NET_F_CSUM, and VIRTIO_NET_F_HOST_ECN additionally on at
	 * least one of the TSO features being accepted alongside it.
	 */
	if (!virtio_features_present(vio, VIRTIO_NET_F_CSUM)) {
		features &= ~(VIRTIO_NET_F_GSO | VIRTIO_NET_F_HOST_TSO4 |
		    VIRTIO_NET_F_HOST_TSO6);
	}
	if (!virtio_features_present(vio, VIRTIO_NET_F_HOST_TSO4))
		features &= ~VIRTIO_NET_F_HOST_TSO4;
	if (!virtio_features_present(vio, VIRTIO_NET_F_HOST_TSO6))
		features &= ~VIRTIO_NET_F_HOST_TSO6;
	if ((features &
	    (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6)) == 0) {
		features &= ~VIRTIO_NET_F_HOST_ECN;
	}

	if (!virtio_init_features(vio, features, B_TRUE)) {
		virtio_fini(vio, B_TRUE);
		return (DDI_FAILURE);
	}

	vif = kmem_zalloc(sizeof (*vif), KM_SLEEP);
	vif->vif_dip = dip;
	vif->vif_virtio = vio;
	vif->vif_runstate = VIOIF_RUNSTATE_STOPPED;
	vif->vif_link_state = LINK_STATE_UNKNOWN;
	ddi_set_driver_private(dip, vif);

	(void) snprintf(tqname, sizeof (tqname), "vioif%d_taskq",
	    ddi_get_instance(dip));
	vif->vif_taskq = taskq_create(tqname, 1, minclsyspri, 1, 1,
	    TASKQ_PREPOPULATE);

	itypes = vioif_select_interrupt_types();

	vif->vif_nqpairs = vioif_calculate_qpairs(vif, itypes, &maxpairs);
	if (vif->vif_nqpairs == 0) {
		/*
		 * The device configuration is unusable. The specific problem
		 * has already been reported.
		 */
		goto fail;
	}
	vif->vif_nqpairs_alloc = vif->vif_nqpairs;

	vif->vif_rxqs = kmem_zalloc(
	    sizeof (vioif_rxq_t) * vif->vif_nqpairs_alloc, KM_SLEEP);
	vif->vif_txqs = kmem_zalloc(
	    sizeof (vioif_txq_t) * vif->vif_nqpairs_alloc, KM_SLEEP);

	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		vioif_rxq_t *rxq = &vif->vif_rxqs[i];
		vioif_txq_t *txq = &vif->vif_txqs[i];

		rxq->vrq_vif = vif;
		(void) snprintf(rxq->vrq_name, sizeof (rxq->vrq_name),
		    "rx%u", i);
		if ((rxq->vrq_vq = virtio_queue_alloc(vio,
		    VIRTIO_NET_VIRTQ_RX(i), rxq->vrq_name, vioif_rx_handler,
		    rxq, B_FALSE, VIOIF_MAX_SEGS)) == NULL) {
			goto fail;
		}

		txq->vtq_vif = vif;
		(void) snprintf(txq->vtq_name, sizeof (txq->vtq_name),
		    "tx%u", i);
		if ((txq->vtq_vq = virtio_queue_alloc(vio,
		    VIRTIO_NET_VIRTQ_TX(i), txq->vtq_name, vioif_tx_handler,
		    txq, B_FALSE, VIOIF_MAX_SEGS)) == NULL) {
			goto fail;
		}
	}

	/*
	 * The control queue always follows all of the queue pairs provided by
	 * the device, regardless of how many of those pairs we use.
	 */
	if (vioif_has_feature(vif, VIRTIO_NET_F_CTRL_VQ) &&
	    (vif->vif_ctrl_vq = virtio_queue_alloc(vio,
	    VIRTIO_NET_VIRTQ_CONTROL(maxpairs), "ctrlq", NULL, vif,
	    B_FALSE, VIOIF_MAX_SEGS)) == NULL) {
		goto fail;
	}

	virtio_register_cfgchange_handler(vio, vioif_cfgchange, vif);

	if (virtio_init_complete(vio, itypes) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to complete Virtio init");
		goto fail;
	}

	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		virtio_queue_no_interrupt(vif->vif_rxqs[i].vrq_vq, B_TRUE);
		virtio_queue_no_interrupt(vif->vif_txqs[i].vtq_vq, B_TRUE);
	}
	if (vif->vif_ctrl_vq != NULL)
		virtio_queue_no_interrupt(vif->vif_ctrl_vq, B_TRUE);

	/*
	 * Our earlier sizing of the queue pair count against the available
	 * MSI-X vectors was only advisory: the framework performs the actual
	 * allocation as part of virtio_init_complete(), and falls back to a
	 * single shared fixed interrupt if the strict MSI-X allocation fails.
	 * Multiple queue pairs all serviced by one shared interrupt are worse
	 * than a single pair, so check what was allocated and adapt.
	 */
	if (vif->vif_nqpairs > 1 &&
	    virtio_interrupts_type(vio) != DDI_INTR_TYPE_MSIX) {
		dev_err(dip, CE_WARN, "!MSI-X interrupts were not allocated; "
		    "using a single queue pair");
		vif->vif_nqpairs = 1;
	}

	mutex_init(&vif->vif_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		mutex_init(&vif->vif_rxqs[i].vrq_mutex, NULL, MUTEX_DRIVER,
		    virtio_intr_pri(vio));
		mutex_init(&vif->vif_txqs[i].vtq_mutex, NULL, MUTEX_DRIVER,
		    virtio_intr_pri(vio));
	}
	mutexes_init = true;

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

	mutex_exit(&vif->vif_mutex);

	if (vioif_alloc_bufs(vif) != 0) {
		dev_err(dip, CE_WARN, "failed to allocate memory");
		goto fail;
	}

	/*
	 * If we negotiated multiple queue pairs, ask the device to use them.
	 * If the request fails, fall back to using a single pair; the
	 * additional allocated queues are simply left unused. If the device
	 * did not respond to the request at all it is unlikely to be usable,
	 * so fail the attach.
	 */
	if (vif->vif_nqpairs > 1) {
		int e = vioif_set_mq_pairs(vif, vif->vif_nqpairs);

		if (e == ETIMEDOUT) {
			dev_err(dip, CE_WARN, "device did not respond to the "
			    "%u queue pair request", vif->vif_nqpairs);
			goto fail_shutdown;
		}
		if (e != 0) {
			dev_err(dip, CE_WARN, "!failed to enable %u queue "
			    "pairs; using a single pair", vif->vif_nqpairs);
			vif->vif_nqpairs = 1;
		}
	}

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
	/*
	 * MAC_VIRT_LEVEL1 is required for MAC to initialise the rings and
	 * groups that we advertise through MAC_CAPAB_RINGS. Without it,
	 * mac_register() rejects a driver that has no mc_unicst entrypoint.
	 */
	macp->m_v12n = MAC_VIRT_LEVEL1;

	ret = mac_register(macp, &vif->vif_mac_handle);
	mac_free(macp);
	if (ret != 0) {
		dev_err(dip, CE_WARN, "mac_register() failed (%d)", ret);
		goto fail;
	}

	mutex_enter(&vif->vif_mutex);
	vioif_get_data(vif);
	mutex_exit(&vif->vif_mutex);

	return (DDI_SUCCESS);

fail_shutdown:
	/*
	 * Reset the device so that the buffer submitted with the timed-out
	 * control queue request is returned to us. Every control buffer must
	 * be back in the pool before the buffer pools are freed below.
	 */
	virtio_shutdown(vio);
	mutex_enter(&vif->vif_mutex);
	for (;;) {
		virtio_chain_t *vic;

		if ((vic = virtio_queue_evacuate(vif->vif_ctrl_vq)) == NULL)
			break;
		vioif_ctrlbuf_free(vif, virtio_chain_data(vic));
	}
	mutex_exit(&vif->vif_mutex);

fail:
	/*
	 * Quiesce the interrupt handlers before starting to tear down the
	 * resources they use. The mutexes must outlive the handlers, so
	 * they are destroyed only after virtio_fini() has removed them.
	 */
	virtio_interrupts_disable(vio);
	if (vif->vif_taskq != NULL) {
		taskq_destroy(vif->vif_taskq);
	}
	vioif_free_bufs(vif);
	(void) virtio_fini(vio, B_TRUE);
	if (mutexes_init) {
		for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
			mutex_destroy(&vif->vif_rxqs[i].vrq_mutex);
			mutex_destroy(&vif->vif_txqs[i].vtq_mutex);
		}
		mutex_destroy(&vif->vif_mutex);
	}
	kmem_free(vif->vif_rxqs,
	    sizeof (vioif_rxq_t) * vif->vif_nqpairs_alloc);
	kmem_free(vif->vif_txqs,
	    sizeof (vioif_txq_t) * vif->vif_nqpairs_alloc);
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
	mutex_exit(&vif->vif_mutex);

	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		vioif_rxq_t *rxq = &vif->vif_rxqs[i];
		vioif_txq_t *txq = &vif->vif_txqs[i];

		/*
		 * There should be no outstanding transmit buffers once the
		 * NIC is completely stopped.
		 */
		mutex_enter(&txq->vtq_mutex);
		VERIFY3U(txq->vtq_nbufs_alloc, ==, 0);
		mutex_exit(&txq->vtq_mutex);

		/*
		 * Though we cannot claw back all of the receive buffers until
		 * we reset the device, we must ensure all those loaned to MAC
		 * have been returned before calling mac_unregister().
		 */
		mutex_enter(&rxq->vrq_mutex);
		if (rxq->vrq_nbufs_onloan > 0) {
			dev_err(dip, CE_WARN, "!%u receive buffers still "
			    "loaned, cannot detach", rxq->vrq_nbufs_onloan);
			mutex_exit(&rxq->vrq_mutex);
			return (DDI_FAILURE);
		}
		mutex_exit(&rxq->vrq_mutex);
	}

	/*
	 * Disable interrupts before unregistering from MAC, so that a
	 * configuration change interrupt cannot use the MAC handle after
	 * mac_unregister() has freed it.
	 */
	virtio_interrupts_disable(vif->vif_virtio);

	if ((r = mac_unregister(vif->vif_mac_handle)) != 0) {
		dev_err(dip, CE_WARN, "!MAC unregister failed (%d)", r);
		if (virtio_interrupts_enable(vif->vif_virtio) !=
		    DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "failed to re-enable interrupts");
		}
		return (DDI_FAILURE);
	}

	/*
	 * MAC can no longer call the ring entrypoints that despatch work to
	 * the task queue, so it can be torn down. This waits for any
	 * remaining task to finish.
	 */
	taskq_destroy(vif->vif_taskq);

	/*
	 * Shut down the device so that we can recover any previously
	 * submitted receive buffers.
	 */
	virtio_shutdown(vif->vif_virtio);
	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		vioif_rxq_t *rxq = &vif->vif_rxqs[i];
		virtio_chain_t *vic;

		mutex_enter(&rxq->vrq_mutex);
		while ((vic = virtio_queue_evacuate(rxq->vrq_vq)) != NULL) {
			vioif_rxbuf_t *rb = virtio_chain_data(vic);

			vioif_rxbuf_free(rxq, rb);
		}
		mutex_exit(&rxq->vrq_mutex);
	}

	if (vif->vif_ctrl_vq != NULL) {
		virtio_chain_t *vic;

		/*
		 * Recover the buffer of any control queue request that timed
		 * out and was abandoned. The device reset above has returned
		 * ownership of it to us.
		 */
		mutex_enter(&vif->vif_mutex);
		while ((vic = virtio_queue_evacuate(vif->vif_ctrl_vq)) !=
		    NULL) {
			vioif_ctrlbuf_free(vif, virtio_chain_data(vic));
		}
		mutex_exit(&vif->vif_mutex);
	}

	/*
	 * vioif_free_bufs() must be called before virtio_fini()
	 * as it uses virtio_chain_free() which itself depends on some
	 * virtio data structures still being around.
	 */
	vioif_free_bufs(vif);
	(void) virtio_fini(vif->vif_virtio, B_FALSE);

	for (uint_t i = 0; i < vif->vif_nqpairs_alloc; i++) {
		mutex_destroy(&vif->vif_rxqs[i].vrq_mutex);
		mutex_destroy(&vif->vif_txqs[i].vtq_mutex);
	}
	mutex_destroy(&vif->vif_mutex);

	kmem_free(vif->vif_rxqs,
	    sizeof (vioif_rxq_t) * vif->vif_nqpairs_alloc);
	kmem_free(vif->vif_txqs,
	    sizeof (vioif_txq_t) * vif->vif_nqpairs_alloc);
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
