/*
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/viona_io.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <poll.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlvnic.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "pci_emul.h"
#include "virtio.h"
#include "iov.h"
#include "virtio_net.h"

/*
 * This is the default number of queues allocated and advertised via the
 * multi-queue feature. It can be overridden via the `qpair` device option.
 */
#define	VIONA_DEFAULT_MAX_QPAIR	8

#define	VIONA_RINGSZ		1024
#define	VIONA_CTLQ_SIZE		64
#define	VIONA_CTLQ_MAXSEGS	32

/*
 * These macros work in terms of TX/RX queues only, which is always what we
 * need when interfacing with viona since the control queue is implemented
 * entirely in userspace.
 */
#define	VIONA_P2QS(p)		((p) * 2)
#define	VIONA_NRINGS(sc)	((sc)->vsc_consts.vc_nvq - 1)
#define	VIONA_USABLE_RINGS(sc)	(VIONA_P2QS((sc)->vsc_vq_usepairs))
#define	VIONA_RING_VALID(sc, r)	((r) < VIONA_NRINGS(sc))

#define	VIONA_RING(sc, n)	(&(sc)->vsc_queues[(n)])
#define	VIONA_RXQ(sc, n)	(VIONA_RING(sc, (n) * 2))
#define	VIONA_TXQ(sc, n)	(VIONA_RING(sc, (n) * 2 + 1))
/*
 * The control queue is always in the last slot of allocated rings, regardless
 * of how many rings are in use.
 */
#define	VIONA_CTLQ_NUM(sc)	(VIONA_NRINGS(sc))
#define	VIONA_RING_CTLQ(sc, r)	(r == VIONA_CTLQ_NUM(sc))
#define	VIONA_CTLQ(sc)		(VIONA_RING(sc, VIONA_CTLQ_NUM(sc)))

/*
 * Debug printf
 */
static volatile int pci_viona_debug;
#define	DPRINTF(fmt, arg...) \
	do { \
		if (pci_viona_debug) { \
			FPRINTLN(stdout, fmt, ##arg); \
			fflush(stdout); \
		} \
	} while (0)
#define	WPRINTF(fmt, arg...) FPRINTLN(stderr, fmt, ##arg)

/*
 * Per-device softc
 */
struct pci_viona_softc {
	struct virtio_softc	vsc_vs;
	struct virtio_consts	vsc_consts;
	struct vqueue_info	*vsc_queues;
	pthread_mutex_t		vsc_mtx;

	struct virtio_net_config vsc_config;

	datalink_id_t	vsc_linkid;
	int		vsc_vnafd;

	/* Configurable parameters */
	char		vsc_linkname[MAXLINKNAMELEN];
	uint64_t	vsc_feature_mask;
	uint16_t	vsc_vq_usepairs; /* RX/TX pairs in use */
	uint16_t	vsc_vq_size;	/* size of a TX/RX queue */

	bool		vsc_resetting;
	bool		vsc_msix_active;

	viona_promisc_t	vsc_promisc;		/* Current promisc mode */
	bool		vsc_promisc_promisc;	/* PROMISC enabled */
	bool		vsc_promisc_allmulti;	/* ALLMULTI enabled */
	bool		vsc_promisc_umac;	/* unicast MACs sent */
	bool		vsc_promisc_mmac;	/* multicast MACs sent */
};

static int pci_viona_cfgread(void *, int, int, uint32_t *);
static int pci_viona_cfgwrite(void *, int, int, uint32_t);
static uint64_t pci_viona_get_hv_features(void *, bool);
static void pci_viona_set_hv_features(void *, uint64_t *);
static void pci_viona_qnotify(void *, struct vqueue_info *);
static void pci_viona_ctlqnotify(void *, struct vqueue_info *);
static void pci_viona_ring_init(void *, uint64_t, bool);
static void pci_viona_reset(void *);
static void pci_viona_ring_set_msix(void *, int);
static void pci_viona_update_msix(void *, uint64_t);

static virtio_capstr_t viona_caps[] = {
	{ VIRTIO_NET_F_CSUM,		"VIRTIO_NET_F_CSUM" },
	{ VIRTIO_NET_F_GUEST_CSUM,	"VIRTIO_NET_F_GUEST_CSUM" },
	{ VIRTIO_NET_F_MTU,		"VIRTIO_NET_F_MTU" },
	{ VIRTIO_NET_F_MAC,		"VIRTIO_NET_F_MAC" },
	{ VIRTIO_NET_F_GSO_DEPREC,	"VIRTIO_NET_F_GSO_DEPREC" },
	{ VIRTIO_NET_F_GUEST_TSO4,	"VIRTIO_NET_F_GUEST_TSO4" },
	{ VIRTIO_NET_F_GUEST_TSO6,	"VIRTIO_NET_F_GUEST_TSO6" },
	{ VIRTIO_NET_F_GUEST_ECN,	"VIRTIO_NET_F_GUEST_ECN" },
	{ VIRTIO_NET_F_GUEST_UFO,	"VIRTIO_NET_F_GUEST_UFO" },
	{ VIRTIO_NET_F_HOST_TSO4,	"VIRTIO_NET_F_HOST_TSO4" },
	{ VIRTIO_NET_F_HOST_TSO6,	"VIRTIO_NET_F_HOST_TSO6" },
	{ VIRTIO_NET_F_HOST_ECN,	"VIRTIO_NET_F_HOST_ECN" },
	{ VIRTIO_NET_F_HOST_UFO,	"VIRTIO_NET_F_HOST_UFO" },
	{ VIRTIO_NET_F_MRG_RXBUF,	"VIRTIO_NET_F_MRG_RXBUF" },
	{ VIRTIO_NET_F_STATUS,		"VIRTIO_NET_F_STATUS" },
	{ VIRTIO_NET_F_CTRL_VQ,		"VIRTIO_NET_F_CTRL_VQ" },
	{ VIRTIO_NET_F_CTRL_RX,		"VIRTIO_NET_F_CTRL_RX" },
	{ VIRTIO_NET_F_CTRL_VLAN,	"VIRTIO_NET_F_CTRL_VLAN" },
	{ VIRTIO_NET_F_GUEST_ANNOUNCE,	"VIRTIO_NET_F_GUEST_ANNOUNCE" },
	{ VIRTIO_NET_F_MQ,		"VIRTIO_NET_F_MQ" },
	{ VIRTIO_F_CTRL_MAC_ADDR,	"VIRTIO_F_CTRL_MAC_ADDR" },
};

static struct virtio_consts viona_vi_consts = {
	.vc_name		= "viona",
	.vc_nvq			= 0,	/* set in pci_viona_qalloc() */
	.vc_max_nvq		= 0,	/* set in pci_viona_parse_opts() */
	.vc_cfgsize		= sizeof (struct virtio_net_config),
	.vc_cfgread		= pci_viona_cfgread,
	.vc_cfgwrite		= pci_viona_cfgwrite,
	.vc_set_msix		= pci_viona_ring_set_msix,
	.vc_update_msix		= pci_viona_update_msix,
	.vc_reset		= pci_viona_reset,
	.vc_qinit		= pci_viona_ring_init,
	.vc_qnotify		= pci_viona_qnotify,
	.vc_hv_features		= pci_viona_get_hv_features,
	.vc_apply_features	= pci_viona_set_hv_features,
	/*
	 * The following fields are populated using the response from the
	 * viona driver during initialisation, augmented with the additional
	 * capabilities emulated in userspace.
	 */
	.vc_hv_caps_legacy	= 0,
	.vc_hv_caps_modern	= 0,

	.vc_capstr =		viona_caps,
	.vc_ncapstr =		ARRAY_SIZE(viona_caps),
};

static void
pci_viona_ring_reset(struct pci_viona_softc *sc, int ring)
{
	DPRINTF("viona: ring reset 0x%x", ring);
	for (;;) {
		int res;

		res = ioctl(sc->vsc_vnafd, VNA_IOC_RING_RESET, ring);
		if (res == 0) {
			break;
		} else if (errno != EINTR) {
			WPRINTF("ioctl viona ring 0x%x reset failed %d",
			    ring, errno);
			return;
		}
	}
}

static bool
pci_viona_set_usepairs(struct pci_viona_softc *sc, uint16_t pairs)
{
	const uint16_t opairs = sc->vsc_vq_usepairs;

	DPRINTF("QUSE pairs 0x%x -> 0x%x", opairs, pairs);

	if (opairs == pairs)
		return (true);

	if (ioctl(sc->vsc_vnafd, VNA_IOC_SET_USEPAIRS, pairs) != 0) {
		WPRINTF("error setting viona use pairs(0x%x): %s",
		    pairs, strerror(errno));
		return (false);
	}
	sc->vsc_vq_usepairs = pairs;
	return (true);
}

static bool
pci_viona_qalloc(struct pci_viona_softc *sc, int pairs)
{
	struct virtio_consts *vc = &sc->vsc_consts;
	struct vqueue_info *queues;
	int nqueues, oqueues;

	oqueues = vc->vc_nvq;
	/* Add one for the control queue */
	nqueues = VIONA_P2QS(pairs) + 1;
	DPRINTF("QALLOC pairs 0x%x (0x%x -> 0x%x)", pairs,
	    oqueues, nqueues);

	if (oqueues == nqueues)
		return (true);

	queues = recallocarray(sc->vsc_queues, oqueues, nqueues,
	    sizeof (struct vqueue_info));
	if (queues == NULL) {
		WPRINTF("Failed to allocate memory changing queues from "
		    "0x%x to 0x%x", oqueues, nqueues);
		return (false);
	}
	sc->vsc_queues = queues;
	vc->vc_nvq = nqueues;

	for (uint_t i = 0; i < vc->vc_nvq; i++) {
		sc->vsc_queues[i].vq_qsize = sc->vsc_vq_size;
		sc->vsc_queues[i].vq_notify = NULL;
	}
	VIONA_CTLQ(sc)->vq_qsize = VIONA_CTLQ_SIZE;
	VIONA_CTLQ(sc)->vq_notify = pci_viona_ctlqnotify;

	vi_queue_linkup(&sc->vsc_vs, sc->vsc_queues);

	if (ioctl(sc->vsc_vnafd, VNA_IOC_SET_PAIRS, pairs) != 0) {
		WPRINTF("error setting viona queue pairs(0x%x): %s",
		    pairs, strerror(errno));
		return (false);
	}

	return (true);
}

static void
pci_viona_reset(void *vsc)
{
	struct pci_viona_softc *sc = vsc;

	DPRINTF("viona: device reset requested !");

	vi_reset_dev(&sc->vsc_vs);

	/* Reset all TX/RX rings */
	for (uint16_t i = 0; i < VIONA_NRINGS(sc); i++)
		pci_viona_ring_reset(sc, i);

	/* Shrink back down to one queue pair */
	VERIFY(pci_viona_set_usepairs(sc, 1));
	VERIFY(pci_viona_qalloc(sc, 1));
}

static const char *
pci_viona_promisc_descr(viona_promisc_t mode)
{
	switch (mode) {
	case VIONA_PROMISC_NONE:
		return ("none");
	case VIONA_PROMISC_MULTI:
		return ("multicast");
	case VIONA_PROMISC_ALL:
		return ("all");
	default:
		abort();
	}
}

static int
pci_viona_eval_promisc(struct pci_viona_softc *sc)
{
	viona_promisc_t mode = VIONA_PROMISC_NONE;
	int err = 0;

	/*
	 * If the guest has explicitly requested promiscuous mode or has sent a
	 * non-empty unicast MAC address table, then set viona to promiscuous
	 * mode. Otherwise, if the guest has explicitly requested multicast
	 * promiscuity or has sent a non-empty multicast MAC address table,
	 * then set viona to multicast promiscuous mode.
	 */
	if (sc->vsc_promisc_promisc || sc->vsc_promisc_umac)
		mode = VIONA_PROMISC_ALL;
	else if (sc->vsc_promisc_allmulti || sc->vsc_promisc_mmac)
		mode = VIONA_PROMISC_MULTI;

	if (mode != sc->vsc_promisc) {
		DPRINTF("viona: setting promiscuous mode to %d (%s)",
		    mode, pci_viona_promisc_descr(mode));
		DPRINTF("       promisc=%u, umac=%u, allmulti=%u, mmac=%u",
		    sc->vsc_promisc_promisc, sc->vsc_promisc_umac,
		    sc->vsc_promisc_allmulti, sc->vsc_promisc_mmac);

		err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_PROMISC, mode);
		if (err == 0)
			sc->vsc_promisc = mode;
		else
			WPRINTF("ioctl viona set promisc failed %d", errno);
	}

	return (err);
}

static uint8_t
pci_viona_control_rx(struct vqueue_info *vq, const virtio_net_ctrl_hdr_t *hdr,
    iov_bunch_t *iob)
{
	struct pci_viona_softc *sc = (struct pci_viona_softc *)vq->vq_vs;
	uint8_t v;

	if (!iov_bunch_copy(iob, &v, sizeof (v))) {
		EPRINTLN("viona: bad control RX data");
		return (VIRTIO_NET_CQ_ERR);
	}

	switch (hdr->vnch_command) {
	case VIRTIO_NET_CTRL_RX_PROMISC:
		DPRINTF("viona: ctrl RX promisc %d", v);
		sc->vsc_promisc_promisc = (v != 0);
		break;
	case VIRTIO_NET_CTRL_RX_ALLMULTI:
		DPRINTF("viona: ctrl RX allmulti %d", v);
		sc->vsc_promisc_allmulti = (v != 0);
		break;
	default:
		/*
		 * VIRTIO_NET_F_CTRL_RX_EXTRA was not offered so no other
		 * commands are expected.
		 */
		EPRINTLN("viona: unrecognised RX control cmd %u",
		    hdr->vnch_command);
		return (VIRTIO_NET_CQ_ERR);
	}

	if (pci_viona_eval_promisc(sc) == 0)
		return (VIRTIO_NET_CQ_OK);
	return (VIRTIO_NET_CQ_ERR);
}

static void
pci_viona_control_mac_dump(const char *tag, iov_bunch_t *iob, uint32_t cnt)
{
	if (!pci_viona_debug) {
		(void) iov_bunch_skip(iob, cnt * ETHERADDRL);
		return;
	}

	DPRINTF("-- %s MAC TABLE (entries: %u)", tag, cnt);

	for (uint32_t i = 0; i < cnt; i++) {
		ether_addr_t mac;

		if (!iov_bunch_copy(iob, &mac, sizeof (mac)))
			return;

		DPRINTF("   [%2d] %s", i, ether_ntoa((struct ether_addr *)mac));
	}
}

static uint8_t
pci_viona_control_mac(struct vqueue_info *vq, const virtio_net_ctrl_hdr_t *hdr,
    iov_bunch_t *iob)
{
	struct pci_viona_softc *sc = (struct pci_viona_softc *)vq->vq_vs;

	switch (hdr->vnch_command) {
	case VIRTIO_NET_CTRL_MAC_TABLE_SET: {
		virtio_net_ctrl_mac_t table;

		DPRINTF("viona: ctrl MAC table set");

		/*
		 * We advertise VIRTIO_NET_F_CTRL_RX and therefore need to
		 * accept VIRTIO_NET_CTRL_MAC, but we don't support passing
		 * changes in the MAC address lists down to viona.
		 * Instead, we set flags to indicate if the guest has sent
		 * any MAC addresses for each table, and use these to determine
		 * the resulting promiscuous mode, see pci_viona_eval_promisc()
		 * above.
		 */

		/* Unicast MAC table */
		if (!iov_bunch_copy(iob,
		    &table.vncm_entries, sizeof (table.vncm_entries))) {
			EPRINTLN("viona: bad control MAC unicast header");
			return (VIRTIO_NET_CQ_ERR);
		}
		sc->vsc_promisc_umac = (table.vncm_entries != 0);
		pci_viona_control_mac_dump("UNICAST", iob, table.vncm_entries);

		/* Multicast MAC table */
		if (!iov_bunch_copy(iob,
		    &table.vncm_entries, sizeof (table.vncm_entries))) {
			EPRINTLN("viona: bad control MAC multicast header");
			return (VIRTIO_NET_CQ_ERR);
		}
		sc->vsc_promisc_mmac = (table.vncm_entries != 0);
		pci_viona_control_mac_dump("MULTICAST", iob,
		    table.vncm_entries);

		break;
	}
	case VIRTIO_NET_CTRL_MAC_ADDR_SET:
		/* disallow setting the primary filter MAC address */
		DPRINTF("viona: ctrl MAC addr set with 0x%x bytes",
		    iob->ib_remain);
		return (VIRTIO_NET_CQ_ERR);
	default:
		EPRINTLN("viona: unrecognised MAC control cmd %u",
		    hdr->vnch_command);
		return (VIRTIO_NET_CQ_ERR);
	}

	if (pci_viona_eval_promisc(sc) == 0)
		return (VIRTIO_NET_CQ_OK);
	return (VIRTIO_NET_CQ_ERR);
}

static uint8_t
pci_viona_control_mq(struct vqueue_info *vq, const virtio_net_ctrl_hdr_t *hdr,
    iov_bunch_t *iob)
{
	struct pci_viona_softc *sc = (struct pci_viona_softc *)vq->vq_vs;

	switch (hdr->vnch_command) {
	case VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: {
		virtio_net_ctrl_mq_t mq;

		if (!iov_bunch_copy(iob, &mq, sizeof (mq))) {
			EPRINTLN("viona: bad control MQ data");
			return (VIRTIO_NET_CQ_ERR);
		}

		DPRINTF("VQ PAIRS SET 0x%x", mq.virtqueue_pairs);
		if (mq.virtqueue_pairs < 1 ||
		    VIONA_P2QS(mq.virtqueue_pairs) > VIONA_NRINGS(sc)) {
			EPRINTLN("viona: invalid VQ pairs from guest 0x%x",
			    mq.virtqueue_pairs);
			return (VIRTIO_NET_CQ_ERR);
		}
		if (!pci_viona_set_usepairs(sc, mq.virtqueue_pairs))
			return (VIRTIO_NET_CQ_ERR);
		break;
	}
	default:
		EPRINTLN("viona: unrecognised MQ control cmd %u",
		    hdr->vnch_command);
		return (VIRTIO_NET_CQ_ERR);
	}

	return (VIRTIO_NET_CQ_OK);
}

static void
pci_viona_control(struct vqueue_info *vq)
{
	struct iovec iov[VIONA_CTLQ_MAXSEGS];
	virtio_net_ctrl_hdr_t hdr;
	struct vi_req req = { 0 };
	iov_bunch_t iob;
	uint8_t *ackp;
	uint32_t wlen = 0;
	size_t len;
	int niov;

	niov = vq_getchain(vq, iov, VIONA_CTLQ_MAXSEGS, &req);
	assert(niov >= 1 && niov <= VIONA_CTLQ_MAXSEGS);

	/*
	 * Since we support the modern interface we must accept a flexible
	 * layout here. Even with that we can do some basic checks - there have
	 * to be at least two descriptors and only a single writable one sized
	 * for one byte. Check the incoming message to make sure it matches
	 * this layout and drop the entire chain if not.
	 */
	if (niov < 2 || req.writable != 1 || req.readable + 1 != niov ||
	    iov[req.readable].iov_len != sizeof (uint8_t)) {
		EPRINTLN("viona: bad control chain, niov=0x%x, w=0x%x, r=0x%x",
		    niov, req.writable, req.readable);
		goto drop;
	}

	len = iov_bunch_init(&iob, iov, niov);
	if (!iov_bunch_copy(&iob, &hdr, sizeof (hdr))) {
		EPRINTLN("viona: control header copy failed, len=0x%x", len);
		goto drop;
	}

	/*
	 * Writable iovecs start at iov[req.readable], and we've already
	 * checked that there is only one writable, it's at the end, and the
	 * right size; it's the acknowledgement byte.
	 */
	ackp = (uint8_t *)iov[req.readable].iov_base;
	iob.ib_remain--;

	switch (hdr.vnch_class) {
	case VIRTIO_NET_CTRL_RX:
		*ackp = pci_viona_control_rx(vq, &hdr, &iob);
		break;
	case VIRTIO_NET_CTRL_MAC:
		*ackp = pci_viona_control_mac(vq, &hdr, &iob);
		break;
	case VIRTIO_NET_CTRL_MQ:
		*ackp = pci_viona_control_mq(vq, &hdr, &iob);
		break;
	default:
		EPRINTLN("viona: unrecognised control class %u, cmd %u",
		    hdr.vnch_class, hdr.vnch_command);
		*ackp = VIRTIO_NET_CQ_ERR;
		break;
	}

	/* We've written the status byte */
	wlen++;

drop:
	vq_relchain(vq, req.idx, wlen);
}

static void
pci_viona_process_ctrlq(struct vqueue_info *vq)
{
	for (;;) {
		vq_kick_disable(vq);

		while (vq_has_descs(vq))
			pci_viona_control(vq);

		vq_kick_enable(vq);

		/*
		 * One more check in case a late addition raced with
		 * re-enabling kicks. Note that vq_kick_enable() includes a
		 * memory barrier.
		 */

		if (!vq_has_descs(vq))
			break;
	}

	vq_endchains(vq, /* used_all_avail= */1);
}

static void *
pci_viona_poll_thread(void *param)
{
	struct pci_viona_softc *sc = param;
	pollfd_t pollset;
	const int fd = sc->vsc_vnafd;

	pollset.fd = fd;
	pollset.events = POLLRDBAND;

	for (;;) {
		if (poll(&pollset, 1, -1) < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				WPRINTF("pci_viona_poll_thread poll() error %d",
				    errno);
				break;
			}
		}
		if (pollset.revents & POLLRDBAND) {
			uint_t i;
			int entries;
			bool assert_lintr = false;
			const bool do_msix = pci_msix_enabled(sc->vsc_vs.vs_pi);
			vioc_intr_poll_mq_t vipm;

			vipm.vipm_nrings = VIONA_USABLE_RINGS(sc);

			entries = ioctl(fd, VNA_IOC_INTR_POLL_MQ, &vipm);
			for (i = 0; entries > 0 && i < vipm.vipm_nrings &&
			    i < VIONA_USABLE_RINGS(sc); i++) {
				if (!VIONA_INTR_TEST(&vipm, i))
					continue;
				entries--;
				if (do_msix) {
					pci_generate_msix(sc->vsc_vs.vs_pi,
					    sc->vsc_queues[i].vq_msix_idx);
				} else {
					assert_lintr = true;
				}
				if (ioctl(fd, VNA_IOC_RING_INTR_CLR, i) != 0) {
					WPRINTF("ioctl viona vq %d intr "
					    "clear failed %d", i, errno);
				}
			}
			if (assert_lintr) {
				pthread_mutex_lock(&sc->vsc_mtx);
				sc->vsc_vs.vs_isr |= VIRTIO_PCI_ISR_INTR;
				pci_lintr_assert(sc->vsc_vs.vs_pi);
				pthread_mutex_unlock(&sc->vsc_mtx);
			}
		}
	}

	pthread_exit(NULL);
}

static void
pci_viona_ring_init(void *vsc, uint64_t pfn, bool modern)
{
	struct pci_viona_softc *sc = vsc;
	int qnum = sc->vsc_vs.vs_curq;
	struct vqueue_info *vq = &sc->vsc_queues[qnum];
	vioc_ring_init_modern_t vna_rim = { 0 };
	int error;
	const bool ctlq = VIONA_RING_CTLQ(sc, qnum);

	DPRINTF("viona: ring init 0x%x", qnum);

	if (!ctlq && !VIONA_RING_VALID(sc, qnum)) {
		DPRINTF("viona: bad ring 0x%d", qnum);
		return;
	}

	if (modern)
		vi_vq_init(&sc->vsc_vs);
	else
		vi_legacy_vq_init(&sc->vsc_vs, pfn);

	if (ctlq)
		return;

	vna_rim.rim_index = qnum;
	vna_rim.rim_qsize = vq->vq_qsize;
	vna_rim.rim_qaddr_desc = vq->vq_desc_gpa;
	vna_rim.rim_qaddr_avail = vq->vq_avail_gpa;
	vna_rim.rim_qaddr_used = vq->vq_used_gpa;

	error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_INIT_MODERN, &vna_rim);

	if (error != 0) {
		WPRINTF("ioctl viona ring 0x%x init failed %d", qnum, errno);
	}
}

static int
pci_viona_viona_init(struct vmctx *ctx, struct pci_viona_softc *sc)
{
	vioc_create_t		vna_create;
	int			error, version;

	sc->vsc_vnafd = open("/dev/viona", O_RDWR | O_EXCL);
	if (sc->vsc_vnafd == -1) {
		WPRINTF("open viona ctl failed: %d", errno);
		return (-1);
	}

	version = ioctl(sc->vsc_vnafd, VNA_IOC_VERSION, 0);
	if (version != VIONA_CURRENT_INTERFACE_VERSION) {
		(void) close(sc->vsc_vnafd);
		WPRINTF(
		    "ioctl interface version %d != expected %d",
		    version, VIONA_CURRENT_INTERFACE_VERSION);
		return (-1);
	}

	vna_create.c_linkid = sc->vsc_linkid;
	vna_create.c_vmfd = vm_get_device_fd(ctx);
	error = ioctl(sc->vsc_vnafd, VNA_IOC_CREATE, &vna_create);
	if (error != 0) {
		(void) close(sc->vsc_vnafd);
		WPRINTF("ioctl viona create failed %d", errno);
		return (-1);
	}

	return (0);
}

static int
pci_viona_legacy_config(nvlist_t *nvl, const char *opt)
{
	char *config, *name, *tofree, *value;

	if (opt == NULL)
		return (0);

	config = tofree = strdup(opt);
	while ((name = strsep(&config, ",")) != NULL) {
		value = strchr(name, '=');
		if (value != NULL) {
			*value++ = '\0';
			set_config_value_node(nvl, name, value);
		} else {
			set_config_value_node(nvl, "vnic", name);
		}
	}
	free(tofree);
	return (0);
}

static int
pci_viona_parse_opts(struct pci_viona_softc *sc, nvlist_t *nvl)
{
	const char *value, *errstr;
	long long num;
	int err = 0;

	sc->vsc_vq_size = VIONA_RINGSZ;
	sc->vsc_config.vnc_max_qpair = VIONA_DEFAULT_MAX_QPAIR;
	sc->vsc_feature_mask = 0;
	sc->vsc_linkname[0] = '\0';

	value = get_config_value_node(nvl, "feature_mask");
	if (value != NULL) {
		num = strtonumx(value, 0, UINT64_MAX, &errstr, 0);
		if (errstr != NULL) {
			EPRINTLN("viona: invalid feature_mask '%s': %s",
			    value, errstr);
			err = -1;
		} else {
			sc->vsc_feature_mask = num;
		}
	}

	value = get_config_value_node(nvl, "vqsize");
	if (value != NULL) {
		num = strtonumx(value, 2, 32768, &errstr, 0);
		if (errstr != NULL) {
			EPRINTLN("viona: invalid vqsize '%s': %s",
			    value, errstr);
			err = -1;
		} else if ((1 << (ffs(num) - 1)) != num) {
			EPRINTLN("viona: vqsize '%s' must be power of 2",
			    value);
			err = -1;
		} else {
			sc->vsc_vq_size = num;
		}
	}

	value = get_config_value_node(nvl, "qpair");
	if (value != NULL) {
		num = strtonumx(value, VIONA_MIN_QPAIR, VIONA_MAX_QPAIR,
		    &errstr, 0);
		if (errstr != NULL) {
			EPRINTLN("viona: invalid qpair '%s': %s",
			    value, errstr);
			err = -1;
		} else {
			sc->vsc_config.vnc_max_qpair = num;
		}
	}

	value = get_config_value_node(nvl, "vnic");
	if (value == NULL) {
		EPRINTLN("viona: vnic name required");
		err = -1;
	} else {
		(void) strlcpy(sc->vsc_linkname, value, MAXLINKNAMELEN);
	}

	DPRINTF(
	    "viona=%p dev=%s vqsize=0x%x qpair=0x%x feature_mask=0x%" PRIx64,
	    sc, sc->vsc_linkname, sc->vsc_vq_size,
	    sc->vsc_config.vnc_max_qpair, sc->vsc_feature_mask);
	return (err);
}

static uint16_t
pci_viona_query_mtu(dladm_handle_t handle, datalink_id_t linkid)
{
	char buf[DLADM_PROP_VAL_MAX];
	char *propval = buf;
	uint_t propcnt = 1;

	if (dladm_get_linkprop(handle, linkid, DLADM_PROP_VAL_CURRENT, "mtu",
	    &propval, &propcnt) == DLADM_STATUS_OK && propcnt == 1) {
		ulong_t parsed = strtoul(buf, NULL, 10);

		/*
		 * The virtio spec notes that for devices implementing
		 * VIRTIO_NET_F_MTU, that the noted MTU MUST be between
		 * 68-65535, inclusive.
		 */
		if (parsed >= 68 && parsed <= 65535)
			return (parsed);
	}

	/*
	 * Default to 1500 if query is unsuccessful or the result is out of
	 * bounds.
	 */
	return (1500);
}

static int
pci_viona_free_softstate(struct pci_viona_softc *sc, int err)
{
	pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc->vsc_queues);
	free(sc);

	return (err);
}

static int
pci_viona_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	dladm_handle_t		handle;
	dladm_status_t		status;
	dladm_vnic_attr_t	attr;
	char			errmsg[DLADM_STRSIZE];
	char			tname[MAXCOMLEN + 1];
	int			error;
	struct			pci_viona_softc *sc;
	struct			virtio_consts *vc;
	const char		*vnic;
	pthread_t		tid;

	vnic = get_config_value_node(nvl, "vnic");
	if (vnic == NULL) {
		WPRINTF("virtio-viona: vnic required");
		return (1);
	}

	sc = calloc(1, sizeof (struct pci_viona_softc));
	if (sc == NULL) {
		WPRINTF("Failed to allocate memory for soft state");
		return (1);
	}
	vc = &sc->vsc_consts;
	*vc = viona_vi_consts;

	pthread_mutex_init(&sc->vsc_mtx, NULL);

	if (get_config_bool_default("viona.debug", false))
		pci_viona_debug = 1;
	vi_set_debug(&sc->vsc_vs, pci_viona_debug);

	if (pci_viona_parse_opts(sc, nvl) != 0)
		return (pci_viona_free_softstate(sc, 1));

	/* Add one for the control queue */
	vc->vc_max_nvq = VIONA_P2QS(sc->vsc_config.vnc_max_qpair) + 1;

	if ((status = dladm_open(&handle)) != DLADM_STATUS_OK) {
		WPRINTF("could not open /dev/dld");
		return (pci_viona_free_softstate(sc, 1));
	}

	if ((status = dladm_name2info(handle, sc->vsc_linkname, &sc->vsc_linkid,
	    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
		WPRINTF("dladm_name2info() for %s failed: %s", vnic,
		    dladm_status2str(status, errmsg));
		dladm_close(handle);
		return (pci_viona_free_softstate(sc, 1));
	}

	if ((status = dladm_vnic_info(handle, sc->vsc_linkid, &attr,
	    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
		WPRINTF("dladm_vnic_info() for %s failed: %s", vnic,
		    dladm_status2str(status, errmsg));
		dladm_close(handle);
		return (pci_viona_free_softstate(sc, 1));
	}
	memcpy(sc->vsc_config.vnc_macaddr, attr.va_mac_addr, ETHERADDRL);
	sc->vsc_config.vnc_status = VIRTIO_NET_S_LINK_UP; /* link always up */
	sc->vsc_config.vnc_mtu = pci_viona_query_mtu(handle, sc->vsc_linkid);
	dladm_close(handle);

	error = pci_viona_viona_init(pi->pi_vmctx, sc);
	if (error != 0)
		return (pci_viona_free_softstate(sc, 1));

	if (ioctl(sc->vsc_vnafd, VNA_IOC_SET_MTU,
	    sc->vsc_config.vnc_mtu) != 0) {
		WPRINTF("error setting viona MTU(%u): %s",
		    sc->vsc_config.vnc_mtu, strerror(errno));
	}

	/* link virtio to softc */
	vi_softc_linkup(&sc->vsc_vs, vc, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	/*
	 * We initially need to configure a single queue pair. Some legacy
	 * drivers will set these up before completing feature negotiation,
	 * which is before we know if they support multi-queue.
	 */
	if (!pci_viona_qalloc(sc, 1))
		return (pci_viona_free_softstate(sc, 1));
	/* Until the guest tells us otherwise, we'll only use a single pair */
	sc->vsc_vq_usepairs = 1;

	error = pthread_create(&tid, NULL, pci_viona_poll_thread, sc);
	assert(error == 0);
	snprintf(tname, sizeof (tname), "vionapoll:%s", vnic);
	pthread_set_name_np(tid, tname);

	/* initialize config space */
	vi_pci_init(pi, VIRTIO_MODE_TRANSITIONAL, VIRTIO_DEV_NET,
	    VIRTIO_ID_NETWORK, PCIC_NETWORK);

	/*
	 * Guests that do not support CTRL_RX_MAC still generally need to
	 * receive multicast packets. Guests that do support this feature will
	 * end up setting this flag indirectly via messages on the control
	 * queue but it does not hurt to default to multicast promiscuity here
	 * and it is what older version of viona did.
	 */
	sc->vsc_promisc_mmac = true;
	pci_viona_eval_promisc(sc);

	/* Viona always uses MSI-X */
	if (!vi_intr_init(&sc->vsc_vs, false, true))
		return (pci_viona_free_softstate(sc, 1));

	if (!vi_pcibar_setup(&sc->vsc_vs))
		return (pci_viona_free_softstate(sc, 1));

	return (0);
}

static int
pci_viona_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_viona_softc *sc = vsc;
	void *ptr;

	/* We will only ever end up here with an 8, 16 or 32-bit size */
	ASSERT(size == 1 || size == 2 || size == 4);

	/*
	 * The driver is allowed to change the MAC address.
	 * vnc_macaddr is the first element of vsc_config
	 */
	if (offset < (int)sizeof (sc->vsc_config.vnc_macaddr) &&
	    offset + size <= (int)sizeof (sc->vsc_config.vnc_macaddr)) {
		ptr = &sc->vsc_config.vnc_macaddr[offset];
		memcpy(ptr, &value, size);
		vq_devcfg_changed(&sc->vsc_vs);
	} else {
		/* silently ignore other writes */
		DPRINTF("viona: write to readonly reg 0x%x", offset);
	}

	return (0);
}

static int
pci_viona_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_viona_softc *sc = vsc;
	void *ptr;

	ptr = (uint8_t *)&sc->vsc_config + offset;
	memcpy(retval, ptr, size);
	return (0);
}

static void
pci_viona_ring_set_msix(void *vsc, int ring)
{
	struct pci_viona_softc *sc = vsc;
	struct pci_devinst *pi = sc->vsc_vs.vs_pi;
	struct msix_table_entry mte;
	uint16_t tab_index;
	vioc_ring_msi_t vrm;
	int res;

	if (!VIONA_RING_VALID(sc, ring))
		return;

	vrm.rm_index = ring;
	vrm.rm_addr = 0;
	vrm.rm_msg = 0;
	tab_index = sc->vsc_queues[ring].vq_msix_idx;

	if (tab_index != VIRTIO_MSI_NO_VECTOR && sc->vsc_msix_active) {
		mte = pi->pi_msix.table[tab_index];
		if ((mte.vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
			vrm.rm_addr = mte.addr;
			vrm.rm_msg = mte.msg_data;
		}
	}

	DPRINTF("SET MSI ring=0x%x addr=0x%" PRIx64 " msg=0x%" PRIx64,
	    vrm.rm_index, vrm.rm_addr, vrm.rm_msg);

	res = ioctl(sc->vsc_vnafd, VNA_IOC_RING_SET_MSI, &vrm);
	if (res != 0) {
		WPRINTF("ioctl viona set_msi %d failed %d", ring, errno);
	}
}

static void
pci_viona_lintrupdate(struct pci_devinst *pi)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	bool msix_on = false;

	pthread_mutex_lock(&sc->vsc_mtx);
	msix_on = pci_msix_enabled(pi) && (pi->pi_msix.function_mask == 0);
	if ((sc->vsc_msix_active && !msix_on) ||
	    (msix_on && !sc->vsc_msix_active)) {
		DPRINTF("MSIX %u -> %u", sc->vsc_msix_active, msix_on);
		sc->vsc_msix_active = msix_on;
		/* Update in-kernel ring configs */
		for (uint16_t i = 0; i < VIONA_NRINGS(sc); i++)
			pci_viona_ring_set_msix(sc, VIONA_RING(sc, i)->vq_num);
	}
	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_viona_update_msix(void *vsc, uint64_t offset)
{
	struct pci_viona_softc *sc = vsc;
	uint_t tab_index;

	pthread_mutex_lock(&sc->vsc_mtx);
	if (!sc->vsc_msix_active) {
		pthread_mutex_unlock(&sc->vsc_mtx);
		return;
	}

	/*
	 * Rather than update every possible MSI-X vector, cheat and use the
	 * offset to calculate the entry within the table.  Since this should
	 * only be called when a write to the table succeeds, the index should
	 * be valid.
	 */
	tab_index = offset / MSIX_TABLE_ENTRY_SIZE;

	for (uint16_t i = 0; i < VIONA_NRINGS(sc); i++) {
		struct vqueue_info *vq = VIONA_RING(sc, i);

		if (vq->vq_msix_idx == tab_index)
			pci_viona_ring_set_msix(vsc, vq->vq_num);
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_viona_ctlqnotify(void *vsc, struct vqueue_info *vq)
{
	if (vq_has_descs(vq))
		pci_viona_process_ctrlq(vq);
}

static void
pci_viona_qnotify(void *vsc, struct vqueue_info *vq)
{
	struct pci_viona_softc *sc = vsc;
	int ring = vq->vq_num;
	int error;

	if (!VIONA_RING_VALID(sc, ring))
		return;

	error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_KICK, ring);
	if (error != 0)
		WPRINTF("ioctl viona ring 0x%x kick failed %d", ring, errno);
}

static void
pci_viona_baraddr(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	int err;

	DPRINTF("BAR%d ADDRESS %" PRIx64 " (%s)",
	    baridx, address, enabled == 1 ? "enable": "disable");

	switch (baridx) {
	case VIRTIO_LEGACY_BAR: {
		uint64_t ioport;

		if (enabled == 0) {
			err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_IOP, 0);
			if (err != 0)
				WPRINTF("Uninstall ioport hook fail %d", errno);
			break;
		}

		/*
		 * Install ioport hook for virtqueue notification.
		 * This is part of the virtio common configuration area so the
		 * address does not change with MSI-X status.
		 */
		ioport = address + VIRTIO_PCI_QUEUE_NOTIFY;
		err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_IOP, ioport);
		if (err != 0) {
			WPRINTF("Install ioport hook at 0x%x failed %d",
			    ioport, errno);
		}
		break;
	}
	case VIRTIO_MODERN_BAR: {
		virtio_pci_capcfg_t *cfg;
		vioc_notify_mmio_t vim;

		if (enabled == 0) {
			err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_MMIO, 0);
			if (err != 0)
				WPRINTF("Uninstall MMIO hook fail %d", errno);
			break;
		}

		cfg = vi_pci_cfg_bytype(&sc->vsc_vs, VIRTIO_PCI_CAP_NOTIFY_CFG);
		if (cfg == NULL)
			break;

		vim.vim_address = address + cfg->c_baroff;
		vim.vim_size = cfg->c_barlen;

		DPRINTF("MODERN BAR NOTIFY address 0x%" PRIx64 " size 0x%x",
		    vim.vim_address, vim.vim_size);

		err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_MMIO, &vim);
		if (err != 0) {
			WPRINTF(
			    "Install MMIO hook at 0x%" PRIx64 "+0x%x failed %d",
			    vim.vim_address, vim.vim_size, errno);
		}
		break;
	}
	default:
		break;
	}
}

static uint64_t
pci_viona_get_hv_features(void *vsc, bool modern)
{
	struct pci_viona_softc *sc = vsc;
	uint64_t value;
	int err;

	err = ioctl(sc->vsc_vnafd, VNA_IOC_GET_FEATURES, &value);
	if (err != 0)
		WPRINTF("ioctl get host features returned err = %d", errno);
	/*
	 * Supplementary device capabilities provided in the userspace
	 * component.
	 */
	value |= VIRTIO_NET_F_MAC;
	value |= VIRTIO_NET_F_STATUS;
	value |= VIRTIO_NET_F_MTU;
	value |= VIRTIO_NET_F_CTRL_VQ;
	value |= VIRTIO_NET_F_CTRL_RX;
	value |= VIRTIO_NET_F_MQ;

	value &= ~sc->vsc_feature_mask;

	if (modern) {
		value |= VIRTIO_F_VERSION_1;
		sc->vsc_consts.vc_hv_caps_modern = value;
	} else {
		/*
		 * To be a conforming transitional device we must support
		 * arbitrary descriptor layouts on the legacy interface. The
		 * specification is a little ambiguous as it mandates this but
		 * also provides details on how descriptors should be laid out
		 * by transitional drivers that don't negotiate this. Since we
		 * don't make any assumptions about descriptor layout we may as
		 * well set this.
		 */
		value |= VIRTIO_F_ANY_LAYOUT;
		sc->vsc_consts.vc_hv_caps_legacy = value;
	}

	return (value);
}

static void
pci_viona_set_hv_features(void *vsc, uint64_t *value)
{
	struct pci_viona_softc *sc = vsc;
	int err;

	*value &= ~sc->vsc_feature_mask;
	err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_FEATURES, value);
	if (err != 0)
		WPRINTF("ioctl feature negotiation returned err = %d", errno);

	if (*value & VIRTIO_NET_F_MQ) {
		/*
		 * If multi-queue is negotiated then we need to provision all
		 * of the queues we can support. Even if the guest chooses not
		 * to use all of them it will still set them up.
		 */
		DPRINTF("Going MULTIQUEUE with 0x%x pairs!",
		    sc->vsc_config.vnc_max_qpair);
		if (!pci_viona_qalloc(sc, sc->vsc_config.vnc_max_qpair)) {
			vi_error(&sc->vsc_vs,
			    "Failed to allocate 0x%x queue pairs",
			    sc->vsc_config.vnc_max_qpair);
		}
	}
}

struct pci_devemu pci_de_viona = {
	.pe_emu =		"virtio-net-viona",
	.pe_init =		pci_viona_init,
	.pe_legacy_config =	pci_viona_legacy_config,
	.pe_cfgwrite =		vi_pci_cfgwrite,
	.pe_cfgread =		vi_pci_cfgread,
	.pe_barwrite =		vi_pci_write,
	.pe_barread =		vi_pci_read,
	.pe_baraddr =		pci_viona_baraddr,
	.pe_lintrupdate =	pci_viona_lintrupdate
};
PCI_EMUL_SET(pci_de_viona);
