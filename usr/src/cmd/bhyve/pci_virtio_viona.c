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
 */

#include <sys/cdefs.h>

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

#define	VIONA_RINGSZ		1024
#define	VIONA_CTLQ_SIZE		64
#define	VIONA_CTLQ_MAXSEGS	32

/*
 * PCI config-space register offsets
 */
#define	VIONA_R_CFG0	24
#define	VIONA_R_CFG1	25
#define	VIONA_R_CFG2	26
#define	VIONA_R_CFG3	27
#define	VIONA_R_CFG4	28
#define	VIONA_R_CFG5	29
#define	VIONA_R_CFG6	30
#define	VIONA_R_CFG7	31
#define	VIONA_R_MAX	31

#define	VIONA_REGSZ	(VIONA_R_MAX + 1)

/*
 * Queue definitions.
 */
#define	VIONA_RXQ	0
#define	VIONA_TXQ	1
#define	VIONA_CTLQ	2

#define	VIONA_MAXQ	3

/*
 * Supplementary host capabilities provided in the userspace component.
 */
#define	VIONA_S_HOSTCAPS_USERSPACE	(	\
	VIRTIO_NET_F_CTRL_VQ |			\
	VIRTIO_NET_F_CTRL_RX)

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
	struct vqueue_info	vsc_queues[VIONA_MAXQ];
	pthread_mutex_t		vsc_mtx;

	datalink_id_t	vsc_linkid;
	int		vsc_vnafd;

	/* Configurable parameters */
	char		vsc_linkname[MAXLINKNAMELEN];
	uint32_t	vsc_feature_mask;
	uint16_t	vsc_vq_size;

	uint8_t		vsc_macaddr[6];

	bool		vsc_resetting;
	bool		vsc_msix_active;

	viona_promisc_t	vsc_promisc;		/* Current promisc mode */
	bool		vsc_promisc_promisc;	/* PROMISC enabled */
	bool		vsc_promisc_allmulti;	/* ALLMULTI enabled */
	bool		vsc_promisc_umac;	/* unicast MACs sent */
	bool		vsc_promisc_mmac;	/* multicast MACs sent */
};

static struct virtio_consts viona_vi_consts = {
	.vc_name		= "viona",
	.vc_nvq			= VIONA_MAXQ,
	/*
	 * We use the common bhyve virtio framework so that we can call
	 * the utility functions to work with the queues handled in userspace.
	 * The framework PCI read/write functions are not used so these
	 * callbacks will not be invoked.
	 */
	.vc_cfgsize		= 0,
	.vc_reset		= NULL,
	.vc_qnotify		= NULL,
	.vc_cfgread		= NULL,
	.vc_cfgwrite		= NULL,
	.vc_apply_features	= NULL,
	/*
	 * The following field is populated using the response from the
	 * viona driver during initialisation, augmented with the additional
	 * capabilities emulated in userspace.
	 */
	.vc_hv_caps		= 0,
};

/*
 * Return the size of IO BAR that maps virtio header and device specific
 * region. The size would vary depending on whether MSI-X is enabled or
 * not.
 */
static uint64_t
pci_viona_iosize(struct pci_devinst *pi)
{
	if (pci_msix_enabled(pi)) {
		return (VIONA_REGSZ);
	} else {
		return (VIONA_REGSZ -
		    (VIRTIO_PCI_CONFIG_OFF(1) - VIRTIO_PCI_CONFIG_OFF(0)));
	}
}

static uint16_t
pci_viona_qsize(struct pci_viona_softc *sc, int qnum)
{
	if (qnum == VIONA_CTLQ)
		return (VIONA_CTLQ_SIZE);

	return (sc->vsc_vq_size);
}

static void
pci_viona_ring_reset(struct pci_viona_softc *sc, int ring)
{
	assert(ring < VIONA_MAXQ);

	switch (ring) {
	case VIONA_RXQ:
	case VIONA_TXQ:
		break;
	case VIONA_CTLQ:
	default:
		return;
	}

	for (;;) {
		int res;

		res = ioctl(sc->vsc_vnafd, VNA_IOC_RING_RESET, ring);
		if (res == 0) {
			break;
		} else if (errno != EINTR) {
			WPRINTF("ioctl viona ring %d reset failed %d",
			    ring, errno);
			return;
		}
	}
}

static void
pci_viona_update_status(struct pci_viona_softc *sc, uint32_t value)
{

	if (value == 0) {
		DPRINTF("viona: device reset requested !");

		vi_reset_dev(&sc->vsc_vs);
		pci_viona_ring_reset(sc, VIONA_RXQ);
		pci_viona_ring_reset(sc, VIONA_TXQ);
	}

	sc->vsc_vs.vs_status = value;
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
    struct iovec *iov, size_t niov)
{
	struct pci_viona_softc *sc = (struct pci_viona_softc *)vq->vq_vs;
	uint8_t v;

	if (iov[0].iov_len != sizeof (uint8_t) || niov != 1) {
		EPRINTLN("viona: bad control RX data");
		return (VIRTIO_NET_CQ_ERR);
	}

	v = *(uint8_t *)iov[0].iov_base;

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
pci_viona_control_mac_dump(const char *tag, const struct iovec *iov)
{
	virtio_net_ctrl_mac_t *table = (virtio_net_ctrl_mac_t *)iov->iov_base;
	ether_addr_t *mac = &table->vncm_mac;

	DPRINTF("-- %s MAC TABLE (entries: %u)", tag, table->vncm_entries);

	if (table->vncm_entries * ETHERADDRL !=
	    iov->iov_len - sizeof (table->vncm_entries)) {
		DPRINTF("   Bad table size %u", iov->iov_len);
		return;
	}

	for (uint32_t i = 0; i < table->vncm_entries; i++) {
		DPRINTF("   [%2d] %s", i, ether_ntoa((struct ether_addr *)mac));
		mac++;
	}
}

static uint8_t
pci_viona_control_mac(struct vqueue_info *vq, const virtio_net_ctrl_hdr_t *hdr,
    struct iovec *iov, size_t niov)
{
	struct pci_viona_softc *sc = (struct pci_viona_softc *)vq->vq_vs;

	switch (hdr->vnch_command) {
	case VIRTIO_NET_CTRL_MAC_TABLE_SET: {
		virtio_net_ctrl_mac_t *table;

		DPRINTF("viona: ctrl MAC table set");

		if (niov != 2) {
			EPRINTLN("viona: bad control MAC data");
			return (VIRTIO_NET_CQ_ERR);
		}

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
		table = (virtio_net_ctrl_mac_t *)iov[0].iov_base;
		sc->vsc_promisc_umac = (table->vncm_entries != 0);
		if (pci_viona_debug)
			pci_viona_control_mac_dump("UNICAST", &iov[0]);

		/* Multicast MAC table */
		table = (virtio_net_ctrl_mac_t *)iov[1].iov_base;
		sc->vsc_promisc_mmac = (table->vncm_entries != 0);
		if (pci_viona_debug)
			pci_viona_control_mac_dump("MULTICAST", &iov[1]);

		break;
	}
	case VIRTIO_NET_CTRL_MAC_ADDR_SET:
		/* disallow setting the primary filter MAC address */
		DPRINTF("viona: ctrl MAC addr set %d", niov);
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

static void
pci_viona_control(struct vqueue_info *vq)
{
	struct iovec iov[VIONA_CTLQ_MAXSEGS + 1];
	const virtio_net_ctrl_hdr_t *hdr;
	struct iovec *siov = iov;
	struct vi_req req = { 0 };
	uint8_t *ackp;
	size_t nsiov;
	uint32_t len;
	int n;

	n = vq_getchain(vq, iov, VIONA_CTLQ_MAXSEGS, &req);

	assert(n >= 1 && n <= VIONA_CTLQ_MAXSEGS);

	/*
	 * Since we have not negotiated VIRTIO_F_ANY_LAYOUT, we expect the
	 * control message to be laid out in at least three descriptors as
	 * follows:
	 *	header		- sizeof (virtio_net_ctrl_hdr_t)
	 *	data[]		- at least one descriptor, varying size
	 *	ack		- uint8_t, flagged as writable
	 * Check the incoming message to make sure it matches this layout and
	 * drop the entire chain if not.
	 */
	if (n < 3 || req.writable != 1 || req.readable + 1 != n ||
	    iov[req.readable].iov_len != sizeof (uint8_t)) {
		EPRINTLN("viona: bad control chain, len=%d, w=%d, r=%d",
		    n, req.writable, req.readable);
		goto drop;
	}

	hdr = (const virtio_net_ctrl_hdr_t *)iov[0].iov_base;
	if (iov[0].iov_len < sizeof (virtio_net_ctrl_hdr_t)) {
		EPRINTLN("viona: control header too short: %u", iov[0].iov_len);
		goto drop;
	}

	/*
	 * Writable iovecs start at iov[req.readable], and we've already
	 * checked that there is only one writable, it's at the end, and the
	 * right size; it's the acknowledgement byte.
	 */
	ackp = (uint8_t *)iov[req.readable].iov_base;

	siov = &iov[1];
	nsiov = n - 2;

	switch (hdr->vnch_class) {
	case VIRTIO_NET_CTRL_RX:
		*ackp = pci_viona_control_rx(vq, hdr, siov, nsiov);
		break;
	case VIRTIO_NET_CTRL_MAC:
		*ackp = pci_viona_control_mac(vq, hdr, siov, nsiov);
		break;
	default:
		EPRINTLN("viona: unrecognised control class %u, cmd %u",
		    hdr->vnch_class, hdr->vnch_command);
		*ackp = VIRTIO_NET_CQ_ERR;
		break;
	}

drop:
	len = 0;
	for (uint_t i = 0; i < n; i++)
		len += iov[i].iov_len;

	vq_relchain(vq, req.idx, len);
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
			vioc_intr_poll_t vip;
			uint_t i;
			int res;
			bool assert_lintr = false;
			const bool do_msix = pci_msix_enabled(sc->vsc_vs.vs_pi);

			res = ioctl(fd, VNA_IOC_INTR_POLL, &vip);
			for (i = 0; res > 0 && i < VIONA_VQ_MAX; i++) {
				if (vip.vip_status[i] == 0) {
					continue;
				}
				if (do_msix) {
					pci_generate_msix(sc->vsc_vs.vs_pi,
					    sc->vsc_queues[i].vq_msix_idx);
				} else {
					assert_lintr = true;
				}
				res = ioctl(fd, VNA_IOC_RING_INTR_CLR, i);
				if (res != 0) {
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
pci_viona_ring_init(struct pci_viona_softc *sc, uint64_t pfn)
{
	int			qnum = sc->vsc_vs.vs_curq;
	vioc_ring_init_t	vna_ri;
	int			error;

	assert(qnum < VIONA_MAXQ);

	if (qnum == VIONA_CTLQ) {
		vi_vq_init(&sc->vsc_vs, pfn);
		return;
	}

	sc->vsc_queues[qnum].vq_pfn = (pfn << VRING_PFN);
	vna_ri.ri_index = qnum;
	vna_ri.ri_qsize = pci_viona_qsize(sc, qnum);
	vna_ri.ri_qaddr = (pfn << VRING_PFN);
	error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_INIT, &vna_ri);

	if (error != 0) {
		WPRINTF("ioctl viona ring %u init failed %d", qnum, errno);
	}
}

static int
pci_viona_viona_init(struct vmctx *ctx, struct pci_viona_softc *sc)
{
	vioc_create_t		vna_create;
	int			error;

	sc->vsc_vnafd = open("/dev/viona", O_RDWR | O_EXCL);
	if (sc->vsc_vnafd == -1) {
		WPRINTF("open viona ctl failed: %d", errno);
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
	const char *value;
	int err = 0;

	sc->vsc_vq_size = VIONA_RINGSZ;
	sc->vsc_feature_mask = 0;
	sc->vsc_linkname[0] = '\0';

	value = get_config_value_node(nvl, "feature_mask");
	if (value != NULL) {
		long num;

		errno = 0;
		num = strtol(value, NULL, 0);
		if (errno != 0 || num < 0) {
			fprintf(stderr,
			    "viona: invalid mask '%s'", value);
		} else {
			sc->vsc_feature_mask = num;
		}
	}

	value = get_config_value_node(nvl, "vqsize");
	if (value != NULL) {
		long num;

		errno = 0;
		num = strtol(value, NULL, 0);
		if (errno != 0) {
			fprintf(stderr,
			    "viona: invalid vsqize '%s'", value);
			err = -1;
		} else if (num <= 2 || num > 32768) {
			fprintf(stderr,
			    "viona: vqsize out of range", num);
			err = -1;
		} else if ((1 << (ffs(num) - 1)) != num) {
			fprintf(stderr,
			    "viona: vqsize must be power of 2", num);
			err = -1;
		} else {
			sc->vsc_vq_size = num;
		}
	}

	value = get_config_value_node(nvl, "vnic");
	if (value == NULL) {
		fprintf(stderr, "viona: vnic name required");
		err = -1;
	} else {
		(void) strlcpy(sc->vsc_linkname, value, MAXLINKNAMELEN);
	}

	DPRINTF("viona=%p dev=%s vqsize=%x feature_mask=%x", sc,
	    sc->vsc_linkname, sc->vsc_vq_size, sc->vsc_feature_mask);
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
	int error, i;
	struct pci_viona_softc *sc;
	const char *vnic;
	pthread_t tid;

	if (get_config_bool_default("viona.debug", false))
		pci_viona_debug = 1;

	vnic = get_config_value_node(nvl, "vnic");
	if (vnic == NULL) {
		WPRINTF("virtio-viona: vnic required");
		return (1);
	}

	sc = malloc(sizeof (struct pci_viona_softc));
	memset(sc, 0, sizeof (struct pci_viona_softc));

	if (pci_viona_parse_opts(sc, nvl) != 0) {
		free(sc);
		return (1);
	}

	if ((status = dladm_open(&handle)) != DLADM_STATUS_OK) {
		WPRINTF("could not open /dev/dld");
		free(sc);
		return (1);
	}

	if ((status = dladm_name2info(handle, sc->vsc_linkname, &sc->vsc_linkid,
	    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
		WPRINTF("dladm_name2info() for %s failed: %s", vnic,
		    dladm_status2str(status, errmsg));
		dladm_close(handle);
		free(sc);
		return (1);
	}

	if ((status = dladm_vnic_info(handle, sc->vsc_linkid, &attr,
	    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK) {
		WPRINTF("dladm_vnic_info() for %s failed: %s", vnic,
		    dladm_status2str(status, errmsg));
		dladm_close(handle);
		free(sc);
		return (1);
	}

	memcpy(sc->vsc_macaddr, attr.va_mac_addr, ETHERADDRL);

	dladm_close(handle);

	error = pci_viona_viona_init(pi->pi_vmctx, sc);
	if (error != 0) {
		free(sc);
		return (1);
	}

	error = pthread_create(&tid, NULL, pci_viona_poll_thread, sc);
	assert(error == 0);
	snprintf(tname, sizeof (tname), "vionapoll:%s", vnic);
	pthread_set_name_np(tid, tname);

	/* initialize config space */
	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_NET);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);

	sc->vsc_consts = viona_vi_consts;
	pthread_mutex_init(&sc->vsc_mtx, NULL);

	/*
	 * The RX and TX queues are handled in the kernel component of
	 * viona; however The control queue is emulated in userspace.
	 */
	sc->vsc_queues[VIONA_CTLQ].vq_qsize = pci_viona_qsize(sc, VIONA_CTLQ);

	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi, sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	/*
	 * Guests that do not support CTRL_RX_MAC still generally need to
	 * receive multicast packets. Guests that do support this feature will
	 * end up setting this flag indirectly via messages on the control
	 * queue but it does not hurt to default to multicast promiscuity here
	 * and it is what older version of viona did.
	 */
	sc->vsc_promisc_mmac = true;
	pci_viona_eval_promisc(sc);

	/* MSI-X support */
	for (i = 0; i < VIONA_MAXQ; i++)
		sc->vsc_queues[i].vq_msix_idx = VIRTIO_MSI_NO_VECTOR;

	/* BAR 1 used to map MSI-X table and PBA */
	if (pci_emul_add_msixcap(pi, VIONA_MAXQ, 1)) {
		free(sc);
		return (1);
	}

	/* BAR 0 for legacy-style virtio register access. */
	error = pci_emul_alloc_bar(pi, 0, PCIBAR_IO, VIONA_REGSZ);
	if (error != 0) {
		WPRINTF("could not allocate virtio BAR");
		free(sc);
		return (1);
	}

	/*
	 * Need a legacy interrupt for virtio compliance, even though MSI-X
	 * operation is _strongly_ suggested for adequate performance.
	 */
	pci_lintr_request(pi);

	return (0);
}

static uint64_t
viona_adjust_offset(struct pci_devinst *pi, uint64_t offset)
{
	/*
	 * Device specific offsets used by guest would change based on
	 * whether MSI-X capability is enabled or not
	 */
	if (!pci_msix_enabled(pi)) {
		if (offset >= VIRTIO_PCI_CONFIG_OFF(0)) {
			return (offset + (VIRTIO_PCI_CONFIG_OFF(1) -
			    VIRTIO_PCI_CONFIG_OFF(0)));
		}
	}

	return (offset);
}

static void
pci_viona_ring_set_msix(struct pci_devinst *pi, uint_t ring)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	struct msix_table_entry mte;
	uint16_t tab_index;
	vioc_ring_msi_t vrm;
	int res;

	if (ring == VIONA_CTLQ)
		return;

	assert(ring <= VIONA_VQ_TX);

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
		uint_t i;

		sc->vsc_msix_active = msix_on;
		/* Update in-kernel ring configs */
		for (i = 0; i <= VIONA_VQ_TX; i++) {
			pci_viona_ring_set_msix(pi, i);
		}
	}
	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_viona_msix_update(struct pci_devinst *pi, uint64_t offset)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	uint_t tab_index, i;

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

	for (i = 0; i <= VIONA_VQ_TX; i++) {
		if (sc->vsc_queues[i].vq_msix_idx != tab_index) {
			continue;
		}
		pci_viona_ring_set_msix(pi, i);
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
}

static void
pci_viona_qnotify(struct pci_viona_softc *sc, int ring)
{
	int error;

	switch (ring) {
	case VIONA_TXQ:
	case VIONA_RXQ:
		error = ioctl(sc->vsc_vnafd, VNA_IOC_RING_KICK, ring);
		if (error != 0) {
			WPRINTF("ioctl viona ring %d kick failed %d",
			    ring, errno);
		}
		break;
	case VIONA_CTLQ: {
		struct vqueue_info *vq = &sc->vsc_queues[VIONA_CTLQ];

		if (vq_has_descs(vq))
			pci_viona_process_ctrlq(vq);
		break;
	}
	}
}

static void
pci_viona_baraddr(struct pci_devinst *pi, int baridx, int enabled,
    uint64_t address)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	uint64_t ioport;
	int error;

	if (baridx != 0)
		return;

	if (enabled == 0) {
		error = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_IOP, 0);
		if (error != 0)
			WPRINTF("uninstall ioport hook failed %d", errno);
		return;
	}

	/*
	 * Install ioport hook for virtqueue notification.
	 * This is part of the virtio common configuration area so the
	 * address does not change with MSI-X status.
	 */
	ioport = address + VIRTIO_PCI_QUEUE_NOTIFY;
	error = ioctl(sc->vsc_vnafd, VNA_IOC_SET_NOTIFY_IOP, ioport);
	if (error != 0) {
		WPRINTF("install ioport hook at %x failed %d",
		    ioport, errno);
	}
}

static void
pci_viona_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	void *ptr;
	int err = 0;

	if (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi)) {
		if (pci_emul_msix_twrite(pi, offset, size, value) == 0) {
			pci_viona_msix_update(pi, offset);
		}
		return;
	}

	assert(baridx == 0);

	if (offset + size > pci_viona_iosize(pi)) {
		DPRINTF("viona_write: 2big, offset %ld size %d",
		    offset, size);
		return;
	}

	pthread_mutex_lock(&sc->vsc_mtx);

	offset = viona_adjust_offset(pi, offset);

	switch (offset) {
	case VIRTIO_PCI_GUEST_FEATURES:
		assert(size == 4);
		value &= ~(sc->vsc_feature_mask);
		err = ioctl(sc->vsc_vnafd, VNA_IOC_SET_FEATURES, &value);
		if (err != 0) {
			WPRINTF("ioctl feature negotiation returned err = %d",
			    errno);
		} else {
			sc->vsc_vs.vs_negotiated_caps = value;
		}
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		assert(size == 4);
		pci_viona_ring_init(sc, value);
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		assert(size == 2);
		assert(value < VIONA_MAXQ);
		sc->vsc_vs.vs_curq = value;
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		assert(size == 2);
		assert(value < VIONA_MAXQ);
		pci_viona_qnotify(sc, value);
		break;
	case VIRTIO_PCI_STATUS:
		assert(size == 1);
		pci_viona_update_status(sc, value);
		break;
	case VIRTIO_MSI_CONFIG_VECTOR:
		assert(size == 2);
		sc->vsc_vs.vs_msix_cfg_idx = value;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		assert(size == 2);
		assert(sc->vsc_vs.vs_curq < VIONA_MAXQ);
		sc->vsc_queues[sc->vsc_vs.vs_curq].vq_msix_idx = value;
		pci_viona_ring_set_msix(pi, sc->vsc_vs.vs_curq);
		break;
	case VIONA_R_CFG0:
	case VIONA_R_CFG1:
	case VIONA_R_CFG2:
	case VIONA_R_CFG3:
	case VIONA_R_CFG4:
	case VIONA_R_CFG5:
		assert((size + offset) <= (VIONA_R_CFG5 + 1));
		ptr = &sc->vsc_macaddr[offset - VIONA_R_CFG0];
		/*
		 * The driver is allowed to change the MAC address
		 */
		sc->vsc_macaddr[offset - VIONA_R_CFG0] = value;
		if (size == 1) {
			*(uint8_t *)ptr = value;
		} else if (size == 2) {
			*(uint16_t *)ptr = value;
		} else {
			*(uint32_t *)ptr = value;
		}
		break;
	case VIRTIO_PCI_HOST_FEATURES:
	case VIRTIO_PCI_QUEUE_NUM:
	case VIRTIO_PCI_ISR:
	case VIONA_R_CFG6:
	case VIONA_R_CFG7:
		DPRINTF("viona: write to readonly reg %ld", offset);
		break;
	default:
		DPRINTF("viona: unknown i/o write offset %ld", offset);
		value = 0;
		break;
	}

	pthread_mutex_unlock(&sc->vsc_mtx);
}

static uint64_t
pci_viona_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct pci_viona_softc *sc = pi->pi_arg;
	void *ptr;
	uint64_t value;
	int err = 0;

	if (baridx == pci_msix_table_bar(pi) ||
	    baridx == pci_msix_pba_bar(pi)) {
		return (pci_emul_msix_tread(pi, offset, size));
	}

	assert(baridx == 0);

	if (offset + size > pci_viona_iosize(pi)) {
		DPRINTF("viona_read: 2big, offset %ld size %d",
		    offset, size);
		return (0);
	}

	pthread_mutex_lock(&sc->vsc_mtx);

	offset = viona_adjust_offset(pi, offset);

	switch (offset) {
	case VIRTIO_PCI_HOST_FEATURES:
		assert(size == 4);
		err = ioctl(sc->vsc_vnafd, VNA_IOC_GET_FEATURES, &value);
		if (err != 0) {
			WPRINTF("ioctl get host features returned err = %d",
			    errno);
		}
		value |= VIONA_S_HOSTCAPS_USERSPACE;
		value &= ~sc->vsc_feature_mask;
		sc->vsc_consts.vc_hv_caps = value;
		break;
	case VIRTIO_PCI_GUEST_FEATURES:
		assert(size == 4);
		value = sc->vsc_vs.vs_negotiated_caps; /* XXX never read ? */
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		assert(size == 4);
		value = sc->vsc_queues[sc->vsc_vs.vs_curq].vq_pfn >> VRING_PFN;
		break;
	case VIRTIO_PCI_QUEUE_NUM:
		assert(size == 2);
		value = pci_viona_qsize(sc, sc->vsc_vs.vs_curq);
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		assert(size == 2);
		value = sc->vsc_vs.vs_curq;  /* XXX never read ? */
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		assert(size == 2);
		value = sc->vsc_vs.vs_curq;  /* XXX never read ? */
		break;
	case VIRTIO_PCI_STATUS:
		assert(size == 1);
		value = sc->vsc_vs.vs_status;
		break;
	case VIRTIO_PCI_ISR:
		assert(size == 1);
		value = sc->vsc_vs.vs_isr;
		sc->vsc_vs.vs_isr = 0;	/* a read clears this flag */
		if (value != 0) {
			pci_lintr_deassert(pi);
		}
		break;
	case VIRTIO_MSI_CONFIG_VECTOR:
		assert(size == 2);
		value = sc->vsc_vs.vs_msix_cfg_idx;
		break;
	case VIRTIO_MSI_QUEUE_VECTOR:
		assert(size == 2);
		assert(sc->vsc_vs.vs_curq < VIONA_MAXQ);
		value = sc->vsc_queues[sc->vsc_vs.vs_curq].vq_msix_idx;
		break;
	case VIONA_R_CFG0:
	case VIONA_R_CFG1:
	case VIONA_R_CFG2:
	case VIONA_R_CFG3:
	case VIONA_R_CFG4:
	case VIONA_R_CFG5:
		assert((size + offset) <= (VIONA_R_CFG5 + 1));
		ptr = &sc->vsc_macaddr[offset - VIONA_R_CFG0];
		if (size == 1) {
			value = *(uint8_t *)ptr;
		} else if (size == 2) {
			value = *(uint16_t *)ptr;
		} else {
			value = *(uint32_t *)ptr;
		}
		break;
	case VIONA_R_CFG6:
		assert(size != 4);
		value = 0x01;	/* XXX link always up */
		break;
	case VIONA_R_CFG7:
		assert(size == 1);
		value = 0;	/* XXX link status in LSB */
		break;
	default:
		DPRINTF("viona: unknown i/o read offset %ld", offset);
		value = 0;
		break;
	}

	pthread_mutex_unlock(&sc->vsc_mtx);

	return (value);
}

struct pci_devemu pci_de_viona = {
	.pe_emu =	"virtio-net-viona",
	.pe_init =	pci_viona_init,
	.pe_legacy_config = pci_viona_legacy_config,
	.pe_barwrite =	pci_viona_write,
	.pe_barread =	pci_viona_read,
	.pe_baraddr =	pci_viona_baraddr,
	.pe_lintrupdate = pci_viona_lintrupdate
};
PCI_EMUL_SET(pci_de_viona);
