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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Xen network backend - mac client edition.
 *
 * A driver that sits above an existing GLDv3/Nemo MAC driver and
 * relays packets to/from that driver from/to a guest domain.
 */

#include "xnb.h"

#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/strsubr.h>
#include <sys/mac.h>
#include <net/if.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>

typedef struct xnbo {
	mac_handle_t		o_mh;
	mac_rx_handle_t		o_mrh;
	const mac_txinfo_t	*o_mtx;
	mac_notify_handle_t	o_mnh;
	boolean_t		o_running;
	boolean_t		o_promiscuous;
	uint32_t		o_hcksum_capab;
} xnbo_t;

static void xnbo_close_mac(xnbo_t *);

/*
 * Packets from the peer come here.  We pass them to the mac device.
 */
static void
xnbo_to_mac(xnb_t *xnbp, mblk_t *mp)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	ASSERT(mp != NULL);

	if (!xnbop->o_running) {
		xnbp->xnb_stat_tx_too_early++;
		goto fail;
	}

	mp = xnbop->o_mtx->mt_fn(xnbop->o_mtx->mt_arg, mp);

	if (mp != NULL) {
		xnbp->xnb_stat_mac_full++;
		goto fail;
	}

	return;

fail:
	freemsgchain(mp);
}

static mblk_t *
xnbo_cksum_from_peer(xnb_t *xnbp, mblk_t *mp, uint16_t flags)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	ASSERT(mp->b_next == NULL);

	if ((flags & NETTXF_csum_blank) != 0) {
		/*
		 * It would be nice to ASSERT that xnbp->xnb_cksum_offload
		 * is TRUE here, but some peers insist on assuming
		 * that it is available even when they have been told
		 * otherwise.
		 *
		 * The checksum in the packet is blank.  Determine
		 * whether we can do hardware offload and, if so,
		 * update the flags on the mblk according.  If not,
		 * calculate and insert the checksum using software.
		 */
		mp = xnb_process_cksum_flags(xnbp, mp,
		    xnbop->o_hcksum_capab);
	}

	return (mp);
}

static uint16_t
xnbo_cksum_to_peer(xnb_t *xnbp, mblk_t *mp)
{
	uint16_t r = 0;

	/*
	 * We might also check for HCK_PARTIALCKSUM here and,
	 * providing that the partial checksum covers the TCP/UDP
	 * payload, return NETRXF_data_validated.
	 *
	 * It seems that it's probably not worthwhile, as even MAC
	 * devices which advertise HCKSUM_INET_PARTIAL in their
	 * capabilities tend to use HCK_FULLCKSUM on the receive side
	 * - they are actually saying that in the output path the
	 * caller must use HCK_PARTIALCKSUM.
	 */

	if (xnbp->xnb_cksum_offload) {
		uint32_t pflags, csum;

		/*
		 * XXPV dme: Pull in improved hcksum_retrieve() from
		 * Crossbow, which gives back the csum in the seventh
		 * argument for HCK_FULLCKSUM.
		 */
		hcksum_retrieve(mp, NULL, NULL, NULL, NULL,
		    NULL, NULL, &pflags);
		csum = DB_CKSUM16(mp);

		/*
		 * If the MAC driver has asserted that the checksum is
		 * good, let the peer know.
		 */
		if (((pflags & HCK_FULLCKSUM) != 0) &&
		    (((pflags & HCK_FULLCKSUM_OK) != 0) ||
		    (csum == 0xffff)))
			r |= NETRXF_data_validated;
	}

	return (r);
}

/*
 * Packets from the mac device come here.  We pass them to the peer.
 */
/*ARGSUSED*/
static void
xnbo_from_mac(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	xnb_t *xnbp = arg;

	mp = xnb_copy_to_peer(xnbp, mp);

	if (mp != NULL)
		freemsgchain(mp);
}

/*
 * Packets from the mac device come here. We pass them to the peer if
 * the destination mac address matches or it's a multicast/broadcast
 * address.
 */
/*ARGSUSED*/
static void
xnbo_from_mac_filter(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	xnb_t *xnbp = arg;
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	mblk_t *next, *keep, *keep_head, *free, *free_head;

	keep = keep_head = free = free_head = NULL;

#define	ADD(list, bp)				\
	if (list != NULL)			\
		list->b_next = bp;		\
	else					\
		list##_head = bp;		\
	list = bp;

	for (; mp != NULL; mp = next) {
		mac_header_info_t hdr_info;

		next = mp->b_next;
		mp->b_next = NULL;

		if (mac_header_info(xnbop->o_mh, mp, &hdr_info) != 0) {
			ADD(free, mp);
			continue;
		}

		if ((hdr_info.mhi_dsttype == MAC_ADDRTYPE_BROADCAST) ||
		    (hdr_info.mhi_dsttype == MAC_ADDRTYPE_MULTICAST)) {
			ADD(keep, mp);
			continue;
		}

		if (bcmp(hdr_info.mhi_daddr, xnbp->xnb_mac_addr,
		    sizeof (xnbp->xnb_mac_addr)) == 0) {
			ADD(keep, mp);
			continue;
		}

		ADD(free, mp);
	}
#undef	ADD

	if (keep_head != NULL)
		xnbo_from_mac(xnbp, mrh, keep_head);

	if (free_head != NULL)
		freemsgchain(free_head);
}

static void
xnbo_notify(void *arg, mac_notify_type_t type)
{
	xnb_t *xnbp = arg;
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	switch (type) {
	case MAC_NOTE_PROMISC:
		xnbop->o_mtx = mac_tx_get(xnbop->o_mh);
		break;
	}
}

static boolean_t
xnbo_open_mac(xnb_t *xnbp, char *mac)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	int err, need_rx_filter, need_setphysaddr, need_promiscuous;
	const mac_info_t *mi;
	char *xsname;
	void (*rx_fn)(void *, mac_resource_handle_t, mblk_t *);
	uint_t max_sdu;

	xsname = xvdi_get_xsname(xnbp->xnb_devinfo);

	if ((err = mac_open_by_linkname(mac, &xnbop->o_mh)) != 0) {
		cmn_err(CE_WARN, "xnbo_open_mac: "
		    "cannot open mac for link %s (%d)", mac, err);
		return (B_FALSE);
	}
	ASSERT(xnbop->o_mh != NULL);

	mi = mac_info(xnbop->o_mh);
	ASSERT(mi != NULL);

	if (mi->mi_media != DL_ETHER) {
		cmn_err(CE_WARN, "xnbo_open_mac: "
		    "device is not DL_ETHER (%d)", mi->mi_media);
		xnbo_close_mac(xnbop);
		return (B_FALSE);
	}
	if (mi->mi_media != mi->mi_nativemedia) {
		cmn_err(CE_WARN, "xnbo_open_mac: "
		    "device media and native media mismatch (%d != %d)",
		    mi->mi_media, mi->mi_nativemedia);
		xnbo_close_mac(xnbop);
		return (B_FALSE);
	}

	mac_sdu_get(xnbop->o_mh, NULL, &max_sdu);
	if (max_sdu > XNBMAXPKT) {
		cmn_err(CE_WARN, "xnbo_open_mac: mac device SDU too big (%d)",
		    max_sdu);
		xnbo_close_mac(xnbop);
		return (B_FALSE);
	}

	xnbop->o_mnh = mac_notify_add(xnbop->o_mh, xnbo_notify, xnbp);
	ASSERT(xnbop->o_mnh != NULL);

	/*
	 * Should the receive path filter packets from the downstream
	 * NIC before passing them to the peer? The default is "no".
	 */
	if (xenbus_scanf(XBT_NULL, xsname,
	    "SUNW-need-rx-filter", "%d", &need_rx_filter) != 0)
		need_rx_filter = 0;
	if (need_rx_filter > 0)
		rx_fn = xnbo_from_mac_filter;
	else
		rx_fn = xnbo_from_mac;

	xnbop->o_mrh = mac_rx_add(xnbop->o_mh, rx_fn, xnbp);
	ASSERT(xnbop->o_mrh != NULL);

	xnbop->o_mtx = mac_tx_get(xnbop->o_mh);
	ASSERT(xnbop->o_mtx != NULL);

	if (!mac_capab_get(xnbop->o_mh, MAC_CAPAB_HCKSUM,
	    &xnbop->o_hcksum_capab))
		xnbop->o_hcksum_capab = 0;

	/*
	 * Should we set the physical address of the underlying NIC
	 * to match that assigned to the peer? The default is "no".
	 */
	if (xenbus_scanf(XBT_NULL, xsname,
	    "SUNW-need-set-physaddr", "%d", &need_setphysaddr) != 0)
		need_setphysaddr = 0;
	if (need_setphysaddr > 0) {
		struct ether_addr ea;

		err = mac_unicst_set(xnbop->o_mh, xnbp->xnb_mac_addr);
		/* Warn, but continue on. */
		if (err != 0) {
			bcopy(xnbp->xnb_mac_addr, ea.ether_addr_octet,
			    ETHERADDRL);
			cmn_err(CE_WARN, "xnbo_open_mac: "
			    "cannot set MAC address of %s to "
			    "%s: %d", mac, ether_sprintf(&ea),
			    err);
		}
	}

	/*
	 * Should we set the underlying NIC into promiscuous mode? The
	 * default is "no".
	 */
	if (xenbus_scanf(XBT_NULL, xsname,
	    "SUNW-need-promiscuous", "%d", &need_promiscuous) != 0)
		need_promiscuous = 0;
	if (need_promiscuous > 0) {
		err = mac_promisc_set(xnbop->o_mh, B_TRUE, MAC_DEVPROMISC);
		if (err != 0) {
			cmn_err(CE_WARN, "xnbo_open_mac: "
			    "cannot enable promiscuous mode of %s: %d",
			    mac, err);
			xnbo_close_mac(xnbop);
			return (B_FALSE);
		}
		xnbop->o_promiscuous = B_TRUE;
	}

	if ((err = mac_start(xnbop->o_mh)) != 0) {
		cmn_err(CE_WARN, "xnbo_open_mac: "
		    "cannot start mac device (%d)", err);
		xnbo_close_mac(xnbop);
		return (B_FALSE);
	}
	xnbop->o_running = B_TRUE;

	return (B_TRUE);
}

/*
 * xnb calls back here when the user-level hotplug code reports that
 * the hotplug has successfully completed. For this flavour that means
 * that the underlying MAC device that we will use is ready to be
 * opened.
 */
static boolean_t
xnbo_hotplug(xnb_t *xnbp)
{
	char *xsname;
	char mac[LIFNAMSIZ];

	xsname = xvdi_get_xsname(xnbp->xnb_devinfo);
	if (xenbus_scanf(XBT_NULL, xsname, "nic", "%s", mac) != 0) {
		cmn_err(CE_WARN, "xnbo_hotplug: "
		    "cannot read nic name from %s", xsname);
		return (B_FALSE);
	}

	return (xnbo_open_mac(xnbp, mac));
}

static void
xnbo_close_mac(xnbo_t *xnbop)
{
	if (xnbop->o_mh == NULL)
		return;

	if (xnbop->o_running) {
		mac_stop(xnbop->o_mh);
		xnbop->o_running = B_FALSE;
	}

	if (xnbop->o_promiscuous) {
		(void) mac_promisc_set(xnbop->o_mh, B_FALSE,
		    MAC_DEVPROMISC);
		xnbop->o_promiscuous = B_FALSE;
	}

	xnbop->o_mtx = NULL;

	if (xnbop->o_mrh != NULL) {
		mac_rx_remove(xnbop->o_mh, xnbop->o_mrh, B_TRUE);
		xnbop->o_mrh = NULL;
	}

	if (xnbop->o_mnh != NULL) {
		mac_notify_remove(xnbop->o_mh, xnbop->o_mnh);
		xnbop->o_mnh = NULL;
	}

	mac_close(xnbop->o_mh);
	xnbop->o_mh = NULL;
}

/*
 * xnb calls back here when we successfully synchronize with the
 * driver in the guest domain. In this flavour there is nothing to do as
 * we open the underlying MAC device on successful hotplug completion.
 */
/*ARGSUSED*/
static void
xnbo_connected(xnb_t *xnbp)
{
}

/*
 * xnb calls back here when the driver in the guest domain has closed
 * down the inter-domain connection. We close the underlying MAC device.
 */
static void
xnbo_disconnected(xnb_t *xnbp)
{
	xnbo_close_mac(xnbp->xnb_flavour_data);
}

static int
xnbo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	static xnb_flavour_t flavour = {
		xnbo_to_mac, xnbo_connected, xnbo_disconnected, xnbo_hotplug,
		xnbo_cksum_from_peer, xnbo_cksum_to_peer,
	};
	xnbo_t *xnbop;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	xnbop = kmem_zalloc(sizeof (*xnbop), KM_SLEEP);

	xnbop->o_mh = NULL;
	xnbop->o_mrh = NULL;
	xnbop->o_mtx = NULL;
	xnbop->o_running = B_FALSE;
	xnbop->o_hcksum_capab = 0;

	if (xnb_attach(dip, &flavour, xnbop) != DDI_SUCCESS) {
		kmem_free(xnbop, sizeof (*xnbop));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
xnbo_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&xnbp->xnb_tx_lock);
	mutex_enter(&xnbp->xnb_rx_lock);

	if (!xnbp->xnb_detachable || xnbp->xnb_connected ||
	    (xnbp->xnb_tx_buf_count > 0)) {
		mutex_exit(&xnbp->xnb_rx_lock);
		mutex_exit(&xnbp->xnb_tx_lock);

		return (DDI_FAILURE);
	}

	mutex_exit(&xnbp->xnb_rx_lock);
	mutex_exit(&xnbp->xnb_tx_lock);

	xnbo_close_mac(xnbop);
	kmem_free(xnbop, sizeof (*xnbop));

	xnb_detach(dip);

	return (DDI_SUCCESS);
}

static struct cb_ops cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP | D_64BIT	/* Driver compatibility flag */
};

static struct dev_ops ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt  */
	nulldev,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xnbo_attach,		/* devo_attach */
	xnbo_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops, "xnbo driver", &ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
