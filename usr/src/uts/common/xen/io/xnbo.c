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
 * Xen network backend - mac client edition.
 *
 * A driver that sits above an existing GLDv3/Nemo MAC driver and
 * relays packets to/from that driver from/to a guest domain.
 */

#ifdef DEBUG
#define	XNBO_DEBUG 1
#endif /* DEBUG */

#include "xnb.h"

#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/strsubr.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/mac.h>
#include <net/if.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>
#include <sys/sdt.h>
#include <sys/note.h>

#ifdef XNBO_DEBUG
boolean_t xnbo_cksum_offload_to_peer = B_TRUE;
boolean_t xnbo_cksum_offload_from_peer = B_TRUE;
#endif /* XNBO_DEBUG */

/* Track multicast addresses. */
typedef struct xmca {
	struct xmca *next;
	ether_addr_t addr;
} xmca_t;

/* State about this device instance. */
typedef struct xnbo {
	mac_handle_t		o_mh;
	mac_client_handle_t	o_mch;
	mac_unicast_handle_t	o_mah;
	mac_promisc_handle_t	o_mphp;
	boolean_t		o_running;
	boolean_t		o_promiscuous;
	uint32_t		o_hcksum_capab;
	xmca_t			*o_mca;
	char			o_link_name[LIFNAMSIZ];
	boolean_t		o_need_rx_filter;
	boolean_t		o_need_setphysaddr;
	boolean_t		o_multicast_control;
} xnbo_t;

static void xnbo_close_mac(xnb_t *);
static void i_xnbo_close_mac(xnb_t *, boolean_t);

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

	if (mac_tx(xnbop->o_mch, mp, 0,
	    MAC_DROP_ON_NO_DESC, NULL) != (mac_tx_cookie_t)NULL) {
		xnbp->xnb_stat_mac_full++;
	}

	return;

fail:
	freemsgchain(mp);
}

/*
 * Process the checksum flags `flags' provided by the peer for the
 * packet `mp'.
 */
static mblk_t *
xnbo_cksum_from_peer(xnb_t *xnbp, mblk_t *mp, uint16_t flags)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	ASSERT(mp->b_next == NULL);

	if ((flags & NETTXF_csum_blank) != 0) {
		uint32_t capab = xnbop->o_hcksum_capab;

#ifdef XNBO_DEBUG
		if (!xnbo_cksum_offload_from_peer)
			capab = 0;
#endif /* XNBO_DEBUG */

		/*
		 * The checksum in the packet is blank.  Determine
		 * whether we can do hardware offload and, if so,
		 * update the flags on the mblk according.  If not,
		 * calculate and insert the checksum using software.
		 */
		mp = xnb_process_cksum_flags(xnbp, mp, capab);
	}

	return (mp);
}

/*
 * Calculate the checksum flags to be relayed to the peer for the
 * packet `mp'.
 */
static uint16_t
xnbo_cksum_to_peer(xnb_t *xnbp, mblk_t *mp)
{
	_NOTE(ARGUNUSED(xnbp));
	uint16_t r = 0;
	uint32_t pflags, csum;

#ifdef XNBO_DEBUG
	if (!xnbo_cksum_offload_to_peer)
		return (0);
#endif /* XNBO_DEBUG */

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
	 *
	 * Then again, if a NIC supports HCK_PARTIALCKSUM in its'
	 * output path, the host IP stack will use it. If such packets
	 * are destined for the peer (i.e. looped around) we would
	 * gain some advantage.
	 */

	mac_hcksum_get(mp, NULL, NULL, NULL, &csum, &pflags);

	/*
	 * If the MAC driver has asserted that the checksum is
	 * good, let the peer know.
	 */
	if (((pflags & HCK_FULLCKSUM) != 0) &&
	    (((pflags & HCK_FULLCKSUM_OK) != 0) ||
	    (csum == 0xffff)))
		r |= NETRXF_data_validated;

	return (r);
}

/*
 * Packets from the mac device come here.  We pass them to the peer.
 */
/*ARGSUSED*/
static void
xnbo_from_mac(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
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
static void
xnbo_from_mac_filter(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	_NOTE(ARGUNUSED(loopback));
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
		xnbo_from_mac(xnbp, mrh, keep_head, B_FALSE);

	if (free_head != NULL)
		freemsgchain(free_head);
}

static boolean_t
xnbo_open_mac(xnb_t *xnbp, char *mac)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	int err;
	const mac_info_t *mi;
	void (*rx_fn)(void *, mac_resource_handle_t, mblk_t *, boolean_t);
	struct ether_addr ea;
	uint_t max_sdu;
	mac_diag_t diag;

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
		i_xnbo_close_mac(xnbp, B_TRUE);
		return (B_FALSE);
	}
	if (mi->mi_media != mi->mi_nativemedia) {
		cmn_err(CE_WARN, "xnbo_open_mac: "
		    "device media and native media mismatch (%d != %d)",
		    mi->mi_media, mi->mi_nativemedia);
		i_xnbo_close_mac(xnbp, B_TRUE);
		return (B_FALSE);
	}

	mac_sdu_get(xnbop->o_mh, NULL, &max_sdu);
	if (max_sdu > XNBMAXPKT) {
		cmn_err(CE_WARN, "xnbo_open_mac: mac device SDU too big (%d)",
		    max_sdu);
		i_xnbo_close_mac(xnbp, B_TRUE);
		return (B_FALSE);
	}

	/*
	 * MAC_OPEN_FLAGS_MULTI_PRIMARY is relevant when we are migrating a
	 * guest on the localhost itself. In this case we would have the MAC
	 * client open for the guest being migrated *and* also for the
	 * migrated guest (i.e. the former will be active till the migration
	 * is complete when the latter will be activated). This flag states
	 * that it is OK for mac_unicast_add to add the primary MAC unicast
	 * address multiple times.
	 */
	if (mac_client_open(xnbop->o_mh, &xnbop->o_mch, NULL,
	    MAC_OPEN_FLAGS_USE_DATALINK_NAME |
	    MAC_OPEN_FLAGS_MULTI_PRIMARY) != 0) {
		cmn_err(CE_WARN, "xnbo_open_mac: "
		    "error (%d) opening mac client", err);
		i_xnbo_close_mac(xnbp, B_TRUE);
		return (B_FALSE);
	}

	if (xnbop->o_need_rx_filter)
		rx_fn = xnbo_from_mac_filter;
	else
		rx_fn = xnbo_from_mac;

	err = mac_unicast_add_set_rx(xnbop->o_mch, NULL, MAC_UNICAST_PRIMARY,
	    &xnbop->o_mah, 0, &diag, xnbop->o_multicast_control ? rx_fn : NULL,
	    xnbp);
	if (err != 0) {
		cmn_err(CE_WARN, "xnbo_open_mac: failed to get the primary "
		    "MAC address of %s: %d", mac, err);
		i_xnbo_close_mac(xnbp, B_TRUE);
		return (B_FALSE);
	}
	if (!xnbop->o_multicast_control) {
		err = mac_promisc_add(xnbop->o_mch, MAC_CLIENT_PROMISC_ALL,
		    rx_fn, xnbp, &xnbop->o_mphp, MAC_PROMISC_FLAGS_NO_TX_LOOP |
		    MAC_PROMISC_FLAGS_VLAN_TAG_STRIP);
		if (err != 0) {
			cmn_err(CE_WARN, "xnbo_open_mac: "
			    "cannot enable promiscuous mode of %s: %d",
			    mac, err);
			i_xnbo_close_mac(xnbp, B_TRUE);
			return (B_FALSE);
		}
		xnbop->o_promiscuous = B_TRUE;
	}

	if (xnbop->o_need_setphysaddr) {
		err = mac_unicast_primary_set(xnbop->o_mh, xnbp->xnb_mac_addr);
		/* Warn, but continue on. */
		if (err != 0) {
			bcopy(xnbp->xnb_mac_addr, ea.ether_addr_octet,
			    ETHERADDRL);
			cmn_err(CE_WARN, "xnbo_open_mac: "
			    "cannot set MAC address of %s to "
			    "%s: %d", mac, ether_sprintf(&ea), err);
		}
	}

	if (!mac_capab_get(xnbop->o_mh, MAC_CAPAB_HCKSUM,
	    &xnbop->o_hcksum_capab))
		xnbop->o_hcksum_capab = 0;

	xnbop->o_running = B_TRUE;

	return (B_TRUE);
}

static void
xnbo_close_mac(xnb_t *xnbp)
{
	i_xnbo_close_mac(xnbp, B_FALSE);
}

static void
i_xnbo_close_mac(xnb_t *xnbp, boolean_t locked)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	xmca_t *loop;

	ASSERT(!locked || MUTEX_HELD(&xnbp->xnb_state_lock));

	if (xnbop->o_mh == NULL)
		return;

	if (xnbop->o_running)
		xnbop->o_running = B_FALSE;

	if (!locked)
		mutex_enter(&xnbp->xnb_state_lock);
	loop = xnbop->o_mca;
	xnbop->o_mca = NULL;
	if (!locked)
		mutex_exit(&xnbp->xnb_state_lock);

	while (loop != NULL) {
		xmca_t *next = loop->next;

		DTRACE_PROBE3(mcast_remove,
		    (char *), "close",
		    (void *), xnbp,
		    (etheraddr_t *), loop->addr);
		(void) mac_multicast_remove(xnbop->o_mch, loop->addr);
		kmem_free(loop, sizeof (*loop));
		loop = next;
	}

	if (xnbop->o_promiscuous) {
		if (xnbop->o_mphp != NULL) {
			mac_promisc_remove(xnbop->o_mphp);
			xnbop->o_mphp = NULL;
		}
		xnbop->o_promiscuous = B_FALSE;
	} else {
		if (xnbop->o_mch != NULL)
			mac_rx_clear(xnbop->o_mch);
	}

	if (xnbop->o_mah != NULL) {
		(void) mac_unicast_remove(xnbop->o_mch, xnbop->o_mah);
		xnbop->o_mah = NULL;
	}

	if (xnbop->o_mch != NULL) {
		mac_client_close(xnbop->o_mch, 0);
		xnbop->o_mch = NULL;
	}

	mac_close(xnbop->o_mh);
	xnbop->o_mh = NULL;
}

/*
 * Hotplug has completed and we are connected to the peer. We have all
 * the information we need to exchange traffic, so open the MAC device
 * and configure it appropriately.
 */
static boolean_t
xnbo_start_connect(xnb_t *xnbp)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	return (xnbo_open_mac(xnbp, xnbop->o_link_name));
}

/*
 * The guest has successfully synchronize with this instance. We read
 * the configuration of the guest from xenstore to check whether the
 * guest requests multicast control. If not (the default) we make a
 * note that the MAC device needs to be used in promiscious mode.
 */
static boolean_t
xnbo_peer_connected(xnb_t *xnbp)
{
	char *oename;
	int request;
	xnbo_t *xnbop = xnbp->xnb_flavour_data;

	oename = xvdi_get_oename(xnbp->xnb_devinfo);

	if (xenbus_scanf(XBT_NULL, oename,
	    "request-multicast-control", "%d", &request) != 0)
		request = 0;
	xnbop->o_multicast_control = (request > 0);

	return (B_TRUE);
}

/*
 * The guest domain has closed down the inter-domain connection. We
 * close the underlying MAC device.
 */
static void
xnbo_peer_disconnected(xnb_t *xnbp)
{
	xnbo_close_mac(xnbp);
}

/*
 * The hotplug script has completed. We read information from xenstore
 * about our configuration, most notably the name of the MAC device we
 * should use.
 */
static boolean_t
xnbo_hotplug_connected(xnb_t *xnbp)
{
	char *xsname;
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	int need;

	xsname = xvdi_get_xsname(xnbp->xnb_devinfo);

	if (xenbus_scanf(XBT_NULL, xsname,
	    "nic", "%s", xnbop->o_link_name) != 0) {
		cmn_err(CE_WARN, "xnbo_connect: "
		    "cannot read nic name from %s", xsname);
		return (B_FALSE);
	}

	if (xenbus_scanf(XBT_NULL, xsname,
	    "SUNW-need-rx-filter", "%d", &need) != 0)
		need = 0;
	xnbop->o_need_rx_filter = (need > 0);

	if (xenbus_scanf(XBT_NULL, xsname,
	    "SUNW-need-set-physaddr", "%d", &need) != 0)
		need = 0;
	xnbop->o_need_setphysaddr = (need > 0);

	return (B_TRUE);
}

/*
 * Find the multicast address `addr', return B_TRUE if it is one that
 * we receive. If `remove', remove it from the set received.
 */
static boolean_t
xnbo_mcast_find(xnb_t *xnbp, ether_addr_t *addr, boolean_t remove)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	xmca_t *prev, *del, *this;

	ASSERT(MUTEX_HELD(&xnbp->xnb_state_lock));
	ASSERT(xnbop->o_promiscuous == B_FALSE);

	prev = del = NULL;

	this = xnbop->o_mca;

	while (this != NULL) {
		if (bcmp(&this->addr, addr, sizeof (this->addr)) == 0) {
			del = this;
			if (remove) {
				if (prev == NULL)
					xnbop->o_mca = this->next;
				else
					prev->next = this->next;
			}
			break;
		}

		prev = this;
		this = this->next;
	}

	if (del == NULL)
		return (B_FALSE);

	if (remove) {
		DTRACE_PROBE3(mcast_remove,
		    (char *), "remove",
		    (void *), xnbp,
		    (etheraddr_t *), del->addr);
		mac_multicast_remove(xnbop->o_mch, del->addr);
		kmem_free(del, sizeof (*del));
	}

	return (B_TRUE);
}

/*
 * Add the multicast address `addr' to the set received.
 */
static boolean_t
xnbo_mcast_add(xnb_t *xnbp, ether_addr_t *addr)
{
	xnbo_t *xnbop = xnbp->xnb_flavour_data;
	boolean_t r = B_FALSE;

	ASSERT(xnbop->o_promiscuous == B_FALSE);

	mutex_enter(&xnbp->xnb_state_lock);

	if (xnbo_mcast_find(xnbp, addr, B_FALSE)) {
		r = B_TRUE;
	} else if (mac_multicast_add(xnbop->o_mch,
	    (const uint8_t *)addr) == 0) {
		xmca_t *mca;

		DTRACE_PROBE3(mcast_add,
		    (char *), "add",
		    (void *), xnbp,
		    (etheraddr_t *), addr);

		mca = kmem_alloc(sizeof (*mca), KM_SLEEP);
		bcopy(addr, &mca->addr, sizeof (mca->addr));

		mca->next = xnbop->o_mca;
		xnbop->o_mca = mca;

		r = B_TRUE;
	}

	mutex_exit(&xnbp->xnb_state_lock);

	return (r);
}

/*
 * Remove the multicast address `addr' from the set received.
 */
static boolean_t
xnbo_mcast_del(xnb_t *xnbp, ether_addr_t *addr)
{
	boolean_t r;

	mutex_enter(&xnbp->xnb_state_lock);
	r = xnbo_mcast_find(xnbp, addr, B_TRUE);
	mutex_exit(&xnbp->xnb_state_lock);

	return (r);
}

static int
xnbo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	static xnb_flavour_t flavour = {
		xnbo_to_mac, xnbo_peer_connected, xnbo_peer_disconnected,
		xnbo_hotplug_connected, xnbo_start_connect,
		xnbo_cksum_from_peer, xnbo_cksum_to_peer,
		xnbo_mcast_add, xnbo_mcast_del,
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

	xnbo_close_mac(xnbp);
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
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
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
