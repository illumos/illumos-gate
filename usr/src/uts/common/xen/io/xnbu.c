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
 * Xen inter-domain backend - GLDv3 driver edition.
 *
 * A traditional GLDv3 driver used to communicate with a guest
 * domain.  This driver is typically plumbed underneath the IP stack
 * or a software ethernet bridge.
 */

#include "xnb.h"

#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <xen/sys/xendev.h>

/* Required driver entry points for GLDv3 */
static int	xnbu_m_start(void *);
static void	xnbu_m_stop(void *);
static int	xnbu_m_set_mac_addr(void *, const uint8_t *);
static int	xnbu_m_set_multicast(void *, boolean_t, const uint8_t *);
static int	xnbu_m_set_promiscuous(void *, boolean_t);
static int	xnbu_m_stat(void *, uint_t, uint64_t *);
static boolean_t xnbu_m_getcapab(void *, mac_capab_t, void *);
static mblk_t	*xnbu_m_send(void *, mblk_t *);

typedef struct xnbu {
	mac_handle_t		u_mh;
	boolean_t		u_need_sched;
} xnbu_t;

static mac_callbacks_t xnb_callbacks = {
	MC_GETCAPAB,
	xnbu_m_stat,
	xnbu_m_start,
	xnbu_m_stop,
	xnbu_m_set_promiscuous,
	xnbu_m_set_multicast,
	xnbu_m_set_mac_addr,
	xnbu_m_send,
	NULL,
	xnbu_m_getcapab
};

static void
xnbu_to_host(xnb_t *xnbp, mblk_t *mp)
{
	xnbu_t *xnbup = xnbp->xnb_flavour_data;
	boolean_t sched = B_FALSE;

	ASSERT(mp != NULL);

	mac_rx(xnbup->u_mh, NULL, mp);

	mutex_enter(&xnbp->xnb_rx_lock);

	/*
	 * If a transmit attempt failed because we ran out of ring
	 * space and there is now some space, re-enable the transmit
	 * path.
	 */
	if (xnbup->u_need_sched &&
	    RING_HAS_UNCONSUMED_REQUESTS(&xnbp->xnb_rx_ring)) {
		sched = B_TRUE;
		xnbup->u_need_sched = B_FALSE;
	}

	mutex_exit(&xnbp->xnb_rx_lock);

	if (sched)
		mac_tx_update(xnbup->u_mh);
}

static mblk_t *
xnbu_cksum_from_peer(xnb_t *xnbp, mblk_t *mp, uint16_t flags)
{
	/*
	 * Take a conservative approach - if the checksum is blank
	 * then we fill it in.
	 *
	 * If the consumer of the packet is IP then we might actually
	 * only need fill it in if the data is not validated, but how
	 * do we know who might end up with the packet?
	 */

	if ((flags & NETTXF_csum_blank) != 0) {
		/*
		 * The checksum is blank.  We must fill it in here.
		 */
		mp = xnb_process_cksum_flags(xnbp, mp, 0);

		/*
		 * Because we calculated the checksum ourselves we
		 * know that it must be good, so we assert this.
		 */
		flags |= NETTXF_data_validated;
	}

	if ((flags & NETTXF_data_validated) != 0) {
		/*
		 * The checksum is asserted valid.
		 *
		 * The hardware checksum offload specification says
		 * that we must provide the actual checksum as well as
		 * an assertion that it is valid, but the protocol
		 * stack doesn't actually use it so we don't bother.
		 * If it was necessary we could grovel in the packet
		 * to find it.
		 */
		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0,
		    HCK_FULLCKSUM | HCK_FULLCKSUM_OK, KM_NOSLEEP);
	}

	return (mp);
}

static uint16_t
xnbu_cksum_to_peer(xnb_t *xnbp, mblk_t *mp)
{
	uint16_t r = 0;

	if (xnbp->xnb_cksum_offload) {
		uint32_t pflags;

		hcksum_retrieve(mp, NULL, NULL, NULL, NULL,
		    NULL, NULL, &pflags);

		/*
		 * If the protocol stack has requested checksum
		 * offload, inform the peer that we have not
		 * calculated the checksum.
		 */
		if ((pflags & HCK_FULLCKSUM) != 0)
			r |= NETRXF_csum_blank;
	}

	return (r);
}

static void
xnbu_connected(xnb_t *xnbp)
{
	xnbu_t *xnbup = xnbp->xnb_flavour_data;

	mac_link_update(xnbup->u_mh, LINK_STATE_UP);
	/*
	 * We are able to send packets now - bring them on.
	 */
	mac_tx_update(xnbup->u_mh);
}

static void
xnbu_disconnected(xnb_t *xnbp)
{
	xnbu_t *xnbup = xnbp->xnb_flavour_data;

	mac_link_update(xnbup->u_mh, LINK_STATE_DOWN);
}

/*ARGSUSED*/
static boolean_t
xnbu_hotplug(xnb_t *xnbp)
{
	return (B_TRUE);
}

static mblk_t *
xnbu_m_send(void *arg, mblk_t *mp)
{
	xnb_t *xnbp = arg;
	xnbu_t *xnbup = xnbp->xnb_flavour_data;

	mp = xnb_copy_to_peer(arg, mp);

	/* XXPV dme: playing with need_sched without txlock? */

	/*
	 * If we consumed all of the mblk_t's offered, perhaps we need
	 * to indicate that we can accept more.  Otherwise we are full
	 * and need to wait for space.
	 */
	if (mp == NULL) {
		/*
		 * If a previous transmit attempt failed because the ring
		 * was full, try again now.
		 */
		if (xnbup->u_need_sched) {
			xnbup->u_need_sched = B_FALSE;
			mac_tx_update(xnbup->u_mh);
		}
	} else {
		xnbup->u_need_sched = B_TRUE;
	}

	return (mp);
}

/*
 *  xnbu_m_set_mac_addr() -- set the physical network address on the board
 */
/* ARGSUSED */
static int
xnbu_m_set_mac_addr(void *arg, const uint8_t *macaddr)
{
	xnb_t *xnbp = arg;
	xnbu_t *xnbup = xnbp->xnb_flavour_data;

	bcopy(macaddr, xnbp->xnb_mac_addr, ETHERADDRL);
	mac_unicst_update(xnbup->u_mh, xnbp->xnb_mac_addr);

	return (0);
}

/*
 *  xnbu_m_set_multicast() -- set (enable) or disable a multicast address
 */
/*ARGSUSED*/
static int
xnbu_m_set_multicast(void *arg, boolean_t add, const uint8_t *mca)
{
	/*
	 * We always accept all packets from the peer, so nothing to
	 * do for enable or disable.
	 */
	return (0);
}


/*
 * xnbu_m_set_promiscuous() -- set or reset promiscuous mode on the board
 */
/* ARGSUSED */
static int
xnbu_m_set_promiscuous(void *arg, boolean_t on)
{
	/*
	 * We always accept all packets from the peer, so nothing to
	 * do for enable or disable.
	 */
	return (0);
}

/*
 *  xnbu_m_start() -- start the board receiving and enable interrupts.
 */
/*ARGSUSED*/
static int
xnbu_m_start(void *arg)
{
	return (0);
}

/*
 * xnbu_m_stop() - disable hardware
 */
/*ARGSUSED*/
static void
xnbu_m_stop(void *arg)
{
}

static int
xnbu_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	xnb_t *xnbp = arg;

	mutex_enter(&xnbp->xnb_tx_lock);
	mutex_enter(&xnbp->xnb_rx_lock);

#define	map_stat(q, r)				\
	case (MAC_STAT_##q):			\
		*val = xnbp->xnb_stat_##r;	\
		break

	switch (stat) {

	map_stat(IPACKETS, opackets);
	map_stat(OPACKETS, ipackets);
	map_stat(RBYTES, obytes);
	map_stat(OBYTES, rbytes);

	default:
		mutex_exit(&xnbp->xnb_rx_lock);
		mutex_exit(&xnbp->xnb_tx_lock);

		return (ENOTSUP);
	}

#undef map_stat

	mutex_exit(&xnbp->xnb_rx_lock);
	mutex_exit(&xnbp->xnb_tx_lock);

	return (0);
}

static boolean_t
xnbu_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	xnb_t *xnbp = arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *capab = cap_data;

		if (xnbp->xnb_cksum_offload)
			*capab = HCKSUM_INET_PARTIAL;
		else
			*capab = 0;
		break;
	}
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
xnbu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	static xnb_flavour_t flavour = {
		xnbu_to_host, xnbu_connected, xnbu_disconnected, xnbu_hotplug,
		xnbu_cksum_from_peer, xnbu_cksum_to_peer,
	};
	xnbu_t *xnbup;
	xnb_t *xnbp;
	mac_register_t *mr;
	int err;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	xnbup = kmem_zalloc(sizeof (*xnbup), KM_SLEEP);

	if ((mr = mac_alloc(MAC_VERSION)) == NULL) {
		kmem_free(xnbup, sizeof (*xnbup));
		return (DDI_FAILURE);
	}

	if (xnb_attach(dip, &flavour, xnbup) != DDI_SUCCESS) {
		mac_free(mr);
		kmem_free(xnbup, sizeof (*xnbup));
		return (DDI_FAILURE);
	}

	xnbp = ddi_get_driver_private(dip);
	ASSERT(xnbp != NULL);

	mr->m_dip = dip;
	mr->m_driver = xnbp;

	/*
	 *  Initialize pointers to device specific functions which will be
	 *  used by the generic layer.
	 */
	mr->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mr->m_src_addr = xnbp->xnb_mac_addr;
	mr->m_callbacks = &xnb_callbacks;
	mr->m_min_sdu = 0;
	mr->m_max_sdu = XNBMAXPKT;
	/*
	 * xnbu is a virtual device, and it is not associated with any
	 * physical device. Its margin size is determined by the maximum
	 * packet size it can handle, which is PAGESIZE.
	 */
	mr->m_margin = PAGESIZE - XNBMAXPKT - sizeof (struct ether_header);

	(void) memset(xnbp->xnb_mac_addr, 0xff, ETHERADDRL);
	xnbp->xnb_mac_addr[0] &= 0xfe;
	xnbup->u_need_sched = B_FALSE;

	/*
	 * Register ourselves with the GLDv3 interface.
	 */
	err = mac_register(mr, &xnbup->u_mh);
	mac_free(mr);
	if (err != 0) {
		xnb_detach(dip);
		kmem_free(xnbup, sizeof (*xnbup));
		return (DDI_FAILURE);
	}

	mac_link_update(xnbup->u_mh, LINK_STATE_DOWN);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
xnbu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xnb_t *xnbp = ddi_get_driver_private(dip);
	xnbu_t *xnbup = xnbp->xnb_flavour_data;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ASSERT(xnbp != NULL);
	ASSERT(xnbup != NULL);

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

	/*
	 * Attempt to unregister the mac.
	 */
	if ((xnbup->u_mh != NULL) && (mac_unregister(xnbup->u_mh) != 0))
		return (DDI_FAILURE);
	kmem_free(xnbup, sizeof (*xnbup));

	xnb_detach(dip);

	return (DDI_SUCCESS);
}

DDI_DEFINE_STREAM_OPS(ops, nulldev, nulldev, xnbu_attach, xnbu_detach,
    nodev, NULL, D_MP, NULL, ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops, "xnbu driver", &ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int i;

	mac_init_ops(&ops, "xnbu");

	i = mod_install(&modlinkage);
	if (i != DDI_SUCCESS)
		mac_fini_ops(&ops);

	return (i);
}

int
_fini(void)
{
	int i;

	i = mod_remove(&modlinkage);
	if (i == DDI_SUCCESS)
		mac_fini_ops(&ops);

	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
