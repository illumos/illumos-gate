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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Services Module
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/strsun.h>
#include	<sys/sysmacros.h>
#include	<sys/atomic.h>
#include	<sys/dlpi.h>
#include	<sys/vlan.h>
#include	<sys/ethernet.h>
#include	<sys/byteorder.h>
#include	<sys/mac.h>

#include	<sys/dls.h>
#include	<sys/dls_impl.h>
#include	<sys/dls_soft_ring.h>

static kmem_cache_t	*i_dls_impl_cachep;
static uint32_t		i_dls_impl_count;

static kstat_t	*dls_ksp = (kstat_t *)NULL;
struct dls_kstats dls_kstat =
{
	{ "soft_ring_pkt_drop", KSTAT_DATA_UINT32 },
};

/*
 * Private functions.
 */

/*ARGSUSED*/
static int
i_dls_constructor(void *buf, void *arg, int kmflag)
{
	dls_impl_t	*dip = buf;

	bzero(buf, sizeof (dls_impl_t));

	rw_init(&(dip->di_lock), NULL, RW_DRIVER, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_dls_destructor(void *buf, void *arg)
{
	dls_impl_t	*dip = buf;

	ASSERT(dip->di_dvp == NULL);
	ASSERT(dip->di_mnh == NULL);
	ASSERT(dip->di_dmap == NULL);
	ASSERT(!dip->di_bound);
	ASSERT(dip->di_rx == NULL);
	ASSERT(dip->di_txinfo == NULL);

	rw_destroy(&(dip->di_lock));
}

static void
i_dls_notify(void *arg, mac_notify_type_t type)
{
	dls_impl_t		*dip = arg;

	switch (type) {
	case MAC_NOTE_UNICST:
		mac_unicst_get(dip->di_mh, dip->di_unicst_addr);
		break;

	case MAC_NOTE_PROMISC:
	case MAC_NOTE_VNIC:
		/*
		 * Every time the MAC interface changes promiscuity or
		 * the VNIC characteristics change we need to reset
		 * our transmit information.
		 */
		dip->di_txinfo = mac_tx_get(dip->di_mh);
		break;
	}
}

static void
dls_stat_init()
{
	if ((dls_ksp = kstat_create("dls", 0, "dls_stat",
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (dls_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		cmn_err(CE_WARN,
		"DLS: failed to create kstat structure for dls stats");
		return;
	}
	dls_ksp->ks_data = (void *)&dls_kstat;
	kstat_install(dls_ksp);
}

static void
dls_stat_destroy()
{
	kstat_delete(dls_ksp);
}

/*
 * Module initialization functions.
 */

void
dls_init(void)
{
	/*
	 * Create a kmem_cache of dls_impl_t.
	 */
	i_dls_impl_cachep = kmem_cache_create("dls_cache",
	    sizeof (dls_impl_t), 0, i_dls_constructor, i_dls_destructor, NULL,
	    NULL, NULL, 0);
	ASSERT(i_dls_impl_cachep != NULL);
	soft_ring_init();
	dls_stat_init();
}

int
dls_fini(void)
{
	/*
	 * If there are any dls_impl_t in use then return EBUSY.
	 */
	if (i_dls_impl_count != 0)
		return (EBUSY);

	/*
	 * Destroy the kmem_cache.
	 */
	kmem_cache_destroy(i_dls_impl_cachep);
	dls_stat_destroy();
	return (0);
}

/*
 * Client function.
 */

int
dls_create(const char *linkname, const char *macname, uint_t ddi_instance)
{
	return (dls_vlan_create(linkname, macname, ddi_instance, 0));
}

int
dls_destroy(const char *name)
{
	return (dls_vlan_destroy(name));
}

int
dls_open(const char *name, dls_channel_t *dcp)
{
	dls_impl_t	*dip;
	dls_vlan_t	*dvp;
	dls_link_t	*dlp;
	int		err;

	/*
	 * Get a reference to the named dls_vlan_t.
	 * Tagged vlans get created automatically.
	 */
	if ((err = dls_vlan_hold(name, &dvp, B_TRUE)) != 0)
		return (err);

	/*
	 * Allocate a new dls_impl_t.
	 */
	dip = kmem_cache_alloc(i_dls_impl_cachep, KM_SLEEP);
	dip->di_dvp = dvp;

	/*
	 * Cache a copy of the MAC interface handle, a pointer to the
	 * immutable MAC info and a copy of the current MAC address.
	 */
	dlp = dvp->dv_dlp;
	dip->di_mh = dlp->dl_mh;
	dip->di_mip = dlp->dl_mip;

	mac_unicst_get(dip->di_mh, dip->di_unicst_addr);

	/*
	 * Set the MAC transmit information.
	 */
	dip->di_txinfo = mac_tx_get(dip->di_mh);

	/*
	 * Add a notification function so that we get updates from the MAC.
	 */
	dip->di_mnh = mac_notify_add(dip->di_mh, i_dls_notify, (void *)dip);

	/*
	 * Bump the kmem_cache count to make sure it is not prematurely
	 * destroyed.
	 */
	atomic_add_32(&i_dls_impl_count, 1);

	/*
	 * Set the di_zid to the zone id of current zone
	 */
	dip->di_zid = getzoneid();

	/*
	 * Add this dls_impl_t to the list of the "opened stream"
	 * list of the corresponding dls_vlan_t
	 */
	dls_vlan_add_impl(dvp, dip);

	/*
	 * Hand back a reference to the dls_impl_t.
	 */
	*dcp = (dls_channel_t)dip;
	return (0);
}

void
dls_close(dls_channel_t dc)
{
	dls_impl_t		*dip = (dls_impl_t *)dc;
	dls_vlan_t		*dvp;
	dls_link_t		*dlp;
	dls_multicst_addr_t	*p;
	dls_multicst_addr_t	*nextp;

	dls_active_clear(dc);

	rw_enter(&(dip->di_lock), RW_WRITER);

	/*
	 * Remove the notify function.
	 */
	mac_notify_remove(dip->di_mh, dip->di_mnh);
	dip->di_mnh = NULL;

	/*
	 * If the dls_impl_t is bound then unbind it.
	 */
	dvp = dip->di_dvp;
	dlp = dvp->dv_dlp;

	if (dip->di_bound) {
		rw_exit(&(dip->di_lock));
		dls_link_remove(dlp, dip);
		rw_enter(&(dip->di_lock), RW_WRITER);
		dip->di_bound = B_FALSE;
	}

	dip->di_rx = NULL;
	dip->di_rx_arg = NULL;

	/*
	 * Walk the list of multicast addresses, disabling each at the MAC.
	 */
	for (p = dip->di_dmap; p != NULL; p = nextp) {
		(void) mac_multicst_remove(dip->di_mh, p->dma_addr);
		nextp = p->dma_nextp;
		kmem_free(p, sizeof (dls_multicst_addr_t));
	}
	dip->di_dmap = NULL;

	/*
	 * Remove this dls_impl_t from the list of the "open streams"
	 * list of the corresponding dls_vlan_t
	 */
	dls_vlan_remove_impl(dvp, dip);

	rw_exit(&(dip->di_lock));

	/*
	 * If the MAC has been set in promiscuous mode then disable it.
	 */
	(void) dls_promisc(dc, 0);

	/*
	 * Free the dls_impl_t back to the cache.
	 */
	dip->di_dvp = NULL;
	dip->di_txinfo = NULL;

	if (dip->di_soft_ring_list != NULL) {
		soft_ring_set_destroy(dip->di_soft_ring_list,
		    dip->di_soft_ring_size);
		dip->di_soft_ring_list = NULL;
	}
	dip->di_soft_ring_size = 0;

	kmem_cache_free(i_dls_impl_cachep, dip);

	/*
	 * Decrement the reference count to allow the cache to be destroyed
	 * if there are no more dls_impl_t.
	 */
	atomic_add_32(&i_dls_impl_count, -1);

	/*
	 * Release our reference to the dls_vlan_t allowing that to be
	 * destroyed if there are no more dls_impl_t. An unreferenced tagged
	 * vlan gets destroyed automatically.
	 */
	dls_vlan_rele(dvp);
}

mac_handle_t
dls_mac(dls_channel_t dc)
{
	return (((dls_impl_t *)dc)->di_mh);
}

uint16_t
dls_vid(dls_channel_t dc)
{
	return (((dls_impl_t *)dc)->di_dvp->dv_id);
}

int
dls_bind(dls_channel_t dc, uint32_t sap)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;
	dls_link_t	*dlp;
	uint32_t	dls_sap;

	/*
	 * Check to see the value is legal for the media type.
	 */
	if (!mac_sap_verify(dip->di_mh, sap, &dls_sap))
		return (EINVAL);
	if (dip->di_promisc & DLS_PROMISC_SAP)
		dls_sap = DLS_SAP_PROMISC;

	/*
	 * Set up the dls_impl_t to mark it as able to receive packets.
	 */
	rw_enter(&(dip->di_lock), RW_WRITER);
	ASSERT(!dip->di_bound);
	dip->di_sap = sap;
	dip->di_bound = B_TRUE;
	rw_exit(&(dip->di_lock));

	/*
	 * Now bind the dls_impl_t by adding it into the hash table in the
	 * dls_link_t.
	 *
	 * NOTE: This must be done without the dls_impl_t lock being held
	 *	 otherwise deadlock may ensue.
	 */
	dlp = dip->di_dvp->dv_dlp;
	dls_link_add(dlp, dls_sap, dip);

	return (0);
}

void
dls_unbind(dls_channel_t dc)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;
	dls_link_t	*dlp;

	/*
	 * Unbind the dls_impl_t by removing it from the hash table in the
	 * dls_link_t.
	 *
	 * NOTE: This must be done without the dls_impl_t lock being held
	 *	 otherise deadlock may enuse.
	 */
	dlp = dip->di_dvp->dv_dlp;
	dls_link_remove(dlp, dip);

	/*
	 * Mark the dls_impl_t as unable to receive packets This will make
	 * sure that 'receives in flight' will not come our way.
	 */
	dip->di_bound = B_FALSE;
}

int
dls_promisc(dls_channel_t dc, uint32_t flags)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;
	dls_link_t	*dlp;
	int		err = 0;

	ASSERT(!(flags & ~(DLS_PROMISC_SAP | DLS_PROMISC_MULTI |
	    DLS_PROMISC_PHYS)));

	/*
	 * Check if we need to turn on 'all sap' mode.
	 */
	rw_enter(&(dip->di_lock), RW_WRITER);
	dlp = dip->di_dvp->dv_dlp;
	if ((flags & DLS_PROMISC_SAP) &&
	    !(dip->di_promisc & DLS_PROMISC_SAP)) {
		dip->di_promisc |= DLS_PROMISC_SAP;
		if (!dip->di_bound)
			goto multi;

		rw_exit(&(dip->di_lock));
		dls_link_remove(dlp, dip);
		dls_link_add(dlp, DLS_SAP_PROMISC, dip);
		rw_enter(&(dip->di_lock), RW_WRITER);
		goto multi;
	}

	/*
	 * Check if we need to turn off 'all sap' mode.
	 */
	if (!(flags & DLS_PROMISC_SAP) &&
	    (dip->di_promisc & DLS_PROMISC_SAP)) {
		uint32_t dls_sap;

		dip->di_promisc &= ~DLS_PROMISC_SAP;
		if (!dip->di_bound)
			goto multi;

		rw_exit(&(dip->di_lock));
		dls_link_remove(dlp, dip);
		(void) mac_sap_verify(dip->di_mh, dip->di_sap, &dls_sap);
		dls_link_add(dlp, dls_sap, dip);
		rw_enter(&(dip->di_lock), RW_WRITER);
	}

multi:
	/*
	 * It's easiest to add the txloop handler up-front; if promiscuous
	 * mode cannot be enabled, then we'll remove it before returning.
	 * Use dl_promisc_lock to prevent racing with another thread also
	 * manipulating the promiscuous state on another dls_impl_t associated
	 * with the same dls_link_t.
	 */
	mutex_enter(&dlp->dl_promisc_lock);
	if (dlp->dl_npromisc == 0 &&
	    (flags & (DLS_PROMISC_MULTI|DLS_PROMISC_PHYS))) {
		ASSERT(dlp->dl_mth == NULL);
		dlp->dl_mth = mac_txloop_add(dlp->dl_mh, dlp->dl_txloop, dlp);
	}

	/*
	 * Turn on or off 'all multicast' mode, if necessary.
	 */
	if (flags & DLS_PROMISC_MULTI) {
		if (!(dip->di_promisc & DLS_PROMISC_MULTI)) {
			err = mac_promisc_set(dip->di_mh, B_TRUE, MAC_PROMISC);
			if (err != 0)
				goto done;
			dip->di_promisc |= DLS_PROMISC_MULTI;
			dlp->dl_npromisc++;
		}
	} else {
		if (dip->di_promisc & DLS_PROMISC_MULTI) {
			err = mac_promisc_set(dip->di_mh, B_FALSE, MAC_PROMISC);
			if (err != 0)
				goto done;
			dip->di_promisc &= ~DLS_PROMISC_MULTI;
			dlp->dl_npromisc--;
		}
	}

	/*
	 * Turn on or off 'all physical' mode, if necessary.
	 */
	if (flags & DLS_PROMISC_PHYS) {
		if (!(dip->di_promisc & DLS_PROMISC_PHYS)) {
			err = mac_promisc_set(dip->di_mh, B_TRUE, MAC_PROMISC);
			if (err != 0)
				goto done;
			dip->di_promisc |= DLS_PROMISC_PHYS;
			dlp->dl_npromisc++;
		}
	} else {
		if (dip->di_promisc & DLS_PROMISC_PHYS) {
			err = mac_promisc_set(dip->di_mh, B_FALSE, MAC_PROMISC);
			if (err != 0)
				goto done;
			dip->di_promisc &= ~DLS_PROMISC_PHYS;
			dlp->dl_npromisc--;
		}
	}

done:
	if (dlp->dl_npromisc == 0 && dlp->dl_mth != NULL) {
		mac_txloop_remove(dlp->dl_mh, dlp->dl_mth);
		dlp->dl_mth = NULL;
	}

	ASSERT(dlp->dl_npromisc == 0 || dlp->dl_mth != NULL);
	mutex_exit(&dlp->dl_promisc_lock);

	rw_exit(&(dip->di_lock));
	return (err);
}

int
dls_multicst_add(dls_channel_t dc, const uint8_t *addr)
{
	dls_impl_t		*dip = (dls_impl_t *)dc;
	int			err;
	dls_multicst_addr_t	**pp;
	dls_multicst_addr_t	*p;
	uint_t			addr_length;

	/*
	 * Check whether the address is in the list of enabled addresses for
	 * this dls_impl_t.
	 */
	rw_enter(&(dip->di_lock), RW_WRITER);
	addr_length = dip->di_mip->mi_addr_length;
	for (pp = &(dip->di_dmap); (p = *pp) != NULL; pp = &(p->dma_nextp)) {
		if (bcmp(addr, p->dma_addr, addr_length) == 0) {
			/*
			 * It is there so there's nothing to do.
			 */
			err = 0;
			goto done;
		}
	}

	/*
	 * Allocate a new list item.
	 */
	if ((p = kmem_zalloc(sizeof (dls_multicst_addr_t),
	    KM_NOSLEEP)) == NULL) {
		err = ENOMEM;
		goto done;
	}

	/*
	 * Enable the address at the MAC.
	 */
	if ((err = mac_multicst_add(dip->di_mh, addr)) != 0) {
		kmem_free(p, sizeof (dls_multicst_addr_t));
		goto done;
	}

	/*
	 * The address is now enabled at the MAC so add it to the list.
	 */
	bcopy(addr, p->dma_addr, addr_length);
	*pp = p;

done:
	rw_exit(&(dip->di_lock));
	return (err);
}

int
dls_multicst_remove(dls_channel_t dc, const uint8_t *addr)
{
	dls_impl_t		*dip = (dls_impl_t *)dc;
	int			err;
	dls_multicst_addr_t	**pp;
	dls_multicst_addr_t	*p;
	uint_t			addr_length;

	/*
	 * Find the address in the list of enabled addresses for this
	 * dls_impl_t.
	 */
	rw_enter(&(dip->di_lock), RW_WRITER);
	addr_length = dip->di_mip->mi_addr_length;
	for (pp = &(dip->di_dmap); (p = *pp) != NULL; pp = &(p->dma_nextp)) {
		if (bcmp(addr, p->dma_addr, addr_length) == 0)
			break;
	}

	/*
	 * If we walked to the end of the list then the given address is
	 * not currently enabled for this dls_impl_t.
	 */
	if (p == NULL) {
		err = ENOENT;
		goto done;
	}

	/*
	 * Disable the address at the MAC.
	 */
	if ((err = mac_multicst_remove(dip->di_mh, addr)) != 0)
		goto done;

	/*
	 * Remove the address from the list.
	 */
	*pp = p->dma_nextp;
	kmem_free(p, sizeof (dls_multicst_addr_t));

done:
	rw_exit(&(dip->di_lock));
	return (err);
}

mblk_t *
dls_header(dls_channel_t dc, const uint8_t *addr, uint16_t sap, uint_t pri,
    mblk_t **payloadp)
{
	dls_impl_t *dip = (dls_impl_t *)dc;
	uint16_t vid;
	size_t extra_len;
	uint16_t mac_sap;
	mblk_t *mp, *payload;
	boolean_t is_ethernet = (dip->di_mip->mi_media == DL_ETHER);
	struct ether_vlan_header *evhp;

	vid = dip->di_dvp->dv_id;
	payload = (payloadp == NULL) ? NULL : (*payloadp);

	/*
	 * If the following conditions are satisfied:
	 *	- This is not a ETHERTYPE_VLAN listener; and
	 *	- This is either a VLAN stream or this is a physical stream
	 *	  but the priority is not 0.
	 *
	 * then we know ahead of time that we'll need to fill in additional
	 * VLAN information in the link-layer header. We will tell the MAC
	 * layer to pre-allocate some space at the end of the Ethernet
	 * header for us.
	 */
	if (is_ethernet && sap != ETHERTYPE_VLAN &&
	    (vid != VLAN_ID_NONE || pri != 0)) {
		extra_len = sizeof (struct ether_vlan_header) -
		    sizeof (struct ether_header);
		mac_sap = ETHERTYPE_VLAN;
	} else {
		extra_len = 0;
		mac_sap = sap;
	}

	mp = mac_header(dip->di_mh, addr, mac_sap, payload, extra_len);
	if (mp == NULL)
		return (NULL);

	if ((vid == VLAN_ID_NONE && pri == 0) || !is_ethernet)
		return (mp);

	/*
	 * Fill in the tag information.
	 */
	ASSERT(MBLKL(mp) == sizeof (struct ether_header));
	if (extra_len != 0) {
		mp->b_wptr += extra_len;
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		evhp->ether_tci = htons(VLAN_TCI(pri, ETHER_CFI, vid));
		evhp->ether_type = htons(sap);
	} else {
		/*
		 * The stream is ETHERTYPE_VLAN listener, so its VLAN tag is
		 * in the payload. Update the priority.
		 */
		struct ether_vlan_extinfo *extinfo;
		size_t len = sizeof (struct ether_vlan_extinfo);

		ASSERT(sap == ETHERTYPE_VLAN);
		ASSERT(payload != NULL);

		if ((DB_REF(payload) > 1) || (MBLKL(payload) < len)) {
			mblk_t *newmp;

			/*
			 * Because some DLS consumers only check the db_ref
			 * count of the first mblk, we pullup 'payload' into
			 * a single mblk.
			 */
			newmp = msgpullup(payload, -1);
			if ((newmp == NULL) || (MBLKL(newmp) < len)) {
				freemsg(newmp);
				freemsg(mp);
				return (NULL);
			} else {
				freemsg(payload);
				*payloadp = payload = newmp;
			}
		}

		extinfo = (struct ether_vlan_extinfo *)payload->b_rptr;
		extinfo->ether_tci = htons(VLAN_TCI(pri, ETHER_CFI,
		    VLAN_ID(ntohs(extinfo->ether_tci))));
	}
	return (mp);
}

int
dls_header_info(dls_channel_t dc, mblk_t *mp, mac_header_info_t *mhip)
{
	return (dls_link_header_info(((dls_impl_t *)dc)->di_dvp->dv_dlp,
	    mp, mhip));
}

void
dls_rx_set(dls_channel_t dc, dls_rx_t rx, void *arg)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;

	rw_enter(&(dip->di_lock), RW_WRITER);
	dip->di_rx = rx;
	dip->di_rx_arg = arg;
	rw_exit(&(dip->di_lock));
}

mblk_t *
dls_tx(dls_channel_t dc, mblk_t *mp)
{
	const mac_txinfo_t *mtp = ((dls_impl_t *)dc)->di_txinfo;

	return (mtp->mt_fn(mtp->mt_arg, mp));
}

boolean_t
dls_accept(dls_impl_t *dip, mac_header_info_t *mhip, dls_rx_t *di_rx,
    void **di_rx_arg)
{
	dls_multicst_addr_t	*dmap;
	size_t			addr_length = dip->di_mip->mi_addr_length;

	/*
	 * We must not accept packets if the dls_impl_t is not marked as bound
	 * or is being removed.
	 */
	rw_enter(&(dip->di_lock), RW_READER);
	if (!dip->di_bound || dip->di_removing)
		goto refuse;

	/*
	 * If the dls_impl_t is in 'all physical' mode then always accept.
	 */
	if (dip->di_promisc & DLS_PROMISC_PHYS)
		goto accept;

	switch (mhip->mhi_dsttype) {
	case MAC_ADDRTYPE_UNICAST:
		/*
		 * Check to see if the destination address matches the
		 * dls_impl_t unicast address.
		 */
		if (memcmp(mhip->mhi_daddr, dip->di_unicst_addr, addr_length) ==
		    0) {
			goto accept;
		}
		break;
	case MAC_ADDRTYPE_MULTICAST:
		/*
		 * Check the address against the list of addresses enabled
		 * for this dls_impl_t or accept it unconditionally if the
		 * dls_impl_t is in 'all multicast' mode.
		 */
		if (dip->di_promisc & DLS_PROMISC_MULTI)
			goto accept;
		for (dmap = dip->di_dmap; dmap != NULL;
		    dmap = dmap->dma_nextp) {
			if (memcmp(mhip->mhi_daddr, dmap->dma_addr,
			    addr_length) == 0) {
				goto accept;
			}
		}
		break;
	case MAC_ADDRTYPE_BROADCAST:
		/*
		 * If the address is broadcast then the dls_impl_t will
		 * always accept it.
		 */
		goto accept;
	}

refuse:
	rw_exit(&(dip->di_lock));
	return (B_FALSE);

accept:
	/*
	 * Since we hold di_lock here, the returned di_rx and di_rx_arg will
	 * always be in sync.
	 */
	*di_rx = dip->di_rx;
	*di_rx_arg = dip->di_rx_arg;
	rw_exit(&(dip->di_lock));
	return (B_TRUE);
}

/* ARGSUSED */
boolean_t
dls_accept_loopback(dls_impl_t *dip, mac_header_info_t *mhip, dls_rx_t *di_rx,
    void **di_rx_arg)
{
	/*
	 * We must not accept packets if the dls_impl_t is not marked as bound
	 * or is being removed.
	 */
	rw_enter(&(dip->di_lock), RW_READER);
	if (!dip->di_bound || dip->di_removing)
		goto refuse;

	/*
	 * A dls_impl_t should only accept loopback packets if it is in
	 * 'all physical' mode.
	 */
	if (dip->di_promisc & DLS_PROMISC_PHYS)
		goto accept;

refuse:
	rw_exit(&(dip->di_lock));
	return (B_FALSE);

accept:
	/*
	 * Since we hold di_lock here, the returned di_rx and di_rx_arg will
	 * always be in sync.
	 */
	*di_rx = dip->di_rx;
	*di_rx_arg = dip->di_rx_arg;
	rw_exit(&(dip->di_lock));
	return (B_TRUE);
}

boolean_t
dls_active_set(dls_channel_t dc)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;
	dls_link_t	*dlp = dip->di_dvp->dv_dlp;

	rw_enter(&dip->di_lock, RW_WRITER);

	/* If we're already active, then there's nothing more to do. */
	if (dip->di_active) {
		rw_exit(&dip->di_lock);
		return (B_TRUE);
	}

	/*
	 * If this is the first active client on this link, notify
	 * the mac that we're becoming an active client.
	 */
	if (dlp->dl_nactive == 0 && !mac_active_shareable_set(dlp->dl_mh)) {
		rw_exit(&dip->di_lock);
		return (B_FALSE);
	}
	dip->di_active = B_TRUE;
	mutex_enter(&dlp->dl_lock);
	dlp->dl_nactive++;
	mutex_exit(&dlp->dl_lock);
	rw_exit(&dip->di_lock);
	return (B_TRUE);
}

void
dls_active_clear(dls_channel_t dc)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;
	dls_link_t	*dlp = dip->di_dvp->dv_dlp;

	rw_enter(&dip->di_lock, RW_WRITER);

	if (!dip->di_active)
		goto out;
	dip->di_active = B_FALSE;

	mutex_enter(&dlp->dl_lock);
	if (--dlp->dl_nactive == 0)
		mac_active_clear(dip->di_mh);
	mutex_exit(&dlp->dl_lock);
out:
	rw_exit(&dip->di_lock);
}

dev_info_t *
dls_finddevinfo(dev_t dev)
{
	return (dls_vlan_finddevinfo(dev));
}

int
dls_ppa_from_minor(minor_t minor, t_uscalar_t *ppa)
{
	return (dls_vlan_ppa_from_minor(minor, ppa));
}
