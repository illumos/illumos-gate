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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012, Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * Data-Link Services Module
 */

#include	<sys/strsun.h>
#include	<sys/vlan.h>
#include	<sys/dld_impl.h>
#include	<sys/mac_client_priv.h>

int
dls_open(dls_link_t *dlp, dls_dl_handle_t ddh, dld_str_t *dsp)
{
	zoneid_t	zid = getzoneid();
	boolean_t	local;
	int		err;

	/*
	 * Check whether this client belongs to the zone of this dlp. Note that
	 * a global zone client is allowed to open a local zone dlp.
	 */
	if (zid != GLOBAL_ZONEID && dlp->dl_zid != zid)
		return (ENOENT);

	/*
	 * mac_start() is required for non-legacy MACs to show accurate
	 * kstats even before the interface is brought up. For legacy
	 * drivers, this is not needed. Further, calling mac_start() for
	 * legacy drivers would make the shared-lower-stream to stay in
	 * the DL_IDLE state, which in turn causes performance regression.
	 */
	if (!mac_capab_get(dlp->dl_mh, MAC_CAPAB_LEGACY, NULL) &&
	    ((err = mac_start(dlp->dl_mh)) != 0)) {
		return (err);
	}

	local = (zid == dlp->dl_zid);
	dlp->dl_zone_ref += (local ? 1 : 0);

	/*
	 * Cache a copy of the MAC interface handle, a pointer to the
	 * immutable MAC info.
	 */
	dsp->ds_dlp = dlp;
	dsp->ds_mh = dlp->dl_mh;
	dsp->ds_mch = dlp->dl_mch;
	dsp->ds_mip = dlp->dl_mip;
	dsp->ds_ddh = ddh;
	dsp->ds_local = local;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));
	return (0);
}

void
dls_close(dld_str_t *dsp)
{
	dls_link_t		*dlp = dsp->ds_dlp;
	dls_multicst_addr_t	*p;
	dls_multicst_addr_t	*nextp;

	ASSERT(dsp->ds_datathr_cnt == 0);
	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	if (dsp->ds_local)
		dlp->dl_zone_ref--;
	dsp->ds_local = B_FALSE;

	/*
	 * Walk the list of multicast addresses, disabling each at the MAC.
	 * Note that we must remove multicast address before
	 * mac_unicast_remove() (called by dls_active_clear()) because
	 * mac_multicast_remove() relies on the unicast flows on the mac
	 * client.
	 */
	for (p = dsp->ds_dmap; p != NULL; p = nextp) {
		(void) mac_multicast_remove(dsp->ds_mch, p->dma_addr);
		nextp = p->dma_nextp;
		kmem_free(p, sizeof (dls_multicst_addr_t));
	}
	dsp->ds_dmap = NULL;

	dls_active_clear(dsp, B_TRUE);

	/*
	 * If the dld_str_t is bound then unbind it.
	 */
	if (dsp->ds_dlstate == DL_IDLE) {
		dls_unbind(dsp);
		dsp->ds_dlstate = DL_UNBOUND;
	}

	/*
	 * If the MAC has been set in promiscuous mode then disable it.
	 * This needs to be done before resetting ds_rx.
	 */
	(void) dls_promisc(dsp, 0);

	/*
	 * At this point we have cutoff inbound packet flow from the mac
	 * for this 'dsp'. The dls_link_remove above cut off packets meant
	 * for us and waited for upcalls to finish. Similarly the dls_promisc
	 * reset above waited for promisc callbacks to finish. Now we can
	 * safely reset ds_rx to NULL
	 */
	dsp->ds_rx = NULL;
	dsp->ds_rx_arg = NULL;

	dsp->ds_dlp = NULL;

	if (!mac_capab_get(dsp->ds_mh, MAC_CAPAB_LEGACY, NULL))
		mac_stop(dsp->ds_mh);

	/*
	 * Release our reference to the dls_link_t allowing that to be
	 * destroyed if there are no more dls_impl_t.
	 */
	dls_link_rele(dlp);
}

int
dls_bind(dld_str_t *dsp, uint32_t sap)
{
	uint32_t	dls_sap;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	/*
	 * Check to see the value is legal for the media type.
	 */
	if (!mac_sap_verify(dsp->ds_mh, sap, &dls_sap))
		return (EINVAL);

	if (dsp->ds_promisc & DLS_PROMISC_SAP)
		dls_sap = DLS_SAP_PROMISC;

	/*
	 * Set up the dld_str_t to mark it as able to receive packets.
	 */
	dsp->ds_sap = sap;

	/*
	 * The MAC layer does the VLAN demultiplexing and will only pass up
	 * untagged packets to non-promiscuous primary MAC clients. In order to
	 * support the binding to the VLAN SAP which is required by DLPI, dls
	 * needs to get a copy of all tagged packets when the client binds to
	 * the VLAN SAP. We do this by registering a separate promiscuous
	 * callback for each dls client binding to that SAP.
	 *
	 * Note: even though there are two promiscuous handles in dld_str_t,
	 * ds_mph is for the regular promiscuous mode, ds_vlan_mph is the handle
	 * to receive VLAN pkt when promiscuous mode is not on. Only one of
	 * them can be non-NULL at the same time, to avoid receiving dup copies
	 * of pkts.
	 */
	if (sap == ETHERTYPE_VLAN && dsp->ds_promisc == 0) {
		int err;

		if (dsp->ds_vlan_mph != NULL)
			return (EINVAL);
		err = mac_promisc_add(dsp->ds_mch,
		    MAC_CLIENT_PROMISC_ALL, dls_rx_vlan_promisc, dsp,
		    &dsp->ds_vlan_mph, MAC_PROMISC_FLAGS_NO_PHYS);

		if (err == 0 && dsp->ds_nonip &&
		    dsp->ds_dlp->dl_nonip_cnt++ == 0)
			mac_rx_bypass_disable(dsp->ds_mch);

		return (err);
	}

	/*
	 * Now bind the dld_str_t by adding it into the hash table in the
	 * dls_link_t.
	 */
	dls_link_add(dsp->ds_dlp, dls_sap, dsp);
	if (dsp->ds_nonip && dsp->ds_dlp->dl_nonip_cnt++ == 0)
		mac_rx_bypass_disable(dsp->ds_mch);

	return (0);
}

void
dls_unbind(dld_str_t *dsp)
{
	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	if (dsp->ds_nonip && --dsp->ds_dlp->dl_nonip_cnt == 0)
		mac_rx_bypass_enable(dsp->ds_mch);

	/*
	 * For VLAN SAP, there was a promisc handle registered when dls_bind.
	 * When unbind this dls link, we need to remove the promisc handle.
	 * See comments in dls_bind().
	 */
	if (dsp->ds_vlan_mph != NULL) {
		mac_promisc_remove(dsp->ds_vlan_mph);
		dsp->ds_vlan_mph = NULL;
		return;
	}

	/*
	 * Unbind the dld_str_t by removing it from the hash table in the
	 * dls_link_t.
	 */
	dls_link_remove(dsp->ds_dlp, dsp);
	dsp->ds_sap = 0;
}

/*
 * In order to prevent promiscuous-mode processing with dsp->ds_promisc
 * set to inaccurate values, this function sets dsp->ds_promisc with new
 * flags.  For enabling (mac_promisc_add), the flags are set prior to the
 * actual enabling.  For disabling (mac_promisc_remove), the flags are set
 * after the actual disabling.
 */
int
dls_promisc(dld_str_t *dsp, uint32_t new_flags)
{
	int err = 0;
	uint32_t old_flags = dsp->ds_promisc;
	mac_client_promisc_type_t mptype = MAC_CLIENT_PROMISC_ALL;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));
	ASSERT(!(new_flags & ~(DLS_PROMISC_SAP | DLS_PROMISC_MULTI |
	    DLS_PROMISC_PHYS)));

	/*
	 * If the user has only requested DLS_PROMISC_MULTI then we need to make
	 * sure that they don't see all packets.
	 */
	if (new_flags == DLS_PROMISC_MULTI)
		mptype = MAC_CLIENT_PROMISC_MULTI;

	if (dsp->ds_promisc == 0 && new_flags != 0) {
		/*
		 * If only DLS_PROMISC_SAP, we don't turn on the
		 * physical promisc mode
		 */
		dsp->ds_promisc = new_flags;
		err = mac_promisc_add(dsp->ds_mch, mptype,
		    dls_rx_promisc, dsp, &dsp->ds_mph,
		    (new_flags != DLS_PROMISC_SAP) ? 0 :
		    MAC_PROMISC_FLAGS_NO_PHYS);
		if (err != 0) {
			dsp->ds_promisc = old_flags;
			return (err);
		}

		/* Remove vlan promisc handle to avoid sending dup copy up */
		if (dsp->ds_vlan_mph != NULL) {
			mac_promisc_remove(dsp->ds_vlan_mph);
			dsp->ds_vlan_mph = NULL;
		}
	} else if (dsp->ds_promisc != 0 && new_flags == 0) {
		ASSERT(dsp->ds_mph != NULL);

		mac_promisc_remove(dsp->ds_mph);
		dsp->ds_promisc = new_flags;
		dsp->ds_mph = NULL;

		if (dsp->ds_sap == ETHERTYPE_VLAN &&
		    dsp->ds_dlstate != DL_UNBOUND) {
			if (dsp->ds_vlan_mph != NULL)
				return (EINVAL);
			err = mac_promisc_add(dsp->ds_mch,
			    MAC_CLIENT_PROMISC_ALL, dls_rx_vlan_promisc, dsp,
			    &dsp->ds_vlan_mph, MAC_PROMISC_FLAGS_NO_PHYS);
		}
	} else if (dsp->ds_promisc == DLS_PROMISC_SAP && new_flags != 0 &&
	    new_flags != dsp->ds_promisc) {
		/*
		 * If the old flag is PROMISC_SAP, but the current flag has
		 * changed to some new non-zero value, we need to turn the
		 * physical promiscuous mode.
		 */
		ASSERT(dsp->ds_mph != NULL);
		mac_promisc_remove(dsp->ds_mph);
		/* Honors both after-remove and before-add semantics! */
		dsp->ds_promisc = new_flags;
		err = mac_promisc_add(dsp->ds_mch, mptype,
		    dls_rx_promisc, dsp, &dsp->ds_mph, 0);
		if (err != 0)
			dsp->ds_promisc = old_flags;
	} else {
		/* No adding or removing, but record the new flags anyway. */
		dsp->ds_promisc = new_flags;
	}

	return (err);
}

int
dls_multicst_add(dld_str_t *dsp, const uint8_t *addr)
{
	int			err;
	dls_multicst_addr_t	**pp;
	dls_multicst_addr_t	*p;
	uint_t			addr_length;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	/*
	 * Check whether the address is in the list of enabled addresses for
	 * this dld_str_t.
	 */
	addr_length = dsp->ds_mip->mi_addr_length;

	/*
	 * Protect against concurrent access of ds_dmap by data threads using
	 * ds_rw_lock. The mac perimeter serializes the dls_multicst_add and
	 * remove operations. Dropping the ds_rw_lock across mac calls is thus
	 * ok and is also required by the locking protocol.
	 */
	rw_enter(&dsp->ds_rw_lock, RW_WRITER);
	for (pp = &(dsp->ds_dmap); (p = *pp) != NULL; pp = &(p->dma_nextp)) {
		if (bcmp(addr, p->dma_addr, addr_length) == 0) {
			/*
			 * It is there so there's nothing to do.
			 */
			err = 0;
			goto done;
		}
	}

	/*
	 * Allocate a new list item and add it to the list.
	 */
	p = kmem_zalloc(sizeof (dls_multicst_addr_t), KM_SLEEP);
	bcopy(addr, p->dma_addr, addr_length);
	*pp = p;
	rw_exit(&dsp->ds_rw_lock);

	/*
	 * Enable the address at the MAC.
	 */
	err = mac_multicast_add(dsp->ds_mch, addr);
	if (err == 0)
		return (0);

	/* Undo the operation as it has failed */
	rw_enter(&dsp->ds_rw_lock, RW_WRITER);
	ASSERT(*pp == p && p->dma_nextp == NULL);
	*pp = NULL;
	kmem_free(p, sizeof (dls_multicst_addr_t));
done:
	rw_exit(&dsp->ds_rw_lock);
	return (err);
}

int
dls_multicst_remove(dld_str_t *dsp, const uint8_t *addr)
{
	dls_multicst_addr_t	**pp;
	dls_multicst_addr_t	*p;
	uint_t			addr_length;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	/*
	 * Find the address in the list of enabled addresses for this
	 * dld_str_t.
	 */
	addr_length = dsp->ds_mip->mi_addr_length;

	/*
	 * Protect against concurrent access to ds_dmap by data threads using
	 * ds_rw_lock. The mac perimeter serializes the dls_multicst_add and
	 * remove operations. Dropping the ds_rw_lock across mac calls is thus
	 * ok and is also required by the locking protocol.
	 */
	rw_enter(&dsp->ds_rw_lock, RW_WRITER);
	for (pp = &(dsp->ds_dmap); (p = *pp) != NULL; pp = &(p->dma_nextp)) {
		if (bcmp(addr, p->dma_addr, addr_length) == 0)
			break;
	}

	/*
	 * If we walked to the end of the list then the given address is
	 * not currently enabled for this dld_str_t.
	 */
	if (p == NULL) {
		rw_exit(&dsp->ds_rw_lock);
		return (ENOENT);
	}

	/*
	 * Remove the address from the list.
	 */
	*pp = p->dma_nextp;
	rw_exit(&dsp->ds_rw_lock);

	/*
	 * Disable the address at the MAC.
	 */
	mac_multicast_remove(dsp->ds_mch, addr);
	kmem_free(p, sizeof (dls_multicst_addr_t));
	return (0);
}

mblk_t *
dls_header(dld_str_t *dsp, const uint8_t *addr, uint16_t sap, uint_t pri,
    mblk_t **payloadp)
{
	uint16_t vid;
	size_t extra_len;
	uint16_t mac_sap;
	mblk_t *mp, *payload;
	boolean_t is_ethernet = (dsp->ds_mip->mi_media == DL_ETHER);
	struct ether_vlan_header *evhp;

	vid = mac_client_vid(dsp->ds_mch);
	payload = (payloadp == NULL) ? NULL : (*payloadp);

	/*
	 * In the case of Ethernet, we need to tell mac_header() if we need
	 * extra room beyond the Ethernet header for a VLAN header.  We'll
	 * need to add a VLAN header if this isn't an ETHERTYPE_VLAN listener
	 * (because such streams will be handling VLAN headers on their own)
	 * and one of the following conditions is satisfied:
	 *
	 * - This is a VLAN stream
	 * - This is a physical stream, the priority is not 0, and user
	 *   priority tagging is allowed.
	 */
	if (is_ethernet && sap != ETHERTYPE_VLAN &&
	    (vid != VLAN_ID_NONE ||
	    (pri != 0 && dsp->ds_dlp->dl_tagmode != LINK_TAGMODE_VLANONLY))) {
		extra_len = sizeof (struct ether_vlan_header) -
		    sizeof (struct ether_header);
		mac_sap = ETHERTYPE_VLAN;
	} else {
		extra_len = 0;
		mac_sap = sap;
	}

	mp = mac_header(dsp->ds_mh, addr, mac_sap, payload, extra_len);
	if (mp == NULL)
		return (NULL);

	if ((vid == VLAN_ID_NONE && (pri == 0 ||
	    dsp->ds_dlp->dl_tagmode == LINK_TAGMODE_VLANONLY)) || !is_ethernet)
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

void
dls_rx_set(dld_str_t *dsp, dls_rx_t rx, void *arg)
{
	mutex_enter(&dsp->ds_lock);
	dsp->ds_rx = rx;
	dsp->ds_rx_arg = arg;
	mutex_exit(&dsp->ds_lock);
}

static boolean_t
dls_accept_common(dld_str_t *dsp, mac_header_info_t *mhip, dls_rx_t *ds_rx,
    void **ds_rx_arg, boolean_t promisc, boolean_t promisc_loopback)
{
	dls_multicst_addr_t	*dmap;
	size_t			addr_length = dsp->ds_mip->mi_addr_length;

	/*
	 * We must not accept packets if the dld_str_t is not marked as bound
	 * or is being removed.
	 */
	if (dsp->ds_dlstate != DL_IDLE)
		goto refuse;

	if (dsp->ds_promisc != 0) {
		/*
		 * Filter out packets that arrived from the data path
		 * (i_dls_link_rx) when promisc mode is on. We need to correlate
		 * the ds_promisc flags with the mac header destination type. If
		 * only DLS_PROMISC_MULTI is enabled, we need to only reject
		 * multicast packets as those are the only ones which filter up
		 * the promiscuous path. If we have DLS_PROMISC_PHYS or
		 * DLS_PROMISC_SAP set, then we know that we'll be seeing
		 * everything, so we should drop it now.
		 */
		if (!promisc && !(dsp->ds_promisc == DLS_PROMISC_MULTI &&
		    mhip->mhi_dsttype != MAC_ADDRTYPE_MULTICAST))
			goto refuse;
		/*
		 * If the dls_impl_t is in 'all physical' mode then
		 * always accept.
		 */
		if (dsp->ds_promisc & DLS_PROMISC_PHYS)
			goto accept;

		/*
		 * Loopback packets i.e. packets sent out by DLS on a given
		 * mac end point, will be accepted back by DLS on loopback
		 * from the mac, only in the 'all physical' mode which has been
		 * covered by the previous check above
		 */
		if (promisc_loopback)
			goto refuse;
	}

	switch (mhip->mhi_dsttype) {
	case MAC_ADDRTYPE_UNICAST:
	case MAC_ADDRTYPE_BROADCAST:
		/*
		 * We can accept unicast and broadcast packets because
		 * filtering is already done by the mac layer.
		 */
		goto accept;
	case MAC_ADDRTYPE_MULTICAST:
		/*
		 * Additional filtering is needed for multicast addresses
		 * because different streams may be interested in different
		 * addresses.
		 */
		if (dsp->ds_promisc & DLS_PROMISC_MULTI)
			goto accept;

		rw_enter(&dsp->ds_rw_lock, RW_READER);
		for (dmap = dsp->ds_dmap; dmap != NULL;
		    dmap = dmap->dma_nextp) {
			if (memcmp(mhip->mhi_daddr, dmap->dma_addr,
			    addr_length) == 0) {
				rw_exit(&dsp->ds_rw_lock);
				goto accept;
			}
		}
		rw_exit(&dsp->ds_rw_lock);
		break;
	}

refuse:
	return (B_FALSE);

accept:
	/*
	 * the returned ds_rx and ds_rx_arg will always be in sync.
	 */
	mutex_enter(&dsp->ds_lock);
	*ds_rx = dsp->ds_rx;
	*ds_rx_arg = dsp->ds_rx_arg;
	mutex_exit(&dsp->ds_lock);

	return (B_TRUE);
}

/* ARGSUSED */
boolean_t
dls_accept(dld_str_t *dsp, mac_header_info_t *mhip, dls_rx_t *ds_rx,
    void **ds_rx_arg)
{
	return (dls_accept_common(dsp, mhip, ds_rx, ds_rx_arg, B_FALSE,
	    B_FALSE));
}

boolean_t
dls_accept_promisc(dld_str_t *dsp, mac_header_info_t *mhip, dls_rx_t *ds_rx,
    void **ds_rx_arg, boolean_t loopback)
{
	return (dls_accept_common(dsp, mhip, ds_rx, ds_rx_arg, B_TRUE,
	    loopback));
}

int
dls_mac_active_set(dls_link_t *dlp)
{
	int err = 0;

	/*
	 * First client; add the primary unicast address.
	 */
	if (dlp->dl_nactive == 0) {
		/*
		 * First client; add the primary unicast address.
		 */
		mac_diag_t diag;

		/* request the primary MAC address */
		if ((err = mac_unicast_add(dlp->dl_mch, NULL,
		    MAC_UNICAST_PRIMARY | MAC_UNICAST_TAG_DISABLE |
		    MAC_UNICAST_DISABLE_TX_VID_CHECK, &dlp->dl_mah, 0,
		    &diag)) != 0) {
			return (err);
		}

		/*
		 * Set the function to start receiving packets.
		 */
		mac_rx_set(dlp->dl_mch, i_dls_link_rx, dlp);
	}
	dlp->dl_nactive++;
	return (0);
}

void
dls_mac_active_clear(dls_link_t *dlp)
{
	if (--dlp->dl_nactive == 0) {
		ASSERT(dlp->dl_mah != NULL);
		(void) mac_unicast_remove(dlp->dl_mch, dlp->dl_mah);
		dlp->dl_mah = NULL;
		mac_rx_clear(dlp->dl_mch);
	}
}

int
dls_active_set(dld_str_t *dsp)
{
	int err = 0;

	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	if (dsp->ds_passivestate == DLD_PASSIVE)
		return (0);

	/* If we're already active, then there's nothing more to do. */
	if ((dsp->ds_nactive == 0) &&
	    ((err = dls_mac_active_set(dsp->ds_dlp)) != 0)) {
		/* except for ENXIO all other errors are mapped to EBUSY */
		if (err != ENXIO)
			return (EBUSY);
		return (err);
	}

	dsp->ds_passivestate = DLD_ACTIVE;
	dsp->ds_nactive++;
	return (0);
}

/*
 * Note that dls_active_set() is called whenever an active operation
 * (DL_BIND_REQ, DL_ENABMULTI_REQ ...) is processed and
 * dls_active_clear(dsp, B_FALSE) is called whenever the active operation
 * is being undone (DL_UNBIND_REQ, DL_DISABMULTI_REQ ...). In some cases,
 * a stream is closed without every active operation being undone and we
 * need to clear all the "active" states by calling
 * dls_active_clear(dsp, B_TRUE).
 */
void
dls_active_clear(dld_str_t *dsp, boolean_t all)
{
	ASSERT(MAC_PERIM_HELD(dsp->ds_mh));

	if (dsp->ds_passivestate == DLD_PASSIVE)
		return;

	if (all && dsp->ds_nactive == 0)
		return;

	ASSERT(dsp->ds_nactive > 0);

	dsp->ds_nactive -= (all ? dsp->ds_nactive : 1);
	if (dsp->ds_nactive != 0)
		return;

	ASSERT(dsp->ds_passivestate == DLD_ACTIVE);
	dls_mac_active_clear(dsp->ds_dlp);
	dsp->ds_passivestate = DLD_UNINITIALIZED;
}
