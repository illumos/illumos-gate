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
 */

#include <sys/strsun.h>
#include <sys/sdt.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/dlpi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/arp.h>

/*
 * Check if ipaddr is in the 'allowed-ips' list.
 */
static boolean_t
ipnospoof_check_ips(mac_protect_t *protect, ipaddr_t ipaddr)
{
	uint_t i;

	/*
	 * unspecified addresses are harmless and are used by ARP,DHCP..etc.
	 */
	if (ipaddr == INADDR_ANY)
		return (B_TRUE);

	for (i = 0; i < protect->mp_ipaddrcnt; i++) {
		if (protect->mp_ipaddrs[i] == ipaddr)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Enforce ip-nospoof protection. Only IPv4 is supported for now.
 */
static int
ipnospoof_check(mac_client_impl_t *mcip, mac_protect_t *protect,
    mblk_t *mp, mac_header_info_t *mhip)
{
	uint32_t	sap = mhip->mhi_bindsap;
	uchar_t		*start = mp->b_rptr + mhip->mhi_hdrsize;
	int		err = EINVAL;

	/*
	 * This handles the case where the mac header is not in
	 * the same mblk as the IP header.
	 */
	if (start == mp->b_wptr) {
		mp = mp->b_cont;

		/*
		 * IP header missing. Let the packet through.
		 */
		if (mp == NULL)
			return (0);

		start = mp->b_rptr;
	}

	switch (sap) {
	case ETHERTYPE_IP: {
		ipha_t	*ipha = (ipha_t *)start;

		if (start + sizeof (ipha_t) > mp->b_wptr || !OK_32PTR(start))
			goto fail;

		if (!ipnospoof_check_ips(protect, ipha->ipha_src))
			goto fail;

		break;
	}
	case ETHERTYPE_ARP: {
		arh_t		*arh = (arh_t *)start;
		uint32_t	maclen, hlen, plen, arplen;
		ipaddr_t	spaddr;
		uchar_t		*shaddr;

		if (start + sizeof (arh_t) > mp->b_wptr)
			goto fail;

		maclen = mcip->mci_mip->mi_info.mi_addr_length;
		hlen = arh->arh_hlen;
		plen = arh->arh_plen;
		if ((hlen != 0 && hlen != maclen) ||
		    plen != sizeof (ipaddr_t))
			goto fail;

		arplen = sizeof (arh_t) + 2 * hlen + 2 * plen;
		if (start + arplen > mp->b_wptr)
			goto fail;

		shaddr = start + sizeof (arh_t);
		if (hlen != 0 &&
		    bcmp(mcip->mci_unicast->ma_addr, shaddr, maclen) != 0)
			goto fail;

		bcopy(shaddr + hlen, &spaddr, sizeof (spaddr));
		if (!ipnospoof_check_ips(protect, spaddr))
			goto fail;
		break;
	}
	default:
		break;
	}
	return (0);

fail:
	/* increment ipnospoof stat here */
	return (err);
}

/*
 * Enforce link protection on one packet.
 */
static int
mac_protect_check_one(mac_client_impl_t *mcip, mblk_t *mp)
{
	mac_impl_t		*mip = mcip->mci_mip;
	mac_resource_props_t	*mrp = MCIP_RESOURCE_PROPS(mcip);
	mac_protect_t		*protect;
	mac_header_info_t	mhi;
	uint32_t		types;
	int			err;

	ASSERT(mp->b_next == NULL);
	ASSERT(mrp != NULL);

	err = mac_vlan_header_info((mac_handle_t)mip, mp, &mhi);
	if (err != 0) {
		DTRACE_PROBE2(invalid__header, mac_client_impl_t *, mcip,
		    mblk_t *, mp);
		return (err);
	}

	protect = &mrp->mrp_protect;
	types = protect->mp_types;

	if ((types & MPT_MACNOSPOOF) != 0) {
		if (mhi.mhi_saddr != NULL &&
		    bcmp(mcip->mci_unicast->ma_addr, mhi.mhi_saddr,
		    mip->mi_info.mi_addr_length) != 0) {
			DTRACE_PROBE2(mac__nospoof__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (EINVAL);
		}
	}

	if ((types & MPT_RESTRICTED) != 0) {
		uint32_t	vid = VLAN_ID(mhi.mhi_tci);
		uint32_t	sap = mhi.mhi_bindsap;

		/*
		 * ETHERTYPE_VLAN packets are allowed through, provided that
		 * the vid is not spoofed.
		 */
		if (vid != 0 && !mac_client_check_flow_vid(mcip, vid)) {
			DTRACE_PROBE2(restricted__vid__invalid,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (EINVAL);
		}

		if (sap != ETHERTYPE_IP && sap != ETHERTYPE_IPV6 &&
		    sap != ETHERTYPE_ARP) {
			DTRACE_PROBE2(restricted__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (EINVAL);
		}
	}

	if ((types & MPT_IPNOSPOOF) != 0) {
		if ((err = ipnospoof_check(mcip, protect,
		    mp, &mhi)) != 0) {
			DTRACE_PROBE2(ip__nospoof__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (err);
		}
	}
	return (0);
}

/*
 * Enforce link protection on a packet chain.
 * Packets that pass the checks are returned back to the caller.
 */
mblk_t *
mac_protect_check(mac_client_handle_t mch, mblk_t *mp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mblk_t			*ret_mp = NULL, **tailp = &ret_mp, *next;

	/*
	 * Skip checks if we are part of an aggr.
	 */
	if ((mcip->mci_state_flags & MCIS_IS_AGGR_PORT) != 0)
		return (mp);

	for (; mp != NULL; mp = next) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (mac_protect_check_one(mcip, mp) == 0) {
			*tailp = mp;
			tailp = &mp->b_next;
		} else {
			freemsg(mp);
		}
	}
	return (ret_mp);
}

/*
 * Check if a particular protection type is enabled.
 */
boolean_t
mac_protect_enabled(mac_client_handle_t mch, uint32_t type)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_resource_props_t	*mrp = MCIP_RESOURCE_PROPS(mcip);

	ASSERT(mrp != NULL);
	return ((mrp->mrp_protect.mp_types & type) != 0);
}

/*
 * Sanity-checks parameters given by userland.
 */
int
mac_protect_validate(mac_resource_props_t *mrp)
{
	mac_protect_t	*p = &mrp->mrp_protect;

	/* check for invalid types */
	if (p->mp_types != MPT_RESET && (p->mp_types & ~MPT_ALL) != 0)
		return (EINVAL);

	if (p->mp_ipaddrcnt != MPT_RESET) {
		uint_t	i, j;

		if (p->mp_ipaddrcnt > MPT_MAXIPADDR)
			return (EINVAL);

		for (i = 0; i < p->mp_ipaddrcnt; i++) {
			/*
			 * The unspecified address is implicitly allowed
			 * so there's no need to add it to the list.
			 */
			if (p->mp_ipaddrs[i] == INADDR_ANY)
				return (EINVAL);

			for (j = 0; j < p->mp_ipaddrcnt; j++) {
				/* found a duplicate */
				if (i != j &&
				    p->mp_ipaddrs[i] == p->mp_ipaddrs[j])
					return (EINVAL);
			}
		}
	}
	return (0);
}

/*
 * Enable/disable link protection.
 */
int
mac_protect_set(mac_client_handle_t mch, mac_resource_props_t *mrp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	uint_t			media = mip->mi_info.mi_nativemedia;
	int			err;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/* tunnels are not supported */
	if (media == DL_IPV4 || media == DL_IPV6 || media == DL_6TO4)
		return (ENOTSUP);

	if ((err = mac_protect_validate(mrp)) != 0)
		return (err);

	mac_update_resources(mrp, MCIP_RESOURCE_PROPS(mcip), B_FALSE);
	return (0);
}

void
mac_protect_update(mac_resource_props_t *new, mac_resource_props_t *curr)
{
	mac_protect_t	*np = &new->mrp_protect;
	mac_protect_t	*cp = &curr->mrp_protect;
	uint32_t	types = np->mp_types;

	if (types == MPT_RESET) {
		cp->mp_types = 0;
		curr->mrp_mask &= ~MRP_PROTECT;
	} else {
		if (types != 0) {
			cp->mp_types = types;
			curr->mrp_mask |= MRP_PROTECT;
		}
	}

	if (np->mp_ipaddrcnt != 0) {
		if (np->mp_ipaddrcnt < MPT_MAXIPADDR) {
			bcopy(np->mp_ipaddrs, cp->mp_ipaddrs,
			    sizeof (cp->mp_ipaddrs));
			cp->mp_ipaddrcnt = np->mp_ipaddrcnt;
		} else if (np->mp_ipaddrcnt == MPT_RESET) {
			bzero(cp->mp_ipaddrs, sizeof (cp->mp_ipaddrs));
			cp->mp_ipaddrcnt = 0;
		}
	}
}
