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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

/*
 * MAC Services Module - misc utilities
 */

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_soft_ring.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/vlan.h>
#include <sys/pattr.h>
#include <sys/pci_tools.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/sunndi.h>
#include <inet/ipsec_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>

/*
 * Copy an mblk, preserving its hardware checksum flags.
 */
static mblk_t *
mac_copymsg_cksum(mblk_t *mp)
{
	mblk_t *mp1;

	mp1 = copymsg(mp);
	if (mp1 == NULL)
		return (NULL);

	mac_hcksum_clone(mp, mp1);

	return (mp1);
}

/*
 * Copy an mblk chain, presenting the hardware checksum flags of the
 * individual mblks.
 */
mblk_t *
mac_copymsgchain_cksum(mblk_t *mp)
{
	mblk_t *nmp = NULL;
	mblk_t **nmpp = &nmp;

	for (; mp != NULL; mp = mp->b_next) {
		if ((*nmpp = mac_copymsg_cksum(mp)) == NULL) {
			freemsgchain(nmp);
			return (NULL);
		}

		nmpp = &((*nmpp)->b_next);
	}

	return (nmp);
}

/*
 * Process the specified mblk chain for proper handling of hardware
 * checksum offload. This routine is invoked for loopback traffic
 * between MAC clients.
 * The function handles a NULL mblk chain passed as argument.
 */
mblk_t *
mac_fix_cksum(mblk_t *mp_chain)
{
	mblk_t *mp, *prev = NULL, *new_chain = mp_chain, *mp1;
	uint32_t flags, start, stuff, end, value;

	for (mp = mp_chain; mp != NULL; prev = mp, mp = mp->b_next) {
		uint16_t len;
		uint32_t offset;
		struct ether_header *ehp;
		uint16_t sap;
		mblk_t *skipped_hdr = NULL;

		mac_hcksum_get(mp, &start, &stuff, &end, &value, &flags);
		if (flags == 0)
			continue;

		/*
		 * Since the processing of checksum offload for loopback
		 * traffic requires modification of the packet contents,
		 * ensure sure that we are always modifying our own copy.
		 */
		if (DB_REF(mp) > 1) {
			mp1 = copymsg(mp);
			if (mp1 == NULL)
				continue;
			mp1->b_next = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			if (prev != NULL)
				prev->b_next = mp1;
			else
				new_chain = mp1;
			mp = mp1;
		}

		/*
		 * Ethernet, and optionally VLAN header.
		 */
		/* LINTED: improper alignment cast */
		ehp = (struct ether_header *)mp->b_rptr;
		if (ntohs(ehp->ether_type) == VLAN_TPID) {
			struct ether_vlan_header *evhp;

			ASSERT(MBLKL(mp) >= sizeof (struct ether_vlan_header));
			/* LINTED: improper alignment cast */
			evhp = (struct ether_vlan_header *)mp->b_rptr;
			sap = ntohs(evhp->ether_type);
			offset = sizeof (struct ether_vlan_header);
		} else {
			sap = ntohs(ehp->ether_type);
			offset = sizeof (struct ether_header);
		}

		/*
		 * If the first mblk in the chain for this packet contains only
		 * the ethernet header, skip past it for now.  Packets with
		 * their data contained in only a single mblk can then use the
		 * fastpaths tuned to that possibility.
		 */
		if (MBLKL(mp) <= offset) {
			offset -= MBLKL(mp);
			if (mp->b_cont == NULL) {
				/* corrupted packet, skip it */
				if (prev != NULL)
					prev->b_next = mp->b_next;
				else
					new_chain = mp->b_next;
				mp1 = mp->b_next;
				mp->b_next = NULL;
				freemsg(mp);
				mp = mp1;
				continue;
			}
			skipped_hdr = mp;
			mp = mp->b_cont;
		}

		if (flags & (HCK_FULLCKSUM | HCK_IPV4_HDRCKSUM)) {
			ipha_t *ipha = NULL;

			/*
			 * In order to compute the full and header
			 * checksums, we need to find and parse
			 * the IP and/or ULP headers.
			 */

			sap = (sap < ETHERTYPE_802_MIN) ? 0 : sap;

			/*
			 * IP header.
			 */
			if (sap != ETHERTYPE_IP)
				continue;

			ASSERT(MBLKL(mp) >= offset + sizeof (ipha_t));
			/* LINTED: improper alignment cast */
			ipha = (ipha_t *)(mp->b_rptr + offset);

			if (flags & HCK_FULLCKSUM) {
				ipaddr_t src, dst;
				uint32_t cksum;
				uint16_t *up;
				uint8_t proto;

				/*
				 * Pointer to checksum field in ULP header.
				 */
				proto = ipha->ipha_protocol;
				ASSERT(ipha->ipha_version_and_hdr_length ==
				    IP_SIMPLE_HDR_VERSION);

				switch (proto) {
				case IPPROTO_TCP:
					/* LINTED: improper alignment cast */
					up = IPH_TCPH_CHECKSUMP(ipha,
					    IP_SIMPLE_HDR_LENGTH);
					break;

				case IPPROTO_UDP:
					/* LINTED: improper alignment cast */
					up = IPH_UDPH_CHECKSUMP(ipha,
					    IP_SIMPLE_HDR_LENGTH);
					break;

				default:
					cmn_err(CE_WARN, "mac_fix_cksum: "
					    "unexpected protocol: %d", proto);
					continue;
				}

				/*
				 * Pseudo-header checksum.
				 */
				src = ipha->ipha_src;
				dst = ipha->ipha_dst;
				len = ntohs(ipha->ipha_length) -
				    IP_SIMPLE_HDR_LENGTH;

				cksum = (dst >> 16) + (dst & 0xFFFF) +
				    (src >> 16) + (src & 0xFFFF);
				cksum += htons(len);

				/*
				 * The checksum value stored in the packet needs
				 * to be correct. Compute it here.
				 */
				*up = 0;
				cksum += (((proto) == IPPROTO_UDP) ?
				    IP_UDP_CSUM_COMP : IP_TCP_CSUM_COMP);
				cksum = IP_CSUM(mp, IP_SIMPLE_HDR_LENGTH +
				    offset, cksum);
				*(up) = (uint16_t)(cksum ? cksum : ~cksum);

				/*
				 * Flag the packet so that it appears
				 * that the checksum has already been
				 * verified by the hardware.
				 */
				flags &= ~HCK_FULLCKSUM;
				flags |= HCK_FULLCKSUM_OK;
				value = 0;
			}

			if (flags & HCK_IPV4_HDRCKSUM) {
				ASSERT(ipha != NULL);
				ipha->ipha_hdr_checksum =
				    (uint16_t)ip_csum_hdr(ipha);
				flags &= ~HCK_IPV4_HDRCKSUM;
				flags |= HCK_IPV4_HDRCKSUM_OK;

			}
		}

		if (flags & HCK_PARTIALCKSUM) {
			uint16_t *up, partial, cksum;
			uchar_t *ipp; /* ptr to beginning of IP header */
			mblk_t *old_mp = NULL;

			if (mp->b_cont != NULL) {
				mblk_t *new_mp;

				new_mp = msgpullup(mp, offset + end);
				if (new_mp == NULL) {
					continue;
				}
				old_mp = mp;
				mp = new_mp;
			}

			ipp = mp->b_rptr + offset;
			/* LINTED: cast may result in improper alignment */
			up = (uint16_t *)((uchar_t *)ipp + stuff);
			partial = *up;
			*up = 0;

			cksum = IP_BCSUM_PARTIAL(mp->b_rptr + offset + start,
			    end - start, partial);
			cksum = ~cksum;
			*up = cksum ? cksum : ~cksum;

			/*
			 * Since we already computed the whole checksum,
			 * indicate to the stack that it has already
			 * been verified by the hardware.
			 */
			flags &= ~HCK_PARTIALCKSUM;
			flags |= HCK_FULLCKSUM_OK;
			value = 0;

			/*
			 * If 'mp' is the result of a msgpullup(), it needs to
			 * be properly reattached into the existing chain of
			 * messages before continuing.
			 */
			if (old_mp != NULL) {
				if (skipped_hdr != NULL) {
					/*
					 * If the ethernet header was cast
					 * aside before checksum calculation,
					 * prepare for it to be reattached to
					 * the pulled-up mblk.
					 */
					skipped_hdr->b_cont = mp;
				} else {
					/* Link the new mblk into the chain. */
					mp->b_next = old_mp->b_next;

					if (prev != NULL)
						prev->b_next = mp;
					else
						new_chain = mp;
				}

				old_mp->b_next = NULL;
				freemsg(old_mp);
			}
		}

		mac_hcksum_set(mp, start, stuff, end, value, flags);

		/*
		 * If the header was skipped over, we must seek back to it,
		 * since it is that mblk that is part of any packet chain.
		 */
		if (skipped_hdr != NULL) {
			ASSERT3P(skipped_hdr->b_cont, ==, mp);

			/*
			 * Duplicate the HCKSUM data into the header mblk.
			 * This mimics mac_add_vlan_tag which ensures that both
			 * the first mblk _and_ the first data bearing mblk
			 * possess the HCKSUM information.  Consumers like IP
			 * will end up discarding the ether_header mblk, so for
			 * now, it is important that the data be available in
			 * both places.
			 */
			mac_hcksum_clone(mp, skipped_hdr);
			mp = skipped_hdr;
		}
	}

	return (new_chain);
}

/*
 * Add VLAN tag to the specified mblk.
 */
mblk_t *
mac_add_vlan_tag(mblk_t *mp, uint_t pri, uint16_t vid)
{
	mblk_t *hmp;
	struct ether_vlan_header *evhp;
	struct ether_header *ehp;

	ASSERT(pri != 0 || vid != 0);

	/*
	 * Allocate an mblk for the new tagged ethernet header,
	 * and copy the MAC addresses and ethertype from the
	 * original header.
	 */

	hmp = allocb(sizeof (struct ether_vlan_header), BPRI_MED);
	if (hmp == NULL) {
		freemsg(mp);
		return (NULL);
	}

	evhp = (struct ether_vlan_header *)hmp->b_rptr;
	ehp = (struct ether_header *)mp->b_rptr;

	bcopy(ehp, evhp, (ETHERADDRL * 2));
	evhp->ether_type = ehp->ether_type;
	evhp->ether_tpid = htons(ETHERTYPE_VLAN);

	hmp->b_wptr += sizeof (struct ether_vlan_header);
	mp->b_rptr += sizeof (struct ether_header);

	/*
	 * Free the original message if it's now empty. Link the
	 * rest of messages to the header message.
	 */
	mac_hcksum_clone(mp, hmp);
	if (MBLKL(mp) == 0) {
		hmp->b_cont = mp->b_cont;
		freeb(mp);
	} else {
		hmp->b_cont = mp;
	}
	ASSERT(MBLKL(hmp) >= sizeof (struct ether_vlan_header));

	/*
	 * Initialize the new TCI (Tag Control Information).
	 */
	evhp->ether_tci = htons(VLAN_TCI(pri, 0, vid));

	return (hmp);
}

/*
 * Adds a VLAN tag with the specified VID and priority to each mblk of
 * the specified chain.
 */
mblk_t *
mac_add_vlan_tag_chain(mblk_t *mp_chain, uint_t pri, uint16_t vid)
{
	mblk_t *next_mp, **prev, *mp;

	mp = mp_chain;
	prev = &mp_chain;

	while (mp != NULL) {
		next_mp = mp->b_next;
		mp->b_next = NULL;
		if ((mp = mac_add_vlan_tag(mp, pri, vid)) == NULL) {
			freemsgchain(next_mp);
			break;
		}
		*prev = mp;
		prev = &mp->b_next;
		mp = mp->b_next = next_mp;
	}

	return (mp_chain);
}

/*
 * Strip VLAN tag
 */
mblk_t *
mac_strip_vlan_tag(mblk_t *mp)
{
	mblk_t *newmp;
	struct ether_vlan_header *evhp;

	evhp = (struct ether_vlan_header *)mp->b_rptr;
	if (ntohs(evhp->ether_tpid) == ETHERTYPE_VLAN) {
		ASSERT(MBLKL(mp) >= sizeof (struct ether_vlan_header));

		if (DB_REF(mp) > 1) {
			newmp = copymsg(mp);
			if (newmp == NULL)
				return (NULL);
			freemsg(mp);
			mp = newmp;
		}

		evhp = (struct ether_vlan_header *)mp->b_rptr;

		ovbcopy(mp->b_rptr, mp->b_rptr + VLAN_TAGSZ, 2 * ETHERADDRL);
		mp->b_rptr += VLAN_TAGSZ;
	}
	return (mp);
}

/*
 * Strip VLAN tag from each mblk of the chain.
 */
mblk_t *
mac_strip_vlan_tag_chain(mblk_t *mp_chain)
{
	mblk_t *mp, *next_mp, **prev;

	mp = mp_chain;
	prev = &mp_chain;

	while (mp != NULL) {
		next_mp = mp->b_next;
		mp->b_next = NULL;
		if ((mp = mac_strip_vlan_tag(mp)) == NULL) {
			freemsgchain(next_mp);
			break;
		}
		*prev = mp;
		prev = &mp->b_next;
		mp = mp->b_next = next_mp;
	}

	return (mp_chain);
}

/*
 * Default callback function. Used when the datapath is not yet initialized.
 */
/* ARGSUSED */
void
mac_pkt_drop(void *arg, mac_resource_handle_t resource, mblk_t *mp,
    boolean_t loopback)
{
	mblk_t	*mp1 = mp;

	while (mp1 != NULL) {
		mp1->b_prev = NULL;
		mp1->b_queue = NULL;
		mp1 = mp1->b_next;
	}
	freemsgchain(mp);
}

/*
 * Determines the IPv6 header length accounting for all the optional IPv6
 * headers (hop-by-hop, destination, routing and fragment). The header length
 * and next header value (a transport header) is captured.
 *
 * Returns B_FALSE if all the IP headers are not in the same mblk otherwise
 * returns B_TRUE.
 */
boolean_t
mac_ip_hdr_length_v6(ip6_t *ip6h, uint8_t *endptr, uint16_t *hdr_length,
    uint8_t *next_hdr, ip6_frag_t **fragp)
{
	uint16_t length;
	uint_t	ehdrlen;
	uint8_t *whereptr;
	uint8_t *nexthdrp;
	ip6_dest_t *desthdr;
	ip6_rthdr_t *rthdr;
	ip6_frag_t *fraghdr;

	if (((uchar_t *)ip6h + IPV6_HDR_LEN) > endptr)
		return (B_FALSE);
	ASSERT(IPH_HDR_VERSION(ip6h) == IPV6_VERSION);
	length = IPV6_HDR_LEN;
	whereptr = ((uint8_t *)&ip6h[1]); /* point to next hdr */

	if (fragp != NULL)
		*fragp = NULL;

	nexthdrp = &ip6h->ip6_nxt;
	while (whereptr < endptr) {
		/* Is there enough left for len + nexthdr? */
		if (whereptr + MIN_EHDR_LEN > endptr)
			break;

		switch (*nexthdrp) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			/* Assumes the headers are identical for hbh and dst */
			desthdr = (ip6_dest_t *)whereptr;
			ehdrlen = 8 * (desthdr->ip6d_len + 1);
			if ((uchar_t *)desthdr +  ehdrlen > endptr)
				return (B_FALSE);
			nexthdrp = &desthdr->ip6d_nxt;
			break;
		case IPPROTO_ROUTING:
			rthdr = (ip6_rthdr_t *)whereptr;
			ehdrlen =  8 * (rthdr->ip6r_len + 1);
			if ((uchar_t *)rthdr +  ehdrlen > endptr)
				return (B_FALSE);
			nexthdrp = &rthdr->ip6r_nxt;
			break;
		case IPPROTO_FRAGMENT:
			fraghdr = (ip6_frag_t *)whereptr;
			ehdrlen = sizeof (ip6_frag_t);
			if ((uchar_t *)&fraghdr[1] > endptr)
				return (B_FALSE);
			nexthdrp = &fraghdr->ip6f_nxt;
			if (fragp != NULL)
				*fragp = fraghdr;
			break;
		case IPPROTO_NONE:
			/* No next header means we're finished */
		default:
			*hdr_length = length;
			*next_hdr = *nexthdrp;
			return (B_TRUE);
		}
		length += ehdrlen;
		whereptr += ehdrlen;
		*hdr_length = length;
		*next_hdr = *nexthdrp;
	}
	switch (*nexthdrp) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
		/*
		 * If any know extension headers are still to be processed,
		 * the packet's malformed (or at least all the IP header(s) are
		 * not in the same mblk - and that should never happen.
		 */
		return (B_FALSE);

	default:
		/*
		 * If we get here, we know that all of the IP headers were in
		 * the same mblk, even if the ULP header is in the next mblk.
		 */
		*hdr_length = length;
		*next_hdr = *nexthdrp;
		return (B_TRUE);
	}
}

/*
 * The following set of routines are there to take care of interrupt
 * re-targeting for legacy (fixed) interrupts. Some older versions
 * of the popular NICs like e1000g do not support MSI-X interrupts
 * and they reserve fixed interrupts for RX/TX rings. To re-target
 * these interrupts, PCITOOL ioctls need to be used.
 */
typedef struct mac_dladm_intr {
	int	ino;
	int	cpu_id;
	char	driver_path[MAXPATHLEN];
	char	nexus_path[MAXPATHLEN];
} mac_dladm_intr_t;

/* Bind the interrupt to cpu_num */
static int
mac_set_intr(ldi_handle_t lh, processorid_t cpu_num, int oldcpuid, int ino)
{
	pcitool_intr_set_t	iset;
	int			err;

	iset.old_cpu = oldcpuid;
	iset.ino = ino;
	iset.cpu_id = cpu_num;
	iset.user_version = PCITOOL_VERSION;
	err = ldi_ioctl(lh, PCITOOL_DEVICE_SET_INTR, (intptr_t)&iset, FKIOCTL,
	    kcred, NULL);

	return (err);
}

/*
 * Search interrupt information. iget is filled in with the info to search
 */
static boolean_t
mac_search_intrinfo(pcitool_intr_get_t *iget_p, mac_dladm_intr_t *dln)
{
	int	i;
	char	driver_path[2 * MAXPATHLEN];

	for (i = 0; i < iget_p->num_devs; i++) {
		(void) strlcpy(driver_path, iget_p->dev[i].path, MAXPATHLEN);
		(void) snprintf(&driver_path[strlen(driver_path)], MAXPATHLEN,
		    ":%s%d", iget_p->dev[i].driver_name,
		    iget_p->dev[i].dev_inst);
		/* Match the device path for the device path */
		if (strcmp(driver_path, dln->driver_path) == 0) {
			dln->ino = iget_p->ino;
			dln->cpu_id = iget_p->cpu_id;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Get information about ino, i.e. if this is the interrupt for our
 * device and where it is bound etc.
 */
static boolean_t
mac_get_single_intr(ldi_handle_t lh, int oldcpuid, int ino,
    mac_dladm_intr_t *dln)
{
	pcitool_intr_get_t	*iget_p;
	int			ipsz;
	int			nipsz;
	int			err;
	uint8_t			inum;

	/*
	 * Check if SLEEP is OK, i.e if could come here in response to
	 * changing the fanout due to some callback from the driver, say
	 * link speed changes.
	 */
	ipsz = PCITOOL_IGET_SIZE(0);
	iget_p = kmem_zalloc(ipsz, KM_SLEEP);

	iget_p->num_devs_ret = 0;
	iget_p->user_version = PCITOOL_VERSION;
	iget_p->cpu_id = oldcpuid;
	iget_p->ino = ino;

	err = ldi_ioctl(lh, PCITOOL_DEVICE_GET_INTR, (intptr_t)iget_p,
	    FKIOCTL, kcred, NULL);
	if (err != 0) {
		kmem_free(iget_p, ipsz);
		return (B_FALSE);
	}
	if (iget_p->num_devs == 0) {
		kmem_free(iget_p, ipsz);
		return (B_FALSE);
	}
	inum = iget_p->num_devs;
	if (iget_p->num_devs_ret < iget_p->num_devs) {
		/* Reallocate */
		nipsz = PCITOOL_IGET_SIZE(iget_p->num_devs);

		kmem_free(iget_p, ipsz);
		ipsz = nipsz;
		iget_p = kmem_zalloc(ipsz, KM_SLEEP);

		iget_p->num_devs_ret = inum;
		iget_p->cpu_id = oldcpuid;
		iget_p->ino = ino;
		iget_p->user_version = PCITOOL_VERSION;
		err = ldi_ioctl(lh, PCITOOL_DEVICE_GET_INTR, (intptr_t)iget_p,
		    FKIOCTL, kcred, NULL);
		if (err != 0) {
			kmem_free(iget_p, ipsz);
			return (B_FALSE);
		}
		/* defensive */
		if (iget_p->num_devs != iget_p->num_devs_ret) {
			kmem_free(iget_p, ipsz);
			return (B_FALSE);
		}
	}

	if (mac_search_intrinfo(iget_p, dln)) {
		kmem_free(iget_p, ipsz);
		return (B_TRUE);
	}
	kmem_free(iget_p, ipsz);
	return (B_FALSE);
}

/*
 * Get the interrupts and check each one to see if it is for our device.
 */
static int
mac_validate_intr(ldi_handle_t lh, mac_dladm_intr_t *dln, processorid_t cpuid)
{
	pcitool_intr_info_t	intr_info;
	int			err;
	int			ino;
	int			oldcpuid;

	err = ldi_ioctl(lh, PCITOOL_SYSTEM_INTR_INFO, (intptr_t)&intr_info,
	    FKIOCTL, kcred, NULL);
	if (err != 0)
		return (-1);

	for (oldcpuid = 0; oldcpuid < intr_info.num_cpu; oldcpuid++) {
		for (ino = 0; ino < intr_info.num_intr; ino++) {
			if (mac_get_single_intr(lh, oldcpuid, ino, dln)) {
				if (dln->cpu_id == cpuid)
					return (0);
				return (1);
			}
		}
	}
	return (-1);
}

/*
 * Obtain the nexus parent node info. for mdip.
 */
static dev_info_t *
mac_get_nexus_node(dev_info_t *mdip, mac_dladm_intr_t *dln)
{
	struct dev_info		*tdip = (struct dev_info *)mdip;
	struct ddi_minor_data	*minordata;
	int			circ;
	dev_info_t		*pdip;
	char			pathname[MAXPATHLEN];

	while (tdip != NULL) {
		/*
		 * The netboot code could call this function while walking the
		 * device tree so we need to use ndi_devi_tryenter() here to
		 * avoid deadlock.
		 */
		if (ndi_devi_tryenter((dev_info_t *)tdip, &circ) == 0)
			break;

		for (minordata = tdip->devi_minor; minordata != NULL;
		    minordata = minordata->next) {
			if (strncmp(minordata->ddm_node_type, DDI_NT_INTRCTL,
			    strlen(DDI_NT_INTRCTL)) == 0) {
				pdip = minordata->dip;
				(void) ddi_pathname(pdip, pathname);
				(void) snprintf(dln->nexus_path, MAXPATHLEN,
				    "/devices%s:intr", pathname);
				(void) ddi_pathname_minor(minordata, pathname);
				ndi_devi_exit((dev_info_t *)tdip, circ);
				return (pdip);
			}
		}
		ndi_devi_exit((dev_info_t *)tdip, circ);
		tdip = tdip->devi_parent;
	}
	return (NULL);
}

/*
 * For a primary MAC client, if the user has set a list or CPUs or
 * we have obtained it implicitly, we try to retarget the interrupt
 * for that device on one of the CPUs in the list.
 * We assign the interrupt to the same CPU as the poll thread.
 */
static boolean_t
mac_check_interrupt_binding(dev_info_t *mdip, int32_t cpuid)
{
	ldi_handle_t		lh = NULL;
	ldi_ident_t		li = NULL;
	int			err;
	int			ret;
	mac_dladm_intr_t	dln;
	dev_info_t		*dip;
	struct ddi_minor_data	*minordata;

	dln.nexus_path[0] = '\0';
	dln.driver_path[0] = '\0';

	minordata = ((struct dev_info *)mdip)->devi_minor;
	while (minordata != NULL) {
		if (minordata->type == DDM_MINOR)
			break;
		minordata = minordata->next;
	}
	if (minordata == NULL)
		return (B_FALSE);

	(void) ddi_pathname_minor(minordata, dln.driver_path);

	dip = mac_get_nexus_node(mdip, &dln);
	/* defensive */
	if (dip == NULL)
		return (B_FALSE);

	err = ldi_ident_from_major(ddi_driver_major(dip), &li);
	if (err != 0)
		return (B_FALSE);

	err = ldi_open_by_name(dln.nexus_path, FREAD|FWRITE, kcred, &lh, li);
	if (err != 0)
		return (B_FALSE);

	ret = mac_validate_intr(lh, &dln, cpuid);
	if (ret < 0) {
		(void) ldi_close(lh, FREAD|FWRITE, kcred);
		return (B_FALSE);
	}
	/* cmn_note? */
	if (ret != 0)
		if ((err = (mac_set_intr(lh, cpuid, dln.cpu_id, dln.ino)))
		    != 0) {
			(void) ldi_close(lh, FREAD|FWRITE, kcred);
			return (B_FALSE);
		}
	(void) ldi_close(lh, FREAD|FWRITE, kcred);
	return (B_TRUE);
}

void
mac_client_set_intr_cpu(void *arg, mac_client_handle_t mch, int32_t cpuid)
{
	dev_info_t		*mdip = (dev_info_t *)arg;
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_resource_props_t	*mrp;
	mac_perim_handle_t	mph;
	flow_entry_t		*flent = mcip->mci_flent;
	mac_soft_ring_set_t	*rx_srs;
	mac_cpus_t		*srs_cpu;

	if (!mac_check_interrupt_binding(mdip, cpuid))
		cpuid = -1;
	mac_perim_enter_by_mh((mac_handle_t)mcip->mci_mip, &mph);
	mrp = MCIP_RESOURCE_PROPS(mcip);
	mrp->mrp_rx_intr_cpu = cpuid;
	if (flent != NULL && flent->fe_rx_srs_cnt == 2) {
		rx_srs = flent->fe_rx_srs[1];
		srs_cpu = &rx_srs->srs_cpu;
		srs_cpu->mc_rx_intr_cpu = cpuid;
	}
	mac_perim_exit(mph);
}

int32_t
mac_client_intr_cpu(mac_client_handle_t mch)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_cpus_t		*srs_cpu;
	mac_soft_ring_set_t	*rx_srs;
	flow_entry_t		*flent = mcip->mci_flent;
	mac_resource_props_t	*mrp = MCIP_RESOURCE_PROPS(mcip);
	mac_ring_t		*ring;
	mac_intr_t		*mintr;

	/*
	 * Check if we need to retarget the interrupt. We do this only
	 * for the primary MAC client. We do this if we have the only
	 * exclusive ring in the group.
	 */
	if (mac_is_primary_client(mcip) && flent->fe_rx_srs_cnt == 2) {
		rx_srs = flent->fe_rx_srs[1];
		srs_cpu = &rx_srs->srs_cpu;
		ring = rx_srs->srs_ring;
		mintr = &ring->mr_info.mri_intr;
		/*
		 * If ddi_handle is present or the poll CPU is
		 * already bound to the interrupt CPU, return -1.
		 */
		if (mintr->mi_ddi_handle != NULL ||
		    ((mrp->mrp_ncpus != 0) &&
		    (mrp->mrp_rx_intr_cpu == srs_cpu->mc_rx_pollid))) {
			return (-1);
		}
		return (srs_cpu->mc_rx_pollid);
	}
	return (-1);
}

void *
mac_get_devinfo(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	return ((void *)mip->mi_dip);
}

#define	PKT_HASH_2BYTES(x) ((x)[0] ^ (x)[1])
#define	PKT_HASH_4BYTES(x) ((x)[0] ^ (x)[1] ^ (x)[2] ^ (x)[3])
#define	PKT_HASH_MAC(x) ((x)[0] ^ (x)[1] ^ (x)[2] ^ (x)[3] ^ (x)[4] ^ (x)[5])

uint64_t
mac_pkt_hash(uint_t media, mblk_t *mp, uint8_t policy, boolean_t is_outbound)
{
	struct ether_header *ehp;
	uint64_t hash = 0;
	uint16_t sap;
	uint_t skip_len;
	uint8_t proto;
	boolean_t ip_fragmented;

	/*
	 * We may want to have one of these per MAC type plugin in the
	 * future. For now supports only ethernet.
	 */
	if (media != DL_ETHER)
		return (0L);

	/* for now we support only outbound packets */
	ASSERT(is_outbound);
	ASSERT(IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)));
	ASSERT(MBLKL(mp) >= sizeof (struct ether_header));

	/* compute L2 hash */

	ehp = (struct ether_header *)mp->b_rptr;

	if ((policy & MAC_PKT_HASH_L2) != 0) {
		uchar_t *mac_src = ehp->ether_shost.ether_addr_octet;
		uchar_t *mac_dst = ehp->ether_dhost.ether_addr_octet;
		hash = PKT_HASH_MAC(mac_src) ^ PKT_HASH_MAC(mac_dst);
		policy &= ~MAC_PKT_HASH_L2;
	}

	if (policy == 0)
		goto done;

	/* skip ethernet header */

	sap = ntohs(ehp->ether_type);
	if (sap == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evhp;
		mblk_t *newmp = NULL;

		skip_len = sizeof (struct ether_vlan_header);
		if (MBLKL(mp) < skip_len) {
			/* the vlan tag is the payload, pull up first */
			newmp = msgpullup(mp, -1);
			if ((newmp == NULL) || (MBLKL(newmp) < skip_len)) {
				goto done;
			}
			evhp = (struct ether_vlan_header *)newmp->b_rptr;
		} else {
			evhp = (struct ether_vlan_header *)mp->b_rptr;
		}

		sap = ntohs(evhp->ether_type);
		freemsg(newmp);
	} else {
		skip_len = sizeof (struct ether_header);
	}

	/* if ethernet header is in its own mblk, skip it */
	if (MBLKL(mp) <= skip_len) {
		skip_len -= MBLKL(mp);
		mp = mp->b_cont;
		if (mp == NULL)
			goto done;
	}

	sap = (sap < ETHERTYPE_802_MIN) ? 0 : sap;

	/* compute IP src/dst addresses hash and skip IPv{4,6} header */

	switch (sap) {
	case ETHERTYPE_IP: {
		ipha_t *iphp;

		/*
		 * If the header is not aligned or the header doesn't fit
		 * in the mblk, bail now. Note that this may cause packets
		 * reordering.
		 */
		iphp = (ipha_t *)(mp->b_rptr + skip_len);
		if (((unsigned char *)iphp + sizeof (ipha_t) > mp->b_wptr) ||
		    !OK_32PTR((char *)iphp))
			goto done;

		proto = iphp->ipha_protocol;
		skip_len += IPH_HDR_LENGTH(iphp);

		/* Check if the packet is fragmented. */
		ip_fragmented = ntohs(iphp->ipha_fragment_offset_and_flags) &
		    IPH_OFFSET;

		/*
		 * For fragmented packets, use addresses in addition to
		 * the frag_id to generate the hash inorder to get
		 * better distribution.
		 */
		if (ip_fragmented || (policy & MAC_PKT_HASH_L3) != 0) {
			uint8_t *ip_src = (uint8_t *)&(iphp->ipha_src);
			uint8_t *ip_dst = (uint8_t *)&(iphp->ipha_dst);

			hash ^= (PKT_HASH_4BYTES(ip_src) ^
			    PKT_HASH_4BYTES(ip_dst));
			policy &= ~MAC_PKT_HASH_L3;
		}

		if (ip_fragmented) {
			uint8_t *identp = (uint8_t *)&iphp->ipha_ident;
			hash ^= PKT_HASH_2BYTES(identp);
			goto done;
		}
		break;
	}
	case ETHERTYPE_IPV6: {
		ip6_t *ip6hp;
		ip6_frag_t *frag = NULL;
		uint16_t hdr_length;

		/*
		 * If the header is not aligned or the header doesn't fit
		 * in the mblk, bail now. Note that this may cause packets
		 * reordering.
		 */

		ip6hp = (ip6_t *)(mp->b_rptr + skip_len);
		if (((unsigned char *)ip6hp + IPV6_HDR_LEN > mp->b_wptr) ||
		    !OK_32PTR((char *)ip6hp))
			goto done;

		if (!mac_ip_hdr_length_v6(ip6hp, mp->b_wptr, &hdr_length,
		    &proto, &frag))
			goto done;
		skip_len += hdr_length;

		/*
		 * For fragmented packets, use addresses in addition to
		 * the frag_id to generate the hash inorder to get
		 * better distribution.
		 */
		if (frag != NULL || (policy & MAC_PKT_HASH_L3) != 0) {
			uint8_t *ip_src = &(ip6hp->ip6_src.s6_addr8[12]);
			uint8_t *ip_dst = &(ip6hp->ip6_dst.s6_addr8[12]);

			hash ^= (PKT_HASH_4BYTES(ip_src) ^
			    PKT_HASH_4BYTES(ip_dst));
			policy &= ~MAC_PKT_HASH_L3;
		}

		if (frag != NULL) {
			uint8_t *identp = (uint8_t *)&frag->ip6f_ident;
			hash ^= PKT_HASH_4BYTES(identp);
			goto done;
		}
		break;
	}
	default:
		goto done;
	}

	if (policy == 0)
		goto done;

	/* if ip header is in its own mblk, skip it */
	if (MBLKL(mp) <= skip_len) {
		skip_len -= MBLKL(mp);
		mp = mp->b_cont;
		if (mp == NULL)
			goto done;
	}

	/* parse ULP header */
again:
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
		/*
		 * These Internet Protocols are intentionally designed
		 * for hashing from the git-go.  Port numbers are in the first
		 * word for transports, SPI is first for ESP.
		 */
		if (mp->b_rptr + skip_len + 4 > mp->b_wptr)
			goto done;
		hash ^= PKT_HASH_4BYTES((mp->b_rptr + skip_len));
		break;

	case IPPROTO_AH: {
		ah_t *ah = (ah_t *)(mp->b_rptr + skip_len);
		uint_t ah_length = AH_TOTAL_LEN(ah);

		if ((unsigned char *)ah + sizeof (ah_t) > mp->b_wptr)
			goto done;

		proto = ah->ah_nexthdr;
		skip_len += ah_length;

		/* if AH header is in its own mblk, skip it */
		if (MBLKL(mp) <= skip_len) {
			skip_len -= MBLKL(mp);
			mp = mp->b_cont;
			if (mp == NULL)
				goto done;
		}

		goto again;
	}
	}

done:
	return (hash);
}
