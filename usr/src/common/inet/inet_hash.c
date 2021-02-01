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
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Common routines usable by any part of the networking stack for hashing
 * packets. The hashing logic originally was part of MAC, but it has more
 * utility being usable by the rest of the broader system.
 */

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/vlan.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <sys/dlpi.h>
#include <sys/sunndi.h>
#include <inet/ipsec_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>
#include <inet/inet_hash.h>

/*
 * Determines the IPv6 header length accounting for all the optional IPv6
 * headers (hop-by-hop, destination, routing and fragment). The header length
 * and next header value (a transport header) is captured.
 *
 * Returns B_FALSE if all the IP headers are not in the same mblk otherwise
 * returns B_TRUE.
 */
static boolean_t
inet_pkthash_ip_hdr_length_v6(ip6_t *ip6h, uint8_t *endptr,
    uint16_t *hdr_length,  uint8_t *next_hdr, ip6_frag_t **fragp)
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
		 * If any known extension headers are still to be processed,
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

#define	PKT_HASH_2BYTES(x) ((x)[0] ^ (x)[1])
#define	PKT_HASH_4BYTES(x) ((x)[0] ^ (x)[1] ^ (x)[2] ^ (x)[3])
#define	PKT_HASH_MAC(x) ((x)[0] ^ (x)[1] ^ (x)[2] ^ (x)[3] ^ (x)[4] ^ (x)[5])
uint64_t
inet_pkt_hash(uint_t media, mblk_t *mp, uint8_t policy)
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
	ASSERT(IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)));
	ASSERT(MBLKL(mp) >= sizeof (struct ether_header));

	/* compute L2 hash */

	ehp = (struct ether_header *)mp->b_rptr;

	if ((policy & INET_PKT_HASH_L2) != 0) {
		uchar_t *mac_src = ehp->ether_shost.ether_addr_octet;
		uchar_t *mac_dst = ehp->ether_dhost.ether_addr_octet;
		hash = PKT_HASH_MAC(mac_src) ^ PKT_HASH_MAC(mac_dst);
		policy &= ~INET_PKT_HASH_L2;
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
		 * in the mblk, bail now. Note that this may cause packet
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
		if (ip_fragmented || (policy & INET_PKT_HASH_L3) != 0) {
			uint8_t *ip_src = (uint8_t *)&(iphp->ipha_src);
			uint8_t *ip_dst = (uint8_t *)&(iphp->ipha_dst);

			hash ^= (PKT_HASH_4BYTES(ip_src) ^
			    PKT_HASH_4BYTES(ip_dst));
			policy &= ~INET_PKT_HASH_L3;
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

		if (!inet_pkthash_ip_hdr_length_v6(ip6hp, mp->b_wptr,
		    &hdr_length, &proto, &frag))
			goto done;
		skip_len += hdr_length;

		/*
		 * For fragmented packets, use addresses in addition to
		 * the frag_id to generate the hash inorder to get
		 * better distribution.
		 */
		if (frag != NULL || (policy & INET_PKT_HASH_L3) != 0) {
			uint8_t *ip_src = &(ip6hp->ip6_src.s6_addr8[12]);
			uint8_t *ip_dst = &(ip6hp->ip6_dst.s6_addr8[12]);

			hash ^= (PKT_HASH_4BYTES(ip_src) ^
			    PKT_HASH_4BYTES(ip_dst));
			policy &= ~INET_PKT_HASH_L3;
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
