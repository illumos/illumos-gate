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
 * Copyright 2019 Joyent, Inc.
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
#include <inet/tcp.h>
#include <inet/udp_impl.h>
#include <inet/sctp_ip.h>

/*
 * The next two functions are used for dropping packets or chains of
 * packets, respectively. We could use one function for both but
 * separating the use cases allows us to specify intent and prevent
 * dropping more data than intended.
 *
 * The purpose of these functions is to aid the debugging effort,
 * especially in production. Rather than use freemsg()/freemsgchain(),
 * it's preferable to use these functions when dropping a packet in
 * the MAC layer. These functions should only be used during
 * unexpected conditions. That is, any time a packet is dropped
 * outside of the regular, successful datapath. Consolidating all
 * drops on these functions allows the user to trace one location and
 * determine why the packet was dropped based on the msg. It also
 * allows the user to inspect the packet before it is freed. Finally,
 * it allows the user to avoid tracing freemsg()/freemsgchain() thus
 * keeping the hot path running as efficiently as possible.
 *
 * NOTE: At this time not all MAC drops are aggregated on these
 * functions; but that is the plan. This comment should be erased once
 * completed.
 */

/*PRINTFLIKE2*/
void
mac_drop_pkt(mblk_t *mp, const char *fmt, ...)
{
	va_list adx;
	char msg[128];
	char *msgp = msg;

	ASSERT3P(mp->b_next, ==, NULL);

	va_start(adx, fmt);
	(void) vsnprintf(msgp, sizeof (msg), fmt, adx);
	va_end(adx);

	DTRACE_PROBE2(mac__drop, mblk_t *, mp, char *, msgp);
	freemsg(mp);
}

/*PRINTFLIKE2*/
void
mac_drop_chain(mblk_t *chain, const char *fmt, ...)
{
	va_list adx;
	char msg[128];
	char *msgp = msg;

	va_start(adx, fmt);
	(void) vsnprintf(msgp, sizeof (msg), fmt, adx);
	va_end(adx);

	/*
	 * We could use freemsgchain() for the actual freeing but
	 * since we are already walking the chain to fire the dtrace
	 * probe we might as well free the msg here too.
	 */
	for (mblk_t *mp = chain, *next; mp != NULL; ) {
		next = mp->b_next;
		DTRACE_PROBE2(mac__drop, mblk_t *, mp, char *, msgp);
		freemsg(mp);
		mp = next;
	}
}

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
 * Calculate the ULP checksum for IPv4. Return true if the calculation
 * was successful, or false if an error occurred. If the later, place
 * an error message into '*err'.
 */
static boolean_t
mac_sw_cksum_ipv4(mblk_t *mp, uint32_t ip_hdr_offset, ipha_t *ipha,
    const char **err)
{
	const uint8_t proto = ipha->ipha_protocol;
	size_t len;
	const uint32_t ip_hdr_sz = IPH_HDR_LENGTH(ipha);
	/* ULP offset from start of L2. */
	const uint32_t ulp_offset = ip_hdr_offset + ip_hdr_sz;
	ipaddr_t src, dst;
	uint32_t cksum;
	uint16_t *up;

	/*
	 * We need a pointer to the ULP checksum. We're assuming the
	 * ULP checksum pointer resides in the first mblk. Our native
	 * TCP stack should always put the headers in the first mblk,
	 * but currently we have no way to guarantee that other
	 * clients don't spread headers (or even header fields) across
	 * mblks.
	 */
	switch (proto) {
	case IPPROTO_TCP:
		ASSERT3U(MBLKL(mp), >=, (ulp_offset + sizeof (tcph_t)));
		if (MBLKL(mp) < (ulp_offset + sizeof (tcph_t))) {
			*err = "mblk doesn't contain TCP header";
			goto bail;
		}

		up = IPH_TCPH_CHECKSUMP(ipha, ip_hdr_sz);
		cksum = IP_TCP_CSUM_COMP;
		break;

	case IPPROTO_UDP:
		ASSERT3U(MBLKL(mp), >=, (ulp_offset + sizeof (udpha_t)));
		if (MBLKL(mp) < (ulp_offset + sizeof (udpha_t))) {
			*err = "mblk doesn't contain UDP header";
			goto bail;
		}

		up = IPH_UDPH_CHECKSUMP(ipha, ip_hdr_sz);
		cksum = IP_UDP_CSUM_COMP;
		break;

	case IPPROTO_SCTP: {
		sctp_hdr_t *sctph;

		ASSERT3U(MBLKL(mp), >=, (ulp_offset + sizeof (sctp_hdr_t)));
		if (MBLKL(mp) < (ulp_offset + sizeof (sctp_hdr_t))) {
			*err = "mblk doesn't contain SCTP header";
			goto bail;
		}

		sctph = (sctp_hdr_t *)(mp->b_rptr + ulp_offset);
		sctph->sh_chksum = 0;
		sctph->sh_chksum = sctp_cksum(mp, ulp_offset);
		return (B_TRUE);
	}

	default:
		*err = "unexpected protocol";
		goto bail;

	}

	/* Pseudo-header checksum. */
	src = ipha->ipha_src;
	dst = ipha->ipha_dst;
	len = ntohs(ipha->ipha_length) - ip_hdr_sz;

	cksum += (dst >> 16) + (dst & 0xFFFF) + (src >> 16) + (src & 0xFFFF);
	cksum += htons(len);

	/*
	 * We have already accounted for the pseudo checksum above.
	 * Make sure the ULP checksum field is zero before computing
	 * the rest.
	 */
	*up = 0;
	cksum = IP_CSUM(mp, ulp_offset, cksum);
	*up = (uint16_t)(cksum ? cksum : ~cksum);

	return (B_TRUE);

bail:
	return (B_FALSE);
}

/*
 * Calculate the ULP checksum for IPv6. Return true if the calculation
 * was successful, or false if an error occurred. If the later, place
 * an error message into '*err'.
 */
static boolean_t
mac_sw_cksum_ipv6(mblk_t *mp, uint32_t ip_hdr_offset, const char **err)
{
	ip6_t* ip6h = (ip6_t *)(mp->b_rptr + ip_hdr_offset);
	const uint8_t proto = ip6h->ip6_nxt;
	const uint16_t *iphs = (uint16_t *)ip6h;
	/* ULP offset from start of L2. */
	uint32_t ulp_offset;
	size_t len;
	uint32_t cksum;
	uint16_t *up;
	uint16_t ip_hdr_sz;

	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &ip_hdr_sz, NULL)) {
		*err = "malformed IPv6 header";
		goto bail;
	}

	ulp_offset = ip_hdr_offset + ip_hdr_sz;

	/*
	 * We need a pointer to the ULP checksum. We're assuming the
	 * ULP checksum pointer resides in the first mblk. Our native
	 * TCP stack should always put the headers in the first mblk,
	 * but currently we have no way to guarantee that other
	 * clients don't spread headers (or even header fields) across
	 * mblks.
	 */
	switch (proto) {
	case IPPROTO_TCP:
		ASSERT3U(MBLKL(mp), >=, (ulp_offset + sizeof (tcph_t)));
		if (MBLKL(mp) < (ulp_offset + sizeof (tcph_t))) {
			*err = "mblk doesn't contain TCP header";
			goto bail;
		}

		up = IPH_TCPH_CHECKSUMP(ip6h, ip_hdr_sz);
		cksum = IP_TCP_CSUM_COMP;
		break;

	case IPPROTO_UDP:
		ASSERT3U(MBLKL(mp), >=, (ulp_offset + sizeof (udpha_t)));
		if (MBLKL(mp) < (ulp_offset + sizeof (udpha_t))) {
			*err = "mblk doesn't contain UDP header";
			goto bail;
		}

		up = IPH_UDPH_CHECKSUMP(ip6h, ip_hdr_sz);
		cksum = IP_UDP_CSUM_COMP;
		break;

	case IPPROTO_SCTP: {
		sctp_hdr_t *sctph;

		ASSERT3U(MBLKL(mp), >=, (ulp_offset + sizeof (sctp_hdr_t)));
		if (MBLKL(mp) < (ulp_offset + sizeof (sctp_hdr_t))) {
			*err = "mblk doesn't contain SCTP header";
			goto bail;
		}

		sctph = (sctp_hdr_t *)(mp->b_rptr + ulp_offset);
		/*
		 * Zero out the checksum field to ensure proper
		 * checksum calculation.
		 */
		sctph->sh_chksum = 0;
		sctph->sh_chksum = sctp_cksum(mp, ulp_offset);
		return (B_TRUE);
	}

	default:
		*err = "unexpected protocol";
		goto bail;
	}

	/*
	 * The payload length includes the payload and the IPv6
	 * extension headers; the idea is to subtract the extension
	 * header length to get the real payload length.
	 */
	len = ntohs(ip6h->ip6_plen) - (ip_hdr_sz - IPV6_HDR_LEN);
	cksum += len;

	/*
	 * We accumulate the pseudo header checksum in cksum; then we
	 * call IP_CSUM to compute the checksum over the payload.
	 */
	cksum += iphs[4] + iphs[5] + iphs[6] + iphs[7] + iphs[8] + iphs[9] +
	    iphs[10] + iphs[11] + iphs[12] + iphs[13] + iphs[14] + iphs[15] +
	    iphs[16] + iphs[17] + iphs[18] + iphs[19];
	cksum = IP_CSUM(mp, ulp_offset, cksum);

	/* For UDP/IPv6 a zero UDP checksum is not allowed. Change to 0xffff */
	if (proto == IPPROTO_UDP && cksum == 0)
		cksum = ~cksum;

	*up = (uint16_t)cksum;

	return (B_TRUE);

bail:
	return (B_FALSE);
}

/*
 * Perform software checksum on a single message, if needed. The
 * emulation performed is determined by an intersection of the mblk's
 * flags and the emul flags requested. The emul flags are documented
 * in mac.h.
 */
static mblk_t *
mac_sw_cksum(mblk_t *mp, mac_emul_t emul)
{
	mblk_t *skipped_hdr = NULL;
	uint32_t flags, start, stuff, end, value;
	uint32_t ip_hdr_offset;
	uint16_t etype;
	size_t ip_hdr_sz;
	struct ether_header *ehp;
	const char *err = "";

	/*
	 * This function should only be called from mac_hw_emul()
	 * which handles mblk chains and the shared ref case.
	 */
	ASSERT3P(mp->b_next, ==, NULL);

	mac_hcksum_get(mp, &start, &stuff, &end, &value, NULL);

	/*
	 * We use DB_CKSUMFLAGS (instead of mac_hcksum_get()) because
	 * we don't want to mask-out the HW_LOCAL_MAC flag.
	 */
	flags = DB_CKSUMFLAGS(mp);

	/* Why call this if checksum emulation isn't needed? */
	ASSERT3U(flags & (HCK_FLAGS), !=, 0);

	/*
	 * Ethernet, and optionally VLAN header. mac_hw_emul() has
	 * already verified we have enough data to read the L2 header.
	 */
	ehp = (struct ether_header *)mp->b_rptr;
	if (ntohs(ehp->ether_type) == VLAN_TPID) {
		struct ether_vlan_header *evhp;

		evhp = (struct ether_vlan_header *)mp->b_rptr;
		etype = ntohs(evhp->ether_type);
		ip_hdr_offset = sizeof (struct ether_vlan_header);
	} else {
		etype = ntohs(ehp->ether_type);
		ip_hdr_offset = sizeof (struct ether_header);
	}

	/*
	 * If this packet isn't IP, then leave it alone. We don't want
	 * to affect non-IP traffic like ARP. Assume the IP header
	 * doesn't include any options, for now. We will use the
	 * correct size later after we know there are enough bytes to
	 * at least fill out the basic header.
	 */
	switch (etype) {
	case ETHERTYPE_IP:
		ip_hdr_sz = sizeof (ipha_t);
		break;
	case ETHERTYPE_IPV6:
		ip_hdr_sz = sizeof (ip6_t);
		break;
	default:
		return (mp);
	}

	ASSERT3U(MBLKL(mp), >=, ip_hdr_offset);

	/*
	 * If the first mblk of this packet contains only the ethernet
	 * header, skip past it for now. Packets with their data
	 * contained in only a single mblk can then use the fastpaths
	 * tuned to that possibility.
	 */
	if (MBLKL(mp) == ip_hdr_offset) {
		ip_hdr_offset -= MBLKL(mp);
		/* This is guaranteed by mac_hw_emul(). */
		ASSERT3P(mp->b_cont, !=, NULL);
		skipped_hdr = mp;
		mp = mp->b_cont;
	}

	/*
	 * Both full and partial checksum rely on finding the IP
	 * header in the current mblk. Our native TCP stack honors
	 * this assumption but it's prudent to guard our future
	 * clients that might not honor this contract.
	 */
	ASSERT3U(MBLKL(mp), >=, ip_hdr_offset + ip_hdr_sz);
	if (MBLKL(mp) < (ip_hdr_offset + ip_hdr_sz)) {
		err = "mblk doesn't contain IP header";
		goto bail;
	}

	/*
	 * We are about to modify the header mblk; make sure we are
	 * modifying our own copy. The code that follows assumes that
	 * the IP/ULP headers exist in this mblk (and drops the
	 * message if they don't).
	 */
	if (DB_REF(mp) > 1) {
		mblk_t *tmp = copyb(mp);

		if (tmp == NULL) {
			err = "copyb failed";
			goto bail;
		}

		if (skipped_hdr != NULL) {
			ASSERT3P(skipped_hdr->b_cont, ==, mp);
			skipped_hdr->b_cont = tmp;
		}

		tmp->b_cont = mp->b_cont;
		freeb(mp);
		mp = tmp;
	}

	if (etype == ETHERTYPE_IP) {
		ipha_t *ipha = (ipha_t *)(mp->b_rptr + ip_hdr_offset);

		if ((flags & HCK_FULLCKSUM) && (emul & MAC_HWCKSUM_EMUL)) {
			if (!mac_sw_cksum_ipv4(mp, ip_hdr_offset, ipha, &err))
				goto bail;
		}

		/* We always update the ULP checksum flags. */
		if ((flags & HCK_FULLCKSUM) && (emul & MAC_HWCKSUM_EMULS)) {
			flags &= ~HCK_FULLCKSUM;
			flags |= HCK_FULLCKSUM_OK;
			value = 0;
		}

		/*
		 * While unlikely, it's possible to write code that
		 * might end up calling mac_sw_cksum() twice on the
		 * same mblk (performing both LSO and checksum
		 * emualtion in a single mblk chain loop -- the LSO
		 * emulation inserts a new chain into the existing
		 * chain and then the loop iterates back over the new
		 * segments and emulates the checksum a second time).
		 * Normally this wouldn't be a problem, because the
		 * HCK_*_OK flags are supposed to indicate that we
		 * don't need to do peform the work. But
		 * HCK_IPV4_HDRCKSUM and HCK_IPV4_HDRCKSUM_OK have the
		 * same value; so we cannot use these flags to
		 * determine if the IP header checksum has already
		 * been calculated or not. For this reason, we zero
		 * out the the checksum first. In the future, we
		 * should fix the HCK_* flags.
		 */
		if ((flags & HCK_IPV4_HDRCKSUM) && (emul & MAC_HWCKSUM_EMULS)) {
			ipha->ipha_hdr_checksum = 0;
			ipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(ipha);
			flags &= ~HCK_IPV4_HDRCKSUM;
			flags |= HCK_IPV4_HDRCKSUM_OK;
		}
	} else if (etype == ETHERTYPE_IPV6) {
		/* There is no IP header checksum for IPv6. */
		if ((flags & HCK_FULLCKSUM) && (emul & MAC_HWCKSUM_EMUL)) {
			if (!mac_sw_cksum_ipv6(mp, ip_hdr_offset, &err))
				goto bail;
			flags &= ~HCK_FULLCKSUM;
			flags |= HCK_FULLCKSUM_OK;
			value = 0;
		}
	}

	/*
	 * Partial checksum is the same for both IPv4 and IPv6.
	 */
	if ((flags & HCK_PARTIALCKSUM) && (emul & MAC_HWCKSUM_EMUL)) {
		uint16_t *up, partial, cksum;
		uchar_t *ipp; /* ptr to beginning of IP header */

		ipp = mp->b_rptr + ip_hdr_offset;
		up = (uint16_t *)((uchar_t *)ipp + stuff);
		partial = *up;
		*up = 0;

		ASSERT3S(end, >, start);
		cksum = ~IP_CSUM_PARTIAL(mp, ip_hdr_offset + start, partial);
		*up = cksum != 0 ? cksum : ~cksum;
	}

	/* We always update the ULP checksum flags. */
	if ((flags & HCK_PARTIALCKSUM) && (emul & MAC_HWCKSUM_EMULS)) {
		flags &= ~HCK_PARTIALCKSUM;
		flags |= HCK_FULLCKSUM_OK;
		value = 0;
	}

	mac_hcksum_set(mp, start, stuff, end, value, flags);

	/* Don't forget to reattach the header. */
	if (skipped_hdr != NULL) {
		ASSERT3P(skipped_hdr->b_cont, ==, mp);

		/*
		 * Duplicate the HCKSUM data into the header mblk.
		 * This mimics mac_add_vlan_tag which ensures that
		 * both the first mblk _and_ the first data bearing
		 * mblk possess the HCKSUM information. Consumers like
		 * IP will end up discarding the ether_header mblk, so
		 * for now, it is important that the data be available
		 * in both places.
		 */
		mac_hcksum_clone(mp, skipped_hdr);
		mp = skipped_hdr;
	}

	return (mp);

bail:
	if (skipped_hdr != NULL) {
		ASSERT3P(skipped_hdr->b_cont, ==, mp);
		mp = skipped_hdr;
	}

	mac_drop_pkt(mp, err);
	return (NULL);
}

/*
 * Build a single data segment from an LSO packet. The mblk chain
 * returned, seg_head, represents the data segment and is always
 * exactly seg_len bytes long. The lso_mp and offset input/output
 * parameters track our position in the LSO packet. This function
 * exists solely as a helper to mac_sw_lso().
 *
 * Case A
 *
 *     The current lso_mp is larger than the requested seg_len. The
 *     beginning of seg_head may start at the beginning of lso_mp or
 *     offset into it. In either case, a single mblk is returned, and
 *     *offset is updated to reflect our new position in the current
 *     lso_mp.
 *
 *          +----------------------------+
 *          |  in *lso_mp / out *lso_mp  |
 *          +----------------------------+
 *          ^                        ^
 *          |                        |
 *          |                        |
 *          |                        |
 *          +------------------------+
 *          |        seg_head        |
 *          +------------------------+
 *          ^                        ^
 *          |                        |
 *   in *offset = 0        out *offset = seg_len
 *
 *          |------   seg_len    ----|
 *
 *
 *       +------------------------------+
 *       |   in *lso_mp / out *lso_mp   |
 *       +------------------------------+
 *          ^                        ^
 *          |                        |
 *          |                        |
 *          |                        |
 *          +------------------------+
 *          |        seg_head        |
 *          +------------------------+
 *          ^                        ^
 *          |                        |
 *   in *offset = N        out *offset = N + seg_len
 *
 *          |------   seg_len    ----|
 *
 *
 *
 * Case B
 *
 *    The requested seg_len consumes exactly the rest of the lso_mp.
 *    I.e., the seg_head's b_wptr is equivalent to lso_mp's b_wptr.
 *    The seg_head may start at the beginning of the lso_mp or at some
 *    offset into it. In either case we return a single mblk, reset
 *    *offset to zero, and walk to the next lso_mp.
 *
 *          +------------------------+           +------------------------+
 *          |       in *lso_mp       |---------->|      out *lso_mp       |
 *          +------------------------+           +------------------------+
 *          ^                        ^           ^
 *          |                        |           |
 *          |                        |    out *offset = 0
 *          |                        |
 *          +------------------------+
 *          |        seg_head        |
 *          +------------------------+
 *          ^
 *          |
 *   in *offset = 0
 *
 *          |------   seg_len    ----|
 *
 *
 *
 *      +----------------------------+           +------------------------+
 *      |         in *lso_mp         |---------->|      out *lso_mp       |
 *      +----------------------------+           +------------------------+
 *          ^                        ^           ^
 *          |                        |           |
 *          |                        |    out *offset = 0
 *          |                        |
 *          +------------------------+
 *          |        seg_head        |
 *          +------------------------+
 *          ^
 *          |
 *   in *offset = N
 *
 *          |------   seg_len    ----|
 *
 *
 * Case C
 *
 *    The requested seg_len is greater than the current lso_mp. In
 *    this case we must consume LSO mblks until we have enough data to
 *    satisfy either case (A) or (B) above. We will return multiple
 *    mblks linked via b_cont, offset will be set based on the cases
 *    above, and lso_mp will walk forward at least one mblk, but maybe
 *    more.
 *
 *    N.B. This digram is not exhaustive. The seg_head may start on
 *    the beginning of an lso_mp. The seg_tail may end exactly on the
 *    boundary of an lso_mp. And there may be two (in this case the
 *    middle block wouldn't exist), three, or more mblks in the
 *    seg_head chain. This is meant as one example of what might
 *    happen. The main thing to remember is that the seg_tail mblk
 *    must be one of case (A) or (B) above.
 *
 *  +------------------+    +----------------+    +------------------+
 *  |    in *lso_mp    |--->|    *lso_mp     |--->|   out *lso_mp    |
 *  +------------------+    +----------------+    +------------------+
 *        ^            ^    ^                ^    ^            ^
 *        |            |    |                |    |            |
 *        |            |    |                |    |            |
 *        |            |    |                |    |            |
 *        |            |    |                |    |            |
 *        +------------+    +----------------+    +------------+
 *        |  seg_head  |--->|                |--->|  seg_tail  |
 *        +------------+    +----------------+    +------------+
 *        ^                                                    ^
 *        |                                                    |
 *  in *offset = N                          out *offset = MBLKL(seg_tail)
 *
 *        |-------------------   seg_len    -------------------|
 *
 */
static mblk_t *
build_data_seg(mblk_t **lso_mp, uint32_t *offset, uint32_t seg_len)
{
	mblk_t *seg_head, *seg_tail, *seg_mp;

	ASSERT3P(*lso_mp, !=, NULL);
	ASSERT3U((*lso_mp)->b_rptr + *offset, <, (*lso_mp)->b_wptr);

	seg_mp = dupb(*lso_mp);
	if (seg_mp == NULL)
		return (NULL);

	seg_head = seg_mp;
	seg_tail = seg_mp;

	/* Continue where we left off from in the lso_mp. */
	seg_mp->b_rptr += *offset;

last_mblk:
	/* Case (A) */
	if ((seg_mp->b_rptr + seg_len) < seg_mp->b_wptr) {
		*offset += seg_len;
		seg_mp->b_wptr = seg_mp->b_rptr + seg_len;
		return (seg_head);
	}

	/* Case (B) */
	if ((seg_mp->b_rptr + seg_len) == seg_mp->b_wptr) {
		*offset = 0;
		*lso_mp = (*lso_mp)->b_cont;
		return (seg_head);
	}

	/* Case (C) */
	ASSERT3U(seg_mp->b_rptr + seg_len, >, seg_mp->b_wptr);

	/*
	 * The current LSO mblk doesn't have enough data to satisfy
	 * seg_len -- continue peeling off LSO mblks to build the new
	 * segment message. If allocation fails we free the previously
	 * allocated segment mblks and return NULL.
	 */
	while ((seg_mp->b_rptr + seg_len) > seg_mp->b_wptr) {
		ASSERT3U(MBLKL(seg_mp), <=, seg_len);
		seg_len -= MBLKL(seg_mp);
		*offset = 0;
		*lso_mp = (*lso_mp)->b_cont;
		seg_mp = dupb(*lso_mp);

		if (seg_mp == NULL) {
			freemsgchain(seg_head);
			return (NULL);
		}

		seg_tail->b_cont = seg_mp;
		seg_tail = seg_mp;
	}

	/*
	 * We've walked enough LSO mblks that we can now satisfy the
	 * remaining seg_len. At this point we need to jump back to
	 * determine if we have arrived at case (A) or (B).
	 */

	/* Just to be paranoid that we didn't underflow. */
	ASSERT3U(seg_len, <, IP_MAXPACKET);
	ASSERT3U(seg_len, >, 0);
	goto last_mblk;
}

/*
 * Perform software segmentation of a single LSO message. Take an LSO
 * message as input and return head/tail pointers as output. This
 * function should not be invoked directly but instead through
 * mac_hw_emul().
 *
 * The resulting chain is comprised of multiple (nsegs) MSS sized
 * segments. Each segment will consist of two or more mblks joined by
 * b_cont: a header and one or more data mblks. The header mblk is
 * allocated anew for each message. The first segment's header is used
 * as a template for the rest with adjustments made for things such as
 * ID, sequence, length, TCP flags, etc. The data mblks reference into
 * the existing LSO mblk (passed in as omp) by way of dupb(). Their
 * b_rptr/b_wptr values are adjusted to reference only the fraction of
 * the LSO message they are responsible for. At the successful
 * completion of this function the original mblk (omp) is freed,
 * leaving the newely created segment chain as the only remaining
 * reference to the data.
 */
static void
mac_sw_lso(mblk_t *omp, mac_emul_t emul, mblk_t **head, mblk_t **tail,
    uint_t *count)
{
	uint32_t ocsum_flags, ocsum_start, ocsum_stuff;
	uint32_t mss;
	uint32_t oehlen, oiphlen, otcphlen, ohdrslen, opktlen, odatalen;
	uint32_t oleft;
	uint_t nsegs, seg;
	int len;

	struct ether_vlan_header *oevh;
	const ipha_t *oiph;
	const tcph_t *otcph;
	ipha_t *niph;
	tcph_t *ntcph;
	uint16_t ip_id;
	uint32_t tcp_seq, tcp_sum, otcp_sum;

	uint32_t offset;
	mblk_t *odatamp;
	mblk_t *seg_chain, *prev_nhdrmp, *next_nhdrmp, *nhdrmp, *ndatamp;
	mblk_t *tmptail;

	ASSERT3P(head, !=, NULL);
	ASSERT3P(tail, !=, NULL);
	ASSERT3P(count, !=, NULL);
	ASSERT3U((DB_CKSUMFLAGS(omp) & HW_LSO), !=, 0);

	/* Assume we are dealing with a single LSO message. */
	ASSERT3P(omp->b_next, ==, NULL);

	/*
	 * XXX: This is a hack to deal with mac_add_vlan_tag().
	 *
	 * When VLANs are in play, mac_add_vlan_tag() creates a new
	 * mblk with just the ether_vlan_header and tacks it onto the
	 * front of 'omp'. This breaks the assumptions made below;
	 * namely that the TCP/IP headers are in the first mblk. In
	 * this case, since we already have to pay the cost of LSO
	 * emulation, we simply pull up everything. While this might
	 * seem irksome, keep in mind this will only apply in a couple
	 * of scenarios: a) an LSO-capable VLAN client sending to a
	 * non-LSO-capable client over the "MAC/bridge loopback"
	 * datapath or b) an LSO-capable VLAN client is sending to a
	 * client that, for whatever reason, doesn't have DLS-bypass
	 * enabled. Finally, we have to check for both a tagged and
	 * untagged sized mblk depending on if the mblk came via
	 * mac_promisc_dispatch() or mac_rx_deliver().
	 *
	 * In the future, two things should be done:
	 *
	 * 1. This function should make use of some yet to be
	 *    implemented "mblk helpers". These helper functions would
	 *    perform all the b_cont walking for us and guarantee safe
	 *    access to the mblk data.
	 *
	 * 2. We should add some slop to the mblks so that
	 *    mac_add_vlan_tag() can just edit the first mblk instead
	 *    of allocating on the hot path.
	 */
	if (MBLKL(omp) == sizeof (struct ether_vlan_header) ||
	    MBLKL(omp) == sizeof (struct ether_header)) {
		mblk_t *tmp = msgpullup(omp, -1);

		if (tmp == NULL) {
			mac_drop_pkt(omp, "failed to pull up");
			goto fail;
		}

		mac_hcksum_clone(omp, tmp);
		freemsg(omp);
		omp = tmp;
	}

	mss = DB_LSOMSS(omp);
	ASSERT3U(msgsize(omp), <=, IP_MAXPACKET +
	    sizeof (struct ether_vlan_header));
	opktlen = msgsize(omp);

	/*
	 * First, get references to the IP and TCP headers and
	 * determine the total TCP length (header + data).
	 *
	 * Thanks to mac_hw_emul() we know that the first mblk must
	 * contain (at minimum) the full L2 header. However, this
	 * function assumes more than that. It assumes the L2/L3/L4
	 * headers are all contained in the first mblk of a message
	 * (i.e., no b_cont walking for headers). While this is a
	 * current reality (our native TCP stack and viona both
	 * enforce this) things may become more nuanced in the future
	 * (e.g. when introducing encap support or adding new
	 * clients). For now we guard against this case by dropping
	 * the packet.
	 */
	oevh = (struct ether_vlan_header *)omp->b_rptr;
	if (oevh->ether_tpid == htons(ETHERTYPE_VLAN))
		oehlen = sizeof (struct ether_vlan_header);
	else
		oehlen = sizeof (struct ether_header);

	ASSERT3U(MBLKL(omp), >=, (oehlen + sizeof (ipha_t) + sizeof (tcph_t)));
	if (MBLKL(omp) < (oehlen + sizeof (ipha_t) + sizeof (tcph_t))) {
		mac_drop_pkt(omp, "mblk doesn't contain TCP/IP headers");
		goto fail;
	}

	oiph = (ipha_t *)(omp->b_rptr + oehlen);
	oiphlen = IPH_HDR_LENGTH(oiph);
	otcph = (tcph_t *)(omp->b_rptr + oehlen + oiphlen);
	otcphlen = TCP_HDR_LENGTH(otcph);

	/*
	 * Currently we only support LSO for TCP/IPv4.
	 */
	if (IPH_HDR_VERSION(oiph) != IPV4_VERSION) {
		mac_drop_pkt(omp, "LSO unsupported IP version: %uhh",
		    IPH_HDR_VERSION(oiph));
		goto fail;
	}

	if (oiph->ipha_protocol != IPPROTO_TCP) {
		mac_drop_pkt(omp, "LSO unsupported protocol: %uhh",
		    oiph->ipha_protocol);
		goto fail;
	}

	if (otcph->th_flags[0] & (TH_SYN | TH_RST | TH_URG)) {
		mac_drop_pkt(omp, "LSO packet has SYN|RST|URG set");
		goto fail;
	}

	ohdrslen = oehlen + oiphlen + otcphlen;
	if ((len = MBLKL(omp)) < ohdrslen) {
		mac_drop_pkt(omp, "LSO packet too short: %d < %u", len,
		    ohdrslen);
		goto fail;
	}

	/*
	 * Either we have data in the first mblk or it's just the
	 * header. In either case, we need to set rptr to the start of
	 * the TCP data.
	 */
	if (len > ohdrslen) {
		odatamp = omp;
		offset = ohdrslen;
	} else {
		ASSERT3U(len, ==, ohdrslen);
		odatamp = omp->b_cont;
		offset = 0;
	}

	/* Make sure we still have enough data. */
	ASSERT3U(msgsize(odatamp), >=, opktlen - ohdrslen);

	/*
	 * If a MAC negotiated LSO then it must negotioate both
	 * HCKSUM_IPHDRCKSUM and either HCKSUM_INET_FULL_V4 or
	 * HCKSUM_INET_PARTIAL; because both the IP and TCP headers
	 * change during LSO segmentation (only the 3 fields of the
	 * pseudo header checksum don't change: src, dst, proto). Thus
	 * we would expect these flags (HCK_IPV4_HDRCKSUM |
	 * HCK_PARTIALCKSUM | HCK_FULLCKSUM) to be set and for this
	 * function to emulate those checksums in software. However,
	 * that assumes a world where we only expose LSO if the
	 * underlying hardware exposes LSO. Moving forward the plan is
	 * to assume LSO in the upper layers and have MAC perform
	 * software LSO when the underlying provider doesn't support
	 * it. In such a world, if the provider doesn't support LSO
	 * but does support hardware checksum offload, then we could
	 * simply perform the segmentation and allow the hardware to
	 * calculate the checksums. To the hardware it's just another
	 * chain of non-LSO packets.
	 */
	ASSERT3S(DB_TYPE(omp), ==, M_DATA);
	ocsum_flags = DB_CKSUMFLAGS(omp);
	ASSERT3U(ocsum_flags & HCK_IPV4_HDRCKSUM, !=, 0);
	ASSERT3U(ocsum_flags & (HCK_PARTIALCKSUM | HCK_FULLCKSUM), !=, 0);

	/*
	 * If hardware only provides partial checksum then software
	 * must supply the pseudo-header checksum. In the case of LSO
	 * we leave the TCP length at zero to be filled in by
	 * hardware. This function must handle two scenarios.
	 *
	 * 1. Being called by a MAC client on the Rx path to segment
	 *    an LSO packet and calculate the checksum.
	 *
	 * 2. Being called by a MAC provider to segment an LSO packet.
	 *    In this case the LSO segmentation is performed in
	 *    software (by this routine) but the MAC provider should
	 *    still calculate the TCP/IP checksums in hardware.
	 *
	 *  To elaborate on the second case: we cannot have the
	 *  scenario where IP sends LSO packets but the underlying HW
	 *  doesn't support checksum offload -- because in that case
	 *  TCP/IP would calculate the checksum in software (for the
	 *  LSO packet) but then MAC would segment the packet and have
	 *  to redo all the checksum work. So IP should never do LSO
	 *  if HW doesn't support both IP and TCP checksum.
	 */
	if (ocsum_flags & HCK_PARTIALCKSUM) {
		ocsum_start = (uint32_t)DB_CKSUMSTART(omp);
		ocsum_stuff = (uint32_t)DB_CKSUMSTUFF(omp);
	}

	odatalen = opktlen - ohdrslen;

	/*
	 * Subtract one to account for the case where the data length
	 * is evenly divisble by the MSS. Add one to account for the
	 * fact that the division will always result in one less
	 * segment than needed.
	 */
	nsegs = ((odatalen - 1) / mss) + 1;
	if (nsegs < 2) {
		mac_drop_pkt(omp, "LSO not enough segs: %u", nsegs);
		goto fail;
	}

	DTRACE_PROBE6(sw__lso__start, mblk_t *, omp, void_ip_t *, oiph,
	    __dtrace_tcp_tcph_t *, otcph, uint_t, odatalen, uint_t, mss, uint_t,
	    nsegs);

	seg_chain = NULL;
	tmptail = seg_chain;
	oleft = odatalen;

	for (uint_t i = 0; i < nsegs; i++) {
		boolean_t last_seg = ((i + 1) == nsegs);
		uint32_t seg_len;

		/*
		 * If we fail to allocate, then drop the partially
		 * allocated chain as well as the LSO packet. Let the
		 * sender deal with the fallout.
		 */
		if ((nhdrmp = allocb(ohdrslen, 0)) == NULL) {
			freemsgchain(seg_chain);
			mac_drop_pkt(omp, "failed to alloc segment header");
			goto fail;
		}
		ASSERT3P(nhdrmp->b_cont, ==, NULL);

		if (seg_chain == NULL) {
			seg_chain = nhdrmp;
		} else {
			ASSERT3P(tmptail, !=, NULL);
			tmptail->b_next = nhdrmp;
		}

		tmptail = nhdrmp;

		/*
		 * Calculate this segment's lengh. It's either the MSS
		 * or whatever remains for the last segment.
		 */
		seg_len = last_seg ? oleft : mss;
		ASSERT3U(seg_len, <=, mss);
		ndatamp = build_data_seg(&odatamp, &offset, seg_len);

		if (ndatamp == NULL) {
			freemsgchain(seg_chain);
			mac_drop_pkt(omp, "LSO failed to segment data");
			goto fail;
		}

		/* Attach data mblk to header mblk. */
		nhdrmp->b_cont = ndatamp;
		DB_CKSUMFLAGS(ndatamp) &= ~HW_LSO;
		ASSERT3U(seg_len, <=, oleft);
		oleft -= seg_len;
	}

	/* We should have consumed entire LSO msg. */
	ASSERT3S(oleft, ==, 0);
	ASSERT3P(odatamp, ==, NULL);

	/*
	 * All seg data mblks are referenced by the header mblks, null
	 * out this pointer to catch any bad derefs.
	 */
	ndatamp = NULL;

	/*
	 * Set headers and checksum for first segment.
	 */
	nhdrmp = seg_chain;
	bcopy(omp->b_rptr, nhdrmp->b_rptr, ohdrslen);
	nhdrmp->b_wptr = nhdrmp->b_rptr + ohdrslen;
	niph = (ipha_t *)(nhdrmp->b_rptr + oehlen);
	ASSERT3U(msgsize(nhdrmp->b_cont), ==, mss);
	niph->ipha_length = htons(oiphlen + otcphlen + mss);
	niph->ipha_hdr_checksum = 0;
	ip_id = ntohs(niph->ipha_ident);
	ntcph = (tcph_t *)(nhdrmp->b_rptr + oehlen + oiphlen);
	tcp_seq = BE32_TO_U32(ntcph->th_seq);
	tcp_seq += mss;

	/*
	 * The first segment shouldn't:
	 *
	 *	o indicate end of data transmission (FIN),
	 *	o indicate immediate handling of the data (PUSH).
	 */
	ntcph->th_flags[0] &= ~(TH_FIN | TH_PUSH);
	DB_CKSUMFLAGS(nhdrmp) = (uint16_t)(ocsum_flags & ~HW_LSO);

	/*
	 * If the underlying HW provides partial checksum, then make
	 * sure to correct the pseudo header checksum before calling
	 * mac_sw_cksum(). The native TCP stack doesn't include the
	 * length field in the pseudo header when LSO is in play -- so
	 * we need to calculate it here.
	 */
	if (ocsum_flags & HCK_PARTIALCKSUM) {
		DB_CKSUMSTART(nhdrmp) = ocsum_start;
		DB_CKSUMEND(nhdrmp) = ntohs(niph->ipha_length);
		DB_CKSUMSTUFF(nhdrmp) = ocsum_stuff;
		tcp_sum = BE16_TO_U16(ntcph->th_sum);
		otcp_sum = tcp_sum;
		tcp_sum += mss + otcphlen;
		tcp_sum = (tcp_sum >> 16) + (tcp_sum & 0xFFFF);
		U16_TO_BE16(tcp_sum, ntcph->th_sum);
	}

	if ((ocsum_flags & (HCK_PARTIALCKSUM | HCK_FULLCKSUM)) &&
	    (emul & MAC_HWCKSUM_EMULS)) {
		next_nhdrmp = nhdrmp->b_next;
		nhdrmp->b_next = NULL;
		nhdrmp = mac_sw_cksum(nhdrmp, emul);
		nhdrmp->b_next = next_nhdrmp;
		next_nhdrmp = NULL;

		/*
		 * We may have freed the nhdrmp argument during
		 * checksum emulation, make sure that seg_chain
		 * references a valid mblk.
		 */
		seg_chain = nhdrmp;
	}

	ASSERT3P(nhdrmp, !=, NULL);

	seg = 1;
	DTRACE_PROBE5(sw__lso__seg, mblk_t *, nhdrmp, void_ip_t *,
	    (ipha_t *)(nhdrmp->b_rptr + oehlen), __dtrace_tcp_tcph_t *,
	    (tcph_t *)(nhdrmp->b_rptr + oehlen + oiphlen), uint_t, mss,
	    uint_t, seg);
	seg++;

	/* There better be at least 2 segs. */
	ASSERT3P(nhdrmp->b_next, !=, NULL);
	prev_nhdrmp = nhdrmp;
	nhdrmp = nhdrmp->b_next;

	/*
	 * Now adjust the headers of the middle segments. For each
	 * header we need to adjust the following.
	 *
	 *	o IP ID
	 *	o IP length
	 *	o TCP sequence
	 *	o TCP flags
	 *	o cksum flags
	 *	o cksum values (if MAC_HWCKSUM_EMUL is set)
	 */
	for (; seg < nsegs; seg++) {
		/*
		 * We use seg_chain as a reference to the first seg
		 * header mblk -- this first header is a template for
		 * the rest of the segments. This copy will include
		 * the now updated checksum values from the first
		 * header. We must reset these checksum values to
		 * their original to make sure we produce the correct
		 * value.
		 */
		bcopy(seg_chain->b_rptr, nhdrmp->b_rptr, ohdrslen);
		nhdrmp->b_wptr = nhdrmp->b_rptr + ohdrslen;
		niph = (ipha_t *)(nhdrmp->b_rptr + oehlen);
		niph->ipha_ident = htons(++ip_id);
		ASSERT3P(msgsize(nhdrmp->b_cont), ==, mss);
		niph->ipha_length = htons(oiphlen + otcphlen + mss);
		niph->ipha_hdr_checksum = 0;
		ntcph = (tcph_t *)(nhdrmp->b_rptr + oehlen + oiphlen);
		U32_TO_BE32(tcp_seq, ntcph->th_seq);
		tcp_seq += mss;
		/*
		 * Just like the first segment, the middle segments
		 * shouldn't have these flags set.
		 */
		ntcph->th_flags[0] &= ~(TH_FIN | TH_PUSH);
		DB_CKSUMFLAGS(nhdrmp) = (uint16_t)(ocsum_flags & ~HW_LSO);

		if (ocsum_flags & HCK_PARTIALCKSUM) {
			/*
			 * First and middle segs have same
			 * pseudo-header checksum.
			 */
			U16_TO_BE16(tcp_sum, ntcph->th_sum);
			DB_CKSUMSTART(nhdrmp) = ocsum_start;
			DB_CKSUMEND(nhdrmp) = ntohs(niph->ipha_length);
			DB_CKSUMSTUFF(nhdrmp) = ocsum_stuff;
		}

		if ((ocsum_flags & (HCK_PARTIALCKSUM | HCK_FULLCKSUM)) &&
		    (emul & MAC_HWCKSUM_EMULS)) {
			next_nhdrmp = nhdrmp->b_next;
			nhdrmp->b_next = NULL;
			nhdrmp = mac_sw_cksum(nhdrmp, emul);
			nhdrmp->b_next = next_nhdrmp;
			next_nhdrmp = NULL;
			/* We may have freed the original nhdrmp. */
			prev_nhdrmp->b_next = nhdrmp;
		}

		DTRACE_PROBE5(sw__lso__seg, mblk_t *, nhdrmp, void_ip_t *,
		    (ipha_t *)(nhdrmp->b_rptr + oehlen), __dtrace_tcp_tcph_t *,
		    (tcph_t *)(nhdrmp->b_rptr + oehlen + oiphlen),
		    uint_t, mss, uint_t, seg);

		ASSERT3P(nhdrmp->b_next, !=, NULL);
		prev_nhdrmp = nhdrmp;
		nhdrmp = nhdrmp->b_next;
	}

	/* Make sure we are on the last segment. */
	ASSERT3U(seg, ==, nsegs);
	ASSERT3P(nhdrmp->b_next, ==, NULL);

	/*
	 * Now we set the last segment header. The difference being
	 * that FIN/PSH/RST flags are allowed.
	 */
	bcopy(seg_chain->b_rptr, nhdrmp->b_rptr, ohdrslen);
	nhdrmp->b_wptr = nhdrmp->b_rptr + ohdrslen;
	niph = (ipha_t *)(nhdrmp->b_rptr + oehlen);
	niph->ipha_ident = htons(++ip_id);
	len = msgsize(nhdrmp->b_cont);
	ASSERT3S(len, >, 0);
	niph->ipha_length = htons(oiphlen + otcphlen + len);
	niph->ipha_hdr_checksum = 0;
	ntcph = (tcph_t *)(nhdrmp->b_rptr + oehlen + oiphlen);
	U32_TO_BE32(tcp_seq, ntcph->th_seq);

	DB_CKSUMFLAGS(nhdrmp) = (uint16_t)(ocsum_flags & ~HW_LSO);
	if (ocsum_flags & HCK_PARTIALCKSUM) {
		DB_CKSUMSTART(nhdrmp) = ocsum_start;
		DB_CKSUMEND(nhdrmp) = ntohs(niph->ipha_length);
		DB_CKSUMSTUFF(nhdrmp) = ocsum_stuff;
		tcp_sum = otcp_sum;
		tcp_sum += len + otcphlen;
		tcp_sum = (tcp_sum >> 16) + (tcp_sum & 0xFFFF);
		U16_TO_BE16(tcp_sum, ntcph->th_sum);
	}

	if ((ocsum_flags & (HCK_PARTIALCKSUM | HCK_FULLCKSUM)) &&
	    (emul & MAC_HWCKSUM_EMULS)) {
		/* This should be the last mblk. */
		ASSERT3P(nhdrmp->b_next, ==, NULL);
		nhdrmp = mac_sw_cksum(nhdrmp, emul);
		prev_nhdrmp->b_next = nhdrmp;
	}

	DTRACE_PROBE5(sw__lso__seg, mblk_t *, nhdrmp, void_ip_t *,
	    (ipha_t *)(nhdrmp->b_rptr + oehlen), __dtrace_tcp_tcph_t *,
	    (tcph_t *)(nhdrmp->b_rptr + oehlen + oiphlen), uint_t, len,
	    uint_t, seg);

	/*
	 * Free the reference to the original LSO message as it is
	 * being replaced by seg_cahin.
	 */
	freemsg(omp);
	*head = seg_chain;
	*tail = nhdrmp;
	*count = nsegs;
	return;

fail:
	*head = NULL;
	*tail = NULL;
	*count = 0;
}

#define	HCK_NEEDED	(HCK_IPV4_HDRCKSUM | HCK_PARTIALCKSUM | HCK_FULLCKSUM)

/*
 * Emulate various hardware offload features in software. Take a chain
 * of packets as input and emulate the hardware features specified in
 * 'emul'. The resulting chain's head pointer replaces the 'mp_chain'
 * pointer given as input, and its tail pointer is written to
 * '*otail'. The number of packets in the new chain is written to
 * '*ocount'. The 'otail' and 'ocount' arguments are optional and thus
 * may be NULL. The 'mp_chain' argument may point to a NULL chain; in
 * which case 'mp_chain' will simply stay a NULL chain.
 *
 * While unlikely, it is technically possible that this function could
 * receive a non-NULL chain as input and return a NULL chain as output
 * ('*mp_chain' and '*otail' would be NULL and '*ocount' would be
 * zero). This could happen if all the packets in the chain are
 * dropped or if we fail to allocate new mblks. In this case, there is
 * nothing for the caller to free. In any event, the caller shouldn't
 * assume that '*mp_chain' is non-NULL on return.
 *
 * This function was written with two main use cases in mind.
 *
 * 1. A way for MAC clients to emulate hardware offloads when they
 *    can't directly handle LSO packets or packets without fully
 *    calculated checksums.
 *
 * 2. A way for MAC to offer hardware offloads when the underlying
 *    hardware can't or won't.
 */
void
mac_hw_emul(mblk_t **mp_chain, mblk_t **otail, uint_t *ocount, mac_emul_t emul)
{
	mblk_t *head = NULL, *tail = NULL;
	uint_t count = 0;

	ASSERT3S(~(MAC_HWCKSUM_EMULS | MAC_LSO_EMUL) & emul, ==, 0);
	ASSERT3P(mp_chain, !=, NULL);

	for (mblk_t *mp = *mp_chain; mp != NULL; ) {
		mblk_t *tmp, *next, *tmphead, *tmptail;
		struct ether_header *ehp;
		uint32_t flags;
		uint_t len = MBLKL(mp), l2len;

		/* Perform LSO/cksum one message at a time. */
		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * For our sanity the first mblk should contain at
		 * least the full L2 header.
		 */
		if (len < sizeof (struct ether_header)) {
			mac_drop_pkt(mp, "packet too short (A): %u", len);
			mp = next;
			continue;
		}

		ehp = (struct ether_header *)mp->b_rptr;
		if (ntohs(ehp->ether_type) == VLAN_TPID)
			l2len = sizeof (struct ether_vlan_header);
		else
			l2len = sizeof (struct ether_header);

		/*
		 * If the first mblk is solely the L2 header, then
		 * there better be more data.
		 */
		if (len < l2len || (len == l2len && mp->b_cont == NULL)) {
			mac_drop_pkt(mp, "packet too short (C): %u", len);
			mp = next;
			continue;
		}

		DTRACE_PROBE2(mac__emul, mblk_t *, mp, mac_emul_t, emul);

		/*
		 * We use DB_CKSUMFLAGS (instead of mac_hcksum_get())
		 * because we don't want to mask-out the LSO flag.
		 */
		flags = DB_CKSUMFLAGS(mp);

		if ((flags & HW_LSO) && (emul & MAC_LSO_EMUL)) {
			uint_t tmpcount = 0;

			/*
			 * LSO fix-up handles checksum emulation
			 * inline (if requested). It also frees mp.
			 */
			mac_sw_lso(mp, emul, &tmphead, &tmptail,
			    &tmpcount);
			if (tmphead == NULL) {
				/* mac_sw_lso() freed the mp. */
				mp = next;
				continue;
			}
			count += tmpcount;
		} else if ((flags & HCK_NEEDED) && (emul & MAC_HWCKSUM_EMULS)) {
			tmp = mac_sw_cksum(mp, emul);
			if (tmp == NULL) {
				/* mac_sw_cksum() freed the mp. */
				mp = next;
				continue;
			}
			tmphead = tmp;
			tmptail = tmp;
			count++;
		} else {
			/* There is nothing to emulate. */
			tmp = mp;
			tmphead = tmp;
			tmptail = tmp;
			count++;
		}

		/*
		 * The tmp mblk chain is either the start of the new
		 * chain or added to the tail of the new chain.
		 */
		if (head == NULL) {
			head = tmphead;
			tail = tmptail;
		} else {
			/* Attach the new mblk to the end of the new chain. */
			tail->b_next = tmphead;
			tail = tmptail;
		}

		mp = next;
	}

	*mp_chain = head;

	if (otail != NULL)
		*otail = tail;

	if (ocount != NULL)
		*ocount = count;
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
mac_rx_def(void *arg, mac_resource_handle_t resource, mblk_t *mp,
    boolean_t loopback)
{
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
