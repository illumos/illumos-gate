/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/pattr.h>

#include <sys/ethernet.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>

#include "sfxge.h"

#include "efx.h"


/*
 * Parse packet headers and return:
 *	etherhpp	Ethernet MAC header
 *	iphpp		IPv4 header (NULL for non-IPv4 packet)
 *	thpp		TCP header (NULL for non-TCP packet)
 *	offp		Offset to TCP payload
 *	sizep		Size of TCP payload
 *	dportp		TCP/UDP/SCTP dest. port (network order), otherwise zero
 *	sportp		TCP/UDP/SCTP source port, (network order) otherwise zero
 */
sfxge_packet_type_t
sfxge_pkthdr_parse(mblk_t *mp, struct ether_header **etherhpp,
    struct ip **iphpp, struct tcphdr **thpp,
    size_t *offp, size_t *sizep,
    uint16_t *sportp, uint16_t *dportp)
{
	struct ether_header *etherhp;
	uint16_t ether_type;
	size_t etherhs;
	struct ip *iphp;
	size_t iphs;
	struct tcphdr *thp;
	size_t len;
	size_t ths;
	size_t off;
	size_t size;
	uint16_t sport;
	uint16_t dport;
	sfxge_packet_type_t pkt_type = SFXGE_PACKET_TYPE_UNKNOWN;

	etherhp = NULL;
	iphp = NULL;
	thp = NULL;
	off = 0;
	size = 0;
	sport = 0;
	dport = 0;

	/* Grab the MAC header */
	etherhs = sizeof (struct ether_header);
	if ((MBLKL(mp) < etherhs) && (pullupmsg(mp, etherhs) == 0))
		goto done;

	/*LINTED*/
	etherhp = (struct ether_header *)(mp->b_rptr);
	ether_type = etherhp->ether_type;

	if (ether_type == htons(ETHERTYPE_VLAN)) {
		struct ether_vlan_header *ethervhp;

		etherhs = sizeof (struct ether_vlan_header);
		if ((MBLKL(mp) < etherhs) && (pullupmsg(mp, etherhs) == 0))
			goto done;

		/*LINTED*/
		ethervhp = (struct ether_vlan_header *)(mp->b_rptr);
		ether_type = ethervhp->ether_type;
	}

	if (ether_type != htons(ETHERTYPE_IP))
		goto done;

	/* Skip over the MAC header */
	off += etherhs;

	/* Grab the IP header */
	len = off + sizeof (struct ip);
	if ((MBLKL(mp) < len) && (pullupmsg(mp, len) == 0))
		goto done;

	/*LINTED*/
	iphp = (struct ip *)(mp->b_rptr + off);
	iphs = iphp->ip_hl * 4;

	if (iphp->ip_v != IPV4_VERSION)
		goto done;

	/* Get the size of the packet */
	size = ntohs(iphp->ip_len);

	ASSERT3U(etherhs + size, <=, msgdsize(mp));

	pkt_type = SFXGE_PACKET_TYPE_IPV4_OTHER;

	/* Skip over the IP header */
	off += iphs;
	size -= iphs;

	if (iphp->ip_p == IPPROTO_TCP) {
		/* Grab the TCP header */
		len = off + sizeof (struct tcphdr);
		if ((MBLKL(mp) < len) && (pullupmsg(mp, len) == 0))
			goto done;

		/*LINTED*/
		thp = (struct tcphdr *)(mp->b_rptr + off);
		ths = thp->th_off * 4;

		dport = thp->th_dport;
		sport = thp->th_sport;

		/* Skip over the TCP header */
		off += ths;
		size -= ths;

		pkt_type = SFXGE_PACKET_TYPE_IPV4_TCP;

	} else if (iphp->ip_p == IPPROTO_UDP) {
		struct udphdr *uhp;

		/* Grab the UDP header */
		len = off + sizeof (struct udphdr);
		if ((MBLKL(mp) < len) && (pullupmsg(mp, len) == 0))
			goto done;

		/*LINTED*/
		uhp = (struct udphdr *)(mp->b_rptr + off);
		dport = uhp->uh_dport;
		sport = uhp->uh_sport;

		/* Skip over the UDP header */
		off += sizeof (struct udphdr);
		size -= sizeof (struct udphdr);

		pkt_type = SFXGE_PACKET_TYPE_IPV4_UDP;

	} else if (iphp->ip_p == IPPROTO_SCTP) {
		struct sctp_hdr *shp;

		/* Grab the SCTP header */
		len = off + sizeof (struct sctp_hdr);
		if ((MBLKL(mp) < len) && (pullupmsg(mp, len) == 0))
			goto done;

		/*LINTED*/
		shp = (struct sctp_hdr *)(mp->b_rptr + off);
		dport = shp->sh_dport;
		sport = shp->sh_sport;

		/* Skip over the SCTP header */
		off += sizeof (struct sctp_hdr);
		size -= sizeof (struct sctp_hdr);

		pkt_type = SFXGE_PACKET_TYPE_IPV4_SCTP;
	}

	if (MBLKL(mp) < off)
		(void) pullupmsg(mp, off);

done:
	*etherhpp = etherhp;
	*iphpp = iphp;
	*thpp = thp;
	*offp = off;
	*sizep = size;
	*sportp = sport;
	*dportp = dport;

	return (pkt_type);
}
