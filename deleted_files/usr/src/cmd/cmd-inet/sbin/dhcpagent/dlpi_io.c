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

#include <stdio.h>
#include <sys/types.h>
#include <sys/pfmod.h>
#include <sys/socket.h>
#include <netinet/in.h>			/* in_addr (ip.h) */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stropts.h>
#include <string.h>			/* strpbrk */
#include <sys/uio.h>
#include <stdlib.h>
#include <dhcpmsg.h>

#include "dlpi_io.h"
#include "v4_sum_impl.h"
#include "common.h"

/*
 * timeout to wait for acknowledgement of packet filter, in seconds.
 */
#define	FILTER_TIMEOUT	5

/*
 * dlpi_recvfrom(): receives data on a DLPI stream
 *
 *  input: dlpi_handle_t: dlpi handle to receive the data on
 *	    void *: a buffer to store the data in
 *	    size_t: the size of the buffer
 *	    struct sockaddr_in *: if non-NULL, sender's IP address is filled in
 *	    struct sockaddr_in *: if non-NULL, recipient's IP address
 *  output: ssize_t: the number of bytes read on success, -1 on failure
 */
ssize_t
dlpi_recvfrom(dlpi_handle_t dh, void *buf, size_t buflen,
    struct sockaddr_in *from, struct sockaddr_in *to)
{
	struct ip		*ip;
	struct udphdr		*udphdr;
	void			*msgbuf;
	size_t			msglen;
	dlpi_recvinfo_t		dlrecv;
	int			rc;

	msglen = buflen + sizeof (struct ip) + sizeof (struct udphdr);
	msgbuf = malloc(msglen);

	if (msgbuf == NULL) {
		dhcpmsg(MSG_ERR, "dlpi_recvfrom: cannot allocate packet");
		return (-1);
	}

	rc = dlpi_recv(dh, NULL, NULL, msgbuf, &msglen, -1, &dlrecv);
	if (rc != DLPI_SUCCESS) {
		dhcpmsg(MSG_ERR, "dlpi_recvfrom: dlpi_recv failed: %s",
		    dlpi_strerror(rc));
		free(msgbuf);
		return (-1);
	}

	/*
	 * since we're just pulling data off the wire, what we have
	 * may look nothing like a DHCP packet.  note that this
	 * shouldn't happen (pfmod should have tossed it already).
	 */
	if (msglen < sizeof (struct ip) + sizeof (struct udphdr)) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: dropped short packet");
		free(msgbuf);
		return (-1);
	}

	if (msglen < dlrecv.dri_totmsglen) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: discarding stray "
		    "data on streamhead");
	}

	/*
	 * verify checksums
	 */
	ip = msgbuf;
	if (ipv4cksum((uint16_t *)ip, ip->ip_hl << 2) != 0) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: dropped packet with bad "
		    "ipv4 checksum");
		free(msgbuf);
		return (-1);
	}

	udphdr = (struct udphdr *)&ip[1];
	if ((udphdr->uh_sum != 0) &&
	    (udp_chksum(udphdr, &ip->ip_src, &ip->ip_dst, ip->ip_p) != 0)) {
		dhcpmsg(MSG_WARNING, "dlpi_recvfrom: dropped packet with bad "
		    "UDP checksum");
		free(msgbuf);
		return (-1);
	}

	msglen -= (sizeof (struct ip) + sizeof (struct udphdr));
	(void) memcpy(buf, &udphdr[1], msglen);

	if (from != NULL) {
		from->sin_family = AF_INET;
		from->sin_addr = ip->ip_src;
		from->sin_port = udphdr->uh_sport;
	}

	if (to != NULL) {
		to->sin_family = AF_INET;
		to->sin_addr = ip->ip_dst;
		to->sin_port = udphdr->uh_dport;
	}

	free(msgbuf);
	return (msglen);
}

/*
 * dlpi_sendto(): sends UDP packets on a DLPI stream
 *
 *  input: dlpi_handle_t: dlpi handle to send the packet on
 *	    void *: a buffer to send
 *	    size_t: the size of the buffer
 *	    struct sockaddr_in *: the IP address to send the data to
 *	    uchar_t *: the link-layer destination address
 *	    size_t: the size of the link-layer destination address
 *  output: ssize_t: the number of bytes sent on success, -1 on failure
 */
ssize_t
dlpi_sendto(dlpi_handle_t dh, void *buf, size_t buflen,
    struct sockaddr_in *to, uchar_t *dl_to, size_t dl_to_len)
{
	struct ip		*ip;
	struct udphdr		*udphdr;
	void			*msgbuf;
	size_t			msglen;
	static uint16_t		ip_id = 0;
	int			rc;

	/*
	 * TODO: someday we might want to support `to' not being
	 * the same as INADDR_BROADCAST.  we don't need the support
	 * right now, but it's annoying to have a general interface
	 * that only supports a specific function.
	 */
	if (to->sin_addr.s_addr != htonl(INADDR_BROADCAST)) {
		dhcpmsg(MSG_ERROR, "dlpi_sendto: send to unicast address");
		return (-1);
	}

	/*
	 * we allocate one extra byte here in case the UDP checksum
	 * routine needs it to get the packet length to be even.
	 */
	msglen = sizeof (struct ip) + sizeof (struct udphdr) + buflen;
	msgbuf = calloc(1, msglen + 1);
	if (msgbuf == NULL) {
		dhcpmsg(MSG_ERR, "dlpi_sendto: cannot allocate packet");
		return (-1);
	}

	ip	= (struct ip *)msgbuf;
	udphdr	= (struct udphdr *)&ip[1];

	(void) memcpy(&udphdr[1], buf, buflen);

	/*
	 * build the ipv4 header.  assume that our source address is 0
	 * (since we wouldn't be using DLPI if we could actually send
	 * packets an easier way).  note that we only need to set nonzero
	 * fields since we got calloc()'d memory above.
	 */

	/*
	 * From a purist's perspective, we should set the TTL to 1 for
	 * limited broadcasts. But operational experience (cisco routers)
	 * has shown that doing so results in the relay agent dropping our
	 * packets. These same devices (ciscos) also don't set the TTL
	 * to MAXTTL on the unicast side of the relay agent. Thus, the only
	 * safe thing to do is to always set the ttl to MAXTTL. Sigh.
	 */

	ip->ip_ttl	  = MAXTTL;

	ip->ip_v	  = 4;
	ip->ip_hl	  = sizeof (struct ip) / 4;
	ip->ip_id	  = htons(ip_id++);
	ip->ip_off	  = htons(IP_DF);
	ip->ip_p	  = IPPROTO_UDP;
	ip->ip_len	  = htons(msglen);
	ip->ip_dst	  = to->sin_addr;
	ip->ip_src.s_addr = htonl(INADDR_ANY);
	ip->ip_sum	  = ipv4cksum((uint16_t *)ip, sizeof (struct ip));

	udphdr->uh_ulen	  = htons(sizeof (struct udphdr) + buflen);
	udphdr->uh_sport  = htons(IPPORT_BOOTPC);
	udphdr->uh_dport  = htons(IPPORT_BOOTPS);
	udphdr->uh_sum = udp_chksum(udphdr, &ip->ip_src, &ip->ip_dst, ip->ip_p);

	rc = dlpi_send(dh, dl_to, dl_to_len, msgbuf, msglen, NULL);
	if (rc != DLPI_SUCCESS) {
		free(msgbuf);
		dhcpmsg(MSG_ERR, "dlpi_sendto: dlpi_send: %s",
		    dlpi_strerror(rc));
		return (-1);
	}

	free(msgbuf);
	return (buflen);
}

/*
 * set_packet_filter(): sets the current packet filter on a DLPI stream
 *
 *   input: dlpi_handle_t: the DLPI handle to set the packet filter on
 *	    filter_func_t *: the filter to use
 *	    void *: an argument to pass to the filter function
 *	    const char *: a text description of the filter's purpose
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure.
 */
boolean_t
set_packet_filter(dlpi_handle_t dh, filter_func_t *filter, void *arg,
    const char *filter_name)
{
	struct strioctl		sioc;
	struct packetfilt	pf;
	ushort_t		*pfp = pf.Pf_Filter;
	int			fd = dlpi_fd(dh);

	if (ioctl(fd, I_PUSH, "pfmod") == -1) {
		dhcpmsg(MSG_ERR,
		    "open_dlpi_pif: cannot push pfmod on stream");
		return (B_FALSE);
	}

	pf.Pf_FilterLen = filter(pfp, arg) - pf.Pf_Filter;

	sioc.ic_cmd	= PFIOCSETF;
	sioc.ic_timout	= FILTER_TIMEOUT;
	sioc.ic_len	= sizeof (struct packetfilt);
	sioc.ic_dp	= (caddr_t)&pf;

	/*
	 * if this ioctl() fails, we're really hosed.  the best we can
	 * really do is play on.
	 */

	if (ioctl(fd, I_STR, &sioc) == -1)
		dhcpmsg(MSG_ERR, "set_packet_filter: PFIOCSETF");
	else
		dhcpmsg(MSG_DEBUG, "set_packet_filter: set filter %p "
		    "(%s filter)", (void *)filter, filter_name);

	/*
	 * clean out any potential cruft on the descriptor that
	 * appeared before we were able to set the filter
	 */

	(void) ioctl(fd, I_FLUSH, FLUSHR);

	return (B_TRUE);
}

/*
 * dhcp_filter(): builds a packet filter that permits only DHCP/BOOTP messages
 *
 *   input: ushort_t *: a place to store the packet filter code
 *	    void *: not used
 *  output: ushort_t *: two bytes past the last byte in the packet filter
 */

/* ARGSUSED */
ushort_t *
dhcp_filter(ushort_t *pfp, void *arg)
{
	/*
	 * only pass up UDP packets -- 8th byte is the ttl/proto field
	 */

	*pfp++ = ENF_PUSHWORD + 4;
	*pfp++ = ENF_PUSHLIT | ENF_AND;
	*pfp++ = htons(0xff);
	*pfp++ = ENF_PUSHLIT | ENF_CAND;
	*pfp++ = htons(IPPROTO_UDP);

	/*
	 * make sure the IP packet doesn't have any options.  2nd
	 * nibble is the header length field.
	 * TODO: if we decide to handle options, this code goes away.
	 */

	*pfp++ = ENF_PUSHWORD + 0;
	*pfp++ = ENF_PUSHLIT | ENF_AND;
	*pfp++ = htons(0x0f00);			/* only care about 2nd nibble */
	*pfp++ = ENF_PUSHLIT | ENF_CAND;
	*pfp++ = htons(0x0500);			/* which should be 5 * 4 = 20 */

	/*
	 * if there's a fragment offset, or if the IP_MF bit is lit,
	 * pitch the packet.  this  pitches all fragments.
	 * TODO: if we decide to handle fragments, this code goes away.
	 */

	*pfp++ = ENF_PUSHWORD + 3;
	*pfp++ = ENF_PUSHLIT | ENF_AND;
	*pfp++ = htons(0x1fff | IP_MF);
	*pfp++ = ENF_PUSHZERO | ENF_CAND;

	/*
	 * make sure the packet is for the DHCP client port -- 22nd
	 * byte is the UDP port number.
	 */

	*pfp++ = ENF_PUSHWORD + 11;
	*pfp++ = ENF_PUSHLIT | ENF_CAND;
	*pfp++ = htons(IPPORT_BOOTPC);

	return (pfp);
}
