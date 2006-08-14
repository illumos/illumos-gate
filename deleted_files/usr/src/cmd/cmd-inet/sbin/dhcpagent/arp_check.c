/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%W%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <sys/dlpi.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/pfmod.h>
#include <dhcpmsg.h>
#include <stddef.h>

#include "defaults.h"
#include "util.h"
#include "interface.h"
#include "dlpi_io.h"
#include "arp_check.h"

/*
 * the struct arp_info is used by arp_reply_filter() to build a filter
 * that only receives replies from the ARPed IP address.
 */

struct arp_info {

	uchar_t		send_addr_offset;	/* from start of ARP frame */
	in_addr_t	send_addr; 		/* arped IP address */
};

/*
 * arp_reply_filter(): builds a filter that permits ARP replies to our request
 *
 *   input: ushort_t *: a place to store the packet filter code
 *	    void *: a struct arp_info containing the requested IP address
 *  output: ushort_t *: two bytes past the last byte of the filter
 */

static ushort_t *
arp_reply_filter(ushort_t *pfp, void *arg)
{
	struct arp_info *ai = (struct arp_info *)arg;

	*pfp++ = ENF_PUSHWORD + (offsetof(struct arphdr, ar_op) / 2);
	*pfp++ = ENF_PUSHLIT | ENF_EQ;
	*pfp++ = htons(ARPOP_REPLY);

	/*
	 * make sure this ARP reply is from the target IP address,
	 * which will be the "sender" IP address in the reply (even in
	 * the case of proxy ARP).  the position of sender IP address
	 * depends on the link layer; so we can be link-layer
	 * independent, these values are calculated in arp_check().
	 *
	 * the byteorder issues here are *really* subtle.  suppose
	 * that the network address is 0x11223344 (as stored in the
	 * packet read off the wire) by an intel machine.  then notice
	 * that since the packet filter operates 16 bits at a time
	 * that the high-order word will load as 0x2211 and the
	 * low-order word will load as 0x4433.  so send_addr has the
	 * register value 0x44332211 on intel since that will store to
	 * the network address 0x11223344 in memory.  thus, to compare
	 * the low-order word, we must first ntohl() send_addr, which
	 * changes its register-value to 0x11223344, and then mask
	 * off the high-order bits, getting 0x3344, and then convert
	 * that to network order, getting 0x4433, which is what we
	 * want.  the same logic applies to the high-order word.  you
	 * are not expected to understand this.
	 */

	*pfp++ = ENF_PUSHWORD + (ai->send_addr_offset / 2) + 1;
	*pfp++ = ENF_PUSHLIT | ENF_EQ;
	*pfp++ = htons(ntohl(ai->send_addr) & 0xffff);
	*pfp++ = ENF_AND;

	*pfp++ = ENF_PUSHWORD + (ai->send_addr_offset / 2);
	*pfp++ = ENF_PUSHLIT | ENF_EQ;
	*pfp++ = htons(ntohl(ai->send_addr) >> 16);
	*pfp++ = ENF_AND;

	return (pfp);
}

/*
 * arp_check(): checks to see if a given IP address is already in use
 *
 *   input: struct ifslist *: the interface to send the ARP request on
 *	    in_addr_t: the IP address to send from, network order
 *	    in_addr_t: the IP address to check on, network order
 *	    uchar_t *: a scratch buffer that holds the hardware address
 *		       of the machine that replied to our ARP request,
 *		       if there was one.
 *	    uint32_t: the length of the buffer
 *	    uint32_t: how long to wait for an ARP reply, in milliseconds
 *  output: int: 1 if the IP address is in use, 0 if not in use.
 */

int
arp_check(struct ifslist *ifsp, in_addr_t send_addr, in_addr_t target_addr,
    uchar_t *target_hwaddr, uint32_t target_hwlen, uint32_t timeout_msec)
{
	uint32_t		buf[DLPI_BUF_MAX / sizeof (uint32_t)];
	dl_info_ack_t		*dlia = (dl_info_ack_t *)buf;
	int			fd;
	struct arphdr		*arp_pkt = NULL;
	uchar_t			*arp_daddr = NULL;
	caddr_t			arp_payload;
	uchar_t			arp_dlen;
	size_t			offset;
	struct pollfd		pollfd;
	int			retval;
	struct arp_info		ai;
	unsigned int		arp_pkt_len;

	fd = dlpi_open(ifsp->if_name, dlia, sizeof (buf), ETHERTYPE_ARP);
	if (fd == -1)
		goto failure;

	/*
	 * the packet consists of an ARP header, two IP addresses
	 * and two hardware addresses (each ifsp->if_hwlen bytes long).
	 */

	arp_pkt_len = sizeof (struct arphdr) + (sizeof (ipaddr_t) * 2) +
	    (ifsp->if_hwlen * 2);

	arp_pkt   = malloc(arp_pkt_len);
	arp_daddr = build_broadcast_dest(dlia, &arp_dlen);
	if (arp_pkt == NULL || arp_daddr == NULL)
		goto failure;

	(void) memset(arp_pkt, 0xff, arp_pkt_len);

	arp_pkt->ar_hrd		= htons(ifsp->if_hwtype);
	arp_pkt->ar_pro		= htons(ETHERTYPE_IP);
	arp_pkt->ar_hln		= ifsp->if_hwlen;
	arp_pkt->ar_pln		= sizeof (ipaddr_t);
	arp_pkt->ar_op		= htons(ARPOP_REQUEST);

	arp_payload = (caddr_t)&arp_pkt[1];
	(void) memcpy(arp_payload, ifsp->if_hwaddr, ifsp->if_hwlen);
	offset = ifsp->if_hwlen;

	/*
	 * while we're at the appropriate offset for sender IP address,
	 * store it for use by the packet filter.
	 */

	ai.send_addr		= target_addr;
	ai.send_addr_offset	= offset + sizeof (struct arphdr);

	(void) memcpy(&arp_payload[offset], &send_addr, sizeof (ipaddr_t));
	offset += ifsp->if_hwlen + sizeof (ipaddr_t);
	(void) memcpy(&arp_payload[offset], &target_addr, sizeof (ipaddr_t));

	/*
	 * install the packet filter, send our ARP request, and wait
	 * for a reply.  waiting usually isn't a good idea since the
	 * design of the agent is nonblocking.  however, we can
	 * tolerate short waits (< 5 seconds).
	 */

	set_packet_filter(fd, arp_reply_filter, &ai, "ARP reply");

	if (dlpi_send_link(fd, arp_pkt, arp_pkt_len, arp_daddr, arp_dlen) == -1)
		goto failure;

	pollfd.fd	= fd;
	pollfd.events	= POLLIN;

	retval = poll(&pollfd, 1, timeout_msec);
	if (retval > 0 && target_hwaddr != NULL) {

		/*
		 * try to grab the hardware address. if we fail, we'll
		 * just end up with some misleading diagnostics.  the
		 * hardware address is at the start of the payload.
		 */

		if (dlpi_recv_link(fd, arp_pkt, arp_pkt_len, DLPI_RECV_SHORT) ==
		    arp_pkt_len)
			(void) memcpy(target_hwaddr, arp_payload, target_hwlen);
	}

	free(arp_daddr);
	free(arp_pkt);
	(void) close(fd);
	return ((retval == 0) ? 0 : 1);

failure:
	free(arp_daddr);
	free(arp_pkt);
	(void) close(fd);

	if (df_get_bool(ifsp->if_name, DF_IGNORE_FAILED_ARP)) {
		dhcpmsg(MSG_WARNING, "arp_check: cannot send ARP request: "
		    "assuming address is available");
		return (0);
	}

	dhcpmsg(MSG_WARNING, "arp_check: cannot send ARP request: "
	    "assuming address is unavailable");
	return (1);
}
