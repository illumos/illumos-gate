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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * icmp4.c, Code implementing the Internet Control Message Protocol (v4) ICMP.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <socket_impl.h>
#include <socket_inet.h>
#include <sys/salib.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/bootconf.h>
#include <sys/fcntl.h>

#include "icmp4.h"
#include "ipv4.h"
#include "ipv4_impl.h"
#include "mac.h"
#include "v4_sum_impl.h"
#include <sys/bootdebug.h>

/*
 * Handle ICMP redirects, ICMP echo messages. We only deal with redirects to a
 * different default router by changing the default route to the specified
 * value.
 */
void
icmp4(struct inetgram *igp, struct ip *iphp, uint16_t iphlen,
struct in_addr ipsrc)
{
	int		icmp_len;
	struct in_addr	our_ip;
	struct icmp	*icmphp;

	icmp_len = ntohs(iphp->ip_len) - iphlen;
	if (icmp_len < ICMP_MINLEN) {
#ifdef	DEBUG
		printf("icmp4: ICMP message from %s is too short\n",
		    inet_ntoa(ipsrc));
#endif	/* DEBUG */
		return;
	}

	icmphp = (struct icmp *)(igp->igm_mp->b_rptr + iphlen);

	/* check alignment */
	if ((uintptr_t)icmphp % sizeof (uint16_t)) {
		dprintf("icmp4: ICMP header not aligned (from %s)\n",
		    inet_ntoa(ipsrc));
		return;
	}
	if (ipv4cksum((uint16_t *)icmphp, icmp_len) != 0) {
		dprintf("icmp4: Bad ICMP checksum (from %s)\n",
		    inet_ntoa(ipsrc));
		return;
	}
	switch (icmphp->icmp_type) {
	case ICMP_REDIRECT:
		if (icmphp->icmp_code != ICMP_REDIRECT_HOST)
			break;
		dprintf("ICMP Redirect to gateway %s.\n",
		    inet_ntoa(icmphp->icmp_gwaddr));
		if (ipv4_route(IPV4_ADD_ROUTE, RT_HOST, &icmphp->icmp_ip.ip_dst,
		    &icmphp->icmp_gwaddr) != 0) {
			dprintf("icmp4: Cannot add route %s, %d\n",
			    inet_ntoa(icmphp->icmp_ip.ip_dst), errno);
		}
		break;
	case ICMP_UNREACH:
		/*
		 * Need to highlight an error on the socket, and save the
		 * destination address so that we can ensure it is destined
		 * to this socket. We need the port number to be sure...
		 */
		dprintf("ICMP destination unreachable (%s)\n",
		    inet_ntoa(icmphp->icmp_ip.ip_dst));
		break;
	case ICMP_ECHO:
		/*
		 * swap the source and destination IP addresses
		 * and send a reply right out.
		 */
		ipv4_getipaddr(&our_ip);
		if (our_ip.s_addr != INADDR_ANY) {
			int			s;
			struct sockaddr_in	dest;

			if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
				dprintf("icmp4: socket: %d\n", errno);
				break;
			}
			icmphp->icmp_type = ICMP_ECHOREPLY;
			icmphp->icmp_cksum = 0;
			icmphp->icmp_cksum = ipv4cksum((uint16_t *)icmphp,
			    icmp_len);
			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = ipsrc.s_addr;
			dest.sin_port = htons(0);
			(void) sendto(s, (caddr_t)icmphp, icmp_len, 0,
			    (const struct sockaddr *)&dest, sizeof (dest));
			(void) socket_close(s);
		}
		break;
	default:
		dprintf("icmp4: Unsupported ICMP message type: 0x%x "
		    "received from %s\n", icmphp->icmp_type, inet_ntoa(ipsrc));
		break;
	}
}
