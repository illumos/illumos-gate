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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include "snoop.h"

extern char *dlc_header;

int
interpret_udp(int flags, struct udphdr *udp, int iplen, int fraglen)
{
	char *data;
	int udplen;
	int sunrpc;
	char *pname;
	char buff [32];

	if (fraglen < sizeof (struct udphdr))
		return (fraglen);	/* incomplete header */

	data = (char *)udp + sizeof (struct udphdr);
	udplen = ntohs((ushort_t)udp->uh_ulen) - sizeof (struct udphdr);
	fraglen -= sizeof (struct udphdr);
	if (fraglen > udplen)
		fraglen = udplen;

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(),
			"UDP D=%d S=%d LEN=%d",
			ntohs(udp->uh_dport),
			ntohs(udp->uh_sport),
			ntohs((ushort_t)udp->uh_ulen));
	}

	sunrpc = !reservedport(IPPROTO_UDP, ntohs(udp->uh_dport)) &&
		!reservedport(IPPROTO_UDP, ntohs(udp->uh_sport)) &&
		valid_rpc(data, udplen);

	if (flags & F_DTAIL) {
		show_header("UDP:  ", "UDP Header", udplen);
		show_space();
		(void) sprintf(get_line((char *)(uintptr_t)udp->uh_sport -
		    dlc_header, 1), "Source port = %d", ntohs(udp->uh_sport));

		if (sunrpc) {
			pname = "(Sun RPC)";
		} else {
			pname = getportname(IPPROTO_UDP, ntohs(udp->uh_dport));
			if (pname == NULL) {
				pname = "";
			} else {
				(void) sprintf(buff, "(%s)", pname);
				pname = buff;
			}
		}
		(void) sprintf(get_line((char *)(uintptr_t)udp->uh_dport -
		    dlc_header, 1), "Destination port = %d %s",
		    ntohs(udp->uh_dport), pname);
		(void) sprintf(get_line((char *)(uintptr_t)udp->uh_ulen -
		    dlc_header, 1), "Length = %d %s",
		    ntohs((ushort_t)udp->uh_ulen),
		    udplen > fraglen ?
			"(Not all data contained in this fragment)"
			: "");
		    (void) sprintf(get_line((char *)(uintptr_t)udp->uh_sum -
			dlc_header, 1),	"Checksum = %04X %s",
			ntohs(udp->uh_sum),
			udp->uh_sum == 0 ? "(no checksum)" : "");
		show_space();
	}


	/* go to the next protocol layer */

	if (!interpret_reserved(flags, IPPROTO_UDP,
		ntohs(udp->uh_sport),
		ntohs(udp->uh_dport),
		data, fraglen)) {
		if (fraglen > 0 && sunrpc)
			interpret_rpc(flags, data, fraglen, IPPROTO_UDP);
	}

	return (fraglen);
}
