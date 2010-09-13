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

#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if_types.h>

#include "snoop.h"

extern char *dlc_header;
extern jmp_buf xdr_err;

static char *printip(unsigned char *);
static char *addrtoname_align(unsigned char *);

static char unarp_addr[] = "Unknown";
char *opname[] = {
	"",
	"ARP Request",
	"ARP Reply",
	"REVARP Request",
	"REVARP Reply",
};

void
interpret_arp(int flags, struct arphdr *ap, int alen)
{
	char *line;
	extern char *src_name, *dst_name;
	unsigned char *sip, *tip, *sha, *tha;
	char *smacbuf = NULL, *dmacbuf = NULL;
	int maclen;
	ushort_t arpop;
	boolean_t is_ip = B_FALSE;

	/*
	 * Check that at least the generic ARP header was received.
	 */
	if (sizeof (struct arphdr) > alen)
		goto short_packet;

	arpop = ntohs(ap->ar_op);
	maclen = ap->ar_hln;
	if (ntohs(ap->ar_pro) == ETHERTYPE_IP)
		is_ip = B_TRUE;

	sha = (unsigned char *)(ap + 1);
	sip = sha + maclen;
	tha = sip + ap->ar_pln;
	tip = tha + maclen;

	/*
	 * Check that the protocol/hardware addresses were received.
	 */
	if ((tip + ap->ar_pln) > ((unsigned char *)ap + alen))
		goto short_packet;

	if (maclen == 0) {
		smacbuf = dmacbuf = unarp_addr;
	} else {
		if (((flags & F_DTAIL) && is_ip) || (arpop == ARPOP_REPLY)) {
			smacbuf = _link_ntoa(sha, NULL, maclen, IFT_OTHER);
			if (smacbuf == NULL)
				pr_err("Warning: malloc failure");
		}

		if (((flags & F_DTAIL) && is_ip) || (arpop ==
		    REVARP_REQUEST) || (arpop == REVARP_REPLY)) {
			dmacbuf = _link_ntoa(tha, NULL, maclen, IFT_OTHER);
			if (dmacbuf == NULL)
				pr_err("Warning: malloc failure");
		}
	}

	src_name = addrtoname_align(sip);

	if (flags & F_SUM) {

		line = get_sum_line();

		switch (arpop) {
		case ARPOP_REQUEST:
			(void) snprintf(line, MAXLINE, "ARP C Who is %s ?",
			    printip(tip));
			break;
		case ARPOP_REPLY:
			(void) snprintf(line, MAXLINE, "ARP R %s is %s",
			    printip(sip), smacbuf);
			dst_name = addrtoname_align(tip);
			break;
		case REVARP_REQUEST:
			(void) snprintf(line, MAXLINE, "RARP C Who is %s ?",
			    dmacbuf);
			break;
		case REVARP_REPLY:
			(void) snprintf(line, MAXLINE, "RARP R %s is %s",
			    dmacbuf, printip(tip));
			dst_name = addrtoname_align(tip);
			break;
		}
	}

	if (flags & F_DTAIL) {
		show_header("ARP:  ", "ARP/RARP Frame", alen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Hardware type = %d (%s)", ntohs(ap->ar_hrd),
		    arp_htype(ntohs(ap->ar_hrd)));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Protocol type = %04x (%s)", ntohs(ap->ar_pro),
		    print_ethertype(ntohs(ap->ar_pro)));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length of hardware address = %d bytes", ap->ar_hln);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length of protocol address = %d bytes", ap->ar_pln);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Opcode %d (%s)", arpop,
		    (arpop > REVARP_REPLY) ? opname[0] : opname[arpop]);

		if (is_ip) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Sender's hardware address = %s", smacbuf);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Sender's protocol address = %s",
			    printip(sip));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Target hardware address = %s",
			    arpop == ARPOP_REQUEST ? "?" : dmacbuf);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Target protocol address = %s",
			    arpop == REVARP_REQUEST ? "?" :
			    printip(tip));
		}
		show_trailer();
	}

	if (maclen != 0) {
		free(smacbuf);
		free(dmacbuf);
	}
	return;

short_packet:
	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "ARP (short packet)");
	} else if (flags & F_DTAIL) {
		show_header("ARP:  ", "ARP/RARP Frame", alen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "ARP (short packet)");
	}
}

char *
printip(unsigned char *p)
{
	static char buff[MAXHOSTNAMELEN + 32];
	char *ap, *np;
	struct in_addr a;

	memcpy(&a, p, 4);
	ap = (char *)inet_ntoa(a);
	np = (char *)addrtoname(AF_INET, &a);
	(void) snprintf(buff, MAXHOSTNAMELEN, "%s, %s", ap, np);
	return (buff);
}

char *
addrtoname_align(unsigned char *p)
{
	struct in_addr a;

	memcpy(&a, p, 4);
	return ((char *)addrtoname(AF_INET, &a));
}

/*
 * These numbers are assigned by the IANA.  See the arp-parameters registry.
 * Only those values that are used within Solaris have #defines.
 */
const char *
arp_htype(int t)
{
	switch (t) {
	case ARPHRD_ETHER:
		return ("Ethernet (10Mb)");
	case 2:
		return ("Experimental Ethernet (3MB)");
	case 3:
		return ("Amateur Radio AX.25");
	case 4:
		return ("Proteon ProNET Token Ring");
	case 5:
		return ("Chaos");
	case ARPHRD_IEEE802:
		return ("IEEE 802");
	case 7:
		return ("ARCNET");
	case 8:
		return ("Hyperchannel");
	case 9:
		return ("Lanstar");
	case 10:
		return ("Autonet");
	case 11:
		return ("LocalTalk");
	case 12:
		return ("LocalNet");
	case 13:
		return ("Ultra Link");
	case 14:
		return ("SMDS");
	case ARPHRD_FRAME:
		return ("Frame Relay");
	case ARPHRD_ATM:
		return ("ATM");
	case ARPHRD_HDLC:
		return ("HDLC");
	case ARPHRD_FC:
		return ("Fibre Channel");
	case ARPHRD_IPATM:
		return ("IP-ATM");
	case ARPHRD_TUNNEL:
		return ("Tunnel");
	case ARPHRD_IB:
		return ("IPIB");
	};
	return ("UNKNOWN");
}
