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
 * Copyright (c) 1991-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <at.h>
#include <snoop.h>

static char *printat(uint8_t *);

static char *aarp_opname[] = {
	"",
	"AARP Request",
	"AARP Reply",
	"AARP Probe",
};

void
interpret_aarp(int flags, char *data, int alen)
{
	/* LINTED */
	struct ether_arp *ap = (struct ether_arp *)data;

	extern char *dst_name;

	if (flags & F_SUM) {
		if (alen < sizeof (struct ether_arp)) {
			(void) snprintf(get_sum_line(), MAXLINE,
			    "AARP (short packet)");
			return;
		}

		switch (ntohs(ap->arp_op)) {
		case AARP_REQ:
			(void) snprintf(get_sum_line(), MAXLINE,
			    "AARP C Who is %s ?",
			    printat(ap->arp_tpa));
			break;
		case AARP_RESP:
			(void) snprintf(get_sum_line(), MAXLINE,
			    "AARP R %s is %s",
			    printat(ap->arp_spa),
			    printether((struct ether_addr *)&ap->arp_sha));
			dst_name = printat(ap->arp_tpa);
			break;
		case AARP_PROBE:
			(void) snprintf(get_sum_line(), MAXLINE,
			    "AARP Probe %s ?",
			    printat(ap->arp_tpa));
			break;
		}
	}

	if (flags & F_DTAIL) {
		show_header("AARP: ", "AARP Frame", alen);
		show_space();

		if (alen < sizeof (struct ether_arp)) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "AARP (short packet)");
			return;
		}

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Hardware type = %d",
		    ntohs(ap->arp_hrd));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Protocol type = %04X (%s)",
		    ntohs(ap->arp_pro),
		    print_ethertype(ntohs(ap->arp_pro)));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length of hardware address = %d bytes",
		    ap->arp_hln);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Length of protocol address = %d bytes",
		    ap->arp_pln);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Opcode %d (%s)",
		    ntohs(ap->arp_op),
		    aarp_opname[ntohs(ap->arp_op)]);

		if (ntohs(ap->arp_hrd) == ARPHRD_ETHER &&
		    ntohs(ap->arp_pro) == ETHERTYPE_AT) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Sender's hardware address = %s",
			    printether((struct ether_addr *)&ap->arp_sha));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Sender's protocol address = %s",
			    printat(ap->arp_spa));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Target hardware address = %s",
			    (ntohs(ap->arp_op) == AARP_REQ ||
				ntohs(ap->arp_op) == AARP_PROBE) ? "?" :
			    printether((struct ether_addr *)&ap->arp_tha));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Target protocol address = %s",
			    ntohs(ap->arp_op) == REVARP_REQUEST ? "?" :
			    printat(ap->arp_tpa));
		}
		show_trailer();
	}
}

static char *
printat(uint8_t *p)
{
	static char buf[16];

	(void) snprintf(buf, sizeof (buf),  "%d.%d", get_short(&p[1]), p[3]);
	return (buf);
}
