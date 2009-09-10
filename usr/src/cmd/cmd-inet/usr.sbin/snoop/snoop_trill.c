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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <net/trill.h>

#include <snoop.h>

int
interpret_trill(int flags, struct ether_header **e, char *data, int *alen)
{
	trill_header_t *trillhdr;
	struct ether_header *inner_ethhdr;
	struct ether_vlan_header *inner_ethvlanhdr;
	uint16_t ethertype;
	int dlen = *alen;
	size_t optslen;
	size_t trillhdrlen;

	if (dlen < sizeof (trill_header_t)) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "TRILL (short packet)");
		return (0);
	}

	trillhdr = (trill_header_t *)data;
	optslen = GET_TRILL_OPTS_LEN(trillhdr) * sizeof (uint32_t);

	if (flags & F_DTAIL) {
		show_header("TRILL: ", "TRILL Data Frame", dlen);
		show_space();

		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Egress nickname = %d",
		    ntohs(trillhdr->th_egressnick));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Ingress nickname = %d",
		    ntohs(trillhdr->th_ingressnick));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Hop count = %d", trillhdr->th_hopcount);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Multi-destination = %d", trillhdr->th_multidest);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Options Len = %d bytes", optslen);
		show_trailer();
	}

	trillhdrlen = sizeof (trill_header_t) + optslen;

	if (dlen < trillhdrlen) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "TRILL (options truncated)");
		return (0);
	}

	dlen -= trillhdrlen;

	if (dlen < sizeof (struct ether_header)) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "TRILL (missing required inner MAC)");
		return (0);
	}

	inner_ethhdr = (struct ether_header *)(data + trillhdrlen);
	if (inner_ethhdr->ether_type != htons(ETHERTYPE_VLAN)) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "TRILL (inner VLAN missing; ethertype %X)",
		    ntohs(inner_ethhdr->ether_type));
		return (0);
	}

	inner_ethvlanhdr = (struct ether_vlan_header *)inner_ethhdr;
	ethertype = ntohs(inner_ethvlanhdr->ether_type);

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "TRILL D:%d S:%d HC:%d M:%d O:%d L:%d VLAN:%d %s",
		    ntohs(trillhdr->th_egressnick),
		    ntohs(trillhdr->th_ingressnick),
		    trillhdr->th_hopcount,
		    trillhdr->th_multidest,
		    optslen,
		    dlen, VLAN_ID(inner_ethvlanhdr->ether_tci),
		    print_ethertype(ethertype));
	}

	*alen = dlen;
	*e = inner_ethhdr;
	return (ethertype);
}
