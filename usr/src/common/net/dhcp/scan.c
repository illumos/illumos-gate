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
 *
 * Routines used to extract/insert DHCP options. Must be kept MT SAFE,
 * as they are called from different threads.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include "dhcp_impl.h"
#if defined(_KERNEL) && !defined(_BOOT)
#include <sys/sunddi.h>
#else
#include <strings.h>
#endif	/* _KERNEL && !_BOOT */

static uint8_t	bootmagic[] = BOOTMAGIC;

/*
 * Scan field for options.
 */
static void
field_scan(uint8_t *start, uint8_t *end, DHCP_OPT **options,
    uint8_t last_option)
{
	uint8_t		*current;

	while (start < end) {
		if (*start == CD_PAD) {
			start++;
			continue;
		}
		if (*start == CD_END)
			break;		/* done */
		if (*start > last_option) {
			if (++start < end)
				start += *start + 1;
			continue;	/* unrecognized option */
		}

		current = start;
		if (++start < end)
			start += *start + 1; /* advance to next option */

		/* all options besides CD_END and CD_PAD should have a len */
		if ((current + 1) >= end)
			continue;

		/* Ignores duplicate options. */
		if (options[*current] == NULL) {

			options[*current] = (DHCP_OPT *)current;

			/* verify that len won't go beyond end */
			if ((current + options[*current]->len + 1) >= end) {
				options[*current] = NULL;
				continue;
			}
		}
	}
}

/*
 * Scan Vendor field for options.
 */
static void
vendor_scan(PKT_LIST *pl)
{
	uint8_t	*start, *end, len;

	if (pl->opts[CD_VENDOR_SPEC] == NULL)
		return;
	len = pl->opts[CD_VENDOR_SPEC]->len;
	start = pl->opts[CD_VENDOR_SPEC]->value;

	/* verify that len won't go beyond the end of the packet */
	if (((start - (uint8_t *)pl->pkt) + len) > pl->len)
		return;

	end = start + len;
	field_scan(start, end, pl->vs, VS_OPTION_END);
}

/*
 * Load opts table in PKT_LIST entry with PKT's options.
 * Returns 0 if no fatal errors occur, otherwise...
 */
int
dhcp_options_scan(PKT_LIST *pl, boolean_t scan_vendor)
{
	PKT 	*pkt = pl->pkt;
	uint_t	opt_size = pl->len - BASE_PKT_SIZE;

	/*
	 * bcmp() is used here instead of memcmp() since kernel/standalone
	 * doesn't have a memcmp().
	 */
	if (pl->len < BASE_PKT_SIZE ||
	    bcmp(pl->pkt->cookie, bootmagic, sizeof (pl->pkt->cookie)) != 0) {
		pl->rfc1048 = 0;
		return (0);
	}

	pl->rfc1048 = 1;

	/* check the options field */
	field_scan(pkt->options, &pkt->options[opt_size], pl->opts,
	    DHCP_LAST_OPT);

	/*
	 * process vendor specific options. We look at the vendor options
	 * here, simply because a BOOTP server could fake DHCP vendor
	 * options. This increases our interoperability with BOOTP.
	 */
	if (scan_vendor && (pl->opts[CD_VENDOR_SPEC] != NULL))
		vendor_scan(pl);

	if (pl->opts[CD_DHCP_TYPE] == NULL)
		return (0);

	if (pl->opts[CD_DHCP_TYPE]->len != 1)
		return (DHCP_GARBLED_MSG_TYPE);

	if (*pl->opts[CD_DHCP_TYPE]->value < DISCOVER ||
	    *pl->opts[CD_DHCP_TYPE]->value > INFORM)
		return (DHCP_WRONG_MSG_TYPE);

	if (pl->opts[CD_OPTION_OVERLOAD]) {
		if (pl->opts[CD_OPTION_OVERLOAD]->len != 1) {
			pl->opts[CD_OPTION_OVERLOAD] = NULL;
			return (DHCP_BAD_OPT_OVLD);
		}
		switch (*pl->opts[CD_OPTION_OVERLOAD]->value) {
		case 1:
			field_scan(pkt->file, &pkt->cookie[0], pl->opts,
			    DHCP_LAST_OPT);
			break;
		case 2:
			field_scan(pkt->sname, &pkt->file[0], pl->opts,
			    DHCP_LAST_OPT);
			break;
		case 3:
			field_scan(pkt->file, &pkt->cookie[0], pl->opts,
			    DHCP_LAST_OPT);
			field_scan(pkt->sname, &pkt->file[0], pl->opts,
			    DHCP_LAST_OPT);
			break;
		default:
			pl->opts[CD_OPTION_OVERLOAD] = NULL;
			return (DHCP_BAD_OPT_OVLD);
		}
	}
	return (0);
}

/*
 * Locate a DHCPv6 option or suboption within a buffer.  DHCPv6 uses nested
 * options within options, and this function is designed to work with both
 * primary options and the suboptions contained within.
 *
 * The 'oldopt' is a previous option pointer, and is typically used to iterate
 * over options of the same code number.  The 'codenum' is in host byte order
 * for simplicity.  'retlenp' may be NULL, and if present gets the _entire_
 * option length (including header).
 *
 * Warning: the returned pointer has no particular alignment because DHCPv6
 * defines options without alignment.  The caller must deal with unaligned
 * pointers carefully.
 */
dhcpv6_option_t *
dhcpv6_find_option(const void *buffer, size_t buflen,
    const dhcpv6_option_t *oldopt, uint16_t codenum, uint_t *retlenp)
{
	const uchar_t *bp;
	dhcpv6_option_t d6o;
	uint_t olen;

	codenum = htons(codenum);
	bp = buffer;
	while (buflen >= sizeof (dhcpv6_option_t)) {
		(void) memcpy(&d6o, bp, sizeof (d6o));
		olen = ntohs(d6o.d6o_len) + sizeof (d6o);
		if (olen > buflen)
			break;
		if (d6o.d6o_code != codenum ||
		    (oldopt != NULL && bp <= (const uchar_t *)oldopt)) {
			bp += olen;
			buflen -= olen;
			continue;
		}
		if (retlenp != NULL)
			*retlenp = olen;
		/* LINTED: alignment */
		return ((dhcpv6_option_t *)bp);
	}
	return (NULL);
}

/*
 * Locate a DHCPv6 option within the top level of a PKT_LIST entry.  DHCPv6
 * uses nested options within options, and this function returns only the
 * primary options.  Use dhcpv6_find_option to traverse suboptions.
 *
 * See dhcpv6_find_option for usage details and warnings.
 */
dhcpv6_option_t *
dhcpv6_pkt_option(const PKT_LIST *plp, const dhcpv6_option_t *oldopt,
    uint16_t codenum, uint_t *retlenp)
{
	const dhcpv6_message_t *d6m;

	if (plp == NULL || plp->pkt == NULL || plp->len < sizeof (*d6m))
		return (NULL);
	d6m = (const dhcpv6_message_t *)plp->pkt;
	return (dhcpv6_find_option(d6m + 1, plp->len - sizeof (*d6m), oldopt,
	    codenum, retlenp));
}
