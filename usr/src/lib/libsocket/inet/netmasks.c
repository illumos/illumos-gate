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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal the "netmasks" database.  The sources
 * contain mappings between 32 bit Internet addresses and corresponding
 * 32 bit Internet address masks. The addresses are in dotted internet
 * address notation.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>

int str2addr(const char *, int, void *, char *, int);

static DEFINE_NSS_DB_ROOT(db_root);

void
_nss_initf_netmasks(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_NETMASKS;
	p->default_config = NSS_DEFCONF_NETMASKS;
}

/*
 * Print a network number such as 129.144 as well as an IP address.
 * Assumes network byte order for both IP addresses and network numbers
 * (Network numbers are normally passed around in host byte order).
 * to be MT safe, use a passed in buffer like otherget*_r APIs.
 */
static char *
inet_nettoa(struct in_addr in, char *result, int len)
{
	uint32_t addr = in.s_addr;
	uchar_t *up = (uchar_t *)&addr;

	if (result == NULL)
		return (NULL);

	/* Omit leading zeros */
	if (up[0]) {
		(void) snprintf(result, len, "%d.%d.%d.%d",
		    up[0], up[1], up[2], up[3]);
	} else if (up[1]) {
		(void) snprintf(result, len, "%d.%d.%d", up[1], up[2], up[3]);
	} else if (up[2]) {
		(void) snprintf(result, len, "%d.%d", up[2], up[3]);
	} else {
		(void) snprintf(result, len, "%d", up[3]);
	}
	return (result);
}

/*
 * Given a 32 bit key look it up in the netmasks database
 * based on the "netmasks" policy in /etc/nsswitch.conf.
 * If the key is a network number with the trailing zero's removed
 * (e.g. "192.9.200") this routine can't use inet_ntoa to convert
 * the address to the string key.
 * Returns zero if successful, non-zero otherwise.
 */
static int
getnetmaskbykey(const struct in_addr addr, struct in_addr *mask)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;
	char		tmp[NSS_LINELEN_NETMASKS];

	/*
	 * let the backend do the allocation to store stuff for parsing.
	 * To simplify things, we put the dotted internet address form of
	 * the network address in the 'name' field as a filter to speed
	 * up the lookup.
	 */
	if (inet_nettoa(addr, tmp, NSS_LINELEN_NETMASKS) == NULL)
		return (NSS_NOTFOUND);

	NSS_XbyY_INIT(&arg, mask, NULL, 0, str2addr);
	arg.key.name = tmp;
	res = nss_search(&db_root, _nss_initf_netmasks,
			NSS_DBOP_NETMASKS_BYNET, &arg);
	(void) NSS_XbyY_FINI(&arg);
	return (arg.status = res);
}

/*
 * Given a 32 bit internet network number, it finds the corresponding netmask
 * address based on the "netmasks" policy in /etc/nsswitch.conf.
 * Returns zero if successful, non-zero otherwise.
 * Check both for the (masked) network number and the shifted network
 * number (e.g., both "10.0.0.0" and "10").
 * Assumes that the caller passes in an unshifted number (or an IP address).
 */
int
getnetmaskbynet(const struct in_addr net, struct in_addr *mask)
{
	struct in_addr net1, net2;
	uint32_t i;

	i = ntohl(net.s_addr);

	/*
	 * Try looking for the network number both with and without
	 * the trailing zeros.
	 */
	if ((i & IN_CLASSA_NET) == 0) {
		/* Assume already a right-shifted network number */
		net2.s_addr = htonl(i);
		if ((i & IN_CLASSB_NET) != 0) {
			net1.s_addr = htonl(i << IN_CLASSC_NSHIFT);
		} else if ((i & IN_CLASSC_NET) != 0) {
			net1.s_addr = htonl(i << IN_CLASSB_NSHIFT);
		} else {
			net1.s_addr = htonl(i << IN_CLASSA_NSHIFT);
		}
	} else if (IN_CLASSA(i)) {
		net1.s_addr = htonl(i & IN_CLASSA_NET);
		net2.s_addr = htonl(i >> IN_CLASSA_NSHIFT);
	} else if (IN_CLASSB(i)) {
		net1.s_addr = htonl(i & IN_CLASSB_NET);
		net2.s_addr = htonl(i >> IN_CLASSB_NSHIFT);
	} else {
		net1.s_addr = htonl(i & IN_CLASSC_NET);
		net2.s_addr = htonl(i >> IN_CLASSC_NSHIFT);
	}

	if (getnetmaskbykey(net1, mask) == 0) {
		return (0);
	}
	if (getnetmaskbykey(net2, mask) == 0) {
		return (0);
	}
	return (-1);
}

/*
 * Find the netmask used for an IP address.
 * Returns zero if successful, non-zero otherwise.
 *
 * Support Variable Length Subnetmasks by looking for the longest
 * matching subnetmask in the database.
 * Start by looking for a match for the full IP address and
 * mask off one rightmost bit after another until we find a match.
 * Note that for a match the found netmask must match what was used
 * for the lookup masking.
 * As a fallback for compatibility finally lookup the network
 * number with and without the trailing zeros.
 * In order to suppress redundant lookups in the name service
 * we keep the previous lookup key and compare against it before
 * doing the lookup.
 */
int
getnetmaskbyaddr(const struct in_addr addr, struct in_addr *mask)
{
	struct in_addr prevnet, net;
	uint32_t i, maskoff;

	i = ntohl(addr.s_addr);
	prevnet.s_addr = 0;
	mask->s_addr = 0;

	for (maskoff = 0xFFFFFFFF; maskoff != 0; maskoff = maskoff << 1) {
		net.s_addr = htonl(i & maskoff);

		if (net.s_addr != prevnet.s_addr) {
			if (getnetmaskbykey(net, mask) != 0) {
				mask->s_addr = 0;
			}
		}
		if (htonl(maskoff) == mask->s_addr)
			return (0);

		prevnet.s_addr = net.s_addr;
	}

	/*
	 * Non-VLSM fallback.
	 * Try looking for the network number with and without the trailing
	 * zeros.
	 */
	return (getnetmaskbynet(addr, mask));
}

/*
 * Parse netmasks entry into its components. The network address is placed
 * in buffer for use by check_addr for 'files' backend, to match the network
 * address. The network address is placed in the buffer as a network order
 * internet address, if buffer is non null. The network order form of the mask
 * itself is placed in 'ent'.
 */
int
str2addr(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	int	retval;
	struct in_addr	*mask = (struct in_addr *)ent;
	const char	*p, *limit, *start;
	struct in_addr	addr;
	int		i;
	char		tmp[NSS_LINELEN_NETMASKS];

	p = instr;
	limit = p + lenstr;
	retval = NSS_STR_PARSE_PARSE;

	while (p < limit && isspace(*p))	/* skip leading whitespace */
		p++;

	if (buffer) {	/* for 'files' backend verification */
		for (start = p, i = 0; p < limit && !isspace(*p); p++)
			i++;
		if (p < limit && i < buflen) {
			(void) memcpy(tmp, start, i);
			tmp[i] = '\0';
			addr.s_addr = inet_addr(tmp);
			/* Addr will always be an ipv4 address (32bits) */
			if (addr.s_addr == 0xffffffffUL)
				return (NSS_STR_PARSE_PARSE);
			else {
				(void) memcpy(buffer, (char *)&addr,
				    sizeof (struct in_addr));
			}
		} else
			return (NSS_STR_PARSE_ERANGE);
	}

	while (p < limit && isspace(*p))	/* skip intermediate */
		p++;

	if (mask) {
		for (start = p, i = 0; p < limit && !isspace(*p); p++)
			i++;
		if (p <= limit) {
			if ((i + 1) > NSS_LINELEN_NETMASKS)
				return (NSS_STR_PARSE_ERANGE);
			(void) memcpy(tmp, start, i);
			tmp[i] = '\0';
			addr.s_addr = inet_addr(tmp);
			/* Addr will always be an ipv4 address (32bits) */
			if (addr.s_addr == 0xffffffffUL)
				retval = NSS_STR_PARSE_PARSE;
			else {
				mask->s_addr = addr.s_addr;
				retval = NSS_STR_PARSE_SUCCESS;
			}
		}
	}

	return (retval);
}
