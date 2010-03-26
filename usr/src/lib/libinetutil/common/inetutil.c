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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include <netinet/in.h>
#include <libinetutil.h>
#include <inet/ip.h>
#include <strings.h>
#include <errno.h>
#include <libsocket_priv.h>

/*
 * Internet utility functions.
 */

/*
 * Given a host-order address, calculate client's default net mask.
 * Consult netmasks database to see if net is further subnetted.
 * We'll only snag the first netmask that matches our criteria.
 * We return the resultant netmask in host order.
 */
void
get_netmask4(const struct in_addr *n_addrp, struct in_addr *s_addrp)
{
	struct in_addr	hp, tp;

	/*
	 * First check if VLSM is in use.
	 */
	hp.s_addr = htonl(n_addrp->s_addr);
	if (getnetmaskbyaddr(hp, &tp) == 0) {
		s_addrp->s_addr = ntohl(tp.s_addr);
		return;
	}

	/*
	 * Fall back on standard classed networks.
	 */
	if (IN_CLASSA(n_addrp->s_addr))
		s_addrp->s_addr = IN_CLASSA_NET;
	else if (IN_CLASSB(n_addrp->s_addr))
		s_addrp->s_addr = IN_CLASSB_NET;
	else if (IN_CLASSC(n_addrp->s_addr))
		s_addrp->s_addr = IN_CLASSC_NET;
	else
		s_addrp->s_addr = IN_CLASSE_NET;
}

/*
 * Checks if the IP addresses `ssp1' and `ssp2' are equal.
 */
boolean_t
sockaddrcmp(const struct sockaddr_storage *ssp1,
    const struct sockaddr_storage *ssp2)
{
	struct in_addr addr1, addr2;
	const struct in6_addr *addr6p1, *addr6p2;

	if (ssp1->ss_family != ssp2->ss_family)
		return (B_FALSE);

	if (ssp1 == ssp2)
		return (B_TRUE);

	switch (ssp1->ss_family) {
	case AF_INET:
		addr1 = ((const struct sockaddr_in *)ssp1)->sin_addr;
		addr2 = ((const struct sockaddr_in *)ssp2)->sin_addr;
		return (addr1.s_addr == addr2.s_addr);
	case AF_INET6:
		addr6p1 = &((const struct sockaddr_in6 *)ssp1)->sin6_addr;
		addr6p2 = &((const struct sockaddr_in6 *)ssp2)->sin6_addr;
		return (IN6_ARE_ADDR_EQUAL(addr6p1, addr6p2));
	}
	return (B_FALSE);
}

/*
 * Stores the netmask in `mask' for the given prefixlen `plen' and also sets
 * `ss_family' in `mask'.
 */
int
plen2mask(uint_t prefixlen, sa_family_t af, struct sockaddr_storage *mask)
{
	uint8_t	*addr;

	bzero(mask, sizeof (*mask));
	mask->ss_family = af;
	if (af == AF_INET) {
		if (prefixlen > IP_ABITS)
			return (EINVAL);
		addr = (uint8_t *)&((struct sockaddr_in *)mask)->
		    sin_addr.s_addr;
	} else {
		if (prefixlen > IPV6_ABITS)
			return (EINVAL);
		addr = (uint8_t *)&((struct sockaddr_in6 *)mask)->
		    sin6_addr.s6_addr;
	}

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*addr++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*addr |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (0);
}

/*
 * Convert a mask to a prefix length.
 * Returns prefix length on success, -1 otherwise.
 */
int
mask2plen(const struct sockaddr_storage *mask)
{
	int rc = 0;
	uint8_t last;
	uint8_t *addr;
	int limit;

	if (mask->ss_family == AF_INET) {
		limit = IP_ABITS;
		addr = (uint8_t *)&((struct sockaddr_in *)mask)->
		    sin_addr.s_addr;
	} else {
		limit = IPV6_ABITS;
		addr = (uint8_t *)&((struct sockaddr_in6 *)mask)->
		    sin6_addr.s6_addr;
	}

	while (*addr == 0xff) {
		rc += 8;
		if (rc == limit)
			return (limit);
		addr++;
	}

	last = *addr;
	while (last != 0) {
		rc++;
		last = (last << 1) & 0xff;
	}

	return (rc);
}

/*
 * Returns B_TRUE if the address in `ss' is INADDR_ANY for IPv4 or
 * :: for IPv6. Otherwise, returns B_FALSE.
 */
boolean_t
sockaddrunspec(const struct sockaddr_storage *ss)
{
	struct sockaddr_storage zeroaddr = {0};

	switch (ss->ss_family) {
	case AF_INET:
		return (((struct sockaddr_in *)ss)->sin_addr.s_addr ==
		    INADDR_ANY);
	case AF_INET6:
		return (IN6_IS_ADDR_UNSPECIFIED(
		    &((struct sockaddr_in6 *)ss)->sin6_addr));
	}

	return (bcmp(&zeroaddr, ss, sizeof (zeroaddr)) == 0);
}
