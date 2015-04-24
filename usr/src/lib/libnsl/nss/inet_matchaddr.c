/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * inet_matchaddr
 *
 * Match IPv4 or IPv6 address provided in sa (sockaddr_in/sockaddr_in6)
 * against standard text representation specified in name:
 *
 * IPv4:
 *	IPv4
 *	IPv4/netmask
 *
 * IPv6:
 *	[IPv6]
 *	[IPv6]/prefix
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>


boolean_t
inet_matchaddr(const void *sa, const char *name)
{
	boolean_t ret = B_FALSE;
	char *lname, *mp, *p;
	uint32_t claddr4 = 0;

	if ((p = lname = strdup(name)) == NULL)
		err(1, "strdup");

	if ((mp = strchr(p, '/')) != NULL)
		*mp++ = '\0';

	switch (((struct sockaddr_in *)sa)->sin_family) {
	case AF_INET6: {
		char *pp;
		int prefix6;
		ipaddr_t ipaddr4;
		struct in6_addr hcaddr6;
		struct in6_addr *claddr6 =
		    &((struct sockaddr_in6 *)sa)->sin6_addr;

		if (!IN6_IS_ADDR_V4MAPPED(claddr6)) {
			/* IPv6 address */
			if ((p = strchr(p, '[')) == NULL)
				break;
			p++;

			if ((pp = strchr(p, ']')) == NULL)
				break;
			*pp = '\0';

			if (inet_pton(AF_INET6, p, &hcaddr6) != 1)
				break;

			if (mp != NULL) {
				/* Match only first prefix bits */
				if ((prefix6 = (int)strtol(mp,
				    (char **)NULL, 10)) == 0)
					break;
				ret = IN6_ARE_PREFIXEDADDR_EQUAL(claddr6,
				    &hcaddr6, prefix6);
				break;
			} else {
				/* No prefix, exact match */
				ret = IN6_ARE_ADDR_EQUAL(claddr6, &hcaddr6);
				break;
			}
		} else {
			/* IPv4-mapped IPv6 address, fallthrough to IPv4 */
			IN6_V4MAPPED_TO_IPADDR(claddr6, ipaddr4);
			claddr4 = ntohl(ipaddr4);
		}
		/*FALLTHROUGH*/
	}
	case AF_INET: {
		int bits, i;
		uint32_t hcaddr4 = 0, mask4;

		if (claddr4 == 0) {
			claddr4 = ntohl(
			    ((struct sockaddr_in *)sa)->sin_addr.s_addr);
		}

		for (i = 0; i < 4; i++) {
			hcaddr4 |= (int)strtol(p, (char **)NULL, 10) <<
			    ((3 - i) * 8);
			if ((p = strchr(p, '.')) == NULL)
				break;
			p++;
		}

		if (hcaddr4 == 0 && errno != 0)
			break;

		if (mp != NULL) {
			/* Mask is specified explicitly */
			if ((bits = (int)strtol(mp, (char **)NULL, 10)) == 0 &&
			    errno != 0)
				break;
			mask4 = bits ? ~0 << ((sizeof (struct in_addr) * NBBY)
			    - bits) : 0;
			hcaddr4 &= mask4;
		} else {
			/*
			 * Use old-fashioned implicit netmasking by checking
			 * for lower-end zeroes. On the off chance we don't
			 * match any well-known prefixes, return an exact-
			 * match prefix which is misleadingly labelled as
			 * IN_CLASSE_NET.
			 */
			if ((hcaddr4 & IN_CLASSA_HOST) == 0)
				mask4 = IN_CLASSA_NET;
			else if ((hcaddr4 & IN_CLASSB_HOST) == 0)
				mask4 = IN_CLASSB_NET;
			else if ((hcaddr4 & IN_CLASSC_HOST) == 0)
				mask4 = IN_CLASSC_NET;
			else
				mask4 = IN_CLASSE_NET;
		}

		ret = ((claddr4 & mask4) == hcaddr4);
		break;
	}
	}

	free(lname);

	return (ret);
}
