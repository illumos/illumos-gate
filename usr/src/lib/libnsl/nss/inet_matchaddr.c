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
 * Copyright 2016 Nexenta Systems, Inc.
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
 *
 * Return values:
 *
 * 0		mismatch
 * 1		match
 * -1		error occured, caller should check errno:
 * 		EINVAL	access list entry is invalid
 *		ENOMEM	failed to allocate memory
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>

int
inet_matchaddr(const void *sa, const char *name)
{
	int ret = -1;
	char *lname, *mp, *p;
	char *ep;
	int serrno = errno;
	uint32_t claddr4 = 0;

	if ((p = lname = strdup(name)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	if ((mp = strchr(p, '/')) != NULL)
		*mp++ = '\0';

	switch (((struct sockaddr_in *)sa)->sin_family) {
	case AF_INET6: {
		char *pp;
		ipaddr_t ipaddr4;
		struct in6_addr hcaddr6;
		struct in6_addr *claddr6 =
		    &((struct sockaddr_in6 *)sa)->sin6_addr;

		if (!IN6_IS_ADDR_V4MAPPED(claddr6)) {
			/* IPv6 address */
			if (*p != '[') {
				errno = EINVAL;
				break;
			}
			p++;

			if ((pp = strchr(p, ']')) == NULL ||
			    (mp != NULL && pp != mp - 2) ||
			    (mp == NULL && *(pp + 1) != '\0')) {
				errno = EINVAL;
				break;
			}
			*pp = '\0';

			if (inet_pton(AF_INET6, p, &hcaddr6) != 1) {
				errno = EINVAL;
				break;
			}

			if (mp != NULL) {
				/* Match only first prefix bits */
				long prefix6;

				errno = 0;
				prefix6 = strtol(mp, &ep, 10);
				if (errno != 0 || prefix6 < 0 ||
				    prefix6 > 128 || *ep != '\0') {
					errno = EINVAL;
					break;
				}
				ret = IN6_ARE_PREFIXEDADDR_EQUAL(claddr6,
				    &hcaddr6, prefix6) ? 1 : 0;
				break;
			} else {
				/* No prefix, exact match */
				ret = IN6_ARE_ADDR_EQUAL(claddr6,
				    &hcaddr6) ? 1 : 0;
				break;
			}
		} else {
			/* IPv4-mapped IPv6 address, fallthrough to IPv4 */
			IN6_V4MAPPED_TO_IPADDR(claddr6, ipaddr4);
			claddr4 = ntohl(ipaddr4);
		}
	}
	/*FALLTHROUGH*/
	case AF_INET: {
		int i;
		uint32_t hcaddr4 = 0, mask4;

		if (claddr4 == 0) {
			claddr4 = ntohl(
			    ((struct sockaddr_in *)sa)->sin_addr.s_addr);
		}

		for (i = 0; i < 4; i++) {
			long qaddr4;

			errno = 0;
			qaddr4 = strtol(p, &ep, 10);
			if (errno != 0 || qaddr4 < 0 || qaddr4 > 255 ||
			    (*ep != '.' && *ep != '\0')) {
				errno = EINVAL;
				break;
			}
			hcaddr4 |= qaddr4 << ((3 - i) * 8);
			if (*ep == '\0')
				break;
			p = ep + 1;
		}

		if (errno != 0)
			break;

		if (mp != NULL) {
			/* Mask is specified explicitly */
			long mb;

			errno = 0;
			mb = strtol(mp, &ep, 10);
			if (errno != 0 || mb < 0 || mb > 32 || *ep != '\0') {
				errno = EINVAL;
				break;
			}
			mask4 = mb ? ~0 << ((sizeof (struct in_addr) * NBBY)
			    - mb) : 0;
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

		ret = ((claddr4 & mask4) == hcaddr4) ? 1 : 0;
		break;
	}
	}

	free(lname);

	if (ret != -1)
		errno = serrno;
	return (ret);
}
