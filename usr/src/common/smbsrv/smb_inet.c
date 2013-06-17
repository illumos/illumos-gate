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
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This file was originally generated using rpcgen.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if !defined(_KERNEL)
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#else	/* !_KERNEL */
#include <sys/errno.h>
#include <sys/sunddi.h>
/* Don't want the rest of what's in inet/ip.h */
extern char	*inet_ntop(int, const void *, char *, int);
extern int	inet_pton(int, char *, void *);
#endif	/* !_KERNEL */

#include <smbsrv/smb_inet.h>

const struct in6_addr ipv6addr_any = IN6ADDR_ANY_INIT;

boolean_t
smb_inet_equal(smb_inaddr_t *ip1, smb_inaddr_t *ip2)
{
	if ((ip1->a_family == AF_INET) &&
	    (ip2->a_family == AF_INET) &&
	    (ip1->a_ipv4 == ip2->a_ipv4))
		return (B_TRUE);

	if ((ip1->a_family == AF_INET6) &&
	    (ip2->a_family == AF_INET6) &&
	    (!memcmp(&ip1->a_ipv6, &ip2->a_ipv6, sizeof (in6_addr_t))))
		return (B_TRUE);
	else
		return (B_FALSE);
}

boolean_t
smb_inet_same_subnet(smb_inaddr_t *ip1, smb_inaddr_t *ip2, uint32_t v4mask)
{
	if ((ip1->a_family == AF_INET) &&
	    (ip2->a_family == AF_INET) &&
	    ((ip1->a_ipv4 & v4mask) == (ip2->a_ipv4 & v4mask)))
		return (B_TRUE);

	if ((ip1->a_family == AF_INET6) &&
	    (ip2->a_family == AF_INET6) &&
	    (!memcmp(&ip1->a_ipv6, &ip2->a_ipv6, sizeof (in6_addr_t))))
		return (B_TRUE);
	else
		return (B_FALSE);
}

boolean_t
smb_inet_iszero(smb_inaddr_t *ipaddr)
{
	const void *ipsz = (const void *)&ipv6addr_any;

	if ((ipaddr->a_family == AF_INET) &&
	    (ipaddr->a_ipv4 == 0))
		return (B_TRUE);

	if ((ipaddr->a_family == AF_INET6) &&
	    !memcmp(&ipaddr->a_ipv6, ipsz, sizeof (in6_addr_t)))
		return (B_TRUE);
	else
		return (B_FALSE);
}

const char *
smb_inet_ntop(smb_inaddr_t *addr, char *buf, int size)
{
	/* Lint avoidance. */
#if !defined(_KERNEL)
	size_t sz = (size_t)size;
#else
	int sz = size;
#endif
	return ((char *)inet_ntop(addr->a_family, addr, buf, sz));
}
