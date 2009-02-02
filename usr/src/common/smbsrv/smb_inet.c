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

/*
 * This file was originally generated using rpcgen.
 */

#ifndef _KERNEL
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#endif /* !_KERNEL */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/tcp.h>
#include <smbsrv/smb_inet.h>

const struct in6_addr ipv6addr_any = IN6ADDR_ANY_INIT;

boolean_t
smb_inet_equal(smb_inaddr_t *ip1, smb_inaddr_t *ip2, uint32_t v4mask)
{
	if ((ip1->a_family == AF_INET) &&
	    (ip2->a_family == AF_INET) &&
	    ((ip1->a_ipv4 & v4mask) == (ip2->a_ipv4 & v4mask)))
		return (B_TRUE);

	if ((ip1->a_family == AF_INET6) &&
	    (ip2->a_family == AF_INET6) &&
	    (!memcmp(&ip1->a_ipv6, &ip2->a_ipv6, IPV6_ADDR_LEN)))
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
	    !memcmp(&ipaddr->a_ipv6, ipsz, IPV6_ADDR_LEN))
		return (B_TRUE);
	else
		return (B_FALSE);
}

const char *
smb_inet_ntop(smb_inaddr_t *addr, char *buf, int size)
{
	return ((char *)inet_ntop(addr->a_family, (char *)addr, buf, size));
}
