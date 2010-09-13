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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <syslog.h>
#include <addr_match.h>

/*
 * Function to compare IP addresses.  It walks the list provided in
 * the res parameter, comparing to the original address in sin or sin6,
 * with some addition guidance provided by fromp.  It returns B_TRUE
 * if a match is found, otherwise B_FALSE.
 */

static boolean_t
find_match(const struct addrinfo *res,
    const struct sockaddr_storage *fromp,
    const struct sockaddr_in *sin,
    const struct sockaddr_in6 *sin6)
{
	const struct addrinfo *ai;

	/* This is the moral equivalent of an assert. */
	if ((fromp->ss_family == AF_INET && sin == NULL) ||
	    (fromp->ss_family == AF_INET6 && sin6 == NULL))
		return (B_FALSE);

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		struct sockaddr_in *s4;
		struct sockaddr_in6 *s6;
		void *addr1, *addr2;
		size_t size;

		if (ai->ai_family != fromp->ss_family)
			continue;
		if (ai->ai_family == AF_INET) {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			s4 = (struct sockaddr_in *)ai->ai_addr;
			addr1 = &s4->sin_addr;
			addr2 = &((struct sockaddr_in *)sin)->sin_addr;
			size = sizeof (struct in_addr);
		} else if (ai->ai_family == AF_INET6) {
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			s6 = (struct sockaddr_in6 *)ai->ai_addr;
			addr1 = &s6->sin6_addr;
			addr2 = &((struct sockaddr_in6 *)sin6)->sin6_addr;
			size = sizeof (struct in6_addr);
		} else {
			continue;
		}
		if (memcmp(addr1, addr2, size) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

void
check_address(const char *prog,
    const struct sockaddr_storage *fromp,
    const struct sockaddr_in *sin,
    const struct sockaddr_in6 *sin6,
    const char *printable_addr,
    char *hostname,
    size_t hostsize)
{
	/*
	 * We have to check for spoofing.  So take hostname, look up its
	 * address(es), and walk the list until we have a match with the
	 * original IP address.  If no match is found, log a warning and
	 * use the original IP address for authentication purposes.
	 */
	struct addrinfo *res, hints;
	boolean_t match_found = B_FALSE;

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_flags = AI_CANONNAME|AI_V4MAPPED|AI_ADDRCONFIG|AI_ALL;
	hints.ai_family = fromp->ss_family;
	if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
		match_found = find_match(res, fromp, sin, sin6);
		freeaddrinfo(res);
	}
	if (!match_found) {
		syslog(LOG_WARNING, "%s: IP address '%s' maps to host "
		    "name '%s',\r\n but that host name does not map to "
		    "the same IP address.", prog, printable_addr, hostname);
		(void) strlcpy(hostname, printable_addr, hostsize);
	}
}
