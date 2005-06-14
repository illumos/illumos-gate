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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <sys/socket.h>

#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <generic.h>

static int do_ipv6_address(struct sockaddr_in6 *, struct sockaddr_in6 *);
static int do_ipv4_address(struct sockaddr_in *, struct sockaddr_in *);

int
audit_settid(int fd)
{
	struct sockaddr_in6 peer;
	struct sockaddr_in6 sock;
	int peerlen = sizeof (peer);
	int socklen = sizeof (sock);
	int rv;

	if (cannot_audit(0)) {
		return (0);
	}

	/* get peer name */
	if (getpeername(fd, (struct sockaddr *)&peer, (socklen_t *)&peerlen)
		< 0) {
		return (1);
	}

	/* get sock name */
	if (getsockname(fd, (struct sockaddr *)&sock, (socklen_t *)&socklen)
		< 0) {
		return (1);
	}

	if (peer.sin6_family == AF_INET6)
		rv = do_ipv6_address(&peer, &sock);
	else
		rv = do_ipv4_address((struct sockaddr_in *)&peer,
			(struct sockaddr_in *)&sock);

	return (rv);
}

static int
do_ipv6_address(struct sockaddr_in6 *peer, struct sockaddr_in6 *sock)
{
	auditinfo_addr_t ai;

	/* get audit characteristics of process */
	if (getaudit_addr(&ai, sizeof (ai)) < 0) {
		return (errno);
	}

	/*
	 * if terminal ID already set, i.e. non-zero, then just return
	 */
	if (ai.ai_termid.at_port ||
	    ai.ai_termid.at_addr[0] ||
	    ai.ai_termid.at_addr[1] ||
	    ai.ai_termid.at_addr[2] ||
	    ai.ai_termid.at_addr[3]) {
		return (0);
	}

	ai.ai_termid.at_port = ((peer->sin6_port<<16) | (sock->sin6_port));
	ai.ai_termid.at_type = AU_IPv6;
	bcopy(&peer->sin6_addr, ai.ai_termid.at_addr, 16);

	if (setaudit_addr(&ai, sizeof (ai)) < 0) {
		return (errno);
	}

	return (0);
}

static int
do_ipv4_address(struct sockaddr_in *peer, struct sockaddr_in *sock)
{
	auditinfo_t ai;

	/* get audit characteristics of process */
	if (getaudit(&ai) < 0) {
		return (errno);
	}

	/*
	 * if terminal ID already set, i.e. non-zero, then just return
	 */
	if (ai.ai_termid.port || ai.ai_termid.machine) {
		return (0);
	}

	ai.ai_termid.port = (peer->sin_port<<16 | sock->sin_port);
	ai.ai_termid.machine = (uint32_t)peer->sin_addr.s_addr;

	if (setaudit(&ai) < 0) {
		return (errno);
	}

	return (0);
}
