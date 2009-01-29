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
 * selfcheck.c
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <syslog.h>

#include <strings.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>

int
self_check(char *hostname)
{
	int s, res = 0;
	struct sioc_addrreq areq;

	struct hostent *hostinfo;
	int family;
	int flags;
	int error_num;
	char **hostptr;

	struct sockaddr_in6 ipv6addr;

	family = AF_INET6;
	flags = AI_DEFAULT;

	if ((s = socket(family, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "self_check: socket: %m");
		return (0);
	}

	if ((hostinfo = getipnodebyname(hostname, family, flags,
	    &error_num)) == NULL) {

		if (error_num == TRY_AGAIN)
			syslog(LOG_DEBUG,
			    "self_check: unknown host: %s (try again later)\n",
			    hostname);
		else
			syslog(LOG_DEBUG,
			    "self_check: unknown host: %s\n", hostname);

		(void) close(s);
		return (0);
	}

	for (hostptr = hostinfo->h_addr_list; *hostptr; hostptr++) {
		bzero(&ipv6addr, sizeof (ipv6addr));
		ipv6addr.sin6_family = AF_INET6;
		ipv6addr.sin6_addr = *((struct in6_addr *)(*hostptr));
		memcpy(&areq.sa_addr, (void *)&ipv6addr, sizeof (ipv6addr));
		areq.sa_res = -1;
		(void) ioctl(s, SIOCTMYADDR, (caddr_t)&areq);
		if (areq.sa_res == 1) {
			res = 1;
			break;
		}
	}

	freehostent(hostinfo);

	(void) close(s);
	return (res);
}

#define	MAXIFS	32

/*
 * create an ifconf structure that represents all the interfaces
 * configured for this host.  Two buffers are allcated here:
 *	lifc - the ifconf structure returned
 *	lifc->lifc_buf - the list of ifreq structures
 * Both of the buffers must be freed by the calling routine.
 * A NULL pointer is returned upon failure.  In this case any
 * data that was allocated before the failure has already been
 * freed.
 */
struct lifconf *
getmyaddrs(void)
{
	int sock;
	struct lifnum lifn;
	int numifs;
	char *buf;
	struct lifconf *lifc;

	if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		syslog(LOG_ERR, "statd:getmyaddrs socket: %m");
		return ((struct lifconf *)NULL);
	}

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = 0;

	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		syslog(LOG_ERR,
		"statd:getmyaddrs, get number of interfaces, error: %m");
		numifs = MAXIFS;
	}

	numifs = lifn.lifn_count;

	lifc = (struct lifconf *)malloc(sizeof (struct lifconf));
	if (lifc == NULL) {
		syslog(LOG_ERR,
		    "statd:getmyaddrs, malloc for lifconf failed: %m");
		(void) close(sock);
		return ((struct lifconf *)NULL);
	}
	buf = (char *)malloc(numifs * sizeof (struct lifreq));
	if (buf == NULL) {
		syslog(LOG_ERR,
		    "statd:getmyaddrs, malloc for lifreq failed: %m");
		(void) close(sock);
		free(lifc);
		return ((struct lifconf *)NULL);
	}

	lifc->lifc_family = AF_UNSPEC;
	lifc->lifc_flags = 0;
	lifc->lifc_buf = buf;
	lifc->lifc_len = numifs * sizeof (struct lifreq);

	if (ioctl(sock, SIOCGLIFCONF, (char *)lifc) < 0) {
		syslog(LOG_ERR, "statd:getmyaddrs, SIOCGLIFCONF, error: %m");
		(void) close(sock);
		free(buf);
		free(lifc);
		return ((struct lifconf *)NULL);
	}

	(void) close(sock);

	return (lifc);
}

int
Is_ipv6present(void)
{
	int sock;
	struct lifnum lifn;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0)
		return (0);

	lifn.lifn_family = AF_INET6;
	lifn.lifn_flags = 0;
	if (ioctl(sock, SIOCGLIFNUM, (char *)&lifn) < 0) {
		close(sock);
		return (0);
	}
	close(sock);
	if (lifn.lifn_count == 0)
		return (0);
	return (1);
}
