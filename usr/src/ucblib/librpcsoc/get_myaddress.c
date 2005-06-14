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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * get_myaddress.c
 *
 * Get client's IP address via ioctl.  This avoids using the NIS.
 * Copyright (C) 1990, Sun Microsystems, Inc.
 */

#include <rpc/types.h>
#include <rpc/pmap_prot.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <malloc.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>

/*
 * don't use gethostbyname, which would invoke NIS
 */
void
get_myaddress(struct sockaddr_in *addr)
{
	int s;
	struct ifconf ifc;
	struct ifreq ifreq, *ifr;
	int len, numifs;
	int ret;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	    syslog(LOG_ERR, "get_myaddress: socket: %m");
	    exit(1);
	}

	do {
		ret = ioctl(s, SIOCGIFNUM, (char *)&numifs);
	} while (ret < 0 && (errno == EINTR || errno == EAGAIN));
	if (ret < 0) {
		syslog(LOG_ERR, "get_myaddress: ioctl: %m");
		exit(1);
	}

	ifc.ifc_len = numifs * sizeof (struct ifreq);
	if ((ifc.ifc_buf = (caddr_t)malloc(ifc.ifc_len)) == NULL) {
		syslog(LOG_ERR, "get_myaddress: malloc: %m");
		exit(1);
	}

	do {
		ret = ioctl(s, SIOCGIFCONF, (char *)&ifc);
	} while (ret < 0 && (errno == EINTR || errno == EAGAIN));
	if (ret < 0) {
		syslog(LOG_ERR,
		    "get_myaddress: ioctl (get interface configuration): %m");
		exit(1);
	}

	/*
	 * set default to loopback in case nothing is found.
	 */
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr->sin_port = htons(PMAPPORT);

	ifr = ifc.ifc_req;
	for (len = ifc.ifc_len; len > 0; len -= sizeof (ifreq), ifr++) {
		ifreq = *ifr;
		do {
			ret = ioctl(s, SIOCGIFFLAGS, (char *)&ifreq);
		} while (ret < 0 && (errno == EINTR || errno == EAGAIN));
		if (ret < 0) {
			syslog(LOG_ERR, "get_myaddress: ioctl: %m");
			exit(1);
		}
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;
		if ((ifreq.ifr_flags & IFF_UP) == 0)
			continue;
		if (ifreq.ifr_flags & IFF_LOOPBACK)
			continue;
		if ((ifreq.ifr_flags & (IFF_MULTICAST | IFF_BROADCAST)) == 0)
			continue;
		*addr = *((struct sockaddr_in *)&ifr->ifr_addr);
		addr->sin_port = htons(PMAPPORT);
		break;
	}
	free(ifc.ifc_buf);
	(void) close(s);
}
