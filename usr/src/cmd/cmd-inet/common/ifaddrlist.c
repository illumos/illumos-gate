/*
 * Copyright 1997,2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) $Header: ifaddrlist.c,v 1.2 97/04/22 13:31:05 leres Exp $ (LBL)
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>

#include "ifaddrlist.h"

/*
 * Construct the interface list with given address family.
 * If it fails, returns -1 and an error message in *errbuf;
 * otherwise, returns number of interfaces, and the interface list in *ipaddrp.
 */
int
ifaddrlist(struct ifaddrlist **ipaddrp, int family, char *errbuf)
{
	int fd;
	struct lifreq *lifrp, *lifend;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct ifaddrlist *al;
	struct lifconf lifc;
	struct lifreq *ibuf, lifr;
	char device[LIFNAMSIZ + 1];
	struct ifaddrlist *ifaddrlist;
	struct lifnum lifn;
	int lifc_flags = 0;
	int count;

	if (family != AF_INET && family != AF_INET6) {
		(void) sprintf(errbuf, "invalid address family");
		return (-1);
	}

	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0) {
		(void) snprintf(errbuf, ERRBUFSIZE, "socket: %s",
		    strerror(errno));
		return (-1);
	}

	/* determine the number of interfaces */
	lifn.lifn_family = family;
	lifn.lifn_flags = lifc_flags;
	if (ioctl(fd, SIOCGLIFNUM, &lifn) < 0) {
		(void) snprintf(errbuf, ERRBUFSIZE, "SIOCGLIFNUM: %s",
		    strerror(errno));
		(void) close(fd);
		return (-1);
	}

	/* allocate memory for the determined number of interfaces */
	ifaddrlist = calloc((size_t)lifn.lifn_count,
	    (size_t)sizeof (struct ifaddrlist));
	if (ifaddrlist == NULL) {
		(void) snprintf(errbuf, ERRBUFSIZE, "calloc: %s",
		    strerror(errno));
		(void) close(fd);
		return (-1);
	}

	ibuf = calloc((size_t)lifn.lifn_count, (size_t)sizeof (struct lifreq));
	if (ibuf == NULL) {
		(void) snprintf(errbuf, ERRBUFSIZE, "calloc: %s",
		    strerror(errno));
		free(ifaddrlist);
		(void) close(fd);
		return (-1);
	}

	/* pull out the interface list from the kernel */
	lifc.lifc_family = family;
	lifc.lifc_len = (int)(lifn.lifn_count * sizeof (struct lifreq));
	lifc.lifc_buf = (caddr_t)ibuf;
	lifc.lifc_flags = lifc_flags;

	if (ioctl(fd, SIOCGLIFCONF, (char *)&lifc) < 0 ||
	    lifc.lifc_len < sizeof (struct lifreq)) {
		(void) snprintf(errbuf, ERRBUFSIZE, "SIOCGLIFCONF: %s",
		    strerror(errno));
		free(ifaddrlist);
		free(ibuf);
		(void) close(fd);
		return (-1);
	}

	lifrp = ibuf;
	/* LINTED */
	lifend = (struct lifreq *)((char *)ibuf + lifc.lifc_len);

	al = ifaddrlist;
	count = 0;

	/* let's populate the interface entries in the ifaddrlist */
	for (; lifrp < lifend; lifrp++) {
		/*
		 * Need a template to preserve address info that is
		 * used below to locate the next entry.  (Otherwise,
		 * SIOCGLIFFLAGS stomps over it because the requests
		 * are returned in a union.)
		 */
		(void) strlcpy(lifr.lifr_name, lifrp->lifr_name,
		    sizeof (lifr.lifr_name));
		if (ioctl(fd, SIOCGLIFFLAGS, (char *)&lifr) < 0) {
			if (errno == ENXIO) {
				continue;
			}
			(void) snprintf(errbuf, ERRBUFSIZE,
			    "SIOCGLIFFLAGS: %.*s: %s",
			    (int)sizeof (lifr.lifr_name), lifr.lifr_name,
			    strerror(errno));
			free(ifaddrlist);
			free(ibuf);
			(void) close(fd);
			return (-1);
		}

		al->flags = lifr.lifr_flags;

		/* get the interface address */
		(void) strncpy(device, lifr.lifr_name, sizeof (device));
		device[sizeof (device) - 1] = '\0';
		if (ioctl(fd, SIOCGLIFADDR, (char *)&lifr) < 0) {
			(void) snprintf(errbuf, ERRBUFSIZE,
			    "SIOCGLIFADDR: %s: %s", device, strerror(errno));
			free(ifaddrlist);
			free(ibuf);
			(void) close(fd);
			return (-1);
		}

		if (family == AF_INET) {
			sin = (struct sockaddr_in *)&lifr.lifr_addr;
			al->addr.addr = sin->sin_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
			al->addr.addr6 = sin6->sin6_addr;
		}

		(void) strlcpy(al->device, device, sizeof (device));

		/* get the interface index */
		if (ioctl(fd, SIOCGLIFINDEX, (char *)&lifr) < 0) {
			(void) snprintf(errbuf, ERRBUFSIZE,
			    "SIOCGLIFADDR: %s: %s", device, strerror(errno));
			free(ifaddrlist);
			free(ibuf);
			(void) close(fd);
			return (-1);
		}

		al->index = lifr.lifr_index;

		++al;
		++count;
	}

	free(ibuf);
	(void) close(fd);

	*ipaddrp = ifaddrlist;
	return (count);
}
