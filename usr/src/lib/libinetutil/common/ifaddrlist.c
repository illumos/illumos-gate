/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

#include <errno.h>
#include <libinetutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sockio.h>

/*
 * See <libinetutil.h> for a description of the programming interface.
 */
int
ifaddrlist(struct ifaddrlist **ipaddrp, int family, uint_t flags, char *errbuf)
{
	struct ifaddrlist	*ifaddrlist = NULL, *al = NULL;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	struct lifconf		lifc;
	struct lifnum		lifn;
	struct lifreq		*lifrp;
	int			i, count, nlifr;
	int			fd;
	const char		*opstr;

	(void) memset(&lifc, 0, sizeof (lifc));
	if (family != AF_INET && family != AF_INET6) {
		(void) strlcpy(errbuf, "invalid address family", ERRBUFSIZE);
		return (-1);
	}

	if ((fd = socket(family, SOCK_DGRAM, 0)) == -1) {
		opstr = "socket";
		goto fail;
	}

	/*
	 * Get the number of network interfaces of type `family'.
	 */
	lifn.lifn_family = family;
	lifn.lifn_flags = flags;
again:
	if (ioctl(fd, SIOCGLIFNUM, &lifn) == -1) {
		opstr = "SIOCGLIFNUM";
		goto fail;
	}

	/*
	 * Pad the interface count to detect when additional interfaces have
	 * been configured between SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	lifn.lifn_count += 4;

	lifc.lifc_flags = flags;
	lifc.lifc_family = family;
	lifc.lifc_len = lifn.lifn_count * sizeof (struct lifreq);
	if ((lifc.lifc_buf = realloc(lifc.lifc_buf, lifc.lifc_len)) == NULL) {
		opstr = "realloc";
		goto fail;
	}

	if (ioctl(fd, SIOCGLIFCONF, &lifc) == -1) {
		opstr = "SIOCGLIFCONF";
		goto fail;
	}

	/*
	 * If every lifr_req slot is taken, then additional interfaces must
	 * have been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
	 * Recalculate to make sure we didn't miss any interfaces.
	 */
	nlifr = lifc.lifc_len / sizeof (struct lifreq);
	if (nlifr >= lifn.lifn_count)
		goto again;

	/*
	 * Allocate the address list to return.
	 */
	if ((ifaddrlist = calloc(nlifr, sizeof (struct ifaddrlist))) == NULL) {
		opstr = "calloc";
		goto fail;
	}

	/*
	 * Populate the address list by querying each underlying interface.
	 * If a query ioctl returns ENXIO, then the interface must have been
	 * removed after the SIOCGLIFCONF completed -- so we just ignore it.
	 */
	al = ifaddrlist;
	count = 0;
	for (lifrp = lifc.lifc_req, i = 0; i < nlifr; i++, lifrp++) {
		(void) strlcpy(al->device, lifrp->lifr_name, LIFNAMSIZ);

		if (ioctl(fd, SIOCGLIFFLAGS, lifrp) == -1) {
			if (errno == ENXIO)
				continue;
			opstr = "SIOCGLIFFLAGS";
			goto fail;
		}
		al->flags = lifrp->lifr_flags;

		if (ioctl(fd, SIOCGLIFINDEX, lifrp) == -1) {
			if (errno == ENXIO)
				continue;
			opstr = "SIOCGLIFINDEX";
			goto fail;
		}
		al->index = lifrp->lifr_index;

		if (ioctl(fd, SIOCGLIFADDR, lifrp) == -1) {
			if (errno == ENXIO)
				continue;
			opstr = "SIOCGLIFADDR";
			goto fail;
		}

		if (family == AF_INET) {
			sin = (struct sockaddr_in *)&lifrp->lifr_addr;
			al->addr.addr = sin->sin_addr;
		} else {
			sin6 = (struct sockaddr_in6 *)&lifrp->lifr_addr;
			al->addr.addr6 = sin6->sin6_addr;
		}
		al++;
		count++;
	}

	(void) close(fd);
	free(lifc.lifc_buf);
	if (count == 0) {
		free(ifaddrlist);
		*ipaddrp = NULL;
		return (0);
	}

	*ipaddrp = ifaddrlist;
	return (count);
fail:
	if (al == NULL) {
		(void) snprintf(errbuf, ERRBUFSIZE, "%s: %s", opstr,
		    strerror(errno));
	} else {
		(void) snprintf(errbuf, ERRBUFSIZE, "%s: %s: %s", opstr,
		    al->device, strerror(errno));
	}
	free(lifc.lifc_buf);
	free(ifaddrlist);
	(void) close(fd);
	return (-1);
}
