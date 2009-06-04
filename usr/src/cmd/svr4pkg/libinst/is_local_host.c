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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>

static int	is_local_if(struct hostent *hp);

/*
 * Given a host name, check to see if it points to the local host.
 * If it does, return 1, else return 0.
 *
 * The strategy is this:  translate the host name argument to a list of
 * addresses.  Then compare each of those addresses to the addresses of
 * network interfaces on this host.
 */
int
is_local_host(char *host)
{
	struct hostent	*hp;
	int		err;
	int		flags = AI_DEFAULT;

	if (hp = getipnodebyname((const char *) host, AF_INET, flags, &err))
		if (is_local_if(hp))
			return (1);
	if (hp = getipnodebyname((const char *) host, AF_INET6, flags, &err))
		if (is_local_if(hp))
			return (1);

	return (0);
}

static int
is_local_if(struct hostent *hp)
{
	char		*buf;
	struct lifconf	lifc;
	struct lifnum	lifn;
	struct lifreq	lifr;
	struct lifreq	*lifrp;
	int		bufsiz;
	int		nha;
	int		nif;
	int		s;

	if ((s = socket(hp->h_addrtype, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return (0);
	}

	lifn.lifn_family = hp->h_addrtype;
	lifn.lifn_flags = LIFC_EXTERNAL_SOURCE;
	if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) == -1) {
		perror("SIOCGLIFNUM");
		(void) close(s);
		return (0);
	}
	bufsiz = lifn.lifn_count * sizeof (struct lifreq);

	if ((buf = malloc(bufsiz)) == NULL) {
		perror("malloc");
		(void) close(s);
		return (0);
	}

	lifc.lifc_family = hp->h_addrtype;
	lifc.lifc_flags = LIFC_EXTERNAL_SOURCE;
	lifc.lifc_len = bufsiz;
	lifc.lifc_buf = buf;
	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) == -1) {
		perror("SIOCGLIFCONF");
		(void) close(s);
		free(buf);
		return (0);
	}

#define	lifraddrp(lifrp) ((lifrp->lifr_addr.ss_family == AF_INET6) ? \
	(void *) &((struct sockaddr_in6 *)&lifrp->lifr_addr)->sin6_addr : \
	(void *) &((struct sockaddr_in *)&lifrp->lifr_addr)->sin_addr)

	for (lifrp = lifc.lifc_req,
	    nif = lifc.lifc_len / sizeof (struct lifreq);
	    nif > 0; nif--, lifrp++) {
		if (lifrp->lifr_addr.ss_family != hp->h_addrtype) {
			continue;
		}
		(void) memset(&lifr, 0, sizeof (lifr));
		(void) strncpy(lifr.lifr_name, lifrp->lifr_name,
		    sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) == -1) {
			perror("SIOCGLIFFLAGS");
			(void) close(s);
			free(buf);
			return (0);
		}

		for (nha = 0; hp->h_addr_list[nha]; nha++) {
			if (memcmp(hp->h_addr_list[nha], lifraddrp(lifrp),
			    hp->h_length) == 0) {
				(void) close(s);
				free(buf);
				return (1);
			}
		}
	}

#undef	lifraddrp

	(void) close(s);
	free(buf);
	return (0);
}
