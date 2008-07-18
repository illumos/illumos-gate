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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: misc.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <papi.h>
#include <uri.h>
#include <config-site.h>

/*
 * The implementations of strlcpy() and strlcat() have been taken directly
 * from OpenSolaris.  The contents of this file originated from
 *     usr/src/lib/libc/port/gen/strlcpy.c
 *     usr/src/lib/libc/port/gen/strcat.c
 */

#ifndef HAVE_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t len)
{
	size_t slen = strlen(src);
	size_t copied;

	if (len == 0)
		return (slen);

	if (slen >= len)
		copied = len - 1;
	else
		copied = slen;
	(void) memcpy(dst, src, copied);
	dst[copied] = '\0';
	return (slen);
}
#endif

#ifndef HAVE_STRLCAT
size_t
strlcat(char *dst, const char *src, size_t dstsize)
{
	char *df = dst;
	size_t left = dstsize;
	size_t l1;
	size_t l2 = strlen(src);
	size_t copied;

	while (left-- != 0 && *df != '\0')
		df++;
	l1 = df - dst;
	if (dstsize == l1)
		return (l1 + l2);

	copied = l1 + l2 >= dstsize ? dstsize - l1 - 1 : l2;
	(void) memcpy(dst + l1, src, copied);
	dst[l1+copied] = '\0';
	return (l1 + l2);
}
#endif

#if defined(__sun) && defined(__SVR4)
#include <sys/systeminfo.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static struct in6_addr **
local_interfaces()
{
	struct in6_addr **result = NULL;
	int s;
	struct lifnum n;
	struct lifconf c;
	struct lifreq *r;
	int count;

	/* we need a socket to get the interfaces */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (0);

	/* get the number of interfaces */
	memset(&n, 0, sizeof (n));
	n.lifn_family = AF_UNSPEC;
	if (ioctl(s, SIOCGLIFNUM, (char *)&n) < 0) {
		close(s);
		return (0);	/* no interfaces */
	}

	/* get the interface(s) configuration */
	memset(&c, 0, sizeof (c));
	c.lifc_family = AF_UNSPEC;
	c.lifc_buf = calloc(n.lifn_count, sizeof (struct lifreq));
	c.lifc_len = (n.lifn_count * sizeof (struct lifreq));
	if (ioctl(s, SIOCGLIFCONF, (char *)&c) < 0) {
		free(c.lifc_buf);
		close(s);
		return (0);	/* can't get interface(s) configuration */
	}
	close(s);

	r = c.lifc_req;
	for (count = c.lifc_len / sizeof (struct lifreq);
	    count > 0; count--, r++) {
		struct in6_addr v6[1], *addr = NULL;

		switch (r->lifr_addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *s =
			    (struct sockaddr_in *)&r->lifr_addr;
			IN6_INADDR_TO_V4MAPPED(&s->sin_addr, v6);
			addr = v6;
			}
			break;
		case AF_INET6: {
			struct sockaddr_in6 *s =
			    (struct sockaddr_in6 *)&r->lifr_addr;
			addr = &s->sin6_addr;
			}
			break;
		}

		if (addr != NULL) {
			struct in6_addr *a = malloc(sizeof (*a));

			memcpy(a, addr, sizeof (*a));
			list_append(&result, a);
		}
	}
	free(c.lifc_buf);

	return (result);
}

static int
match_interfaces(char *host)
{
	struct in6_addr **lif = local_interfaces();
	struct hostent *hp;
	int rc = 0;
	int errnum;

	/* are there any local interfaces */
	if (lif == NULL)
		return (0);

	/* cycle through the host db addresses */
	hp = getipnodebyname(host, AF_INET6, AI_ALL|AI_V4MAPPED, &errnum);
	if (hp != NULL) {
		struct in6_addr **tmp = (struct in6_addr **)hp->h_addr_list;
		int i;

		for (i = 0; ((rc == 0) && (tmp[i] != NULL)); i++) {
			int j;

			for (j = 0; ((rc == 0) && (lif[j] != NULL)); j++)
				if (memcmp(tmp[i], lif[j],
				    sizeof (struct in6_addr)) == 0)
					rc = 1;
		}
	}
	free(lif);

	return (rc);
}
#endif

int
is_localhost(char *host)
{
	char hostname[BUFSIZ];

	/* is it "localhost" */
	if (strncasecmp(host, "localhost", 10) == 0)
		return (1);

	/* is it the {nodename} */
	sysinfo(SI_HOSTNAME, hostname, sizeof (hostname));
	if (strncasecmp(host, hostname, strlen(hostname)) == 0)
		return (1);

#if defined(__sun) && defined(__SVR4)
	/* does it match one of the host's configured interfaces */
	if (match_interfaces(host) != 0)
		return (1);
#endif
	return (0);
}
