/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: print_toif.c,v 1.8 2002/01/28 06:50:47 darrenr Exp $
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"


void print_toif(tag, fdp)
char *tag;
frdest_t *fdp;
{
	printf("%s %s", tag, fdp->fd_ifname);
	if (opts & OPT_UNDEF) {
		if (!fdp->fd_ifp)
			printf("(!)");
	}
#ifdef	USE_INET6
	if (use_inet6 && IP6_NOTZERO(&fdp->fd_ip6.in6)) {
		char ipv6addr[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &fdp->fd_ip6, ipv6addr,
			  sizeof(ipv6addr));
		printf(":%s", ipv6addr);
	} else
#endif
		if (fdp->fd_ip.s_addr)
			printf(":%s", inet_ntoa(fdp->fd_ip));
	putchar(' ');
}
