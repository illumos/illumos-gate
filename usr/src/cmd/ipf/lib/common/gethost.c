/*
 * Copyright (C) 1993-2005  by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"

int gethost(name, hostp, use_inet6)
char *name;
i6addr_t *hostp;
int use_inet6;
{
	struct addrinfo hints, *ai;
	struct netent *n;
	int error;

	if (!strcmp(name, "test.host.dots")) {
		hostp->in4.s_addr = htonl(0xfedcba98);
		return 0;
	}

	if (!strcmp(name, "<thishost>"))
		name = thishost;

	bzero(&hints, sizeof (hints));
	if (use_inet6 == 0)
		hints.ai_family = AF_INET;
	else
		hints.ai_family = AF_INET6;

	error = getaddrinfo(name, NULL, &hints, &ai);

	if ((error == 0) && (ai != NULL) && (ai->ai_addr != NULL)) {
		switch (ai->ai_family)
		{
			case AF_INET:
				hostp->in4 = ((struct sockaddr_in *)
				    ai->ai_addr)->sin_addr;
				break;
			case AF_INET6:
				hostp->in6 = ((struct sockaddr_in6 *)
				    ai->ai_addr)->sin6_addr;
				break;
			default:
				break;
		}
		freeaddrinfo(ai);
		return 0;
	}

	if (ai != NULL)
		freeaddrinfo(ai);

	if (use_inet6 == 0) {
		n = getnetbyname(name);
		if (n != NULL) {
			hostp->in4.s_addr = htonl(n->n_net);
			return 0;
		}
	}
	return -1;
}
