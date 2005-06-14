/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: hostnum.c,v 1.8 2002/01/28 06:50:46 darrenr Exp $
 */

#include <ctype.h>

#include "ipf.h"


/*
 * returns an ip address as a long var as a result of either a DNS lookup or
 * straight inet_addr() call
 */
int	hostnum(ipa, host, linenum, ifname)
u_32_t	*ipa;
char	*host;
int     linenum;
char	*ifname;
{
	struct	hostent	*hp;
	struct	netent	*np;
	struct	in_addr	ip;

	if (!strcasecmp("any", host) ||
	    (ifname && *ifname && !strcasecmp(ifname, host)))
		return 0;
#ifdef	USE_INET6
	if (use_inet6) {
		if (inet_pton(AF_INET6, host, ipa) == 1)
			return 0;
		else
			return -1;
	}
#endif
	if (isdigit(*host) && inet_aton(host, &ip)) {
		*ipa = ip.s_addr;
		return 0;
	}

	if (!strcasecmp("<thishost>", host))
		host = thishost;

	if (!(hp = gethostbyname(host))) {
		if (!(np = getnetbyname(host))) {
			fprintf(stderr, "%d: can't resolve hostname: %s\n",
				linenum, host);
			return -1;
		}
		*ipa = htonl(np->n_net);
		return 0;
	}
	*ipa = *(u_32_t *)hp->h_addr;
	return 0;
}
