/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ipf.h"

#define	PRINTF	(void)printf
#define	FPRINTF	(void)fprintf

ip_pool_node_t *printpoolnode(np, opts)
ip_pool_node_t *np;
int opts;
{
	if ((opts & OPT_DEBUG) == 0) {
		putchar(' ');
		if (np->ipn_info == 1)
			PRINTF("! ");

#ifdef USE_INET6
		if (np->ipn_addr.adf_family == AF_INET6)
                        printhostmask(6, (u_32_t *)&np->ipn_addr.adf_addr.in6,
                                         (u_32_t *)&np->ipn_mask.adf_addr);
		else
#endif
		{
			printip((u_32_t *)&np->ipn_addr.adf_addr.in4);
			printmask(4, (u_32_t *)&np->ipn_mask.adf_addr);
		}
	} else {
#ifdef USE_INET6
		char addinfo[INET6_ADDRSTRLEN + 1];
#endif
		PRINTF("\t\t");
		if (np->ipn_info == 1)
			PRINTF("! ");

#ifdef USE_INET6
		PRINTF("%s", inet_ntop(np->ipn_addr.adf_family,
				       (void *)&np->ipn_addr.adf_addr.in4,
				       addinfo, INET6_ADDRSTRLEN));
#else
		PRINTF("%s", inet_ntoa(np->ipn_addr.adf_addr.in4));
#endif
#ifdef USE_INET6
		if (np->ipn_addr.adf_family == AF_INET6)
			printmask(6, (u_32_t *)&np->ipn_mask.adf_addr);
		else
#endif
			printmask(4, (u_32_t *)&np->ipn_mask.adf_addr);

		PRINTF("\n\t\tHits %lu\tName %s\n",
			np->ipn_hits, np->ipn_name);
	}
	return np->ipn_next;
}
