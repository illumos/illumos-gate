/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "ipf.h"

#define	PRINTF	(void)printf

ip_pool_node_t *printpoolnode(np, opts)
ip_pool_node_t *np;
int opts;
{
	if ((opts & OPT_DEBUG) == 0)
		PRINTF(" %s", np->ipn_info ? "! " : "");
	else
		PRINTF("\tAddress: %s", np->ipn_info ? "! " : "");

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

	if ((opts & OPT_DEBUG) != 0)
#ifdef USE_QUAD_T
		PRINTF("\t\tHits %qu\t\tBytes %qu\t\tName %s\n",
			np->ipn_hits, np->ipn_bytes, np->ipn_name);
#else
		PRINTF("\t\tHits %lu\t\tBytes %lu\t\tName %s\n",
			np->ipn_hits, np->ipn_bytes, np->ipn_name);
#endif
	return np->ipn_next;
}
