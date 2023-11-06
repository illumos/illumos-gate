/*
 * Copyright (C) 2002 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"

#define	PRINTF	(void)printf
#define	FPRINTF	(void)fprintf

void printpooldata(pool, opts)
ip_pool_t *pool;
int opts;
{

	if ((opts & OPT_DEBUG) == 0) {
		if ((pool->ipo_flags & IPOOL_ANON) != 0)
			PRINTF("# 'anonymous' tree %s\n", pool->ipo_name);
		PRINTF("table role = ");
	} else {
		PRINTF("Name: %s", pool->ipo_name);
		if ((pool->ipo_flags & IPOOL_ANON) == IPOOL_ANON)
			PRINTF("(anon)");
		putchar(' ');
		PRINTF("Role: ");
	}

	switch (pool->ipo_unit)
	{
	case IPL_LOGIPF :
		PRINTF("ipf");
		break;
	case IPL_LOGNAT :
		PRINTF("nat");
		break;
	case IPL_LOGSTATE :
		PRINTF("state");
		break;
	case IPL_LOGAUTH :
		PRINTF("auth");
		break;
	case IPL_LOGSYNC :
		PRINTF("sync");
		break;
	case IPL_LOGSCAN :
		PRINTF("scan");
		break;
	case IPL_LOGLOOKUP :
		PRINTF("lookup");
		break;
	case IPL_LOGCOUNT :
		PRINTF("count");
		break;
	default :
		PRINTF("unknown(%d)", pool->ipo_unit);
	}

	if ((opts & OPT_DEBUG) == 0) {
		PRINTF(" type = tree number = %s\n", pool->ipo_name);
	} else {
		putchar(' ');

		PRINTF("\tReferences: %d\tHits: %lu\n", pool->ipo_ref,
			pool->ipo_hits);
		PRINTF("\tNodes Starting at %p\n", pool->ipo_list);
	}
}
