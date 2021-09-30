/*
 * Copyright (C) 2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 */

#include "ipf.h"


void printlookup(addr, mask)
	i6addr_t *addr, *mask;
{
	switch (addr->iplookuptype)
	{
	case IPLT_POOL :
		printf("pool/");
		break;
	case IPLT_HASH :
		printf("hash/");
		break;
	default :
		printf("lookup(%x)=", addr->iplookuptype);
		break;
	}

	printf("%u", addr->iplookupnum);
	if (opts & OPT_UNDEF) {
		if (mask->iplookupptr == NULL)
			printf("(!)");
	}
}
