/*
 * Copyright (C) 2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 */

#include "ipf.h"


void printaddr(v, type, ifname, addr, mask)
int v, type;
char *ifname;
u_32_t *addr, *mask;
{
	char *suffix;

	switch (type)
	{
	case FRI_BROADCAST :
		suffix = "/bcast";
		break;

	case FRI_DYNAMIC :
		printf("%s", ifname);
		printmask(v, mask);
		suffix = NULL;
		break;

	case FRI_NETWORK :
		suffix = "/net";
		break;

	case FRI_NETMASKED :
		suffix = "/netmasked";
		break;

	case FRI_PEERADDR :
		suffix = "/peer";
		break;

	case FRI_LOOKUP :
		suffix = NULL;
		printlookup((i6addr_t *)addr, (i6addr_t *)mask);
		break;

	case FRI_NORMAL :
		printhostmask(v, addr, mask);
		suffix = NULL;
		break;
	default :
		printf("<%d>", type);
		printmask(v, mask);
		suffix = NULL;
		break;
	}

	if (suffix != NULL) {
		printf("%s/%s", ifname, suffix);
	}
}
