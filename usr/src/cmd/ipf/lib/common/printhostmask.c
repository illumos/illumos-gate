/*
 * Copyright (C) 2000-2005 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: printhostmask.c,v 1.8 2002/04/11 15:01:19 darrenr Exp $
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"


void	printhostmask(v, addr, mask)
int	v;
u_32_t	*addr, *mask;
{
#ifdef  USE_INET6
	char ipbuf[INET6_ADDRSTRLEN];
#else
	struct in_addr ipa;
#endif

	if ((v == 4) && (!*addr) && (!*mask))
		printf("any");
	else {
#ifdef  USE_INET6
		void *ptr = addr;
		int af;

		if (v == 4)
			af = AF_INET;
		else if (v == 6)
			af = AF_INET6;
		else
			af = 0;
		printf("%s", inet_ntop(af, ptr, ipbuf, sizeof(ipbuf)));
#else
		ipa.s_addr = *addr;
		printf("%s", inet_ntoa(ipa));
#endif
		if (mask != NULL)
			printmask(v, mask);
	}
}
