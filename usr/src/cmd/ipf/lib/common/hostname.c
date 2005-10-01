/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ipf.h"

char *hostname(v, ip)
int v;
void *ip;
{
#ifdef  USE_INET6
	static char hostbuf[INET6_ADDRSTRLEN];
#endif
	struct in_addr ipa;

	if (v == 4) {
		ipa.s_addr = *(u_32_t *)ip;
		return inet_ntoa(ipa);
	}
#ifdef  USE_INET6
	(void) inet_ntop(AF_INET6, ip, hostbuf, sizeof(hostbuf));
	return hostbuf;
#else
	return "IPv6";
#endif
}
