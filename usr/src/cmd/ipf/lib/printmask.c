/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: printmask.c,v 1.5 2002/06/15 04:48:33 darrenr Exp $
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"


void	printmask(v, mask)
int v;
u_32_t	*mask;
{
	struct in_addr ipa;
	int ones;

#ifdef  USE_INET6
	if (v == 6)
		printf("/%d", count6bits(mask));
	else
#endif
	if ((ones = count4bits(*mask)) == -1) {
		ipa.s_addr = *mask;
		printf("/%s", inet_ntoa(ipa));
	} else
		printf("/%d", ones);
}
