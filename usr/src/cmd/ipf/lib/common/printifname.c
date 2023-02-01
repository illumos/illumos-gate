/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: printifname.c,v 1.2 2002/01/28 06:50:47 darrenr Exp $
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"

void printifname(format, name, ifp)
char *format, *name;
void *ifp;
{
	printf("%s%s", format, name);
	if (opts & OPT_UNDEF) {
		if ((ifp == NULL) && strcmp(name, "-") && strcmp(name, "*")) {
			printf("(!)");
		}
	}
}
