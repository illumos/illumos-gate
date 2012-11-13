/*
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * See the IPFILTER.LICENCE file for details on licensing.
 */

#ifndef	__IPFZONE_H__
#define	__IPFZONE_H__

#include <stdarg.h>
#include <net/if.h>
#include "netinet/ip_fil.h"

void getzonearg(int, char *[], const char *);
void getzoneopt(int, char *[], const char *);
void setzonename(const char *);

extern zoneid_t	zoneid;

#endif /* __IPFZONE_H__ */
