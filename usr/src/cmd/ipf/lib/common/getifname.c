/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ipf.h"
#include "kmem.h"

/*
 * Given a pointer to an interface in the kernel, return a pointer to a
 * string which is the interface name.
 *
 * The same code is used to run in two different environments: in ipfstat
 * and in ipftest.  In ipftest, kmemcpy is wrapper for bcopy but in ipfstat,
 * it is used as an interface to libkvm.
 */
char *getifname(ptr)
struct ifnet *ptr;
{
# ifdef SOLARIS
#  include <sys/mutex.h>
#  include <sys/condvar.h>
# endif
# ifdef __hpux
#  include "compat.h"
# endif
# if defined(NetBSD) && (NetBSD >= 199905) && (NetBSD < 1991011) || \
    defined(__OpenBSD__) || \
    (defined(__FreeBSD__) && (__FreeBSD_version >= 501113))
#else
	char buf[32];
	int len;
# endif
	struct ifnet netif;
#define SOLARIS_PFHOOKS	1
# ifdef SOLARIS_PFHOOKS
	if ((opts & OPT_DONOTHING) == 0)
		return "@";
# endif

	if ((void *)ptr == (void *)-1)
		return "!";
	if (ptr == NULL)
		return "-";

	if (kmemcpy((char *)&netif, (u_long)ptr, sizeof(netif)) == -1)
		return "X";
# if defined(NetBSD) && (NetBSD >= 199905) && (NetBSD < 1991011) || \
    defined(__OpenBSD__) || defined(linux) || \
    (defined(__FreeBSD__) && (__FreeBSD_version >= 501113))
	return strdup(netif.if_xname);
# else
	if (kstrncpy(buf, (u_long)netif.if_name, sizeof(buf)) == -1)
		return "X";
	if (netif.if_unit < 10)
		len = 2;
	else if (netif.if_unit < 1000)
		len = 3;
	else if (netif.if_unit < 10000)
		len = 4;
	else
		len = 5;
	buf[sizeof(buf) - len] = '\0';
	sprintf(buf + strlen(buf), "%d", netif.if_unit % 10000);
	return strdup(buf);
# endif
}
