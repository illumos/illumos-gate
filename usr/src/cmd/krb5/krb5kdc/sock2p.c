#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * kdc/sock2p.c
 *
 * Copyright 2000 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Network code for Kerberos v5 KDC.
 */

#define NEED_SOCKETS
#include "k5-int.h"
#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifndef HAVE_INET_NTOP
char *
inet_ntop (int family, const void *address, char *buf, size_t bufsiz)
{
    char *p;
    switch (family) {
    case AF_INET:
    {
	p = inet_ntoa (*(const struct in_addr *)address);
    try:
	if (strlen (p) >= bufsiz)
	    return 0;
	strcpy (buf, p);
	break;
    }
#ifdef KRB5_USE_INET6
    case AF_INET6:
    {
	char abuf[46];
	const unsigned char *byte = (const unsigned char *)
	    &((const struct in6_addr *)address)->s6_addr;
	sprintf (abuf, "%x:%x:%x:%x:%x:%x:%x:%x",
		 byte[0] * 256 + byte[1],
		 byte[2] * 256 + byte[3],
		 byte[4] * 256 + byte[5],
		 byte[6] * 256 + byte[7],
		 byte[8] * 256 + byte[9],
		 byte[10] * 256 + byte[11],
		 byte[12] * 256 + byte[13],
		 byte[14] * 256 + byte[15]);
	p = abuf;
	goto try;
    }
#endif /* KRB5_USE_INET6 */
    default:
	return 0;
    }
    return buf;
}
#endif

void
sockaddr2p (const struct sockaddr *s, char *buf, size_t bufsiz, int *port_p)
{
    const void *addr;
    int port;
    switch (s->sa_family) {
    case AF_INET:
	addr = &((const struct sockaddr_in *)s)->sin_addr;
	port = ((const struct sockaddr_in *)s)->sin_port;
	break;
#ifdef KRB5_USE_INET6
    case AF_INET6:
	addr = &((const struct sockaddr_in6 *)s)->sin6_addr;
	port = ((const struct sockaddr_in6 *)s)->sin6_port;
	break;
#endif
    default:
	if (bufsiz >= 2)
	    strcpy (buf, "?");
	if (port_p)
	    *port_p = -1;
	return;
    }
    if (inet_ntop (s->sa_family, addr, buf, bufsiz) == 0 && bufsiz >= 2)
	strcpy (buf, "?");
    if (port_p)
	*port_p = port;
}

#endif /* INET */
