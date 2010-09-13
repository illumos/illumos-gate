/*
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

 /*
  * Misc routines that are used by tcpd and by tcpdchk.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsic[] = "@(#) misc.c 1.2 96/02/11 17:01:29";
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>

#include "tcpd.h"

extern char *fgets();

#ifndef	INADDR_NONE
#define	INADDR_NONE	(-1)		/* XXX should be 0xffffffff */
#endif

/* xgets - fgets() with backslash-newline stripping */

char   *xgets(ptr, len, fp)
char   *ptr;
int     len;
FILE   *fp;
{
    int     got;
    char   *start = ptr;

    while (fgets(ptr, len, fp)) {
	got = strlen(ptr);
	if (got >= 1 && ptr[got - 1] == '\n') {
	    tcpd_context.line++;
	    if (got >= 2 && ptr[got - 2] == '\\') {
		got -= 2;
	    } else {
		return (start);
	    }
	}
	ptr += got;
	len -= got;
	ptr[0] = 0;
    }
    return (ptr > start ? start : 0);
}

/* split_at - break string at delimiter or return NULL */

char   *split_at(string, delimiter)
char   *string;
int     delimiter;
{
    char   *cp;

    if ((cp = strchr(string, delimiter)) != 0)
	*cp++ = 0;
    return (cp);
}

/* dot_quad_addr - convert dotted quad to internal form */

unsigned long dot_quad_addr(str)
char   *str;
{
    int     in_run = 0;
    int     runs = 0;
    char   *cp = str;

    /* Count the number of runs of non-dot characters. */

    while (*cp) {
	if (*cp == '.') {
	    in_run = 0;
	} else if (in_run == 0) {
	    in_run = 1;
	    runs++;
	}
	cp++;
    }
    return (runs == 4 ? inet_addr(str) : INADDR_NONE);
}

/* numeric_addr - convert textual IP address to binary form */

int numeric_addr(str, addr, af, len)
char *str;
union gen_addr *addr;
int *af;
int *len;
{
    union gen_addr t;

    if (addr == NULL)
	addr = &t;
#ifdef HAVE_IPV6
    if (strchr(str,':')) {
	if (af) *af = AF_INET6;
	if (len) *len = sizeof(struct in6_addr);
	if (inet_pton(AF_INET6, str, (void*) addr) == 1)
	    return 0;
	return -1;
    }
#endif
    if (af) *af = AF_INET;
    if (len) *len = sizeof(struct in_addr);
    addr->ga_in.s_addr = dot_quad_addr(str);
    return addr->ga_in.s_addr == INADDR_NONE ? -1 : 0;
}

/* For none RFC 2553 compliant systems */
#ifdef USE_GETHOSTBYNAME2
#define getipnodebyname(h,af,flags,err)	gethostbyname2(h,af)
#define freehostent(x)			x = 0
#endif

/* tcpd_gethostbyname - an IP family neutral gethostbyname */

struct hostent *tcpd_gethostbyname(host, af)
char *host;
int af;
{
#ifdef HAVE_IPV6
    struct hostent *hp;
    static struct hostent *hs;		/* freehostent() on next call */
    int err;

    if (af == AF_INET6) {		/* must be AF_INET6 */
	if (hs)
	    freehostent(hs);
	return (hs = getipnodebyname(host, AF_INET6, 0, &err));
    }
    hp = gethostbyname(host);
    if (hp != NULL || af == AF_INET) { 	/* found or must be AF_INET */
	return hp;
    } else {				/* Try INET6 */
	if (hs)
	    freehostent(hs);
	return (hs = getipnodebyname(host, AF_INET6, 0, &err));
    }
#else
    return gethostbyname(host);
#endif
}

#ifdef HAVE_IPV6
/*
 * When using IPv6 addresses, we'll be seeing lots of ":"s;
 * we require the addresses to be specified as [address].
 * An IPv6 address can be specified in 3 ways:
 *
 * x:x:x:x:x:x:x:x		(fully specified)
 * x::x:x:x:x			(zeroes squashed)
 * ::FFFF:1.2.3.4		(IPv4 mapped)
 *
 * These need to be skipped to get at the ":" delimeters.
 *
 * We also allow a '/prefix' specifier.
 */
char *skip_ipv6_addrs(str)
char *str;
{
    char *obr, *cbr, *colon;
    char *p = str;
    char *q;

    while (1) {
	if ((colon = strchr(p, ':')) == NULL)
	    return p;
	if ((obr = strchr(p, '[')) == NULL || obr > colon)
	    return p;
	if ((cbr = strchr(obr, ']')) == NULL)
	    return p;

	for (q = obr + 1; q < cbr; q++) {
	    /*
	     * Quick and dirty parse, cheaper than inet_pton
	     * Could count colons and dots (must be 0 or 3 dots, no
	     * colons after dots seens, only one double :, etc, etc)
	     */
	    if (*q != ':' && *q != '.' && *q != '/' && !isxdigit(*q & 0xff))
		return p;
	}
	p = cbr + 1;
    }
}
#endif /* HAVE_IPV6 */
