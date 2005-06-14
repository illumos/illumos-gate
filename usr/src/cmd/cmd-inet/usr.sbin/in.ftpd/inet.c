/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility functions which help with address and hostname manipulation in a
 * mixed IPv4 / IPv6 environment.
 */

#include "config.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "proto.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/* Converts a hostname into an IP address in presentation form */
char *inet_htop(const char *hostname)
{
#ifdef INET6
    static char abuf[INET6_ADDRSTRLEN];
    struct addrinfo hints, *result;
    char *str = NULL;
    void *addr = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = PF_UNSPEC;

    if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
	if (result->ai_family == AF_INET)
	    addr = ((void *)&((struct sockaddr_in *)result->ai_addr)->sin_addr);
	else if (result->ai_family == AF_INET6)
	    addr = ((void *)&((struct sockaddr_in6 *)result->ai_addr)->sin6_addr);
	if (addr)
	    str = (char *)inet_ntop_native(result->ai_family, addr, abuf,
					   sizeof(abuf));
	freeaddrinfo(result);
	return str;
    }
#else
    struct hostent *hp;
    struct in_addr in;

    if ((hp = gethostbyname(hostname)) != NULL) {
	memcpy(&in, hp->h_addr, sizeof(in));
	return inet_ntoa(in);
    }
#endif
    return NULL;
}

/*
 * Converts a socket structures IP address into presentation form.
 * Note: returns a pointer to a buffer which is overwritten on each call.
 */
char *inet_stop(struct SOCKSTORAGE *ss)
{
#ifdef INET6
    static char abuf[INET6_ADDRSTRLEN];
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

    if (ss->ss_family == AF_INET6)
        return (char *)inet_ntop_native(AF_INET6, &sin6->sin6_addr, abuf, sizeof (abuf));
#endif
    return inet_ntoa(((struct sockaddr_in *)ss)->sin_addr);
}

char *wu_gethostbyname(const char *hostname)
{
#ifdef INET6
    static char hostbuf[MAXHOSTNAMELEN];
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = PF_UNSPEC;

    if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
	strncpy(hostbuf, result->ai_canonname, sizeof(hostbuf));
	hostbuf[sizeof(hostbuf) - 1] = '\0';
	freeaddrinfo(result);
	return hostbuf;
    }
#else
    struct hostent *hp = gethostbyname(hostname);

    if (hp)
	return hp->h_name;
#endif
    return NULL;
}

int wu_gethostbyaddr(struct SOCKSTORAGE *ss, char *hostname, int hostlen)
{
#ifdef INET6
    char hostbuf[NI_MAXHOST];
#else
    struct hostent *hp;
#endif

    if ((ss == NULL) || (hostname == NULL) || (hostlen < 1))
	return 0;

#ifdef INET6
    if (getnameinfo((struct sockaddr *)ss, SOCK_LEN(*ss), hostbuf,
		    sizeof(hostbuf), NULL, 0, NI_NAMEREQD) == 0) {
	strncpy(hostname, hostbuf, hostlen);
	hostname[hostlen - 1] = '\0';
	return 1;
    }
#else
    hp = gethostbyaddr((char *)&ss->sin_addr, sizeof(struct in_addr), AF_INET);
    if (hp) {
	strncpy(hostname, hp->h_name, hostlen);
	hostname[hostlen - 1] = '\0';
	return 1;
    }
#endif
    return 0;
}

/* Compares a socket structures IP address with addr, returning 0 on a match */
int sock_cmp_inaddr(struct SOCKSTORAGE *ss, struct in_addr addr) {
#ifdef INET6
    if (ss->ss_family == AF_INET6) {
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
	    u_char *a = (u_char *)&sin6->sin6_addr;

	    /* compare the IPv4 part of an IPv4-mapped IPv6 address */
	    return memcmp(&addr, a + sizeof(struct in6_addr) - sizeof(struct in_addr), sizeof(struct in_addr));
	}
	return 1;
    }
#endif
    return ((struct sockaddr_in *)ss)->sin_addr.s_addr != addr.s_addr;
}

#ifdef INET6
/* Sets a socket structures IP address to addr */
void sock_set_inaddr(struct SOCKSTORAGE *ss, struct in_addr addr) {
    if (ss->ss_family == AF_INET6) {
	struct in6_addr *in6;

	in6 = &((struct sockaddr_in6 *)ss)->sin6_addr;
	memset(&in6->s6_addr[0], 0, 10);
	memset(&in6->s6_addr[10], 0xff, 2);
	memcpy(&in6->s6_addr[12], &addr, sizeof(struct in_addr));
	return;
    }
    ((struct sockaddr_in *)ss)->sin_addr = addr;
}

/* Compares two socket structure IP addresses, returning 0 if they match */
int sock_cmp_addr(struct SOCKSTORAGE *ss1, struct SOCKSTORAGE *ss2) {
    if (ss1->ss_family == AF_INET6) {
	if (ss2->ss_family == AF_INET6)
	    return memcmp(&((struct sockaddr_in6 *)ss1)->sin6_addr,
			  &((struct sockaddr_in6 *)ss2)->sin6_addr,
			  sizeof(struct in6_addr));
	return sock_cmp_inaddr(ss1, ((struct sockaddr_in *)ss2)->sin_addr);
    }
    return sock_cmp_inaddr(ss2, ((struct sockaddr_in *)ss1)->sin_addr);
}

void sock_set_scope(struct SOCKSTORAGE *dst, struct SOCKSTORAGE *src) {
#ifdef HAVE_SIN6_SCOPE_ID
    struct sockaddr_in6 *src_in6 = (struct sockaddr_in6 *)src;
    struct sockaddr_in6 *dst_in6 = (struct sockaddr_in6 *)dst;

    if (dst->ss_family == AF_INET6) {
	if ((src->ss_family == AF_INET6) &&
	    (memcmp(&src_in6->sin6_addr, &dst_in6->sin6_addr,
		    sizeof(struct in6_addr)) == 0))
	    dst_in6->sin6_scope_id = src_in6->sin6_scope_id;
	else
	    dst_in6->sin6_scope_id = 0;
    }
#endif
}

/*
 * Similar to inet_pton(), str can be an IPv4 or IPv6 address, but an IPv6
 * address is returned in addr.
 */
int inet_pton6(char *str, struct in6_addr *addr)
{
    struct in_addr v4addr;

    /* Try v6 first */
    if (inet_pton(AF_INET6, str, addr) != 1) {
	/* If that fails, try v4 and map it */
	if (inet_pton(AF_INET, str, &v4addr) == 1) {
	    memset(&addr->s6_addr[0], 0, 10);
	    memset(&addr->s6_addr[10], 0xff, 2);
	    memcpy(&addr->s6_addr[12], &v4addr, sizeof(struct in_addr));
	}
	else
	    return 0;
    }
    return 1;
}

/*
 * Similar to inet_ntop(), except when addr is an IPv4-mapped IPv6 address
 * returns a printable IPv4 address (not an IPv4-mapped IPv6 address).
 */
const char *inet_ntop_native(int af, const void *addr, char *dst, size_t size)
{
    const char *result;

    if (af == AF_INET6) {
	if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr))
	    result = inet_ntop(AF_INET, (char *)addr + sizeof(struct in6_addr)
			       - sizeof(struct in_addr), dst, size);
	else
	    result = inet_ntop(AF_INET6, addr, dst, size);
    }
    else
	result = inet_ntop(af, addr, dst, size);
    return result;
}
#endif /* INET6 */
