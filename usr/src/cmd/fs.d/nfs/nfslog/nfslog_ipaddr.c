/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1991, 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/*
 * Note: If making changes to this file, check also the file
 *	 cmd/cmd-inet/usr.sbin/snoop/snoop_ipaddr.c
 *	 as it has the same functions there.
 */
static jmp_buf nisjmp;

#define	MAXHASH 1024  /* must be a power of 2 */

struct hostdata {
	struct hostdata *h_next;
	char		*h_hostname;
	int		h_pktsout;
	int		h_pktsin;
};

struct hostdata4 {
	struct hostdata4	*h4_next;
	char		*h4_hostname;
	int		h4_pktsout;
	int		h4_pktsin;
	struct in_addr	h4_addr;
};

struct hostdata6 {
	struct hostdata6	*h6_next;
	char		*h6_hostname;
	int		h6_pktsout;
	int		h6_pktsin;
	struct in6_addr	h6_addr;
};

static struct hostdata *addhost(int, void *, char *);

static struct hostdata4 *h_table4[MAXHASH];
static struct hostdata6 *h_table6[MAXHASH];

#define	iphash(e)  ((e) & (MAXHASH-1))

/* ARGSUSED */
static void
wakeup(int n)
{
	longjmp(nisjmp, 1);
}

extern char *inet_ntoa();

static struct hostdata *
iplookup(ipaddr)
	struct in_addr *ipaddr;
{
	register struct hostdata4 *h;
	struct hostent *hp = NULL;
	struct netent *np;
	int error_num;

	for (h = h_table4[iphash(ipaddr->s_addr)]; h; h = h->h4_next) {
		if (h->h4_addr.s_addr == ipaddr->s_addr)
			return ((struct hostdata *)h);
	}

	/* not found.  Put it in */

	if (ipaddr->s_addr == htonl(INADDR_BROADCAST))
		return (addhost(AF_INET, ipaddr, "BROADCAST"));
	if (ipaddr->s_addr == htonl(INADDR_ANY))
		return (addhost(AF_INET, ipaddr, "OLD-BROADCAST"));

	/*
	 * Set an alarm here so we don't get held up by
	 * an unresponsive name server.
	 * Give it 3 sec to do its work.
	 */
	if (setjmp(nisjmp) == 0) {
		(void) signal(SIGALRM, wakeup);
		(void) alarm(3);
		hp = getipnodebyaddr((char *)ipaddr, sizeof (struct in_addr),
		    AF_INET, &error_num);
		if (hp == NULL && inet_lnaof(*ipaddr) == 0) {
			np = getnetbyaddr(inet_netof(*ipaddr), AF_INET);
			if (np)
				return (addhost(AF_INET, ipaddr, np->n_name));
		}
		(void) alarm(0);
	} else {
		hp = NULL;
	}

	return (addhost(AF_INET, ipaddr, hp ? hp->h_name : inet_ntoa(*ipaddr)));
}

static struct hostdata *
ip6lookup(ip6addr)
	struct in6_addr *ip6addr;
{
	struct hostdata6 *h;
	struct hostent *hp = NULL;
	int error_num;
	char addrstr[INET6_ADDRSTRLEN];
	char *addname;
	struct hostdata *retval;

	for (h = h_table6[iphash(((uint32_t *)ip6addr)[3])]; h;
	    h = h->h6_next) {
		if (IN6_ARE_ADDR_EQUAL(&h->h6_addr, ip6addr))
			return ((struct hostdata *)h);
	}

	/* not in the hash table, put it in */
	if (IN6_IS_ADDR_UNSPECIFIED(ip6addr))
		return (addhost(AF_INET6, ip6addr, "UNSPECIFIED"));

	/*
	 * Set an alarm here so we don't get held up by
	 * an unresponsive name server.
	 * Give it 3 sec to do its work.
	 */
	if (setjmp(nisjmp) == 0) {
		(void) signal(SIGALRM, wakeup);
		(void) alarm(3);
		hp = getipnodebyaddr(ip6addr, sizeof (struct in6_addr),
		    AF_INET6, &error_num);
		(void) alarm(0);
	} else {
		hp = NULL;
	}

	if (hp != NULL)
		addname = hp->h_name;
	else {
		(void) inet_ntop(AF_INET6, ip6addr, addrstr, INET6_ADDRSTRLEN);
		addname = addrstr;
	}

	retval = addhost(AF_INET6, ip6addr, addname);
	freehostent(hp);
	return (retval);
}

static struct hostdata *
addhost(family, ipaddr, name)
	int family;
	void *ipaddr;
	char *name;
{
	register struct hostdata **hp, *n;
	int hashval;

	switch (family) {
	case AF_INET:
		n = (struct hostdata *)malloc(sizeof (struct hostdata4));
		if (n == NULL)
			goto alloc_failed;

		(void) memset(n, 0, sizeof (struct hostdata4));
		n->h_hostname = strdup(name);
		if (n->h_hostname == NULL)
			goto alloc_failed;

		((struct hostdata4 *)n)->h4_addr = *(struct in_addr *)ipaddr;
		hashval = ((struct in_addr *)ipaddr)->s_addr;
		hp = (struct hostdata **)&h_table4[iphash(hashval)];
		break;
	case AF_INET6:
		n = (struct hostdata *)malloc(sizeof (struct hostdata6));
		if (n == NULL)
			goto alloc_failed;

		(void) memset(n, 0, sizeof (struct hostdata6));
		n->h_hostname = strdup(name);
		if (n->h_hostname == NULL)
			goto alloc_failed;

		(void) memcpy(&((struct hostdata6 *)n)->h6_addr, ipaddr,
		    sizeof (struct in6_addr));
		hashval = ((int *)ipaddr)[3];
		hp = (struct hostdata **)&h_table6[iphash(hashval)];
		break;
	default:
		(void) fprintf(stderr,
			"nfslog: addhost ERROR: Unknown address family: %d",
			family);
		return (NULL);
	}

	n->h_next = *hp;
	*hp = n;

	return (n);

alloc_failed:
	(void) fprintf(stderr, "addhost: no mem\n");
	if (n != NULL)
		free(n);
	return (NULL);
}

char *
addrtoname(void *sockp)
{
	struct hostdata *hostp;
	int family = ((struct sockaddr_in *)sockp)->sin_family;

	switch (family) {
	case AF_INET:
		hostp = iplookup(&((struct sockaddr_in *)sockp)->sin_addr);
		break;
	case AF_INET6:
		hostp = ip6lookup(&((struct sockaddr_in6 *)sockp)->sin6_addr);
		break;
	default:
		(void) fprintf(stderr, "nfslog: ERROR: unknown address " \
		    "family: %d\n", family);
		hostp = NULL;
	}
	return ((hostp != NULL) ? hostp->h_hostname : NULL);
}
