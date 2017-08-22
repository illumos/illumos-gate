/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "snoop.h"

static sigjmp_buf nisjmp;
static hrtime_t snoop_lastwarn;		/* Last time NS warning fired */
static unsigned snoop_warninter = 60;	/* Time in seconds between warnings */

#define	MAXHASH 1024  /* must be a power of 2 */

#define	SEPARATORS " \t\n"

struct hostdata {
	struct hostdata	*h_next;
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

static struct hostdata *addhost(int, const void *, const char *, char **);

static struct hostdata4 *h_table4[MAXHASH];
static struct hostdata6 *h_table6[MAXHASH];

#define	iphash(e)  ((e) & (MAXHASH-1))

/* ARGSUSED */
static void
wakeup(int n)
{
	siglongjmp(nisjmp, 1);
}

extern char *inet_ntoa();

static void
snoop_nswarn(void)
{
	hrtime_t now = gethrtime();

	if (now - snoop_lastwarn >= snoop_warninter * NANOSEC) {
		snoop_lastwarn = now;
		(void) fprintf(stderr, "snoop: warning: packets captured, but "
		    "name service lookups are timing out. Use snoop -r to "
		    "disable name service lookups\n");
	}
}

static struct hostdata *
iplookup(struct in_addr ipaddr)
{
	register struct hostdata4 *h;
	struct hostent *hp = NULL;
	struct netent *np;
	int error_num;
	struct hostdata *retval;

	for (h = h_table4[iphash(ipaddr.s_addr)]; h; h = h->h4_next) {
		if (h->h4_addr.s_addr == ipaddr.s_addr)
			return ((struct hostdata *)h);
	}

	/* not found.  Put it in */

	if (ipaddr.s_addr == htonl(INADDR_BROADCAST))
		return (addhost(AF_INET, &ipaddr, "BROADCAST", NULL));
	if (ipaddr.s_addr == htonl(INADDR_ANY))
		return (addhost(AF_INET, &ipaddr, "OLD-BROADCAST", NULL));

	/*
	 * Set an alarm here so we don't get held up by
	 * an unresponsive name server.
	 * Give it 3 sec to do its work.
	 */
	if (!rflg) {
		if (sigsetjmp(nisjmp, 1) == 0) {
			(void) snoop_alarm(3, wakeup);
			hp = getipnodebyaddr((char *)&ipaddr, sizeof (int),
			    AF_INET, &error_num);
			if (hp == NULL && inet_lnaof(ipaddr) == 0) {
				np = getnetbyaddr(inet_netof(ipaddr), AF_INET);
				if (np)
					return (addhost(AF_INET, &ipaddr,
					    np->n_name, np->n_aliases));
			}
			(void) snoop_alarm(0, wakeup);
		} else {
			snoop_nswarn();
		}
	}

	retval = addhost(AF_INET, &ipaddr,
	    hp ? hp->h_name : inet_ntoa(ipaddr),
	    hp ? hp->h_aliases : NULL);
	if (hp != NULL)
		freehostent(hp);
	return (retval);
}

static struct hostdata *
ip6lookup(const struct in6_addr *ip6addr)
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
		return (addhost(AF_INET6, ip6addr, "UNSPECIFIED", NULL));

	/*
	 * Set an alarm here so we don't get held up by
	 * an unresponsive name server.
	 * Give it 3 sec to do its work.
	 */
	if (!rflg) {
		if (sigsetjmp(nisjmp, 1) == 0) {
			(void) snoop_alarm(3, wakeup);
			hp = getipnodebyaddr(ip6addr, sizeof (struct in6_addr),
			    AF_INET6, &error_num);
			(void) snoop_alarm(0, wakeup);
		} else {
			snoop_nswarn();
		}
	} else {
		hp = NULL;
	}

	if (hp != NULL)
		addname = hp->h_name;
	else {
		(void) inet_ntop(AF_INET6, ip6addr, addrstr, INET6_ADDRSTRLEN);
		addname = addrstr;
	}

	retval = addhost(AF_INET6, ip6addr, addname, hp ? hp->h_aliases : NULL);
	if (hp != NULL)
		freehostent(hp);
	return (retval);
}

static struct hostdata *
addhost(int family, const void *ipaddr, const char *name, char **aliases)
{
	struct hostdata **hp, *n = NULL;
	extern FILE *namefile;
	int hashval;
	static char aname[128];
	char *np;
	static struct hostdata h;
	int ind;

	switch (family) {
	case AF_INET:
		n = (struct hostdata *)malloc(sizeof (struct hostdata4));
		if (n == NULL)
			goto alloc_failed;

		memset(n, 0, sizeof (struct hostdata4));
		n->h_hostname = strdup(name);
		if (n->h_hostname == NULL)
			goto alloc_failed;

		((struct hostdata4 *)n)->h4_addr =
		    *(const struct in_addr *)ipaddr;
		hashval = ((struct in_addr *)ipaddr)->s_addr;
		hp = (struct hostdata **)&h_table4[iphash(hashval)];
		break;
	case AF_INET6:
		n = (struct hostdata *)malloc(sizeof (struct hostdata6));
		if (n == NULL)
			goto alloc_failed;

		memset(n, 0, sizeof (struct hostdata6));
		n->h_hostname = strdup(name);
		if (n->h_hostname == NULL)
			goto alloc_failed;

		memcpy(&((struct hostdata6 *)n)->h6_addr, ipaddr,
		    sizeof (struct in6_addr));
		hashval = ((const int *)ipaddr)[3];
		hp = (struct hostdata **)&h_table6[iphash(hashval)];
		break;
	default:
		fprintf(stderr, "snoop: ERROR: Unknown address family: %d",
		    family);
		exit(1);
	}

	n->h_next = *hp;
	*hp = n;

	if (namefile != NULL) {
		if (family == AF_INET) {
			np = inet_ntoa(*(const struct in_addr *)ipaddr);
			if (np) {
				(void) fprintf(namefile, "%s\t%s", np, name);
				if (aliases) {
					for (ind = 0;
					    aliases[ind] != NULL;
					    ind++) {
						(void) fprintf(namefile, " %s",
						    aliases[ind]);
					}
				}
				(void) fprintf(namefile, "\n");
			}
		} else if (family == AF_INET6) {
			np = (char *)inet_ntop(AF_INET6, (void *)ipaddr, aname,
			    sizeof (aname));
			if (np) {
				(void) fprintf(namefile, "%s\t%s", np, name);
				if (aliases) {
					for (ind = 0;
					    aliases[ind] != NULL;
					    ind++) {
						(void) fprintf(namefile, " %s",
						    aliases[ind]);
					}
				}
				(void) fprintf(namefile, "\n");
			}
		} else {
			(void) fprintf(stderr, "addhost: unknown family %d\n",
			    family);
		}
	}
	return (n);

alloc_failed:
	if (n)
		free(n);
	(void) fprintf(stderr, "addhost: no mem\n");

	aname[0] = '\0';
	memset(&h, 0, sizeof (struct hostdata));
	h.h_hostname = aname;
	return (&h);
}

char *
addrtoname(int family, const void *ipaddr)
{
	switch (family) {
	case AF_INET:
		return (iplookup(*(const struct in_addr *)ipaddr)->h_hostname);
	case AF_INET6:
		return (ip6lookup((const struct in6_addr *)ipaddr)->h_hostname);
	}
	(void) fprintf(stderr, "snoop: ERROR: unknown address family: %d\n",
	    family);
	exit(1);
	/* NOTREACHED */
}

void
load_names(char *fname)
{
	char buf[1024];
	char *addr, *name, *alias;
	FILE *f;
	unsigned int addrv4;
	struct in6_addr addrv6;
	int family;
	void *naddr;

	(void) fprintf(stderr, "Loading name file %s\n", fname);
	f = fopen(fname, "r");
	if (f == NULL) {
		perror(fname);
		return;
	}

	while (fgets(buf, 1024, f) != NULL) {
		addr = strtok(buf, SEPARATORS);
		if (addr == NULL || *addr == '#')
			continue;
		if (inet_pton(AF_INET6, addr, (void *)&addrv6) == 1) {
			family = AF_INET6;
			naddr = (void *)&addrv6;
		} else if ((addrv4 = inet_addr(addr)) != (ulong_t)-1) {
			family = AF_INET;
			naddr = (void *)&addrv4;
		}
		name = strtok(NULL, SEPARATORS);
		if (name == NULL)
			continue;
		while ((alias = strtok(NULL, SEPARATORS)) != NULL &&
		    (*alias != '#')) {
			(void) addhost(family, naddr, alias, NULL);
		}
		(void) addhost(family, naddr, name, NULL);
		/* Note: certain addresses such as broadcast are skipped */
	}

	(void) fclose(f);
}

/*
 * lgetipnodebyname: looks up hostname in cached address data. This allows
 * filtering on hostnames from the .names file to work properly, and
 * avoids name clashes between domains. Note that only the first of the
 * ipv4, ipv6, or v4mapped address will be returned, because the
 * cache does not contain information on multi-homed hosts.
 */
/*ARGSUSED*/
struct hostent *
lgetipnodebyname(const char *name, int af, int flags, int *error_num)
{
	int i;
	struct hostdata4 *h;
	struct hostdata6 *h6;
	static struct hostent he;		/* host entry */
	static struct in6_addr h46_addr[MAXADDRS];	/* v4mapped address */
	static char h_name[MAXHOSTNAMELEN];	/* hostname */
	static char *list[MAXADDRS];		/* addr_list array */
	struct hostent *hp = &he;
	int ind;

	(void) memset((char *)hp, 0, sizeof (struct hostent));
	hp->h_name = h_name;
	h_name[0] = '\0';
	strcpy(h_name, name);

	hp->h_addrtype = AF_INET6;

	hp->h_addr_list = list;
	for (i = 0; i < MAXADDRS; i++)
		hp->h_addr_list[i] = NULL;
	ind = 0;

	/* ipv6 lookup */
	if (af == AF_INET6) {
		hp->h_length = sizeof (struct in6_addr);
		for (i = 0; i < MAXHASH; i++) {
			for (h6 = h_table6[i]; h6; h6 = h6->h6_next) {
				if (strcmp(name, h6->h6_hostname) == 0) {
					if (ind >= MAXADDRS - 1) {
						/* too many addresses */
						return (hp);
					}
					/* found ipv6 addr */
					hp->h_addr_list[ind] =
					    (char *)&h6->h6_addr;
					ind++;
				}
			}
		}
	}
	/* ipv4 or v4mapped lookup */
	if (af == AF_INET || (flags & AI_ALL)) {
		for (i = 0; i < MAXHASH; i++) {
			for (h = h_table4[i]; h; h = h->h4_next) {
				if (strcmp(name, h->h4_hostname) == 0) {
					if (ind >= MAXADDRS - 1) {
						/* too many addresses */
						return (hp);
					}
					if (af == AF_INET) {
						/* found ipv4 addr */
						hp->h_addrtype = AF_INET;
						hp->h_length =
						    sizeof (struct in_addr);
						hp->h_addr_list[ind] =
						    (char *)&h->h4_addr;
						ind++;
					} else {
						/* found v4mapped addr */
						hp->h_length =
						    sizeof (struct in6_addr);
						hp->h_addr_list[ind] =
						    (char *)&h46_addr[ind];
						IN6_INADDR_TO_V4MAPPED(
						    &h->h4_addr,
						    &h46_addr[ind]);
						ind++;
					}
				}
			}
		}
	}
	return (ind > 0 ? hp : NULL);
}
