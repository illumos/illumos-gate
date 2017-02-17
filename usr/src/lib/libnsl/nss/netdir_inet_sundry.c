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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * lib/libnsl/nss/netdir_inet_sundry.c
 *
 * This file contains inet-specific implementations of netdir_options,
 * uaddr2taddr, and taddr2uaddr. These implementations
 * used to be in both tcpip.so and switch.so (identical copies).
 * Since we got rid of those, and also it's a good idea to build-in
 * inet-specific implementations in one place, we decided to put
 * them in this file with a not-so glorious name. These are INET-SPECIFIC
 * only, and will not be used for non-inet transports or by third-parties
 * that decide to provide their own nametoaddr libs for inet transports
 * (they are on their own for these as well => they get flexibility).
 *
 * Copied mostly from erstwhile lib/nametoaddr/tcpip/tcpip.c.
 */

#include "mt.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <thread.h>
#include <netconfig.h>
#include <netdir.h>
#include <nss_netdir.h>
#include <tiuser.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <rpc/types.h>
#include <rpc/rpc_com.h>
#include <syslog.h>
#include <values.h>
#include <limits.h>
#include <nss_dbdefs.h>
#include "nss.h"

#define	MAXIFS 32

/*
 * Extracted from socketvar.h
 */
#define	SOV_DEFAULT	1	/* Select based on so_default_version */
#define	SOV_SOCKBSD	3	/* Socket with no streams operations */

extern int _so_socket(int, int, int, char *, int);
extern int _so_connect(int, struct sockaddr *, socklen_t, int);
extern int _so_getsockname(int, struct sockaddr *, socklen_t *, int);


static char *inet_netdir_mergeaddr(struct netconfig *, char *, char *);
static int bindresvport(struct netconfig *, int, struct netbuf *);
static int checkresvport(struct netbuf *);
static struct netbuf *ip_uaddr2taddr(char *);
static struct netbuf *ipv6_uaddr2taddr(char *);


extern char *inet_ntoa_r(struct in_addr, char *);

int
__inet_netdir_options(struct netconfig *tp, int opts, int fd, char *par)
{
	struct nd_mergearg *ma;

	switch (opts) {
	case ND_SET_BROADCAST:
		/* Every one is allowed to broadcast without asking */
		return (ND_OK);
	case ND_SET_RESERVEDPORT:	/* bind to a resered port */
		/* LINTED pointer cast */
		return (bindresvport(tp, fd, (struct netbuf *)par));
	case ND_CHECK_RESERVEDPORT:	/* check if reserved prot */
		/* LINTED pointer cast */
		return (checkresvport((struct netbuf *)par));
	case ND_MERGEADDR:	/* Merge two addresses */
		/* LINTED pointer cast */
		ma = (struct nd_mergearg *)(par);
		ma->m_uaddr = inet_netdir_mergeaddr(tp, ma->c_uaddr,
		    ma->s_uaddr);
		return (_nderror);
	default:
		return (ND_NOCTRL);
	}
}


/*
 * This routine will convert a TCP/IP internal format address
 * into a "universal" format address. In our case it prints out the
 * decimal dot equivalent. h1.h2.h3.h4.p1.p2 where h1-h4 are the host
 * address and p1-p2 are the port number.
 */
char *
__inet_taddr2uaddr(struct netconfig *tp, struct netbuf *addr)
{
	struct sockaddr_in	*sa;	/* our internal format */
	struct sockaddr_in6	*sa6;	/* our internal format */
	char			tmp[RPC_INET6_MAXUADDRSIZE];
	unsigned short		myport;

	if (addr == NULL || tp == NULL || addr->buf == NULL) {
		_nderror = ND_BADARG;
		return (NULL);
	}
	if (strcmp(tp->nc_protofmly, NC_INET) == 0) {
		/* LINTED pointer cast */
		sa = (struct sockaddr_in *)(addr->buf);
		myport = ntohs(sa->sin_port);
		(void) inet_ntoa_r(sa->sin_addr, tmp);
	} else {
		/* LINTED pointer cast */
		sa6 = (struct sockaddr_in6 *)(addr->buf);
		myport = ntohs(sa6->sin6_port);
		if (inet_ntop(AF_INET6, sa6->sin6_addr.s6_addr, tmp,
		    sizeof (tmp)) == NULL) {
			_nderror = ND_BADARG;
			return (NULL);
		}
	}

	(void) sprintf(tmp + strlen(tmp), ".%d.%d", myport >> 8, myport & 255);
	return (strdup(tmp));	/* Doesn't return static data ! */
}

/*
 * This internal routine will convert one of those "universal" addresses
 * to the internal format used by the Sun TLI TCP/IP provider.
 */
struct netbuf *
__inet_uaddr2taddr(struct netconfig *tp, char *addr)
{
	if (!addr || !tp) {
		_nderror = ND_BADARG;
		return (NULL);
	}
	if (strcmp(tp->nc_protofmly, NC_INET) == 0)
		return (ip_uaddr2taddr(addr));
	else
		return (ipv6_uaddr2taddr(addr));
}

static struct netbuf *
ip_uaddr2taddr(char *addr)
{

	struct sockaddr_in	*sa;
	uint32_t		inaddr;
	unsigned short		inport;
	int			h1, h2, h3, h4, p1, p2;
	struct netbuf		*result;

	result = malloc(sizeof (struct netbuf));
	if (!result) {
		_nderror = ND_NOMEM;
		return (NULL);
	}

	sa = calloc(1, sizeof (*sa));

	if (!sa) {
		free(result);
		_nderror = ND_NOMEM;
		return (NULL);
	}

	result->buf = (char *)(sa);
	result->maxlen = sizeof (struct sockaddr_in);
	result->len = sizeof (struct sockaddr_in);

	/* XXX there is probably a better way to do this. */
	if (sscanf(addr, "%d.%d.%d.%d.%d.%d", &h1, &h2, &h3, &h4,
	    &p1, &p2) != 6) {
		free(result);
		_nderror = ND_NO_RECOVERY;
		return (NULL);
	}

	/* convert the host address first */
	inaddr = (h1 << 24) + (h2 << 16) + (h3 << 8) + h4;
	sa->sin_addr.s_addr = htonl(inaddr);

	/* convert the port */
	inport = (p1 << 8) + p2;
	sa->sin_port = htons(inport);

	sa->sin_family = AF_INET;

	return (result);
}

static struct netbuf *
ipv6_uaddr2taddr(char	*addr)
{
	struct sockaddr_in6	*sa;
	unsigned short		inport;
	int	 p1, p2;
	struct netbuf		*result;
	char tmpaddr[RPC_INET6_MAXUADDRSIZE];
	char *dot;

	result = malloc(sizeof (struct netbuf));
	if (!result) {
		_nderror = ND_NOMEM;
		return (NULL);
	}

	sa = calloc(1, sizeof (struct sockaddr_in6));
	if (!sa) {
		free(result);
		_nderror = ND_NOMEM;
		return (NULL);
	}
	result->buf = (char *)(sa);
	result->maxlen = sizeof (struct sockaddr_in6);
	result->len = sizeof (struct sockaddr_in6);

	/* retrieve the ipv6 address and port info */

	if (strlen(addr) > sizeof (tmpaddr) - 1) {
		free(result);
		_nderror = ND_NOMEM;
		return (NULL);
	}

	(void) strcpy(tmpaddr, addr);

	if ((dot = strrchr(tmpaddr, '.')) != 0) {
		*dot = '\0';
		p2 = atoi(dot+1);
		if ((dot = strrchr(tmpaddr, '.')) != 0) {
			*dot = '\0';
			p1 = atoi(dot+1);
		}
	}

	if (dot == 0) {
		free(result);
		_nderror = ND_NOMEM;
		return (NULL);
	}

	if (inet_pton(AF_INET6, tmpaddr, sa->sin6_addr.s6_addr) == 0) {
		free(result);
		_nderror = ND_NOMEM;
		return (NULL);
	}

	/* convert the port */
	inport = (p1 << 8) + p2;
	sa->sin6_port = htons(inport);

	sa->sin6_family = AF_INET6;

	return (result);
}

/*
 * Interface caching routines.  The cache is refreshed every
 * IF_CACHE_REFRESH_TIME seconds.  A read-write lock is used to
 * protect the cache.
 */
#define	IF_CACHE_REFRESH_TIME 10

static int if_cache_refresh_time = IF_CACHE_REFRESH_TIME;
static rwlock_t iflock = DEFAULTRWLOCK;
static time_t last_updated = 0;		/* protected by iflock */

/*
 * Changing the data type of if_flags from uint_t to uint64_t to accomodate
 * extra flags. Refer <net/if.h> for the extra flags.
 */
typedef struct if_info_s {
	struct in_addr if_netmask;	/* netmask in network order */
	struct in_addr if_address;	/* address in network order */
	uint64_t if_flags;		/* interface flags */
} if_info_t;

static if_info_t *if_info = NULL;	/* if cache, protected by iflock */
static int n_ifs = 0;			/* number of cached interfaces */
static int numifs_last = 0;		/* number of interfaces last seen */

/*
 * Builds the interface cache.  Write lock on iflock is needed
 * for calling this routine.  It sets _nderror for error returns.
 * Returns TRUE if successful, FALSE otherwise.
 * Changing the structures ifreq and ifconf to lifreq and lifconf to
 * have larger flag field. This is to accomodate the extra flags associated
 * with the interface. Also introducing lifn which will contain the number
 * of IPV4 interfaces present.
 */
static bool_t
get_if_info(void)
{
	size_t		needed;
	struct lifreq	*buf = NULL;
	int		numifs;
	struct lifconf  lifc;
	struct lifreq   *lifr;
	struct lifnum   lifn;

	lifn.lifn_family = AF_INET;
	lifn.lifn_flags = 0;
getifnum:
	if (nss_ioctl(AF_INET, SIOCGLIFNUM, &lifn) == -1) {
		numifs = MAXIFS;
	} else {
		numifs = lifn.lifn_count;
	}
	/*
	 * Add a small fudge factor in case interfaces are plumbed
	 * between the SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	needed = (numifs + 4) * sizeof (struct lifreq);
	if (buf == NULL)
		buf = malloc(needed);
	else
		buf = realloc(buf, needed);
	if (buf == NULL) {
		_nderror = ND_NOMEM;
		return (FALSE);
	}

	lifc.lifc_family = AF_INET;
	lifc.lifc_flags = 0;
	lifc.lifc_len = needed;
	lifc.lifc_buf = (char *)buf;
	if (nss_ioctl(AF_INET, SIOCGLIFCONF, &lifc) == -1) {
		/*
		 * IP returns EINVAL if the buffer was too small to fit
		 * all of the entries.  If that's the case, go back and
		 * try again.
		 */
		if (errno == EINVAL)
			goto getifnum;

		free(buf);
		free(if_info);
		if_info = NULL;
		_nderror = ND_SYSTEM;
		return (FALSE);
	}
	numifs = lifc.lifc_len / (int)sizeof (struct lifreq);

	if (if_info == NULL || numifs > numifs_last) {
		if (if_info == NULL)
			if_info = malloc(numifs * sizeof (if_info_t));
		else
			if_info = realloc(if_info, numifs * sizeof (if_info_t));
		if (if_info == NULL) {
			free(buf);
			_nderror = ND_NOMEM;
			return (FALSE);
		}
		numifs_last = numifs;
	}

	n_ifs = 0;
	for (lifr = buf; lifr < (buf + numifs); lifr++) {
		if (lifr->lifr_addr.ss_family != AF_INET)
			continue;

		if_info[n_ifs].if_address =
		    ((struct sockaddr_in *)&lifr->lifr_addr)->sin_addr;

		if (nss_ioctl(AF_INET, SIOCGLIFFLAGS, lifr) < 0)
			continue;

		if ((lifr->lifr_flags & IFF_UP) == 0)
			continue;
		if_info[n_ifs].if_flags = lifr->lifr_flags;

		if (nss_ioctl(AF_INET, SIOCGLIFNETMASK, lifr) < 0)
			continue;

		if_info[n_ifs].if_netmask =
		    ((struct sockaddr_in *)&lifr->lifr_addr)->sin_addr;
		n_ifs++;
	}
	free(buf);
	return (TRUE);
}


/*
 * Update the interface cache based on last update time.
 */
static bool_t
update_if_cache(void)
{
	time_t	curtime;

	(void) rw_wrlock(&iflock);
	/*
	 * Check if some other thread has beaten this one to it.
	 */
	(void) time(&curtime);
	if ((curtime - last_updated) >= if_cache_refresh_time) {
		if (!get_if_info()) {
			(void) rw_unlock(&iflock);
			return (FALSE);
		}
		(void) time(&last_updated);
	}
	(void) rw_unlock(&iflock);
	return (TRUE);
}


/*
 * Given an IP address, check if this matches any of the interface
 * addresses.  If an error occurs, return FALSE so that the caller
 * will not assume that this address belongs to this machine.
 */
static bool_t
is_my_address(struct in_addr addr)
{
	time_t		curtime;
	if_info_t	*ifn;

	(void) time(&curtime);
	if ((curtime - last_updated) >= if_cache_refresh_time) {
		/*
		 * Cache needs to be refreshed.
		 */
		if (!update_if_cache())
			return (FALSE);
	}
	(void) rw_rdlock(&iflock);
	for (ifn = if_info; ifn < (if_info + n_ifs); ifn++) {
		if (addr.s_addr == ifn->if_address.s_addr) {
			(void) rw_unlock(&iflock);
			return (TRUE);
		}
	}
	(void) rw_unlock(&iflock);
	return (FALSE);
}


/*
 * Given a host name, check if it is this host.
 */
bool_t
__inet_netdir_is_my_host(const char *host)
{
	int		error;
	char		buf[NSS_BUFLEN_HOSTS];
	struct hostent	res, *h;
	char		**c;
	struct in_addr	in;

	h = gethostbyname_r(host, (void *)&res, buf, sizeof (buf), &error);
	if (h == NULL)
		return (FALSE);
	if (h->h_addrtype != AF_INET)
		return (FALSE);
	for (c = h->h_addr_list; *c != NULL; c++) {
		(void) memcpy(&in.s_addr, *c, sizeof (in.s_addr));
		if (is_my_address(in))
			return (TRUE);
	}
	return (FALSE);
}


/*
 * Given an IP address, find the interface address that has the best
 * prefix match.  Return the address in network order.
 */
static uint32_t
get_best_match(struct in_addr addr)
{
	if_info_t *bestmatch, *ifn;
	int bestcount, count, limit;
	uint32_t mask, netmask, clnt_addr, if_addr;
	bool_t found, subnet_match;
	int subnet_count;

	bestmatch = NULL;				/* no match yet */
	bestcount = BITSPERBYTE * sizeof (uint32_t);	/* worst match */
	clnt_addr = ntohl(addr.s_addr);			/* host order */

	subnet_match = FALSE;		/* subnet match not found yet */
	subnet_count = bestcount;	/* worst subnet match */

	for (ifn = if_info; ifn < (if_info + n_ifs); ifn++) {
		netmask = ntohl(ifn->if_netmask.s_addr);  /* host order */
		if_addr = ntohl(ifn->if_address.s_addr);  /* host order */

		/*
		 * set initial count to first bit set in netmask, with
		 * zero being the number of the least significant bit.
		 */
		count = 0;
		for (mask = netmask; mask && ((mask & 1) == 0); mask >>= 1)
			count++;

		/*
		 * Set limit so that we don't try to match prefixes shorter
		 * than the inherent netmask for the class (A, B, C, etc).
		 */
		if (IN_CLASSC(if_addr))
			limit = IN_CLASSC_NSHIFT;
		else if (IN_CLASSB(if_addr))
			limit = IN_CLASSB_NSHIFT;
		else if (IN_CLASSA(if_addr))
			limit = IN_CLASSA_NSHIFT;
		else
			limit = 0;

		/*
		 * We assume that the netmask consists of a contiguous
		 * sequence of 1-bits starting with the most significant bit.
		 * Prefix comparison starts at the subnet mask level.
		 * The prefix mask used for comparison is progressively
		 * reduced until it equals the inherent mask for the
		 * interface address class.  The algorithm finds an
		 * interface in the following order of preference:
		 *
		 * (1) the longest subnet match
		 * (2) the best partial subnet match
		 * (3) the first non-loopback && non-PPP interface
		 * (4) the first non-loopback interface (PPP is OK)
		 */
		found = FALSE;
		while (netmask && count < subnet_count) {
			if ((netmask & clnt_addr) == (netmask & if_addr)) {
				bestcount = count;
				bestmatch = ifn;
				found = TRUE;
				break;
			}
			netmask <<= 1;
			count++;
			if (count >= bestcount || count > limit || subnet_match)
				break;
		}
		/*
		 * If a subnet level match occurred, note this for
		 * comparison with future subnet matches.
		 */
		if (found && (netmask == ntohl(ifn->if_netmask.s_addr))) {
			subnet_match = TRUE;
			subnet_count = count;
		}
	}

	/*
	 * If we don't have a match, select the first interface that
	 * is not a loopback interface (and preferably not a PPP interface)
	 * as the best match.
	 */
	if (bestmatch == NULL) {
		for (ifn = if_info; ifn < (if_info + n_ifs); ifn++) {
			if ((ifn->if_flags & IFF_LOOPBACK) == 0) {
				bestmatch = ifn;

				/*
				 * If this isn't a PPP interface, we're
				 * done.  Otherwise, keep walking through
				 * the list in case we have a non-loopback
				 * iface that ISN'T a PPP further down our
				 * list...
				 */
				if ((ifn->if_flags & IFF_POINTOPOINT) == 0) {
					break;
				}
			}
		}
	}

	if (bestmatch != NULL)
		return (bestmatch->if_address.s_addr);
	else
		return (0);
}

static int
is_myself(struct sockaddr_in6 *sa6)
{
	struct sioc_addrreq areq;
	int s;

	if ((s = open("/dev/udp6", O_RDONLY)) < 0) {
		syslog(LOG_ERR, "is_myself: can't open /dev/udp6: %m");
		return (0);
	}

	(void) memcpy(&areq.sa_addr, sa6, sizeof (struct sockaddr_storage));
	areq.sa_res = -1;

	if (ioctl(s, SIOCTMYADDR, (caddr_t)&areq) < 0) {
		syslog(LOG_ERR, "is_myself:SIOCTMYADDR failed: %m");
		(void) close(s);
		return (0);
	}

	(void) close(s);
	return (areq.sa_res);

}
/*
 * For a given destination address, determine a source address to use.
 * Returns wildcard address if it cannot determine the source address.
 * copied from ping.c.
 */
union any_in_addr {
	struct in6_addr addr6;
	struct in_addr addr;
};

static bool_t
select_server_addr(union any_in_addr *dst_addr, int family,
    union any_in_addr *src_addr)
{
	struct sockaddr *sock;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int tmp_fd;
	socklen_t sock_len;

	sock = calloc(1, sizeof (struct sockaddr_in6));
	if (sock == NULL) {
		return (FALSE);
	}

	if (family == AF_INET) {
		/* LINTED pointer cast */
		sin = (struct sockaddr_in *)sock;
		sin->sin_family = AF_INET;
		sin->sin_port = 111;
		sin->sin_addr = dst_addr->addr;
		sock_len = sizeof (struct sockaddr_in);
	} else {
		/* LINTED pointer cast */
		sin6 = (struct sockaddr_in6 *)sock;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = 111;
		sin6->sin6_addr = dst_addr->addr6;
		sock_len = sizeof (struct sockaddr_in6);
	}

	/* open a UDP socket */
	tmp_fd = _so_socket(family, SOCK_DGRAM, 0, NULL, SOV_SOCKBSD);
	if (tmp_fd < 0) {
		syslog(LOG_ERR, "select_server_addr: connect failed\n");
		return (FALSE);
	}

	/* connect it */
	if (_so_connect(tmp_fd, sock, sock_len, SOV_SOCKBSD) < 0) {
		/*
		 * If there's no route to the destination, this connect() call
		 * fails. We just return all-zero (wildcard) as the source
		 * address, so that user can get to see "no route to dest"
		 * message, as it'll try to send the probe packet out and will
		 * receive ICMP unreachable.
		 */
		if (family == AF_INET) {
			src_addr->addr.s_addr = INADDR_ANY;
		} else {
			/*
			 * Since in6addr_any is not in the scope
			 * use the following hack
			 */
			(void) memset(src_addr->addr6.s6_addr,
			    0, sizeof (struct in6_addr));
		}
		(void) close(tmp_fd);
		free(sock);
		return (FALSE);
	}

	/* get the local sock info */
	if (_so_getsockname(tmp_fd, sock, &sock_len, SOV_DEFAULT) < 0) {
		syslog(LOG_ERR, "select_server_addr: getsockname failed\n");
		(void) close(tmp_fd);
		free(sock);
		return (FALSE);
	}

	if (family == AF_INET) {
		/* LINTED pointer cast */
		sin = (struct sockaddr_in *)sock;
		src_addr->addr = sin->sin_addr;
	} else {
		/* LINTED pointer cast */
		sin6 = (struct sockaddr_in6 *)sock;
		src_addr->addr6 = sin6->sin6_addr;
	}

	(void) close(tmp_fd);
	free(sock);
	return (TRUE);
}

/*
 * This internal routine will merge one of those "universal" addresses
 * to the one which will make sense to the remote caller.
 */
static char *
inet_netdir_mergeaddr(struct netconfig *tp, char *ruaddr, char *uaddr)
{
	char	tmp[SYS_NMLN], *cp;
	int	j;
	struct	in_addr clientaddr, bestmatch;
	time_t	curtime;
	int af;

	if (!uaddr || !ruaddr || !tp) {
		_nderror = ND_BADARG;
		return (NULL);
	}
	(void) bzero(tmp, SYS_NMLN);

	if (strcmp(tp->nc_protofmly, NC_INET) == 0)
		af = AF_INET;
	else
		af = AF_INET6;

	if (af == AF_INET) {
		if (strncmp(ruaddr, "0.0.0.0.", strlen("0.0.0.0.")) == 0)
			/* thats me: return the way it is */
			return (strdup(uaddr));

		/*
		 * Convert remote uaddr into an in_addr so that we can compare
		 * to it.  Shave off last two dotted-decimal values.
		 */
		for (cp = ruaddr, j = 0; j < 4; j++, cp++)
			if ((cp = strchr(cp, '.')) == NULL)
				break;

		if (cp != NULL)
			*--cp = '\0';	/* null out the dot after the IP addr */
		else {
			_nderror = ND_NOHOST;
			return (NULL);
		}

		clientaddr.s_addr = inet_addr(ruaddr);

		/* We know cp is not NULL due to the check above */
		*cp = '.';	/* Put the dot back in the IP addr */

		(void) time(&curtime);
		if ((curtime - last_updated) >= if_cache_refresh_time) {
			/*
			 * Cache needs to be refreshed.
			 */
			if (!update_if_cache())
				return (NULL);
		}

		/*
		 * Find the best match now.
		 */
		(void) rw_rdlock(&iflock);
		bestmatch.s_addr = get_best_match(clientaddr);
		(void) rw_unlock(&iflock);

		if (bestmatch.s_addr)
			_nderror = ND_OK;
		else {
			_nderror = ND_NOHOST;
			return (NULL);
		}

		/* prepare the reply */
		(void) memset(tmp, '\0', sizeof (tmp));

		/* reply consists of the IP addr of the closest interface */
		(void) strcpy(tmp, inet_ntoa(bestmatch));

		/*
		 * ... and the port number part (last two dotted-decimal values)
		 * of uaddr
		 */
		for (cp = uaddr, j = 0; j < 4; j++, cp++)
			cp = strchr(cp, '.');
		(void) strcat(tmp, --cp);

	} else {
		/* IPv6 */
		char *dot;
		char *truaddr;
		struct sockaddr_in6 sa;
		struct sockaddr_in6 server_addr;
		union any_in_addr in_addr, out_addr;

		if (strncmp(ruaddr, "::", strlen("::")) == 0)
			if (*(ruaddr + strlen("::")) == '\0')
				/* thats me: return the way it is */
				return (strdup(uaddr));

		bzero(&sa, sizeof (sa));
		bzero(&server_addr, sizeof (server_addr));
		truaddr = &tmp[0];
		(void) strcpy(truaddr, ruaddr);

		/*
		 * now extract the server ip address from
		 * the address supplied by client.  It can be
		 * client's own IP address.
		 */

		if ((dot = strrchr(truaddr, '.')) != 0) {
			*dot = '\0';
			if ((dot = strrchr(truaddr, '.')) != 0)
				*dot = '\0';
		}

		if (dot == 0) {
			_nderror = ND_NOHOST;
			return (NULL);
		}

		if (inet_pton(af, truaddr, sa.sin6_addr.s6_addr)
		    != 1) {
			_nderror = ND_NOHOST;
			return (NULL);
		}

		in_addr.addr6 = sa.sin6_addr;
		sa.sin6_family = AF_INET6;

		/* is it my IP address */
		if (!is_myself(&sa)) {
			/* have the kernel select one for me */
			if (select_server_addr(&in_addr, af, &out_addr) ==
			    FALSE)
				return (NULL);
			server_addr.sin6_addr = out_addr.addr6;
		} else {
			(void) memcpy(&server_addr, &sa, sizeof (server_addr));
		}

		if (inet_ntop(af, server_addr.sin6_addr.s6_addr, tmp,
		    sizeof (tmp)) == NULL) {
			_nderror = ND_NOHOST;
			return (NULL);
		}

		/* now extract the port info */
		if ((dot = strrchr(uaddr, '.')) != 0) {
			char *p = --dot;

			while (*p-- != '.')
				;
			p++;
			(void) strcat(tmp + strlen(tmp), p);
			_nderror = ND_OK;
		} else {
			_nderror = ND_NOHOST;
			return (NULL);
		}

	}
	return (strdup(tmp));
}

static int
bindresvport(struct netconfig *nconf, int fd, struct netbuf *addr)
{
	int res;
	struct sockaddr_in myaddr;
	struct sockaddr_in6 myaddr6;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int i;
	struct t_bind tbindstr, *tres;
	struct t_info tinfo;
	struct t_optmgmt req, resp;
	struct opthdr *opt;
	int reqbuf[64/sizeof (int)];
	int *optval;

	union {
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		char *buf;
	} u;

	_nderror = ND_SYSTEM;
	if (geteuid()) {
		errno = EACCES;
		return (-1);
	}
	if ((i = t_getstate(fd)) != T_UNBND) {
		if (t_errno == TBADF)
			errno = EBADF;
		if (i != -1)
			errno = EISCONN;
		return (-1);
	}

	if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
		if (addr == NULL) {
			sin = &myaddr;
			(void) memset(sin, 0, sizeof (*sin));
			sin->sin_family = AF_INET;
			u.buf = (char *)sin;
		} else
			u.buf = (char *)addr->buf;
	} else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
		if (addr == NULL) {
			sin6 = &myaddr6;
			(void) memset(sin6, 0, sizeof (*sin6));
			sin6->sin6_family = AF_INET6;
			u.buf = (char *)sin6;
		} else
			u.buf = addr->buf;

	} else {
		errno = EPFNOSUPPORT;
		return (-1);
	}

	/* Transform sockaddr_in to netbuf */
	if (t_getinfo(fd, &tinfo) == -1)
		return (-1);
	/* LINTED pointer cast */
	tres = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
	if (tres == NULL) {
		_nderror = ND_NOMEM;
		return (-1);
	}

	tbindstr.qlen = 0; /* Always 0; user should change if they want to */
	tbindstr.addr.buf = (char *)u.buf;
	tbindstr.addr.len = tbindstr.addr.maxlen = __rpc_get_a_size(tinfo.addr);

	/*
	 * Use *_ANONPRIVBIND to ask the kernel to pick a port in the
	 * priviledged range for us.
	 */
	opt = (struct opthdr *)reqbuf;
	if (strcmp(nconf->nc_proto, NC_TCP) == 0) {
		opt->level = IPPROTO_TCP;
		opt->name = TCP_ANONPRIVBIND;
	} else if (strcmp(nconf->nc_proto, NC_UDP) == 0) {
		opt->level = IPPROTO_UDP;
		opt->name = UDP_ANONPRIVBIND;
	} else {
		errno = EPROTONOSUPPORT;
		(void) t_free((char *)tres, T_BIND);
		return (-1);
	}

	opt->len = sizeof (int);
	req.flags = T_NEGOTIATE;
	req.opt.len = sizeof (struct opthdr) + opt->len;
	req.opt.buf = (char *)opt;
	/* LINTED pointer cast */
	optval = (int *)((char *)reqbuf + sizeof (struct opthdr));
	*optval = 1;
	resp.flags = 0;
	resp.opt.buf = (char *)reqbuf;
	resp.opt.maxlen = sizeof (reqbuf);
	if (t_optmgmt(fd, &req, &resp) < 0 || resp.flags != T_SUCCESS) {
		(void) t_free((char *)tres, T_BIND);
		return (-1);
	}

	if (u.sin->sin_family == AF_INET)
		u.sin->sin_port = htons(0);
	else
		u.sin6->sin6_port = htons(0);
	res = t_bind(fd, &tbindstr, tres);
	if (res != 0) {
		if (t_errno == TNOADDR) {
			_nderror = ND_FAILCTRL;
			res = 1;
		}
	} else {
		_nderror = ND_OK;
	}

	/*
	 * Always turn off the option when we are done.  Note that by doing
	 * this, if the caller has set this option before calling
	 * bindresvport(), it will be unset.  Better be safe...
	 */
	*optval = 0;
	resp.flags = 0;
	resp.opt.buf = (char *)reqbuf;
	resp.opt.maxlen = sizeof (reqbuf);
	if (t_optmgmt(fd, &req, &resp) < 0 || resp.flags != T_SUCCESS) {
		(void) t_free((char *)tres, T_BIND);
		if (res == 0)
			(void) t_unbind(fd);
		_nderror = ND_FAILCTRL;
		return (-1);
	}

	(void) t_free((char *)tres, T_BIND);
	return (res);
}

static int
checkresvport(struct netbuf *addr)
{
	struct sockaddr_in *sin;
	unsigned short port;

	if (addr == NULL) {
		_nderror = ND_FAILCTRL;
		return (-1);
	}
	/*
	 * Still works for IPv6 since the first two memebers of
	 * both address structure point to family and port # respectively
	 */
	/* LINTED pointer cast */
	sin = (struct sockaddr_in *)(addr->buf);
	port = ntohs(sin->sin_port);
	if (port < IPPORT_RESERVED)
		return (0);
	return (1);
}
