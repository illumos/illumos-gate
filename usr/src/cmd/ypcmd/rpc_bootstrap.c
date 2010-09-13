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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/file.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <tiuser.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdir.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/nis.h>

CLIENT *__clnt_tp_create_bootstrap();
int __rpcb_getaddr_bootstrap();
struct hostent *__files_gethostbyname(char *, sa_family_t);

extern int hostNotKnownLocally;

static char *__map_addr();
static struct hostent host;
static char hostaddr[sizeof (struct in6_addr)];
static char *host_aliases[MAXALIASES];
static char *host_addrs[] = {
	hostaddr,
	NULL
};

/*
 * __clnt_tp_create_bootstrap()
 *
 * This routine is NOT TRANSPORT INDEPENDENT.
 *
 * It relies on the local /etc/hosts file for hostname to address
 * translation and does it itself instead of calling netdir_getbyname
 * thereby avoids recursion.  Secondarily, it will use a validated
 * IP address directly.
 */
CLIENT *
__clnt_tp_create_bootstrap(hostname, prog, vers, nconf)
	char *hostname;
	ulong_t prog, vers;
	struct netconfig    *nconf;
{
	CLIENT *cl;
	struct netbuf	*svc_taddr;
	struct sockaddr_in6	*sa;
	int fd;

	if (nconf == (struct netconfig *)NULL) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		return (NULL);
	}
	if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		return (NULL);
	}
	svc_taddr = (struct netbuf *)malloc(sizeof (struct netbuf));
	if (! svc_taddr) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		t_close(fd);
		return (NULL);
	}
	sa = (struct sockaddr_in6 *)calloc(1, sizeof (*sa));
	if (! sa) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		t_close(fd);
		free(svc_taddr);
		return (NULL);
	}
	svc_taddr->maxlen = svc_taddr->len = sizeof (*sa);
	svc_taddr->buf = (char *)sa;
	if (__rpcb_getaddr_bootstrap(prog,
		vers, nconf, svc_taddr, hostname) == FALSE) {
		t_close(fd);
		free(svc_taddr);
		free(sa);
		return (NULL);
	}
	rpc_createerr.cf_stat = RPC_SUCCESS;
	cl = __nis_clnt_create(fd, nconf, 0, svc_taddr, 0, prog, vers, 0, 0);
	if (cl == 0) {
		if (rpc_createerr.cf_stat == RPC_SUCCESS)
			rpc_createerr.cf_stat = RPC_TLIERROR;
		t_close(fd);
	}
	free(svc_taddr);
	free(sa);
	return (cl);
}

/*
 * __rpcb_getaddr_bootstrap()
 *
 * This is our internal function that replaces rpcb_getaddr(). We
 * build our own to prevent calling netdir_getbyname() which could
 * recurse to the nameservice.
 */
int
__rpcb_getaddr_bootstrap(program, version, nconf, address, hostname)
	ulong_t program;
	ulong_t version;
	struct netconfig *nconf;
	struct netbuf *address; /* populate with the taddr of the service */
	char *hostname;
{
	char *svc_uaddr;
	struct hostent *hent, tmphent;
	struct sockaddr_in *sa;
	struct sockaddr_in6 *sa6;
	struct netbuf rpcb_taddr;
	struct sockaddr_in local_sa;
	struct sockaddr_in6 local_sa6;
	in_port_t inport;
	int p1, p2;
	char *ipaddr, *port;
	int i, ipaddrlen;
	sa_family_t type;
	char addr[sizeof (in6_addr_t)];
	char *tmphost_addrs[2];

	if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
		type = AF_INET6;
	} else if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
		type = AF_INET;
	} else {
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		return (FALSE);
	}

	/* Get the address of the RPCBIND at hostname */
	hent = __files_gethostbyname(hostname, type);
	if (hent == (struct hostent *)NULL) {
		/* Make sure this is not an IP address before giving up */
		if (inet_pton(type, hostname, addr) == 1) {
			/* This is a numeric address, fill in the blanks */
			hent = &tmphent;
			memset(&tmphent, 0, sizeof (struct hostent));
			hent->h_addrtype = type;
			hent->h_length = (type == AF_INET6) ?
			    sizeof (in6_addr_t) : sizeof (in_addr_t);
			hent->h_addr_list = tmphost_addrs;
			tmphost_addrs[0] = addr;
			tmphost_addrs[1] = NULL;
		} else {
			rpc_createerr.cf_stat = RPC_UNKNOWNHOST;
			hostNotKnownLocally = 1;
			return (FALSE);
		}
	}

	switch (hent->h_addrtype) {
	case AF_INET:
		local_sa.sin_family = AF_INET;
		local_sa.sin_port = htons(111); /* RPCBIND port */
		memcpy((char *)&(local_sa.sin_addr.s_addr),
		    hent->h_addr_list[0], hent->h_length);
		rpcb_taddr.buf = (char *)&local_sa;
		rpcb_taddr.maxlen = sizeof (local_sa);
		rpcb_taddr.len = rpcb_taddr.maxlen;
		break;
	case AF_INET6:
		local_sa6.sin6_family = AF_INET6;
		local_sa6.sin6_port = htons(111); /* RPCBIND port */
		memcpy((char *)&(local_sa6.sin6_addr.s6_addr),
		    hent->h_addr_list[0], hent->h_length);
		rpcb_taddr.buf = (char *)&local_sa6;
		rpcb_taddr.maxlen = sizeof (local_sa6);
		rpcb_taddr.len = rpcb_taddr.maxlen;
		break;
	default:
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		return (FALSE);
	}

	svc_uaddr = __map_addr(nconf, &rpcb_taddr, program, version);
	if (! svc_uaddr)
		return (FALSE);

/* do a local uaddr2taddr and stuff in the memory supplied by the caller */
	ipaddr = svc_uaddr;
	ipaddrlen = strlen(ipaddr);
	/* Look for the first '.' starting from the end */
	for (i = ipaddrlen-1; i >= 0; i--)
		if (ipaddr[i] == '.')
			break;
	/* Find the second dot (still counting from the end) */
	for (i--; i >= 0; i--)
		if (ipaddr[i] == '.')
			break;
	/* If we didn't find it, the uaddr has a syntax error */
	if (i < 0) {
		rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
		return (FALSE);
	}
	port = &ipaddr[i+1];
	ipaddr[i] = '\0';
	sscanf(port, "%d.%d", &p1, &p2);
	inport = (p1 << 8) + p2;
	if (hent->h_addrtype == AF_INET) {
		sa = (struct sockaddr_in *)address->buf;
		address->len = sizeof (*sa);
		if (inet_pton(AF_INET, ipaddr, &sa->sin_addr) != 1) {
			rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
			return (FALSE);
		}
		sa->sin_port = htons(inport);
		sa->sin_family = AF_INET;
	} else {
		sa6 = (struct sockaddr_in6 *)address->buf;
		address->len = sizeof (*sa6);
		if (inet_pton(AF_INET6, ipaddr, &sa6->sin6_addr) != 1) {
			rpc_createerr.cf_stat = RPC_N2AXLATEFAILURE;
			return (FALSE);
		}
		sa6->sin6_port = htons(inport);
		sa6->sin6_family = AF_INET6;
	}
	return (TRUE);
}

/*
 * __map_addr()
 *
 */
static char *
__map_addr(nc, rpcb_taddr, prog, ver)
	struct netconfig	*nc;		/* Our transport	*/
	struct netbuf		*rpcb_taddr;	/* RPCBIND address */
	ulong_t			prog, ver;	/* Name service Prog/vers */
{
	register CLIENT *client;
	RPCB 		parms;		/* Parameters for RPC binder	  */
	enum clnt_stat	clnt_st;	/* Result from the rpc call	  */
	int		fd;		/* Stream file descriptor	  */
	char 		*ua = NULL;	/* Universal address of service	  */
	struct timeval	tv;		/* Timeout for our rpcb call	  */

	/*
	 * First we open a connection to the remote rpcbind process.
	 */
	if ((fd = t_open(nc->nc_device, O_RDWR, NULL)) == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		return (NULL);
	}

	client = __nis_clnt_create(fd, nc, 0, rpcb_taddr, 0,
	    RPCBPROG, RPCBVERS, 0, 0);
	if (!client) {
		t_close(fd);
		rpc_createerr.cf_stat = RPC_TLIERROR;
		return (NULL);
	}

	/*
	 * Now make the call to get the NIS service address.
	 */
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	parms.r_prog = prog;
	parms.r_vers = ver;
	parms.r_netid = nc->nc_netid;	/* not needed */
	parms.r_addr = "";	/* not needed; just for xdring */
	parms.r_owner = "";	/* not needed; just for xdring */
	clnt_st = clnt_call(client, RPCBPROC_GETADDR, xdr_rpcb, (char *)&parms,
	    xdr_wrapstring, (char *)&ua, tv);

	rpc_createerr.cf_stat = clnt_st;
	if (clnt_st == RPC_SUCCESS) {

		clnt_destroy(client);
		t_close(fd);
		if (*ua == '\0') {
			xdr_free(xdr_wrapstring, (char *)&ua);
			return (NULL);
		}
		return (ua);
	} else if (((clnt_st == RPC_PROGVERSMISMATCH) ||
	    (clnt_st == RPC_PROGUNAVAIL) ||
	    (clnt_st == RPC_TIMEDOUT)) &&
	    (strcmp(nc->nc_protofmly, NC_INET) == 0)) {
		/*
		 * version 3 not available. Try version 2
		 * The assumption here is that the netbuf
		 * is arranged in the sockaddr_in
		 * style for IP cases.
		 */
		ushort_t	port;
		struct sockaddr_in	*sa;
		struct netbuf 		remote;
		int		protocol;
		char	buf[32];
		char	*res;

		clnt_control(client, CLGET_SVC_ADDR, (char *)&remote);
		sa = (struct sockaddr_in *)(remote.buf);
		protocol = strcmp(nc->nc_proto, NC_TCP) ? IPPROTO_UDP :
		    IPPROTO_TCP;
		port = (ushort_t)pmap_getport(sa, prog, ver, protocol);

		if (port != 0) {
			/* print s_addr (and port) in host byte order */
			sa->sin_addr.s_addr = ntohl(sa->sin_addr.s_addr);
			sprintf(buf, "%d.%d.%d.%d.%d.%d",
			    (sa->sin_addr.s_addr >> 24) & 0xff,
			    (sa->sin_addr.s_addr >> 16) & 0xff,
			    (sa->sin_addr.s_addr >>  8) & 0xff,
			    (sa->sin_addr.s_addr) & 0xff,
			    (port >> 8) & 0xff,
			    port & 0xff);
			res = strdup(buf);
			if (res != 0) {
				rpc_createerr.cf_stat = RPC_SUCCESS;
			} else {
				rpc_createerr.cf_stat = RPC_SYSTEMERROR;
			}
		} else {
			rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
			res = NULL;
		}
		clnt_destroy(client);
		t_close(fd);
		return (res);
	}
	clnt_destroy(client);
	t_close(fd);
	return (NULL);
}

#define	bcmp(s1, s2, len)	memcmp(s1, s2, len)
#define	bcopy(s1, s2, len)	memcpy(s2, s1, len)

#define	MAXALIASES	35

static char line[BUFSIZ+1];

static char *_hosts4_6[] = { "/etc/inet/hosts", "/etc/inet/ipnodes", 0 };

static char *any();

static struct hostent *__files_gethostent();

struct hostent *
__files_gethostbyname(char *nam, sa_family_t af)
{
	register struct hostent *hp;
	register char **cp;
	char **file = _hosts4_6;
	FILE *hostf;

	if ((af != AF_INET) && (af != AF_INET6))
		return (0);

	for (; *file != 0; file++) {

		if ((hostf = fopen(*file, "r")) == 0)
			continue;

		while (hp = __files_gethostent(hostf)) {
			if (hp->h_addrtype != af)
				continue;
			if (strcasecmp(hp->h_name, nam) == 0) {
				(void) fclose(hostf);
				return (hp);
			}
			for (cp = hp->h_aliases; cp != 0 && *cp != 0; cp++)
				if (strcasecmp(*cp, nam) == 0) {
					(void) fclose(hostf);
					return (hp);
				}
		}

		(void) fclose(hostf);
	}

	return (0);
}

#define	isV6Addr(s)	(strchr(s, (int)':') != 0)

static struct hostent *
__files_gethostent(FILE *hostf)
{
	char *p;
	register char *cp, **q;
	struct in6_addr in6;
	struct in_addr in4;
	void *addr;
	sa_family_t af;
	int len;

	if (hostf == NULL)
		return (NULL);
again:
	if ((p = fgets(line, BUFSIZ, hostf)) == NULL)
		return (NULL);
	if (*p == '#')
		goto again;
	cp = any(p, "#\n");
	if (cp == NULL)
		goto again;
	*cp = '\0';
	cp = any(p, " \t");
	if (cp == NULL)
		goto again;
	*cp++ = '\0';
	/* THIS STUFF IS INTERNET SPECIFIC */
	host.h_addr_list = host_addrs;
	if (isV6Addr(p)) {
		af = AF_INET6;
		addr = (void *)&in6;
		len = sizeof (in6);
	} else {
		af = AF_INET;
		addr = (void *)&in4;
		len = sizeof (in4);
	}
	if (inet_pton(af, p, addr) != 1)
		goto again;
	bcopy(addr, host.h_addr_list[0], len);
	host.h_length = len;
	host.h_addrtype = af;
	while (*cp == ' ' || *cp == '\t')
		cp++;
	host.h_name = cp;
	q = host.h_aliases = host_aliases;
	cp = any(cp, " \t");
	if (cp != NULL)
		*cp++ = '\0';
	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (q < &host_aliases[MAXALIASES - 1])
			*q++ = cp;
		cp = any(cp, " \t");
		if (cp != NULL)
			*cp++ = '\0';
	}
	*q = NULL;
	return (&host);
}

static char *
any(cp, match)
	register char *cp;
	char *match;
{
	register char *mp, c;

	while (c = *cp) {
		for (mp = match; *mp; mp++)
			if (*mp == c)
				return (cp);
		cp++;
	}
	return ((char *)0);
}
