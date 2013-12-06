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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * BrandZ lx name services translation library.
 *
 * This library is specified as the default name services translation
 * library in a custom netconfig(4) file that is only used when running
 * native solaris processes in a Linux branded zone.
 *
 * What this means it that when a native solaris process runs in a
 * Linux branded zone and issues a name service request to libnsl.so
 * (either directly or indirectly via any libraries the program may
 * be linked against) libnsl.so will dlopen(3c) this library and call
 * into it to service these requests.
 *
 * This library is in turn linked against lx_thunk.so and will attempt
 * to call interfaces in lx_thunk.so to resolve these requests.  The
 * functions that are called in lx_thunk.so are designed to have the
 * same signature and behavior as the existing solaris name service
 * interfaces.  The name services interfaces we call are:
 *
 *	Native Interface	-> lx_thunk.so Interface
 *	----------------	-> ---------------------
 *	gethostbyname_r		-> lxt_gethostbyname_r
 *	gethostbyaddr_r		-> lxt_gethostbyaddr_r
 *	getservbyname_r		-> lxt_getservbyname_r
 *	getservbyport_r		-> lxt_getservbyport_r
 *
 * This library also uses one additional interface from lx_thunk.so:
 * 	lxt_debug
 * Information debugging messages are sent to lx_thunk.so via this
 * interface and that library can decided if it wants to drop the
 * messages or output them somewhere.
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netdir.h>
#include <nss_dbdefs.h>
#include <rpc/clnt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/wait.h>
#include <thread.h>
#include <tiuser.h>
#include <unistd.h>
#include <sys/lx_thunk.h>


/*
 * Private nametoaddr library interfaces.
 */
static int
netconfig_is_ipv4(struct netconfig *config)
{
	int i;
	/*
	 * If we look at the rpc services registered on a Linux system
	 * (this can be done via rpcinfo(1M)) for both on the loopback
	 * interface and on any remote interfaces we only see services
	 * registered for tcp and udp.  So here we'll limit our support
	 * to these transports.
	 */
	char *ipv4_netids[] = {
		"tcp",
		"udp",
		NULL
	};

	for (i = 0; ipv4_netids[i] != NULL; i++) {
		if (strcmp(ipv4_netids[i], config->nc_netid) == 0)
			return (1);
	}
	return (0);
}

/*
 * Public nametoaddr library interfaces.
 *
 * These are the functional entry points that libnsl will lookup (via
 * the symbol names) when it loads this nametoaddr translation library.
 */

/*
 * _netdir_getbyname() returns all of the addresses for
 * a specified host and service.
 */
struct nd_addrlist *
_netdir_getbyname(struct netconfig *netconfigp,
    struct nd_hostserv *nd_hostservp)
{
	struct nd_addrlist	*rp = NULL;
	struct netbuf		*nbp = NULL;
	struct sockaddr_in	*sap = NULL;
	struct hostent		n2h_result;
	struct servent		n2s_result;
	char			*n2h_buf = NULL, *n2s_buf = NULL;
	int			h_errno, i, host_self = 0, r_count;
	int			n2h_count = 0, n2s_count = 0;

	lxt_debug("_netdir_getbyname: request recieved\n");

	/* Make sure this is an ipv4 request. */
	if (!netconfig_is_ipv4(netconfigp)) {
		_nderror = ND_BADARG;
		goto fail;
	}

	/* Allocate memory for the queries. */
	if (((n2h_buf = malloc(NSS_BUFLEN_HOSTS)) == NULL) ||
	    ((n2s_buf = malloc(NSS_BUFLEN_SERVICES)) == NULL))
		goto malloc_fail;

	/* Check if the host name specified is HOST_SELF. */
	if (strcmp(nd_hostservp->h_host, HOST_SELF) == 0)
		host_self = 1;

	/*
	 * If the hostname specified is HOST_SELF, the we're just
	 * just doing a service lookup so don't bother with trying
	 * to lookup the host name.
	 */
	if (!host_self) {
		/* Resolve the hostname. */
		lxt_debug("_netdir_getbyname: "
		    "resolving host name: %s\n", nd_hostservp->h_host);
		if (lxt_gethostbyname_r(nd_hostservp->h_host, &n2h_result,
		    n2h_buf, NSS_BUFLEN_HOSTS, &h_errno) == NULL) {
			if (errno == ERANGE) {
				_nderror = ND_SYSTEM;
			} else if (h_errno == HOST_NOT_FOUND) {
				_nderror = ND_NOHOST;
			} else if (h_errno == TRY_AGAIN) {
				_nderror = ND_TRY_AGAIN;
			} else if (h_errno == NO_RECOVERY) {
				_nderror = ND_NO_RECOVERY;
			} else if (h_errno == NO_DATA) {
				_nderror = ND_NO_DATA;
			} else {
				_nderror = ND_SYSTEM;
			}
			goto fail;
		}
		while (n2h_result.h_addr_list[n2h_count++] != NULL);
		n2h_count--;
	}

	if (nd_hostservp->h_serv != NULL) {
		/* Resolve the service name */
		lxt_debug("_netdir_getbyname: "
		    "resolving service name: %s\n", nd_hostservp->h_serv);
		if (lxt_getservbyname_r(nd_hostservp->h_serv,
		    netconfigp->nc_proto, &n2s_result,
		    n2s_buf, NSS_BUFLEN_SERVICES) == NULL) {
			_nderror = ND_SYSTEM;
			goto fail;
		}
		n2s_count = 1;
	}

	/* Make sure we got some results. */
	if ((n2h_count + n2s_count) == 0) {
		lxt_debug("_netdir_getbyname: no results!\n");
		goto exit;
	}
	r_count = (n2h_count != 0) ? n2h_count : 1;

	/*
	 * Allocate the return buffers.  These buffers will be free'd
	 * by libnsl`netdir_free(), so we need to allocate them in the
	 * way that libnsl`netdir_free() expects.
	 */
	if (((rp = calloc(1, sizeof (struct nd_addrlist))) == NULL) ||
	    ((nbp = calloc(1, sizeof (struct netbuf) * r_count)) == NULL) ||
	    ((sap = calloc(1, sizeof (struct sockaddr_in) * r_count)) == NULL))
		goto malloc_fail;

	/* Initialize the structures we're going to return. */
	rp->n_cnt = r_count;
	rp->n_addrs = nbp;
	for (i = 0; i < r_count; i++) {

		/* Initialize the netbuf. */
		nbp[i].maxlen = nbp[i].len = sizeof (struct sockaddr_in);
		nbp[i].buf = (char *)&sap[i];

		/* Initialize the sockaddr_in. */
		sap[i].sin_family = AF_INET;

		/* If we looked up any host address copy them out. */
		if (!host_self)
			bcopy(n2h_result.h_addr_list[i], &sap[i].sin_addr,
			    sizeof (sap[i].sin_addr));

		/* If we looked up any service ports copy them out. */
		if (nd_hostservp->h_serv != NULL)
			sap[i].sin_port = n2s_result.s_port;
	}

	/* We're finally done. */
	lxt_debug("_netdir_getbyname: success\n");
	return (rp);

malloc_fail:
	_nderror = ND_NOMEM;

fail:
	lxt_debug("_netdir_getbyname: failed!\n");

exit:
	if (n2h_buf == NULL)
		free(n2h_buf);
	if (n2s_buf == NULL)
		free(n2s_buf);
	if (rp == NULL)
		free(rp);
	if (nbp == NULL)
		free(nbp);
	if (sap == NULL)
		free(sap);
	return (NULL);
}

/*
 * _netdir_getbyaddr() takes an address (hopefully obtained from
 * someone doing a _netdir_getbyname()) and returns all hosts with
 * that address.
 */
struct nd_hostservlist *
/*ARGSUSED*/
_netdir_getbyaddr(struct netconfig *netconfigp, struct netbuf *nbp)
{
	struct nd_hostservlist	*rp = NULL;
	struct nd_hostserv	*hsp = NULL;
	struct sockaddr_in	*sap;
	struct servent		p2s_result;
	struct hostent		a2h_result;
	char			*a2h_buf = NULL, *p2s_buf = NULL;
	int			h_errno, r_count, i;
	int			a2h_count = 0, p2s_count = 0;

	lxt_debug("_netdir_getbyaddr: request recieved\n");

	/* Make sure this is an ipv4 request. */
	if (!netconfig_is_ipv4(netconfigp)) {
		_nderror = ND_BADARG;
		goto fail;
	}

	/*
	 * Make sure the netbuf contains one struct sockaddr_in of
	 * type AF_INET.
	 */
	if ((nbp->len != sizeof (struct sockaddr_in)) ||
	    (nbp->len < nbp->maxlen)) {
		_nderror = ND_BADARG;
		goto fail;
	}
	/*LINTED*/
	sap = (struct sockaddr_in *)nbp->buf;
	if (sap->sin_family != AF_INET) {
		_nderror = ND_BADARG;
		goto fail;
	}

	/* Allocate memory for the queries. */
	if (((a2h_buf = malloc(NSS_BUFLEN_HOSTS)) == NULL) ||
	    ((p2s_buf = malloc(NSS_BUFLEN_SERVICES)) == NULL))
		goto malloc_fail;

	if (sap->sin_addr.s_addr != INADDR_ANY) {
		lxt_debug("_netdir_getbyaddr: "
		    "resolving host address: 0x%x\n", sap->sin_addr.s_addr);
		if (lxt_gethostbyaddr_r((char *)&sap->sin_addr.s_addr,
		    sizeof (sap->sin_addr.s_addr), AF_INET,
		    &a2h_result, a2h_buf, NSS_BUFLEN_HOSTS,
		    &h_errno) == NULL) {
			if (errno == ERANGE) {
				_nderror = ND_SYSTEM;
			} else if (h_errno == HOST_NOT_FOUND) {
				_nderror = ND_NOHOST;
			} else if (h_errno == TRY_AGAIN) {
				_nderror = ND_TRY_AGAIN;
			} else if (h_errno == NO_RECOVERY) {
				_nderror = ND_NO_RECOVERY;
			} else if (h_errno == NO_DATA) {
				_nderror = ND_NO_DATA;
			} else {
				_nderror = ND_SYSTEM;
			}
			goto fail;
		}
		while (a2h_result.h_aliases[a2h_count++] != NULL);
		/*
		 * We need to count a2h_result.h_name as a valid name for
		 * for the address we just looked up.  Of course a2h_count
		 * is actually over estimated by one, so instead of
		 * decrementing it here we'll just leave it as it to
		 * account for a2h_result.h_name.
		 */
	}

	if (sap->sin_port != 0) {
		lxt_debug("_netdir_getbyaddr: "
		    "resolving service port: 0x%x\n", sap->sin_port);
		if (lxt_getservbyport_r(sap->sin_port,
		    netconfigp->nc_proto, &p2s_result,
		    p2s_buf, NSS_BUFLEN_SERVICES) == NULL) {
			_nderror = ND_SYSTEM;
			goto fail;
		}
		p2s_count = 1;
	}

	/* Make sure we got some results. */
	if ((a2h_count + p2s_count) == 0) {
		lxt_debug("_netdir_getbyaddr: no results!\n");
		goto exit;
	}
	r_count = (a2h_count != 0) ? a2h_count : 1;

	/*
	 * Allocate the return buffers.  These buffers will be free'd
	 * by libnsl`netdir_free(), so we need to allocate them in the
	 * way that libnsl`netdir_free() expects.
	 */
	if (((rp = calloc(1, sizeof (struct nd_hostservlist))) == NULL) ||
	    ((hsp = calloc(1, sizeof (struct nd_hostserv) * r_count)) == NULL))
		goto malloc_fail;

	lxt_debug("_netdir_getbyaddr: hahaha0 - %d\n", r_count);
	rp->h_cnt = r_count;
	rp->h_hostservs = hsp;
	for (i = 0; i < r_count; i++) {
		/* If we looked up any host names copy them out. */
	lxt_debug("_netdir_getbyaddr: hahaha1 - %d\n", r_count);
		if ((a2h_count > 0) && (i == 0) &&
		    ((hsp[i].h_host = strdup(a2h_result.h_name)) == NULL))
			goto malloc_fail;

		if ((a2h_count > 0) && (i > 0) &&
		    ((hsp[i].h_host =
			    strdup(a2h_result.h_aliases[i - 1])) == NULL))
			goto malloc_fail;

	lxt_debug("_netdir_getbyaddr: hahaha2 - %d\n", r_count);
		/* If we looked up any service names copy them out. */
		if ((p2s_count > 0) &&
		    ((hsp[i].h_serv = strdup(p2s_result.s_name)) == NULL))
			goto malloc_fail;
	lxt_debug("_netdir_getbyaddr: hahaha3 - %d\n", r_count);
	}

	/* We're finally done. */
	lxt_debug("_netdir_getbyaddr: success\n");
	return (rp);

malloc_fail:
	_nderror = ND_NOMEM;

fail:
	lxt_debug("_netdir_getbyaddr: failed!\n");

exit:
	if (a2h_buf == NULL)
		free(a2h_buf);
	if (p2s_buf == NULL)
		free(p2s_buf);
	if (rp == NULL)
		free(rp);
	if (hsp != NULL) {
		for (i = 0; i < r_count; i++) {
			if (hsp[i].h_host != NULL)
				free(hsp[i].h_host);
			if (hsp[i].h_serv != NULL)
				free(hsp[i].h_serv);
		}
		free(hsp);
	}
	return (NULL);
}

char *
/* ARGSUSED */
_taddr2uaddr(struct netconfig *netconfigp, struct netbuf *nbp)
{
	extern char		*inet_ntoa_r();

	struct sockaddr_in	*sa;
	char			tmp[RPC_INET6_MAXUADDRSIZE];
	unsigned short		myport;

	if (netconfigp == NULL || nbp == NULL || nbp->buf == NULL) {
		_nderror = ND_BADARG;
		return (NULL);
	}

	if (strcmp(netconfigp->nc_protofmly, NC_INET) != 0) {
		/* we only support inet address translation */
		assert(0);
		_nderror = ND_SYSTEM;
		return (NULL);
	}

	/* LINTED pointer cast */
	sa = (struct sockaddr_in *)(nbp->buf);
	myport = ntohs(sa->sin_port);
	(void) inet_ntoa_r(sa->sin_addr, tmp);

	(void) sprintf(tmp + strlen(tmp), ".%d.%d",
	    myport >> 8, myport & 255);
	return (strdup(tmp));	/* Doesn't return static data ! */
}

/*
 * _uaddr2taddr() translates a universal address back into a
 * netaddr structure.  Since the universal address is a string,
 * put that into the TLI buffer (making sure to change all \ddd
 * characters back and strip off the trailing \0 character).
 */
struct netbuf *
/* ARGSUSED */
_uaddr2taddr(struct netconfig *netconfigp, char *uaddr)
{
	assert(0);
	_nderror = ND_SYSTEM;
	return (NULL);
}

/*
 * _netdir_options() is a "catch-all" routine that does
 * transport specific things.  The only thing that these
 * routines have to worry about is ND_MERGEADDR.
 */
int
/* ARGSUSED */
_netdir_options(struct netconfig *netconfigp, int option, int fd, void *par)
{
	assert(0);
	_nderror = ND_SYSTEM;
	return (0);
}
