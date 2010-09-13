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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miscl routines for RPC.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <sys/param.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <sys/resource.h>
#include <netconfig.h>
#include <malloc.h>
#include <syslog.h>
#include <string.h>
#include <sys/systeminfo.h>
#include <netdir.h>
#include <netdb.h>

struct handle {
	NCONF_HANDLE *nhandle;
	int nflag;		/* Whether NETPATH or NETCONFIG */
	int nettype;
};

struct _rpcnettype {
	const char *name;
	const int type;
} _rpctypelist[] = {
	"netpath", _RPC_NETPATH,
	"visible", _RPC_VISIBLE,
	"circuit_v", _RPC_CIRCUIT_V,
	"datagram_v", _RPC_DATAGRAM_V,
	"circuit_n", _RPC_CIRCUIT_N,
	"datagram_n", _RPC_DATAGRAM_N,
	"tcp", _RPC_TCP,
	"udp", _RPC_UDP,
	"local", _RPC_LOCAL,
	"door", _RPC_DOOR,
	"door_local", _RPC_DOOR_LOCAL,
	"door_netpath", _RPC_DOOR_NETPATH,
	0, _RPC_NONE
};

/*
 * Cache the result of getrlimit(), so we don't have to do an
 * expensive call every time. Since many old programs assume
 * it will not return more than 1024 and use svc_fdset, return
 * maximum of FD_SETSIZE.
 */
int
__rpc_dtbsize(void)
{
	static int tbsize;
	struct rlimit rl;

	if (tbsize)
		return (tbsize);
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		tbsize = rl.rlim_max;
		/*
		 * backward compatibility; too many places
		 * this function is called assuming it returns
		 * maximum of 1024.
		 */
		if (tbsize > FD_SETSIZE)
			tbsize = FD_SETSIZE;
		return (tbsize);
	}
	/*
	 * Something wrong.  I'll try to save face by returning a
	 * pessimistic number.
	 */
	return (32);
}

/*
 * Find the appropriate buffer size
 */
uint_t
__rpc_get_t_size(
	t_scalar_t size,	/* Size requested */
	t_scalar_t bufsize)	/* Supported by the transport */
{
	if (bufsize == -2)	/* transfer of data unsupported */
		return ((uint_t)0);
	if (size == 0) {
		if ((bufsize == -1) || (bufsize == 0)) {
			/*
			 * bufsize == -1 : No limit on the size
			 * bufsize == 0 : Concept of tsdu foreign. Choose
			 *			a value.
			 */
			return ((uint_t)RPC_MAXDATASIZE);
		}
		return ((uint_t)bufsize);
	}
	if ((bufsize == -1) || (bufsize == 0))
		return ((uint_t)size);
	/* Check whether the value is within the upper max limit */
	return (size > bufsize ? (uint_t)bufsize : (uint_t)size);
}

/*
 * Find the appropriate address buffer size
 */
uint_t
__rpc_get_a_size(
	t_scalar_t size)	/* normally tinfo.addr */
{
	if (size >= 0)
		return ((uint_t)size);
	if (size <= -2)
		return ((uint_t)0);
	/*
	 * (size == -1) No limit on the size. we impose a limit here.
	 */
	return ((uint_t)RPC_MAXADDRSIZE);
}

/*
 * Returns the type of the network as defined in <rpc/nettype.h>
 * If nettype is NULL, it defaults to NETPATH.
 */
static int
getnettype(const char *nettype)
{
	int i;

	if ((nettype == NULL) || (nettype[0] == NULL))
		return (_RPC_NETPATH);	/* Default */

	for (i = 0; _rpctypelist[i].name; i++)
		if (strcasecmp(nettype, _rpctypelist[i].name) == 0)
			return (_rpctypelist[i].type);
	return (_rpctypelist[i].type);
}

/*
 * For the given nettype (tcp or udp only), return the first structure found.
 * This should be freed by calling freenetconfigent()
 */
struct netconfig *
__rpc_getconfip(char *nettype)
{
	char *netid;
	char *netid_tcp;
	char *netid_udp;
	static char *netid_tcp_main = NULL;
	static char *netid_udp_main = NULL;
	static pthread_key_t tcp_key = PTHREAD_ONCE_KEY_NP;
	static pthread_key_t udp_key = PTHREAD_ONCE_KEY_NP;
	int main_thread;

	if ((main_thread = thr_main())) {
		netid_udp = netid_udp_main;
		netid_tcp = netid_tcp_main;
	} else {
		(void) pthread_key_create_once_np(&tcp_key, free);
		netid_tcp = pthread_getspecific(tcp_key);
		(void) pthread_key_create_once_np(&udp_key, free);
		netid_udp = pthread_getspecific(udp_key);
	}
	if (!netid_udp && !netid_tcp) {
		struct netconfig *nconf;
		void *confighandle;

		if (!(confighandle = setnetconfig()))
			return (NULL);
		while (nconf = getnetconfig(confighandle)) {
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
				if (strcmp(nconf->nc_proto, NC_TCP) == 0) {
					netid_tcp = strdup(nconf->nc_netid);
					if (netid_tcp == NULL) {
						syslog(LOG_ERR,
							"__rpc_getconfip : "
							"strdup failed");
						return (NULL);
					}
					if (main_thread)
						netid_tcp_main = netid_tcp;
					else
						(void) pthread_setspecific(
							tcp_key,
							(void *)netid_tcp);
				} else
				if (strcmp(nconf->nc_proto, NC_UDP) == 0) {
					netid_udp = strdup(nconf->nc_netid);
					if (netid_udp == NULL) {
						syslog(LOG_ERR,
							"__rpc_getconfip : "
							"strdup failed");
						return (NULL);
					}
					if (main_thread)
						netid_udp_main = netid_udp;
					else
						(void) pthread_setspecific(
							udp_key,
							(void *)netid_udp);
				}
			}
		}
		(void) endnetconfig(confighandle);
	}
	if (strcmp(nettype, "udp") == 0)
		netid = netid_udp;
	else if (strcmp(nettype, "tcp") == 0)
		netid = netid_tcp;
	else
		return (NULL);
	if ((netid == NULL) || (netid[0] == NULL))
		return (NULL);
	return (getnetconfigent(netid));
}


/*
 * Returns the type of the nettype, which should then be used with
 * __rpc_getconf().
 */
void *
__rpc_setconf(char *nettype)
{
	struct handle *handle;

	handle = malloc(sizeof (struct handle));
	if (handle == NULL)
		return (NULL);
	switch (handle->nettype = getnettype(nettype)) {
	case _RPC_DOOR_NETPATH:
	case _RPC_NETPATH:
	case _RPC_CIRCUIT_N:
	case _RPC_DATAGRAM_N:
		if (!(handle->nhandle = setnetpath())) {
			free(handle);
			return (NULL);
		}
		handle->nflag = TRUE;
		break;
	case _RPC_VISIBLE:
	case _RPC_CIRCUIT_V:
	case _RPC_DATAGRAM_V:
	case _RPC_TCP:
	case _RPC_UDP:
	case _RPC_LOCAL:
	case _RPC_DOOR_LOCAL:
		if (!(handle->nhandle = setnetconfig())) {
			free(handle);
			return (NULL);
		}
		handle->nflag = FALSE;
		break;
	default:
		free(handle);
		return (NULL);
	}

	return (handle);
}

/*
 * Returns the next netconfig struct for the given "net" type.
 * __rpc_setconf() should have been called previously.
 */
struct netconfig *
__rpc_getconf(void *vhandle)
{
	struct handle *handle;
	struct netconfig *nconf;

	handle = (struct handle *)vhandle;
	if (handle == NULL)
		return (NULL);
	for (;;) {
		if (handle->nflag)
			nconf = getnetpath(handle->nhandle);
		else
			nconf = getnetconfig(handle->nhandle);
		if (nconf == NULL)
			break;
		if ((nconf->nc_semantics != NC_TPI_CLTS) &&
		    (nconf->nc_semantics != NC_TPI_COTS) &&
		    (nconf->nc_semantics != NC_TPI_COTS_ORD))
			continue;
		switch (handle->nettype) {
		case _RPC_VISIBLE:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			/*FALLTHROUGH*/
		case _RPC_DOOR_NETPATH:
			/*FALLTHROUGH*/
		case _RPC_NETPATH:	/* Be happy */
			break;
		case _RPC_CIRCUIT_V:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			/*FALLTHROUGH*/
		case _RPC_CIRCUIT_N:
			if ((nconf->nc_semantics != NC_TPI_COTS) &&
			    (nconf->nc_semantics != NC_TPI_COTS_ORD))
				continue;
			break;
		case _RPC_DATAGRAM_V:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			/*FALLTHROUGH*/
		case _RPC_DATAGRAM_N:
			if (nconf->nc_semantics != NC_TPI_CLTS)
				continue;
			break;
		case _RPC_TCP:
			if (((nconf->nc_semantics != NC_TPI_COTS) &&
			    (nconf->nc_semantics != NC_TPI_COTS_ORD)) ||
			    (strcmp(nconf->nc_protofmly, NC_INET) &&
			    strcmp(nconf->nc_protofmly, NC_INET6)) ||
			    strcmp(nconf->nc_proto, NC_TCP))
				continue;
			break;
		case _RPC_UDP:
			if ((nconf->nc_semantics != NC_TPI_CLTS) ||
			    (strcmp(nconf->nc_protofmly, NC_INET) &&
			    strcmp(nconf->nc_protofmly, NC_INET6)) ||
			    strcmp(nconf->nc_proto, NC_UDP))
				continue;
			break;
		case _RPC_LOCAL:
		case _RPC_DOOR_LOCAL:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			if (strcmp(nconf->nc_protofmly, NC_LOOPBACK))
				continue;
			break;
		}
		break;
	}
	return (nconf);
}

void
__rpc_endconf(void *vhandle)
{
	struct handle *handle;

	handle = (struct handle *)vhandle;
	if (handle == NULL)
		return;
	if (handle->nflag) {
		(void) endnetpath(handle->nhandle);
	} else {
		(void) endnetconfig(handle->nhandle);
	}
	free(handle);
}

/*
 * Used to ping the NULL procedure for clnt handle.
 * Returns NULL if fails, else a non-NULL pointer.
 */
void *
rpc_nullproc(CLIENT *clnt)
{
	struct timeval TIMEOUT = {25, 0};

	if (clnt_call(clnt, NULLPROC, (xdrproc_t)xdr_void, NULL,
			(xdrproc_t)xdr_void, NULL, TIMEOUT) != RPC_SUCCESS)
		return (NULL);
	return ((void *)clnt);
}

/*
 * Given a fd, find the transport device it is using and return the
 * netconf entry corresponding to it.
 * Note: It assumes servtpe parameter is 0 when uninitialized.
 *	That is true for xprt->xp_type field.
 */
struct netconfig *
__rpcfd_to_nconf(int fd, int servtype)
{
	struct stat statbuf;
	void *hndl;
	struct netconfig *nconf, *newnconf = NULL;
	major_t fdmajor;
	struct t_info tinfo;

	if (fstat(fd, &statbuf) == -1)
		return (NULL);

	fdmajor = major(statbuf.st_rdev);
	if (servtype == 0) {
		if (t_getinfo(fd, &tinfo) == -1) {
			char errorstr[100];

			__tli_sys_strerror(errorstr, sizeof (errorstr),
					t_errno, errno);
			(void) syslog(LOG_ERR, "__rpcfd_to_nconf : %s : %s",
					"could not get transport information",
					errorstr);
			return (NULL);
		}
		servtype = tinfo.servtype;
	}

	hndl = setnetconfig();
	if (hndl == NULL)
		return (NULL);
	/*
	 * Go through all transports listed in /etc/netconfig looking for
	 *	transport device in use on fd.
	 * - Match on service type first
	 * - if that succeeds, match on major numbers (used for new local
	 *	transport code that is self cloning)
	 * - if that fails, assume transport device uses clone driver
	 *	and try match the fdmajor with minor number of device path
	 *	which will be the major number of transport device since it
	 *	uses the clone driver.
	 */

	while (nconf = getnetconfig(hndl)) {
		if (__rpc_matchserv(servtype, nconf->nc_semantics) == TRUE) {
			if (!stat(nconf->nc_device, &statbuf)) {
				if (fdmajor == major(statbuf.st_rdev))
					break; /* self cloning driver ? */
				if (fdmajor == minor(statbuf.st_rdev))
					break; /* clone driver! */
			}
		}
	}
	if (nconf)
		newnconf = getnetconfigent(nconf->nc_netid);
	(void) endnetconfig(hndl);
	return (newnconf);
}

int
__rpc_matchserv(int servtype, unsigned int nc_semantics)
{
	switch (servtype) {
	case T_COTS:
		if (nc_semantics == NC_TPI_COTS)
			return (TRUE);
		break;

	case T_COTS_ORD:
		if (nc_semantics == NC_TPI_COTS_ORD)
			return (TRUE);
		break;

	case T_CLTS:
		if (nc_semantics == NC_TPI_CLTS)
			return (TRUE);
		break;

	default:
		/* FALSE! */
		break;

	}
	return (FALSE);
}

/*
 * Routines for RPC/Doors support.
 */

extern bool_t __inet_netdir_is_my_host(const char *);

bool_t
__rpc_is_local_host(const char *host)
{
	char	buf[MAXHOSTNAMELEN + 1];

	if (host == NULL || strcmp(host, "localhost") == 0 ||
			strcmp(host, HOST_SELF) == 0 ||
			strcmp(host, HOST_SELF_CONNECT) == 0 ||
			strlen(host) == 0)
		return (TRUE);
	if (sysinfo(SI_HOSTNAME, buf, sizeof (buf)) < 0)
		return (FALSE);
	if (strcmp(host, buf) == 0)
		return (TRUE);
	return (__inet_netdir_is_my_host(host));
}

bool_t
__rpc_try_doors(const char *nettype, bool_t *try_others)
{
	switch (getnettype(nettype)) {
	case _RPC_DOOR:
		*try_others = FALSE;
		return (TRUE);
	case _RPC_DOOR_LOCAL:
	case _RPC_DOOR_NETPATH:
		*try_others = TRUE;
		return (TRUE);
	default:
		*try_others = TRUE;
		return (FALSE);
	}
}
