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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef PORTMAP

/*
 * interface to pmap rpc service.
 */
#include "mt.h"
#include "rpc_mt.h"
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <netdir.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_rmt.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int use_portmapper = 0;
static const struct timeval timeout = { 5, 0 };
static const struct timeval tottimeout = { 60, 0 };
static const struct timeval rmttimeout = { 3, 0 };

/*
 * Solaris hasn't trully supported local portmappers since Solaris 2.4.
 *
 * In Solaris 2.0 the portmapper was replaced with rpcbind.  Essentially
 * rpcbind implements version 3 of the portmapper protocol.  (The last
 * version of the portmapper protocol while it was still called
 * portmap was version 2.)  The rpcbind protocol provides a lot
 * of improvements over the portmap protocol.  (Like the ability
 * to bind to non AF_INET transports like TLI and to unregister
 * individual transport providers instead of entire serivices.)
 *
 * So in Solaris 2.0 the portmapper was replace with rpcbind, but it
 * wasn't until Solaris 2.5 that all the local portmapper code was
 * modified to assume that the local processes managing rpc services
 * always supported the rpcbind protocol.  When this happened all the
 * local portmap registration code was enhanced to translated any
 * portmapper requests into rpcbind requests.  This is a fine assumption
 * for Solaris where we always have control over the local
 * portmapper/rpcbind service and we can make sure that it always
 * understands the rpcbind protocol.
 *
 * But this is a problem for BrandZ.  In BrandZ we don't have contol over
 * what local portmapper is running.  (Unless we want to replace it.)
 * In the Linux case, current Linux distributions don't support the
 * rpcbind protocol, instead they support the old portmapper protocol
 * (verison 2.)  So to allow Solaris services to register with the
 * Linux portmapper (which we need to support to allow us to run the
 * native NFS daemons) there are two things that need to be done.
 *
 * - The classic interfaces for registering services with the version 2
 *   portmapper is via pmap_set() and pmap_unset().  In Solaris 2.5 these
 *   functions were changed to translate portmap requests into rpcbind
 *   requests.  These interfaces need to be enhanced so that if we're
 *   trying to register with a portmapper instead of rpcbind, we don't
 *   translate the requests to rpcbind requests.
 *
 * - Libnsl provides lots of interfaces to simplify the creation of rpc
 *   services (see rpc_svc_*).  Internally, the interfaces all assume
 *   that the local process that manages rpc services support the rpcbind
 *   protocol.  To avoid having to update all rpc services that use these
 *   functions to be portmapper aware, we need to enhance these functions
 *   to support the portmapper protocol in addition to rpcbind.
 *
 * To address both these requirements we've introduced three key functions.
 *
 * 	__pmap_set() - Registers services using the portmapper version 2
 * 		protocol.  (Behaves like the Pre-Solaris 2.5 pmap_set())
 *
 * 	__pmap_unset() - Unregisters services using the portmapper version 2
 * 		protocol.  (Behaves like the Pre-Solaris 2.5 pmap_unset())
 *
 * 	__use_portmapper() - Tells libnsl if the local system expects
 * 		the portmapper protocol versus the rpcbind protocol.
 *
 * 		If an rpc program uses this interface to tell libnsl
 * 		that it want's to use portmap based services instead of
 * 		rpcbind based services, then libnsl will internally
 * 		replace attempts to register services via rpcbind
 * 		with portmap.
 */

static CLIENT *
pmap_common(const struct netconfig *nconf, int *socket)
{
	struct sockaddr_in	sa_local;
	CLIENT			*client;

	/* we only support tcp and udp */
	if ((nconf != NULL) &&
	    (strcmp(nconf->nc_netid, "udp") != 0) &&
	    (strcmp(nconf->nc_netid, "tcp") != 0))
		return (NULL);

	/* try connecting to the portmapper via udp */
	get_myaddress(&sa_local);
	client = clntudp_bufcreate(&sa_local, PMAPPROG, PMAPVERS,
	    timeout, socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
	if (client == NULL) {
		/* try connecting to the portmapper via tcp */
		client = clnttcp_create(&sa_local, PMAPPROG, PMAPVERS,
		    socket, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
		if (client == NULL)
			return (NULL);
	}

	return (client);
}

void
__use_portmapper(int p)
{
	use_portmapper = p;
}

/*
 * Set a mapping between program, version and address.
 * Calls the portmapper service to do the mapping.
 */
bool_t
__pmap_set(const rpcprog_t program, const rpcvers_t version,
		const struct netconfig *nconf, const struct netbuf *address)
{
	struct sockaddr_in	*sa;
	struct pmap		parms;
	CLIENT			*client;
	bool_t			rslt;
	int			socket = RPC_ANYSOCK;

	/* address better be a sockaddr_in struct */
	if (address == NULL)
		return (FALSE);
	if (address->len != sizeof (struct sockaddr_in))
		return (FALSE);

	/* get a connection to the portmapper */
	if (nconf == NULL)
		return (FALSE);
	if ((client = pmap_common(nconf, &socket)) == NULL)
		return (FALSE);

	/* LINTED pointer cast */
	sa = (struct sockaddr_in *)(address->buf);

	/* initialize the portmapper request */
	parms.pm_prog = program;
	parms.pm_vers = version;
	parms.pm_port = ntohs(sa->sin_port);
	parms.pm_prot =
	    (strcmp(nconf->nc_netid, "udp") == 0) ? IPPROTO_UDP : IPPROTO_TCP;

	/* make the call */
	if (CLNT_CALL(client, PMAPPROC_SET, xdr_pmap, (caddr_t)&parms,
	    xdr_bool, (char *)&rslt, tottimeout) != RPC_SUCCESS)
		rslt = FALSE;

	CLNT_DESTROY(client);
	(void) close(socket);
	return (rslt);
}

/*
 * Remove the mapping between program, version and port.
 * Calls the portmapper service remotely to do the un-mapping.
 */
bool_t
__pmap_unset(const rpcprog_t program, const rpcvers_t version)
{
	struct pmap		parms;
	CLIENT			*client;
	bool_t			rslt;
	int			socket = RPC_ANYSOCK;

	/* get a connection to the portmapper */
	if ((client = pmap_common(NULL, &socket)) == NULL)
		return (FALSE);

	/* initialize the portmapper request */
	parms.pm_prog = program;
	parms.pm_vers = version;
	parms.pm_port = 0;
	parms.pm_prot = 0;

	/* make the call */
	CLNT_CALL(client, PMAPPROC_UNSET, xdr_pmap, (caddr_t)&parms,
	    xdr_bool, (char *)&rslt, tottimeout);
	CLNT_DESTROY(client);
	(void) close(socket);
	return (rslt);
}

/*
 * Set a mapping between program, version and port.
 * Calls the pmap service remotely to do the mapping.
 */
bool_t
pmap_set(rpcprog_t program, rpcvers_t version, rpcprot_t protocol,
								ushort_t port)
{
	bool_t rslt;
	struct netbuf *na;
	struct netconfig *nconf;
	char buf[32];

	if ((protocol != IPPROTO_UDP) && (protocol != IPPROTO_TCP))
		return (FALSE);
	nconf = __rpc_getconfip(protocol == IPPROTO_UDP ? "udp" : "tcp");
	if (!nconf)
		return (FALSE);
	(void) sprintf(buf, "0.0.0.0.%d.%d", port >> 8 & 0xff, port & 0xff);
	na = uaddr2taddr(nconf, buf);
	if (!na) {
		freenetconfigent(nconf);
		return (FALSE);
	}
	if (!use_portmapper)
		rslt = rpcb_set(program, version, nconf, na);
	else
		rslt = __pmap_set(program, version, nconf, na);
	netdir_free((char *)na, ND_ADDR);
	freenetconfigent(nconf);
	return (rslt);
}

/*
 * Remove the mapping between program, version and port.
 * Calls the pmap service remotely to do the un-mapping.
 */
bool_t
pmap_unset(rpcprog_t program, rpcvers_t version)
{
	struct netconfig *nconf;
	bool_t udp_rslt = FALSE;
	bool_t tcp_rslt = FALSE;

	if (use_portmapper)
		return (__pmap_unset(program, version));

	nconf = __rpc_getconfip("udp");
	if (nconf) {
		udp_rslt = rpcb_unset(program, version, nconf);
		freenetconfigent(nconf);
	}
	nconf = __rpc_getconfip("tcp");
	if (nconf) {
		tcp_rslt = rpcb_unset(program, version, nconf);
		freenetconfigent(nconf);
	}
	/*
	 * XXX: The call may still succeed even if only one of the
	 * calls succeeded.  This was the best that could be
	 * done for backward compatibility.
	 */
	return (tcp_rslt || udp_rslt);
}

/*
 * Find the mapped port for program, version.
 * Calls the pmap service remotely to do the lookup.
 * Returns 0 if no map exists.
 *
 * XXX: It talks only to the portmapper and not to the rpcbind
 * service.  There may be implementations out there which do not
 * run portmapper as a part of rpcbind.
 */
ushort_t
pmap_getport(struct sockaddr_in *address, rpcprog_t program,
					rpcvers_t version, rpcprot_t protocol)
{
	ushort_t port = 0;
	int fd = RPC_ANYFD;
	CLIENT *client;
	struct pmap parms;

	address->sin_port = htons(PMAPPORT);
	client = clntudp_bufcreate(address, PMAPPROG, PMAPVERS, timeout,
				&fd, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
	if (client != NULL) {
		parms.pm_prog = program;
		parms.pm_vers = version;
		parms.pm_prot = protocol;
		parms.pm_port = 0;	/* not needed or used */
		if (CLNT_CALL(client, PMAPPROC_GETPORT, (xdrproc_t)xdr_pmap,
			    (caddr_t)&parms, (xdrproc_t)xdr_u_short,
			    (caddr_t)&port, tottimeout) != RPC_SUCCESS) {
			rpc_createerr.cf_stat = RPC_PMAPFAILURE;
			clnt_geterr(client, &rpc_createerr.cf_error);
		} else if (port == 0) {
			rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
		}
		CLNT_DESTROY(client);
	}
	address->sin_port = 0;
	return (port);
}

/*
 * Get a copy of the current port maps.
 * Calls the pmap service remotely to do get the maps.
 */
struct pmaplist *
pmap_getmaps(struct sockaddr_in *address)
{
	pmaplist_ptr head = NULL;
	int fd = RPC_ANYFD;
	struct timeval minutetimeout;
	CLIENT *client;

	minutetimeout.tv_sec = 60;
	minutetimeout.tv_usec = 0;
	address->sin_port = htons(PMAPPORT);
	client = clnttcp_create(address, PMAPPROG, PMAPVERS, &fd, 50, 500);
	if (client != NULL) {
		if (CLNT_CALL(client, PMAPPROC_DUMP, (xdrproc_t)xdr_void,
			    NULL, (xdrproc_t)xdr_pmaplist_ptr,
			    (caddr_t)&head, minutetimeout) != RPC_SUCCESS) {
			(void) syslog(LOG_ERR, "%s",
			clnt_sperror(client, "pmap_getmaps rpc problem"));
		}
		CLNT_DESTROY(client);
	}
	address->sin_port = 0;
	return ((struct pmaplist *)head);
}

/*
 * pmapper remote-call-service interface.
 * This routine is used to call the pmapper remote call service
 * which will look up a service program in the port maps, and then
 * remotely call that routine with the given parameters. This allows
 * programs to do a lookup and call in one step.
 */
enum clnt_stat
pmap_rmtcall(struct sockaddr_in *addr, rpcprog_t prog, rpcvers_t vers,
	rpcproc_t proc, xdrproc_t xdrargs, caddr_t argsp, xdrproc_t xdrres,
	caddr_t resp, struct timeval tout, rpcport_t *port_ptr)
{
	int fd = RPC_ANYFD;
	CLIENT *client;
	struct p_rmtcallargs a;
	struct p_rmtcallres r;
	enum clnt_stat stat;
	short tmp = addr->sin_port;

	addr->sin_port = htons(PMAPPORT);
	client = clntudp_create(addr, PMAPPROG, PMAPVERS, rmttimeout, &fd);
	if (client != NULL) {
		a.prog = prog;
		a.vers = vers;
		a.proc = proc;
		a.args.args_val = argsp;
		a.xdr_args = xdrargs;
		r.res.res_val = resp;
		r.xdr_res = xdrres;
		stat = CLNT_CALL(client, PMAPPROC_CALLIT,
				(xdrproc_t)xdr_rmtcallargs,
				(caddr_t)&a, (xdrproc_t)xdr_rmtcallres,
				(caddr_t)&r, tout);
		CLNT_DESTROY(client);
	} else {
		stat = RPC_FAILED;
	}
	addr->sin_port = tmp;
	*port_ptr = r.port;
	return (stat);
}

#endif /* PORTMAP */
