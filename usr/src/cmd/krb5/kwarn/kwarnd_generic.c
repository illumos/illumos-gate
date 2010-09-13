/*
 * Copyright (c) 1988-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <syslog.h>
#include <rpc/nettype.h>
#include <netconfig.h>
#include <netdir.h>
#include <tiuser.h>
#include <fcntl.h>
#include <string.h>
#include <rpc/svc.h>
#include <locale.h>

extern int __rpc_negotiate_uid(int);

/*
 * The highest level interface for server creation.
 * Copied from svc_generic.c and cmd/keyserv/key_generic.c, but adapted
 * to work only for TPI_CLTS semantics, and to be called only once
 * from kwarnd.c. Returns 1 (interface created) on success and 0
 * (no interfaces created) on failure.
 */
int
svc_create_local_service(void (*dispatch) (),		/* Dispatch function */
			u_long prognum,			/* Program number */
			u_long versnum,			/* Version number */
			char *nettype,			/* Networktype token */
			char *servname)			/* name of the srvc */
{
	int num = 0;
	SVCXPRT *xprt;
	struct netconfig *nconf;
	struct t_bind *bind_addr;
	void *net;
	int fd;
	struct nd_hostserv ns;
	struct nd_addrlist *nas;

	if ((net = __rpc_setconf(nettype)) == 0) {
		(void) syslog(LOG_ERR,
		gettext("svc_create: could not read netconfig database"));
		return (0);
	}
	while (nconf = __rpc_getconf(net)) {
		if ((strcmp(nconf->nc_protofmly, NC_LOOPBACK)) ||
				(nconf->nc_semantics != NC_TPI_COTS_ORD))
			continue;

		if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) < 0) {
			(void) syslog(LOG_ERR,
			gettext("svc_create: %s: cannot open connection: %s"),
				nconf->nc_netid, t_errlist[t_errno]);
			break;
		}

		/*
		 * Negotiate for returning the uid of the caller.
		 * This should be done before enabling the endpoint for
		 * service via t_bind() (called in svc_tli_create())
		 * so that requests to kwarnd contain the uid.
		 */
		if (__rpc_negotiate_uid(fd) != 0) {
			syslog(LOG_ERR,
			gettext("Could not negotiate for"
				" uid with loopback transport %s"),
				nconf->nc_netid);
			t_close(fd);
			break;
		}

		/* LINTED pointer alignment */
		bind_addr = (struct t_bind *) t_alloc(fd, T_BIND, T_ADDR);
		if ((bind_addr == NULL)) {
			(void) t_close(fd);
			(void) syslog(LOG_ERR,
				gettext("svc_create: t_alloc failed\n"));
			break;
		}
		ns.h_host = HOST_SELF;
		ns.h_serv = servname;
		if (!netdir_getbyname(nconf, &ns, &nas)) {
			/* Copy the address */
			bind_addr->addr.len = nas->n_addrs->len;
			(void) memcpy(bind_addr->addr.buf, nas->n_addrs->buf,
				(int) nas->n_addrs->len);
			bind_addr->qlen = 8;
			netdir_free((char *) nas, ND_ADDRLIST);
		} else {
			(void) syslog(LOG_ERR,
			gettext("svc_create: no well known "
				"address for %s on %s\n"),
				servname, nconf->nc_netid);
			(void) t_free((char *) bind_addr, T_BIND);
			bind_addr = NULL;
		}

		xprt = svc_tli_create(fd, nconf, bind_addr, 0, 0);
		if (bind_addr)
			(void) t_free((char *) bind_addr, T_BIND);
		if (xprt == NULL) {
			(void) t_close(fd);
			(void) syslog(LOG_ERR,
			    gettext("svc_create: svc_tli_create failed\n"));
			break;
		} else {
			(void) rpcb_unset(prognum, versnum, nconf);
			if (svc_reg(xprt, prognum, versnum, dispatch, nconf)
					== FALSE) {
				(void) syslog(LOG_ERR,
				gettext("svc_create: cannot"
					" register %d vers %d on %s"),
					prognum, versnum, nconf->nc_netid);
				SVC_DESTROY(xprt);	/* also t_closes fd */
				break;
			}
			num = 1;
			break;
		}
	}
	__rpc_endconf(net);
	return (num);
}
