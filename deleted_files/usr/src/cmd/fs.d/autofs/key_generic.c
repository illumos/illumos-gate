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
 *	key_generic.c
 *
 *	Copyright (c) 1988-1996 Sun Microsystems Inc
 *	All Rights Reserved.
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
#include "automount.h"

#define	MAXCACHETIME 900

/*
 * The highest level interface for server creation.
 * Copied from svc_generic.c and ../keyserv/key_generic.c, but adapted
 * to work only for TPI_COTS_ORD semantics, and to be called only once
 * from autod_main.c. Returns 1 (interface created) on success and 0
 * (interfaces created) on failure.
 */
int
svc_create_local_service(dispatch, prognum, versnum, nettype, servname)
void (*dispatch) ();		/* Dispatch function */
u_long prognum;			/* Program number */
u_long versnum;			/* Version number */
char *nettype;			/* Networktype token */
char *servname;			/* name of the service */
{
	int num = 0;
	SVCXPRT *xprt;
	struct netconfig *nconf;
	struct t_bind *bind_addr;
	void *net;
	int fd;
	struct nd_hostserv ns;
	struct nd_addrlist *nas;
	time_t maxcachetime = MAXCACHETIME;

	if ((net = __rpc_setconf(nettype)) == 0) {
		(void) syslog(LOG_ERR,
		"svc_create: could not read netconfig database");
		return (0);
	}
	while (nconf = __rpc_getconf(net)) {
		if ((strcmp(nconf->nc_protofmly, NC_LOOPBACK)) ||
				(nconf->nc_semantics != NC_TPI_COTS_ORD))
			continue;

		if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) < 0) {
			(void) syslog(LOG_ERR,
			"svc_create: %s: cannot open connection: %s",
				nconf->nc_netid, t_errlist[t_errno]);
			return (0);
		}

		/*
		 * Negotiate for returning the uid of the caller.
		 * This should be done before enabling the endpoint for
		 * service via t_bind() (called in svc_tli_create())
		 * so that requests to automountd contain the uid.
		 */
		if (__rpc_negotiate_uid(fd) != 0) {
			syslog(LOG_ERR,
			"Couldn't negotiate for uid with loopback transport %s",
				nconf->nc_netid);
			t_close(fd);
			return (0);
		}

		/* LINTED pointer alignment */
		bind_addr = (struct t_bind *) t_alloc(fd, T_BIND, T_ADDR);
		if ((bind_addr == NULL)) {
			(void) t_close(fd);
			(void) syslog(LOG_ERR, "svc_create: t_alloc failed\n");
			return (0);
		}
		ns.h_host = HOST_SELF;
		ns.h_serv = servname;			/* autofs */
		if (!netdir_getbyname(nconf, &ns, &nas)) {
			/* Copy the address */
			bind_addr->addr.len = nas->n_addrs->len;
			(void) memcpy(bind_addr->addr.buf, nas->n_addrs->buf,
				(int) nas->n_addrs->len);
			bind_addr->qlen = 8;
			netdir_free((char *) nas, ND_ADDRLIST);
		} else {
			(void) syslog(LOG_ERR,
			"svc_create: no well known address for %s on %s\n",
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
			    "svc_create: svc_tli_create failed\n");
			return (0);
		} else {
			(void) rpcb_unset(prognum, versnum, nconf);
			if (svc_reg(xprt, prognum, versnum, dispatch, nconf)
					== FALSE) {
				(void) syslog(LOG_ERR,
				"svc_create: cannot register %d vers %d on %s",
					prognum, versnum, nconf->nc_netid);
				SVC_DESTROY(xprt);	/* also t_closes fd */
				return (0);
			}

			if (!__svc_vc_dupcache_init(xprt, (void *)&maxcachetime,
						DUPCACHE_FIXEDTIME)) {
				syslog(LOG_ERR,
					"svc_create: init dupcache failed");
				SVC_DESTROY(xprt);	/* also t_closes fd */
				return (0);
			}
			num = 1;
		}
		break;
	}
	__rpc_endconf(net);
	return (num);
}
