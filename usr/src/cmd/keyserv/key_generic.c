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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <rpc/rpc.h>
#include <errno.h>
#ifdef SYSLOG
#include <sys/syslog.h>
#else
#define	LOG_ERR 3
#endif				/* SYSLOG */
#include <rpc/nettype.h>
#include <netconfig.h>
#include <netdir.h>

extern char *strdup();

/*
 * The highest level interface for server creation.
 * It tries for all the nettokens in that particular class of token
 * and returns the number of handles it can create and/or find.
 *
 * It creates a link list of all the handles it could create.
 * If svc_create() is called multiple times, it uses the handle
 * created earlier instead of creating a new handle every time.
 *
 * Copied from svc_generic.c
 */
int
svc_create_local_service(dispatch, prognum, versnum, nettype, servname)
void (*dispatch) ();		/* Dispatch function */
ulong_t prognum;			/* Program number */
ulong_t versnum;			/* Version number */
char *nettype;			/* Networktype token */
char *servname;			/* name of the service */
{
	struct xlist {
		SVCXPRT *xprt;		/* Server handle */
		struct xlist *next;	/* Next item */
	} *l;
	static struct xlist *xprtlist;
	int num = 0;
	SVCXPRT *xprt;
	struct netconfig *nconf;
	struct t_bind *bind_addr;
	void *handle;
	int fd;
	struct nd_hostserv ns;
	struct nd_addrlist *nas;

	if ((handle = __rpc_setconf(nettype)) == NULL) {
		(void) syslog(LOG_ERR,
		"svc_create: could not read netconfig database");
		return (0);
	}
	while (nconf = __rpc_getconf(handle)) {
		if (strcmp(nconf->nc_protofmly, NC_LOOPBACK))
			continue;
		for (l = xprtlist; l; l = l->next) {
			if (strcmp(l->xprt->xp_netid, nconf->nc_netid) == 0) {
				/* Found an  old  one,  use  it */
				(void) rpcb_unset(prognum, versnum, nconf);
				if (svc_reg(l->xprt, prognum, versnum,
					dispatch, nconf) == FALSE)
					(void) syslog(LOG_ERR,
	    "svc_create: could not register prog %d vers %d on %s",
					    prognum, versnum, nconf->nc_netid);
				else
					num++;
				break;
			}
		}
		if (l)
			continue;
		/* It was not found. Now create a new one */
		if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) < 0) {
			syslog(LOG_ERR,
		"svc_create: %s: cannot open connection: %s",
			    nconf->nc_netid, t_errlist[t_errno]);
			continue;
		}

		/*
		 * Negotiate for returning the uid of the caller.
		 * This should be done before enabling the endpoint for
		 * service via t_bind() (called in svc_tli_create())
		 * so that requests to keyserv contain the uid.
		 */
		if (__rpc_negotiate_uid(fd) != 0) {
			syslog(LOG_ERR,
			"Couldn't negotiate for uid with loopback transport %s",
				nconf->nc_netid);
			t_close(fd);
			continue;
		}

		bind_addr = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR);
		if ((bind_addr == NULL)) {
			t_close(fd);
			(void) syslog(LOG_ERR, "svc_create: t_alloc failed\n");
			continue;
		}
		ns.h_host = HOST_SELF;
		ns.h_serv = servname;
		if (!netdir_getbyname(nconf, &ns, &nas)) {
			/* Copy the address */
			bind_addr->addr.len = nas->n_addrs->len;
			memcpy(bind_addr->addr.buf, nas->n_addrs->buf,
				(int)nas->n_addrs->len);
			bind_addr->qlen = 8;
			netdir_free((char *)nas, ND_ADDRLIST);
		} else {
			syslog(LOG_ERR,
	"svc_create: no well known address for %s on transport %s",
			    servname, nconf->nc_netid);
			(void) t_free((char *)bind_addr, T_BIND);
			bind_addr = NULL;
		}

		xprt = svc_tli_create(fd, nconf, bind_addr, 0, 0);
		if (bind_addr)
			(void) t_free((char *)bind_addr, T_BIND);
		if (xprt) {
			(void) rpcb_unset(prognum, versnum, nconf);
			if (svc_reg(xprt, prognum, versnum,
				dispatch, nconf) == FALSE) {
				(void) syslog(LOG_ERR,
	    "svc_create: could not register prog %d vers %d on %s",
				    prognum, versnum, nconf->nc_netid);
				SVC_DESTROY(xprt);
				continue;
			}
			l = (struct xlist *)malloc(sizeof (struct xlist));
			if (l == (struct xlist *)NULL) {
				(void) syslog(LOG_ERR,
					    "svc_create: no memory");
				SVC_DESTROY(xprt);
				return (num);
			}
			l->xprt = xprt;
			l->next = xprtlist;
			xprtlist = l;
			num++;
		}
	}
	__rpc_endconf(handle);
	return (num);
}
