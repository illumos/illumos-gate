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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * svc_simple.c
 * Simplified front end to rpc.
 */

/*
 * This interface creates a virtual listener for all the services
 * started thru rpc_reg(). It listens on the same endpoint for
 * all the services and then executes the corresponding service
 * for the given prognum and procnum.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/rpc.h>
#include <sys/types.h>
#include <syslog.h>
#include <rpc/nettype.h>

static struct proglst {
	char *(*p_progname)();
	rpcprog_t p_prognum;
	rpcvers_t p_versnum;
	rpcproc_t p_procnum;
	SVCXPRT *p_transp;
	char *p_netid;
	char *p_xdrbuf;
	int p_recvsz;
	xdrproc_t p_inproc, p_outproc;
	struct proglst *p_nxt;
} *proglst;

static void universal();

static const char rpc_reg_err[] = "%s: %s";
static const char rpc_reg_msg[] = "rpc_reg: ";
static const char __reg_err1[] = "can't find appropriate transport";
static const char __reg_err3[] = "unsupported transport size";
static const char __no_mem_str[] = "out of memory";
/*
 * For simplified, easy to use kind of rpc interfaces.
 * nettype indicates the type of transport on which the service will be
 * listening. Used for conservation of the system resource. Only one
 * handle is created for all the services (actually one of each netid)
 * and same xdrbuf is used for same netid. The size of the arguments
 * is also limited by the recvsize for that transport, even if it is
 * a COTS transport. This may be wrong, but for cases like these, they
 * should not use the simplified interfaces like this.
 */

int
rpc_reg(const rpcprog_t prognum, const rpcvers_t versnum,
	const rpcproc_t procnum, char *(*progname)(), const xdrproc_t inproc,
	const xdrproc_t outproc, const char *nettype)
{
	struct netconfig *nconf;
	int done = FALSE;
	void *handle;
	extern mutex_t proglst_lock;

	if (procnum == NULLPROC) {
		(void) syslog(LOG_ERR, (const char *) "%s: %s %d",
			rpc_reg_msg,
			(const char *) "can't reassign procedure number %d",
			NULLPROC);
		return (-1);
	}

	if (nettype == NULL)
		nettype = "netpath";		/* The default behavior */
	if ((handle = __rpc_setconf((char *)nettype)) == NULL) {
		(void) syslog(LOG_ERR, rpc_reg_err, rpc_reg_msg, __reg_err1);
		return (-1);
	}
/* VARIABLES PROTECTED BY proglst_lock: proglst */
	(void) mutex_lock(&proglst_lock);
	while (nconf = __rpc_getconf(handle)) {
		struct proglst *pl;
		SVCXPRT *svcxprt;
		int madenow;
		uint_t recvsz;
		char *xdrbuf;
		char *netid;

		madenow = FALSE;
		svcxprt = NULL;
		for (pl = proglst; pl; pl = pl->p_nxt)
			if (strcmp(pl->p_netid, nconf->nc_netid) == 0) {
				svcxprt = pl->p_transp;
				xdrbuf = pl->p_xdrbuf;
				recvsz = pl->p_recvsz;
				netid = pl->p_netid;
				break;
			}

		if (svcxprt == NULL) {
			struct t_info tinfo;

			svcxprt = svc_tli_create(RPC_ANYFD, nconf, NULL, 0, 0);
			if (svcxprt == NULL)
				continue;
			if (t_getinfo(svcxprt->xp_fd, &tinfo) == -1) {
				char errorstr[100];

				__tli_sys_strerror(errorstr, sizeof (errorstr),
						t_errno, errno);
				(void) syslog(LOG_ERR, "%s : %s : %s",
					rpc_reg_msg, "t_getinfo failed",
					errorstr);
				SVC_DESTROY(svcxprt);
				continue;
			}
			if ((recvsz = __rpc_get_t_size(0, tinfo.tsdu)) == 0) {
				(void) syslog(LOG_ERR, rpc_reg_err, rpc_reg_msg,
					__reg_err3);
				SVC_DESTROY(svcxprt);
				continue;
			}
			if (((xdrbuf = malloc((unsigned)recvsz)) == NULL) ||
				((netid = strdup(nconf->nc_netid)) == NULL)) {
				(void) syslog(LOG_ERR, rpc_reg_err, rpc_reg_msg,
					__no_mem_str);
				SVC_DESTROY(svcxprt);
				break;
			}
			madenow = TRUE;
		}
		/*
		 * Check if this (program, version, netid) had already been
		 * registered.  The check may save a few RPC calls to rpcbind
		 */
		for (pl = proglst; pl; pl = pl->p_nxt)
			if ((pl->p_prognum == prognum) &&
				(pl->p_versnum == versnum) &&
				(strcmp(pl->p_netid, netid) == 0))
				break;
		if (pl == NULL) { /* Not yet */
			(void) rpcb_unset(prognum, versnum, nconf);
		} else {
			/* so that svc_reg does not call rpcb_set() */
			nconf = NULL;
		}

		if (!svc_reg(svcxprt, prognum, versnum, universal, nconf)) {
			(void) syslog(LOG_ERR,
				"%s couldn't register prog %d vers %d for %s",
				rpc_reg_msg, prognum, versnum, netid);
			if (madenow) {
				SVC_DESTROY(svcxprt);
				free(xdrbuf);
				free(netid);
			}
			continue;
		}

		pl = malloc(sizeof (struct proglst));
		if (pl == NULL) {
			(void) syslog(LOG_ERR, rpc_reg_err, rpc_reg_msg,
					__no_mem_str);
			if (madenow) {
				SVC_DESTROY(svcxprt);
				free(xdrbuf);
				free(netid);
			}
			break;
		}
		pl->p_progname = progname;
		pl->p_prognum = prognum;
		pl->p_versnum = versnum;
		pl->p_procnum = procnum;
		pl->p_inproc = inproc;
		pl->p_outproc = outproc;
		pl->p_transp = svcxprt;
		pl->p_xdrbuf = xdrbuf;
		pl->p_recvsz = recvsz;
		pl->p_netid = netid;
		pl->p_nxt = proglst;
		proglst = pl;
		done = TRUE;
	}
	__rpc_endconf(handle);
	(void) mutex_unlock(&proglst_lock);

	if (done == FALSE) {
		(void) syslog(LOG_ERR,
			(const char *) "%s cant find suitable transport for %s",
			rpc_reg_msg, nettype);
		return (-1);
	}
	return (0);
}

/*
 * The universal handler for the services registered using registerrpc.
 * It handles both the connectionless and the connection oriented cases.
 */

static void
universal(struct svc_req *rqstp, SVCXPRT *transp)
{
	rpcprog_t prog;
	rpcvers_t vers;
	rpcproc_t proc;
	char *outdata;
	char *xdrbuf;
	struct proglst *pl;
	extern mutex_t proglst_lock;

	/*
	 * enforce "procnum 0 is echo" convention
	 */
	if (rqstp->rq_proc == NULLPROC) {
		if (svc_sendreply(transp, (xdrproc_t)xdr_void, NULL) == FALSE) {
			(void) syslog(LOG_ERR,
				(const char *) "svc_sendreply failed");
		}
		return;
	}
	prog = rqstp->rq_prog;
	vers = rqstp->rq_vers;
	proc = rqstp->rq_proc;
	(void) mutex_lock(&proglst_lock);
	for (pl = proglst; pl; pl = pl->p_nxt) {
		if (pl->p_prognum == prog && pl->p_procnum == proc &&
			pl->p_versnum == vers &&
			(strcmp(pl->p_netid, transp->xp_netid) == 0)) {
			/* decode arguments into a CLEAN buffer */
			xdrbuf = pl->p_xdrbuf;
			/* Zero the arguments: reqd ! */
			(void) memset(xdrbuf, 0, pl->p_recvsz);
			/*
			 * Assuming that sizeof (xdrbuf) would be enough
			 * for the arguments; if not then the program
			 * may bomb. BEWARE!
			 */
			if (!svc_getargs(transp, pl->p_inproc, xdrbuf)) {
				svcerr_decode(transp);
				(void) mutex_unlock(&proglst_lock);
				return;
			}
			outdata = (*(pl->p_progname))(xdrbuf);
			if (outdata == NULL &&
				pl->p_outproc != (xdrproc_t)xdr_void) {
				/* there was an error */
				(void) mutex_unlock(&proglst_lock);
				return;
			}
			if (!svc_sendreply(transp, pl->p_outproc, outdata)) {
				(void) syslog(LOG_ERR, (const char *)
			"rpc: rpc_reg trouble replying to prog %d vers %d",
				prog, vers);
				(void) mutex_unlock(&proglst_lock);
				return;
			}
			/* free the decoded arguments */
			(void) svc_freeargs(transp, pl->p_inproc, xdrbuf);
			(void) mutex_unlock(&proglst_lock);
			return;
		}
	}
	(void) mutex_unlock(&proglst_lock);
	/* This should never happen */
	(void) syslog(LOG_ERR, (const char *)
		"rpc: rpc_reg: never registered prog %d vers %d",
		prog, vers);
}
