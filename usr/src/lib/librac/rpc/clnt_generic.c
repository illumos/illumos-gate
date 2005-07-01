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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <tiuser.h>
#include <rpc/nettype.h>
#include <netdir.h>
#include <string.h>
#include "rac_private.h"

/*
 * Generic client creation with version checking the value of
 * vers_out is set to the highest server supported value
 * vers_low <= vers_out <= vers_high  AND an error results
 * if this can not be done.
 */
CLIENT *
clnt_create_vers(const char *hostname, const rpcprog_t prog,
    rpcvers_t *vers_out, const rpcvers_t vers_low, const rpcvers_t vers_high,
    const char *nettype)
{
	CLIENT *clnt;
	struct timeval to;
	enum clnt_stat rpc_stat;
	struct rpc_err rpcerr;
	rpcvers_t v_low, v_high;

	clnt = clnt_create(hostname, prog, vers_high, nettype);
	if (clnt == NULL)
		return (NULL);
	to.tv_sec = 10;
	to.tv_usec = 0;
	rpc_stat = clnt_call(clnt, NULLPROC, (xdrproc_t)xdr_void,
			NULL, (xdrproc_t)xdr_void, NULL, to);
	if (rpc_stat == RPC_SUCCESS) {
		*vers_out = vers_high;
		return (clnt);
	}
	if (rpc_stat == RPC_PROGVERSMISMATCH) {
		unsigned int minvers, maxvers;

		clnt_geterr(clnt, &rpcerr);
		minvers = rpcerr.re_vers.low;
		maxvers = rpcerr.re_vers.high;
		if (maxvers < vers_high)
			v_high = maxvers;
		if (minvers > vers_low)
			v_low = minvers;
		if (v_low > v_high) {
			goto error;
		}
		CLNT_CONTROL(clnt, CLSET_VERS, (char *)&v_high);
		rpc_stat = clnt_call(clnt, NULLPROC, (xdrproc_t)xdr_void,
				NULL, (xdrproc_t)xdr_void, NULL, to);
		if (rpc_stat == RPC_SUCCESS) {
			*vers_out = v_high;
			return (clnt);
		}
	}
	clnt_geterr(clnt, &rpcerr);

error:	rpc_createerr.cf_stat = rpc_stat;
	rpc_createerr.cf_error = rpcerr;
	clnt_destroy(clnt);
	return (NULL);
}

/*
 * Top level client creation routine.
 * Generic client creation: takes (servers name, program-number, nettype) and
 * returns client handle. Default options are set, which the user can
 * change using the rpc equivalent of ioctl()'s.
 *
 * It tries for all the netids in that particular class of netid until
 * it succeeds.
 * XXX The error message in the case of failure will be the one
 * pertaining to the last create error.
 *
 * It calls clnt_tp_create();
 */
CLIENT *
clnt_create(const char *hostname, const rpcprog_t prog, const rpcvers_t vers,
    const char *nettype)
{
	struct netconfig *nconf;
	CLIENT *clnt = NULL;
	void *handle;
	enum clnt_stat	save_cf_stat = RPC_SUCCESS;
	struct rpc_err	save_cf_error;

	if ((handle = __rpc_setconf((char *)nettype)) == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		return (NULL);
	}

	rpc_createerr.cf_stat = RPC_SUCCESS;
	while (clnt == NULL) {
		if ((nconf = __rpc_getconf(handle)) == NULL) {
			if (rpc_createerr.cf_stat == RPC_SUCCESS)
				rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			break;
		}
		clnt = clnt_tp_create(hostname, prog, vers, nconf);
		if (clnt)
			break;
		else
			/*
			 *	Since we didn't get a name-to-address
			 *	translation failure here, we remember
			 *	this particular error.  The object of
			 *	this is to enable us to return to the
			 *	caller a more-specific error than the
			 *	unhelpful ``Name to address translation
			 *	failed'' which might well occur if we
			 *	merely returned the last error (because
			 *	the local loopbacks are typically the
			 *	last ones in /etc/netconfig and the most
			 *	likely to be unable to translate a host
			 *	name).
			 */
			if (rpc_createerr.cf_stat != RPC_N2AXLATEFAILURE) {
				save_cf_stat = rpc_createerr.cf_stat;
				save_cf_error = rpc_createerr.cf_error;
			}
	}

	/*
	 *	Attempt to return an error more specific than ``Name to address
	 *	translation failed''
	 */
	if ((rpc_createerr.cf_stat == RPC_N2AXLATEFAILURE) &&
		(save_cf_stat != RPC_SUCCESS)) {
		rpc_createerr.cf_stat = save_cf_stat;
		rpc_createerr.cf_error = save_cf_error;
	}
	__rpc_endconf(handle);
	return (clnt);
}

/*
 * Generic client creation: takes (servers name, program-number, netconf) and
 * returns client handle. Default options are set, which the user can
 * change using the rpc equivalent of ioctl()'s : clnt_control()
 * It finds out the server address from rpcbind and calls clnt_tli_create()
 */
CLIENT *
clnt_tp_create(const char *hostname, const rpcprog_t prog, const rpcvers_t vers,
    const struct netconfig *nconf)
{
	struct netbuf *svcaddr;			/* servers address */
	CLIENT *cl = NULL;			/* client handle */

	if (nconf == NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
		return (NULL);
	}
	/*
	 * Get the address of the server
	 */

	if ((svcaddr = __rpcb_findaddr(prog, vers, nconf, hostname,
							&cl)) == NULL) {
		/* appropriate error number is set by rpcbind libraries */
		return (NULL);
	}
	if (cl == NULL) {
		cl = clnt_tli_create(RPC_ANYFD, nconf, svcaddr,
					prog, vers, 0, 0);
	} else {
		/* Reuse the CLIENT handle and change the appropriate fields */
		if (CLNT_CONTROL(cl, CLSET_SVC_ADDR, (void *)svcaddr) == TRUE) {
			if (cl->cl_netid == NULL)
				cl->cl_netid = strdup(nconf->nc_netid);
			if (cl->cl_tp == NULL)
				cl->cl_tp = strdup(nconf->nc_device);
			(void) CLNT_CONTROL(cl, CLSET_PROG, (void *)&prog);
			(void) CLNT_CONTROL(cl, CLSET_VERS, (void *)&vers);
		} else {
			CLNT_DESTROY(cl);
			cl = clnt_tli_create(RPC_ANYFD, nconf, svcaddr,
					prog, vers, 0, 0);
		}
	}
	netdir_free((char *)svcaddr, ND_ADDR);
	return (cl);
}

/*
 * Generic client creation:  returns client handle.
 * Default options are set, which the user can
 * change using the rpc equivalent of ioctl()'s : clnt_control().
 * If fd is RPC_ANYFD, it will be opened using nconf.
 * It will be bound if not so.
 * If sizes are 0; appropriate defaults will be chosen.
 */
CLIENT *
clnt_tli_create(const int fd, const struct netconfig *nconf,
    struct netbuf *svcaddr, const rpcprog_t prog, const rpcvers_t vers,
    const uint_t sendsz, const uint_t recvsz)
{
	CLIENT *cl;			/* client handle */
	struct t_info tinfo;		/* transport info */
	bool_t madefd;			/* whether fd opened here */
	int servtype;
	int nfd = fd;

	if (nfd == RPC_ANYFD) {
		if (nconf == NULL) {
			rpc_createerr.cf_stat = RPC_UNKNOWNPROTO;
			return (NULL);
		}
		nfd = t_open(nconf->nc_device, O_RDWR, NULL);
		if (nfd == -1)
			goto err;
		madefd = TRUE;
		if (t_bind(nfd, NULL, NULL) == -1)
			goto err;

		switch (nconf->nc_semantics) {
		case NC_TPI_CLTS:
			servtype = T_CLTS;
			break;
		case NC_TPI_COTS:
			servtype = T_COTS;
			break;
		case NC_TPI_COTS_ORD:
			servtype = T_COTS_ORD;
			break;
		default:
			if (t_getinfo(nfd, &tinfo) == -1)
				goto err;
			servtype = tinfo.servtype;
			break;
		}
	} else {
		int state;		/* Current state of provider */

		/*
		 * Sync the opened fd.
		 * Check whether bound or not, else bind it
		 */
		if (((state = t_sync(nfd)) == -1) ||
		    ((state == T_UNBND) && (t_bind(nfd, NULL, NULL) == -1)) ||
		    (t_getinfo(nfd, &tinfo) == -1))
			goto err;
		servtype = tinfo.servtype;
		madefd = FALSE;
	}

	switch (servtype) {
	case T_COTS:
	case T_COTS_ORD:
		cl = clnt_vc_create(nfd, svcaddr, prog, vers, sendsz, recvsz);
		break;
	case T_CLTS:

		cl = clnt_dg_create(nfd, svcaddr, prog, vers, sendsz, recvsz);
		break;
	default:
		goto err;
	}

	if (cl == NULL)
		goto err1; /* borrow errors from clnt_dg/vc creates */
	if (nconf) {
		cl->cl_netid = strdup(nconf->nc_netid);
		cl->cl_tp = strdup(nconf->nc_device);
	} else {
		cl->cl_netid = "";
		cl->cl_tp = "";
	}
	if (madefd)
		(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);

	return (cl);

err:
	rpc_createerr.cf_stat = RPC_TLIERROR;
	rpc_createerr.cf_error.re_errno = errno;
	rpc_createerr.cf_error.re_terrno = t_errno;
err1:	if (madefd)
		(void) t_close(nfd);
	return (NULL);
}
