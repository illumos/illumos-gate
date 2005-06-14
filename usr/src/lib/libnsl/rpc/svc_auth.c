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
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
 * svc_auth.c, Server-side rpc authenticator interface.
 *
 */

#include "mt.h"
#include "rpc_mt.h"
#include <rpc/rpc.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <stdlib.h>

/*
 * svcauthsw is the bdevsw of server side authentication.
 *
 * Server side authenticators are called from authenticate by
 * using the client auth struct flavor field to index into svcauthsw.
 * The server auth flavors must implement a routine that looks
 * like:
 *
 *	enum auth_stat
 *	flavorx_auth(rqst, msg)
 *		struct svc_req *rqst;
 *		struct rpc_msg *msg;
 *
 * The RPCSEC_GSS flavor is an exception.  Its routine takes an
 * additional boolean parameter that gets set to TRUE when the call
 * is not to be dispatched to the server.
 */

enum auth_stat __svcauth_null();	/* no authentication */
enum auth_stat __svcauth_sys();		/* (system) unix style (uid, gids) */
enum auth_stat __svcauth_short();	/* short hand unix style */
enum auth_stat __svcauth_des();		/* des style */
enum auth_stat __svcauth_loopback();	/* (loopback) unix style (uid, gids) */
extern enum auth_stat __svcrpcsec_gss();	/* GSS style */

/* declarations to allow servers to specify new authentication flavors */
struct authsvc {
	int	flavor;
	enum	auth_stat (*handler)();
	struct	authsvc	  *next;
};
static struct authsvc *Auths = NULL;

/*
 * The call rpc message, msg has been obtained from the wire.  The msg contains
 * the raw form of credentials and verifiers.  no_dispatch is used and
 * dereferenced in subsequent gss function calls.  authenticate returns AUTH_OK
 * if the msg is successfully authenticated.  If AUTH_OK then the routine also
 * does the following things:
 * set rqst->rq_xprt->verf to the appropriate response verifier;
 * sets rqst->rq_client_cred to the "cooked" form of the credentials.
 *
 * NB: rqst->rq_cxprt->verf must be pre-alloctaed;
 * its length is set appropriately.
 *
 * The caller still owns and is responsible for msg->u.cmb.cred and
 * msg->u.cmb.verf.  The authentication system retains ownership of
 * rqst->rq_client_cred, the cooked credentials.
 *
 * There is an assumption that any flavour less than AUTH_NULL is
 * invalid.
 */
enum auth_stat
__gss_authenticate(rqst, msg, no_dispatch)
	struct svc_req *rqst;
	struct rpc_msg *msg;
	bool_t *no_dispatch;
{
	int cred_flavor;
	struct authsvc *asp;
	enum auth_stat dummy;
	extern mutex_t authsvc_lock;

/* VARIABLES PROTECTED BY authsvc_lock: asp, Auths */

	trace1(TR___gss_authenticate, 0);
	rqst->rq_cred = msg->rm_call.cb_cred;
	rqst->rq_xprt->xp_verf.oa_flavor = _null_auth.oa_flavor;
	rqst->rq_xprt->xp_verf.oa_length = 0;
	cred_flavor = rqst->rq_cred.oa_flavor;
	*no_dispatch = FALSE;
	switch (cred_flavor) {
	case AUTH_NULL:
		dummy = __svcauth_null(rqst, msg);
		trace1(TR___gss_authenticate, 1);
		return (dummy);
	case AUTH_SYS:
		dummy = __svcauth_sys(rqst, msg);
		trace1(TR___gss_authenticate, 1);
		return (dummy);
	case AUTH_SHORT:
		dummy = __svcauth_short(rqst, msg);
		trace1(TR___gss_authenticate, 1);
		return (dummy);
	case AUTH_DES:
		dummy = __svcauth_des(rqst, msg);
		trace1(TR___gss_authenticate, 1);
		return (dummy);
	case AUTH_LOOPBACK:
		dummy = __svcauth_loopback(rqst, msg);
		trace1(TR___gss_authenticate, 1);
		return (dummy);
	case RPCSEC_GSS:
		dummy = __svcrpcsec_gss(rqst, msg, no_dispatch);
		trace1(TR___gss_authenticate, 1);
		return (dummy);
	}

	/* flavor doesn't match any of the builtin types, so try new ones */
	mutex_lock(&authsvc_lock);
	for (asp = Auths; asp; asp = asp->next) {
		if (asp->flavor == cred_flavor) {
			enum auth_stat as;

			as = (*asp->handler)(rqst, msg);
			mutex_unlock(&authsvc_lock);
			trace1(TR___gss_authenticate, 1);
			return (as);
		}
	}
	mutex_unlock(&authsvc_lock);

	trace1(TR___gss_authenticate, 1);
	return (AUTH_REJECTEDCRED);
}

/*
 * The following function __authenticate(rqst, msg) is preserved for
 * backward compatibility.
 */
enum auth_stat
__authenticate(rqst, msg)
	struct svc_req *rqst;
	struct rpc_msg *msg;
{
	bool_t no_dispatch;
	enum auth_stat st;

	trace1(TR___authenticate, 0);

	st = __gss_authenticate(rqst, msg, &no_dispatch);

	trace1(TR___authenticate, 1);
	return (st);
}

/*ARGSUSED*/
enum auth_stat
__svcauth_null(rqst, msg)
	struct svc_req *rqst;
	struct rpc_msg *msg;
{
	trace1(TR___svcauth_null, 0);
	trace1(TR___svcauth_null, 1);
	return (AUTH_OK);
}

/*
 *  Allow the rpc service to register new authentication types that it is
 *  prepared to handle.  When an authentication flavor is registered,
 *  the flavor is checked against already registered values.  If not
 *  registered, then a new Auths entry is added on the list.
 *
 *  There is no provision to delete a registration once registered.
 *
 *  This routine returns:
 *	 0 if registration successful
 *	 1 if flavor already registered
 *	-1 if can't register (errno set)
 */

int
svc_auth_reg(cred_flavor, handler)
	int cred_flavor;
	enum auth_stat (*handler)();
{
	struct authsvc *asp;
	extern mutex_t authsvc_lock;

	trace2(TR_svc_auth_reg, 0, cred_flavor);
	switch (cred_flavor) {
	    case AUTH_NULL:
	    case AUTH_SYS:
	    case AUTH_SHORT:
	    case AUTH_DES:
	    case AUTH_LOOPBACK:
	    case RPCSEC_GSS:
		/* already registered */
		trace1(TR_svc_auth_reg, 1);
		return (1);

	    default:
		mutex_lock(&authsvc_lock);
		for (asp = Auths; asp; asp = asp->next) {
			if (asp->flavor == cred_flavor) {
				/* already registered */
				mutex_unlock(&authsvc_lock);
				trace1(TR_svc_auth_reg, 1);
				return (1);
			}
		}

		/* this is a new one, so go ahead and register it */
		asp = (struct authsvc *)mem_alloc(sizeof (*asp));
		if (asp == NULL) {
			mutex_unlock(&authsvc_lock);
			trace1(TR_svc_auth_reg, 1);
			return (-1);
		}
		asp->flavor = cred_flavor;
		asp->handler = handler;
		asp->next = Auths;
		Auths = asp;
		mutex_unlock(&authsvc_lock);
		break;
	}
	trace1(TR_svc_auth_reg, 1);
	return (0);
}
