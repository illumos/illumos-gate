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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
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
 * svc_auth_sys.c
 * Handles UNIX flavor authentication parameters on the service side of rpc.
 * There are two svc auth implementations here: AUTH_SYS and AUTH_SHORT.
 * __svcauth_sys does full blown unix style uid, gid+gids auth,
 * __svcauth_short uses a shorthand auth to index into a cache of
 *	longhand auths.
 * Note: the shorthand has been gutted for efficiency.
 *
 */

#ifdef KERNEL
#include <sys/param.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/svc.h>
#include <rpc/auth_sys.h>
#include <rpc/svc_auth.h>
#else
#include <stdio.h>
#include <rpc/rpc.h>
#include <syslog.h>
#endif
#include <sys/types.h>
#include <rpc/trace.h>

/*
 * System (Unix) longhand authenticator
 */
enum auth_stat
__svcauth_sys(rqst, msg)
	register struct svc_req *rqst;
	register struct rpc_msg *msg;
{
	register enum auth_stat stat;
	XDR xdrs;
	register struct authsys_parms *aup;
	register rpc_inline_t *buf;
	struct area {
		struct authsys_parms area_aup;
		char area_machname[MAX_MACHINE_NAME+1];
		gid_t area_gids[NGRPS];
	} *area;
	u_int auth_len;
	u_int str_len, gid_len;
	register int i;

	trace1(TR___svcauth_sys, 0);
	area = (struct area *) rqst->rq_clntcred;
	aup = &area->area_aup;
	aup->aup_machname = area->area_machname;
	aup->aup_gids = area->area_gids;
	auth_len = (u_int)msg->rm_call.cb_cred.oa_length;
	if (auth_len == 0) {
		trace1(TR___svcauth_sys, 1);
		return (AUTH_BADCRED);
	}
	xdrmem_create(&xdrs, msg->rm_call.cb_cred.oa_base, auth_len,
			XDR_DECODE);
	buf = XDR_INLINE(&xdrs, auth_len);
	if (buf != NULL) {
		aup->aup_time = IXDR_GET_INT32(buf);
		str_len = IXDR_GET_U_INT32(buf);
		if (str_len > MAX_MACHINE_NAME) {
			stat = AUTH_BADCRED;
			goto done;
		}
		(void) memcpy(aup->aup_machname, (caddr_t)buf, str_len);
		aup->aup_machname[str_len] = 0;
		str_len = RNDUP(str_len);
		buf += str_len / (int) sizeof (int32_t);
		aup->aup_uid = IXDR_GET_INT32(buf);
		aup->aup_gid = IXDR_GET_INT32(buf);
		gid_len = IXDR_GET_U_INT32(buf);
		if (gid_len > NGRPS) {
			stat = AUTH_BADCRED;
			goto done;
		}
		aup->aup_len = gid_len;
		for (i = 0; i < gid_len; i++) {
			aup->aup_gids[i] = (gid_t) IXDR_GET_INT32(buf);
		}
		/*
		 * five is the smallest unix credentials structure -
		 * timestamp, hostname len (0), uid, gid, and gids len (0).
		 */
		if ((5 + gid_len) * BYTES_PER_XDR_UNIT + str_len > auth_len) {
#ifdef	KERNEL
			printf("bad auth_len gid %d str %d auth %d",
			    gid_len, str_len, auth_len);
#else
			(void) syslog(LOG_ERR,
				"bad auth_len gid %d str %d auth %d",
					gid_len, str_len, auth_len);
#endif
			stat = AUTH_BADCRED;
			goto done;
		}
	} else if (! xdr_authsys_parms(&xdrs, aup)) {
		xdrs.x_op = XDR_FREE;
		(void) xdr_authsys_parms(&xdrs, aup);
		stat = AUTH_BADCRED;
		goto done;
	}
	rqst->rq_xprt->xp_verf.oa_flavor = AUTH_NULL;
	rqst->rq_xprt->xp_verf.oa_length = 0;
	stat = AUTH_OK;
done:
	XDR_DESTROY(&xdrs);
	trace1(TR___svcauth_sys, 1);
	return (stat);
}

/*
 * Shorthand unix authenticator
 * Looks up longhand in a cache.
 */
/*ARGSUSED*/
enum auth_stat
__svcauth_short(rqst, msg)
	struct svc_req *rqst;
	struct rpc_msg *msg;
{
	trace1(TR___svcauth_short, 0);
	trace1(TR___svcauth_short, 1);
	return (AUTH_REJECTEDCRED);
}

/*
 * Unix longhand authenticator. Will be obsoleted
 */
enum auth_stat
__svcauth_unix(rqst, msg)
	register struct svc_req *rqst;
	register struct rpc_msg *msg;
{
	enum auth_stat dummy;

	trace1(TR___svcauth_unix, 0);
	dummy = __svcauth_sys(rqst, msg);
	trace1(TR___svcauth_unix, 1);
	return (dummy);
}
