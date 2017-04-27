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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2017 Joyent Inc
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * Handles UNIX flavor authentication parameters on the service side of rpc.
 * There are two svc auth implementations here: AUTH_SYS and AUTH_SHORT.
 * __svcauth_sys does full blown unix style uid, gid+gids auth,
 * __svcauth_short uses a shorthand auth to index into a cache of
 *	longhand auths.
 * Note: the shorthand has been gutted for efficiency.
 *
 */

#include "mt.h"
#include <stdio.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <string.h>

/*
 * NOTE: this has to fit inside RQCRED_SIZE bytes. If you update this struct,
 * double-check it still fits.
 */
struct authsys_area {
	struct authsys_parms area_aup;
	char area_machname[MAX_MACHINE_NAME+1];
	gid_t area_gids[NGRPS];
};
CTASSERT(sizeof (struct authsys_area) <= RQCRED_SIZE);

/*
 * System (Unix) longhand authenticator
 */
enum auth_stat
__svcauth_sys(struct svc_req *rqst, struct rpc_msg *msg)
{
	enum auth_stat stat;
	XDR xdrs;
	struct authsys_parms *aup;
	rpc_inline_t *buf;
	struct authsys_area *area;
	uint_t auth_len;
	uint_t str_len, gid_len;
	int i;

	/* LINTED pointer cast */
	area = (struct authsys_area *)rqst->rq_clntcred;
	aup = &area->area_aup;
	aup->aup_machname = area->area_machname;
	aup->aup_gids = area->area_gids;
	auth_len = (uint_t)msg->rm_call.cb_cred.oa_length;
	if (auth_len == 0)
		return (AUTH_BADCRED);
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
		(void) memcpy(aup->aup_machname, buf, str_len);
		aup->aup_machname[str_len] = 0;
		str_len = RNDUP(str_len);
		buf += str_len / (int)sizeof (int32_t);
		aup->aup_uid = IXDR_GET_INT32(buf);
		aup->aup_gid = IXDR_GET_INT32(buf);
		gid_len = IXDR_GET_U_INT32(buf);
		if (gid_len > NGRPS) {
			stat = AUTH_BADCRED;
			goto done;
		}
		aup->aup_len = gid_len;
		for (i = 0; i < gid_len; i++) {
			aup->aup_gids[i] = (gid_t)IXDR_GET_INT32(buf);
		}
		/*
		 * five is the smallest unix credentials structure -
		 * timestamp, hostname len (0), uid, gid, and gids len (0).
		 */
		if ((5 + gid_len) * BYTES_PER_XDR_UNIT + str_len > auth_len) {
			(void) syslog(LOG_ERR,
				"bad auth_len gid %d str %d auth %d",
					gid_len, str_len, auth_len);
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
	return (stat);
}

/*
 * Shorthand unix authenticator
 * Looks up longhand in a cache.
 */
/*ARGSUSED*/
enum auth_stat
__svcauth_short(struct svc_req *rqst, struct rpc_msg *msg)
{
	return (AUTH_REJECTEDCRED);
}

/*
 * Unix longhand authenticator. Will be obsoleted
 */
enum auth_stat
__svcauth_unix(struct svc_req *rqst, struct rpc_msg *msg)
{
	return (__svcauth_sys(rqst, msg));
}
