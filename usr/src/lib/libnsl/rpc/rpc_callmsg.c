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

#include "mt.h"
#include <stdlib.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <sys/byteorder.h>

extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);

/*
 * XDR a call message
 */
bool_t
xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg)
{
	rpc_inline_t *buf;
	struct opaque_auth *oa;

	if (xdrs->x_op == XDR_ENCODE) {
		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES)
			return (FALSE);
		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES)
			return (FALSE);
		buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT
			+ RNDUP(cmsg->rm_call.cb_cred.oa_length)
			+ 2 * BYTES_PER_XDR_UNIT
			+ RNDUP(cmsg->rm_call.cb_verf.oa_length));
		if (buf != NULL) {
			IXDR_PUT_INT32(buf, cmsg->rm_xid);
			IXDR_PUT_ENUM(buf, cmsg->rm_direction);
			if (cmsg->rm_direction != CALL)
				return (FALSE);
			IXDR_PUT_INT32(buf, cmsg->rm_call.cb_rpcvers);
			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION)
				return (FALSE);
			IXDR_PUT_INT32(buf, cmsg->rm_call.cb_prog);
			IXDR_PUT_INT32(buf, cmsg->rm_call.cb_vers);
			IXDR_PUT_INT32(buf, cmsg->rm_call.cb_proc);
			oa = &cmsg->rm_call.cb_cred;
			IXDR_PUT_ENUM(buf, oa->oa_flavor);
			IXDR_PUT_INT32(buf, oa->oa_length);
			if (oa->oa_length) {
				(void) memcpy(buf, oa->oa_base, oa->oa_length);
				buf += RNDUP(oa->oa_length) / sizeof (int32_t);
			}
			oa = &cmsg->rm_call.cb_verf;
			IXDR_PUT_ENUM(buf, oa->oa_flavor);
			IXDR_PUT_INT32(buf, oa->oa_length);
			if (oa->oa_length) {
				(void) memcpy(buf, oa->oa_base, oa->oa_length);
				/*
				 * no real need....
				 * buf += RNDUP(oa->oa_length) / sizeof
				 * (int32_t);
				 */
			}
			return (TRUE);
		}
	}
	if (xdrs->x_op == XDR_DECODE) {
		buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT);
		if (buf != NULL) {
			cmsg->rm_xid = IXDR_GET_INT32(buf);
			cmsg->rm_direction = IXDR_GET_ENUM(buf, enum msg_type);
			if (cmsg->rm_direction != CALL)
				return (FALSE);
			cmsg->rm_call.cb_rpcvers = IXDR_GET_INT32(buf);
			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION)
				return (FALSE);
			cmsg->rm_call.cb_prog = IXDR_GET_INT32(buf);
			cmsg->rm_call.cb_vers = IXDR_GET_INT32(buf);
			cmsg->rm_call.cb_proc = IXDR_GET_INT32(buf);
			oa = &cmsg->rm_call.cb_cred;
			oa->oa_flavor = IXDR_GET_ENUM(buf, enum_t);
			oa->oa_length = IXDR_GET_INT32(buf);
			if (oa->oa_length) {
				if (oa->oa_length > MAX_AUTH_BYTES)
					return (FALSE);
				if (oa->oa_base == NULL) {
					oa->oa_base = malloc(oa->oa_length);
					if (oa->oa_base == NULL) {
						syslog(LOG_ERR,
							"xdr_callmsg : "
							"out of memory.");
						return (FALSE);
					}
				}
				buf = XDR_INLINE(xdrs, RNDUP(oa->oa_length));
				if (buf == NULL) {
					if (xdr_opaque(xdrs, oa->oa_base,
					    oa->oa_length) == FALSE)
						return (FALSE);
				} else {
					(void) memcpy(oa->oa_base,
					    buf, (size_t)oa->oa_length);
					/*
					 * no real need....
					 * buf += RNDUP(oa->oa_length) /
					 *	(int)sizeof (int32_t);
					 */
				}
			}
			oa = &cmsg->rm_call.cb_verf;
			buf = XDR_INLINE(xdrs, 2 * BYTES_PER_XDR_UNIT);
			if (buf == NULL) {
				if (xdr_enum(xdrs, &oa->oa_flavor) == FALSE ||
				    xdr_u_int(xdrs, &oa->oa_length) == FALSE)
					return (FALSE);
			} else {
				oa->oa_flavor = IXDR_GET_ENUM(buf, enum_t);
				oa->oa_length = IXDR_GET_INT32(buf);
			}
			if (oa->oa_length) {
				if (oa->oa_length > MAX_AUTH_BYTES)
					return (FALSE);
				if (oa->oa_base == NULL) {
					oa->oa_base = malloc(oa->oa_length);
					if (oa->oa_base == NULL) {
						syslog(LOG_ERR,
							"xdr_callmsg : "
							"out of memory.");
						return (FALSE);
					}
				}
				buf = XDR_INLINE(xdrs, RNDUP(oa->oa_length));
				if (buf == NULL) {
					if (xdr_opaque(xdrs, oa->oa_base,
					    oa->oa_length) == FALSE)
						return (FALSE);
				} else {
					(void) memcpy(oa->oa_base,
					    buf, (size_t)oa->oa_length);
					/*
					 * no real need...
					 * buf += RNDUP(oa->oa_length) /
					 *	(int)sizeof (int32_t);
					 */
				}
			}
			return (TRUE);
		}
	}
	if (xdr_u_int(xdrs, &(cmsg->rm_xid)) &&
	    xdr_enum(xdrs, (enum_t *)&(cmsg->rm_direction)) &&
	    (cmsg->rm_direction == CALL) &&
	    xdr_u_int(xdrs, (uint_t *)&(cmsg->rm_call.cb_rpcvers)) &&
	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
	    xdr_u_int(xdrs, (uint_t *)&(cmsg->rm_call.cb_prog)) &&
	    xdr_u_int(xdrs, (uint_t *)&(cmsg->rm_call.cb_vers)) &&
	    xdr_u_int(xdrs, (uint_t *)&(cmsg->rm_call.cb_proc)) &&
	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred))) {
		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
	}
	return (FALSE);
}
