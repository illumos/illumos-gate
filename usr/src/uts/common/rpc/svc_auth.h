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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#ifndef _RPC_SVC_AUTH_H
#define	_RPC_SVC_AUTH_H

/*
 * svc_auth.h, Service side of rpc authentication.
 */
#include <rpc/rpcsec_gss.h>
#include <rpc/rpc_msg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Server side authenticator
 */
#ifdef _KERNEL
/*
 * Copy of GSS parameters, needed for MT operation
 */
typedef struct {
	bool_t			established;
	rpc_gss_service_t	service;
	uint_t			qop_rcvd;
	void			*context;
	uint_t			seq_num;
} svc_rpc_gss_parms_t;

/*
 * sec_svc_control() commands
 */
#define	RPC_SVC_SET_GSS_CALLBACK	1  /* set rpcsec_gss callback routine */
extern bool_t sec_svc_control(uint_t, void *);

/*
 * Interface to server-side authentication flavors, may change on
 * each request.
 */
typedef struct {
	struct svc_auth_ops {
		int		(*svc_ah_wrap)();
		int		(*svc_ah_unwrap)();
	} svc_ah_ops;
	caddr_t			svc_ah_private;
	svc_rpc_gss_parms_t	svc_gss_parms;
	rpc_gss_rawcred_t	raw_cred;
} SVCAUTH;

#define	SVCAUTH_GSSPARMS(auth)  ((svc_rpc_gss_parms_t *)&(auth)->svc_gss_parms)

/*
 * Auth flavors can now apply a transformation in addition to simple XDR
 * on the body of a call/response in ways that depend on the flavor being
 * used.  These interfaces provide a generic interface between the
 * internal RPC frame and the auth flavor specific code to allow the
 * auth flavor to encode (WRAP) or decode (UNWRAP) the body.
 */
#define	SVCAUTH_WRAP(auth, xdrs, xfunc, xwhere) \
	((*((auth)->svc_ah_ops.svc_ah_wrap))(auth, xdrs, xfunc, xwhere))
#define	SVCAUTH_UNWRAP(auth, xdrs, xfunc, xwhere) \
	((*((auth)->svc_ah_ops.svc_ah_unwrap))(auth, xdrs, xfunc, xwhere))

/*
 * Server side authenticator
 */
extern enum auth_stat sec_svc_msg(struct svc_req *, struct rpc_msg *,
				bool_t *);

extern int sec_svc_getcred(struct svc_req *, cred_t *,  caddr_t *, int *);

#else

extern enum auth_stat __gss_authenticate(struct svc_req *, struct rpc_msg *,
				bool_t *);
extern enum auth_stat __authenticate(struct svc_req *, struct rpc_msg *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _RPC_SVC_AUTH_H */
