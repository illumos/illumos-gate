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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Joyent Inc
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 * auth_sys.h, Protocol for UNIX style authentication parameters for RPC
 */

#ifndef	_RPC_AUTH_SYS_H
#define	_RPC_AUTH_SYS_H

/*
 * The system is very weak.  The client uses no encryption for  it
 * credentials and only sends null verifiers.  The server sends backs
 * null verifiers or optionally a verifier that suggests a new short hand
 * for the credentials.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* The machine name is part of a credential; it may not exceed 255 bytes */
#define	 MAX_MACHINE_NAME 255

/* gids compose part of a credential; there may not be more than 16 of them */
#define	 NGRPS 16

/*
 * "sys" (Old UNIX) style credentials.
 */
struct authsys_parms {
	uint_t	 aup_time;
	char	*aup_machname;
	uid_t	 aup_uid;
	gid_t	 aup_gid;
	uint_t	 aup_len;
	gid_t	*aup_gids;
};
/* For backward compatibility */
#define	 authunix_parms authsys_parms

/*
 * Ideally, we would like this to be NGROUPS_UMAX, but the RFC mandates that
 * auth sections must not exceed 400 bytes. For AUTH_LOOPBACK, that means the
 * largest number of groups we can have without breaking RFC compat is 92
 * groups.
 *
 * NOTE: changing this value changes the size of authlpbk_area in
 * svc_auth_loopb.c, which means RQCRED_SIZE *must* be updated!
 */
#define	 NGRPS_LOOPBACK 92

#ifdef __STDC__
extern bool_t xdr_authsys_parms(XDR *, struct authsys_parms *);
extern bool_t xdr_authloopback_parms(XDR *, struct authsys_parms *);
#else
extern bool_t xdr_authsys_parms();
extern bool_t xdr_authloopback_parms();
#endif


/* For backward compatibility */
#define	xdr_authunix_parms(xdrs, p) xdr_authsys_parms(xdrs, p)

/*
 * If a response verifier has flavor AUTH_SHORT, then the body of
 * the response verifier encapsulates the following structure;
 * again it is serialized in the obvious fashion.
 */
struct short_hand_verf {
	struct opaque_auth new_cred;
};

struct svc_req;

extern bool_t xdr_gid_t(XDR *, gid_t *);
extern bool_t xdr_uid_t(XDR *, uid_t *);

#ifdef _KERNEL
extern bool_t xdr_authkern(XDR *);
extern bool_t xdr_authloopback(XDR *);
extern enum auth_stat _svcauth_unix(struct svc_req *, struct rpc_msg *);
extern enum auth_stat _svcauth_short(struct svc_req *, struct rpc_msg *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_RPC_AUTH_SYS_H */
