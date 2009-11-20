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
 * auth_sys.c, Implements UNIX (system) style authentication parameters.
 *
 * The system is very weak.  The client uses no encryption for its
 * credentials and only sends null verifiers.  The server sends backs
 * null verifiers or optionally a verifier that suggests a new short hand
 * for the credentials.
 *
 */
#include "mt.h"
#include "rpc_mt.h"
#include <alloca.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>
#include <synch.h>

extern int gethostname(char *, int);
extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);

static struct auth_ops *authsys_ops(void);

/*
 * This struct is pointed to by the ah_private field of an auth_handle.
 */
struct audata {
	struct opaque_auth	au_origcred;	/* original credentials */
	struct opaque_auth	au_shcred;	/* short hand cred */
	uint_t			au_shfaults;	/* short hand cache faults */
	char			au_marshed[MAX_AUTH_BYTES];
	uint_t			au_mpos;	/* xdr pos at end of marshed */
};
#define	AUTH_PRIVATE(auth)	((struct audata *)auth->ah_private)

static void marshal_new_auth();

static const char auth_sys_str[] = "%s : %s";
static const char authsys_create_str[] = "authsys_create";
static const char __no_mem_auth[] = "out of memory";

/*
 * Create a (sys) unix style authenticator.
 * Returns an auth handle with the given stuff in it.
 */
AUTH *
authsys_create(const char *machname, const uid_t uid, const gid_t gid,
	const int len, const gid_t *aup_gids)
{
	struct authsys_parms aup;
	char mymem[MAX_AUTH_BYTES];
	struct timeval now;
	XDR xdrs;
	AUTH *auth;
	struct audata *au;

	/*
	 * Allocate and set up auth handle
	 */
	auth = malloc(sizeof (*auth));
	if (auth == NULL) {
		(void) syslog(LOG_ERR, auth_sys_str, authsys_create_str,
		    __no_mem_auth);
		return (NULL);
	}
	au = malloc(sizeof (*au));
	if (au == NULL) {
		(void) syslog(LOG_ERR, auth_sys_str, authsys_create_str,
		    __no_mem_auth);
		free(auth);
		return (NULL);
	}
	auth->ah_ops = authsys_ops();
	auth->ah_private = (caddr_t)au;
	auth->ah_verf = au->au_shcred = _null_auth;
	au->au_shfaults = 0;

	/*
	 * fill in param struct from the given params
	 */
	(void) gettimeofday(&now,  (struct timezone *)0);
	aup.aup_time = now.tv_sec;
	aup.aup_machname = (char *)machname;
	aup.aup_uid = uid;
	aup.aup_gid = gid;
	aup.aup_len = (uint_t)len;
	aup.aup_gids = (gid_t *)aup_gids;

	/*
	 * Serialize the parameters into origcred
	 */
	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
	if (!xdr_authsys_parms(&xdrs, &aup)) {
		(void) syslog(LOG_ERR, auth_sys_str, authsys_create_str,
		    ":  xdr_authsys_parms failed");
		return (NULL);
	}
	au->au_origcred.oa_length = XDR_GETPOS(&xdrs);
	au->au_origcred.oa_flavor = AUTH_SYS;
	if ((au->au_origcred.oa_base = malloc(au->au_origcred.oa_length)) ==
	    NULL) {
		(void) syslog(LOG_ERR, auth_sys_str, authsys_create_str,
		    __no_mem_auth);
		free(au);
		free(auth);
		return (NULL);
	}
	(void) memcpy(au->au_origcred.oa_base, mymem,
	    (size_t)au->au_origcred.oa_length);

	/*
	 * set auth handle to reflect new cred.
	 */
	auth->ah_cred = au->au_origcred;
	(void) marshal_new_auth(auth);
	return (auth);
}

/*
 * authsys_create_default is a public interface.
 *
 * Returns an auth handle with parameters determined by doing lots of
 * syscalls.
 */

static const char authsys_def_str[] =
	"authsys_create_default:  get%s failed:  %m";

AUTH *
authsys_create_default(void)
{
	int len;
	char machname[MAX_MACHINE_NAME + 1];
	uid_t uid;
	gid_t gid;
	int maxgrp = getgroups(0, NULL);
	gid_t *gids = alloca(maxgrp * sizeof (gid_t));

	if (gethostname(machname, MAX_MACHINE_NAME) == -1) {
		(void) syslog(LOG_ERR, authsys_def_str, "hostname");
		return (NULL);
	}
	machname[MAX_MACHINE_NAME] = 0;
	uid = geteuid();
	gid = getegid();
	if ((len = getgroups(maxgrp, gids)) < 0) {
		(void) syslog(LOG_ERR, authsys_def_str, "groups");
		return (NULL);
	}
	if (len > NGRPS)
		len = NGRPS;
	return (authsys_create(machname, uid, gid, len, gids));
}

/*
 * authsys_create_ruid() is a private routine and is a
 * variant of authsys_create_default().
 *
 * authsys_create_default() is using the effective uid.
 * authsys_create_ruid() is using the real uid.
 *
 * This routine is used by key_call_ext() in key_call.c
 */
AUTH *
authsys_create_ruid(void)
{
	int len;
	char machname[MAX_MACHINE_NAME + 1];
	uid_t uid;
	gid_t gid;
	int maxgrp = getgroups(0, NULL);
	gid_t *gids = alloca(maxgrp * sizeof (gid_t));
	AUTH *res;

	if (gethostname(machname, MAX_MACHINE_NAME) == -1) {
		(void) syslog(LOG_ERR,
		    "authsys_create_ruid:gethostname failed");
		return (NULL);
	}
	machname[MAX_MACHINE_NAME] = 0;
	uid = getuid();
	gid = getgid();
	if ((len = getgroups(maxgrp, gids)) < 0) {
		(void) syslog(LOG_ERR,
		    "authsys_create_ruid:getgroups failed");
		return (NULL);
	}
	if (len > NGRPS)
		len = NGRPS;
	res = authsys_create(machname, uid, gid, len, gids);
	return (res);
}

/*
 * authsys operations
 */

/*ARGSUSED*/
static void
authsys_nextverf(AUTH *auth)
{
	/* no action necessary */
}

static bool_t
authsys_marshal(AUTH *auth, XDR *xdrs)
{
/* LINTED pointer alignment */
	struct audata *au = AUTH_PRIVATE(auth);

	return (XDR_PUTBYTES(xdrs, au->au_marshed, au->au_mpos));
}

static bool_t
authsys_validate(AUTH *auth, struct opaque_auth *verf)
{
	struct audata *au;
	XDR xdrs;

	if (verf->oa_flavor == AUTH_SHORT) {
/* LINTED pointer alignment */
		au = AUTH_PRIVATE(auth);
		xdrmem_create(&xdrs, verf->oa_base,
		    verf->oa_length, XDR_DECODE);

		if (au->au_shcred.oa_base != NULL) {
			free(au->au_shcred.oa_base);
			au->au_shcred.oa_base = NULL;
		}
		if (xdr_opaque_auth(&xdrs, &au->au_shcred)) {
			auth->ah_cred = au->au_shcred;
		} else {
			xdrs.x_op = XDR_FREE;
			(void) xdr_opaque_auth(&xdrs, &au->au_shcred);
			au->au_shcred.oa_base = NULL;
			auth->ah_cred = au->au_origcred;
		}
		(void) marshal_new_auth(auth);
	}
	return (TRUE);
}

/*ARGSUSED*/
static bool_t
authsys_refresh(AUTH *auth, void *dummy)
{
/* LINTED pointer alignment */
	struct audata *au = AUTH_PRIVATE(auth);
	struct authsys_parms aup;
	struct timeval now;
	XDR xdrs;
	int stat;

	if (auth->ah_cred.oa_base == au->au_origcred.oa_base)
		return (FALSE);	/* there is no hope.  Punt */
	au->au_shfaults ++;

	/* first deserialize the creds back into a struct authsys_parms */
	aup.aup_machname = NULL;
	aup.aup_gids = NULL;
	xdrmem_create(&xdrs, au->au_origcred.oa_base,
	    au->au_origcred.oa_length, XDR_DECODE);
	stat = xdr_authsys_parms(&xdrs, &aup);
	if (!stat)
		goto done;

	/* update the time and serialize in place */
	(void) gettimeofday(&now, (struct timezone *)0);
	aup.aup_time = now.tv_sec;
	xdrs.x_op = XDR_ENCODE;
	XDR_SETPOS(&xdrs, 0);
	stat = xdr_authsys_parms(&xdrs, &aup);
	if (!stat)
		goto done;
	auth->ah_cred = au->au_origcred;
	(void) marshal_new_auth(auth);
done:
	/* free the struct authsys_parms created by deserializing */
	xdrs.x_op = XDR_FREE;
	(void) xdr_authsys_parms(&xdrs, &aup);
	XDR_DESTROY(&xdrs);
	return (stat);
}

static void
authsys_destroy(AUTH *auth)
{
/* LINTED pointer alignment */
	struct audata *au = AUTH_PRIVATE(auth);

	free(au->au_origcred.oa_base);
	if (au->au_shcred.oa_base != NULL)
		free(au->au_shcred.oa_base);
	free(auth->ah_private);
	if (auth->ah_verf.oa_base != NULL)
		free(auth->ah_verf.oa_base);
	free(auth);
}

/*
 * Marshals (pre-serializes) an auth struct.
 * sets private data, au_marshed and au_mpos
 */

static const char marshal_new_auth_str[] =
		"marshal_new_auth - Fatal marshalling problem";
static void
marshal_new_auth(AUTH *auth)
{
	XDR	xdr_stream;
	XDR	*xdrs = &xdr_stream;
/* LINTED pointer alignment */
	struct audata *au = AUTH_PRIVATE(auth);

	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
	if ((!xdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
	    (!xdr_opaque_auth(xdrs, &(auth->ah_verf)))) {
		(void) syslog(LOG_ERR, marshal_new_auth_str);
	} else {
		au->au_mpos = XDR_GETPOS(xdrs);
	}
	XDR_DESTROY(xdrs);
}

static struct auth_ops *
authsys_ops(void)
{
	static struct auth_ops ops;
	extern mutex_t ops_lock;

	/* VARIABLES PROTECTED BY ops_lock: ops */

	(void) mutex_lock(&ops_lock);
	if (ops.ah_nextverf == NULL) {
		ops.ah_nextverf = authsys_nextverf;
		ops.ah_marshal = authsys_marshal;
		ops.ah_validate = authsys_validate;
		ops.ah_refresh = authsys_refresh;
		ops.ah_destroy = authsys_destroy;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}
