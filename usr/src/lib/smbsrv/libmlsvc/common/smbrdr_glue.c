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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * There used to be a "redirector" library, which has been replaced,
 * leaving only the "glue" functions in this file that adapt this
 * library to the interface provided by libsmbfs.
 */

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <priv.h>

#include <netsmb/smbfs_api.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <libsmbrdr.h>
#include <mlsvc.h>

#include <assert.h>

void
smbrdr_initialize(void)
{
	(void) smb_lib_init();
}

/*
 * mlsvc_disconnect
 *
 * Disconnects the session with given server.
 * The new conection manager is smart enough
 * so that we don't need this to do anything.
 */
/* ARGSUSED */
void
smbrdr_disconnect(const char *server)
{
}


/*
 * smbrdr_logon
 *
 * I'm not sure this really needs to do anything, but for now
 * let's go ahead and authenticate here so this can return a
 * status reflecting the outcome of authentication.
 *
 * If this successfully builds an smb_ctx, it just frees it.
 * The driver retains sessions for a little while after the
 * last reference goes away, so the session created here will
 * usually still exist when the next call to smbrdr_ctx_new
 * asks for this server+user (immediately after this returns),
 * and only one session setup will go over the wire.
 */
int
smbrdr_logon(char *srv, char *dom, char *user)
{
	struct smb_ctx *ctx;
	int err;

	err = smbrdr_ctx_new(&ctx, srv, dom, user);
	if (err == 0)
		smb_ctx_free(ctx);
	return (err);
}

void
smbrdr_ctx_free(struct smb_ctx *ctx)
{
	smb_ctx_free(ctx);
}

/*
 * Setup a new SMB client context.
 *
 * Get the SMB server's configuration stuff and
 * store it in the new client context object.
 */
int
smbrdr_ctx_new(struct smb_ctx **ctx_p, char *server,
	char *domain, char *user)
{
	struct smb_ctx *ctx = NULL;
	uchar_t nthash[SMBAUTH_HASH_SZ];
	int64_t lmcl;
	int authflags, err;

	assert(server != NULL);
	assert(domain != NULL);
	assert(user != NULL);

	if (server[0] == '\0')
		return (NT_STATUS_INTERNAL_ERROR);

	if ((err = smb_ctx_alloc(&ctx)) != 0)
		return (NT_STATUS_NO_MEMORY);

	/*
	 * Set server, share, domain, user
	 * (in the ctx handle).
	 */
	(void) smb_ctx_setfullserver(ctx, server);
	(void) smb_ctx_setshare(ctx, "IPC$", USE_IPC);
	(void) smb_ctx_setdomain(ctx, domain, B_TRUE);
	(void) smb_ctx_setuser(ctx, user, B_TRUE);

	/*
	 * Set auth. info (hash) and type.
	 */
	if (user[0] == '\0') {
		authflags = SMB_AT_ANON;
	} else {
		(void) smb_config_getnum(SMB_CI_LM_LEVEL, &lmcl);
		if (lmcl <= 2) {
			/* Send NTLM */
			authflags = SMB_AT_NTLM1;
		} else {
			/* Send NTLMv2 */
			authflags = SMB_AT_NTLM2;
		}
		smb_ipc_get_passwd(nthash, sizeof (nthash));
		(void) smb_ctx_setpwhash(ctx, nthash, NULL);
	}
	(void) smb_ctx_setauthflags(ctx, authflags);

	/*
	 * Do lookup, connect, session setup, tree connect.
	 * Or find and reuse a session/tree, if one exists.
	 */
	if ((err = smb_ctx_resolve(ctx)) != 0) {
		err = NT_STATUS_BAD_NETWORK_PATH;
		goto errout;
	}
	if ((err = smb_ctx_get_ssn(ctx)) != 0) {
		err = NT_STATUS_NETWORK_ACCESS_DENIED;
		goto errout;
	}
	if ((err = smb_ctx_get_tree(ctx)) != 0) {
		err = NT_STATUS_BAD_NETWORK_NAME;
		goto errout;
	}

	/* Success! */
	*ctx_p = ctx;
	return (0);

errout:
	smb_ctx_free(ctx);
	return (err);
}
