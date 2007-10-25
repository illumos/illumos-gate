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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Local Security Authority RPC (LSARPC) library interface functions for
 * open and close calls.
 */

#include <stdio.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/lsalib.h>

/*
 * lsar_open
 *
 * This is a wrapper round lsar_open_policy2 to ensure that we connect
 * using the appropriate session and logon. We default to the resource
 * domain information if the caller didn't supply a server name and a
 * domain name.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
int lsar_open(int ipc_mode, char *server, char *domain, char *username,
    char *password, mlsvc_handle_t *domain_handle)
{
	smb_ntdomain_t *di;
	int remote_os;
	int remote_lm;
	int rc;

	if ((di = smb_getdomaininfo(0)) == NULL)
		return (-1);

	if (server == NULL || domain == NULL) {
		server = di->server;
		domain = di->domain;
	}

	switch (ipc_mode) {
	case MLSVC_IPC_USER:
		/*
		 * Use the supplied credentials.
		 */
		rc = mlsvc_user_logon(server, domain, username, password);
		break;

	case MLSVC_IPC_ADMIN:
		/*
		 * Use the resource domain administrator credentials.
		 */
		server = di->server;
		domain = di->domain;
		username = smbrdr_ipc_get_user();

		rc = mlsvc_admin_logon(server, domain);
		break;

	case MLSVC_IPC_ANON:
	default:
		rc = mlsvc_anonymous_logon(server, domain, &username);
		break;
	}

	if (rc != 0)
		return (-1);

	rc = lsar_open_policy2(server, domain, username, domain_handle);
	if (rc == 0) {
		if (mlsvc_session_native_values(domain_handle->context->fid,
		    &remote_os, &remote_lm, 0) != 0)
			remote_os = NATIVE_OS_UNKNOWN;

		domain_handle->context->server_os = remote_os;
	}
	return (rc);
}


/*
 * lsar_open_policy2
 *
 * Obtain an LSA policy handle. A policy handle is required to access
 * LSA resources on a remote server. The server name supplied here does
 * not need the double backslash prefix; it is added here. Call this
 * function via lsar_open to ensure that the appropriate connection is
 * in place.
 *
 * I'm not sure if it makes a difference whether we use GENERIC_EXECUTE
 * or STANDARD_RIGHTS_EXECUTE. For a long time I used the standard bit
 * and then I added the generic bit while working on privileges because
 * NT sets that bit. I don't think it matters.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int lsar_open_policy2(char *server, char *domain, char *username,
    mlsvc_handle_t *lsa_handle)
{
	struct mslsa_OpenPolicy2 arg;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;
	int fid;
	int remote_os;
	int remote_lm;
	int len;

	if (server == NULL || domain == NULL ||
	    username == NULL || lsa_handle == NULL)
		return (-1);

	fid = mlsvc_open_pipe(server, domain, username, "\\lsarpc");
	if (fid < 0)
		return (-1);

	if ((rc = mlsvc_rpc_bind(lsa_handle, fid, "LSARPC")) < 0) {
		(void) mlsvc_close_pipe(fid);
		return (rc);
	}

	opnum = LSARPC_OPNUM_OpenPolicy2;
	bzero(&arg, sizeof (struct mslsa_OpenPolicy2));

	len = strlen(server) + 4;
	arg.servername = malloc(len);
	if (arg.servername == NULL) {
		(void) mlsvc_close_pipe(fid);
		free(lsa_handle->context);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.attributes.length = sizeof (struct mslsa_object_attributes);

	(void) mlsvc_session_native_values(fid, &remote_os, &remote_lm, 0);

	if (remote_os == NATIVE_OS_NT5_0) {
		arg.desiredAccess = MAXIMUM_ALLOWED;
	} else {
		arg.desiredAccess = GENERIC_EXECUTE
		    | STANDARD_RIGHTS_EXECUTE
		    | POLICY_VIEW_LOCAL_INFORMATION
		    | POLICY_LOOKUP_NAMES;
	}

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(lsa_handle->context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			rc = -1;
		} else {
			(void) memcpy(&lsa_handle->handle, &arg.domain_handle,
			    sizeof (mslsa_handle_t));

			if (mlsvc_is_null_handle(lsa_handle))
				rc = -1;
		}
	}

	mlsvc_rpc_free(lsa_handle->context, &heap);
	free(arg.servername);

	if (rc != 0) {
		(void) mlsvc_close_pipe(fid);
		free(lsa_handle->context);
	}

	return (rc);
}

/*
 * lsar_open_account
 *
 * Obtain an LSA account handle. The lsa_handle must be a valid handle
 * obtained via lsar_open_policy2. The main thing to remember here is
 * to set up the context in the lsa_account_handle. I'm not sure what
 * the requirements are for desired access. Some values require admin
 * access.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int
lsar_open_account(mlsvc_handle_t *lsa_handle, struct mslsa_sid *sid,
    mlsvc_handle_t *lsa_account_handle)
{
	struct mslsa_OpenAccount arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;

	if (mlsvc_is_null_handle(lsa_handle) ||
	    sid == NULL || lsa_account_handle == NULL)
		return (-1);

	context = lsa_handle->context;
	opnum = LSARPC_OPNUM_OpenAccount;
	bzero(&arg, sizeof (struct mslsa_OpenAccount));

	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));
	arg.sid = sid;
	arg.access_mask = STANDARD_RIGHTS_REQUIRED
#if 0
	    | POLICY_VIEW_AUDIT_INFORMATION
	    | POLICY_GET_PRIVATE_INFORMATION
	    | POLICY_TRUST_ADMIN
#endif
	    | POLICY_VIEW_LOCAL_INFORMATION;

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			rc = -1;
		} else {
			lsa_account_handle->context = context;

			(void) memcpy(&lsa_account_handle->handle,
			    &arg.account_handle, sizeof (mslsa_handle_t));

			if (mlsvc_is_null_handle(lsa_account_handle))
				rc = -1;
		}
	}

	mlsvc_rpc_free(context, &heap);
	return (rc);
}

/*
 * lsar_close
 *
 * Close the LSA connection associated with the handle. The lsa_handle
 * must be a valid handle obtained via a call to lsar_open_policy2 or
 * lsar_open_account. On success the handle will be zeroed out to
 * ensure that it is not used again. If this is the top level handle
 * (i.e. the one obtained via lsar_open_policy2) the pipe is closed
 * and the context is freed.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int
lsar_close(mlsvc_handle_t *lsa_handle)
{
	struct mslsa_CloseHandle arg;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;

	if (mlsvc_is_null_handle(lsa_handle))
		return (-1);

	opnum = LSARPC_OPNUM_CloseHandle;
	bzero(&arg, sizeof (struct mslsa_CloseHandle));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(lsa_handle->context, opnum, &arg, &heap);
	mlsvc_rpc_free(lsa_handle->context, &heap);

	if (lsa_handle->context->handle == &lsa_handle->handle) {
		(void) mlsvc_close_pipe(lsa_handle->context->fid);
		free(lsa_handle->context);
	}

	bzero(lsa_handle, sizeof (mlsvc_handle_t));
	return (rc);
}
