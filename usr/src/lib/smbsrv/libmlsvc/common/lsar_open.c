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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Local Security Authority RPC (LSARPC) library interface functions for
 * open and close calls.
 */

#include <stdio.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/ntstatus.h>
#include <lsalib.h>

/*
 * lsar_open
 *
 * This is a wrapper round lsar_open_policy2 to ensure that we connect
 * using the appropriate domain information.
 *
 * If username argument is NULL, an anonymous connection will be established.
 * Otherwise, an authenticated connection will be established.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
int lsar_open(char *server, char *domain, char *username,
    mlsvc_handle_t *domain_handle)
{
	if (server == NULL || domain == NULL)
		return (-1);

	if (username == NULL)
		username = MLSVC_ANON_USER;

	return (lsar_open_policy2(server, domain, username, domain_handle));
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
int
lsar_open_policy2(char *server, char *domain, char *username,
    mlsvc_handle_t *lsa_handle)
{
	struct mslsa_OpenPolicy2 arg;
	int opnum;
	int len;
	int rc;

	rc = ndr_rpc_bind(lsa_handle, server, domain, username, "LSARPC");
	if (rc != 0)
		return (-1);

	opnum = LSARPC_OPNUM_OpenPolicy2;
	bzero(&arg, sizeof (struct mslsa_OpenPolicy2));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(lsa_handle, len);
	if (arg.servername == NULL) {
		ndr_rpc_unbind(lsa_handle);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.attributes.length = sizeof (struct mslsa_object_attributes);

	if (ndr_rpc_server_os(lsa_handle) == NATIVE_OS_NT5_0) {
		arg.desiredAccess = MAXIMUM_ALLOWED;
	} else {
		arg.desiredAccess = GENERIC_EXECUTE
		    | STANDARD_RIGHTS_EXECUTE
		    | POLICY_VIEW_LOCAL_INFORMATION
		    | POLICY_LOOKUP_NAMES;
	}

	if ((rc = ndr_rpc_call(lsa_handle, opnum, &arg)) != 0) {
		ndr_rpc_unbind(lsa_handle);
		return (-1);
	}

	if (arg.status != 0) {
		rc = -1;
	} else {
		(void) memcpy(&lsa_handle->handle, &arg.domain_handle,
		    sizeof (ndr_hdid_t));

		if (ndr_is_null_handle(lsa_handle))
			rc = -1;
	}

	ndr_rpc_release(lsa_handle);

	if (rc != 0)
		ndr_rpc_unbind(lsa_handle);
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
	int opnum;
	int rc;

	if (ndr_is_null_handle(lsa_handle) || sid == NULL)
		return (-1);

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

	if ((rc = ndr_rpc_call(lsa_handle, opnum, &arg)) != 0)
		return (-1);

	if (arg.status != 0) {
		rc = -1;
	} else {
		ndr_inherit_handle(lsa_account_handle, lsa_handle);

		(void) memcpy(&lsa_account_handle->handle,
		    &arg.account_handle, sizeof (ndr_hdid_t));

		if (ndr_is_null_handle(lsa_account_handle))
			rc = -1;
	}

	ndr_rpc_release(lsa_handle);
	return (rc);
}

/*
 * lsar_close
 *
 * Close the LSA connection associated with the handle. The lsa_handle
 * must be a valid handle obtained via a call to lsar_open_policy2 or
 * lsar_open_account. On success the handle will be zeroed out to
 * ensure that it is not used again. If this is the top level handle
 * (i.e. the one obtained via lsar_open_policy2) the pipe is closed.
 *
 * Returns 0 on success. Otherwise non-zero to indicate a failure.
 */
int
lsar_close(mlsvc_handle_t *lsa_handle)
{
	struct mslsa_CloseHandle arg;
	int opnum;

	if (ndr_is_null_handle(lsa_handle))
		return (-1);

	opnum = LSARPC_OPNUM_CloseHandle;
	bzero(&arg, sizeof (struct mslsa_CloseHandle));
	(void) memcpy(&arg.handle, lsa_handle, sizeof (mslsa_handle_t));

	(void) ndr_rpc_call(lsa_handle, opnum, &arg);
	ndr_rpc_release(lsa_handle);

	if (ndr_is_bind_handle(lsa_handle))
		ndr_rpc_unbind(lsa_handle);

	bzero(lsa_handle, sizeof (mlsvc_handle_t));
	return (0);
}
