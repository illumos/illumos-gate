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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Client NDR RPC interface.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <time.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <thread.h>
#include <syslog.h>
#include <synch.h>

#include <libmlrpc/libmlrpc.h>
#include <netsmb/smbfs_api.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <libsmbrdr.h>
#include <mlsvc.h>


/*
 * This call must be made to initialize an RPC client structure and bind
 * to the remote service before any RPCs can be exchanged with that service.
 *
 * The mlsvc_handle_t is a wrapper that is used to associate an RPC handle
 * with the client context for an instance of the interface.  The handle
 * is zeroed to ensure that it doesn't look like a valid handle -
 * handle content is provided by the remove service.
 *
 * The client points to this top-level handle so that we know when to
 * unbind and teardown the connection.  As each handle is initialized it
 * will inherit a reference to the client context.
 *
 * Returns 0 or an NT_STATUS:		(failed in...)
 *
 *	NT_STATUS_BAD_NETWORK_PATH	(get server addr)
 *	NT_STATUS_NETWORK_ACCESS_DENIED	(connect, auth)
 *	NT_STATUS_BAD_NETWORK_NAME	(tcon)
 *	RPC_NT_SERVER_TOO_BUSY		(open pipe)
 *	RPC_NT_SERVER_UNAVAILABLE	(open pipe)
 *	NT_STATUS_ACCESS_DENIED		(open pipe)
 *	NT_STATUS_INVALID_PARAMETER	(rpc bind)
 *	NT_STATUS_INTERNAL_ERROR	(bad args etc)
 *	NT_STATUS_NO_MEMORY
 */
DWORD
ndr_rpc_bind(mlsvc_handle_t *handle, char *server, char *domain,
    char *username, const char *service)
{
	struct smb_ctx		*ctx = NULL;
	ndr_service_t		*svc;
	DWORD			status;
	int			rc;

	if (handle == NULL || server == NULL || server[0] == '\0' ||
	    domain == NULL || username == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

	/* In case the service was not registered... */
	if ((svc = ndr_svc_lookup_name(service)) == NULL)
		return (NT_STATUS_INTERNAL_ERROR);

	/*
	 * Some callers pass this when they want a NULL session.
	 * Todo: have callers pass an empty string for that.
	 */
	if (strcmp(username, MLSVC_ANON_USER) == 0)
		username = "";

	/*
	 * Setup smbfs library handle, authenticate, connect to
	 * the IPC$ share.  This will reuse an existing connection
	 * if the driver already has one for this combination of
	 * server, user, domain.  It may return any of:
	 *	NT_STATUS_BAD_NETWORK_PATH	(get server addr)
	 *	NT_STATUS_NETWORK_ACCESS_DENIED	(connect, auth)
	 *	NT_STATUS_BAD_NETWORK_NAME	(tcon)
	 */
	status = smbrdr_ctx_new(&ctx, server, domain, username);
	if (status != NT_STATUS_SUCCESS) {
		syslog(LOG_ERR, "ndr_rpc_bind: smbrdr_ctx_new"
		    "(Srv=%s Dom=%s User=%s), %s (0x%x)",
		    server, domain, username,
		    xlate_nt_status(status), status);
		/*
		 * If the error is one where changing to a new DC
		 * might help, try looking for a different DC.
		 */
		switch (status) {
		case NT_STATUS_BAD_NETWORK_PATH:
		case NT_STATUS_BAD_NETWORK_NAME:
			/* Look for a new DC */
			smb_ddiscover_bad_dc(server);
		default:
			break;
		}
		return (status);
	}

	/*
	 * Setup the RPC client handle.
	 */
	rc = mlrpc_clh_create(handle, ctx);
	if (rc != 0) {
		syslog(LOG_ERR, "ndr_rpc_bind: mlrpc_clh_create: rc=%d", rc);
		smbrdr_ctx_free(ctx);
		switch (rc) {
		case ENOMEM:
			return (NT_STATUS_NO_MEMORY);
		case EINVAL:
			return (NT_STATUS_INVALID_PARAMETER);
		default:
			return (NT_STATUS_INTERNAL_ERROR);
		}
	}

	/*
	 * This does the pipe open and OtW RPC bind.
	 * Handles pipe open retries.
	 */
	status = mlrpc_clh_bind(handle, svc);
	if (status != 0) {
		syslog(LOG_DEBUG, "ndr_rpc_bind: "
		    "mlrpc_clh_bind, %s (0x%x)",
		    xlate_nt_status(status), status);
		switch (status) {
		case RPC_NT_SERVER_TOO_BUSY:
			/* Look for a new DC */
			smb_ddiscover_bad_dc(server);
			break;
		default:
			break;
		}
		ctx = mlrpc_clh_free(handle);
		if (ctx != NULL) {
			smbrdr_ctx_free(ctx);
		}
	}

	return (status);
}

/*
 * Unbind and close the pipe to an RPC service
 * and cleanup the smb_ctx.
 *
 * The heap may or may not be destroyed (see mlrpc_clh_free)
 */
void
ndr_rpc_unbind(mlsvc_handle_t *handle)
{
	struct smb_ctx *ctx;

	ctx = mlrpc_clh_free(handle);
	if (ctx != NULL)
		smbrdr_ctx_free(ctx);

	bzero(handle, sizeof (mlsvc_handle_t));
}

void
ndr_rpc_status(mlsvc_handle_t *handle, int opnum, DWORD status)
{
	ndr_service_t *svc;
	char *name = "NDR RPC";
	char *s = "unknown";

	switch (NT_SC_SEVERITY(status)) {
	case NT_STATUS_SEVERITY_SUCCESS:
		s = "success";
		break;
	case NT_STATUS_SEVERITY_INFORMATIONAL:
		s = "info";
		break;
	case NT_STATUS_SEVERITY_WARNING:
		s = "warning";
		break;
	case NT_STATUS_SEVERITY_ERROR:
		s = "error";
		break;
	}

	if (handle) {
		svc = handle->clnt->binding->service;
		name = svc->name;
	}

	smb_tracef("%s[0x%02x]: %s: %s (0x%08x)",
	    name, opnum, s, xlate_nt_status(status), status);
}
