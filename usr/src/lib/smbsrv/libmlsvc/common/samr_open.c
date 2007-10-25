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
 * Security Access Manager RPC (SAMR) library interface functions for
 * connect, open and close calls.  The SAM is a hierarchical database.
 * If you want to talk to the SAM you need a SAM handle, if you want
 * to work with a domain, you need to use the SAM handle to obtain a
 * domain handle.  Then you can use the domain handle to obtain a user
 * handle etc.  Be careful about returning null handles to the
 * application.  Use of a null handle may crash the domain controller
 * if you attempt to use it.
 */

#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/param.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/ntaccess.h>
#include <smbsrv/samlib.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/mlsvc.h>

/*LINTED E_STATIC_UNUSED*/
static DWORD samr_connect1(char *, char *, char *, DWORD, mlsvc_handle_t *);
static DWORD samr_connect2(char *, char *, char *, DWORD, mlsvc_handle_t *);
static DWORD samr_connect3(char *, char *, char *, DWORD, mlsvc_handle_t *);
static DWORD samr_connect4(char *, char *, char *, DWORD, mlsvc_handle_t *);

/*
 * samr_open
 *
 * This is a wrapper round samr_connect to ensure that we connect using
 * the appropriate session and logon.  We default to the resource domain
 * information if the caller doesn't supply a server name and a domain
 * name.  We store the remote server's native OS type - we may need it
 * due to differences between platforms like NT and Windows 2000.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
int
samr_open(int ipc_mode, char *server, char *domain, char *username,
    char *password, DWORD access_mask, mlsvc_handle_t *samr_handle)
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

	rc = samr_connect(server, domain, username, access_mask, samr_handle);
	if (rc == 0) {
		(void) mlsvc_session_native_values(samr_handle->context->fid,
		    &remote_os, &remote_lm, 0);
		samr_handle->context->server_os = remote_os;
	}
	return (rc);
}


/*
 * samr_connect
 *
 * Connect to the SAM on the specified server (domain controller).
 * This is the entry point for the various SAM connect calls.  We do
 * parameter validation and open the samr named pipe here.  The actual
 * RPC is based on the native OS of the server.
 *
 * Returns 0 on success. Otherwise returns a -ve error code.
 */
int
samr_connect(char *server, char *domain, char *username, DWORD access_mask,
    mlsvc_handle_t *samr_handle)
{
	DWORD status;
	int remote_os;
	int remote_lm;
	int fid;
	int rc = 0;

	if (server == NULL || domain == NULL ||
	    username == NULL || samr_handle == NULL)
		return (-1);

	if ((fid = mlsvc_open_pipe(server, domain, username, "\\samr")) < 0)
		return (-1);

	if (mlsvc_rpc_bind(samr_handle, fid, "SAMR") < 0) {
		(void) mlsvc_close_pipe(fid);
		return (-1);
	}

	(void) mlsvc_session_native_values(fid, &remote_os, &remote_lm, 0);

	switch (remote_os) {
	case NATIVE_OS_NT5_1:
		status = samr_connect4(server, domain, username, access_mask,
		    samr_handle);
		break;

	case NATIVE_OS_NT5_0:
		status = samr_connect3(server, domain, username, access_mask,
		    samr_handle);
		break;

	case NATIVE_OS_NT4_0:
	default:
		status = samr_connect2(server, domain, username, access_mask,
		    samr_handle);
		break;
	}

	if (status != NT_STATUS_SUCCESS) {
		(void) mlsvc_close_pipe(fid);
		free(samr_handle->context);
		rc = -1;
	}
	return (rc);
}

/*
 * samr_connect1
 *
 * Original SAMR connect call; probably used on Windows NT 3.51.
 * Windows 95 uses this call with the srvmgr tools update.
 * Servername appears to be a dword rather than a string.
 * The first word contains '\' and the second word contains 0x001,
 * (which is probably uninitialized junk: 0x0001005c.
 */
/*ARGSUSED*/
static DWORD
samr_connect1(char *server, char *domain, char *username, DWORD access_mask,
    mlsvc_handle_t *samr_handle)
{
	struct samr_ConnectAnon arg;
	mlrpc_heapref_t heapref;
	int opnum;
	DWORD status;

	bzero(&arg, sizeof (struct samr_ConnectAnon));
	opnum = SAMR_OPNUM_ConnectAnon;
	status = NT_STATUS_SUCCESS;

	(void) mlsvc_rpc_init(&heapref);
	arg.servername = (DWORD *)mlrpc_heap_malloc(heapref.heap,
	    sizeof (DWORD));
	*(arg.servername) = 0x0001005c;
	arg.access_mask = access_mask;

	if (mlsvc_rpc_call(samr_handle->context, opnum, &arg, &heapref) != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (arg.status != 0) {
		status = NT_SC_VALUE(arg.status);
	} else {
		(void) memcpy(&samr_handle->handle, &arg.handle,
		    sizeof (ms_handle_t));

		if (mlsvc_is_null_handle(samr_handle))
			status = NT_STATUS_INVALID_HANDLE;
	}

	mlsvc_rpc_free(samr_handle->context, &heapref);
	return (status);
}

/*
 * samr_connect2
 *
 * Connect to the SAM on a Windows NT 4.0 server (domain controller).
 * We need the domain controller name and, if everything works, we
 * return a handle.  This function adds the double backslash prefx to
 * make it easy for applications.
 *
 * Returns 0 on success. Otherwise returns a -ve error code.
 */
/*ARGSUSED*/
static DWORD
samr_connect2(char *server, char *domain, char *username, DWORD access_mask,
    mlsvc_handle_t *samr_handle)
{
	struct samr_Connect arg;
	mlrpc_heapref_t heapref;
	int opnum;
	DWORD status;
	int len;

	bzero(&arg, sizeof (struct samr_Connect));
	opnum = SAMR_OPNUM_Connect;
	status = NT_STATUS_SUCCESS;

	(void) mlsvc_rpc_init(&heapref);
	len = strlen(server) + 4;
	arg.servername = mlrpc_heap_malloc(heapref.heap, len);
	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.access_mask = access_mask;

	if (mlsvc_rpc_call(samr_handle->context, opnum, &arg, &heapref) != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (arg.status != 0) {
		status = NT_SC_VALUE(arg.status);
	} else {
		(void) memcpy(&samr_handle->handle, &arg.handle,
		    sizeof (ms_handle_t));

		if (mlsvc_is_null_handle(samr_handle))
			status = NT_STATUS_INVALID_HANDLE;
	}

	mlsvc_rpc_free(samr_handle->context, &heapref);
	return (status);
}

/*
 * samr_connect3
 *
 * Connect to the SAM on a Windows 2000 domain controller.
 */
/*ARGSUSED*/
static DWORD
samr_connect3(char *server, char *domain, char *username, DWORD access_mask,
    mlsvc_handle_t *samr_handle)
{
	struct samr_Connect3 arg;
	mlrpc_heapref_t heapref;
	int opnum;
	DWORD status;
	int len;

	bzero(&arg, sizeof (struct samr_Connect3));
	opnum = SAMR_OPNUM_Connect3;
	status = NT_STATUS_SUCCESS;

	(void) mlsvc_rpc_init(&heapref);
	len = strlen(server) + 4;
	arg.servername = mlrpc_heap_malloc(heapref.heap, len);
	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.unknown_02 = 0x00000002;
	arg.access_mask = access_mask;

	if (mlsvc_rpc_call(samr_handle->context, opnum, &arg, &heapref) != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (arg.status != 0) {
		status = NT_SC_VALUE(arg.status);
	} else {
		(void) memcpy(&samr_handle->handle, &arg.handle,
		    sizeof (ms_handle_t));

		if (mlsvc_is_null_handle(samr_handle))
			status = NT_STATUS_INVALID_HANDLE;
	}

	mlsvc_rpc_free(samr_handle->context, &heapref);
	return (status);
}

/*
 * samr_connect4
 *
 * Connect to the SAM on a Windows XP domain controller.  On Windows
 * XP, the server should be the fully qualified DNS domain name with
 * a double backslash prefix.  At this point, it is assumed that we
 * need to add the prefix and the DNS domain name here.
 *
 * If this call succeeds, a SAMR handle is placed in samr_handle and
 * zero is returned. Otherwise, a -ve error code is returned.
 */
/*ARGSUSED*/
static DWORD
samr_connect4(char *server, char *domain, char *username, DWORD access_mask,
    mlsvc_handle_t *samr_handle)
{
	struct samr_Connect4 arg;
	mlrpc_heapref_t heapref;
	char *dns_name;
	int len;
	int opnum;
	DWORD status;

	bzero(&arg, sizeof (struct samr_Connect4));
	opnum = SAMR_OPNUM_Connect;
	status = NT_STATUS_SUCCESS;

	(void) mlsvc_rpc_init(&heapref);
	dns_name = mlrpc_heap_malloc(heapref.heap, MAXHOSTNAMELEN);
	(void) smb_getdomainname(dns_name, MAXHOSTNAMELEN);

	if (strlen(dns_name) > 0) {
		len = strlen(server) + strlen(dns_name) + 4;
		arg.servername = mlrpc_heap_malloc(heapref.heap, len);
		(void) snprintf((char *)arg.servername, len, "\\\\%s.%s",
		    server, dns_name);
	} else {
		len = strlen(server) + 4;
		arg.servername = mlrpc_heap_malloc(heapref.heap, len);
		(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	}

	arg.access_mask = SAM_ENUM_LOCAL_DOMAIN;
	arg.unknown2_00000001 = 0x00000001;
	arg.unknown3_00000001 = 0x00000001;
	arg.unknown4_00000003 = 0x00000003;
	arg.unknown5_00000000 = 0x00000000;

	if (mlsvc_rpc_call(samr_handle->context, opnum, &arg, &heapref) != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (arg.status != 0) {
		status = NT_SC_VALUE(arg.status);
	} else {

		(void) memcpy(&samr_handle->handle, &arg.handle,
		    sizeof (ms_handle_t));

		if (mlsvc_is_null_handle(samr_handle))
			status = NT_STATUS_INVALID_HANDLE;
	}

	mlsvc_rpc_free(samr_handle->context, &heapref);

	return (status);
}


/*
 * samr_close_handle
 *
 * This is function closes any valid handle, i.e. sam, domain, user etc.
 * Just to be safe we check for, and reject, null handles. The handle
 * returned by the SAM server is all null. If the handle being closed is
 * the top level connect handle, we also close the pipe. Then we zero
 * out the handle to invalidate it. Things go badly if you attempt to
 * use an invalid handle, i.e. the DC crashes.
 */
int
samr_close_handle(mlsvc_handle_t *desc)
{
	struct samr_CloseHandle arg;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	if (mlsvc_is_null_handle(desc))
		return (-1);

	opnum = SAMR_OPNUM_CloseHandle;
	bzero(&arg, sizeof (struct samr_CloseHandle));
	(void) memcpy(&arg.handle, &desc->handle, sizeof (ms_handle_t));

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(desc->context, opnum, &arg, &heap);
	mlsvc_rpc_free(desc->context, &heap);

	if (desc->context->handle == &desc->handle) {
		(void) mlsvc_close_pipe(desc->context->fid);
		free(desc->context);
	}

	bzero(desc, sizeof (mlsvc_handle_t));
	return (rc);
}

/*
 * samr_open_domain
 *
 * We use a SAM handle to obtain a handle for a domain, specified by
 * the SID. The SID can be obtain via the LSA interface. A handle for
 * the domain is returned in domain_handle.
 */
DWORD
samr_open_domain(mlsvc_handle_t *samr_handle, DWORD access_mask,
    struct samr_sid *sid, mlsvc_handle_t *domain_handle)
{
	struct samr_OpenDomain arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	DWORD status;

	if (mlsvc_is_null_handle(samr_handle) ||
	    sid == 0 || domain_handle == 0) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	context = samr_handle->context;
	opnum = SAMR_OPNUM_OpenDomain;
	bzero(&arg, sizeof (struct samr_OpenDomain));
	(void) memcpy(&arg.handle, &samr_handle->handle, sizeof (ms_handle_t));

	arg.access_mask = access_mask;
	arg.sid = sid;

	(void) mlsvc_rpc_init(&heap);
	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (arg.status != 0) {
		status = arg.status;
	} else {
		status = NT_STATUS_SUCCESS;
		(void) memcpy(&domain_handle->handle, &arg.domain_handle,
		    sizeof (ms_handle_t));
		domain_handle->context = context;
		if (mlsvc_is_null_handle(domain_handle))
			status = NT_STATUS_INVALID_HANDLE;
	}

	if (status != NT_STATUS_SUCCESS)
		mlsvc_rpc_report_status(opnum, status);

	mlsvc_rpc_free(context, &heap);
	return (status);
}

/*
 * samr_open_user
 *
 * Use a domain handle to obtain a handle for a user, specified by the
 * user RID. A user RID (effectively a uid) can be obtained via the
 * LSA interface. A handle for the user is returned in user_handle.
 * Once you have a user handle it should be possible to query the SAM
 * for information on that user.
 */
int
samr_open_user(mlsvc_handle_t *domain_handle, DWORD access_mask, DWORD rid,
    mlsvc_handle_t *user_handle)
{
	struct samr_OpenUser arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	if (mlsvc_is_null_handle(domain_handle) || user_handle == NULL)
		return (-1);

	context = domain_handle->context;
	opnum = SAMR_OPNUM_OpenUser;
	bzero(&arg, sizeof (struct samr_OpenUser));
	(void) memcpy(&arg.handle, &domain_handle->handle,
	    sizeof (ms_handle_t));
	arg.access_mask = access_mask;
	arg.rid = rid;

	(void) mlsvc_rpc_init(&heap);
	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			mlsvc_rpc_report_status(opnum, arg.status);
			rc = -1;
		} else {
			(void) memcpy(&user_handle->handle, &arg.user_handle,
			    sizeof (ms_handle_t));
			user_handle->context = context;

			if (mlsvc_is_null_handle(user_handle))
				rc = -1;
		}
	}

	mlsvc_rpc_free(context, &heap);
	return (rc);
}

/*
 * samr_delete_user
 *
 * Delete the user specified by the user_handle.
 */
DWORD
samr_delete_user(mlsvc_handle_t *user_handle)
{
	struct samr_DeleteUser arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	DWORD status;

	if (mlsvc_is_null_handle(user_handle))
		return (NT_STATUS_INVALID_PARAMETER);

	context = user_handle->context;
	opnum = SAMR_OPNUM_DeleteUser;
	bzero(&arg, sizeof (struct samr_DeleteUser));
	(void) memcpy(&arg.user_handle, &user_handle->handle,
	    sizeof (ms_handle_t));

	(void) mlsvc_rpc_init(&heap);
	if (mlsvc_rpc_call(context, opnum, &arg, &heap) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		mlsvc_rpc_report_status(opnum, arg.status);
		status = NT_SC_VALUE(arg.status);
	} else {
		status = 0;
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}

/*
 * samr_open_group
 *
 * Use a domain handle to obtain a handle for a group, specified by the
 * group RID. A group RID (effectively a gid) can be obtained via the
 * LSA interface. A handle for the group is returned in group_handle.
 * Once you have a group handle it should be possible to query the SAM
 * for information on that group.
 */
int
samr_open_group(
	mlsvc_handle_t *domain_handle,
	DWORD rid,
	mlsvc_handle_t *group_handle)
{
	struct samr_OpenGroup arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;

	if (mlsvc_is_null_handle(domain_handle) || group_handle == 0)
		return (-1);

	context = domain_handle->context;
	opnum = SAMR_OPNUM_OpenGroup;
	bzero(&arg, sizeof (struct samr_OpenUser));
	(void) memcpy(&arg.handle, &domain_handle->handle,
	    sizeof (ms_handle_t));
	arg.access_mask = SAM_LOOKUP_INFORMATION | SAM_ACCESS_USER_READ;
	arg.rid = rid;

	(void) mlsvc_rpc_init(&heap);

	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc == 0) {
		if (arg.status != 0) {
			mlsvc_rpc_report_status(opnum, arg.status);
			rc = -1;
		} else {
			(void) memcpy(&group_handle->handle, &arg.group_handle,
			    sizeof (ms_handle_t));
			group_handle->context = context;
			if (mlsvc_is_null_handle(group_handle))
				rc = -1;
		}
	}

	mlsvc_rpc_free(context, &heap);
	return (rc);
}

/*
 * samr_create_user
 *
 * Create a user in the domain specified by the domain handle. If this
 * call is successful, the server will return the RID for the user and
 * a user handle, which may be used to set or query the SAM.
 *
 * Observed status codes:
 *	NT_STATUS_INVALID_PARAMETER
 *	NT_STATUS_INVALID_ACCOUNT_NAME
 *	NT_STATUS_ACCESS_DENIED
 *	NT_STATUS_USER_EXISTS
 *
 * Returns 0 on success. Otherwise returns an NT status code.
 */
DWORD
samr_create_user(mlsvc_handle_t *domain_handle, char *username,
    DWORD account_flags, DWORD *rid, mlsvc_handle_t *user_handle)
{
	struct samr_CreateUser arg;
	struct mlsvc_rpc_context *context;
	mlrpc_heapref_t heap;
	int opnum;
	int rc;
	DWORD status = 0;

	if (mlsvc_is_null_handle(domain_handle) ||
	    username == NULL || rid == NULL) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	context = domain_handle->context;
	opnum = SAMR_OPNUM_CreateUser;

	bzero(&arg, sizeof (struct samr_CreateUser));
	(void) memcpy(&arg.handle, &domain_handle->handle,
	    sizeof (ms_handle_t));

	(void) mlsvc_rpc_init(&heap);
	mlrpc_heap_mkvcs(heap.heap, username, (mlrpc_vcbuf_t *)&arg.username);

	arg.account_flags = account_flags;
	arg.unknown_e00500b0 = 0xE00500B0;

	rc = mlsvc_rpc_call(context, opnum, &arg, &heap);
	if (rc != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
	} else if (arg.status != 0) {
		status = NT_SC_VALUE(arg.status);

		if (status != NT_STATUS_USER_EXISTS) {
			smb_tracef("SamrCreateUser[%s]: %s", username,
			    xlate_nt_status(status));
		}
	} else {
		(void) memcpy(&user_handle->handle, &arg.user_handle,
		    sizeof (ms_handle_t));
		user_handle->context = context;
		*rid = arg.rid;

		if (mlsvc_is_null_handle(user_handle))
			status = NT_STATUS_INVALID_HANDLE;
		else
			status = 0;
	}

	mlsvc_rpc_free(context, &heap);
	return (status);
}
