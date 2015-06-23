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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Client NDR RPC interface.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/tzfile.h>
#include <time.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <thread.h>
#include <unistd.h>
#include <syslog.h>
#include <synch.h>

#include <netsmb/smbfs_api.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/srvsvc.ndl>
#include <libsmbrdr.h>
#include <mlsvc.h>

static int ndr_xa_init(ndr_client_t *, ndr_xa_t *);
static int ndr_xa_exchange(ndr_client_t *, ndr_xa_t *);
static int ndr_xa_read(ndr_client_t *, ndr_xa_t *);
static void ndr_xa_preserve(ndr_client_t *, ndr_xa_t *);
static void ndr_xa_destruct(ndr_client_t *, ndr_xa_t *);
static void ndr_xa_release(ndr_client_t *);


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
 */
int
ndr_rpc_bind(mlsvc_handle_t *handle, char *server, char *domain,
    char *username, const char *service)
{
	struct smb_ctx		*ctx = NULL;
	ndr_client_t		*clnt = NULL;
	ndr_service_t		*svc;
	srvsvc_server_info_t	svinfo;
	int			fd = -1;
	int			rc;

	if (handle == NULL || server == NULL ||
	    domain == NULL || username == NULL)
		return (-1);

	if ((svc = ndr_svc_lookup_name(service)) == NULL)
		return (-1);

	/*
	 * Set the default based on the assumption that most
	 * servers will be Windows 2000 or later.  This used to
	 * try to get the actual server version, but that RPC
	 * is not necessarily allowed anymore, so don't bother.
	 */
	bzero(&svinfo, sizeof (srvsvc_server_info_t));
	svinfo.sv_platform_id = SV_PLATFORM_ID_NT;
	svinfo.sv_version_major = 5;
	svinfo.sv_version_minor = 0;
	svinfo.sv_type = SV_TYPE_DEFAULT;
	svinfo.sv_os = NATIVE_OS_WIN2000;

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
	 * server, user, domain.
	 */
	if ((rc = smbrdr_ctx_new(&ctx, server, domain, username)) != 0) {
		syslog(LOG_ERR, "ndr_rpc_bind: smbrdr_ctx_new"
		    "(Srv=%s Dom=%s User=%s), %s (0x%x)",
		    server, domain, username,
		    xlate_nt_status(rc), rc);
		goto errout;
	}

	/*
	 * Open the named pipe.
	 */
	fd = smb_fh_open(ctx, svc->endpoint, O_RDWR);
	if (fd < 0) {
		syslog(LOG_DEBUG, "ndr_rpc_bind: "
		    "smb_fh_open, err=%d", errno);
		goto errout;
	}

	/*
	 * Setup the RPC client handle.
	 */
	if ((clnt = malloc(sizeof (ndr_client_t))) == NULL)
		goto errout;
	bzero(clnt, sizeof (ndr_client_t));

	clnt->handle = &handle->handle;
	clnt->xa_init = ndr_xa_init;
	clnt->xa_exchange = ndr_xa_exchange;
	clnt->xa_read = ndr_xa_read;
	clnt->xa_preserve = ndr_xa_preserve;
	clnt->xa_destruct = ndr_xa_destruct;
	clnt->xa_release = ndr_xa_release;
	clnt->xa_private = ctx;
	clnt->xa_fd = fd;

	ndr_svc_binding_pool_init(&clnt->binding_list,
	    clnt->binding_pool, NDR_N_BINDING_POOL);

	if ((clnt->heap = ndr_heap_create()) == NULL)
		goto errout;

	/*
	 * Fill in the caller's handle.
	 */
	bzero(&handle->handle, sizeof (ndr_hdid_t));
	handle->clnt = clnt;
	bcopy(&svinfo, &handle->svinfo, sizeof (srvsvc_server_info_t));

	/*
	 * Do the OtW RPC bind.
	 */
	rc = ndr_clnt_bind(clnt, service, &clnt->binding);
	if (NDR_DRC_IS_FAULT(rc)) {
		syslog(LOG_DEBUG, "ndr_rpc_bind: "
		    "ndr_clnt_bind, rc=0x%x", rc);
		goto errout;
	}

	/* Success! */
	return (0);

errout:
	handle->clnt = NULL;
	if (clnt != NULL) {
		ndr_heap_destroy(clnt->heap);
		free(clnt);
	}
	if (ctx != NULL) {
		if (fd != -1)
			(void) smb_fh_close(fd);
		smbrdr_ctx_free(ctx);
	}

	return (-1);
}

/*
 * Unbind and close the pipe to an RPC service.
 *
 * If the heap has been preserved we need to go through an xa release.
 * The heap is preserved during an RPC call because that's where data
 * returned from the server is stored.
 *
 * Otherwise we destroy the heap directly.
 */
void
ndr_rpc_unbind(mlsvc_handle_t *handle)
{
	ndr_client_t *clnt = handle->clnt;
	struct smb_ctx *ctx = clnt->xa_private;

	if (clnt->heap_preserved)
		ndr_clnt_free_heap(clnt);
	else
		ndr_heap_destroy(clnt->heap);

	(void) smb_fh_close(clnt->xa_fd);
	smbrdr_ctx_free(ctx);
	free(clnt);
	bzero(handle, sizeof (mlsvc_handle_t));
}

/*
 * Call the RPC function identified by opnum.  The remote service is
 * identified by the handle, which should have been initialized by
 * ndr_rpc_bind.
 *
 * If the RPC call is successful (returns 0), the caller must call
 * ndr_rpc_release to release the heap.  Otherwise, we release the
 * heap here.
 */
int
ndr_rpc_call(mlsvc_handle_t *handle, int opnum, void *params)
{
	ndr_client_t *clnt = handle->clnt;
	int rc;

	if (ndr_rpc_get_heap(handle) == NULL)
		return (-1);

	rc = ndr_clnt_call(clnt->binding, opnum, params);

	/*
	 * Always clear the nonull flag to ensure
	 * it is not applied to subsequent calls.
	 */
	clnt->nonull = B_FALSE;

	if (NDR_DRC_IS_FAULT(rc)) {
		ndr_rpc_release(handle);
		return (-1);
	}

	return (0);
}

/*
 * Outgoing strings should not be null terminated.
 */
void
ndr_rpc_set_nonull(mlsvc_handle_t *handle)
{
	handle->clnt->nonull = B_TRUE;
}

/*
 * Return a reference to the server info.
 */
const srvsvc_server_info_t *
ndr_rpc_server_info(mlsvc_handle_t *handle)
{
	return (&handle->svinfo);
}

/*
 * Return the RPC server OS level.
 */
uint32_t
ndr_rpc_server_os(mlsvc_handle_t *handle)
{
	return (handle->svinfo.sv_os);
}

/*
 * Get the session key from a bound RPC client handle.
 *
 * The key returned is the 16-byte "user session key"
 * established by the underlying authentication protocol
 * (either Kerberos or NTLM).  This key is needed for
 * SAM RPC calls such as SamrSetInformationUser, etc.
 * See [MS-SAMR] sections: 2.2.3.3, 2.2.7.21, 2.2.7.25.
 *
 * Returns zero (success) or an errno.
 */
int
ndr_rpc_get_ssnkey(mlsvc_handle_t *handle,
	unsigned char *ssn_key, size_t len)
{
	ndr_client_t *clnt = handle->clnt;
	int rc;

	if (clnt == NULL)
		return (EINVAL);

	rc = smb_fh_getssnkey(clnt->xa_fd, ssn_key, len);
	return (rc);
}

void *
ndr_rpc_malloc(mlsvc_handle_t *handle, size_t size)
{
	ndr_heap_t *heap;

	if ((heap = ndr_rpc_get_heap(handle)) == NULL)
		return (NULL);

	return (ndr_heap_malloc(heap, size));
}

ndr_heap_t *
ndr_rpc_get_heap(mlsvc_handle_t *handle)
{
	ndr_client_t *clnt = handle->clnt;

	if (clnt->heap == NULL)
		clnt->heap = ndr_heap_create();

	return (clnt->heap);
}

/*
 * Must be called by RPC clients to free the heap after a successful RPC
 * call, i.e. ndr_rpc_call returned 0.  The caller should take a copy
 * of any data returned by the RPC prior to calling this function because
 * returned data is in the heap.
 */
void
ndr_rpc_release(mlsvc_handle_t *handle)
{
	ndr_client_t *clnt = handle->clnt;

	if (clnt->heap_preserved)
		ndr_clnt_free_heap(clnt);
	else
		ndr_heap_destroy(clnt->heap);

	clnt->heap = NULL;
}

/*
 * Returns true if the handle is null.
 * Otherwise returns false.
 */
boolean_t
ndr_is_null_handle(mlsvc_handle_t *handle)
{
	static ndr_hdid_t zero_handle;

	if (handle == NULL || handle->clnt == NULL)
		return (B_TRUE);

	if (!memcmp(&handle->handle, &zero_handle, sizeof (ndr_hdid_t)))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Returns true if the handle is the top level bind handle.
 * Otherwise returns false.
 */
boolean_t
ndr_is_bind_handle(mlsvc_handle_t *handle)
{
	return (handle->clnt->handle == &handle->handle);
}

/*
 * Pass the client reference from parent to child.
 */
void
ndr_inherit_handle(mlsvc_handle_t *child, mlsvc_handle_t *parent)
{
	child->clnt = parent->clnt;
	bcopy(&parent->svinfo, &child->svinfo, sizeof (srvsvc_server_info_t));
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

/*
 * The following functions provide the client callback interface.
 * If the caller hasn't provided a heap, create one here.
 */
static int
ndr_xa_init(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	ndr_stream_t	*recv_nds = &mxa->recv_nds;
	ndr_stream_t	*send_nds = &mxa->send_nds;
	ndr_heap_t	*heap = clnt->heap;
	int		rc;

	if (heap == NULL) {
		if ((heap = ndr_heap_create()) == NULL)
			return (-1);

		clnt->heap = heap;
	}

	mxa->heap = heap;

	rc = nds_initialize(send_nds, 0, NDR_MODE_CALL_SEND, heap);
	if (rc == 0)
		rc = nds_initialize(recv_nds, NDR_PDU_SIZE_HINT_DEFAULT,
		    NDR_MODE_RETURN_RECV, heap);

	if (rc != 0) {
		nds_destruct(&mxa->recv_nds);
		nds_destruct(&mxa->send_nds);
		ndr_heap_destroy(mxa->heap);
		mxa->heap = NULL;
		clnt->heap = NULL;
		return (-1);
	}

	if (clnt->nonull)
		NDS_SETF(send_nds, NDS_F_NONULL);

	return (0);
}

/*
 * This is the entry pointy for an RPC client call exchange with
 * a server, which will result in an smbrdr SmbTransact request.
 *
 * SmbTransact should return the number of bytes received, which
 * we record as the PDU size, or a negative error code.
 */
static int
ndr_xa_exchange(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	ndr_stream_t *recv_nds = &mxa->recv_nds;
	ndr_stream_t *send_nds = &mxa->send_nds;
	int err, more, nbytes;

	nbytes = recv_nds->pdu_max_size;
	err = smb_fh_xactnp(clnt->xa_fd,
	    send_nds->pdu_size, (char *)send_nds->pdu_base_offset,
	    &nbytes, (char *)recv_nds->pdu_base_offset, &more);
	if (err) {
		recv_nds->pdu_size = 0;
		return (-1);
	}

	recv_nds->pdu_size = nbytes;
	return (0);
}

/*
 * This entry point will be invoked if the xa-exchange response contained
 * only the first fragment of a multi-fragment response.  The RPC client
 * code will then make repeated xa-read requests to obtain the remaining
 * fragments, which will result in smbrdr SmbReadX requests.
 *
 * SmbReadX should return the number of bytes received, in which case we
 * expand the PDU size to include the received data, or a negative error
 * code.
 */
static int
ndr_xa_read(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	ndr_stream_t *nds = &mxa->recv_nds;
	int len;
	int nbytes;

	if ((len = (nds->pdu_max_size - nds->pdu_size)) < 0)
		return (-1);

	nbytes = smb_fh_read(clnt->xa_fd, 0, len,
	    (char *)nds->pdu_base_offset + nds->pdu_size);

	if (nbytes < 0)
		return (-1);

	nds->pdu_size += nbytes;

	if (nds->pdu_size > nds->pdu_max_size) {
		nds->pdu_size = nds->pdu_max_size;
		return (-1);
	}

	return (nbytes);
}

/*
 * Preserve the heap so that the client application has access to data
 * returned from the server after an RPC call.
 */
static void
ndr_xa_preserve(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	assert(clnt->heap == mxa->heap);

	clnt->heap_preserved = B_TRUE;
	mxa->heap = NULL;
}

/*
 * Dispose of the transaction streams.  If the heap has not been
 * preserved, we can destroy it here.
 */
static void
ndr_xa_destruct(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	nds_destruct(&mxa->recv_nds);
	nds_destruct(&mxa->send_nds);

	if (!clnt->heap_preserved) {
		ndr_heap_destroy(mxa->heap);
		mxa->heap = NULL;
		clnt->heap = NULL;
	}
}

/*
 * Dispose of a preserved heap.
 */
static void
ndr_xa_release(ndr_client_t *clnt)
{
	if (clnt->heap_preserved) {
		ndr_heap_destroy(clnt->heap);
		clnt->heap = NULL;
		clnt->heap_preserved = B_FALSE;
	}
}


/*
 * Compare the time here with the remote time on the server
 * and report clock skew.
 */
void
ndr_srvsvc_timecheck(char *server, char *domain)
{
	char			hostname[MAXHOSTNAMELEN];
	struct timeval		dc_tv;
	struct tm		dc_tm;
	struct tm		*tm;
	time_t			tnow;
	time_t			tdiff;
	int			priority;

	if (srvsvc_net_remote_tod(server, domain, &dc_tv, &dc_tm) < 0) {
		syslog(LOG_DEBUG, "srvsvc_net_remote_tod failed");
		return;
	}

	tnow = time(NULL);

	if (tnow > dc_tv.tv_sec)
		tdiff = (tnow - dc_tv.tv_sec) / SECSPERMIN;
	else
		tdiff = (dc_tv.tv_sec - tnow) / SECSPERMIN;

	if (tdiff != 0) {
		(void) strlcpy(hostname, "localhost", MAXHOSTNAMELEN);
		(void) gethostname(hostname, MAXHOSTNAMELEN);

		priority = (tdiff > 2) ? LOG_NOTICE : LOG_DEBUG;
		syslog(priority, "DC [%s] clock skew detected: %u minutes",
		    server, tdiff);

		tm = gmtime(&dc_tv.tv_sec);
		syslog(priority, "%-8s  UTC: %s", server, asctime(tm));
		tm = gmtime(&tnow);
		syslog(priority, "%-8s  UTC: %s", hostname, asctime(tm));
	}
}
