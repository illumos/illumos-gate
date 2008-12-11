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
 * Client NDR RPC interface.
 */

#include <sys/errno.h>
#include <strings.h>
#include <assert.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>

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
	ndr_client_t		*clnt;
	ndr_service_t		*svc;
	smbrdr_session_info_t	si;
	int			fid;
	int			rc;

	if (handle == NULL || server == NULL ||
	    domain == NULL || username == NULL)
		return (-1);

	if ((svc = ndr_svc_lookup_name(service)) == NULL)
		return (-1);

	if ((clnt = malloc(sizeof (ndr_client_t))) == NULL)
		return (-1);

	fid = smbrdr_open_pipe(server, domain, username, svc->endpoint);
	if (fid < 0) {
		free(clnt);
		return (-1);
	}

	bzero(clnt, sizeof (ndr_client_t));
	clnt->handle = &handle->handle;
	clnt->fid = fid;

	ndr_svc_binding_pool_init(&clnt->binding_list,
	    clnt->binding_pool, NDR_N_BINDING_POOL);

	clnt->xa_init = ndr_xa_init;
	clnt->xa_exchange = ndr_xa_exchange;
	clnt->xa_read = ndr_xa_read;
	clnt->xa_preserve = ndr_xa_preserve;
	clnt->xa_destruct = ndr_xa_destruct;
	clnt->xa_release = ndr_xa_release;

	(void) smbrdr_session_info(fid, &si);
	bzero(&handle->handle, sizeof (ndr_hdid_t));
	handle->clnt = clnt;
	handle->remote_os = si.si_server_os;

	if (ndr_rpc_get_heap(handle) == NULL) {
		free(clnt);
		return (-1);
	}

	rc = ndr_clnt_bind(clnt, service, &clnt->binding);
	if (NDR_DRC_IS_FAULT(rc)) {
		(void) smbrdr_close_pipe(fid);
		ndr_heap_destroy(clnt->heap);
		free(clnt);
		handle->clnt = NULL;
		return (-1);
	}

	return (0);
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

	if (clnt->heap_preserved)
		ndr_clnt_free_heap(clnt);
	else
		ndr_heap_destroy(clnt->heap);

	(void) smbrdr_close_pipe(clnt->fid);
	free(handle->clnt);
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

	if (NDR_DRC_IS_FAULT(rc)) {
		ndr_rpc_release(handle);
		return (-1);
	}

	return (0);
}

/*
 * Returns the Native-OS of the RPC server.
 */
int
ndr_rpc_server_os(mlsvc_handle_t *handle)
{
	return (handle->remote_os);
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
	child->remote_os = parent->remote_os;
}

void
ndr_rpc_status(mlsvc_handle_t *handle, int opnum, DWORD status)
{
	ndr_service_t *svc;
	char *name = "NDR RPC";
	char *s = "unknown";

	if (status == 0)
		s = "success";
	else if (NT_SC_IS_ERROR(status))
		s = "error";
	else if (NT_SC_IS_WARNING(status))
		s = "warning";
	else if (NT_SC_IS_INFO(status))
		s = "info";

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
	ndr_stream_t *recv_nds = &mxa->recv_nds;
	ndr_stream_t *send_nds = &mxa->send_nds;
	ndr_heap_t *heap = clnt->heap;

	if (heap == NULL) {
		if ((heap = ndr_heap_create()) == NULL)
			return (-1);

		clnt->heap = heap;
	}

	mxa->heap = heap;

	nds_initialize(send_nds, 0, NDR_MODE_CALL_SEND, heap);
	nds_initialize(recv_nds, 16 * 1024, NDR_MODE_RETURN_RECV, heap);
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
	int nbytes;

	nbytes = smbrdr_transact(clnt->fid,
	    (char *)send_nds->pdu_base_offset, send_nds->pdu_size,
	    (char *)recv_nds->pdu_base_offset, recv_nds->pdu_max_size);

	if (nbytes < 0) {
		recv_nds->pdu_size = 0;
		return (-1);
	}

	recv_nds->pdu_size = nbytes;
	return (nbytes);
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

	nbytes = smbrdr_readx(clnt->fid,
	    (char *)nds->pdu_base_offset + nds->pdu_size, len);

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
