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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * ML-RPC Client handle interface and support functions.
 */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/poll.h>

#include <errno.h>
#include <strings.h>
#include <unistd.h>

#include <netsmb/smbfs_api.h>
#include <smb/ntstatus.h>
#include <libmlrpc.h>

#include <assert.h>

static int ndr_xa_init(ndr_client_t *, ndr_xa_t *);
static int ndr_xa_exchange(ndr_client_t *, ndr_xa_t *);
static int ndr_xa_read(ndr_client_t *, ndr_xa_t *);
static void ndr_xa_preserve(ndr_client_t *, ndr_xa_t *);
static void ndr_xa_destruct(ndr_client_t *, ndr_xa_t *);
static void ndr_xa_release(ndr_client_t *);

/* See notes in mlrpc_clh_bind */
int rpc_pipe_open_retries = 10;

/*
 * Create an RPC client binding handle using the given smb_ctx.
 * That context must already have a session and tree connected.
 *
 * Returns zero or an errno value.
 */
int
mlrpc_clh_create(mlrpc_handle_t *handle, void *ctx)
{
	ndr_client_t	*clnt = NULL;

	if (ctx == NULL)
		return (EINVAL);

	/*
	 * Allocate...
	 */
	if ((clnt = malloc(sizeof (*clnt))) == NULL)
		return (ENOMEM);
	bzero(clnt, sizeof (*clnt));

	clnt->xa_fd = -1;

	/*
	 * Setup the transport functions.
	 * Always a named pipe (for now).
	 */
	clnt->xa_private = ctx;
	clnt->xa_init = ndr_xa_init;
	clnt->xa_exchange = ndr_xa_exchange;
	clnt->xa_read = ndr_xa_read;
	clnt->xa_preserve = ndr_xa_preserve;
	clnt->xa_destruct = ndr_xa_destruct;
	clnt->xa_release = ndr_xa_release;

	/* See _is_bind_handle */
	clnt->handle = &handle->handle;

	ndr_svc_binding_pool_init(&clnt->binding_list,
	    clnt->binding_pool, NDR_N_BINDING_POOL);

	if ((clnt->heap = ndr_heap_create()) == NULL)
		goto nomem;

	/* success! */
	bzero(handle, sizeof (*handle));
	handle->clnt = clnt;
	return (0);

nomem:
	free(clnt);
	return (ENOMEM);
}


/*
 * This call must be made to initialize an RPC client structure and bind
 * to the remote service before any RPCs can be exchanged with that service.
 *
 * The mlrpc_handle_t is a wrapper that is used to associate an RPC handle
 * with the client context for an instance of the interface.  The handle
 * is zeroed to ensure that it doesn't look like a valid handle -
 * handle content is provided by the remove service.
 *
 * The client points to this top-level handle so that we know when to
 * unbind and teardown the connection.  As each handle is initialized it
 * will inherit a reference to the client context.
 *
 *
 * Similar to MSRPC RpcBindingBind()
 *
 * Returns 0 or an NT_STATUS:		(failed in...)
 *
 *	RPC_NT_SERVER_TOO_BUSY		(open pipe)
 *	RPC_NT_SERVER_UNAVAILABLE	(open pipe)
 *	NT_STATUS_ACCESS_DENIED		(open pipe)
 *	NT_STATUS_INVALID_PARAMETER	(rpc bind)
 *	NT_STATUS_INTERNAL_ERROR	(bad args etc)
 *	NT_STATUS_NO_MEMORY
 */
uint32_t
mlrpc_clh_bind(mlrpc_handle_t *handle, ndr_service_t *svc)
{
	ndr_client_t		*clnt = NULL;
	struct smb_ctx		*ctx = NULL;
	uint32_t		status = 0;
	int			fd = -1;
	int			rc, retries;

	if ((clnt = handle->clnt) == NULL)
		return (NT_STATUS_INTERNAL_ERROR);
	if ((ctx = clnt->xa_private) == NULL)
		return (NT_STATUS_INTERNAL_ERROR);
	if (clnt->xa_fd != -1)
		return (NT_STATUS_INTERNAL_ERROR);

	/*
	 * Open the named pipe.
	 *
	 * Sometimes a DC may return NT_STATUS_PIPE_NOT_AVAILABLE for
	 * the first few seconds during service auto-start.  The client
	 * translates that to EBUSY, so when we see that, wait a bit
	 * and retry the open for up to rpc_pipe_open_retries.  If we
	 * fail even after retries, return RPC_NT_SERVER_TOO_BUSY,
	 * which is how callers of this layer expect that reported.
	 * We try up to 10 times, with a 0.5 sec. wait after each
	 * BUSY failure, giving a total wait here of 5 sec.
	 */
	retries = rpc_pipe_open_retries;
retry_open:
	fd = smb_fh_open(ctx, svc->endpoint, O_RDWR);
	if (fd < 0) {
		rc = errno;
		switch (rc) {
		case EBUSY:
			if (--retries > 0) {
				(void) poll(NULL, 0, 500);
				goto retry_open;
			}
			status = RPC_NT_SERVER_TOO_BUSY;
			break;
		case EACCES:
			status = NT_STATUS_ACCESS_DENIED;
			break;
		default:
			status = RPC_NT_SERVER_UNAVAILABLE;
			break;
		}
		return (status);
	}

	clnt->xa_fd = fd;

	/* Paranoia, in case of re-bind. */
	bzero(&handle->handle, sizeof (ndr_hdid_t));

	/*
	 * Do the OtW RPC bind.
	 */
	rc = ndr_clnt_bind(clnt, svc, &clnt->binding);
	switch (rc) {
	case NDR_DRC_FAULT_OUT_OF_MEMORY:
		status = NT_STATUS_NO_MEMORY;
		break;
	case NDR_DRC_FAULT_API_SERVICE_INVALID:
		/* svc->..._uuid parse errors */
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	default:
		if (NDR_DRC_IS_FAULT(rc)) {
			status = RPC_NT_PROTOCOL_ERROR;
			break;
		}
		/* FALLTHROUGH */
	case NDR_DRC_OK:
		status = NT_STATUS_SUCCESS;
	}

	if (status != 0) {
		if (fd != -1)
			(void) smb_fh_close(fd);
		clnt->xa_fd = -1;
	}

	return (status);
}

/*
 * Unbind and close the pipe to an RPC service.
 *
 * Similar to MSRPC RpcBindingUnbind()
 * This should be called after a dropped connection.
 */
void
mlrpc_clh_unbind(mlrpc_handle_t *handle)
{
	ndr_client_t *clnt = handle->clnt;

	if (clnt->xa_fd != -1) {
		(void) smb_fh_close(clnt->xa_fd);
		clnt->xa_fd = -1;
	}
}

/*
 * If the heap has been preserved we need to go through an xa release.
 * The heap is preserved during an RPC call because that's where data
 * returned from the server is stored.
 *
 * Otherwise we destroy the heap directly.
 *
 * Returns the xa_private pointer (if non-NULL) to inform the caller
 * that it can now be destroyed.
 */
void *
mlrpc_clh_free(mlrpc_handle_t *handle)
{
	ndr_client_t *clnt = handle->clnt;
	void *private;

	if (clnt == NULL)
		return (NULL);

	/*
	 * Should never get an unbind on inherited handles.
	 * Callers of ndr_inherit_handle() check handles
	 * with ndr_is_bind_handle() before calling this.
	 *
	 * Maybe make this function more tolerant?
	 */
	assert(handle->clnt->handle == &handle->handle);

	mlrpc_clh_unbind(handle);

	if (clnt->heap_preserved)
		ndr_clnt_free_heap(clnt); /* xa_release */
	else
		ndr_heap_destroy(clnt->heap);

	/*
	 * Note: Caller will free the smb_ctx stored in
	 * clnt->xa_private (or possibly reuse it).
	 */
	private = clnt->xa_private;
	free(clnt);
	bzero(handle, sizeof (*handle));
	return (private);
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
ndr_rpc_call(mlrpc_handle_t *handle, int opnum, void *params)
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
ndr_rpc_set_nonull(mlrpc_handle_t *handle)
{
	handle->clnt->nonull = B_TRUE;
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
ndr_rpc_get_ssnkey(mlrpc_handle_t *handle, uchar_t *key, size_t len)
{
	ndr_client_t *clnt = handle->clnt;

	if (clnt == NULL || clnt->xa_fd == -1)
		return (EINVAL);

	return (smb_fh_getssnkey(clnt->xa_fd, key, len));
}

void *
ndr_rpc_malloc(mlrpc_handle_t *handle, size_t size)
{
	ndr_heap_t *heap;

	if ((heap = ndr_rpc_get_heap(handle)) == NULL)
		return (NULL);

	return (ndr_heap_malloc(heap, size));
}

ndr_heap_t *
ndr_rpc_get_heap(mlrpc_handle_t *handle)
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
ndr_rpc_release(mlrpc_handle_t *handle)
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
ndr_is_null_handle(mlrpc_handle_t *handle)
{
	static const ndr_hdid_t hdid0 = {0};

	if (handle == NULL || handle->clnt == NULL)
		return (B_TRUE);

	if (!memcmp(&handle->handle, &hdid0, sizeof (hdid0)))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Returns true if the handle is the top level bind handle.
 * Otherwise returns false.
 */
boolean_t
ndr_is_bind_handle(mlrpc_handle_t *handle)
{
	return (handle->clnt->handle == &handle->handle);
}

/*
 * Pass the client reference from parent to child.
 */
void
ndr_inherit_handle(mlrpc_handle_t *child, mlrpc_handle_t *parent)
{
	child->clnt = parent->clnt;
}

/*
 * ndr_rpc_status remains in libmlsvc mlsvc_client.c
 */

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
