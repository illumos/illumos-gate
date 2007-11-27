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
 * Context functions to support the RPC interface library.
 */

#include <sys/errno.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/mlsvc_util.h>

static int mlsvc_xa_init(struct mlrpc_client *, struct mlrpc_xaction *,
    mlrpc_heap_t *);
static int mlsvc_xa_exchange(struct mlrpc_client *, struct mlrpc_xaction *);
static int mlsvc_xa_read(struct mlrpc_client *, struct mlrpc_xaction *);
static int mlsvc_xa_preserve(struct mlrpc_client *, struct mlrpc_xaction *,
    mlrpc_heapref_t *);
static int mlsvc_xa_destruct(struct mlrpc_client *, struct mlrpc_xaction *);
static void mlsvc_xa_release(struct mlrpc_client *, mlrpc_heapref_t *heapref);

/*
 * mlsvc_rpc_bind
 *
 * This the entry point for all client RPC services. This call must be
 * made to initialize an RPC context structure and bind to the remote
 * service before any RPCs can be exchanged with that service. The
 * descriptor is a wrapper that is used to associate an RPC handle with
 * the context data for that specific instance of the interface. The
 * handle is zeroed to ensure that it doesn't look like a valid handle.
 * The context handle is assigned to point at the RPC handle so that we
 * know when to free the context. As each handle is initialized it will
 * include a pointer to this context but only when we close this initial
 * RPC handle can the context be freed.
 *
 * On success, return a pointer to the descriptor. Otherwise return a
 * null pointer.
 */
int
mlsvc_rpc_bind(mlsvc_handle_t *desc, int fid, char *service)
{
	struct mlsvc_rpc_context *context;
	int rc;

	bzero(&desc->handle, sizeof (ms_handle_t));

	context = malloc(sizeof (struct mlsvc_rpc_context));
	if ((desc->context = context) == NULL)
		return (-1);

	bzero(context, sizeof (struct mlsvc_rpc_context));
	context->cli.context = context;

	mlrpc_binding_pool_initialize(&context->cli.binding_list,
	    context->binding_pool, CTXT_N_BINDING_POOL);

	context->fid = fid;
	context->handle = &desc->handle;
	context->cli.xa_init = mlsvc_xa_init;
	context->cli.xa_exchange = mlsvc_xa_exchange;
	context->cli.xa_read = mlsvc_xa_read;
	context->cli.xa_preserve = mlsvc_xa_preserve;
	context->cli.xa_destruct = mlsvc_xa_destruct;
	context->cli.xa_release = mlsvc_xa_release;

	rc = mlrpc_c_bind(&context->cli, service, &context->binding);
	if (MLRPC_DRC_IS_FAULT(rc)) {
		free(context);
		desc->context = NULL;
		return (-1);
	}

	return (rc);
}

/*
 * mlsvc_rpc_init
 *
 * This function must be called by client side applications before
 * calling mlsvc_rpc_call to allocate a heap. The heap must be
 * destroyed by either calling mlrpc_heap_destroy or mlsvc_rpc_free.
 * Use mlrpc_heap_destroy if mlsvc_rpc_call has not yet been called.
 * Otherwise use mlsvc_rpc_free.
 *
 * Returns 0 on success. Otherwise returns -1 to indicate an error.
 */
int
mlsvc_rpc_init(mlrpc_heapref_t *heapref)
{
	bzero(heapref, sizeof (mlrpc_heapref_t));

	if ((heapref->heap = mlrpc_heap_create()) == NULL)
		return (-1);

	return (0);
}

/*
 * mlsvc_rpc_call
 *
 * This function should be called by the client RPC interface functions
 * to make an RPC call. The remote service is identified by the context
 * handle, which should have been initialized with by mlsvc_rpc_bind.
 */
int
mlsvc_rpc_call(struct mlsvc_rpc_context *context, int opnum, void *params,
    mlrpc_heapref_t *heapref)
{
	return (mlrpc_c_call(context->binding, opnum, params, heapref));
}

/*
 * mlsvc_rpc_free
 *
 * This function should be called by the client RPC interface functions
 * to free the heap after an RPC call returns.
 */
void
mlsvc_rpc_free(struct mlsvc_rpc_context *context, mlrpc_heapref_t *heapref)
{
	mlrpc_c_free_heap(context->binding, heapref);
}

/*
 * The following functions provide the callback interface in the
 * context handle.
 */
/*ARGSUSED*/
static int
mlsvc_xa_init(struct mlrpc_client *mcli, struct mlrpc_xaction *mxa,
    mlrpc_heap_t *heap)
{
	struct mlndr_stream *recv_mlnds = &mxa->recv_mlnds;
	struct mlndr_stream *send_mlnds = &mxa->send_mlnds;

	/*
	 * If the caller hasn't provided a heap, create one here.
	 */
	if (heap == 0) {
		if ((heap = mlrpc_heap_create()) == 0)
			return (-1);
	}

	mxa->heap = heap;

	mlnds_initialize(send_mlnds, 0, NDR_MODE_CALL_SEND, heap);
	mlnds_initialize(recv_mlnds, 16 * 1024, NDR_MODE_RETURN_RECV, heap);
	return (0);
}

/*
 * mlsvc_xa_exchange
 *
 * This is the entry pointy for an RPC client call exchange with
 * a server, which will result in an smbrdr SmbTransact request.
 *
 * SmbTransact should return the number of bytes received, which
 * we record as the PDU size, or a negative error code.
 */
static int
mlsvc_xa_exchange(struct mlrpc_client *mcli, struct mlrpc_xaction *mxa)
{
	struct mlsvc_rpc_context *context = mcli->context;
	struct mlndr_stream *recv_mlnds = &mxa->recv_mlnds;
	struct mlndr_stream *send_mlnds = &mxa->send_mlnds;
	int rc;

	rc = smbrdr_rpc_transact(context->fid,
	    (char *)send_mlnds->pdu_base_offset, send_mlnds->pdu_size,
	    (char *)recv_mlnds->pdu_base_offset, recv_mlnds->pdu_max_size);

	if (rc < 0)
		recv_mlnds->pdu_size = 0;
	else
		recv_mlnds->pdu_size = rc;

	return (rc);
}

/*
 * mlsvc_xa_read
 *
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
mlsvc_xa_read(struct mlrpc_client *mcli, struct mlrpc_xaction *mxa)
{
	struct mlsvc_rpc_context *context = mcli->context;
	struct mlndr_stream *mlnds = &mxa->recv_mlnds;
	int len;
	int rc;

	if ((len = (mlnds->pdu_max_size - mlnds->pdu_size)) < 0)
		return (-1);

	rc = smbrdr_rpc_readx(context->fid,
	    (char *)mlnds->pdu_base_offset + mlnds->pdu_size, len);

	if (rc < 0)
		return (-1);

	mlnds->pdu_size += rc;

	if (mlnds->pdu_size > mlnds->pdu_max_size) {
		mlnds->pdu_size = mlnds->pdu_max_size;
		return (-1);
	}

	return (rc);
}

/*
 * mlsvc_xa_preserve
 *
 * This function is called to preserve the heap. We save a reference
 * to the heap and set the mxa heap pointer to null so that the heap
 * will not be discarded when mlsvc_xa_destruct is called.
 */
/*ARGSUSED*/
static int
mlsvc_xa_preserve(struct mlrpc_client *mcli, struct mlrpc_xaction *mxa,
    mlrpc_heapref_t *heapref)
{
	heapref->state = MLRPC_HRST_PRESERVED;
	heapref->heap = mxa->heap;
	heapref->recv_pdu_buf = (char *)mxa->recv_mlnds.pdu_base_addr;
	heapref->send_pdu_buf = (char *)mxa->send_mlnds.pdu_base_addr;

	mxa->heap = NULL;
	return (0);
}

/*
 * mlsvc_xa_destruct
 *
 * This function is called to dispose of the heap. If the heap has
 * been preserved via mlsvc_xa_preserve, the mxa heap pointer will
 * be null and we assume that the heap will be released later via
 * a call to mlsvc_xa_release. Otherwise we free the memory here.
 */
/*ARGSUSED*/
static int
mlsvc_xa_destruct(struct mlrpc_client *mcli, struct mlrpc_xaction *mxa)
{
	if (mxa->heap) {
		mlnds_destruct(&mxa->recv_mlnds);
		mlnds_destruct(&mxa->send_mlnds);
		mlrpc_heap_destroy(mxa->heap);
	}

	return (0);
}

/*
 * mlsvc_xa_release
 *
 * This function is called, via some indirection, as a result of a
 * call to mlsvc_rpc_free. This is where we free the heap memory
 * that was preserved during an RPC call.
 */
/*ARGSUSED*/
static void
mlsvc_xa_release(struct mlrpc_client *mcli, mlrpc_heapref_t *heapref)
{
	if (heapref == NULL)
		return;

	if (heapref->state == MLRPC_HRST_PRESERVED) {
		free(heapref->recv_pdu_buf);
		free(heapref->send_pdu_buf);
		mlrpc_heap_destroy(heapref->heap);
	}
}
