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

#ifndef _SMBSRV_MLSVC_UTIL_H
#define	_SMBSRV_MLSVC_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MLSVC RPC interface and utility function definitions.
 */

#include <smbsrv/ndl/ndrtypes.ndl>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/smb_token.h>

#ifndef _KERNEL
#include <stdio.h>
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

smb_userinfo_t *mlsvc_alloc_user_info(void);
void mlsvc_free_user_info(smb_userinfo_t *user_info);
void mlsvc_release_user_info(smb_userinfo_t *user_info);
void mlsvc_setadmin_user_info(smb_userinfo_t *user_info);
char *mlsvc_sid_name_use(unsigned int snu_id);
extern int mlsvc_is_local_domain(const char *);

/*
 * The definition of a local unique id (LUID). This is an opaque id
 * used by servers to identify local resources, such as privileges.
 * A client will use lookup functions to translate the LUID to a
 * more general, machine independent form; like a string.
 */
struct ms_luid {
	DWORD low_part;
	DWORD high_part;
};

/*
 * As with SIDs, this is the generic, interface independent string
 * definition.
 */
struct ms_string_desc {
	WORD length;
	WORD allosize;
	LPTSTR str;
};
typedef struct ms_string_desc ms_string_t;

int mlsvc_string_save(ms_string_t *ms, char *str, struct mlrpc_xaction *mxa);
smb_sid_t *mlsvc_sid_save(smb_sid_t *sid, struct mlrpc_xaction *mxa);

/*
 * This is the generic, interface independent handle definition.
 */
typedef struct ms_handle {
	DWORD handle[5];
} ms_handle_t;

/*
 * The mlsvc_rpc_context structure provides the connection binding context
 * for client RPC calls. This space must be provided by the client library
 * for use by the underlying RPC library. Note that we need two binding
 * pools per connection.
 */
#define	CTXT_N_BINDING_POOL		2

struct mlsvc_rpc_context {
	struct mlrpc_client	cli;
	int fid;
	ms_handle_t *handle;
	smb_dr_user_ctx_t *user_ctx;
	smb_pipe_t *inpipe;	/* used for winpipe */
	uint32_t inlen;		/* inpipes */
	smb_pipe_t *outpipe;	/* used for winpipe */
	uint32_t outcookie;	/* for rpc_read and transact */
	uint32_t outlen;	/* outpipes */
	int server_os;
	int server_pdc;
	WORD max_xmit_frag;
	WORD max_recv_frag;
	struct mlrpc_binding *binding;
	struct mlrpc_binding binding_pool[CTXT_N_BINDING_POOL];
};

/*
 * Each RPC interface requires a context and each RPC call within that
 * interface requires a handle. Handles are call specific, however, so
 * a number of different handles may be used during a sequence of calls
 * to a specific RPC interface. Contexts are interface specific so
 * there is one per interface per thread of execution. This structure
 * provides a handle to context relationship so that we know which
 * context to use with any particular handle.
 *
 * The context contains a pointer to the top level handle for the
 * interface, which is assigned during the bind. It's used when closing
 * to detect when to free the context.
 */
typedef struct mlsvc_rpc_desc {
	ms_handle_t handle;
	struct mlsvc_rpc_context *context;
} mlsvc_handle_t;


int mlsvc_rpc_bind(mlsvc_handle_t *handle, int fid, char *service);
int mlsvc_rpc_init(mlrpc_heapref_t *heapref);
int mlsvc_rpc_call(struct mlsvc_rpc_context *context, int opnum, void *params,
    mlrpc_heapref_t *heapref);
void mlsvc_rpc_free(struct mlsvc_rpc_context *context,
    mlrpc_heapref_t *heapref);
int mlsvc_is_null_handle(mlsvc_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_MLSVC_UTIL_H */
