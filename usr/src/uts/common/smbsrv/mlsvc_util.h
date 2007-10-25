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
#include <smbsrv/ntsid.h>
#include <smbsrv/smb_token.h>

#ifndef _KERNEL
#include <stdio.h>
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Predefined global RIDs.
 */
#define	MLSVC_DOMAIN_GROUP_RID_ADMINS		0x00000200L
#define	MLSVC_DOMAIN_GROUP_RID_USERS		0x00000201L
#define	MLSVC_DOMAIN_GROUP_RID_GUESTS		0x00000202L
#define	MLSVC_DOMAIN_GROUP_RID_COMPUTERS	0x00000203L
#define	MLSVC_DOMAIN_GROUP_RID_CONTROLLERS	0x00000204L
#define	MLSVC_DOMAIN_GROUP_RID_CERT_ADMINS	0x00000205L
#define	MLSVC_DOMAIN_GROUP_RID_SCHEMA_ADMINS	0x00000206L

/*
 * Predefined local alias RIDs.
 */
#define	MLSVC_LOCAL_GROUP_RID_ADMINS		0x00000220L
#define	MLSVC_LOCAL_GROUP_RID_USERS		0x00000221L
#define	MLSVC_LOCAL_GROUP_RID_GUESTS		0x00000222L
#define	MLSVC_LOCAL_GROUP_RID_POWER_USERS	0x00000223L
#define	MLSVC_LOCAL_GROUP_RID_ACCOUNT_OPS	0x00000224L
#define	MLSVC_LOCAL_GROUP_RID_SERVER_OPS	0x00000225L
#define	MLSVC_LOCAL_GROUP_RID_PRINT_OPS		0x00000226L
#define	MLSVC_LOCAL_GROUP_RID_BACKUP_OPS	0x00000227L
#define	MLSVC_LOCAL_GROUP_RID_REPLICATOR	0x00000228L

/*
 * All predefined local group RIDs belong
 * to a special domain called BUILTIN.
 */
#define	MLSVC_BUILTIN_DOMAIN_NAME		"BUILTIN"
#define	MLSVC_BUILTIN_DOMAIN_SIDSTRLEN		8

/*
 * Universal and NT well-known SIDs
 */
#define	MLSVC_NULL_SIDSTR			"S-1-0-0"
#define	MSLVC_WORLD_SIDSTR			"S-1-1-0"
#define	MSLVC_LOCAL_SIDSTR			"S-1-2-0"
#define	MSLVC_CREATOR_OWNER_ID_SIDSTR		"S-1-3-0"
#define	MSLVC_CREATOR_GROUP_ID_SIDSTR		"S-1-3-1"
#define	MSLVC_CREATOR_OWNER_SERVER_ID_SIDSTR	"S-1-3-2"
#define	MSLVC_CREATOR_GROUP_SERVER_ID_SIDSTR	"S-1-3-3"
#define	MSLVC_NON_UNIQUE_IDS_SIDSTR		"S-1-4"
#define	MLSVC_NT_AUTHORITY_SIDSTR		"S-1-5"
#define	MLSVC_DIALUP_SIDSTR			"S-1-5-1"
#define	MLSVC_NETWORK_SIDSTR			"S-1-5-2"
#define	MLSVC_BATCH_SIDSTR			"S-1-5-3"
#define	MLSVC_INTERACTIVE_SIDSTR		"S-1-5-4"
#define	MLSVC_SERVICE_SIDSTR			"S-1-5-6"
#define	MLSVC_ANONYMOUS_LOGON_SIDSTR		"S-1-5-7"
#define	MLSVC_PROXY_SIDSTR			"S-1-5-8"
#define	MLSVC_SERVER_LOGON_SIDSTR		"S-1-5-9"
#define	MLSVC_SELF_SIDSTR			"S-1-5-10"
#define	MLSVC_AUTHENTICATED_USER_SIDSTR		"S-1-5-11"
#define	MLSVC_RESTRICTED_CODE_SIDSTR		"S-1-5-12"
#define	MLSVC_NT_LOCAL_SYSTEM_SIDSTR		"S-1-5-18"
#define	MLSVC_NT_NON_UNIQUE_SIDSTR		"S-1-5-21"
#define	MLSVC_BUILTIN_DOMAIN_SIDSTR		"S-1-5-32"

int mlsvc_lookup_name(char *domain, char *name, nt_sid_t **sid);
int mlsvc_lookup_sid(nt_sid_t *sid, char *buf, int bufsize);

smb_userinfo_t *mlsvc_alloc_user_info(void);
void mlsvc_free_user_info(smb_userinfo_t *user_info);
void mlsvc_release_user_info(smb_userinfo_t *user_info);
void mlsvc_setadmin_user_info(smb_userinfo_t *user_info);
char *mlsvc_sid_name_use(unsigned int snu_id);

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
nt_sid_t *mlsvc_sid_save(nt_sid_t *sid, struct mlrpc_xaction *mxa);

/*
 * This is the generic, interface independent handle definition.
 */
typedef struct ms_handle {
	DWORD handle[5];
} ms_handle_t;

/*
 * List of interface specifications: can be used to identify the
 * sub-system to which a handle is assigned. The handle management
 * library doesn't check or care about the ifspec value.
 */
typedef enum ms_ifspec {
	MLSVC_IFSPEC_NULL,
	MLSVC_IFSPEC_LSAR,
	MLSVC_IFSPEC_SAMR,
	MLSVC_IFSPEC_WINREG,
	MLSVC_IFSPEC_SVCCTL,
	MLSVC_IFSPEC_SPOOLSS,
	MLSVC_IFSPEC_LOGR,
	MLSVC_IFSPEC_LLSR,
	MLSVC_NUM_IFSPECS
} ms_ifspec_t;

#define	MLSVC_HANDLE_KEY_MAX	32

typedef struct ms_handle_desc {
	struct ms_handle_desc *next;
	ms_handle_t handle;
	ms_ifspec_t ifspec;
	char key[MLSVC_HANDLE_KEY_MAX];
	DWORD discrim;
} ms_handle_desc_t;

ms_handle_t *mlsvc_get_handle(ms_ifspec_t ifspec, char *key, DWORD discrim);
int mlsvc_put_handle(ms_handle_t *handle);
int mlsvc_validate_handle(ms_handle_t *handle, char *key);
ms_handle_desc_t *mlsvc_lookup_handle(ms_handle_t *handle);

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
 *
 * I know this is really tacky but the elements in the descriptor are
 * arranged so that a handle can be overlaid directly onto a descriptor.
 * I probably won't do this but now you know - just in case you see it
 * in the code.
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
