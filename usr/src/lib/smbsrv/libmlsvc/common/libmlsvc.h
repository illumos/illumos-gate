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
 */

#ifndef	_LIBMLSVC_H
#define	_LIBMLSVC_H

#include <uuid/uuid.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ksynch.h>
#include <stdio.h>
#include <string.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_privilege.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/ndl/lsarpc.ndl>

#ifdef	__cplusplus
extern "C" {
#endif

extern uint32_t mlsvc_lookup_name(char *, smb_sid_t **, uint16_t *);
extern uint32_t mlsvc_lookup_sid(smb_sid_t *, char **);

/*
 * SMB domain API to discover a domain controller and obtain domain
 * information.
 */

typedef struct smb_domain {
	char	d_dc[MAXHOSTNAMELEN];
	char	d_nbdomain[NETBIOS_NAME_SZ];
	char	d_fqdomain[MAXHOSTNAMELEN];
	char	d_forest[MAXHOSTNAMELEN];
	char	d_guid[UUID_PRINTABLE_STRING_LENGTH];
} smb_domain_t;
extern boolean_t smb_locate_dc(char *, char *, smb_domain_t *);
extern boolean_t smb_domain_getinfo(smb_domain_t *);


extern int mlsvc_get_door_fd(void);
extern uint64_t mlsvc_get_num_users(void);
extern int mlsvc_get_user_list(int, smb_dr_ulist_t *);
extern void dssetup_clear_domain_info(void);
extern int mlsvc_init(void);
extern void mlsvc_set_door_fd(int);
extern int mlsvc_set_share(int, char *, char *);
extern DWORD mlsvc_netlogon(char *, char *);
extern DWORD mlsvc_join(smb_domain_t *, char *, char *);


/*
 * The maximum number of domains (NT limit).
 */
#define	MLSVC_DOMAIN_MAX		32

/*
 * Status code returned from enumeration RPCs to indicate
 * that the server has no more data. Normally returned at
 * severity level ERROR_SEVERITY_WARNING.
 */
#define	MLSVC_NO_MORE_DATA		0x1A

#define	MLSVC_ANON_USER			"IPC$"

char *mlsvc_ipc_name(int ipc_type, char *username);

/*
 * Passthrough negotiation and authentication interface.
 *
 * NT supports two forms of password: a Lanman (case-insensitive)
 * password and an NT (case-sensitive) password. If either of the
 * passwords is not available its pointer and length should be set
 * to zero. The session key and vc number are required to validate
 * the encrypted passwords.
 */

void mlsvc_nt_password_hash(char *result, char *password);
int mlsvc_encrypt_nt_password(char *password, char *key, int keylen, char *out,
    int outmax);

#define	SMB_AUTOHOME_FILE	"smbautohome"
#define	SMB_AUTOHOME_PATH	"/etc"

typedef struct smb_autohome {
	struct smb_autohome *ah_next;
	uint32_t ah_hits;
	time_t ah_timestamp;
	char *ah_name;		/* User account name */
	char *ah_path;		/* Home directory path */
	char *ah_container;	/* ADS container distinguished name */
} smb_autohome_t;

extern void smb_autohome_add(const char *);
extern void smb_autohome_remove(const char *);

/*
 * A local unique id (LUID) is an opaque id used by servers to identify
 * local resources, such as privileges.  A client will use lookup
 * functions to translate the LUID to a more general, machine independent
 * form; such as a string.
 */
typedef struct ms_luid {
	uint32_t low_part;
	uint32_t high_part;
} ms_luid_t;

/*
 * A client_t is created while binding a client connection to hold the
 * context for calls made using that connection.
 *
 * Handles are RPC call specific and we use an inheritance mechanism to
 * ensure that each handle has a pointer to the client_t.  When the top
 * level (bind) handle is released, we close the connection.
 */
typedef struct mlsvc_handle {
	ndr_hdid_t			handle;
	ndr_client_t			*clnt;
	int				remote_os;
} mlsvc_handle_t;

int ndr_rpc_bind(mlsvc_handle_t *, char *, char *, char *, const char *);
void ndr_rpc_unbind(mlsvc_handle_t *);
int ndr_rpc_call(mlsvc_handle_t *, int, void *);
int ndr_rpc_server_os(mlsvc_handle_t *);
void *ndr_rpc_malloc(mlsvc_handle_t *, size_t);
ndr_heap_t *ndr_rpc_get_heap(mlsvc_handle_t *);
void ndr_rpc_release(mlsvc_handle_t *);
boolean_t ndr_is_null_handle(mlsvc_handle_t *);
boolean_t ndr_is_bind_handle(mlsvc_handle_t *);
void ndr_inherit_handle(mlsvc_handle_t *, mlsvc_handle_t *);
void ndr_rpc_status(mlsvc_handle_t *, int, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBMLSVC_H */
