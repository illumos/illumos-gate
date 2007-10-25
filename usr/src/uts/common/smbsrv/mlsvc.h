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

#ifndef _SMBSRV_MLSVC_H
#define	_SMBSRV_MLSVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MLSVC RPC layer public interface definitions.
 */

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/ksynch.h>

#include <smbsrv/wintypes.h>
#include <smbsrv/ntsid.h>

#include <smbsrv/smb_winpipe.h>
#include <smbsrv/smb_xdr.h>


#ifdef __cplusplus
extern "C" {
#endif

/*
 * RPC strings
 *
 * DCE RPC strings (CAE section 14.3.4) are represented as varying or
 * varying and conformant one-dimensional arrays. Characters can be
 * single-byte or multi-byte as long as all characters conform to a
 * fixed element size, i.e. UCS-2 is okay but UTF-8 is not a valid
 * DCE RPC string format. The string is terminated by a null character
 * of the appropriate element size.
 *
 * MSRPC strings are always varying and conformant format and not null
 * terminated. This format uses the size_is, first_is and length_is
 * attributes (CAE section 4.2.18).
 *
 *	typedef struct mlrpc_string {
 *		DWORD size_is;
 *		DWORD first_is;
 *		DWORD length_is;
 *		wchar_t string[ANY_SIZE_ARRAY];
 *  } mlrpc_string_t;
 *
 * The size_is attribute is used to specify the number of data elements
 * in each dimension of an array.
 *
 * The first_is attribute is used to define the lower bound for
 * significant elements in each dimension of an array. For strings
 * this is always 0.
 *
 * The length_is attribute is used to define the number of significant
 * elements in each dimension of an array. For strings this is typically
 * the same as size_is. Although it might be (size_is - 1) if the string
 * is null terminated.
 *
 * In MSRPC, Unicode strings are not null terminated. This means
 * that the recipient has to manually null-terminate the string after
 * it has been unmarshalled. Note that there is often a wide-char pad
 * following a string. Although the padding sometimes contains zero,
 * it's not guaranteed.
 *
 *   4 bytes   4 bytes   4 bytes  2bytes 2bytes 2bytes 2bytes
 * +---------+---------+---------+------+------+------+------+
 * |size_is  |first_is |length_is| char | char | char | char |
 * +---------+---------+---------+------+------+------+------+
 *
 * The problem is that some strings are null terminated. This seems
 * to conflict with the statement above that Unicode strings are not
 * null terminated, which may be a historical thing from earlier
 * implementations or it may be that different services do different
 * things. So there is an additional string wrapper with two more
 * fields used in some RPC structures as shown below (LPTSTR is
 * automatically converted to mlrpc_string by the NDR marshalling).
 *
 * typedef struct ms_string {
 *		WORD length;
 *		WORD maxlen;
 *		LPTSTR str;
 * } ms_string_t;
 *
 * Here, length is the array length in bytes excluding any terminating
 * null bytes and maxlen is the array length in bytes including null
 * terminator bytes.
 */
typedef struct mlsvc_string {
	WORD length;
	WORD maxlen;
	LPTSTR str;
} mlsvc_string_t;

/*
 * The maximum number of domains (NT limit).
 */
#define	MLSVC_DOMAIN_MAX		32

/*
 * Some buffer size limits. I don't know if these are definitive
 * limits for NT but these numbers appear in various places.
 */
#define	MLSVC_DOMAIN_NAME_MAX		32
#define	MLSVC_ACCOUNT_NAME_MAX		32
#define	MLSVC_CLIENT_NAME_MAX		48

/* 32-byte machine account password (null-terminated) */
#define	MLSVC_MACHINE_ACCT_PASSWD_MAX	32 + 1

/*
 * Status code returned from enumeration RPCs to indicate
 * that the server has no more data. Normally returned at
 * severity level ERROR_SEVERITY_WARNING.
 */
#define	MLSVC_NO_MORE_DATA		0x1A

/*
 * IPC connection types, used to indicate the type of session
 * required for a subsequent series of requests.
 */
#define	MLSVC_IPC_ANON			0x00
#define	MLSVC_IPC_USER			0x01
#define	MLSVC_IPC_ADMIN			0x02

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

int mlsvc_anonymous_logon(char *domain_controller, char *domain_name,
    char **username);
int mlsvc_user_logon(char *domain_controller, char *domain_name,
    char *username, char *password);
int mlsvc_admin_logon(char *domain_controller, char *domain_name);
int mlsvc_echo(char *server);
int mlsvc_open_pipe(char *hostname, char *domain, char *username,
    char *pipename);
int mlsvc_close_pipe(int fid);
void mlsvc_nt_password_hash(char *result, char *password);
int mlsvc_encrypt_nt_password(char *password, char *key, int keylen, char *out,
    int outmax);
DWORD mlsvc_validate_user(char *server, char *domain, char *username,
    char *password);
int mlsvc_locate_domain_controller(char *domain);

/*
 * RPC request processing interface (mlsvc_server.c).
 */
#define	MLSVC_MAX_IOVEC			512

typedef struct mlrpc_frag {
	struct mlrpc_frag *next;
	struct mbuf *mhead;
	uint32_t length;
} mlrpc_frag_t;

typedef struct mlsvc_stream {
	mlrpc_frag_t *head;
	mlrpc_frag_t *tail;
	mlrpc_frag_t *pending;
	unsigned int nfrag;
	struct uio uio;
	struct iovec iovec[MLSVC_MAX_IOVEC];
} mlsvc_stream_t;

typedef struct mlsvc_pipe {
	kmutex_t mutex;
	kcondvar_t cv;
	uint32_t busy;
	uint32_t fid;
	char *pipe_name;
	mlsvc_stream_t input;
	uchar_t *output;
	int32_t outlen;
} mlsvc_pipe_t;

int mlsvc_rpc_process(
	smb_pipe_t		*inpipe,
	smb_pipe_t		**outpipe,
	smb_dr_user_ctx_t	*user_ctx);

struct mlsvc_rpc_context *mlsvc_lookup_context(int fid);

void mlsvc_rpc_release(int fid);
int mlsvc_session_native_values(int fid, int *remote_os, int *remote_lm,
    int *pdc_type);
void mlsvc_rpc_report_status(int opnum, DWORD status);

/*
 * This is a temporary location for this NETLOGON stuff.
 */
typedef int (*mlsvc_locate_pdc_t)(char *domain);
void mlsvc_install_pdc_cb(mlsvc_locate_pdc_t locate_pdc_cb);

#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_MLSVC_H */
