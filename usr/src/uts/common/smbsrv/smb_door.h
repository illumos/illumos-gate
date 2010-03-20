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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_SMB_DOOR_H
#define	_SMBSRV_SMB_DOOR_H

#include <sys/door.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_token.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SMBD_DOOR_NAME			"/var/run/smbd_door"

#define	SMB_DOOR_CALL_RETRIES		3

/*
 * Opcodes for smbd door.
 *
 * SMB_DR_NULL is the equivalent of the NULL RPC.  It ensures that an
 * opcode of zero is not misinterpreted as an operational door call
 * and it is available as a test interface.
 *
 * SMB_DR_ASYNC_RESPONSE delivers the response part of an asynchronous
 * request and must be processed as a synchronous request.
 */
typedef enum smb_dopcode {
	SMB_DR_NULL = 0,
	SMB_DR_ASYNC_RESPONSE,
	SMB_DR_USER_AUTH_LOGON,
	SMB_DR_USER_NONAUTH_LOGON,
	SMB_DR_USER_AUTH_LOGOFF,
	SMB_DR_LOOKUP_SID,
	SMB_DR_LOOKUP_NAME,
	SMB_DR_JOIN,
	SMB_DR_GET_DCINFO,
	SMB_DR_VSS_GET_COUNT,
	SMB_DR_VSS_GET_SNAPSHOTS,
	SMB_DR_VSS_MAP_GMTTOKEN,
	SMB_DR_ADS_FIND_HOST,
	SMB_DR_QUOTA_QUERY,
	SMB_DR_QUOTA_SET,
	SMB_DR_DFS_GET_REFERRALS
} smb_dopcode_t;

struct smb_event;

typedef struct smb_doorarg {
	smb_doorhdr_t		da_hdr;
	door_arg_t		da_arg;
	xdrproc_t		da_req_xdr;
	xdrproc_t		da_rsp_xdr;
	void			*da_req_data;
	void			*da_rsp_data;
	smb_dopcode_t		da_opcode;
	const char		*da_opname;
	struct smb_event	*da_event;
	uint32_t		da_flags;
} smb_doorarg_t;

/*
 * Door call return codes.
 */
#define	SMB_DOP_SUCCESS			0
#define	SMB_DOP_NOT_CALLED		1
#define	SMB_DOP_DECODE_ERROR		2
#define	SMB_DOP_ENCODE_ERROR		3
#define	SMB_DOP_EMPTYBUF		4

#ifndef _KERNEL
char *smb_common_encode(void *, xdrproc_t, size_t *);
int smb_common_decode(char *, size_t, xdrproc_t, void *);
char *smb_string_encode(char *, size_t *);
int smb_string_decode(smb_string_t *, char *, size_t);
#endif /* _KERNEL */

typedef struct smb_dr_ctx {
	char *ptr;
	char *start_ptr;
	char *end_ptr;
	int status;
} smb_dr_ctx_t;

smb_dr_ctx_t *smb_dr_decode_start(char *, int);
int smb_dr_decode_finish(smb_dr_ctx_t *);

smb_dr_ctx_t *smb_dr_encode_start(char *, int);
int smb_dr_encode_finish(smb_dr_ctx_t *, unsigned int *);

int32_t smb_dr_get_int32(smb_dr_ctx_t *);
DWORD smb_dr_get_dword(smb_dr_ctx_t *);
uint32_t smb_dr_get_uint32(smb_dr_ctx_t *);
int64_t smb_dr_get_int64(smb_dr_ctx_t *);
uint64_t smb_dr_get_uint64(smb_dr_ctx_t *);
unsigned short smb_dr_get_ushort(smb_dr_ctx_t *);

void smb_dr_put_int32(smb_dr_ctx_t *, int32_t);
void smb_dr_put_dword(smb_dr_ctx_t *, DWORD);
void smb_dr_put_uint32(smb_dr_ctx_t *, uint32_t);
void smb_dr_put_int64(smb_dr_ctx_t *, int64_t);
void smb_dr_put_uint64(smb_dr_ctx_t *, uint64_t);
void smb_dr_put_ushort(smb_dr_ctx_t *, unsigned short);

char *smb_dr_get_string(smb_dr_ctx_t *);
void smb_dr_put_string(smb_dr_ctx_t *, const char *);
void smb_dr_free_string(char *);

void smb_dr_put_word(smb_dr_ctx_t *, WORD);
WORD smb_dr_get_word(smb_dr_ctx_t *);

void smb_dr_put_BYTE(smb_dr_ctx_t *, BYTE);
BYTE smb_dr_get_BYTE(smb_dr_ctx_t *);

void smb_dr_put_buf(smb_dr_ctx_t *, unsigned char *, int);
int smb_dr_get_buf(smb_dr_ctx_t *, unsigned char *, int);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_SMB_DOOR_H */
