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

#ifndef _SMBSRV_SMB_COMMON_DOOR_H
#define	_SMBSRV_SMB_COMMON_DOOR_H

#pragma ident	"@(#)smb_common_door.h	1.3	08/08/07 SMI"

#include <smbsrv/wintypes.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_token.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int smb_dr_get_opcode(char *argp, size_t arg_size);
extern int smb_dr_get_res_stat(char *rbufp, size_t rbuf_size);
extern char *smb_dr_set_opcode(uint32_t opcode, size_t *len);
extern char *smb_dr_set_res_stat(uint32_t stat, size_t *len);
extern char *smb_dr_encode_string(uint32_t reserved, char *buf, size_t *len);

#ifdef _KERNEL
extern int smb_kdr_decode_common(char *buf, size_t len, xdrproc_t proc,
    void *data);
extern char *smb_kdr_encode_common(uint_t reserved, void *data,
    xdrproc_t proc, size_t *len);

/* kernel encode functions */
extern char *smb_dr_encode_arg_get_token(netr_client_t *clnt_info,
    size_t *len);
/* kernel decode functions */
extern smb_token_t *smb_dr_decode_res_token(char *buf, size_t len);
extern smb_dr_kshare_t *smb_dr_decode_kshare(char *buf, size_t len);

/* kernel free functions */
void smb_dr_kshare_free(smb_dr_kshare_t *kshare);
#else /* _KERNEL */
extern int smb_dr_decode_common(char *buf, size_t len, xdrproc_t proc,
    void *data);
extern char *smb_dr_encode_common(uint_t reserved, void *data, xdrproc_t proc,
    size_t *len);

/* user-space encode functions */
extern char *smb_dr_encode_res_token(smb_token_t *token, size_t *len);
extern char *smb_dr_encode_kshare(smb_dr_kshare_t *, size_t *);

/* user-space decode functions */
extern netr_client_t *smb_dr_decode_arg_get_token(char *buf, size_t len);
extern char *smb_dr_decode_string(char *buf, size_t len);

/* user-space free functions */
extern void smb_dr_ulist_free(smb_dr_ulist_t *ulist);
#endif /* _KERNEL */

/*
 * PBSHORTCUT - should be removed once XDR is used for
 * serializing/deserializing data across door.
 */

/*
 * Common encode/decode functions used by door clients/servers.
 */

typedef struct smb_dr_ctx {
	char *ptr;
	char *start_ptr;
	char *end_ptr;
	int status;
} smb_dr_ctx_t;


extern smb_dr_ctx_t *smb_dr_decode_start(char *ptr, int size);
extern int smb_dr_decode_finish(smb_dr_ctx_t *ctx);

extern smb_dr_ctx_t *smb_dr_encode_start(char *ptr, int size);
extern int smb_dr_encode_finish(smb_dr_ctx_t *ctx, unsigned int *used);

extern int32_t smb_dr_get_int32(smb_dr_ctx_t *ctx);
extern DWORD smb_dr_get_dword(smb_dr_ctx_t *ctx);
extern uint32_t smb_dr_get_uint32(smb_dr_ctx_t *ctx);
extern int64_t smb_dr_get_int64(smb_dr_ctx_t *ctx);
extern uint64_t smb_dr_get_uint64(smb_dr_ctx_t *ctx);
extern unsigned short smb_dr_get_ushort(smb_dr_ctx_t *ctx);

extern void smb_dr_put_int32(smb_dr_ctx_t *ctx, int32_t num);
extern void smb_dr_put_dword(smb_dr_ctx_t *ctx, DWORD num);
extern void smb_dr_put_uint32(smb_dr_ctx_t *ctx, uint32_t num);
extern void smb_dr_put_int64(smb_dr_ctx_t *ctx, int64_t num);
extern void smb_dr_put_uint64(smb_dr_ctx_t *ctx, uint64_t num);
extern void smb_dr_put_ushort(smb_dr_ctx_t *ctx, unsigned short num);

extern char *smb_dr_get_string(smb_dr_ctx_t *ctx);
extern void smb_dr_put_string(smb_dr_ctx_t *ctx, const char *buf);
extern void smb_dr_free_string(char *buf);

extern void smb_dr_put_word(smb_dr_ctx_t *ctx, WORD num);
extern WORD smb_dr_get_word(smb_dr_ctx_t *ctx);

extern void smb_dr_put_BYTE(smb_dr_ctx_t *ctx, BYTE byte);
extern BYTE smb_dr_get_BYTE(smb_dr_ctx_t *ctx);

extern void smb_dr_put_buf(smb_dr_ctx_t *ctx, unsigned char *start, int len);
extern int smb_dr_get_buf(smb_dr_ctx_t *ctx, unsigned char *buf, int bufsize);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_SMB_COMMON_DOOR_H */
