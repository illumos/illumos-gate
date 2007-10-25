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

#ifndef	_SMBSRV_SMB_XDR_H
#define	_SMBSRV_SMB_XDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <rpc/xdr.h>
#include <sys/param.h>

typedef struct smb_dr_kshare {
	int32_t k_op;
	char *k_path;
	char *k_sharename;
} smb_dr_kshare_t;

#ifdef _KERNEL
#define	xdr_int8_t	xdr_char
#define	xdr_uint8_t	xdr_u_char
#define	xdr_int16_t	xdr_short
#define	xdr_uint16_t	xdr_u_short

extern bool_t xdr_u_char(XDR *xdrs, uchar_t *cp);
extern bool_t xdr_vector(XDR *xdrs, char *basep, uint_t nelem,
    uint_t elemsize, xdrproc_t xdr_elem);

smb_dr_kshare_t *smb_share_mkabsolute(uint8_t *buf, uint32_t len);
#else
uint8_t *smb_kshare_mkselfrel(smb_dr_kshare_t *kshare, uint32_t *len);
#endif /* _KERNEL */

/* null-terminated string buffer */
typedef struct smb_dr_string {
	char *buf;
} smb_dr_string_t;

/* byte buffer (non-null terminated) */
typedef struct smb_dr_bytes {
	uint32_t bytes_len;
	uint8_t *bytes_val;
} smb_dr_bytes_t;

/*
 * smb_dr_user_ctx/smb_dr_ulist data structures are defined to transfer
 * the necessary information for all connected users via door to
 * mlsvc. The smb_dr_user_ctx provides user context that will be part
 * of the MLSVC rpc context.
 *
 * Both SMB session ID and SMB UID of smb_dr_user_ctx_t are used to
 * uniquely identified the corresponding in-kernel SMB user object.
 */
#define	SMB_DR_MAX_USERS	50
typedef struct smb_dr_user_ctx {
	uint64_t du_session_id;
	uint16_t du_uid;
	uint16_t du_domain_len;
	char *du_domain;
	uint16_t du_account_len;
	char *du_account;
	uint16_t du_workstation_len;
	char *du_workstation;
	uint32_t du_ipaddr;
	int32_t du_native_os;
	int64_t du_logon_time;
	uint32_t du_flags;
} smb_dr_user_ctx_t;

typedef struct smb_dr_ulist {
	uint32_t dul_cnt;
	smb_dr_user_ctx_t dul_users[SMB_DR_MAX_USERS];
} smb_dr_ulist_t;

/* xdr routines for common door arguments/results */
extern bool_t xdr_smb_dr_string_t(XDR *, smb_dr_string_t *);
extern bool_t xdr_smb_dr_bytes_t(XDR *, smb_dr_bytes_t *);
extern bool_t xdr_smb_dr_user_ctx_t(XDR *, smb_dr_user_ctx_t *);
extern bool_t xdr_smb_dr_ulist_t(XDR *, smb_dr_ulist_t *);
extern bool_t xdr_smb_dr_kshare_t(XDR *, smb_dr_kshare_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SMBSRV_SMB_XDR_H */
