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

#ifndef	_SMBSRV_SMB_XDR_H
#define	_SMBSRV_SMB_XDR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <rpc/xdr.h>
#include <sys/param.h>
#include <smbsrv/smbinfo.h>

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

#define	SMB_DR_MAX_USERS	50

#define	SMB_OPIPE_HDR_MAGIC	0x4F484452	/* OHDR */
#define	SMB_OPIPE_DOOR_BUFSIZE	(30 * 1024)

/*
 * Door operations for opipes.
 */
typedef enum {
	SMB_OPIPE_NULL = 0,
	SMB_OPIPE_LOOKUP,
	SMB_OPIPE_OPEN,
	SMB_OPIPE_CLOSE,
	SMB_OPIPE_READ,
	SMB_OPIPE_WRITE,
	SMB_OPIPE_STAT
} smb_opipe_op_t;

typedef struct smb_opipe_hdr {
	uint32_t oh_magic;
	uint32_t oh_fid;
	uint32_t oh_op;
	uint32_t oh_datalen;
	uint32_t oh_resid;
	uint32_t oh_status;
} smb_opipe_hdr_t;

typedef struct smb_opipe_context {
	uint64_t oc_session_id;
	uint16_t oc_uid;
	uint16_t oc_domain_len;
	char *oc_domain;
	uint16_t oc_account_len;
	char *oc_account;
	uint16_t oc_workstation_len;
	char *oc_workstation;
	smb_inaddr_t oc_ipaddr;
	int32_t oc_native_os;
	int64_t oc_logon_time;
	uint32_t oc_flags;
} smb_opipe_context_t;

typedef struct smb_dr_ulist {
	uint32_t dul_cnt;
	smb_opipe_context_t dul_users[SMB_DR_MAX_USERS];
} smb_dr_ulist_t;

/* xdr routines for common door arguments/results */
extern bool_t xdr_smb_dr_string_t(XDR *, smb_dr_string_t *);
extern bool_t xdr_smb_dr_bytes_t(XDR *, smb_dr_bytes_t *);
extern bool_t xdr_smb_dr_ulist_t(XDR *, smb_dr_ulist_t *);
extern bool_t xdr_smb_dr_kshare_t(XDR *, smb_dr_kshare_t *);
extern bool_t xdr_smb_inaddr_t(XDR *, smb_inaddr_t *);

int smb_opipe_hdr_encode(smb_opipe_hdr_t *, uint8_t *, uint32_t);
int smb_opipe_hdr_decode(smb_opipe_hdr_t *, uint8_t *, uint32_t);
bool_t smb_opipe_hdr_xdr(XDR *xdrs, smb_opipe_hdr_t *objp);
int smb_opipe_context_encode(smb_opipe_context_t *, uint8_t *, uint32_t);
int smb_opipe_context_decode(smb_opipe_context_t *, uint8_t *, uint32_t);
bool_t smb_opipe_context_xdr(XDR *, smb_opipe_context_t *);
/*
 * VSS Door Structures
 */
#define	SMB_VSS_GMT_SIZE sizeof ("@GMT-yyyy.mm.dd-hh.mm.ss")

typedef struct smb_dr_get_gmttokens {
	uint32_t gg_count;
	char *gg_path;
} smb_dr_get_gmttokens_t;

typedef char *gmttoken;

typedef struct smb_dr_return_gmttokens {
	uint32_t rg_count;
	struct {
		uint_t rg_gmttokens_len;
		gmttoken *rg_gmttokens_val;
	} rg_gmttokens;
} smb_dr_return_gmttokens_t;

typedef struct smb_dr_map_gmttoken {
	char *mg_path;
	char *mg_gmttoken;
} smb_dr_map_gmttoken_t;

extern bool_t xdr_smb_dr_get_gmttokens_t(XDR *, smb_dr_get_gmttokens_t *);
extern bool_t xdr_gmttoken(XDR *, gmttoken *);
extern bool_t xdr_smb_dr_return_gmttokens_t(XDR *xdrs,
    smb_dr_return_gmttokens_t *);
extern bool_t xdr_smb_dr_map_gmttoken_t(XDR *, smb_dr_map_gmttoken_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SMBSRV_SMB_XDR_H */
