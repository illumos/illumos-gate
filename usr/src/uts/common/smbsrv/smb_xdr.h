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
#include <smbsrv/wintypes.h>
#include <smbsrv/smb_sid.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_ioctl.h>

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

typedef struct smb_netuserinfo {
	uint64_t	ui_session_id;
	uint16_t	ui_uid;
	uint16_t	ui_domain_len;
	char		*ui_domain;
	uint16_t	ui_account_len;
	char		*ui_account;
	uint16_t	ui_workstation_len;
	char		*ui_workstation;
	smb_inaddr_t	ui_ipaddr;
	int32_t		ui_native_os;
	int64_t		ui_logon_time;
	uint32_t	ui_numopens;
	uint32_t	ui_flags;
} smb_netuserinfo_t;

typedef struct smb_opennum {
	uint32_t	open_users;
	uint32_t	open_trees;
	uint32_t	open_files;
	uint32_t	qualtype;
	char		qualifier[MAXNAMELEN];
} smb_opennum_t;

typedef struct smb_netconnectinfo {
	uint32_t	ci_id;
	uint32_t	ci_type;
	uint32_t	ci_numopens;
	uint32_t	ci_numusers;
	uint32_t	ci_time;
	uint32_t	ci_namelen;
	uint32_t	ci_sharelen;
	char		*ci_username;
	char		*ci_share;
} smb_netconnectinfo_t;

typedef struct smb_netfileinfo {
	uint16_t	fi_fid;
	uint32_t	fi_uniqid;
	uint32_t	fi_permissions;
	uint32_t	fi_numlocks;
	uint32_t	fi_pathlen;
	uint32_t	fi_namelen;
	char		*fi_path;
	char		*fi_username;
} smb_netfileinfo_t;

typedef struct smb_netsvcitem {
	list_node_t	nsi_lnd;
	union {
		smb_netuserinfo_t	nsi_user;
		smb_netconnectinfo_t	nsi_tree;
		smb_netfileinfo_t	nsi_ofile;
	} nsi_un;
} smb_netsvcitem_t;

typedef struct smb_netsvc {
	list_t			ns_list;
	smb_netsvcitem_t	*ns_items;
	smb_ioc_svcenum_t	*ns_ioc;
	uint32_t		ns_ioclen;
} smb_netsvc_t;

/* xdr routines for common door arguments/results */
extern bool_t xdr_smb_dr_string_t(XDR *, smb_dr_string_t *);
extern bool_t xdr_smb_dr_bytes_t(XDR *, smb_dr_bytes_t *);
extern bool_t xdr_smb_dr_kshare_t(XDR *, smb_dr_kshare_t *);
extern bool_t xdr_smb_inaddr_t(XDR *, smb_inaddr_t *);

int smb_opipe_hdr_encode(smb_opipe_hdr_t *, uint8_t *, uint32_t);
int smb_opipe_hdr_decode(smb_opipe_hdr_t *, uint8_t *, uint32_t);
bool_t smb_opipe_hdr_xdr(XDR *xdrs, smb_opipe_hdr_t *objp);
int smb_netuserinfo_encode(smb_netuserinfo_t *, uint8_t *, uint32_t, uint_t *);
int smb_netuserinfo_decode(smb_netuserinfo_t *, uint8_t *, uint32_t, uint_t *);
bool_t smb_netuserinfo_xdr(XDR *, smb_netuserinfo_t *);
int smb_netconnectinfo_encode(smb_netconnectinfo_t *, uint8_t *, uint32_t,
    uint_t *);
int smb_netconnectinfo_decode(smb_netconnectinfo_t *, uint8_t *, uint32_t,
    uint_t *);
bool_t smb_netconnectinfo_xdr(XDR *, smb_netconnectinfo_t *);
int smb_netfileinfo_encode(smb_netfileinfo_t *, uint8_t *, uint32_t, uint_t *);
int smb_netfileinfo_decode(smb_netfileinfo_t *, uint8_t *, uint32_t, uint_t *);
bool_t smb_netfileinfo_xdr(XDR *, smb_netfileinfo_t *);

typedef uint16_t sid_type_t;

typedef struct lsa_account {
	ntstatus_t	a_status;
	sid_type_t	a_sidtype;
	char		a_domain[MAXNAMELEN];
	char		a_name[MAXNAMELEN];
	char		a_sid[SMB_SID_STRSZ];
} lsa_account_t;

int lsa_account_encode(lsa_account_t *, uint8_t *, uint32_t);
int lsa_account_decode(lsa_account_t *, uint8_t *, uint32_t);
bool_t lsa_account_xdr(XDR *, lsa_account_t *);

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
