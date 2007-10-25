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

#ifndef _SMBSRV_LSALIB_H
#define	_SMBSRV_LSALIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Prototypes for the LSA library and RPC client side library interface.
 * There are two levels of interface defined here: lsa_xxx and lsar_xxx.
 * The lsa_xxx functions provide a high level interface which make
 * multiple RPC calls and do all the work necessary to obtain and return
 * the requested information. The lsar_xxx functions provide a low level
 * interface in which each function maps to a single underlying RPC.
 */

#include <smbsrv/ndl/lsarpc.ndl>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ntsid.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
 * lsalib.c
 */
int lsa_lookup_builtin_name(char *account_name,
    smb_userinfo_t *user_info);

int lsa_lookup_local_sam(char *domain,
    char *account_name,
    smb_userinfo_t *user_info);

int lsa_lookup_local(char *name,
    smb_userinfo_t *user_info);

int lsa_lookup_name(char *server,
    char *domain,
    char *account_name,
    smb_userinfo_t *user_info);

DWORD lsa_lookup_name2(char *server,
    char *domain,
    char *account_name,
    smb_userinfo_t *user_info);

int lsa_lookup_sid(nt_sid_t *sid,
    smb_userinfo_t *user_info);

DWORD lsa_lookup_sid2(nt_sid_t *sid,
    smb_userinfo_t *user_info);

int lsa_lookup_privs(char *server,
    char *account_name,
    char *target_name,
    smb_userinfo_t *user_info);

int lsa_test(char *server, char *account_name);


/*
 * lsar_open.c
 */
int lsar_open(int ipc_mode,
    char *server,
    char *domain,
    char *username,
    char *password,
    mlsvc_handle_t *domain_handle);

int lsar_open_policy2(char *server,
    char *domain,
    char *username,
    mlsvc_handle_t *lsa_handle);

int lsar_open_account(mlsvc_handle_t *lsa_handle,
    struct mslsa_sid *sid,
    mlsvc_handle_t *lsa_account_handle);

int lsar_close(mlsvc_handle_t *lsa_handle);


/*
 * lsar_lookup.c
 */
int lsar_query_security_desc(mlsvc_handle_t *lsa_handle);

DWORD lsar_query_info_policy(mlsvc_handle_t *lsa_handle, WORD infoClass);

int lsar_lookup_names(mlsvc_handle_t *lsa_handle,
    char *name,
    smb_userinfo_t *user_info);

int lsar_lookup_sids(mlsvc_handle_t *lsa_handle,
    struct mslsa_sid *sid,
    smb_userinfo_t *user_info);

DWORD lsar_get_userid(char *server, char *name);

int lsar_enum_accounts(mlsvc_handle_t *lsa_handle,
    DWORD *enum_context,
    struct mslsa_EnumAccountBuf *accounts);

DWORD lsar_enum_trusted_domains(mlsvc_handle_t *lsa_handle,
    DWORD *enum_context);

int lsar_enum_privs_account(mlsvc_handle_t *account_handle,
    smb_userinfo_t *user_info);

int lsar_lookup_priv_value(mlsvc_handle_t *lsa_handle,
    char *name,
    struct  ms_luid *luid);

int lsar_lookup_priv_name(mlsvc_handle_t *lsa_handle,
    struct  ms_luid *luid,
    char *name,
    int namelen);

DWORD lsar_lookup_priv_display_name(mlsvc_handle_t *lsa_handle,
    char *name,
    char *display_name,
    int display_len);

DWORD lsar_lookup_sids2(mlsvc_handle_t *lsa_handle,
    struct mslsa_sid *sid,
    smb_userinfo_t *user_info);

DWORD lsar_lookup_names2(mlsvc_handle_t *lsa_handle,
    char *name,
    smb_userinfo_t *user_info);


#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_LSALIB_H */
