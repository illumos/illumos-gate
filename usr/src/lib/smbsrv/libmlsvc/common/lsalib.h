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
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _LSALIB_H
#define	_LSALIB_H

/*
 * Prototypes for the LSA library and RPC client side library interface.
 * There are two levels of interface defined here: lsa_xxx and lsar_xxx.
 * The lsa_xxx functions provide a high level interface which make
 * multiple RPC calls and do all the work necessary to obtain and return
 * the requested information. The lsar_xxx functions provide a low level
 * interface in which each function maps to a single underlying RPC.
 */

#include <smbsrv/ndl/lsarpc.ndl>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb_sid.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct mslsa_sid lsa_sid_t;

/*
 * lsalib.c
 */
uint32_t lsa_lookup_name(char *, uint16_t, smb_account_t *);
uint32_t lsa_lookup_sid(smb_sid_t *, smb_account_t *);
DWORD lsa_query_primary_domain_info(char *, char *, smb_domain_t *);
DWORD lsa_query_account_domain_info(char *, char *, smb_domain_t *);
DWORD lsa_query_dns_domain_info(char *, char *, smb_domain_t *);
DWORD lsa_enum_trusted_domains(char *, char *, smb_trusted_domains_t *);
DWORD lsa_enum_trusted_domains_ex(char *, char *, smb_trusted_domains_t *);

/*
 * lsar_open.c
 */
DWORD lsar_open(char *, char *, char *, mlsvc_handle_t *);
DWORD lsar_open_policy2(char *, char *, char *, mlsvc_handle_t *);
int lsar_open_account(mlsvc_handle_t *, struct mslsa_sid *, mlsvc_handle_t *);
int lsar_close(mlsvc_handle_t *);

/*
 * lsar_lookup.c
 */
int lsar_query_security_desc(mlsvc_handle_t *);
DWORD lsar_query_info_policy(mlsvc_handle_t *, WORD, smb_domain_t *);
uint32_t lsar_lookup_names(mlsvc_handle_t *, char *, smb_account_t *);
uint32_t lsar_lookup_sids(mlsvc_handle_t *, smb_sid_t *, smb_account_t *);

DWORD lsar_enum_accounts(mlsvc_handle_t *, DWORD *,
    struct mslsa_EnumAccountBuf *);
DWORD lsar_enum_trusted_domains(mlsvc_handle_t *, DWORD *,
    smb_trusted_domains_t *);
DWORD lsar_enum_trusted_domains_ex(mlsvc_handle_t *, DWORD *,
    smb_trusted_domains_t *);
int lsar_enum_privs_account(mlsvc_handle_t *, smb_account_t *);
int lsar_lookup_priv_value(mlsvc_handle_t *, char *, struct  ms_luid *);
int lsar_lookup_priv_name(mlsvc_handle_t *, struct  ms_luid *, char *, int);
DWORD lsar_lookup_priv_display_name(mlsvc_handle_t *, char *, char *, int);

#ifdef __cplusplus
}
#endif

#endif /* _LSALIB_H */
