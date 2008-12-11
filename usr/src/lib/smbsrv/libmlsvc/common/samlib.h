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

#ifndef _SMBSRV_SAMLIB_H
#define	_SMBSRV_SAMLIB_H

/*
 * Prototypes for the SAM library and RPC client side library interface.
 * There are two levels of interface defined here: sam_xxx and samr_xxx.
 * The sam_xxx functions provide a high level interface which make
 * multiple RPC calls and do all the work necessary to obtain and return
 * the requested information. The samr_xxx functions provide a low level
 * interface in which each function maps to a single underlying RPC.
 */

#include <smbsrv/ndl/samrpc.ndl>


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Account Control Flags
 * Use in SAMR Query Display Information RPC
 */
#define	ACF_DISABLED	0x001	/* account disable */
#define	ACF_HOMEDIRREQ	0x002	/* home dir required */
#define	ACF_PWDNOTREQ	0x004	/* password not required */
#define	ACF_TEMPDUP	0x008	/* temp dup account */
#define	ACF_NORMUSER	0x010	/* normal user */
#define	ACF_MNS		0x020	/* MNS account */
#define	ACF_DOMTRUST	0x040	/* Domain trust acct */
#define	ACF_WSTRUST	0x080	/* WKST trust acct */
#define	ACF_SVRTRUST	0x100	/* Server trust acct */
#define	ACF_PWDNOEXP	0x200	/* password no expire */
#define	ACF_AUTOLOCK	0x400	/* acct auto lock */

/*
 * samlib.c
 */
int sam_lookup_user_info(char *server, char *domain_name, char *username,
    smb_userinfo_t *user_info);

DWORD sam_create_trust_account(char *server, char *domain,
    smb_auth_info_t *auth);

DWORD sam_create_account(char *server, char *domain_name, char *account_name,
    smb_auth_info_t *auth, DWORD account_flags);

DWORD sam_remove_trust_account(char *server, char *domain);

DWORD sam_delete_account(char *server, char *domain_name, char *account_name);

DWORD sam_lookup_name(char *server, char *domain_name, char *account_name,
    DWORD *rid_ret);

DWORD sam_get_local_domains(char *server, char *domain_name);
DWORD sam_check_user(char *server, char *domain_name, char *account_name);

/*
 * samr_open.c
 */
int samr_open(char *server, char *domain, char *username,
    DWORD access_mask, mlsvc_handle_t *samr_handle);

int samr_connect(char *server, char *domain, char *username,
    DWORD access_mask, mlsvc_handle_t *samr_handle);

int samr_close_handle(mlsvc_handle_t *handle);

DWORD samr_open_domain(mlsvc_handle_t *samr_handle, DWORD access_mask,
    struct samr_sid *sid, mlsvc_handle_t *domain_handle);

DWORD samr_open_user(mlsvc_handle_t *domain_handle, DWORD access_mask,
    DWORD rid, mlsvc_handle_t *user_handle);

DWORD samr_delete_user(mlsvc_handle_t *user_handle);

int samr_open_group(mlsvc_handle_t *domain_handle, DWORD rid,
    mlsvc_handle_t *group_handle);

DWORD samr_create_user(mlsvc_handle_t *domain_handle, char *username,
    DWORD account_flags, DWORD *rid, mlsvc_handle_t *user_handle);

/*
 * samr_lookup.c
 */
union samr_user_info {
	struct info1 {
		char *username;
		char *fullname;
		DWORD group_rid;
		char *description;
		char *unknown;
	} info1;

	struct info6 {
		char *username;
		char *fullname;
	} info6;

	struct info7 {
		char *username;
	} info7;

	struct info8 {
		char *fullname;
	} info8;

	struct info9 {
		DWORD group_rid;
	} info9;

	struct info16 {
		DWORD unknown;
	} info16;
};


int samr_lookup_domain(mlsvc_handle_t *samr_handle, char *domain_name,
    smb_userinfo_t *user_info);

DWORD samr_enum_local_domains(mlsvc_handle_t *samr_handle);

DWORD samr_lookup_domain_names(mlsvc_handle_t *domain_handle, char *name,
    smb_userinfo_t *user_info);

int samr_query_user_info(mlsvc_handle_t *user_handle, WORD switch_value,
    union samr_user_info *user_info);

int samr_query_user_groups(mlsvc_handle_t *user_handle,
    smb_userinfo_t *user_info);

DWORD samr_get_user_pwinfo(mlsvc_handle_t *user_handle);

typedef struct oem_password {
	BYTE data[512];
	DWORD length;
} oem_password_t;


int sam_oem_password(oem_password_t *oem_password, unsigned char *new_password,
    unsigned char *old_password);

#ifdef __cplusplus
}
#endif


#endif /* _SMBSRV_SAMLIB_H */
