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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SAMLIB_H
#define	_SAMLIB_H

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
DWORD sam_create_trust_account(char *, char *);
DWORD sam_create_account(char *, char *, char *, DWORD);
DWORD sam_remove_trust_account(char *, char *);
DWORD sam_delete_account(char *, char *, char *);
DWORD sam_get_local_domains(char *, char *);
DWORD sam_check_user(char *, char *, char *);

/*
 * samr_open.c
 */
DWORD samr_open(char *, char *, char *, DWORD, mlsvc_handle_t *);
DWORD samr_connect(char *, char *, char *, DWORD, mlsvc_handle_t *);
void samr_close_handle(mlsvc_handle_t *);
DWORD samr_open_domain(mlsvc_handle_t *, DWORD, struct samr_sid *,
    mlsvc_handle_t *);
DWORD samr_open_user(mlsvc_handle_t *, DWORD, DWORD, mlsvc_handle_t *);
DWORD samr_delete_user(mlsvc_handle_t *);
int samr_open_group(mlsvc_handle_t *, DWORD, mlsvc_handle_t *);
DWORD samr_create_user(mlsvc_handle_t *, char *, DWORD, DWORD *,
    mlsvc_handle_t *);

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
		DWORD acct_ctrl;
	} info16;
};


smb_sid_t *samr_lookup_domain(mlsvc_handle_t *, char *);
DWORD samr_enum_local_domains(mlsvc_handle_t *);
uint32_t samr_lookup_domain_names(mlsvc_handle_t *, char *, smb_account_t *);
DWORD samr_query_user_info(mlsvc_handle_t *, WORD, union samr_user_info *);
DWORD samr_get_user_pwinfo(mlsvc_handle_t *);

DWORD
samr_change_password(
	mlsvc_handle_t *handle,
	char *server,
	char *account,
	struct samr_encr_passwd *newpw,
	struct samr_encr_hash *oldpw);

DWORD
samr_set_user_info(
	mlsvc_handle_t *user_handle,
	int info_level,
	void *info_buf);

DWORD
netr_set_user_control(
	mlsvc_handle_t *user_handle,
	DWORD UserAccountControl);

DWORD
netr_set_user_password(
	mlsvc_handle_t *user_handle,
	char *new_pw_clear);

DWORD
netr_change_password(
	char *server,
	char *account,
	char *old_password,
	char *new_password);

#ifdef __cplusplus
}
#endif


#endif /* _SAMLIB_H */
