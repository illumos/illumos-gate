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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_TOKEN_H
#define	_SMB_TOKEN_H

#include <smbsrv/netrauth.h>
#include <smbsrv/smb_privilege.h>
#include <smbsrv/smb_sid.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * User Session Key
 *
 * This is part of the MAC key which is required for signing SMB messages.
 */
typedef struct smb_session_key {
	uint8_t data[16];
} smb_session_key_t;

/* 32-bit opaque buffer (non-null terminated strings) */
typedef struct smb_buf32 {
	uint32_t	len;
	uint8_t		*val;
} smb_buf32_t;

/*
 * Access Token
 *
 * An access token identifies a user, the user's privileges and the
 * list of groups of which the user is a member. This information is
 * used when access is requested to an object by comparing this
 * information with the DACL in the object's security descriptor.
 *
 * There should be one unique token per user per session per client.
 *
 * Access Token Flags
 *
 * SMB_ATF_GUEST	Token belongs to guest user
 * SMB_ATF_ANON		Token belongs to anonymous user
 * 			and it's only good for IPC Connection.
 * SMB_ATF_POWERUSER	Token belongs to a Power User member
 * SMB_ATF_BACKUPOP	Token belongs to a Power User member
 * SMB_ATF_ADMIN	Token belongs to a Domain Admins member
 */
#define	SMB_ATF_GUEST		0x00000001
#define	SMB_ATF_ANON		0x00000002
#define	SMB_ATF_POWERUSER	0x00000004
#define	SMB_ATF_BACKUPOP	0x00000008
#define	SMB_ATF_ADMIN		0x00000010

#define	SMB_POSIX_GRPS_SIZE(n) \
	(sizeof (smb_posix_grps_t) + (n - 1) * sizeof (gid_t))
/*
 * It consists of the primary and supplementary POSIX groups.
 */
typedef struct smb_posix_grps {
	uint32_t	pg_ngrps;
	gid_t		pg_grps[ANY_SIZE_ARRAY];
} smb_posix_grps_t;

typedef struct smb_token {
	smb_id_t	tkn_user;
	smb_id_t	tkn_owner;
	smb_id_t	tkn_primary_grp;
	smb_ids_t	tkn_win_grps;
	smb_privset_t	*tkn_privileges;
	char		*tkn_account_name;
	char		*tkn_domain_name;
	uint32_t	tkn_flags;
	uint32_t	tkn_audit_sid;
	smb_session_key_t *tkn_session_key;
	smb_posix_grps_t *tkn_posix_grps;
} smb_token_t;

/*
 * Details required to authenticate a user.
 */
typedef struct smb_logon {
	uint16_t	lg_level;
	char		*lg_username;	/* requested username */
	char		*lg_domain;	/* requested domain */
	char		*lg_e_username;	/* effective username */
	char		*lg_e_domain;	/* effective domain */
	char		*lg_workstation;
	smb_inaddr_t	lg_clnt_ipaddr;
	smb_inaddr_t	lg_local_ipaddr;
	uint16_t	lg_local_port;
	smb_buf32_t	lg_challenge_key;
	smb_buf32_t	lg_nt_password;
	smb_buf32_t	lg_lm_password;
	int		lg_native_os;
	int		lg_native_lm;
	uint32_t	lg_flags;
	uint32_t	lg_logon_id;	/* filled in user space */
	uint32_t	lg_domain_type;	/* filled in user space */
	uint32_t	lg_secmode;	/* filled in user space */
	uint32_t	lg_status;	/* filled in user space */
} smb_logon_t;

int smb_logon_xdr();
int smb_token_xdr();

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
void smb_token_free(smb_token_t *);
#else /* _KERNEL */
smb_token_t *smb_logon(smb_logon_t *);
void smb_logon_abort(void);
void smb_token_destroy(smb_token_t *);
uint8_t *smb_token_encode(smb_token_t *, uint32_t *);
void smb_token_log(smb_token_t *);
smb_logon_t *smb_logon_decode(uint8_t *, uint32_t);
void smb_logon_free(smb_logon_t *);
#endif /* _KERNEL */

int smb_token_query_privilege(smb_token_t *token, int priv_id);
boolean_t smb_token_valid(smb_token_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_TOKEN_H */
