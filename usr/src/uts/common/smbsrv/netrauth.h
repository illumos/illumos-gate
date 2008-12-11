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

#ifndef _SMBSRV_NETRAUTH_H
#define	_SMBSRV_NETRAUTH_H


/*
 * Interface definitions for the NETR remote authentication and logon
 * services.
 */

#include <sys/types.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/netbios.h>

#ifndef _KERNEL
#include <syslog.h>
#endif /* _KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * See also netlogon.ndl.
 */
#define	NETR_WKSTA_TRUST_ACCOUNT_TYPE		0x02
#define	NETR_DOMAIN_TRUST_ACCOUNT_TYPE		0x04

/*
 * Negotiation flags for challenge/response authentication.
 */
#define	NETR_NEGOTIATE_BASE_FLAGS		0x000001FF
#define	NETR_NEGOTIATE_STRONGKEY_FLAG		0x00004000

#define	NETR_SESSKEY64_SZ			8
#define	NETR_SESSKEY128_SZ			16
#define	NETR_SESSKEY_MAXSZ			NETR_SESSKEY128_SZ
#define	NETR_CRED_DATA_SZ			8
#define	NETR_OWF_PASSWORD_SZ			16


/*
 * SAM logon levels: interactive and network.
 */
#define	NETR_INTERACTIVE_LOGON			0x01
#define	NETR_NETWORK_LOGON			0x02


/*
 * SAM logon validation levels.
 */
#define	NETR_VALIDATION_LEVEL3			0x03


/*
 * This is a duplicate of the netr_credential
 * from netlogon.ndl.
 */
typedef struct netr_cred {
	BYTE data[NETR_CRED_DATA_SZ];
} netr_cred_t;

typedef struct netr_session_key {
	BYTE key[NETR_SESSKEY_MAXSZ];
	short len;
} netr_session_key_t;

#define	NETR_FLG_NULL		0x00000001
#define	NETR_FLG_VALID		0x00000001
#define	NETR_FLG_INIT		0x00000002

/*
 * 32-byte machine account password (null-terminated)
 */
#define	NETR_MACHINE_ACCT_PASSWD_MAX	32 + 1

typedef struct netr_info {
	DWORD flags;
	char server[NETBIOS_NAME_SZ * 2];
	char hostname[NETBIOS_NAME_SZ * 2];
	netr_cred_t client_challenge;
	netr_cred_t server_challenge;
	netr_cred_t client_credential;
	netr_cred_t server_credential;
	netr_session_key_t session_key;
	BYTE password[NETR_MACHINE_ACCT_PASSWD_MAX];
	time_t timestamp;
} netr_info_t;

/*
 * netr_client_t flags
 *
 * NETR_CFLG_ANON               Anonymous connection
 * NETR_CFLG_LOCAL              Local user
 * NETR_CFLG_DOMAIN		Domain user
 */
#define	NETR_CFLG_ANON  	0x01
#define	NETR_CFLG_LOCAL 	0x02
#define	NETR_CFLG_DOMAIN	0x04


typedef struct netr_client {
	uint16_t logon_level;
	char *username;
	char *domain;
	char *workstation;
	uint32_t ipaddr;
	struct {
		uint32_t challenge_key_len;
		uint8_t *challenge_key_val;
	} challenge_key;
	struct {
		uint32_t nt_password_len;
		uint8_t *nt_password_val;
	} nt_password;
	struct {
		uint32_t lm_password_len;
		uint8_t *lm_password_val;
	} lm_password;
	uint32_t logon_id;
	int native_os;
	int native_lm;
	uint32_t local_ipaddr;
	uint16_t local_port;
	uint32_t flags;
} netr_client_t;


/*
 * NETLOGON private interface.
 */
int netr_gen_skey64(netr_info_t *);
int netr_gen_skey128(netr_info_t *);

int netr_gen_credentials(BYTE *, netr_cred_t *, DWORD, netr_cred_t *);


#define	NETR_A2H(c) (isdigit(c)) ? ((c) - '0') : ((c) - 'A' + 10)

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NETRAUTH_H */
