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

#ifndef _SMBSRV_ADS_H
#define	_SMBSRV_ADS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <netdb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * UserAccountControl flags: manipulate user account properties.
 *
 * The hexadecimal value of the following property flags are based on MSDN
 * article # 305144.
 */
#define	ADS_USER_ACCT_CTL_SCRIPT				0x00000001
#define	ADS_USER_ACCT_CTL_ACCOUNTDISABLE			0x00000002
#define	ADS_USER_ACCT_CTL_HOMEDIR_REQUIRED			0x00000008
#define	ADS_USER_ACCT_CTL_LOCKOUT				0x00000010
#define	ADS_USER_ACCT_CTL_PASSWD_NOTREQD			0x00000020
#define	ADS_USER_ACCT_CTL_PASSWD_CANT_CHANGE			0x00000040
#define	ADS_USER_ACCT_CTL_ENCRYPTED_TEXT_PWD_ALLOWED		0x00000080
#define	ADS_USER_ACCT_CTL_TMP_DUP_ACCT				0x00000100
#define	ADS_USER_ACCT_CTL_NORMAL_ACCT				0x00000200
#define	ADS_USER_ACCT_CTL_INTERDOMAIN_TRUST_ACCT		0x00000800
#define	ADS_USER_ACCT_CTL_WKSTATION_TRUST_ACCT			0x00001000
#define	ADS_USER_ACCT_CTL_SRV_TRUST_ACCT			0x00002000
#define	ADS_USER_ACCT_CTL_DONT_EXPIRE_PASSWD			0x00010000
#define	ADS_USER_ACCT_CTL_MNS_LOGON_ACCT			0x00020000
#define	ADS_USER_ACCT_CTL_SMARTCARD_REQUIRED			0x00040000
#define	ADS_USER_ACCT_CTL_TRUSTED_FOR_DELEGATION		0x00080000
#define	ADS_USER_ACCT_CTL_NOT_DELEGATED				0x00100000
#define	ADS_USER_ACCT_CTL_USE_DES_KEY_ONLY			0x00200000
#define	ADS_USER_ACCT_CTL_DONT_REQ_PREAUTH			0x00400000
#define	ADS_USER_ACCT_CTL_PASSWD_EXPIRED			0x00800000
#define	ADS_USER_ACCT_CTL_TRUSTED_TO_AUTH_FOR_DELEGATION	0x01000000

typedef struct ads_host_info_s {
	char *name;		/* fully qualified hostname */
	int port;		/* ldap port */
	in_addr_t ip_addr;	/* network byte order */
} ADS_HOST_INFO;

#define	UNC_HOSTADDR 0		/* use ip addr in UNC */
#define	UNC_HOSTNAME 1		/* use hostname in UNC */
#define	ADS_PATH_SCRN_LEN  60

ADS_HOST_INFO *ads_find_host(char *, char *, int *, char *, int *);
char *ads_convert_directory(char *);


#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_ADS_H */
