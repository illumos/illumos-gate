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

#ifndef	_SMBSRV_SMBINFO_H
#define	_SMBSRV_SMBINFO_H

#include <sys/types.h>
#include <smbsrv/netbios.h>
#include <netinet/in.h>
#include <smbsrv/smb_inet.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Native OS types used in SmbSessionSetupX.
 */
#ifndef NATIVE_OS_DEFINED
#define	NATIVE_OS_DEFINED

#define	NATIVE_OS_UNKNOWN	0x00000000
#define	NATIVE_OS_NT4_0		0x00000001
#define	NATIVE_OS_WIN95		0x00000002
#define	NATIVE_OS_OTHER		0x00000003
#define	NATIVE_OS_NT5_0		0x00000004
#define	NATIVE_OS_NT5_1		0x00000005
#define	NATIVE_OS_MACOS		0x00000006

/*
 * Backward compatibility aliases.
 */
#define	NATIVE_OS_WINNT		NATIVE_OS_NT4_0
#define	NATIVE_OS_WIN2000	NATIVE_OS_NT5_0
#define	NATIVE_OS_WINXP		NATIVE_OS_NT5_1

#endif /* NATIVE_OS_DEFINED */


/*
 * Native lanman types in SmbSessionSetupX. Note that these values
 * are not directly related to the negotiated protocol dialect.
 */
#ifndef NATIVE_LANMAN_DEFINED
#define	NATIVE_LANMAN_DEFINED

#define	NATIVE_LM_NONE		0x00000000
#define	NATIVE_LM_NT		0x00000001
#define	NATIVE_LM_WIN2000	0x00000002

#endif /* NATIVE_LANMAN_DEFINED */


/* PDC types to be used in user authentication process */

#define	PDC_UNKNOWN		0
#define	PDC_WINNT		1
#define	PDC_WIN2000		2
#define	PDC_WINXP		3
#define	PDC_SAMBA		4

/*
 * Please replace the use of MAX_NETWORKS with SMB_PI_MAX_NETWORKS if
 * you find it used in conjunction with smbparm_info and maybe one day
 * there will be just a single definition (here) throughout the code.
 */
#ifndef MAX_NETWORKS
#define	MAX_NETWORKS		36
#endif /* MAX_NETWORKS */

#define	SMB_PI_MAX_NETWORKS	36
#define	SMB_PI_MAX_WINS		2

#define	SMB_SECMODE_WORKGRP	1
#define	SMB_SECMODE_DOMAIN	2

#define	SMB_PI_MAX_HOST		48
#define	SMB_PI_MAX_DOMAIN	256
#define	SMB_PI_MAX_SCOPE	16
#define	SMB_PI_MAX_COMMENT	58
#define	SMB_PI_MAX_NATIVE_OS	32
#define	SMB_PI_MAX_LANMAN	32

#define	SMB_PI_KEEP_ALIVE_MIN		(90 * 60)
#define	SMB_LM_COMPATIBILITY_DEFAULT_LEV 3

typedef struct smb_kmod_cfg {
	uint32_t skc_maxworkers;
	uint32_t skc_maxconnections;
	uint32_t skc_keepalive;
	int32_t skc_restrict_anon;
	int32_t skc_signing_enable;
	int32_t skc_signing_required;
	int32_t skc_oplock_enable;
	int32_t skc_sync_enable;
	int32_t skc_secmode;
	int32_t skc_ipv6_enable;
	char skc_nbdomain[NETBIOS_NAME_SZ];
	char skc_fqdn[SMB_PI_MAX_DOMAIN];
	char skc_hostname[SMB_PI_MAX_HOST];
	char skc_system_comment[SMB_PI_MAX_COMMENT];
} smb_kmod_cfg_t;

#define	SMB_VERSION_MAJOR  4
#define	SMB_VERSION_MINOR  0

int smbnative_os_value(char *native_os);
int smbnative_lm_value(char *native_lm);
int smbnative_pdc_value(char *native_lm);

/*
 * Support for passthrough authentication.
 */
#define	AUTH_USER_GRANT			0x00000000
#define	AUTH_GUEST_GRANT		0x00000001
#define	AUTH_IPC_ONLY_GRANT		0x00000002
#define	AUTH_CONEXUS_GRANT		0x00000004

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMBINFO_H */
