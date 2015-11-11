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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SMBSRV_SMBINFO_H
#define	_SMBSRV_SMBINFO_H

#include <sys/types.h>
#include <sys/uuid.h>
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
#define	NATIVE_OS_WINNT		0x00000001
#define	NATIVE_OS_WIN95		0x00000002
#define	NATIVE_OS_MACOS		0x00000003
#define	NATIVE_OS_WIN2000	0x00000004

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
#define	SMB_PI_MAX_NEGTOK	256	/* GUID and SMB negotiate token */

#define	SMB_PI_KEEP_ALIVE_MIN		(90 * 60)
/*
 * Some older clients (Windows 98) only handle the low byte
 * of the max workers value. If the low byte is less than
 * SMB_PI_MAX_WORKERS_MIN we set it to SMB_PI_MAX_WORKERS_MIN.
 * SMB_PI_MAX_WORKERS_MIN must therefore be < 256
 */
#define	SMB_PI_MAX_WORKERS_MIN		64
#define	SMB_PI_MAX_WORKERS_DEF		1024
#define	SMB_PI_MAX_WORKERS_MAX		16384

/*
 * Min/max initial credit grant and credit limit we allow to be
 * configured via SMB_CI_INITIAL_CREDITS, SMB_CI_MAXIMUM_CREDITS
 */
#define	SMB_PI_INITIAL_CREDITS_MIN	16
#define	SMB_PI_INITIAL_CREDITS_DEF	20
#define	SMB_PI_INITIAL_CREDITS_MAX	256

#define	SMB_PI_MAXIMUM_CREDITS_MIN	64
#define	SMB_PI_MAXIMUM_CREDITS_DEF	1000
#define	SMB_PI_MAXIMUM_CREDITS_MAX	1024

/*
 * sv_size is used by the RPC services and should be set to
 * sizeof (smb_version_t).
 */
typedef struct smb_version {
	uint32_t	sv_size;
	uint32_t	sv_major;
	uint32_t	sv_minor;
	uint32_t	sv_build_number;
	uint32_t	sv_platform_id;
} smb_version_t;

/* See also: smb_ioc_cfg_t */
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
	int32_t skc_netbios_enable;
	int32_t skc_ipv6_enable;
	int32_t skc_print_enable;
	int32_t skc_traverse_mounts;
	uint32_t skc_max_protocol;	/* SMB_VERS_... */
	uint32_t skc_execflags;
	uint32_t skc_negtok_len;
	smb_version_t skc_version;
	uint16_t skc_initial_credits;
	uint16_t skc_maximum_credits;
	uuid_t skc_machine_uuid;
	uchar_t skc_negtok[SMB_PI_MAX_NEGTOK];
	char skc_native_os[SMB_PI_MAX_NATIVE_OS];
	char skc_native_lm[SMB_PI_MAX_LANMAN];
	char skc_nbdomain[NETBIOS_NAME_SZ];
	char skc_fqdn[SMB_PI_MAX_DOMAIN];
	char skc_hostname[SMB_PI_MAX_HOST];
	char skc_system_comment[SMB_PI_MAX_COMMENT];
} smb_kmod_cfg_t;

#define	SMB_EXEC_MAP	0x01
#define	SMB_EXEC_UNMAP	0x02
#define	SMB_EXEC_TERM	0x04

#define	SMB_EXEC_DISP_CONTINUE	"continue"
#define	SMB_EXEC_DISP_TERMINATE	"terminate"

/*
 * Major version numbers
 */
#define	SMB_MAJOR_NT		4	/* Windows 95/98/Me, Windows NT4.0 */
#define	SMB_MAJOR_2000		5
#define	SMB_MAJOR_XP		5
#define	SMB_MAJOR_2003		5
#define	SMB_MAJOR_VISTA		6
#define	SMB_MAJOR_2008		6
#define	SMB_MAJOR_2008R2	6
#define	SMB_MAJOR_7		6

/*
 * Minor version numbers
 */
#define	SMB_MINOR_NT		0
#define	SMB_MINOR_2000		0
#define	SMB_MINOR_XP		1
#define	SMB_MINOR_2003		2
#define	SMB_MINOR_VISTA		0
#define	SMB_MINOR_2008		0
#define	SMB_MINOR_2008R2	1
#define	SMB_MINOR_7		1

/*
 * Max version length in string format
 */
#define	SMB_VERSTR_LEN		8

int smbnative_os_value(const char *);
int smbnative_lm_value(const char *);
int smbnative_pdc_value(const char *);
const char *smbnative_os_str(smb_version_t *);
const char *smbnative_lm_str(smb_version_t *);

/*
 * Support for passthrough authentication.
 */
#define	AUTH_USER_GRANT			0x00000000
#define	AUTH_GUEST_GRANT		0x00000001
#define	AUTH_IPC_ONLY_GRANT		0x00000002

/*
 * Defined SMB1, SMB2(+) protocol versions, as returned by
 * smb_config_get_max_protocol()
 */
#define	SMB_VERS_1		1	/* arbitrary value < 0x200 */
#define	SMB_VERS_2_BASE		0x200	/* for (SMB2 or higher?) tests */
#define	SMB_VERS_2_002		0x202	/* "2.002" */
#define	SMB_VERS_2_1		0x210	/* "2.1" */
#define	SMB_VERS_3_0		0x300	/* "3.0" */

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMBINFO_H */
