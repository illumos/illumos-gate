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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_PRIVILEGE_H
#define	_SMB_PRIVILEGE_H

#include <smb/wintypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Privileges
 *
 * Privileges apply to all objects and over-ride the access controls
 * in an object's security descriptor in a manner specific to each
 * privilege. Privileges are still not full defined. Privileges are
 * defined in a set structure (LUID = Locally Unique Identifier).
 *
 * The default LUID, name and display names defined on NT 4.0 are:
 * LUID Privilege Name                Display Name
 * ---- --------------                ------------
 * 0:2  SeCreateTokenPrivilege        Create a token object
 * 0:3  SeAssignPrimaryTokenPrivilege Replace a process level token
 * 0:4  SeLockMemoryPrivilege         Lock pages in memory
 * 0:5  SeIncreaseQuotaPrivilege      Increase quotas
 * 0:6  SeMachineAccountPrivilege     Add workstations to domain
 * 0:7  SeTcbPrivilege                Act as part of the operating system
 * 0:8  SeSecurityPrivilege           Manage auditing and security log
 * 0:9  SeTakeOwnershipPrivilege      Take ownership of files or other objects
 * 0:10 SeLoadDriverPrivilege         Load and unload device drivers
 * 0:11 SeSystemProfilePrivilege      Profile system performance
 * 0:12 SeSystemtimePrivilege         Change the system time
 * 0:13 SeProfileSingleProcessPrivilege  Profile single process
 * 0:14 SeIncreaseBasePriorityPrivilege  Increase scheduling priority
 * 0:15 SeCreatePagefilePrivilege     Create a pagefile
 * 0:16 SeCreatePermanentPrivilege    Create permanent shared objects
 * 0:17 SeBackupPrivilege             Back up files and directories
 * 0:18 SeRestorePrivilege            Restore files and directories
 * 0:19 SeShutdownPrivilege           Shut down the system
 * 0:20 SeDebugPrivilege              Debug programs
 * 0:21 SeAuditPrivilege              Generate security audits
 * 0:22 SeSystemEnvironmentPrivilege  Modify firmware environment values
 * 0:23 SeChangeNotifyPrivilege       Bypass traverse checking
 * 0:24 SeRemoteShutdownPrivilege     Force shutdown from a remote system
 */

/*
 * Privilege names
 */
#define	SE_CREATE_TOKEN_NAME		"SeCreateTokenPrivilege"
#define	SE_ASSIGNPRIMARYTOKEN_NAME	"SeAssignPrimaryTokenPrivilege"
#define	SE_LOCK_MEMORY_NAME		"SeLockMemoryPrivilege"
#define	SE_INCREASE_QUOTA_NAME		"SeIncreaseQuotaPrivilege"
#define	SE_UNSOLICITED_INPUT_NAME	"SeUnsolicitedInputPrivilege"
#define	SE_MACHINE_ACCOUNT_NAME		"SeMachineAccountPrivilege"
#define	SE_TCB_NAME			"SeTcbPrivilege"
#define	SE_SECURITY_NAME		"SeSecurityPrivilege"
#define	SE_TAKE_OWNERSHIP_NAME		"SeTakeOwnershipPrivilege"
#define	SE_LOAD_DRIVER_NAME		"SeLoadDriverPrivilege"
#define	SE_SYSTEM_PROFILE_NAME		"SeSystemProfilePrivilege"
#define	SE_SYSTEMTIME_NAME		"SeSystemtimePrivilege"
#define	SE_PROF_SINGLE_PROCESS_NAME	"SeProfileSingleProcessPrivilege"
#define	SE_INC_BASE_PRIORITY_NAME	"SeIncreaseBasePriorityPrivilege"
#define	SE_CREATE_PAGEFILE_NAME		"SeCreatePagefilePrivilege"
#define	SE_CREATE_PERMANENT_NAME	"SeCreatePermanentPrivilege"
#define	SE_BACKUP_NAME			"SeBackupPrivilege"
#define	SE_RESTORE_NAME			"SeRestorePrivilege"
#define	SE_SHUTDOWN_NAME		"SeShutdownPrivilege"
#define	SE_DEBUG_NAME			"SeDebugPrivilege"
#define	SE_AUDIT_NAME			"SeAuditPrivilege"
#define	SE_SYSTEM_ENVIRONMENT_NAME	"SeSystemEnvironmentPrivilege"
#define	SE_CHANGE_NOTIFY_NAME		"SeChangeNotifyPrivilege"
#define	SE_REMOTE_SHUTDOWN_NAME		"SeRemoteShutdownPrivilege"

#define	SE_MIN_LUID			2
#define	SE_CREATE_TOKEN_LUID		2
#define	SE_ASSIGNPRIMARYTOKEN_LUID	3
#define	SE_LOCK_MEMORY_LUID		4
#define	SE_INCREASE_QUOTA_LUID		5
#define	SE_MACHINE_ACCOUNT_LUID		6
#define	SE_TCB_LUID			7
#define	SE_SECURITY_LUID		8
#define	SE_TAKE_OWNERSHIP_LUID		9
#define	SE_LOAD_DRIVER_LUID		10
#define	SE_SYSTEM_PROFILE_LUID		11
#define	SE_SYSTEMTIME_LUID		12
#define	SE_PROF_SINGLE_PROCESS_LUID	13
#define	SE_INC_BASE_PRIORITY_LUID	14
#define	SE_CREATE_PAGEFILE_LUID		15
#define	SE_CREATE_PERMANENT_LUID	16
#define	SE_BACKUP_LUID			17
#define	SE_RESTORE_LUID			18
#define	SE_SHUTDOWN_LUID		19
#define	SE_DEBUG_LUID			20
#define	SE_AUDIT_LUID			21
#define	SE_SYSTEM_ENVIRONMENT_LUID	22
#define	SE_CHANGE_NOTIFY_LUID		23
#define	SE_REMOTE_SHUTDOWN_LUID		24
#define	SE_MAX_LUID			24

/*
 * Privilege attributes
 */
#define	SE_PRIVILEGE_DISABLED			0x00000000
#define	SE_PRIVILEGE_ENABLED_BY_DEFAULT		0x00000001
#define	SE_PRIVILEGE_ENABLED			0x00000002
#define	SE_PRIVILEGE_USED_FOR_ACCESS		0x80000000

/*
 * Privilege Set Control flags
 */
#define	PRIVILEGE_SET_ALL_NECESSARY		1

/*
 * Local User ID (an NT thing, not a Unix UID)
 * See also: smb_luid_xdr()
 */
typedef struct smb_luid {
	uint32_t lo_part;
	uint32_t hi_part;
} smb_luid_t;

/*
 * Local User ID and attributes (again, an NT thing)
 * See also: smb_luid_attrs_xdr()
 */
typedef struct smb_luid_attrs {
	smb_luid_t luid;
	uint32_t attrs;
} smb_luid_attrs_t;

/*
 * An (NT-style) collection of privileges.
 * See also: smb_privset_xdr()
 */
typedef struct smb_privset {
	uint32_t priv_cnt;
	uint32_t control;
	smb_luid_attrs_t priv[ANY_SIZE_ARRAY];
} smb_privset_t;

/*
 * These are possible value for smb_privinfo_t.flags
 *
 * PF_PRESENTABLE	Privilege is user visible
 */
#define	PF_PRESENTABLE	0x1

/*
 * Structure for passing privilege name and id information around within
 * the system. Note that we are only storing the low uint32_t of the LUID;
 * the high part is always zero here.
 */
typedef struct smb_privinfo {
	uint32_t id;
	char *name;
	char *display_name;
	uint16_t flags;
} smb_privinfo_t;

smb_privinfo_t *smb_priv_getbyvalue(uint32_t id);
smb_privinfo_t *smb_priv_getbyname(char *name);
int smb_priv_presentable_num(void);
int smb_priv_presentable_ids(uint32_t *ids, int num);
smb_privset_t *smb_privset_new();
int smb_privset_size();
void smb_privset_init(smb_privset_t *privset);
void smb_privset_free(smb_privset_t *privset);
void smb_privset_copy(smb_privset_t *dst, smb_privset_t *src);
void smb_privset_merge(smb_privset_t *dst, smb_privset_t *src);
void smb_privset_enable(smb_privset_t *privset, uint32_t id);
int smb_privset_query(smb_privset_t *privset, uint32_t id);
void smb_privset_log(smb_privset_t *privset);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_PRIVILEGE_H */
