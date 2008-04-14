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

#ifndef _SMB_SID_H
#define	_SMB_SID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NT Security Identifier (SID) interface definition.
 */
#include <smbsrv/wintypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Predefined global user RIDs.
 */
#define	DOMAIN_USER_RID_ADMIN		(0x000001F4L)	/* 500 */
#define	DOMAIN_USER_RID_GUEST		(0x000001F5L)	/* 501 */
#define	DOMAIN_USER_RID_KRBTGT		(0x000001F6L)	/* 502 */

/*
 * Predefined global group RIDs.
 */
#define	DOMAIN_GROUP_RID_ADMINS		(0x00000200L)	/* 512 */
#define	DOMAIN_GROUP_RID_USERS		(0x00000201L)
#define	DOMAIN_GROUP_RID_GUESTS		(0x00000202L)
#define	DOMAIN_GROUP_RID_COMPUTERS	(0x00000203L)
#define	DOMAIN_GROUP_RID_CONTROLLERS	(0x00000204L)
#define	DOMAIN_GROUP_RID_CERT_ADMINS	(0x00000205L)
#define	DOMAIN_GROUP_RID_SCHEMA_ADMINS	(0x00000206L)


/*
 * Predefined local alias RIDs.
 */
#define	DOMAIN_ALIAS_RID_ADMINS		(0x00000220L)	/* 544 */
#define	DOMAIN_ALIAS_RID_USERS		(0x00000221L)
#define	DOMAIN_ALIAS_RID_GUESTS		(0x00000222L)
#define	DOMAIN_ALIAS_RID_POWER_USERS	(0x00000223L)
#define	DOMAIN_ALIAS_RID_ACCOUNT_OPS	(0x00000224L)
#define	DOMAIN_ALIAS_RID_SYSTEM_OPS	(0x00000225L)
#define	DOMAIN_ALIAS_RID_PRINT_OPS	(0x00000226L)
#define	DOMAIN_ALIAS_RID_BACKUP_OPS	(0x00000227L)
#define	DOMAIN_ALIAS_RID_REPLICATOR	(0x00000228L)


/*
 * Universal and NT well-known SIDs
 */
#define	NT_NULL_SIDSTR				"S-1-0-0"
#define	NT_WORLD_SIDSTR				"S-1-1-0"
#define	NT_LOCAL_SIDSTR				"S-1-2-0"
#define	NT_CREATOR_OWNER_ID_SIDSTR		"S-1-3-0"
#define	NT_CREATOR_GROUP_ID_SIDSTR		"S-1-3-1"
#define	NT_CREATOR_OWNER_SERVER_ID_SIDSTR	"S-1-3-2"
#define	NT_CREATOR_GROUP_SERVER_ID_SIDSTR	"S-1-3-3"
#define	NT_NON_UNIQUE_IDS_SIDSTR		"S-1-4"
#define	NT_AUTHORITY_SIDSTR			"S-1-5"
#define	NT_DIALUP_SIDSTR			"S-1-5-1"
#define	NT_NETWORK_SIDSTR			"S-1-5-2"
#define	NT_BATCH_SIDSTR				"S-1-5-3"
#define	NT_INTERACTIVE_SIDSTR			"S-1-5-4"
#define	NT_SERVICE_SIDSTR			"S-1-5-6"
#define	NT_ANONYMOUS_LOGON_SIDSTR		"S-1-5-7"
#define	NT_PROXY_SIDSTR				"S-1-5-8"
#define	NT_SERVER_LOGON_SIDSTR			"S-1-5-9"
#define	NT_SELF_SIDSTR				"S-1-5-10"
#define	NT_AUTHENTICATED_USER_SIDSTR		"S-1-5-11"
#define	NT_RESTRICTED_CODE_SIDSTR		"S-1-5-12"
#define	NT_LOCAL_SYSTEM_SIDSTR			"S-1-5-18"
#define	NT_NON_UNIQUE_SIDSTR			"S-1-5-21"
#define	NT_BUILTIN_DOMAIN_SIDSTR		"S-1-5-32"


/*
 * SID type indicators (SID_NAME_USE).
 */
#define	SidTypeNull			0
#define	SidTypeUser			1
#define	SidTypeGroup			2
#define	SidTypeDomain			3
#define	SidTypeAlias			4
#define	SidTypeWellKnownGroup		5
#define	SidTypeDeletedAccount		6
#define	SidTypeInvalid			7
#define	SidTypeUnknown			8
#define	SidTypeComputer			9


/*
 * Identifier authorities for various domains.
 */
#define	NT_SID_NULL_AUTH		0
#define	NT_SID_WORLD_AUTH		1
#define	NT_SID_LOCAL_AUTH		2
#define	NT_SID_CREATOR_AUTH		3
#define	NT_SID_NON_UNIQUE_AUTH		4
#define	NT_SID_NT_AUTH			5


#define	NT_SECURITY_NULL_AUTH		{0, 0, 0, 0, 0, 0}
#define	NT_SECURITY_WORLD_AUTH		{0, 0, 0, 0, 0, 1}
#define	NT_SECURITY_LOCAL_AUTH		{0, 0, 0, 0, 0, 2}
#define	NT_SECURITY_CREATOR_AUTH	{0, 0, 0, 0, 0, 3}
#define	NT_SECURITY_NON_UNIQUE_AUTH	{0, 0, 0, 0, 0, 4}
#define	NT_SECURITY_NT_AUTH		{0, 0, 0, 0, 0, 5}
#define	NT_SECURITY_UNIX_AUTH		{0, 0, 0, 0, 0, 99}


#define	SECURITY_NULL_RID			(0x00000000L)
#define	SECURITY_WORLD_RID			(0x00000000L)
#define	SECURITY_LOCAL_RID			(0X00000000L)

#define	SECURITY_CREATOR_OWNER_RID		(0x00000000L)
#define	SECURITY_CREATOR_GROUP_RID		(0x00000001L)
#define	SECURITY_CREATOR_OWNER_SERVER_RID	(0x00000002L)
#define	SECURITY_CREATOR_GROUP_SERVER_RID	(0x00000003L)

#define	SECURITY_DIALUP_RID			(0x00000001L)
#define	SECURITY_NETWORK_RID			(0x00000002L)
#define	SECURITY_BATCH_RID			(0x00000003L)
#define	SECURITY_INTERACTIVE_RID		(0x00000004L)
#define	SECURITY_LOGON_IDS_RID			(0x00000005L)
#define	SECURITY_LOGON_IDS_RID_COUNT		(3L)
#define	SECURITY_SERVICE_RID			(0x00000006L)
#define	SECURITY_ANONYMOUS_LOGON_RID		(0x00000007L)
#define	SECURITY_PROXY_RID			(0x00000008L)
#define	SECURITY_ENTERPRISE_CONTROLLERS_RID	(0x00000009L)
#define	SECURITY_SERVER_LOGON_RID	SECURITY_ENTERPRISE_CONTROLLERS_RID
#define	SECURITY_PRINCIPAL_SELF_RID		(0x0000000AL)
#define	SECURITY_AUTHENTICATED_USER_RID		(0x0000000BL)
#define	SECURITY_RESTRICTED_CODE_RID		(0x0000000CL)

#define	SECURITY_LOCAL_SYSTEM_RID		(0x00000012L)
#define	SECURITY_NT_NON_UNIQUE			(0x00000015L)
#define	SECURITY_BUILTIN_DOMAIN_RID		(0x00000020L)


#define	NT_SID_NON_UNIQUE_SUBAUTH 21


/*
 * Common definition for a SID.
 */
#define	NT_SID_REVISION		1
#define	NT_SID_AUTH_MAX		6
#define	NT_SID_SUBAUTH_MAX	15


/*
 * Security Identifier (SID)
 *
 * The security identifier (SID) uniquely identifies a user, group or
 * a domain. It consists of a revision number, the identifier authority,
 * and a list of sub-authorities. The revision number is currently 1.
 * The identifier authority identifies which system issued the SID. The
 * sub-authorities of a domain SID uniquely identify a domain. A user
 * or group SID consists of a domain SID with the user or group id
 * appended. The user or group id (also known as a relative id (RID)
 * uniquely identifies a user within a domain. A user or group SID
 * uniquely identifies a user or group across all domains. The SidType
 * values identify the various types of SID.
 *
 *      1   1   1   1   1   1
 *      5   4   3   2   1   0   9   8   7   6   5   4   3   2   1   0
 *   +---------------------------------------------------------------+
 *   |      SubAuthorityCount        |Reserved1 (SBZ)|   Revision    |
 *   +---------------------------------------------------------------+
 *   |                   IdentifierAuthority[0]                      |
 *   +---------------------------------------------------------------+
 *   |                   IdentifierAuthority[1]                      |
 *   +---------------------------------------------------------------+
 *   |                   IdentifierAuthority[2]                      |
 *   +---------------------------------------------------------------+
 *   |                                                               |
 *   +- -  -  -  -  -  -  -  SubAuthority[]  -  -  -  -  -  -  -  - -+
 *   |                                                               |
 *   +---------------------------------------------------------------+
 *
 */
/*
 * Note: NT defines the Identifier Authority as a separate
 * structure (SID_IDENTIFIER_AUTHORITY) containing a literal
 * definition of a 6 byte vector but the effect is the same
 * as defining it as a member value.
 */
typedef struct smb_sid {
	uint8_t sid_revision;
	uint8_t sid_subauthcnt;
	uint8_t sid_authority[NT_SID_AUTH_MAX];
	uint32_t sid_subauth[ANY_SIZE_ARRAY];
} smb_sid_t;

/*
 * Well-known account structure
 */
typedef struct smb_wka {
	uint16_t	wka_type;
	uint8_t		wka_domidx;
	char		*wka_sid;
	char		*wka_name;
	uint16_t	wka_flags;
	char		*wka_desc;
	smb_sid_t	*wka_binsid;
} smb_wka_t;

/*
 * Defined values for smb_wka.wka_flags
 *
 * SMB_WKAFLG_LGRP_ENABLE		Can be added as local group
 */
#define	SMB_WKAFLG_LGRP_ENABLE	0x1

/*
 * The maximum size of a SID in string format
 */
#define	SMB_SID_STRSZ		256

boolean_t smb_sid_isvalid(smb_sid_t *);
int smb_sid_len(smb_sid_t *);
smb_sid_t *smb_sid_dup(smb_sid_t *);
smb_sid_t *smb_sid_splice(smb_sid_t *, uint32_t);
int smb_sid_getrid(smb_sid_t *, uint32_t *);
int smb_sid_split(smb_sid_t *, uint32_t *);
boolean_t smb_sid_cmp(smb_sid_t *, smb_sid_t *);
boolean_t smb_sid_islocal(smb_sid_t *);
boolean_t smb_sid_indomain(smb_sid_t *, smb_sid_t *);
void smb_sid_free(smb_sid_t *);
int smb_sid_splitstr(char *, uint32_t *);
void smb_sid_tostr(smb_sid_t *, char *);
smb_sid_t *smb_sid_fromstr(char *);
char *smb_sid_type2str(uint16_t);


/*
 * Well-known account interfaces
 */
int smb_wka_init(void);
void smb_wka_fini(void);
smb_wka_t *smb_wka_lookup(char *);
char *smb_wka_lookup_sid(smb_sid_t *, uint16_t *);
smb_sid_t *smb_wka_lookup_name(char *, uint16_t *);
char *smb_wka_lookup_domain(char *);
boolean_t smb_wka_is_wellknown(char *);


#ifdef __cplusplus
}
#endif


#endif /* _SMB_SID_H */
