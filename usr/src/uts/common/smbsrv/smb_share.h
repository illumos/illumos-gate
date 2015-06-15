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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_SHARE_H
#define	_SMB_SHARE_H

#include <sys/param.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_inet.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/wintypes.h>
#include <smb/lmerr.h>

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <libshare.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	SMB_CVOL		"/var/smb/cvol"
#define	SMB_SYSROOT		SMB_CVOL "/windows"
#define	SMB_SYSTEM32		SMB_SYSROOT "/system32"
#define	SMB_VSS			SMB_SYSTEM32 "/vss"

/* Exported named pipes are in... */
#define	SMB_PIPE_DIR		"/var/smb/pipe"

/*
 * Share Properties:
 *
 * name			Advertised name of the share
 *
 * ad-container		Active directory container in which the share
 * 			will be published
 *
 * abe			Determines whether Access Based Enumeration is applied
 *			to a share
 *
 * csc			Client-side caching (CSC) options applied to this share
 * 	disabled	The client MUST NOT cache any files
 * 	manual		The client should not automatically cache every file
 * 			that it	opens
 * 	auto		The client may cache every file that it opens
 * 	vdo		The client may cache every file that it opens
 *			and satisfy file requests from its local cache.
 *
 * catia		CATIA character substitution
 *
 * guestok		Determines whether guest access is allowed
 *
 * next three properties use access-list a al NFS
 *
 * ro			list of hosts that will have read-only access
 * rw			list of hosts that will have read/write access
 * none			list of hosts that won't be allowed access
 */
#define	SHOPT_AD_CONTAINER	"ad-container"
#define	SHOPT_ABE		"abe"
#define	SHOPT_NAME		"name"
#define	SHOPT_CSC		"csc"
#define	SHOPT_CATIA		"catia"
#define	SHOPT_GUEST		"guestok"
#define	SHOPT_RO		"ro"
#define	SHOPT_RW		"rw"
#define	SHOPT_NONE		"none"
#define	SHOPT_DFSROOT		"dfsroot"
#define	SHOPT_DESCRIPTION	"description"

#define	SMB_DEFAULT_SHARE_GROUP	"smb"
#define	SMB_PROTOCOL_NAME	"smb"

/*
 * RAP protocol share related commands only understand
 * share names in OEM format and there is a 13 char size
 * limitation
 */
#define	SMB_SHARE_OEMNAME_MAX		13
#define	SMB_SHARE_NTNAME_MAX		81
#define	SMB_SHARE_CMNT_MAX		(64 * MTS_MB_CHAR_MAX)

/*
 *	struct SHARE_INFO_1 {
 *		char		shi1_netname[13]
 *		char		shi1_pad;
 *		unsigned short	shi1_type
 *		char		*shi1_remark;
 *	}
 */
#define	SHARE_INFO_1_SIZE	(SMB_SHARE_OEMNAME_MAX + 1 + 2 + 4)

/*
 * Share flags:
 *
 * There are two types of flags:
 *
 *   - flags that represent a share property
 *   - other flags set at runtime
 *
 * Property flags:
 *
 * SMB_SHRF_CSC_DISABLED	Client-side caching is disabled for this share
 * SMB_SHRF_CSC_MANUAL	Manual client-side caching is allowed
 * SMB_SHRF_CSC_AUTO	Automatic client-side caching (CSC) is allowed
 * SMB_SHRF_CSC_VDO	Automatic CSC and local cache lookup is allowed
 * SMB_SHRF_ACC_OPEN	No restrictions set
 * SMB_SHRF_ACC_NONE	"none" property set
 * SMB_SHRF_ACC_RO	"ro" (readonly) property set
 * SMB_SHRF_ACC_RW	"rw" (read/write) property set
 * SMB_SHRF_ACC_ALL	All of the access bits
 * SMB_SHRF_CATIA	CATIA character translation on/off
 * SMB_SHRF_GUEST_OK	Guest access on/off
 * SMB_SHRF_ABE		Access Based Enumeration on/off
 * SMB_SHRF_DFSROOT	Share is a standalone DFS root
 *
 * Runtime flags:
 *
 * SMB_SHRF_TRANS	Transient share
 * SMB_SHRF_PERM	Permanent share
 * SMB_SHRF_AUTOHOME	Autohome share.
 * SMB_SHRF_ADMIN	Admin share
 *
 * All autohome shares are transient but not all transient shares are autohome.
 * IPC$ and drive letter shares (e.g. d$, e$, etc) are transient but
 * not autohome.
 */

/*
 * Property flags
 */
#define	SMB_SHRF_DFSROOT	0x0001
#define	SMB_SHRF_CATIA		0x0002
#define	SMB_SHRF_GUEST_OK	0x0004
#define	SMB_SHRF_ABE		0x0008

#define	SMB_SHRF_CSC_DISABLED	0x0010
#define	SMB_SHRF_CSC_MANUAL	0x0020
#define	SMB_SHRF_CSC_AUTO	0x0040
#define	SMB_SHRF_CSC_VDO	0x0080
#define	SMB_SHRF_CSC_MASK	0x00F0

#define	SMB_SHRF_ACC_OPEN	0x0000
#define	SMB_SHRF_ACC_NONE	0x0100
#define	SMB_SHRF_ACC_RO		0x0200
#define	SMB_SHRF_ACC_RW		0x0400
#define	SMB_SHRF_ACC_ALL	0x0F00

/*
 * Runtime flags
 */
#define	SMB_SHRF_ADMIN		0x01000000
#define	SMB_SHRF_TRANS		0x10000000
#define	SMB_SHRF_PERM		0x20000000
#define	SMB_SHRF_AUTOHOME	0x40000000

#define	SMB_SHARE_PRINT		"print$"
#define	SMB_SHARE_PRINT_LEN	6
/*
 * refcnt is currently only used for autohome.  autohome needs a refcnt
 * because a user can map his autohome share from more than one client
 * at the same time and the share should only be removed when the last
 * one is disconnected
 */
typedef struct smb_share {
	char		shr_name[MAXNAMELEN];
	char		shr_path[MAXPATHLEN];
	char		shr_cmnt[SMB_SHARE_CMNT_MAX];
	char		shr_container[MAXPATHLEN];
	uint32_t	shr_flags;
	uint32_t	shr_type;
	uint32_t	shr_refcnt;
	uint32_t	shr_access_value;	/* host return access value */
	uid_t		shr_uid;		/* autohome only */
	gid_t		shr_gid;		/* autohome only */
	char		shr_access_none[MAXPATHLEN];
	char		shr_access_ro[MAXPATHLEN];
	char		shr_access_rw[MAXPATHLEN];
} smb_share_t;

typedef struct smb_shriter {
	smb_share_t	si_share;
	HT_ITERATOR	si_hashiter;
	boolean_t	si_first;
} smb_shriter_t;

#define	LMSHARES_PER_REQUEST  10
typedef struct smb_shrlist {
	int		sl_cnt;
	smb_share_t	sl_shares[LMSHARES_PER_REQUEST];
} smb_shrlist_t;

typedef struct smb_shr_execinfo {
	char		*e_sharename;
	char		*e_winname;
	char		*e_userdom;
	smb_inaddr_t	e_srv_ipaddr;
	smb_inaddr_t	e_cli_ipaddr;
	char		*e_cli_netbiosname;
	uid_t		e_uid;
	int		e_type;
} smb_shr_execinfo_t;

/*
 * LanMan share API (for both SMB kernel module and GUI/CLI sub-system)
 *
 * NOTE: If any error is encounted by either the door server or client,
 * NERR_InternalError will be returned by most functions, smb_share_count
 * will return -1.
 */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)

/*
 * CIFS share management functions exported by libmlsvc
 */
int smb_shr_start(void);
void smb_shr_stop(void);
void *smb_shr_load(void *);
void smb_shr_iterinit(smb_shriter_t *);
smb_share_t *smb_shr_iterate(smb_shriter_t *);
void smb_shr_list(int, smb_shrlist_t *);
int smb_shr_count(void);
uint32_t smb_shr_add(smb_share_t *);
uint32_t smb_shr_remove(char *);
uint32_t smb_shr_rename(char *, char *);
uint32_t smb_shr_get(char *, smb_share_t *);
uint32_t smb_shr_modify(smb_share_t *);
uint32_t smb_shr_get_realpath(const char *, char *, int);
uint32_t smb_shr_hostaccess(smb_inaddr_t *, char *, char *, char *, uint32_t);
int smb_shr_exec(smb_shr_execinfo_t *);

boolean_t smb_shr_exists(char *);
int smb_shr_is_special(char *);
boolean_t smb_shr_is_restricted(char *);
boolean_t smb_shr_is_admin(char *);
char smb_shr_drive_letter(const char *);

sa_handle_t smb_shr_sa_enter(void);
void smb_shr_sa_exit(void);
void smb_shr_sa_csc_option(const char *, smb_share_t *);
char *smb_shr_sa_csc_name(const smb_share_t *);
void smb_shr_sa_setflag(const char *, smb_share_t *, uint32_t);

/*
 * CIFS share management API exported for other processes
 */
uint32_t smb_share_list(int, smb_shrlist_t *);
int smb_share_count(void);
uint32_t smb_share_delete(char *);
uint32_t smb_share_rename(char *, char *);
uint32_t smb_share_create(smb_share_t *);
uint32_t smb_share_modify(smb_share_t *);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SHARE_H */
