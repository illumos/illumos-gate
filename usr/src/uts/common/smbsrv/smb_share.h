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

#ifndef _SMB_SHARE_H
#define	_SMB_SHARE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the LanMan (CIFS/SMB) resource share interface.
 */

#include <sys/param.h>
#include <smbsrv/string.h>
#include <smbsrv/hash_table.h>
#include <smbsrv/smb_fsd.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/smb_common_door.h>

#ifndef _KERNEL
#include <libshare.h>
#else
#include <sys/door.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The following 4 macros are mainly for sharemgr use
 */
#define	SMB_SHROPT_AD_CONTAINER	"ad-container"
#define	SMB_SHROPT_NAME		"name"	/* name is a pseudo property */

#define	SMB_DEFAULT_SHARE_GROUP	"smb"
#define	SMB_PROTOCOL_NAME	"smb"

/*
 * RAP protocol share related commands only understand
 * share names in OEM format and there is a 13 char size
 * limitation
 */
#define	SMB_SHARE_OEMNAME_MAX		13
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
 * SMB_SHRF_TRANS	Transient share
 * SMB_SHRF_PERM	Permanent share
 * SMB_SHRF_AUTOHOME	Autohome share.
 * SMB_SHRF_LONGNAME	Share name in OEM is longer than 13 chars
 * SMB_SHRF_ADMIN	Admin share
 *
 * All autohome shares are transient but not all transient shares are autohome.
 * IPC$ and drive letter shares (e.g. d$, e$, etc) are transient but
 * not autohome.
 */
#define	SMB_SHRF_TRANS		0x0001
#define	SMB_SHRF_PERM		0x0002
#define	SMB_SHRF_AUTOHOME	0x0004
#define	SMB_SHRF_LONGNAME	0x0008
#define	SMB_SHRF_ADMIN		0x0010
#define	SMB_SHRF_ALL		(SMB_SHRF_TRANS | SMB_SHRF_PERM)

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
	char		shr_oemname[SMB_SHARE_OEMNAME_MAX];
	uint32_t	shr_flags;
	uint32_t	shr_type;
	uint32_t	shr_refcnt;
} smb_share_t;

typedef struct smb_shriter {
	smb_share_t	si_share;
	HT_ITERATOR	si_hashiter;
	uint32_t	si_counter;
	uint32_t	si_mode;
} smb_shriter_t;

#define	LMSHARES_PER_REQUEST  10
typedef struct smb_shrlist {
	int		no;
	smb_share_t	smbshr[LMSHARES_PER_REQUEST];
} smb_shrlist_t;

/*
 * This structure is a helper for building NetShareEnum response
 * in user space and send it back down to kernel.
 *
 * es_username	name of the user requesting the shares list which
 * 		is used to detect if the user has any autohome
 * es_bufsize	size of the response buffer
 * es_buf	pointer to the response buffer
 * es_ntotal	total number of shares exported by server which
 * 		their OEM names is less then 13 chars
 * es_nsent	number of shares that can fit in the specified buffer
 * es_datasize	actual data size (share's data) which was encoded
 * 		in the response buffer
 */
typedef struct smb_enumshare_info {
	char		*es_username;
	uint16_t	es_bufsize;
	char		*es_buf;
	uint16_t	es_ntotal;
	uint16_t	es_nsent;
	uint16_t	es_datasize;
} smb_enumshare_info_t;

/*
 * LanMan share API (for both SMB kernel module and GUI/CLI sub-system)
 *
 * NOTE: If any error is encounted by either the door server or client,
 * NERR_InternalError will be returned by most functions, smb_share_count
 * will return -1.
 */

#ifndef _KERNEL

/*
 * CIFS share management functions in libmlsvc
 */
int smb_shr_start(void);
void smb_shr_stop(void);
void smb_shr_iterinit(smb_shriter_t *, uint32_t);
smb_share_t *smb_shr_iterate(smb_shriter_t *iterator);
void smb_shr_list(int offset, smb_shrlist_t *list);
int smb_shr_count(void);
uint32_t smb_shr_add(smb_share_t *si, int);
uint32_t smb_shr_del(char *share_name, int);
uint32_t smb_shr_ren(char *from, char *to, int);
uint32_t smb_shr_get(char *share_name, smb_share_t *si);
uint32_t smb_shr_set(smb_share_t *si, int);
uint32_t smb_shr_get_realpath(const char *srcbuf, char *dstbuf, int maxlen);

int smb_shr_exists(char *share_name);
int smb_shr_is_special(char *share_name);
int smb_shr_is_restricted(char *share_name);
int smb_shr_is_admin(char *share_name);
int smb_shr_is_valid(char *share_name);
int smb_shr_is_dir(char *path);
uint32_t smb_shr_add_adminshare(char *volname, unsigned char drive);

sa_group_t smb_get_smb_share_group(sa_handle_t);
void smb_build_lmshare_info(char *, char *, sa_resource_t, smb_share_t *);

/*
 * CIFS share management API exported for other processes
 */
uint32_t smb_share_list(int offset, smb_shrlist_t *list);
int smb_share_count(void);
uint32_t smb_share_get(char *, smb_share_t *);
uint32_t smb_share_del(char *);
uint32_t smb_share_ren(char *, char *);
uint32_t smb_share_add(smb_share_t *);
uint32_t smb_share_set(smb_share_t *);

#else

door_handle_t smb_kshare_init(int);
void smb_kshare_fini(door_handle_t);
uint32_t smb_kshare_getinfo(door_handle_t, char *, smb_share_t *);
int smb_kshare_upcall(door_handle_t, void *, boolean_t);
uint32_t smb_kshare_enum(door_handle_t, smb_enumshare_info_t *);

#endif

#define	SMB_SHARE_DNAME		"/var/run/smb_lmshare_door"
#define	SMB_SHARE_DSIZE		(65 * 1024)

/*
 * Door interface
 *
 * Define door operations
 */
#define	SMB_SHROP_NUM_SHARES		1
#define	SMB_SHROP_DELETE		2
#define	SMB_SHROP_RENAME		3
#define	SMB_SHROP_GETINFO		4
#define	SMB_SHROP_ADD			5
#define	SMB_SHROP_SETINFO		6
#define	SMB_SHROP_LIST			7
#define	SMB_SHROP_ENUM			8

/*
 * Door server status
 *
 * SMB_SHARE_DERROR is returned by the door server if there is problem
 * with marshalling/unmarshalling. Otherwise, SMB_SHARE_DSUCCESS is
 * returned.
 *
 */
#define	SMB_SHARE_DSUCCESS		0
#define	SMB_SHARE_DERROR		-1

void smb_dr_get_share(smb_dr_ctx_t *, smb_share_t *);
void smb_dr_put_share(smb_dr_ctx_t *, smb_share_t *);

void smb_dr_get_shrlist(smb_dr_ctx_t *, smb_shrlist_t *);
void smb_dr_put_shrlist(smb_dr_ctx_t *, smb_shrlist_t *);

void smb_share_dclose(void);

#ifdef __cplusplus
}
#endif

#endif /* _SMB_SHARE_H */
