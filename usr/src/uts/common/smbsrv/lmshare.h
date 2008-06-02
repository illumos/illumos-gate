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

#ifndef _SMBSRV_LMSHARE_H
#define	_SMBSRV_LMSHARE_H

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

#ifndef _KERNEL
#include <libshare.h>
#else
#include <sys/door.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	SHOPT_AD_CONTAINER	"ad-container"
#define	SHOPT_NAME		"name"	/* name is a pseudo property */

#define	SMB_DEFAULT_SHARE_GROUP	"smb"
#define	SMB_PROTOCOL_NAME	"smb"

/*
 * Despite the fact that the MAXNAMELEN is 256, we only
 * support a maximum share name length of 15 characters.
 */

#define	LMSHR_OEM_NAME_MAX		13
#define	LMSHR_VALID_NAME_MAX		15
#define	LMSHR_VALID_NAME_BUFSIZ		16
#define	LMSHR_COMMENT_MAX		(64 * MTS_MB_CHAR_MAX)

/*
 *	struct SHARE_INFO_1 {
 *		char		shi1_netname[13]
 *		char		shi1_pad;
 *		unsigned short	shi1_type
 *		char		*shi1_remark;
 *	}
 */
#define	SHARE_INFO_1_SIZE	(LMSHR_OEM_NAME_MAX + 1 + 2 + 4)

/*
 * Mode should be renamed to flags.
 *
 * LMSHRM_TRANS		Transient share
 * LMSHRM_PERM		Permanent share
 * LMSHRM_AUTOHOME	Autohome share.
 * LMSHRM_LONGNAME	Share name in OEM is longer than 13 chars
 * LMSHRM_ADMIN		Admin share
 *
 * All autohome shares are transient but not all transient shares are autohome.
 * IPC$ and drive letter shares (e.g. d$, e$, etc) are transient but
 * not autohome.
 */
#define	LMSHRM_TRANS		0x0001
#define	LMSHRM_PERM		0x0002
#define	LMSHRM_AUTOHOME		0x0004
#define	LMSHRM_LONGNAME		0x0008
#define	LMSHRM_ADMIN		0x0010
#define	LMSHRM_ALL		(LMSHRM_TRANS | LMSHRM_PERM)

#define	LMSHR_PUBLISH	0
#define	LMSHR_UNPUBLISH	1

#define	LMSHR_ADD	0
#define	LMSHR_DELETE	1

/*
 * refcnt is currently only used for autohome.  autohome needs a refcnt
 * because a user can map his autohome share from more than one client
 * at the same time and the share should only be removed when the last
 * one is disconnected
 */
typedef struct lmshare_info {
	char		share_name[MAXNAMELEN];
	char		directory[MAXPATHLEN];
	char		comment[LMSHR_COMMENT_MAX];
	char		container[MAXPATHLEN];
	char		oem_name[LMSHR_OEM_NAME_MAX];
	uint32_t	mode;
	uint32_t	stype;
	uint32_t	refcnt;
} lmshare_info_t;

typedef struct lmshare_iterator {
	lmshare_info_t	si;
	HT_ITERATOR	iterator;
	uint32_t	iteration;
	uint32_t	mode;
} lmshare_iterator_t;

#define	LMSHARES_PER_REQUEST  10
typedef struct lmshare_list {
	int		no;
	lmshare_info_t	smbshr[LMSHARES_PER_REQUEST];
} lmshare_list_t;

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
 * NERR_InternalError will be returned by most functions.
 * lmshrd_num_shares will return -1 while the lmshrd_open_iterator/
 * lmshrd_close_iterator will return NULL.
 */

#ifndef _KERNEL

/*
 * CIFS share management functions (private to the smb daemon).
 */
int lmshare_start(void);
void lmshare_stop(void);
void lmshare_init_iterator(lmshare_iterator_t *, uint32_t);
lmshare_info_t *lmshare_iterate(lmshare_iterator_t *iterator);

void lmshare_list(int offset, lmshare_list_t *list);
DWORD lmshare_list_transient(int offset, lmshare_list_t *list);
int lmshare_num_transient(void);

int lmshare_num_shares(void);
DWORD lmshare_add(lmshare_info_t *si, int);
DWORD lmshare_delete(char *share_name, int);
DWORD lmshare_rename(char *from, char *to, int);
DWORD lmshare_getinfo(char *share_name, lmshare_info_t *si);
DWORD lmshare_setinfo(lmshare_info_t *si, int);
DWORD lmshare_get_realpath(const char *srcbuf, char *dstbuf, int maxlen);
void lmshare_do_publish(lmshare_info_t *, char, int);

int lmshare_exists(char *share_name);
int lmshare_is_special(char *share_name);
int lmshare_is_restricted(char *share_name);
int lmshare_is_admin(char *share_name);
int lmshare_is_valid(char *share_name);
int lmshare_is_dir(char *path);

DWORD lmshare_add_adminshare(char *volname, unsigned char drive);

sa_group_t smb_get_smb_share_group(sa_handle_t);
void smb_build_lmshare_info(char *, char *, sa_resource_t, lmshare_info_t *);

DWORD lmshrd_list(int offset, lmshare_list_t *list);
DWORD lmshrd_list_transient(int offset, lmshare_list_t *list);
DWORD lmshrd_num_transient(void);
int lmshrd_num_shares(void);
DWORD lmshrd_getinfo(char *, lmshare_info_t *);
int lmshrd_exists(char *);
int lmshrd_is_special(char *);
int lmshrd_is_restricted(char *);
int lmshrd_is_admin(char *);
int lmshrd_is_valid(char *);
int lmshrd_is_dir(char *);
DWORD lmshrd_delete(char *);
DWORD lmshrd_rename(char *, char *);
DWORD lmshrd_add(lmshare_info_t *);
DWORD lmshrd_setinfo(lmshare_info_t *);

#else

door_handle_t smb_kshare_init(int);
void smb_kshare_fini(door_handle_t);
uint32_t smb_kshare_getinfo(door_handle_t, char *, lmshare_info_t *);
int smb_kshare_upcall(door_handle_t, void *, boolean_t);
uint32_t smb_kshare_enum(door_handle_t, smb_enumshare_info_t *);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_LMSHARE_H */
