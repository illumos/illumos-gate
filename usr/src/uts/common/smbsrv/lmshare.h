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
#define	LMSHR_VALID_NAME_MAX		15
#define	LMSHR_VALID_NAME_BUFSIZ		16
#define	LMSHR_COMMENT_MAX		(64 * MTS_MB_CHAR_MAX)

/*
 * Mode should be renamed to flags.
 *
 * LMSHRM_TRANS		Transient share
 * LMSHRM_PERM		Permanent share
 */
#define	LMSHRM_TRANS			0x0001
#define	LMSHRM_PERM			0x0002
#define	LMSHRM_ALL			(LMSHRM_TRANS | LMSHRM_PERM)

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
	char share_name[MAXNAMELEN];
	char directory[MAXPATHLEN];
	char comment[LMSHR_COMMENT_MAX];
	char container[MAXPATHLEN];
	int mode;
	int stype;
	int refcnt;
} lmshare_info_t;

typedef struct lmshare_iterator {
	lmshare_info_t si;
	HT_ITERATOR *iterator;
	unsigned int iteration;
	int mode;
} lmshare_iterator_t;

#define	LMSHARES_PER_REQUEST  10
typedef struct lmshare_list {
	int	no;
	lmshare_info_t	smbshr[LMSHARES_PER_REQUEST];
} lmshare_list_t;


#ifndef _KERNEL
/*
 * CIFS share management functions (private to the smb daemon).
 */
extern int lmshare_start(void);
extern void lmshare_stop(void);
extern lmshare_iterator_t *lmshare_open_iterator(int mode);
extern void lmshare_close_iterator(lmshare_iterator_t *iterator);
extern lmshare_info_t *lmshare_iterate(lmshare_iterator_t *iterator);

extern DWORD lmshare_list(int offset, lmshare_list_t *list);
extern DWORD lmshare_list_transient(int offset, lmshare_list_t *list);
extern int lmshare_num_transient(void);

extern int lmshare_num_shares(void);
extern DWORD lmshare_add(lmshare_info_t *si, int);
extern DWORD lmshare_delete(char *share_name, int);
extern DWORD lmshare_rename(char *from, char *to, int);
extern DWORD lmshare_getinfo(char *share_name, lmshare_info_t *si);
extern DWORD lmshare_setinfo(lmshare_info_t *si, int);
extern DWORD lmshare_get_realpath(const char *srcbuf, char *dstbuf, int maxlen);
extern void lmshare_do_publish(lmshare_info_t *, char, int);

extern int lmshare_exists(char *share_name);
extern int lmshare_is_special(char *share_name);
extern int lmshare_is_restricted(char *share_name);
extern int lmshare_is_admin(char *share_name);
extern int lmshare_is_valid(char *share_name);
extern int lmshare_is_dir(char *path);
/* XXX Move these 2 functions in mlsvc_util.h, after the libmlsvc cleanup */
extern sa_group_t smb_get_smb_share_group(sa_handle_t handle);
extern void smb_build_lmshare_info(char *share_name, char *path,
    sa_optionset_t opts, lmshare_info_t *si);

/* The following 3 functions are called by FSD user-space library */
extern DWORD lmshare_add_adminshare(char *volname, unsigned char drive);

#endif /* _KERNEL */

/*
 * LanMan share API (for both SMB kernel module and GUI/CLI sub-system)
 *
 * NOTE: If any error is encounted by either the door server or client,
 * NERR_InternalError will be returned by most functions.
 * lmshrd_num_shares will return -1 while the lmshrd_open_iterator/
 * lmshrd_close_iterator will return NULL.
 */

extern uint64_t lmshrd_open_iterator(int mode);
extern DWORD lmshrd_close_iterator(uint64_t iterator);
extern DWORD lmshrd_iterate(uint64_t iterator, lmshare_info_t *si);
#ifndef _KERNEL
extern DWORD lmshrd_list(int offset, lmshare_list_t *list);
extern DWORD lmshrd_list_transient(int offset, lmshare_list_t *list);
extern DWORD lmshrd_num_transient(void);
extern int lmshrd_dump_hash(char *logfname);
#endif
extern int lmshrd_num_shares(void);
extern DWORD lmshrd_delete(char *share_name);
extern DWORD lmshrd_rename(char *from, char *to);
extern DWORD lmshrd_getinfo(char *share_name, lmshare_info_t *si);
extern DWORD lmshrd_add(lmshare_info_t *si);
extern DWORD lmshrd_setinfo(lmshare_info_t *si);

extern int lmshrd_exists(char *share_name);
extern int lmshrd_is_special(char *share_name);
extern int lmshrd_is_restricted(char *share_name);
extern int lmshrd_is_admin(char *share_name);
extern int lmshrd_is_valid(char *share_name);
extern int lmshrd_is_dir(char *path);

/*
 * The SMB kernel module must invoke the following functions to start/stop
 * the LanMan share door client.
 */
#ifdef _KERNEL
extern int lmshrd_kclient_start(void);
extern void lmshrd_kclient_stop(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_LMSHARE_H */
