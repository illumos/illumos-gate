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

#ifndef _SMBSRV_SMB_VOPS_H
#define	_SMBSRV_SMB_VOPS_H

/*
 * Common file system interfaces and definitions.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/mntent.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/refstr.h>
#include <sys/acl.h>
#include <sys/fcntl.h>
#include <smbsrv/smb_i18n.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ROOTVOL ""
#define	XATTR_DIR "xattr_dir"

#define	SMB_STREAM_PREFIX "SUNWsmb"
#define	SMB_STREAM_PREFIX_LEN (sizeof (SMB_STREAM_PREFIX) - 1)

#define	SMB_SHORTNAMELEN 14
#define	SMB_MAXDIRSIZE	0x7FFFFFFF

struct smb_node;
struct smb_request;

/*
 * Note: When specifying the mask for an smb_attr_t,
 * the sa_mask, and not the sa_vattr.va_mask, should be
 * filled in.  The #define's that should be used are those
 * prefixed with SMB_AT_*.  Only FSIL routines should
 * manipulate the sa_vattr.va_mask field.
 */
typedef struct smb_attr {
	uint_t		sa_mask;	/* For both vattr and CIFS attr's */
	vattr_t		sa_vattr;	/* Legacy vattr */
	uint32_t	sa_dosattr;	/* DOS attributes */
	timestruc_t	sa_crtime;	/* Creation time */
} smb_attr_t;

#define	SMB_AT_TYPE	0x00001
#define	SMB_AT_MODE	0x00002
#define	SMB_AT_UID	0x00004
#define	SMB_AT_GID	0x00008
#define	SMB_AT_FSID	0x00010
#define	SMB_AT_NODEID	0x00020
#define	SMB_AT_NLINK	0x00040
#define	SMB_AT_SIZE	0x00080
#define	SMB_AT_ATIME	0x00100
#define	SMB_AT_MTIME	0x00200
#define	SMB_AT_CTIME	0x00400
#define	SMB_AT_RDEV	0x00800
#define	SMB_AT_BLKSIZE	0x01000
#define	SMB_AT_NBLOCKS	0x02000
#define	SMB_AT_SEQ	0x08000

#define	SMB_AT_DOSATTR	0x00100000
#define	SMB_AT_CRTIME	0x00200000
#define	SMB_AT_SMB	0x00300000

#define	SMB_AT_ALL	(SMB_AT_TYPE|SMB_AT_MODE|SMB_AT_UID|SMB_AT_GID|\
			SMB_AT_FSID|SMB_AT_NODEID|SMB_AT_NLINK|SMB_AT_SIZE|\
			SMB_AT_ATIME|SMB_AT_MTIME|SMB_AT_CTIME|SMB_AT_RDEV|\
			SMB_AT_BLKSIZE|SMB_AT_NBLOCKS|SMB_AT_SEQ|SMB_AT_SMB)

int fhopen(const struct smb_node *, int);

int smb_vop_init(void);
void smb_vop_fini(void);
void smb_vop_start(void);
int smb_vop_open(vnode_t **, int, cred_t *);
void smb_vop_close(vnode_t *, int, cred_t *);
int smb_vop_read(vnode_t *, uio_t *, cred_t *);
int smb_vop_write(vnode_t *, uio_t *, int, uint32_t *, cred_t *);
int smb_vop_getattr(vnode_t *, vnode_t *, smb_attr_t *, int, cred_t *);
int smb_vop_setattr(vnode_t *, vnode_t *, smb_attr_t *, int, cred_t *);
int smb_vop_access(vnode_t *, int, int, vnode_t *, cred_t *);
void smb_vop_eaccess(vnode_t *, int *, int, vnode_t *, cred_t *);
int smb_vop_lookup(vnode_t *, char *, vnode_t **, char *, int, vnode_t *,
    cred_t *);
int smb_vop_create(vnode_t *, char *, smb_attr_t *, vnode_t **, int, cred_t *,
    vsecattr_t *);
int smb_vop_remove(vnode_t *, char *, int, cred_t *);
int smb_vop_rename(vnode_t *, char *, vnode_t *, char *, int, cred_t *);
int smb_vop_mkdir(vnode_t *, char *, smb_attr_t *, vnode_t **, int, cred_t *,
    vsecattr_t *);
int smb_vop_rmdir(vnode_t *, char *, int, cred_t *);
int smb_vop_readdir(vnode_t *, uint32_t, void *, int *, int *, cred_t *);
int smb_vop_commit(vnode_t *, cred_t *);
int smb_vop_statfs(vnode_t *, struct statvfs64 *, cred_t *);
int smb_vop_stream_lookup(vnode_t *, char *, vnode_t **, char *, vnode_t **,
    int, vnode_t *, cred_t *);
int smb_vop_stream_create(vnode_t *, char *, smb_attr_t *, vnode_t **,
    vnode_t **, int, cred_t *);
int smb_vop_stream_remove(vnode_t *, char *, int, cred_t *);
int smb_vop_lookup_xattrdir(vnode_t *, vnode_t **, int, cred_t *);
int smb_vop_traverse_check(vnode_t **);

int smb_vop_acl_read(vnode_t *, acl_t **, int, acl_type_t, cred_t *);
int smb_vop_acl_write(vnode_t *, acl_t *, int, cred_t *);
acl_type_t smb_vop_acl_type(vnode_t *);

int smb_vop_shrlock(vnode_t *, uint32_t, uint32_t, uint32_t, cred_t *);
int smb_vop_unshrlock(vnode_t *, uint32_t, cred_t *);

int smb_vop_frlock(vnode_t *, cred_t *, int, flock64_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMB_VOPS_H */
