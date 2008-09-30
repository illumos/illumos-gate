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

#ifndef _SMBSRV_SMB_VOPS_H
#define	_SMBSRV_SMB_VOPS_H

#pragma ident	"@(#)smb_vops.h	1.9	08/08/07 SMI"

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
#define	SMB_EOF	0x7FFFFFFF

/*
 * SMB_MINLEN_RDDIR_BUF: minimum length of buffer server will provide to
 *	VOP_READDIR.  Its value is the size of the maximum possible edirent_t
 *	for solaris.  The EDIRENT_RECLEN macro returns the size of edirent_t
 *	required for a given name length.  MAXNAMELEN is the maximum
 *	filename length allowed in Solaris.  The first two EDIRENT_RECLEN()
 *	macros are to allow for . and .. entries -- just a minor tweak to try
 *	and guarantee that buffer we give to VOP_READDIR will be large enough
 *	to hold ., .., and the largest possible solaris edirent_t.
 *
 *	This bufsize will also be used when reading dirent64_t entries.
 */

#define	SMB_MINLEN_RDDIR_BUF \
	(EDIRENT_RECLEN(1) + EDIRENT_RECLEN(2) + EDIRENT_RECLEN(MAXNAMELEN))

/*
 * DP_TO_EDP
 *
 * Fill in an edirent_t structure with information from a dirent64_t.
 * This allows the use of an edirent_t in code where both edirent_t's
 * and dirent64_t's are manipulated.
 */

#define	DP_TO_EDP(dp, edp)						\
{									\
	ASSERT((dp));							\
	ASSERT((edp));							\
	(edp)->ed_ino = (dp)->d_ino;					\
	(edp)->ed_off = (dp)->d_off;					\
	(edp)->ed_eflags = 0;						\
	(edp)->ed_reclen = (dp)->d_reclen;				\
	(void) strlcpy((edp)->ed_name, (dp)->d_name, MAXNAMELEN);	\
}

/*
 * DP_ADVANCE
 *
 * In readdir operations, advance to read the next entry in a buffer
 * returned from VOP_READDIR.  The entries are of type dirent64_t.
 */

#define	DP_ADVANCE(dp, dirbuf, numbytes)				\
{									\
	ASSERT((dp));							\
	if ((dp)->d_reclen == 0) {					\
		(dp) = NULL;						\
	} else {							\
		(dp) = (dirent64_t *)((char *)(dp) + (dp)->d_reclen);	\
		if ((dp) >= (dirent64_t *)((dirbuf) + (numbytes)))	\
			(dp) = NULL;					\
	}								\
}

/*
 * EDP_ADVANCE
 *
 * In readdir operations, advance to read the next entry in a buffer
 * returned from VOP_READDIR.  The entries are of type edirent_t.
 */

#define	EDP_ADVANCE(edp, dirbuf, numbytes)				\
{									\
	ASSERT((edp));							\
	if ((edp)->ed_reclen == 0) {					\
		(edp) = NULL;						\
	} else {							\
		(edp) = (edirent_t *)((char *)(edp) + (edp)->ed_reclen);\
		if ((edp) >= (edirent_t *)((dirbuf) + (numbytes)))	\
			(edp) = NULL;					\
	}								\
}

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

struct fs_stream_info {
	char name[MAXPATHLEN];
	uint64_t size;
};

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
int smb_vop_readdir(vnode_t *, uint32_t *, char *, int *, ino64_t *, vnode_t **,
    char *, int, cred_t *);
int smb_vop_commit(vnode_t *, cred_t *);
int smb_vop_getdents(struct smb_node *, uint32_t *, uint64_t *, int32_t *,
    char *, char *, uint32_t, struct smb_request *, cred_t *);
int smb_vop_statfs(vnode_t *, struct statvfs64 *, cred_t *);
int smb_vop_stream_lookup(vnode_t *, char *, vnode_t **, char *, vnode_t **,
    int, vnode_t *, cred_t *);
int smb_vop_stream_create(vnode_t *, char *, smb_attr_t *, vnode_t **,
    vnode_t **, int, cred_t *);
int smb_vop_stream_remove(vnode_t *, char *, int, cred_t *);
int smb_vop_stream_readdir(vnode_t *, uint32_t *, struct fs_stream_info *,
    vnode_t **, vnode_t **, int, cred_t *);
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
