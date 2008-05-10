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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <smbsrv/smb_fsd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ROOTVOL ""
#define	CHKPNT ".chkpnt"
#define	XATTR_DIR "xattr_dir"

#define	SMB_STREAM_PREFIX "SUNWsmb"
#define	SMB_STREAM_PREFIX_LEN (sizeof (SMB_STREAM_PREFIX) - 1)

#define	MANGLE_NAMELEN 14
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

/*
 * DOS Attributes
 * Previously defined in smbsrv/ntaccess.h
 */

#define	FILE_ATTRIBUTE_READONLY			0x00000001
#define	FILE_ATTRIBUTE_HIDDEN			0x00000002
#define	FILE_ATTRIBUTE_SYSTEM			0x00000004
#define	FILE_ATTRIBUTE_DIRECTORY		0x00000010
#define	FILE_ATTRIBUTE_ARCHIVE			0x00000020
#define	FILE_ATTRIBUTE_ENCRYPTED		0x00000040
#define	FILE_ATTRIBUTE_NORMAL			0x00000080
#define	FILE_ATTRIBUTE_TEMPORARY		0x00000100
#define	FILE_ATTRIBUTE_SPARSE_FILE		0x00000200
#define	FILE_ATTRIBUTE_REPARSE_POINT		0x00000400
#define	FILE_ATTRIBUTE_COMPRESSED		0x00000800
#define	FILE_ATTRIBUTE_OFFLINE			0x00001000
#define	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000
#define	FILE_ATTRIBUTE_MODIFIED			0x00004000
#define	FILE_ATTRIBUTE_QUARANTINED		0x00008000
#define	FILE_ATTRIBUTE_VALID_FLAGS		0x0000dfb7
#define	FILE_ATTRIBUTE_VALID_SET_FLAGS		0x0000dfa7
#define	FILE_ATTRIBUTE_MASK			0x00003FFF


#ifndef PBSHORTCUT
/* remove from libsmbbase */
#define	FHF_SMB			0x02
#endif

/* DOS specific attribute bits */
#define	FSA_DOSATTR	(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM | \
			FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN)

/*
 * File types (FSA_FMT) and permissions (FSA_MODMASK).
 * Restricted to lower 16-bits due to FS inode definitions.
 */
#define	FSA_MTIME_SEQ	0x10000000
/* #define FSA_USTREAM_SKIPSEQ	0x10000000 */
#define	FSA_UNDEF	0007000
#define	FSA_SUID	0004000
#define	FSA_SGID	0002000
#define	FSA_STICKY	0001000
#define	FSA_UPERM	0000700
#define	FSA_UREAD	0000400
#define	FSA_UWRITE	0000200
#define	FSA_UEXEC	0000100
#define	FSA_GPERM	0000070
#define	FSA_GREAD	0000040
#define	FSA_GWRITE	0000020
#define	FSA_GEXEC	0000010
#define	FSA_OPERM	0000007
#define	FSA_OREAD	0000004
#define	FSA_OWRITE	0000002
#define	FSA_OEXEC	0000001


#define	FSA_PERM_MASK		(FSA_UPERM | FSA_GPERM | FSA_OPERM)
#define	FSA_MODMASK		0007777	/* mutable by fs_setaddr() */
#define	FSA_DIR_PERM		0777	/* default permission for new */
					/* directories */
#define	FSA_FILE_PERM		0666	/* default permission for new files */

#define	FCM_CREATEVERFSIZE	8

/* stability for write */
#define	FSSTAB_UNSTABLE		0
#define	FSSTAB_DATA_SYNC	1
#define	FSSTAB_FILE_SYNC	2

/*
 * fs_online flags (meaning when set):
 *
 * FSOLF_NOMON		Do not monitor this FS.
 * FSOLF_UTF8_NAME	All names in this FS should be in UTF-8 format.
 * FSOLF_SYNCNOW	Flush all dirty blocks for this FS.
 * FSOLF_NODRIVE	Do not assign a drive letter to this FS.
 * FSOLF_STREAMS	This FS supports streams.
 * FSOLF_DISABLE_OPLOCKS  Oplocks are disabled on this FS.
 * FSOLF_RM_PENDING 	The volume is being removed (unmounted, deleted,
 *                      zapped etc.).
 * FSOLF_MDCACHE	Enable VFS meta-data caching for this FS.
 * FSOLF_ERROR 		Inconsistencies detected in the volume.
 * FSOLF_SYSTEM     	This is a system volume, no del, ren, dtq, quotas etc
 *                      allowed
 * FSOLF_COMPLIANT  	This volume is compliant; supports retention on
 *                      immutable and unlinkable (no delete, no rename).
 * FSOLF_LITE_COMPLIANT This volume has a less-stringent compliant capability
 * FSOLF_SYSAUDIT   	This volume supports the storing of system audit logs
 */
#define	FSOLF_NOEXPORT		0x00000001
#define	FSOLF_READONLY		0x00000002
#define	FSOLF_LOCKED		0x00000004
#define	FSOLF_NOMON		0x00000008
#define	FSOLF_NOSHOWMNT		0x00000010
#define	FSOLF_CASE_INSENSITIVE	0x00000020
#define	FSOLF_SUPPORTS_ACLS	0x00000040
#define	FSOLF_UTF8_NAME		0x00000080
#define	FSOLF_MIRRORING		0x00000100
#define	FSOLF_SYNCNOW		0x00000200
#define	FSOLF_NODRIVE		0x00000400
#define	FSOLF_OFFLINE		0x00000800
#define	FSOLF_STREAMS		0x00001000
#define	FSOLF_DISABLE_OPLOCKS	0x00002000
#define	FSOLF_RM_PENDING	0x00004000
#define	FSOLF_MDCACHE		0x00008000
#define	FSOLF_MNT_IN_PROGRESS	0x00010000
#define	FSOLF_NO_ATIME		0x00020000
#define	FSOLF_ERROR		0x00040000
#define	FSOLF_SYSTEM		0x00080000
#define	FSOLF_COMPLIANT		0x00100000
#define	FSOLF_LITE_COMPLIANT	0x00200000
#define	FSOLF_SYSAUDIT		0x00400000
#define	FSOLF_NO_CASE_SENSITIVE	0x00800000
#define	FSOLF_XVATTR		0x02000000
#define	FSOLF_DIRENTFLAGS	0x04000000

/*
 * The following flags are shared between live and checkpoint volumes.
 */
#define	FSOLF_SHARED_FLAGS	(FSOLF_CASE_INSENSITIVE | FSOLF_UTF8_NAME | \
    FSOLF_STREAMS)

/*
 * the following flags are dynamically set and reset so should not be stored
 * in volume.
 */
#define	FSOLF_MASK		~(FSOLF_NOEXPORT | FSOLF_READONLY |  \
				FSOLF_LOCKED | FSOLF_NOMON |        \
				FSOLF_SYNCNOW | FSOLF_NOSHOWMNT |   \
				FSOLF_NODRIVE | FSOLF_RM_PENDING)

/*
 * case_flag: set FHF_IGNORECASE for case-insensitive compare.
 */

struct fs_stream_info {
	char name[MAXPATHLEN];
	uint64_t size;
};

int fhopen(const struct smb_node *, int);

int smb_vop_init(void);
void smb_vop_fini(void);
void smb_vop_start(void);
int smb_vop_open(vnode_t **, int, cred_t *);
int smb_vop_close(vnode_t *, int, cred_t *);
int smb_vop_read(vnode_t *, uio_t *, cred_t *);
int smb_vop_write(vnode_t *, uio_t *, unsigned int *, uint32_t *, cred_t *);
int smb_vop_getattr(vnode_t *, vnode_t *, smb_attr_t *, int, cred_t *);
int smb_vop_setattr(vnode_t *, vnode_t *, smb_attr_t *, int, cred_t *,
    boolean_t);
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
