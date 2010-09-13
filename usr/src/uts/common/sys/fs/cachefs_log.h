/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_CACHEFS_LOG_H
#define	_SYS_FS_CACHEFS_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/types32.h>
#include <sys/vfs.h>
#include <sys/fs/cachefs_fs.h>

#ifdef __cplusplus
extern "C" {
#endif

/* constants, etc. */

#define	CACHEFS_LOG_MAGIC	32321
#define	CACHEFS_LOG_FILE_REV	    2

#define	CACHEFS_LOG_MOUNT		 1
#define	CACHEFS_LOG_UMOUNT		 2
#define	CACHEFS_LOG_GETPAGE		 3
#define	CACHEFS_LOG_READDIR		 4
#define	CACHEFS_LOG_READLINK		 5
#define	CACHEFS_LOG_REMOVE		 6
#define	CACHEFS_LOG_RMDIR		 7
#define	CACHEFS_LOG_TRUNCATE		 8
#define	CACHEFS_LOG_PUTPAGE		 9
#define	CACHEFS_LOG_CREATE		10
#define	CACHEFS_LOG_MKDIR		11
#define	CACHEFS_LOG_RENAME		12
#define	CACHEFS_LOG_SYMLINK		13
#define	CACHEFS_LOG_POPULATE		14
#define	CACHEFS_LOG_CSYMLINK		15
#define	CACHEFS_LOG_FILLDIR		16
#define	CACHEFS_LOG_MDCREATE		17
#define	CACHEFS_LOG_GPFRONT		18
#define	CACHEFS_LOG_RFDIR		19
#define	CACHEFS_LOG_UALLOC		20
#define	CACHEFS_LOG_CALLOC		21
#define	CACHEFS_LOG_NOCACHE		22
#define	CACHEFS_LOG_NUMRECS		22

/*
 * cachefs_log_* are stored on disk, so they need to be the same
 * 32-bit vs. 64-bit.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * for communicating from user to kernel, or for storing state.
 */

typedef struct cachefs_log_control {
	int	lc_magic;
	char	lc_path[MAXPATHLEN];
	uchar_t	lc_which[(CACHEFS_LOG_NUMRECS / NBBY) + 1];
	uint64_t lc_cachep; /* really cachefscache_t * */
} cachefs_log_control_t;

/*
 * per-cachefscache information
 */

typedef struct cachefs_log_cookie {
	void		*cl_head;	/* head of records to be written */
	void		*cl_tail;	/* tail of records to be written */
	uint_t		cl_size;	/* # of bytes to be written */

	struct vnode	*cl_logvp;	/* vnode for logfile */

	cachefs_log_control_t *cl_logctl; /* points at ksp->ks_data */

	int		cl_magic;	/* cheap sanity check */
} cachefs_log_cookie_t;

/* macros for determining which things we're logging + misc stuff */
#define	CACHEFS_LOG_LOGGING(cp, which)				\
	((cp != NULL) &&					\
	(cp->c_log != NULL) &&				\
	(cp->c_log_ctl->lc_which[which / NBBY] &	\
	(1 << (which % NBBY))))
#define	CACHEFS_LOG_SET(lc, which)	\
	(lc->lc_which[which / NBBY] |= (1 << (which % NBBY)))
#define	CACHEFS_LOG_CLEAR(lc, which)	\
	(lc->lc_which[which / NBBY] &= ~(1 << (which % NBBY)))
#define	CLPAD(sname, field)			\
	(sizeof (struct sname) -		\
	offsetof(struct sname, field) -	\
	sizeof (((struct sname *)0)->field))

struct cachefs_log_logfile_header {
	uint_t lh_magic;
	uint_t lh_revision;
	int lh_errno;
	uint_t lh_blocks;
	uint_t lh_files;
	uint_t lh_maxbsize;
	uint_t lh_pagesize;
};

/*
 * declarations of the logging records.
 *
 * note -- the first three fields must be int, int, and time_t (time32_t),
 * corresponding to record type, error status, and timestamp.
 *
 * note -- the size of a trailing string should be large enough to
 * hold any necessary null-terminating bytes.  i.e. for one string,
 * say `char foo[1]'.  for two strings, null-separated, say `char
 * foo[2]'.
 *
 * XX64	time32_t (above) is going to be a problem when the underlying
 *	filesystems support 64-bit time.
 */

/*
 * XX64 - for now define all time types as 32-bits.
 */

#if (defined(_SYSCALL32) && defined(_LP64))
typedef uid32_t		cfs_uid_t;
#else /* not _SYSCALL32 && _LP64 */
typedef uid_t		cfs_uid_t;
#endif /* _SYSCALL32 && _LP64 */

struct cachefs_log_mount_record {
	int type;		/* == CACHEFS_LOG_MOUNT */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* vfs pointer -- unique while mounted */
	uint_t flags;		/* opt_flags from cachefsoptions */
	uint_t popsize;		/* opt_popsize from cachefsoptions */
	uint_t fgsize;		/* opt_fgsize from cachefsoptions */
	ushort_t pathlen;	/* length of path */
	ushort_t cacheidlen;	/* length of cacheid */
	char path[2];		/* the path of the mountpoint, and cacheid */
};

struct cachefs_log_umount_record {
	int type;		/* == CACHEFS_LOG_UMOUNT */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* vfs pointer we're unmounting */
};

struct cachefs_log_getpage_record {
	int type;		/* == CACHEFS_LOG_GETPAGE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* file identifier */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
	u_offset_t offset;	/* offset we're getting */
	uint_t len;		/* how many bytes we're getting */
};

struct cachefs_log_readdir_record {
	int type;		/* == CACHEFS_LOG_READDIR */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* file identifier */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
	u_offset_t offset;	/* offset into directory */
	int eof;		/* like `*eofp' in VOP_READDIR */
};

struct cachefs_log_readlink_record {
	int type;		/* == CACHEFS_LOG_READLINK */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* file identifier */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
	uint_t length;		/* length of symlink */
};

struct cachefs_log_remove_record {
	int type;		/* == CACHEFS_LOG_REMOVE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of file being removed */
				/* (not the directory holding the file) */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_rmdir_record {
	int type;		/* == CACHEFS_LOG_RMDIR */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of directory being removed */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_truncate_record {
	int type;		/* == CACHEFS_LOG_TRUNCATE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* file being truncated */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
	u_offset_t size;	/* new size */
};

struct cachefs_log_putpage_record {
	int type;		/* == CACHEFS_LOG_PUTPAGE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* file being written */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
	u_offset_t offset;	/* offset */
	uint_t len;		/* length */
};

struct cachefs_log_create_record {
	int type;		/* == CACHEFS_LOG_CREATE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of newly created file */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_mkdir_record {
	int type;		/* == CACHEFS_LOG_MKDIR */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of newly created directory */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_rename_record {
	int type;		/* == CACHEFS_LOG_RENAME */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t gone;		/* fid of file removed (may be undefined) */
	ino64_t fileno;		/* fileno */
	int removed;		/* nonzero if file was removed */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_symlink_record {
	int type;		/* == CACHEFS_LOG_SYMLINK */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of newly created symlink */
	ino64_t fileno;		/* fileno */
	uint_t size;		/* size of newly created symlink */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_populate_record {
	int type;		/* == CACHEFS_LOG_POPULATE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of file being populated */
	ino64_t fileno;		/* fileno */
	u_offset_t off;		/* offset */
	uint_t size;		/* popsize */
};

struct cachefs_log_csymlink_record {
	int type;		/* == CACHEFS_LOG_CSYMLINK */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of symlink being cached */
	ino64_t fileno;		/* fileno */
	int size;		/* size of symlink being cached */
};

struct cachefs_log_filldir_record {
	int type;		/* == CACHEFS_LOG_FILLDIR */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of directory being filled */
	ino64_t fileno;		/* fileno */
	int size;		/* size of frontfile after filling */
};

struct cachefs_log_mdcreate_record {
	int type;		/* == CACHEFS_LOG_MDCREATE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of file for whom md slot is created */
	ino64_t fileno;		/* fileno */
	uint_t count;		/* new number of entries in attrcache */
};

struct cachefs_log_gpfront_record {
	int type;		/* == CACHEFS_LOG_GPFRONT */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of file for whom md slot is created */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
	u_offset_t off;		/* offset */
	uint_t len;		/* length */
};

struct cachefs_log_rfdir_record {
	int type;		/* == CACHEFS_LOG_GPFRONT */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of directory */
	ino64_t fileno;		/* fileno */
	cfs_uid_t uid;		/* uid of credential */
};

struct cachefs_log_ualloc_record {
	int type;		/* == CACHEFS_LOG_UALLOC */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of allocmap-updated file */
	ino64_t fileno;		/* fileno of allocmap-updated file */
	u_offset_t off;		/* offset of new area */
	uint_t len;		/* length of new area */
};

struct cachefs_log_calloc_record {
	int type;		/* == CACHEFS_LOG_CALLOC */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of allocmap-checked file */
	ino64_t fileno;		/* fileno of allocmap-checked file */
	u_offset_t off;		/* offset of successful check_allocmap */
	uint_t len;		/* length of successful check_allocmap */
};

struct cachefs_log_nocache_record {
	int type;		/* == CACHEFS_LOG_NOCACHE */
	int error;		/* errno */
	cfs_time_t time;	/* timestamp */
	uint64_t vfsp;		/* which filesystem */
	cfs_fid_t fid;		/* fid of file being nocached */
	ino64_t fileno;		/* fileno of file being nocached */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef __cplusplus
}
#endif


#endif /* _SYS_FS_CACHEFS_LOG_H */
