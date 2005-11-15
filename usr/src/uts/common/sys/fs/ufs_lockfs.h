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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_UFS_LOCKFS_H
#define	_SYS_FS_UFS_LOCKFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lockfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sun ufs file system locking (lockfs)
 *
 * ufs file system supports the following lock types:
 * 	unlock		- releasing existing locks, or do a file system flush
 *	name lock	- no delete, no rename
 *	write lock	- no update to file system, including delete
 *	delete lock	- no delete, rename is allowed
 *	hard lock	- no update, no access, cannot be unlocked
 *			- for supporting forcible umount
 *	error lock	- no update, no access, may only be unlocked
 *			- once fs becomes clean, may be upgraded to
 *			- a hard lock
 *	error lock (read-only) -- not yet implemented --
 *			- no write changes allowed to fs, may be upgraded
 *			- to error or hard lock
 *			- degrades to panic on subsequent failures
 *
 * ufs_vnodeops(es) that conflict with the above file system lock types
 *	will get either suspended, or get a EAGAIN error,
 *	or get an EIO error if the file sytem is hard locked,
 *	or will block if the file system is error locked.
 *
 * There are exceptions.
 *	The following ufs_vnops do not obey the locking protocol:
 *	ufs_close, ufs_putpage, ufs_inactive, ufs_addmap, ufs_delmap,
 *	ufs_rwlock, ufs_rwunlock, ufs_poll.
 *
 * ul_vnops_cnt will get increment by 1 when a ufs vnodeops is entered;
 * it will be decremented by 1 when a ufs_vnodeops is exited.
 * A file system is in a quiescent state if ufs_vnops_cnt is zero.
 * Since ufs_pageio() has to change ul_vnops_cnt without using ul_lock
 * all users of ul_vnops_cnt increment and decrement it via atomic_add_long().
 */

#include <sys/fs/ufs_trans.h>
#include <sys/thread.h>

/*
 * ul_flag
 */
#define	ULOCKFS_BUSY	0x00000001	/* ul_fs_lock is being set */
#define	ULOCKFS_NOIACC	0x00000004	/* don't keep access times */
#define	ULOCKFS_NOIDEL	0x00000008	/* don't free deleted files */
#define	ULOCKFS_FALLOC	0x00000010	/* fallocate threads exist */

#define	ULOCKFS_IS_BUSY(LF)	((LF)->ul_flag & ULOCKFS_BUSY)
#define	ULOCKFS_IS_NOIACC(LF)	((LF)->ul_flag & ULOCKFS_NOIACC)
#define	ULOCKFS_IS_NOIDEL(LF)	((LF)->ul_flag & ULOCKFS_NOIDEL)
#define	ULOCKFS_IS_FALLOC(LF)	((LF)->ul_flag & ULOCKFS_FALLOC)

#define	ULOCKFS_CLR_BUSY(LF)	((LF)->ul_flag &= ~ULOCKFS_BUSY)
#define	ULOCKFS_SET_BUSY(LF)	((LF)->ul_flag |= ULOCKFS_BUSY)

#define	ULOCKFS_CLR_FALLOC(LF)	((LF)->ul_flag &= ~ULOCKFS_FALLOC)
#define	ULOCKFS_SET_FALLOC(LF)	((LF)->ul_flag |= ULOCKFS_FALLOC)

/*
 * ul_fs_mod
 */
#define	ULOCKFS_SET_MOD(LF)	((LF)->ul_fs_mod = 1)
#define	ULOCKFS_CLR_MOD(LF)	((LF)->ul_fs_mod = 0)
#define	ULOCKFS_IS_MOD(LF)	((LF)->ul_fs_mod)

/*
 * ul_fs_lock
 *
 * softlock will temporarily block most ufs_vnodeops.
 * it is used so that a waiting lockfs command will not be starved
 *
 * fwlock will block other fallocate threads wanting to obtain a write lock
 * on the file system.
 */
#define	ULOCKFS_ULOCK	((1 << LOCKFS_ULOCK))	/* unlock */
#define	ULOCKFS_WLOCK	((1 << LOCKFS_WLOCK))	/* write  lock */
#define	ULOCKFS_NLOCK	((1 << LOCKFS_NLOCK))	/* name   lock */
#define	ULOCKFS_DLOCK	((1 << LOCKFS_DLOCK))	/* delete lock */
#define	ULOCKFS_HLOCK	((1 << LOCKFS_HLOCK))	/* hard   lock */
#define	ULOCKFS_ELOCK	((1 << LOCKFS_ELOCK))	/* error  lock */
#define	ULOCKFS_ROELOCK	((1 << LOCKFS_ROELOCK)) /* error lock (read-only) */
/* Maximum number of LOCKFS lockfs defined in sys/lockfs.h are 6 */
#define	ULOCKFS_FWLOCK	(1 << (LOCKFS_MAXLOCK + 1)) /* fallocate write lock */
#define	ULOCKFS_SLOCK	0x80000000		/* soft   lock */

#define	ULOCKFS_IS_WLOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_WLOCK)
#define	ULOCKFS_IS_HLOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_HLOCK)
#define	ULOCKFS_IS_ELOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_ELOCK)
#define	ULOCKFS_IS_ROELOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_ROELOCK)
#define	ULOCKFS_IS_ULOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_ULOCK)
#define	ULOCKFS_IS_NLOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_NLOCK)
#define	ULOCKFS_IS_DLOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_DLOCK)
#define	ULOCKFS_IS_SLOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_SLOCK)
#define	ULOCKFS_IS_FWLOCK(LF)	((LF)->ul_fs_lock & ULOCKFS_FWLOCK)
#define	ULOCKFS_IS_JUSTULOCK(LF) \
	(((LF)->ul_fs_lock & (ULOCKFS_SLOCK | ULOCKFS_ULOCK)) == ULOCKFS_ULOCK)

#define	ULOCKFS_SET_SLOCK(LF)	((LF)->ul_fs_lock |= ULOCKFS_SLOCK)
#define	ULOCKFS_CLR_SLOCK(LF)	((LF)->ul_fs_lock &= ~ULOCKFS_SLOCK)

#define	ULOCKFS_SET_FWLOCK(LF)	((LF)->ul_fs_lock |= ULOCKFS_FWLOCK)
#define	ULOCKFS_CLR_FWLOCK(LF)	((LF)->ul_fs_lock &= ~ULOCKFS_FWLOCK)

#define	ULOCKFS_READ_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_WRITE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
			ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
/* used by both ufs_getattr and ufs_getsecattr */
#define	ULOCKFS_GETATTR_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
/* used by both ufs_setattr and ufs_setsecattr */
#define	ULOCKFS_SETATTR_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_ACCESS_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_LOOKUP_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_CREATE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_REMOVE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
			ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK | \
					ULOCKFS_NLOCK | ULOCKFS_DLOCK)
#define	ULOCKFS_LINK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_RENAME_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
					ULOCKFS_SLOCK | ULOCKFS_WLOCK | \
					ULOCKFS_ROELOCK | ULOCKFS_NLOCK)
#define	ULOCKFS_MKDIR_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_RMDIR_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
			ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK | \
					ULOCKFS_NLOCK | ULOCKFS_DLOCK)
#define	ULOCKFS_READDIR_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_SYMLINK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_READLINK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_FSYNC_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_FID_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_RWLOCK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_RWUNLOCK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_SEEK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_FRLOCK_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_SPACE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_FALLOCATE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | \
				ULOCKFS_WLOCK | ULOCKFS_FWLOCK)
#define	ULOCKFS_QUOTA_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
/* GETPAGE breaks up into two masks */
#define	ULOCKFS_GETREAD_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_GETWRITE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_MAP_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_FIODUTIMES_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_FIODIO_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)
#define	ULOCKFS_FIODIOS_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_PATHCONF_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)

#define	ULOCKFS_VGET_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | ULOCKFS_SLOCK)
#define	ULOCKFS_DELETE_MASK	(ULOCKFS_HLOCK | ULOCKFS_ELOCK | \
				ULOCKFS_ROELOCK | ULOCKFS_SLOCK | ULOCKFS_WLOCK)

struct ulockfs {
	ulong_t		ul_flag;	/* flags */
	ulong_t		ul_fs_lock;	/* current file system lock state */
	ulong_t		ul_fs_mod;	/* for test; fs was modified */
	ulong_t		ul_vnops_cnt;	/* # of active ufs vnops outstanding */
	kmutex_t	ul_lock;	/* mutex to protect ulockfs structure */
	kcondvar_t 	ul_cv;
	kthread_id_t	ul_sbowner;	/* thread than can write superblock */
	struct lockfs	ul_lockfs;	/* ioctl lock struct */
	ulong_t		ul_falloc_cnt;	/* # of on-going fallocate ops */
};

extern ulong_t ufs_quiesce_pend;

#define	VTOUL(VP) \
	((struct ulockfs *) \
	&((struct ufsvfs *)((VP)->v_vfsp->vfs_data))->vfs_ulockfs)
#define	ITOUL(IP)	((struct ulockfs *)&((IP)->i_ufsvfs->vfs_ulockfs))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_LOCKFS_H */
