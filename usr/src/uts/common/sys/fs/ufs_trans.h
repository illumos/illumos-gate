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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_UFS_TRANS_H
#define	_SYS_FS_UFS_TRANS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/types.h>
#include	<sys/cred.h>
#include	<sys/fs/ufs_fs.h>

/*
 * Types of deltas
 */
typedef enum delta_type {
	DT_NONE,	/*  0 no assigned type */
	DT_SB,		/*  1 superblock */
	DT_CG,		/*  2 cylinder group */
	DT_SI,		/*  3 summary info */
	DT_AB,		/*  4 allocation block */
	DT_ABZERO,	/*  5 a zero'ed allocation block */
	DT_DIR,		/*  6 directory */
	DT_INODE,	/*  7 inode */
	DT_FBI,		/*  8 fbiwrite */
	DT_QR,		/*  9 quota record */
	DT_COMMIT,	/* 10 commit record */
	DT_CANCEL,	/* 11 cancel record */
	DT_BOT,		/* 12 begin transaction */
	DT_EOT,		/* 13 end   transaction */
	DT_UD,		/* 14 userdata */
	DT_SUD,		/* 15 userdata found during log scan */
	DT_SHAD,	/* 16 data for a shadow inode */
	DT_MAX		/* 17 maximum delta type */
} delta_t;

/*
 * transaction operation types
 */
typedef enum top_type {
	TOP_READ_SYNC,		/* 0 */
	TOP_WRITE,		/* 1 */
	TOP_WRITE_SYNC,		/* 2 */
	TOP_SETATTR,		/* 3 */
	TOP_CREATE,		/* 4 */
	TOP_REMOVE,		/* 5 */
	TOP_LINK,		/* 6 */
	TOP_RENAME,		/* 7 */
	TOP_MKDIR,		/* 8 */
	TOP_RMDIR,		/* 9 */
	TOP_SYMLINK,		/* 10 */
	TOP_FSYNC,		/* 11 */
	TOP_GETPAGE,		/* 12 */
	TOP_PUTPAGE,		/* 13 */
	TOP_SBUPDATE_FLUSH,	/* 14 */
	TOP_SBUPDATE_UPDATE,	/* 15 */
	TOP_SBUPDATE_UNMOUNT,	/* 16 */
	TOP_SYNCIP_CLOSEDQ,	/* 17 */
	TOP_SYNCIP_FLUSHI,	/* 18 */
	TOP_SYNCIP_HLOCK,	/* 19 */
	TOP_SYNCIP_SYNC,	/* 20 */
	TOP_SYNCIP_FREE,	/* 21 */
	TOP_SBWRITE_RECLAIM,	/* 22 */
	TOP_SBWRITE_STABLE,	/* 23 */
	TOP_IFREE,		/* 24 */
	TOP_IUPDAT,		/* 25 */
	TOP_MOUNT,		/* 26 */
	TOP_COMMIT_ASYNC,	/* 27 */
	TOP_COMMIT_FLUSH,	/* 28 */
	TOP_COMMIT_UPDATE,	/* 29 */
	TOP_COMMIT_UNMOUNT,	/* 30 */
	TOP_SETSECATTR,		/* 31 */
	TOP_QUOTA,		/* 32 */
	TOP_ITRUNC,		/* 33 */
	TOP_ALLOCSP,		/* 34 */
	TOP_MAX			/* 35 TOP_MAX MUST be the last entry */
} top_t;

struct inode;
struct ufsvfs;

/*
 * vfs_log == NULL means not logging
 */
#define	TRANS_ISTRANS(ufsvfsp)	(ufsvfsp->vfs_log)

/*
 * begin a synchronous transaction
 */
#define	TRANS_BEGIN_SYNC(ufsvfsp, vid, vsize, error)\
{\
	if (TRANS_ISTRANS(ufsvfsp)) { \
		error = 0; \
		top_begin_sync(ufsvfsp, vid, vsize, &error); \
	} \
}

/*
 * begin a asynchronous transaction
 */
#define	TRANS_BEGIN_ASYNC(ufsvfsp, vid, vsize)\
{\
	if (TRANS_ISTRANS(ufsvfsp))\
		(void) top_begin_async(ufsvfsp, vid, vsize, 0); \
}

/*
 * try to begin a asynchronous transaction
 */
#define	TRANS_TRY_BEGIN_ASYNC(ufsvfsp, vid, vsize, err)\
{\
	if (TRANS_ISTRANS(ufsvfsp))\
		err = top_begin_async(ufsvfsp, vid, vsize, 1); \
	else\
		err = 0; \
}

/*
 * Begin a synchronous or asynchronous transaction.
 * The lint case is needed because vsize can be a constant.
 */
#ifndef __lint

#define	TRANS_BEGIN_CSYNC(ufsvfsp, issync, vid, vsize)\
{\
	if (TRANS_ISTRANS(ufsvfsp)) {\
		if (ufsvfsp->vfs_syncdir) {\
			int error = 0; \
			ASSERT(vsize); \
			top_begin_sync(ufsvfsp, vid, vsize, &error); \
			ASSERT(error == 0); \
			issync = 1; \
		} else {\
			(void) top_begin_async(ufsvfsp, vid, vsize, 0); \
			issync = 0; \
		}\
	}\
}

#else /* __lint */

#define	TRANS_BEGIN_CSYNC(ufsvfsp, issync, vid, vsize)\
{\
	if (TRANS_ISTRANS(ufsvfsp)) {\
		if (ufsvfsp->vfs_syncdir) {\
			int error = 0; \
			top_begin_sync(ufsvfsp, vid, vsize, &error); \
			issync = 1; \
		} else {\
			(void) top_begin_async(ufsvfsp, vid, vsize, 0); \
			issync = 0; \
		}\
	}\
}
#endif /* __lint */

/*
 * try to begin a synchronous or asynchronous transaction
 */

#define	TRANS_TRY_BEGIN_CSYNC(ufsvfsp, issync, vid, vsize, error)\
{\
	if (TRANS_ISTRANS(ufsvfsp)) {\
		if (ufsvfsp->vfs_syncdir) {\
			ASSERT(vsize); \
			top_begin_sync(ufsvfsp, vid, vsize, &error); \
			ASSERT(error == 0); \
			issync = 1; \
		} else {\
			error = top_begin_async(ufsvfsp, vid, vsize, 1); \
			issync = 0; \
		}\
	}\
}\


/*
 * end a asynchronous transaction
 */
#define	TRANS_END_ASYNC(ufsvfsp, vid, vsize)\
{\
	if (TRANS_ISTRANS(ufsvfsp))\
		top_end_async(ufsvfsp, vid, vsize); \
}

/*
 * end a synchronous transaction
 */
#define	TRANS_END_SYNC(ufsvfsp, error, vid, vsize)\
{\
	if (TRANS_ISTRANS(ufsvfsp))\
		top_end_sync(ufsvfsp, &error, vid, vsize); \
}

/*
 * end a synchronous or asynchronous transaction
 */
#define	TRANS_END_CSYNC(ufsvfsp, error, issync, vid, vsize)\
{\
	if (TRANS_ISTRANS(ufsvfsp))\
		if (issync)\
			top_end_sync(ufsvfsp, &error, vid, vsize); \
		else\
			top_end_async(ufsvfsp, vid, vsize); \
}
/*
 * record a delta
 */
#define	TRANS_DELTA(ufsvfsp, mof, nb, dtyp, func, arg) \
	if (TRANS_ISTRANS(ufsvfsp)) \
		top_delta(ufsvfsp, (offset_t)(mof), nb, dtyp, func, arg)

/*
 * cancel a delta
 */
#define	TRANS_CANCEL(ufsvfsp, mof, nb, flags) \
	if (TRANS_ISTRANS(ufsvfsp)) \
		top_cancel(ufsvfsp, (offset_t)(mof), nb, flags)
/*
 * log a delta
 */
#define	TRANS_LOG(ufsvfsp, va, mof, nb, buf, bufsz) \
	if (TRANS_ISTRANS(ufsvfsp)) \
		top_log(ufsvfsp, va, (offset_t)(mof), nb, buf, bufsz)
/*
 * check if a range is being canceled (converting from metadata into userdata)
 */
#define	TRANS_ISCANCEL(ufsvfsp, mof, nb) \
	((TRANS_ISTRANS(ufsvfsp)) ? \
		top_iscancel(ufsvfsp, (offset_t)(mof), nb) : 0)
/*
 * put the log into error state
 */
#define	TRANS_SETERROR(ufsvfsp) \
	if (TRANS_ISTRANS(ufsvfsp)) \
		top_seterror(ufsvfsp)
/*
 * check if device has had an error
 */
#define	TRANS_ISERROR(ufsvfsp) \
	((TRANS_ISTRANS(ufsvfsp)) ? \
		ufsvfsp->vfs_log->un_flags & LDL_ERROR : 0)

/*
 * The following macros provide a more readable interface to TRANS_DELTA
 */
#define	TRANS_BUF(ufsvfsp, vof, nb, bp, type) \
	TRANS_DELTA(ufsvfsp, \
		ldbtob(bp->b_blkno) + (offset_t)(vof), nb, type, \
		ufs_trans_push_buf, bp->b_blkno)

#define	TRANS_BUF_ITEM_128(ufsvfsp, item, base, bp, type) \
	TRANS_BUF(ufsvfsp, \
	(((uintptr_t)&(item)) & ~(128 - 1)) - (uintptr_t)(base), 128, bp, type)

#define	TRANS_INODE(ufsvfsp, ip) \
	TRANS_DELTA(ufsvfsp, ip->i_doff, sizeof (struct dinode), \
			DT_INODE, ufs_trans_push_inode, ip->i_number)

/*
 * If ever parts of an inode except the timestamps are logged using
 * this macro (or any other technique), bootloader logging support must
 * be made aware of these changes.
 */
#define	TRANS_INODE_DELTA(ufsvfsp, vof, nb, ip) \
	TRANS_DELTA(ufsvfsp, (ip->i_doff + (offset_t)(vof)), \
		nb, DT_INODE, ufs_trans_push_inode, ip->i_number)

#define	TRANS_INODE_TIMES(ufsvfsp, ip) \
	TRANS_INODE_DELTA(ufsvfsp, (caddr_t)&ip->i_atime - (caddr_t)&ip->i_ic, \
		sizeof (struct timeval32) * 3, ip)

/*
 * Check if we need to log cylinder group summary info.
 */
#define	TRANS_SI(ufsvfsp, fs, cg) \
	if (TRANS_ISTRANS(ufsvfsp)) \
		if (ufsvfsp->vfs_nolog_si) \
			fs->fs_si = FS_SI_BAD; \
		else \
			TRANS_DELTA(ufsvfsp, \
				ldbtob(fsbtodb(fs, fs->fs_csaddr)) + \
				((caddr_t)&fs->fs_cs(fs, cg) - \
				(caddr_t)fs->fs_u.fs_csp), \
				sizeof (struct csum), DT_SI, \
				ufs_trans_push_si, cg)

#define	TRANS_DIR(ip, offset) \
	(TRANS_ISTRANS(ip->i_ufsvfs) ? ufs_trans_dir(ip, offset) : 0)

#define	TRANS_QUOTA(dqp)	\
	if (TRANS_ISTRANS(dqp->dq_ufsvfsp))	\
		ufs_trans_quota(dqp);

#define	TRANS_DQRELE(ufsvfsp, dqp) \
	if (TRANS_ISTRANS(ufsvfsp) && \
	    ((curthread->t_flag & T_DONTBLOCK) == 0)) { \
		ufs_trans_dqrele(dqp); \
	} else { \
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER); \
		dqrele(dqp); \
		rw_exit(&ufsvfsp->vfs_dqrwlock); \
	}

#define	TRANS_ITRUNC(ip, length, flags, cr)	\
	ufs_trans_itrunc(ip, length, flags, cr);

#define	TRANS_WRITE_RESV(ip, uiop, ulp, resvp, residp)	\
	if ((TRANS_ISTRANS(ip->i_ufsvfs) != NULL) && (ulp != NULL)) \
		ufs_trans_write_resv(ip, uiop, resvp, residp);

#define	TRANS_WRITE(ip, uiop, ioflag, err, ulp, cr, resv, resid)	\
	if ((TRANS_ISTRANS(ip->i_ufsvfs) != NULL) && (ulp != NULL)) \
		err = ufs_trans_write(ip, uiop, ioflag, cr, resv, resid); \
	else \
		err = wrip(ip, uiop, ioflag, cr);

/*
 * These functions "wrap" functions that are not VOP or VFS
 * entry points but must still use the TRANS_BEGIN/TRANS_END
 * protocol
 */
#define	TRANS_SBUPDATE(ufsvfsp, vfsp, topid) \
	ufs_trans_sbupdate(ufsvfsp, vfsp, topid)
#define	TRANS_SYNCIP(ip, bflags, iflag, topid) \
	ufs_syncip(ip, bflags, iflag, topid)
#define	TRANS_SBWRITE(ufsvfsp, topid)	ufs_trans_sbwrite(ufsvfsp, topid)
#define	TRANS_IUPDAT(ip, waitfor)	ufs_trans_iupdat(ip, waitfor)

#ifdef	DEBUG
/*
 * Test/Debug ops
 *	The following ops maintain the metadata map.
 *	The metadata map is a debug/test feature.
 *	These ops are *not* used in the production product.
 */

/*
 * Set a flag if meta data checking.
 */
#define	TRANS_DOMATAMAP(ufsvfsp) \
	ufsvfsp->vfs_domatamap = \
		(TRANS_ISTRANS(ufsvfsp) && \
		(ufsvfsp->vfs_log->un_debug & MT_MATAMAP))

#define	TRANS_MATA_IGET(ufsvfsp, ip) \
	if (ufsvfsp->vfs_domatamap) \
		ufs_trans_mata_iget(ip)

#define	TRANS_MATA_FREE(ufsvfsp, mof, nb) \
	if (ufsvfsp->vfs_domatamap) \
		ufs_trans_mata_free(ufsvfsp, (offset_t)(mof), nb)

#define	TRANS_MATA_ALLOC(ufsvfsp, ip, bno, size, zero) \
	if (ufsvfsp->vfs_domatamap) \
		ufs_trans_mata_alloc(ufsvfsp, ip, bno, size, zero)

#define	TRANS_MATA_MOUNT(ufsvfsp) \
	if (ufsvfsp->vfs_domatamap) \
		ufs_trans_mata_mount(ufsvfsp)

#define	TRANS_MATA_UMOUNT(ufsvfsp) \
	if (ufsvfsp->vfs_domatamap) \
		ufs_trans_mata_umount(ufsvfsp)

#define	TRANS_MATA_SI(ufsvfsp, fs) \
	if (ufsvfsp->vfs_domatamap) \
		ufs_trans_mata_si(ufsvfsp, fs)

#define	TRANS_MATAADD(ufsvfsp, mof, nb) \
	top_mataadd(ufsvfsp, (offset_t)(mof), nb)

#else /* !DEBUG */

#define	TRANS_DOMATAMAP(ufsvfsp)
#define	TRANS_MATA_IGET(ufsvfsp, ip)
#define	TRANS_MATA_FREE(ufsvfsp, mof, nb)
#define	TRANS_MATA_ALLOC(ufsvfsp, ip, bno, size, zero)
#define	TRANS_MATA_MOUNT(ufsvfsp)
#define	TRANS_MATA_UMOUNT(ufsvfsp)
#define	TRANS_MATA_SI(ufsvfsp, fs)
#define	TRANS_MATAADD(ufsvfsp, mof, nb)

#endif  /* !DEBUG */

#include	<sys/fs/ufs_quota.h>
#include	<sys/fs/ufs_lockfs.h>
/*
 * identifies the type of operation passed into TRANS_BEGIN/END
 */
#define	TOP_SYNC		(0x00000001)
#define	TOP_ASYNC		(0x00000002)
#define	TOP_SYNC_FORCED		(0x00000004)	/* forced sync transaction */
/*
 *  estimated values
 */
#define	HEADERSIZE		(128)
#define	ALLOCSIZE		(160)
#define	INODESIZE		(sizeof (struct dinode) + HEADERSIZE)
#define	SIZESB			((sizeof (struct fs)) + HEADERSIZE)
#define	SIZEDIR			(DIRBLKSIZ + HEADERSIZE)
/*
 * calculated values
 */
#define	SIZECG(IP)		((IP)->i_fs->fs_cgsize + HEADERSIZE)
#define	FRAGSIZE(IP)		((IP)->i_fs->fs_fsize + HEADERSIZE)
#define	ACLSIZE(IP)		(((IP)->i_ufsvfs->vfs_maxacl + HEADERSIZE) + \
					INODESIZE)
#define	MAXACLSIZE		((MAX_ACL_ENTRIES << 1) * sizeof (aclent_t))
#define	DIRSIZE(IP)		(INODESIZE + (4 * ALLOCSIZE) + \
				    (IP)->i_fs->fs_fsize + HEADERSIZE)
#define	QUOTASIZE		sizeof (struct dquot) + HEADERSIZE
/*
 * size calculations
 */
#define	TOP_CREATE_SIZE(IP)	\
	(ACLSIZE(IP) + SIZECG(IP) + DIRSIZE(IP) + INODESIZE)
#define	TOP_REMOVE_SIZE(IP)	\
	DIRSIZE(IP)  + SIZECG(IP) + INODESIZE + SIZESB
#define	TOP_LINK_SIZE(IP)	\
	DIRSIZE(IP) + INODESIZE
#define	TOP_RENAME_SIZE(IP)	\
	DIRSIZE(IP) + DIRSIZE(IP) + SIZECG(IP)
#define	TOP_MKDIR_SIZE(IP)	\
	DIRSIZE(IP) + INODESIZE + DIRSIZE(IP) + INODESIZE + FRAGSIZE(IP) + \
	    SIZECG(IP) + ACLSIZE(IP)
#define	TOP_SYMLINK_SIZE(IP)	\
	DIRSIZE((IP)) + INODESIZE + INODESIZE + SIZECG(IP)
#define	TOP_GETPAGE_SIZE(IP)	\
	ALLOCSIZE + ALLOCSIZE + ALLOCSIZE + INODESIZE + SIZECG(IP)
#define	TOP_SYNCIP_SIZE		INODESIZE
#define	TOP_READ_SIZE		INODESIZE
#define	TOP_RMDIR_SIZE		(SIZESB + (INODESIZE * 2) + SIZEDIR)
#define	TOP_SETQUOTA_SIZE(FS)	((FS)->fs_bsize << 2)
#define	TOP_QUOTA_SIZE		(QUOTASIZE)
#define	TOP_SETSECATTR_SIZE(IP)	(MAXACLSIZE)
#define	TOP_IUPDAT_SIZE(IP)	INODESIZE + SIZECG(IP)
#define	TOP_SBUPDATE_SIZE	(SIZESB)
#define	TOP_SBWRITE_SIZE	(SIZESB)
#define	TOP_PUTPAGE_SIZE(IP)	(INODESIZE + SIZECG(IP))
#define	TOP_SETATTR_SIZE(IP)	(SIZECG(IP) + INODESIZE + QUOTASIZE + \
		ACLSIZE(IP))
#define	TOP_IFREE_SIZE(IP)	(SIZECG(IP) + INODESIZE + QUOTASIZE)
#define	TOP_MOUNT_SIZE		(SIZESB)
#define	TOP_COMMIT_SIZE		(0)

/*
 * The minimum log size is 1M.  So we will allow 1 fs operation to
 * reserve at most 512K of log space.
 */
#define	TOP_MAX_RESV	(512 * 1024)


/*
 * ufs trans function prototypes
 */
#if defined(_KERNEL)

extern int		ufs_trans_hlock();
extern void		ufs_trans_onerror();
extern int		ufs_trans_push_inode(struct ufsvfs *, delta_t, ino_t);
extern int		ufs_trans_push_buf(struct ufsvfs *, delta_t, daddr_t);
extern int		ufs_trans_push_si(struct ufsvfs *, delta_t, int);
extern void		ufs_trans_sbupdate(struct ufsvfs *, struct vfs *,
				top_t);
extern void		ufs_trans_sbwrite(struct ufsvfs *, top_t);
extern void		ufs_trans_iupdat(struct inode *, int);
extern void		ufs_trans_mata_mount(struct ufsvfs *);
extern void		ufs_trans_mata_umount(struct ufsvfs *);
extern void		ufs_trans_mata_si(struct ufsvfs *, struct fs *);
extern void		ufs_trans_mata_iget(struct inode *);
extern void		ufs_trans_mata_free(struct ufsvfs *, offset_t, off_t);
extern void		ufs_trans_mata_alloc(struct ufsvfs *, struct inode *,
				daddr_t, ulong_t, int);
extern int		ufs_trans_dir(struct inode *, off_t);
extern void		ufs_trans_quota(struct dquot *);
extern void		ufs_trans_dqrele(struct dquot *);
extern int		ufs_trans_itrunc(struct inode *, u_offset_t, int,
			    cred_t *);
extern int		ufs_trans_write(struct inode *, struct uio *, int,
			    cred_t *, int, long);
extern void		ufs_trans_write_resv(struct inode *, struct uio *,
				int *, int *);
extern int		ufs_trans_check(dev_t);
extern void		ufs_trans_redev(dev_t odev, dev_t ndev);
extern void		ufs_trans_trunc_resv(struct inode *, u_offset_t, int *,
				u_offset_t *);

/*
 * transaction prototypes
 */
void	lufs_unsnarf(struct ufsvfs *ufsvfsp);
int	lufs_snarf(struct ufsvfs *ufsvfsp, struct fs *fs, int ronly);
void	top_delta(struct ufsvfs *ufsvfsp, offset_t mof, off_t nb, delta_t dtyp,
	    int (*func)(), ulong_t arg);
void	top_cancel(struct ufsvfs *ufsvfsp, offset_t mof, off_t nb, int flags);
int	top_iscancel(struct ufsvfs *ufsvfsp, offset_t mof, off_t nb);
void	top_seterror(struct ufsvfs *ufsvfsp);
int	top_iserror(struct ufsvfs *ufsvfsp);
void	top_begin_sync(struct ufsvfs *ufsvfsp, top_t topid, ulong_t size,
	    int *error);
int	top_begin_async(struct ufsvfs *ufsvfsp, top_t topid, ulong_t size,
	    int tryasync);
void	top_end_sync(struct ufsvfs *ufsvfsp, int *ep, top_t topid,
	    ulong_t size);
void	top_end_async(struct ufsvfs *ufsvfsp, top_t topid, ulong_t size);
void	top_log(struct ufsvfs *ufsvfsp, char *va, offset_t vamof, off_t nb,
	    caddr_t buf, uint32_t bufsz);
void	top_mataadd(struct ufsvfs *ufsvfsp, offset_t mof, off_t nb);
void	top_matadel(struct ufsvfs *ufsvfsp, offset_t mof, off_t nb);
void	top_mataclr(struct ufsvfs *ufsvfsp);


#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_TRANS_H */
