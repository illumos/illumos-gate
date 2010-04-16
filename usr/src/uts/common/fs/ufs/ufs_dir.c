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
 * Copyright (c) 1984, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Directory manipulation routines.
 *
 * When manipulating directories, the i_rwlock provides serialization
 * since directories cannot be mmapped. The i_contents lock is redundant.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/mount.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_panic.h>
#include <sys/fs/ufs_quota.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/seg.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/unistd.h>
#include <sys/policy.h>

/*
 * This is required since we're using P2ROUNDUP_TYPED on DIRBLKSIZ
 */
#if !ISP2(DIRBLKSIZ)
#error	"DIRBLKSIZ not a power of 2"
#endif

/*
 * A virgin directory.
 */
static struct dirtemplate mastertemplate = {
	0, 12, 1, ".",
	0, DIRBLKSIZ - 12, 2, ".."
};

#define	LDIRSIZ(len) \
	((sizeof (struct direct) - (MAXNAMLEN + 1)) + ((len + 1 + 3) &~ 3))
#define	MAX_DIR_NAME_LEN(len) \
	(((len) - (sizeof (struct direct) - (MAXNAMLEN + 1))) - 1)

/*
 * The dnlc directory cache allows a 64 bit handle for directory entries.
 * For ufs we squeeze both the 32 bit inumber and a 32 bit disk offset
 * into the handle. Note, a 32 bit offset allows a 4GB directory, which
 * is way beyond what could be cached in memory by the directory
 * caching routines. So we are quite safe with this limit.
 * The macros below pack and unpack the handle.
 */
#define	H_TO_INO(h) (uint32_t)((h) & UINT_MAX)
#define	H_TO_OFF(h) (off_t)((h) >> 32)
#define	INO_OFF_TO_H(ino, off) (uint64_t)(((uint64_t)(off) << 32) | (ino))

/*
 * The average size of a typical on disk directory entry is about 16 bytes
 * and so defines AV_DIRECT_SHIFT : log2(16)
 * This define is only used to approximate the number of entries
 * is a directory. This is needed for dnlc_dir_start() which will immediately
 * return an error if the value is not within its acceptable range of
 * number of files in a directory.
 */
#define	AV_DIRECT_SHIFT 4
/*
 * If the directory size (from i_size) is greater than the ufs_min_dir_cache
 * tunable then we request dnlc directory caching.
 * This has found to be profitable after 1024 file names.
 */
int ufs_min_dir_cache = 1024 << AV_DIRECT_SHIFT;

/* The time point the dnlc directory caching was disabled */
static hrtime_t ufs_dc_disable_at;
/* directory caching disable duration */
static hrtime_t ufs_dc_disable_duration = (hrtime_t)NANOSEC * 5;

#ifdef DEBUG
int dirchk = 1;
#else /* !DEBUG */
int dirchk = 0;
#endif /* DEBUG */
int ufs_negative_cache = 1;
uint64_t ufs_dirremove_retry_cnt;

static void dirbad();
static int ufs_dirrename();
static int ufs_diraddentry();
static int ufs_dirempty();
static int ufs_dirscan();
static int ufs_dirclrdotdot();
static int ufs_dirfixdotdot();
static int ufs_dirpurgedotdot();
static int dirprepareentry();
static int ufs_dirmakedirect();
static int dirbadname();
static int dirmangled();

/*
 * Check accessibility of directory against inquired mode and type.
 * Execute access is required to search the directory.
 * Access for write is interpreted as allowing
 * deletion of files in the directory.
 * Note, the reader i_contents lock will be acquired in
 * ufs_iaccess().
 */
int
ufs_diraccess(struct inode *ip, int mode, struct cred *cr)
{
	if (((ip->i_mode & IFMT) != IFDIR) &&
	    ((ip->i_mode & IFMT) != IFATTRDIR))
		return (ENOTDIR);

	return (ufs_iaccess(ip, mode, cr, 1));
}

/*
 * Look for a given name in a directory.  On successful return, *ipp
 * will point to the VN_HELD inode.
 * The caller is responsible for checking accessibility upfront
 * via ufs_diraccess().
 */
int
ufs_dirlook(
	struct inode *dp,
	char *namep,
	struct inode **ipp,
	struct cred *cr,
	int skipdnlc,			/* skip the 1st level dnlc */
	int skipcaching)		/* force directory caching off */
{
	uint64_t handle;
	struct fbuf *fbp;		/* a buffer of directory entries */
	struct direct *ep;		/* the current directory entry */
	struct vnode *vp;
	struct vnode *dvp;		/* directory vnode ptr */
	struct ulockfs *ulp;
	dcanchor_t *dcap;
	off_t endsearch;		/* offset to end directory search */
	off_t offset;
	off_t start_off;		/* starting offset from middle search */
	off_t last_offset;		/* last offset */
	int entryoffsetinblock;		/* offset of ep in addr's buffer */
	int numdirpasses;		/* strategy for directory search */
	int namlen;			/* length of name */
	int err;
	int doingchk;
	int i;
	int caching;
	int indeadlock;
	ino_t ep_ino;			/* entry i number */
	ino_t chkino;
	ushort_t ep_reclen;		/* direct local d_reclen */

	ASSERT(*namep != '\0'); /* All callers ensure *namep is non null */

	if (dp->i_ufsvfs)
		ulp = &dp->i_ufsvfs->vfs_ulockfs;

	/*
	 * Check the directory name lookup cache, first for individual files
	 * then for complete directories.
	 */
	dvp = ITOV(dp);
	if (!skipdnlc && (vp = dnlc_lookup(dvp, namep))) {
		/* vp is already held from dnlc_lookup */
		if (vp == DNLC_NO_VNODE) {
			VN_RELE(vp);
			return (ENOENT);
		}
		*ipp = VTOI(vp);
		return (0);
	}

	dcap = &dp->i_danchor;

	/*
	 * Grab the reader lock on the directory data before checking
	 * the dnlc to avoid a race with ufs_dirremove() & friends.
	 *
	 * ufs_tryirwlock uses rw_tryenter and checks for SLOCK to
	 * avoid i_rwlock, ufs_lockfs_begin deadlock. If deadlock
	 * possible, retries the operation.
	 */
	ufs_tryirwlock((&dp->i_rwlock), RW_READER, retry_dircache);
	if (indeadlock)
		return (EAGAIN);

	switch (dnlc_dir_lookup(dcap, namep, &handle)) {
	case DFOUND:
		ep_ino = (ino_t)H_TO_INO(handle);
		if (dp->i_number == ep_ino) {
			VN_HOLD(dvp);	/* want ourself, "." */
			*ipp = dp;
			rw_exit(&dp->i_rwlock);
			return (0);
		}
		if (namep[0] == '.' && namep[1] == '.' && namep[2] == 0) {
			uint64_t handle2;
			/*
			 * release the lock on the dir we are searching
			 * to avoid a deadlock when grabbing the
			 * i_contents lock in ufs_iget_alloced().
			 */
			rw_exit(&dp->i_rwlock);
			rw_enter(&dp->i_ufsvfs->vfs_dqrwlock, RW_READER);
			err = ufs_iget_alloced(dp->i_vfs, ep_ino, ipp, cr);
			rw_exit(&dp->i_ufsvfs->vfs_dqrwlock);
			/*
			 * must recheck as we dropped dp->i_rwlock
			 */
			ufs_tryirwlock(&dp->i_rwlock, RW_READER, retry_parent);
			if (indeadlock) {
				if (!err)
					VN_RELE(ITOV(*ipp));
				return (EAGAIN);
			}
			if (!err && (dnlc_dir_lookup(dcap, namep, &handle2)
			    == DFOUND) && (handle == handle2)) {
				dnlc_update(dvp, namep, ITOV(*ipp));
				rw_exit(&dp->i_rwlock);
				return (0);
			}
			/* check failed, read the actual directory */
			if (!err) {
				VN_RELE(ITOV(*ipp));
			}
			goto restart;
		}
		/* usual case of not "." nor ".." */
		rw_enter(&dp->i_ufsvfs->vfs_dqrwlock, RW_READER);
		err = ufs_iget_alloced(dp->i_vfs, ep_ino, ipp, cr);
		rw_exit(&dp->i_ufsvfs->vfs_dqrwlock);
		if (err) {
			rw_exit(&dp->i_rwlock);
			return (err);
		}
		dnlc_update(dvp, namep, ITOV(*ipp));
		rw_exit(&dp->i_rwlock);
		return (0);
	case DNOENT:
		if (ufs_negative_cache && (dp->i_nlink > 0)) {
			dnlc_enter(dvp, namep, DNLC_NO_VNODE);
		}
		rw_exit(&dp->i_rwlock);
		return (ENOENT);
	default:
		break;
	}
restart:

	fbp = NULL;
	doingchk = 0;
	chkino = 0;
	caching = 0;

	/*
	 * Attempt to cache any directories greater than the tunable
	 * ufs_min_cache_dir. If it fails due to memory shortage (DNOMEM),
	 * disable caching for this directory and record the system time.
	 * Any attempt after the disable time has expired will enable
	 * the caching again.
	 */
	if (!skipcaching && (dp->i_size >= ufs_min_dir_cache)) {
		/*
		 * if the directory caching disable time has expired
		 * enable the caching again.
		 */
		if (dp->i_cachedir == CD_DISABLED_NOMEM &&
		    gethrtime() - ufs_dc_disable_at > ufs_dc_disable_duration) {
			ufs_dc_disable_at = 0;
			dp->i_cachedir = CD_ENABLED;
		}
		if (dp->i_cachedir == CD_ENABLED) {
			switch (dnlc_dir_start(dcap, dp->i_size >>
			    AV_DIRECT_SHIFT)) {
			case DNOMEM:
				dp->i_cachedir = CD_DISABLED_NOMEM;
				ufs_dc_disable_at = gethrtime();
				break;
			case DTOOBIG:
				dp->i_cachedir = CD_DISABLED_TOOBIG;
				break;
			case DOK:
				caching = 1;
				break;
			default:
				break;
			}
		}
	}
	/*
	 * If caching we don't stop when the file has been
	 * found, but need to know later, so clear *ipp now
	 */
	*ipp = NULL;

recheck:
	if (caching) {
		offset = 0;
		entryoffsetinblock = 0;
		numdirpasses = 1;
	} else {
		/*
		 * Take care to look at dp->i_diroff only once, as it
		 * may be changing due to other threads/cpus.
		 */
		offset = dp->i_diroff;
		if (offset > dp->i_size) {
			offset = 0;
		}
		if (offset == 0) {
			entryoffsetinblock = 0;
			numdirpasses = 1;
		} else {
			start_off = offset;

			entryoffsetinblock = blkoff(dp->i_fs, offset);
			if (entryoffsetinblock != 0) {
				err = blkatoff(dp, offset, (char **)0, &fbp);
				if (err)
					goto bad;
			}
			numdirpasses = 2;
		}
	}
	endsearch = P2ROUNDUP_TYPED(dp->i_size, DIRBLKSIZ, u_offset_t);
	namlen = strlen(namep);
	last_offset = 0;

searchloop:
	while (offset < endsearch) {
		/*
		 * If offset is on a block boundary,
		 * read the next directory block.
		 * Release previous if it exists.
		 */
		if (blkoff(dp->i_fs, offset) == 0) {
			if (fbp != NULL) {
				fbrelse(fbp, S_OTHER);
			}
			err = blkatoff(dp, offset, (char **)0, &fbp);
			if (err)
				goto bad;
			entryoffsetinblock = 0;
		}

		/*
		 * If the offset to the next entry is invalid or if the
		 * next entry is a zero length record or if the record
		 * length is invalid, then skip to the next directory
		 * block.  Complete validation checks are done if the
		 * record length is invalid.
		 *
		 * Full validation checks are slow so they are disabled
		 * by default.  Complete checks can be run by patching
		 * "dirchk" to be true.
		 *
		 * We have to check the validity of entryoffsetinblock
		 * here because it can be set to i_diroff above.
		 */
		ep = (struct direct *)(fbp->fb_addr + entryoffsetinblock);
		if ((entryoffsetinblock & 0x3) || ep->d_reclen == 0 ||
		    (dirchk || (ep->d_reclen & 0x3)) &&
		    dirmangled(dp, ep, entryoffsetinblock, offset)) {
			i = DIRBLKSIZ - (entryoffsetinblock & (DIRBLKSIZ - 1));
			offset += i;
			entryoffsetinblock += i;
			if (caching) {
				dnlc_dir_purge(dcap);
				caching = 0;
			}
			continue;
		}

		ep_reclen = ep->d_reclen;

		/*
		 * Add named entries and free space into the directory cache
		 */
		if (caching) {
			ushort_t extra;
			off_t off2;

			if (ep->d_ino == 0) {
				extra = ep_reclen;
				if (offset & (DIRBLKSIZ - 1)) {
					dnlc_dir_purge(dcap);
					dp->i_cachedir = CD_DISABLED;
					caching = 0;
				}
			} else {
				/*
				 * entries hold the previous offset except the
				 * 1st which holds the offset + 1
				 */
				if (offset & (DIRBLKSIZ - 1)) {
					off2 = last_offset;
				} else {
					off2 = offset + 1;
				}
				caching = (dnlc_dir_add_entry(dcap, ep->d_name,
				    INO_OFF_TO_H(ep->d_ino, off2)) == DOK);
				extra = ep_reclen - DIRSIZ(ep);
			}
			if (caching && (extra >= LDIRSIZ(1))) {
				caching = (dnlc_dir_add_space(dcap, extra,
				    (uint64_t)offset) == DOK);
			}
		}

		/*
		 * Check for a name match.
		 * We have the parent inode read locked with i_rwlock.
		 */
		if (ep->d_ino && ep->d_namlen == namlen &&
		    *namep == *ep->d_name &&	/* fast chk 1st chr */
		    bcmp(namep, ep->d_name, (int)ep->d_namlen) == 0) {

			/*
			 * We have to release the fbp early here to avoid
			 * a possible deadlock situation where we have the
			 * fbp and want the directory inode and someone doing
			 * a ufs_direnter_* has the directory inode and wants
			 * the fbp.  XXX - is this still needed?
			 */
			ep_ino = (ino_t)ep->d_ino;
			ASSERT(fbp != NULL);
			fbrelse(fbp, S_OTHER);
			fbp = NULL;

			/*
			 * Atomic update (read lock held)
			 */
			dp->i_diroff = offset;

			if (namlen == 2 && namep[0] == '.' && namep[1] == '.') {
				struct timeval32 omtime;

				if (caching) {
					dnlc_dir_purge(dcap);
					caching = 0;
				}
				if (doingchk) {
					/*
					 * if the inumber didn't change
					 * continue with already found inode.
					 */
					if (ep_ino == chkino)
						goto checkok;
					else {
						VN_RELE(ITOV(*ipp));
						/* *ipp is nulled at restart */
						goto restart;
					}
				}
				/*
				 * release the lock on the dir we are searching
				 * to avoid a deadlock when grabbing the
				 * i_contents lock in ufs_iget_alloced().
				 */
				omtime = dp->i_mtime;
				rw_exit(&dp->i_rwlock);
				rw_enter(&dp->i_ufsvfs->vfs_dqrwlock,
				    RW_READER);
				err = ufs_iget_alloced(dp->i_vfs, ep_ino, ipp,
				    cr);
				rw_exit(&dp->i_ufsvfs->vfs_dqrwlock);
				ufs_tryirwlock(&dp->i_rwlock, RW_READER,
				    retry_disk);
				if (indeadlock) {
					if (!err)
						VN_RELE(ITOV(*ipp));
					return (EAGAIN);
				}
				if (err)
					goto bad;
				/*
				 * Since we released the lock on the directory,
				 * we must check that the same inode is still
				 * the ".." entry for this directory.
				 */
				/*CSTYLED*/
				if (timercmp(&omtime, &dp->i_mtime, !=)) {
					/*
					 * Modification time changed on the
					 * directory, we must go check if
					 * the inumber changed for ".."
					 */
					doingchk = 1;
					chkino = ep_ino;
					entryoffsetinblock = 0;
					if (caching) {
						/*
						 * Forget directory caching
						 * for this rare case
						 */
						dnlc_dir_purge(dcap);
						caching = 0;
					}
					goto recheck;
				}
			} else if (dp->i_number == ep_ino) {
				VN_HOLD(dvp);	/* want ourself, "." */
				*ipp = dp;
				if (caching) {
					dnlc_dir_purge(dcap);
					caching = 0;
				}
			} else {
				rw_enter(&dp->i_ufsvfs->vfs_dqrwlock,
				    RW_READER);
				err = ufs_iget_alloced(dp->i_vfs, ep_ino, ipp,
				    cr);
				rw_exit(&dp->i_ufsvfs->vfs_dqrwlock);
				if (err)
					goto bad;
			}
checkok:
			ASSERT(*ipp);
			dnlc_update(dvp, namep, ITOV(*ipp));
			/*
			 * If we are not caching then just return the entry
			 * otherwise complete loading up the cache
			 */
			if (!caching) {
				rw_exit(&dp->i_rwlock);
				return (0);
			}
			err = blkatoff(dp, offset, (char **)0, &fbp);
			if (err)
				goto bad;
		}
		last_offset = offset;
		offset += ep_reclen;
		entryoffsetinblock += ep_reclen;
	}
	/*
	 * If we started in the middle of the directory and failed
	 * to find our target, we must check the beginning as well.
	 */
	if (numdirpasses == 2) {
		numdirpasses--;
		offset = 0;
		endsearch = start_off;
		goto searchloop;
	}

	/*
	 * If whole directory caching is on (or was originally on) then
	 * the entry may have been found.
	 */
	if (*ipp == NULL) {
		err = ENOENT;
		if (ufs_negative_cache && (dp->i_nlink > 0)) {
			dnlc_enter(dvp, namep, DNLC_NO_VNODE);
		}
	}
	if (caching) {
		dnlc_dir_complete(dcap);
		caching = 0;
	}

bad:
	if (err && *ipp) {
		/*
		 * err and *ipp can both be set if we were attempting to
		 * cache the directory, and we found the entry, then later
		 * while trying to complete the directory cache encountered
		 * a error (eg reading a directory sector).
		 */
		VN_RELE(ITOV(*ipp));
		*ipp = NULL;
	}

	if (fbp)
		fbrelse(fbp, S_OTHER);
	rw_exit(&dp->i_rwlock);
	if (caching)
		dnlc_dir_purge(dcap);
	return (err);
}

/*
 * Write a new directory entry for DE_CREATE or DE_MKDIR operations.
 */
int
ufs_direnter_cm(
	struct inode *tdp,	/* target directory to make entry in */
	char *namep,		/* name of entry */
	enum de_op op,		/* entry operation */
	struct vattr *vap,	/* attributes if new inode needed */
	struct inode **ipp,	/* return entered inode here */
	struct cred *cr,	/* user credentials */
	int flags)		/* no entry exists */
{
	struct inode *tip;	/* inode of (existing) target file */
	char *s;
	struct ufs_slot slot;	/* slot info to pass around */
	int namlen;		/* length of name */
	int err;		/* error number */
	struct inode *nip;	/* new inode */
	int do_rele_nip = 0;	/* release nip */
	int noentry = flags & ~IQUIET;
	int quiet = flags & IQUIET;	/* Suppress out of inodes message */
	int indeadlock;
	struct ulockfs *ulp;

	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));

	if (((tdp->i_mode & IFMT) == IFATTRDIR) && ((op == DE_MKDIR) ||
	    ((vap->va_type == VCHR) || (vap->va_type == VBLK) ||
	    (vap->va_type == VDOOR) || (vap->va_type == VSOCK) ||
	    (vap->va_type == VFIFO))))
		return (EINVAL);

	/* don't allow '/' characters in pathname component */
	for (s = namep, namlen = 0; *s; s++, namlen++)
		if (*s == '/')
			return (EACCES);
	ASSERT(namlen);

	/*
	 * Check accessibility of target directory.
	 */
	if (err = ufs_diraccess(tdp, IEXEC, cr))
		return (err);

	/*
	 * If name is "." or ".." then if this is a create look it up
	 * and return EEXIST.
	 */
	if (namep[0] == '.' &&
	    (namlen == 1 || (namlen == 2 && namep[1] == '.'))) {
		/*
		 * ufs_dirlook will acquire the i_rwlock
		 */
		if (tdp->i_ufsvfs)
			ulp = &tdp->i_ufsvfs->vfs_ulockfs;
		rw_exit(&tdp->i_rwlock);
		if (err = ufs_dirlook(tdp, namep, ipp, cr, 0, 0)) {
			if (err == EAGAIN)
				return (err);

			/*
			 * ufs_tryirwlock uses rw_tryenter and checks for
			 * SLOCK to avoid i_rwlock, ufs_lockfs_begin deadlock.
			 * If deadlock possible, retries the operation.
			 */
			ufs_tryirwlock(&tdp->i_rwlock, RW_WRITER, retry_err);
			if (indeadlock)
				return (EAGAIN);

			return (err);
		}
		ufs_tryirwlock(&tdp->i_rwlock, RW_WRITER, retry);
		if (indeadlock) {
			VN_RELE(ITOV(*ipp));
			return (EAGAIN);
		}
		return (EEXIST);
	}

	/*
	 * If target directory has not been removed, then we can consider
	 * allowing file to be created.
	 */
	if (tdp->i_nlink <= 0) {
		return (ENOENT);
	}

	/*
	 * Search for the entry. Return VN_HELD tip if found.
	 */
	tip = NULL;
	slot.fbp = NULL;
	slot.status = NONE;
	rw_enter(&tdp->i_ufsvfs->vfs_dqrwlock, RW_READER);
	rw_enter(&tdp->i_contents, RW_WRITER);
	err = ufs_dircheckforname(tdp, namep, namlen, &slot, &tip, cr, noentry);
	if (err)
		goto out;
	if (tip) {
		ASSERT(!noentry);
		*ipp = tip;
		err = EEXIST;
	} else {
		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if (err = ufs_iaccess(tdp, IWRITE, cr, 0))
			goto out;
		/*
		 * Make new inode and directory entry.
		 */
		tdp->i_flag |= quiet;
		if (err = ufs_dirmakeinode(tdp, &nip, vap, op, cr)) {
			if (nip != NULL)
				do_rele_nip = 1;
			goto out;
		}
		if (err = ufs_diraddentry(tdp, namep, op,
		    namlen, &slot, nip, NULL, cr)) {
			/*
			 * Unmake the inode we just made.
			 */
			rw_enter(&nip->i_contents, RW_WRITER);
			if (((nip->i_mode & IFMT) == IFDIR) ||
			    ((nip->i_mode & IFMT) == IFATTRDIR)) {
				tdp->i_nlink--;
				ufs_setreclaim(tdp);
				tdp->i_flag |= ICHG;
				tdp->i_seq++;
				TRANS_INODE(tdp->i_ufsvfs, tdp);
				ITIMES_NOLOCK(tdp);
			}
			nip->i_nlink = 0;
			ufs_setreclaim(nip);
			TRANS_INODE(nip->i_ufsvfs, nip);
			nip->i_flag |= ICHG;
			nip->i_seq++;
			ITIMES_NOLOCK(nip);
			rw_exit(&nip->i_contents);
			do_rele_nip = 1;
		} else {
			*ipp = nip;
		}
	}

out:
	if (slot.fbp)
		fbrelse(slot.fbp, S_OTHER);

	tdp->i_flag &= ~quiet;
	rw_exit(&tdp->i_contents);

	/*
	 * Drop vfs_dqrwlock before calling VN_RELE() on nip to
	 * avoid deadlock since ufs_delete() grabs vfs_dqrwlock as reader.
	 */
	rw_exit(&tdp->i_ufsvfs->vfs_dqrwlock);

	if (do_rele_nip) {
		VN_RELE(ITOV(nip));
	}

	return (err);
}

/*
 * Write a new directory entry for DE_LINK, DE_SYMLINK or DE_RENAME operations.
 */
int
ufs_direnter_lr(
	struct inode *tdp,	/* target directory to make entry in */
	char *namep,		/* name of entry */
	enum de_op op,		/* entry operation */
	struct inode *sdp,	/* source inode parent if rename */
	struct inode *sip,	/* source inode */
	struct cred *cr)	/* user credentials */
{
	struct inode *tip;	/* inode of (existing) target file */
	char *s;
	struct ufs_slot slot;	/* slot info to pass around */
	int namlen;		/* length of name */
	int err;		/* error number */

	/* don't allow '/' characters in pathname component */
	for (s = namep, namlen = 0; *s; s++, namlen++)
		if (*s == '/')
			return (EACCES);
	ASSERT(namlen);
	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));

	/*
	 * If name is "." or ".." then if this is a create look it up
	 * and return EEXIST.  Rename or link TO "." or ".." is forbidden.
	 */
	if (namep[0] == '.' &&
	    (namlen == 1 || (namlen == 2 && namep[1] == '.'))) {
		if (op == DE_RENAME) {
			return (EINVAL);	/* *SIGH* should be ENOTEMPTY */
		}
		return (EEXIST);
	}
	/*
	 * For link and rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.  If not, we
	 * increment the link count and force the inode to disk to make sure
	 * that it is there before any directory entry that points to it.
	 *
	 * In the case of a symbolic link, we are dealing with a new inode
	 * which does not yet have any links.  We've created it with a link
	 * count of 1, and we don't want to increment it since this will be
	 * its first link.
	 *
	 * We are about to push the inode to disk. We make sure
	 * that the inode's data blocks are flushed first so the
	 * inode and it's data blocks are always in sync.  This
	 * adds some robustness in in the event of a power failure
	 * or panic where sync fails. If we panic before the
	 * inode is updated, then the inode still refers to the
	 * old data blocks (or none for a new file). If we panic
	 * after the inode is updated, then the inode refers to
	 * the new data blocks.
	 *
	 * We do this before grabbing the i_contents lock because
	 * ufs_syncip() will want that lock. We could do the data
	 * syncing after the removal checks, but upon return from
	 * the data sync we would have to repeat the removal
	 * checks.
	 */
	if (err = TRANS_SYNCIP(sip, 0, I_DSYNC, TOP_FSYNC)) {
		return (err);
	}

	rw_enter(&sip->i_contents, RW_WRITER);
	if (sip->i_nlink <= 0) {
		rw_exit(&sip->i_contents);
		return (ENOENT);
	}
	if (sip->i_nlink == MAXLINK) {
		rw_exit(&sip->i_contents);
		return (EMLINK);
	}

	/*
	 * Sync the indirect blocks associated with the file
	 * for the same reasons as described above.  Since this
	 * call wants the i_contents lock held for it we can do
	 * this here with no extra work.
	 */
	if (err = ufs_sync_indir(sip)) {
		rw_exit(&sip->i_contents);
		return (err);
	}

	if (op != DE_SYMLINK)
		sip->i_nlink++;
	TRANS_INODE(sip->i_ufsvfs, sip);
	sip->i_flag |= ICHG;
	sip->i_seq++;
	ufs_iupdat(sip, I_SYNC);
	rw_exit(&sip->i_contents);

	/*
	 * If target directory has not been removed, then we can consider
	 * allowing file to be created.
	 */
	if (tdp->i_nlink <= 0) {
		err = ENOENT;
		goto out2;
	}

	/*
	 * Check accessibility of target directory.
	 */
	if (err = ufs_diraccess(tdp, IEXEC, cr))
		goto out2;

	/*
	 * Search for the entry. Return VN_HELD tip if found.
	 */
	tip = NULL;
	slot.status = NONE;
	slot.fbp = NULL;
	rw_enter(&tdp->i_ufsvfs->vfs_dqrwlock, RW_READER);
	rw_enter(&tdp->i_contents, RW_WRITER);
	err = ufs_dircheckforname(tdp, namep, namlen, &slot, &tip, cr, 0);
	if (err)
		goto out;

	if (tip) {
		switch (op) {
		case DE_RENAME:
			err = ufs_dirrename(sdp, sip, tdp, namep,
			    tip, &slot, cr);
			break;

		case DE_LINK:
		case DE_SYMLINK:
			/*
			 * Can't link to an existing file.
			 */
			err = EEXIST;
			break;
		default:
			break;
		}
	} else {
		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if (err = ufs_iaccess(tdp, IWRITE, cr, 0))
			goto out;
		err = ufs_diraddentry(tdp, namep, op, namlen, &slot, sip, sdp,
		    cr);
	}

out:
	if (slot.fbp)
		fbrelse(slot.fbp, S_OTHER);

	rw_exit(&tdp->i_contents);

	/*
	 * Drop vfs_dqrwlock before calling VN_RELE() on tip to
	 * avoid deadlock since ufs_delete() grabs vfs_dqrwlock as reader.
	 */
	rw_exit(&tdp->i_ufsvfs->vfs_dqrwlock);

	/*
	 * If we renamed a file over the top of an existing file,
	 * or linked a file to an existing file (or tried to),
	 * then release and delete (or just release) the inode.
	 */
	if (tip)
		VN_RELE(ITOV(tip));

out2:
	if (err) {
		/*
		 * Undo bumped link count.
		 */
		if (op != DE_SYMLINK) {
			rw_enter(&sip->i_contents, RW_WRITER);
			sip->i_nlink--;
			ufs_setreclaim(sip);
			TRANS_INODE(sip->i_ufsvfs, sip);
			sip->i_flag |= ICHG;
			sip->i_seq++;
			ITIMES_NOLOCK(sip);
			rw_exit(&sip->i_contents);
		}
	}
	return (err);
}

/*
 * Check for the existence of a name in a directory (unless noentry
 * is set) , or else of an empty
 * slot in which an entry may be made.  If the requested name is found,
 * then on return *ipp points at the inode and *offp contains
 * its offset in the directory.  If the name is not found, then *ipp
 * will be NULL and *slotp will contain information about a directory slot in
 * which an entry may be made (either an empty slot, or the first position
 * past the end of the directory).
 * The target directory inode (tdp) is supplied write locked (i_rwlock).
 *
 * This may not be used on "." or "..", but aliases of "." are ok.
 */
int
ufs_dircheckforname(
	struct inode *tdp,	/* inode of directory being checked */
	char *namep,		/* name we're checking for */
	int namlen,		/* length of name, excluding null */
	struct ufs_slot *slotp,	/* slot structure */
	struct inode **ipp,	/* return inode if we find one */
	struct cred *cr,
	int noentry)		/* noentry - just look for space */
{
	uint64_t handle;
	struct fbuf *fbp;	/* pointer to directory block */
	struct direct *ep;	/* directory entry */
	struct direct *nep;	/* next directory entry */
	dcanchor_t *dcap;
	vnode_t *dvp;		/* directory vnode ptr */
	off_t dirsize;		/* size of the directory */
	off_t offset;		/* offset in the directory */
	off_t last_offset;	/* last offset */
	off_t enduseful;	/* pointer past last used dir slot */
	int entryoffsetinblk;	/* offset of ep in fbp's buffer */
	int i;			/* length of mangled entry */
	int needed;
	int err;
	int first;
	int caching;
	int stat;
	ino_t ep_ino;
	slotstat_t initstat = slotp->status;

	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&tdp->i_contents));
	ASSERT(*ipp == NULL);
	fbp = NULL;

	/*
	 * First check if there is a complete cache of the directory.
	 */
	dvp = ITOV(tdp);

	dcap = &tdp->i_danchor;
	if (noentry) {
		/*
		 * We know from the 1st level dnlc cache that the entry
		 * doesn't exist, so don't bother searching the directory
		 * cache, but just look for space (possibly in the directory
		 * cache).
		 */
		stat = DNOENT;
	} else {
		stat = dnlc_dir_lookup(dcap, namep, &handle);
	}
	switch (stat) {
	case DFOUND:
		ep_ino = (ino_t)H_TO_INO(handle);
		if (tdp->i_number == ep_ino) {
			*ipp = tdp;	/* we want ourself, ie "." */
			VN_HOLD(dvp);
		} else {
			err = ufs_iget_alloced(tdp->i_vfs, ep_ino, ipp, cr);
			if (err)
				return (err);
		}
		offset = H_TO_OFF(handle);
		first = 0;
		if (offset & 1) {
			/* This is the first entry in the block */
			first = 1;
			offset -= 1;
			ASSERT((offset & (DIRBLKSIZ - 1)) == 0);
		}
		err = blkatoff(tdp, offset, (char **)&ep, &fbp);
		if (err) {
			VN_RELE(ITOV(*ipp));
			*ipp = NULL;
			return (err);
		}
		/*
		 * Check the validity of the entry.
		 * If it's bad, then throw away the cache and
		 * continue without it. The dirmangled() routine
		 * will then be called upon it.
		 */
		if ((ep->d_reclen == 0) || (ep->d_reclen & 0x3)) {
			VN_RELE(ITOV(*ipp));
			*ipp = NULL;
			dnlc_dir_purge(dcap);
			break;
		}
		/*
		 * Remember the returned offset is the offset of the
		 * preceding record (unless this is the 1st record
		 * in the DIRBLKSIZ sized block (disk sector)), then it's
		 * offset + 1. Note, no real offsets are on odd boundaries.
		 */
		if (first) {
			ASSERT((offset & (DIRBLKSIZ - 1)) == 0);
			slotp->offset = offset;
			slotp->size = 0;
			slotp->ep = ep;
		} else {
			/* get the next entry */
			nep = (struct direct *)((char *)ep + ep->d_reclen);
			/*
			 * Check the validity of this entry as well
			 * If it's bad, then throw away the cache and
			 * continue without it. The dirmangled() routine
			 * will then be called upon it.
			 */
			if ((nep->d_reclen == 0) || (nep->d_reclen & 0x3) ||
			    (nep->d_ino != ep_ino)) {
				VN_RELE(ITOV(*ipp));
				*ipp = NULL;
				dnlc_dir_purge(dcap);
				break;
			}
			slotp->offset = offset + ep->d_reclen;
			slotp->size = ep->d_reclen;
			slotp->ep = nep;
		}
		slotp->status = EXIST;
		slotp->fbp = fbp;
		slotp->endoff = 0;
		slotp->cached = 1;
		dnlc_update(dvp, namep, ITOV(*ipp));
		return (0);
	case DNOENT:
		/*
		 * The caller gets to set the initial slot status to
		 * indicate whether it's interested in getting a
		 * empty slot. For example, the status can be set
		 * to FOUND when an entry is being deleted.
		 */
		ASSERT(slotp->fbp == NULL);
		if (slotp->status == FOUND) {
			return (0);
		}
		switch (dnlc_dir_rem_space_by_len(dcap, LDIRSIZ(namlen),
		    &handle)) {
		case DFOUND:
			offset = (off_t)handle;
			err = blkatoff(tdp, offset, (char **)&ep, &fbp);
			if (err) {
				dnlc_dir_purge(dcap);
				ASSERT(*ipp == NULL);
				return (err);
			}
			/*
			 * Check the validity of the entry.
			 * If it's bad, then throw away the cache and
			 * continue without it. The dirmangled() routine
			 * will then be called upon it.
			 */
			if ((ep->d_reclen == 0) || (ep->d_reclen & 0x3)) {
				dnlc_dir_purge(dcap);
				break;
			}
			/*
			 * Remember the returned offset is the offset of the
			 * containing record.
			 */
			slotp->status = FOUND;
			slotp->ep = ep;
			slotp->offset = offset;
			slotp->fbp = fbp;
			slotp->size = ep->d_reclen;
			/*
			 * Set end offset to 0. Truncation is handled
			 * because the dnlc cache will blow away the
			 * cached directory when an entry is removed
			 * that drops the entries left to less than half
			 * the minumum number (dnlc_min_dir_cache).
			 */
			slotp->endoff = 0;
			slotp->cached = 1;
			return (0);
		case DNOENT:
			slotp->status = NONE;
			slotp->offset = P2ROUNDUP_TYPED(tdp->i_size,
			    DIRBLKSIZ, u_offset_t);
			slotp->size = DIRBLKSIZ;
			slotp->endoff = 0;
			slotp->cached = 1;
			return (0);
		default:
			break;
		}
		break;
	}
	slotp->cached = 0;
	caching = NULL;
	if (!noentry && tdp->i_size >= ufs_min_dir_cache) {
		/*
		 * if the directory caching disable time has expired
		 * enable caching again.
		 */
		if (tdp->i_cachedir == CD_DISABLED_NOMEM &&
		    gethrtime() - ufs_dc_disable_at > ufs_dc_disable_duration) {
			ufs_dc_disable_at = 0;
			tdp->i_cachedir = CD_ENABLED;
		}
		/*
		 * Attempt to cache any directories greater than the tunable
		 * ufs_min_cache_dir. If it fails due to memory shortage
		 * (DNOMEM), disable caching for this directory and record
		 * the system time. Any attempt after the disable time has
		 * expired will enable the caching again.
		 */
		if (tdp->i_cachedir == CD_ENABLED) {
			switch (dnlc_dir_start(dcap,
			    tdp->i_size >> AV_DIRECT_SHIFT)) {
			case DNOMEM:
				tdp->i_cachedir = CD_DISABLED_NOMEM;
				ufs_dc_disable_at = gethrtime();
				break;
			case DTOOBIG:
				tdp->i_cachedir = CD_DISABLED_TOOBIG;
				break;
			case DOK:
				caching = 1;
				break;
			default:
				break;
			}
		}
	}

	/*
	 * No point in using i_diroff since we must search whole directory
	 */
	dirsize = P2ROUNDUP_TYPED(tdp->i_size, DIRBLKSIZ, u_offset_t);
	enduseful = 0;
	offset = last_offset = 0;
	entryoffsetinblk = 0;
	needed = (int)LDIRSIZ(namlen);
	while (offset < dirsize) {
		/*
		 * If offset is on a block boundary,
		 * read the next directory block.
		 * Release previous if it exists.
		 */
		if (blkoff(tdp->i_fs, offset) == 0) {
			if (fbp != NULL)
				fbrelse(fbp, S_OTHER);

			err = blkatoff(tdp, offset, (char **)0, &fbp);
			if (err) {
				ASSERT(*ipp == NULL);
				if (caching) {
					dnlc_dir_purge(dcap);
				}
				return (err);
			}
			entryoffsetinblk = 0;
		}
		/*
		 * If still looking for a slot, and at a DIRBLKSIZ
		 * boundary, have to start looking for free space
		 * again.
		 */
		if (slotp->status == NONE &&
		    (entryoffsetinblk & (DIRBLKSIZ - 1)) == 0) {
			slotp->offset = -1;
		}
		/*
		 * If the next entry is a zero length record or if the
		 * record length is invalid, then skip to the next
		 * directory block.  Complete validation checks are
		 * done if the record length is invalid.
		 *
		 * Full validation checks are slow so they are disabled
		 * by default.  Complete checks can be run by patching
		 * "dirchk" to be true.
		 *
		 * We do not have to check the validity of
		 * entryoffsetinblk here because it starts out as zero
		 * and is only incremented by d_reclen values that we
		 * validate here.
		 */
		ep = (struct direct *)(fbp->fb_addr + entryoffsetinblk);
		if (ep->d_reclen == 0 ||
		    (dirchk || (ep->d_reclen & 0x3)) &&
		    dirmangled(tdp, ep, entryoffsetinblk, offset)) {
			i = DIRBLKSIZ - (entryoffsetinblk & (DIRBLKSIZ - 1));
			offset += i;
			entryoffsetinblk += i;
			if (caching) {
				dnlc_dir_purge(dcap);
				caching = 0;
			}
			continue;
		}

		/*
		 * Add named entries and free space into the directory cache
		 */
		if (caching) {
			ushort_t extra;
			off_t off2;

			if (ep->d_ino == 0) {
				extra = ep->d_reclen;
				if (offset & (DIRBLKSIZ - 1)) {
					dnlc_dir_purge(dcap);
					caching = 0;
				}
			} else {
				/*
				 * entries hold the previous offset if
				 * not the 1st one
				 */
				if (offset & (DIRBLKSIZ - 1)) {
					off2 = last_offset;
				} else {
					off2 = offset + 1;
				}
				caching = (dnlc_dir_add_entry(dcap, ep->d_name,
				    INO_OFF_TO_H(ep->d_ino, off2)) == DOK);
				extra = ep->d_reclen - DIRSIZ(ep);
			}
			if (caching && (extra >= LDIRSIZ(1))) {
				caching = (dnlc_dir_add_space(dcap, extra,
				    (uint64_t)offset) == DOK);
			}
		}

		/*
		 * If an appropriate sized slot has not yet been found,
		 * check to see if one is available.
		 */
		if ((slotp->status != FOUND) && (slotp->status != EXIST)) {
			int size = ep->d_reclen;

			if (ep->d_ino != 0)
				size -= DIRSIZ(ep);
			if (size > 0) {
				if (size >= needed) {
					slotp->offset = offset;
					slotp->size = ep->d_reclen;
					if (noentry) {
						slotp->ep = ep;
						slotp->fbp = fbp;
						slotp->status = FOUND;
						slotp->endoff = 0;
						return (0);
					}
					slotp->status = FOUND;
				} else if (slotp->status == NONE) {
					if (slotp->offset == -1)
						slotp->offset = offset;
				}
			}
		}
		/*
		 * Check for a name match.
		 */
		if (ep->d_ino && ep->d_namlen == namlen &&
		    *namep == *ep->d_name &&	/* fast chk 1st char */
		    bcmp(namep, ep->d_name, namlen) == 0) {

			tdp->i_diroff = offset;

			if (tdp->i_number == ep->d_ino) {
				*ipp = tdp;	/* we want ourself, ie "." */
				VN_HOLD(dvp);
			} else {
				err = ufs_iget_alloced(tdp->i_vfs,
				    (ino_t)ep->d_ino, ipp, cr);
				if (err) {
					fbrelse(fbp, S_OTHER);
					if (caching)
						dnlc_dir_purge(dcap);
					return (err);
				}
			}
			slotp->status = EXIST;
			slotp->offset = offset;
			slotp->size = (int)(offset - last_offset);
			slotp->fbp = fbp;
			slotp->ep = ep;
			slotp->endoff = 0;
			if (caching)
				dnlc_dir_purge(dcap);
			return (0);
		}
		last_offset = offset;
		offset += ep->d_reclen;
		entryoffsetinblk += ep->d_reclen;
		if (ep->d_ino)
			enduseful = offset;
	}
	if (fbp) {
		fbrelse(fbp, S_OTHER);
	}

	if (caching) {
		dnlc_dir_complete(dcap);
		slotp->cached = 1;
		if (slotp->status == FOUND) {
			if (initstat == FOUND) {
				return (0);
			}
			(void) dnlc_dir_rem_space_by_handle(dcap,
			    slotp->offset);
			slotp->endoff = 0;
			return (0);
		}
	}

	if (slotp->status == NONE) {
		/*
		 * We didn't find a slot; the new directory entry should be put
		 * at the end of the directory.  Return an indication of where
		 * this is, and set "endoff" to zero; since we're going to have
		 * to extend the directory, we're certainly not going to
		 * truncate it.
		 */
		slotp->offset = dirsize;
		slotp->size = DIRBLKSIZ;
		slotp->endoff = 0;
	} else {
		/*
		 * We found a slot, and will return an indication of where that
		 * slot is, as any new directory entry will be put there.
		 * Since that slot will become a useful entry, if the last
		 * useful entry we found was before this one, update the offset
		 * of the last useful entry.
		 */
		if (enduseful < slotp->offset + slotp->size)
			enduseful = slotp->offset + slotp->size;
		slotp->endoff = P2ROUNDUP_TYPED(enduseful, DIRBLKSIZ, off_t);
	}
	*ipp = NULL;
	return (0);
}

uint64_t ufs_dirrename_retry_cnt;

/*
 * Rename the entry in the directory tdp so that it points to
 * sip instead of tip.
 */
static int
ufs_dirrename(
	struct inode *sdp,	/* parent directory of source */
	struct inode *sip,	/* source inode */
	struct inode *tdp,	/* parent directory of target */
	char *namep,		/* entry we are trying to change */
	struct inode *tip,	/* target inode */
	struct ufs_slot *slotp,	/* slot for entry */
	struct cred *cr)	/* credentials */
{
	vnode_t *tdvp;
	off_t offset;
	int err;
	int doingdirectory;

	ASSERT(sdp->i_ufsvfs != NULL);
	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&tdp->i_contents));
	/*
	 * Short circuit rename of something to itself.
	 */
	if (sip->i_number == tip->i_number) {
		return (ESAME); /* special KLUDGE error code */
	}

	/*
	 * We're locking 2 peer level locks, so must use tryenter
	 * on the 2nd to avoid deadlocks that would occur
	 * if we renamed a->b and b->a concurrently.
	 */
retry:
	rw_enter(&tip->i_contents, RW_WRITER);
	if (!rw_tryenter(&sip->i_contents, RW_READER)) {
		/*
		 * drop tip and wait (sleep) until we stand a chance
		 * of holding sip
		 */
		rw_exit(&tip->i_contents);
		rw_enter(&sip->i_contents, RW_READER);
		/*
		 * Reverse the lock grabs in case we have heavy
		 * contention on the 2nd lock.
		 */
		if (!rw_tryenter(&tip->i_contents, RW_WRITER)) {
			ufs_dirrename_retry_cnt++;
			rw_exit(&sip->i_contents);
			goto retry;
		}
	}

	/*
	 * Check that everything is on the same filesystem.
	 */
	if ((ITOV(tip)->v_vfsp != ITOV(tdp)->v_vfsp) ||
	    (ITOV(tip)->v_vfsp != ITOV(sip)->v_vfsp)) {
		err = EXDEV;		/* XXX archaic */
		goto out;
	}
	/*
	 * Must have write permission to rewrite target entry.
	 * Perform additional checks for sticky directories.
	 */
	if ((err = ufs_iaccess(tdp, IWRITE, cr, 0)) != 0 ||
	    (err = ufs_sticky_remove_access(tdp, tip, cr)) != 0)
		goto out;

	/*
	 * Ensure source and target are compatible (both directories
	 * or both not directories).  If target is a directory it must
	 * be empty and have no links to it; in addition it must not
	 * be a mount point, and both the source and target must be
	 * writable.
	 */
	doingdirectory = (((sip->i_mode & IFMT) == IFDIR) ||
	    ((sip->i_mode & IFMT) == IFATTRDIR));
	if (((tip->i_mode & IFMT) == IFDIR) ||
	    ((tip->i_mode & IFMT) == IFATTRDIR)) {
		if (!doingdirectory) {
			err = EISDIR;
			goto out;
		}
		/*
		 * vn_vfsrlock will prevent mounts from using the directory
		 * until we are done.
		 */
		if (vn_vfsrlock(ITOV(tip))) {
			err = EBUSY;
			goto out;
		}
		if (vn_mountedvfs(ITOV(tip)) != NULL) {
			vn_vfsunlock(ITOV(tip));
			err = EBUSY;
			goto out;
		}
		if (!ufs_dirempty(tip, tdp->i_number, cr) || tip->i_nlink > 2) {
			vn_vfsunlock(ITOV(tip));
			err = EEXIST;	/* SIGH should be ENOTEMPTY */
			goto out;
		}
	} else if (doingdirectory) {
		err = ENOTDIR;
		goto out;
	}

	/*
	 * Rewrite the inode pointer for target name entry
	 * from the target inode (ip) to the source inode (sip).
	 * This prevents the target entry from disappearing
	 * during a crash. Mark the directory inode to reflect the changes.
	 */
	tdvp = ITOV(tdp);
	slotp->ep->d_ino = (int32_t)sip->i_number;
	dnlc_update(tdvp, namep, ITOV(sip));
	if (slotp->size) {
		offset = slotp->offset - slotp->size;
	} else {
		offset = slotp->offset + 1;
	}
	if (slotp->cached) {
		(void) dnlc_dir_update(&tdp->i_danchor, namep,
		    INO_OFF_TO_H(slotp->ep->d_ino, offset));
	}

	err = TRANS_DIR(tdp, slotp->offset);
	if (err)
		fbrelse(slotp->fbp, S_OTHER);
	else
		err = ufs_fbwrite(slotp->fbp, tdp);

	slotp->fbp = NULL;
	if (err) {
		if (doingdirectory)
			vn_vfsunlock(ITOV(tip));
		goto out;
	}

	TRANS_INODE(tdp->i_ufsvfs, tdp);
	tdp->i_flag |= IUPD|ICHG;
	tdp->i_seq++;
	ITIMES_NOLOCK(tdp);

	/*
	 * Decrement the link count of the target inode.
	 * Fix the ".." entry in sip to point to dp.
	 * This is done after the new entry is on the disk.
	 */
	tip->i_nlink--;
	TRANS_INODE(tip->i_ufsvfs, tip);
	tip->i_flag |= ICHG;
	tip->i_seq++;
	ITIMES_NOLOCK(tip);
	if (doingdirectory) {
		/*
		 * The entry for tip no longer exists so I can unlock the
		 * vfslock.
		 */
		vn_vfsunlock(ITOV(tip));
		/*
		 * Decrement target link count once more if it was a directory.
		 */
		if (--tip->i_nlink != 0) {
			err = ufs_fault(ITOV(tip),
		    "ufs_dirrename: target directory link count != 0 (%s)",
			    tip->i_fs->fs_fsmnt);
			rw_exit(&tip->i_contents);
			return (err);
		}
		TRANS_INODE(tip->i_ufsvfs, tip);
		ufs_setreclaim(tip);
		/*
		 * Renaming a directory with the parent different
		 * requires that ".." be rewritten.  The window is
		 * still there for ".." to be inconsistent, but this
		 * is unavoidable, and a lot shorter than when it was
		 * done in a user process.  We decrement the link
		 * count in the new parent as appropriate to reflect
		 * the just-removed target.  If the parent is the
		 * same, this is appropriate since the original
		 * directory is going away.  If the new parent is
		 * different, ufs_dirfixdotdot() will bump the link count
		 * back.
		 */
		tdp->i_nlink--;
		ufs_setreclaim(tdp);
		TRANS_INODE(tdp->i_ufsvfs, tdp);
		tdp->i_flag |= ICHG;
		tdp->i_seq++;
		ITIMES_NOLOCK(tdp);
		if (sdp != tdp) {
			rw_exit(&tip->i_contents);
			rw_exit(&sip->i_contents);
			err = ufs_dirfixdotdot(sip, sdp, tdp);
			return (err);
		}
	} else
		ufs_setreclaim(tip);
out:
	rw_exit(&tip->i_contents);
	rw_exit(&sip->i_contents);
	return (err);
}

/*
 * Fix the ".." entry of the child directory so that it points
 * to the new parent directory instead of the old one.  Routine
 * assumes that dp is a directory and that all the inodes are on
 * the same file system.
 */
static int
ufs_dirfixdotdot(
	struct inode *dp,	/* child directory */
	struct inode *opdp,	/* old parent directory */
	struct inode *npdp)	/* new parent directory */
{
	struct fbuf *fbp;
	struct dirtemplate *dirp;
	vnode_t *dvp;
	int err;

	ASSERT(RW_WRITE_HELD(&npdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&npdp->i_contents));

	/*
	 * We hold the child directory's i_contents lock before calling
	 * blkatoff so that we honor correct locking protocol which is
	 * i_contents lock and then page lock. (blkatoff will call
	 * ufs_getpage where we want the page lock)
	 * We hold the child directory's i_rwlock before i_contents (as
	 * per the locking protocol) since we are modifying the ".." entry
	 * of the child directory.
	 * We hold the i_rwlock and i_contents lock until we record
	 * this directory delta to the log (via ufs_trans_dir) and have
	 * done fbrelse.
	 */
	rw_enter(&dp->i_rwlock, RW_WRITER);
	rw_enter(&dp->i_contents, RW_WRITER);
	err = blkatoff(dp, (off_t)0, (char **)&dirp, &fbp);
	if (err)
		goto bad;

	if (dp->i_nlink <= 0 ||
	    dp->i_size < sizeof (struct dirtemplate)) {
		err = ENOENT;
		goto bad;
	}

	if (dirp->dotdot_namlen != 2 ||
	    dirp->dotdot_name[0] != '.' ||
	    dirp->dotdot_name[1] != '.') {	/* Sanity check. */
		dirbad(dp, "mangled .. entry", (off_t)0);
		err = ENOTDIR;
		goto bad;
	}

	/*
	 * Increment the link count in the new parent inode and force it out.
	 */
	if (npdp->i_nlink == MAXLINK) {
		err = EMLINK;
		goto bad;
	}
	npdp->i_nlink++;
	TRANS_INODE(npdp->i_ufsvfs, npdp);
	npdp->i_flag |= ICHG;
	npdp->i_seq++;
	ufs_iupdat(npdp, I_SYNC);

	/*
	 * Rewrite the child ".." entry and force it out.
	 */
	dvp = ITOV(dp);
	dirp->dotdot_ino = (uint32_t)npdp->i_number;
	dnlc_update(dvp, "..", ITOV(npdp));
	(void) dnlc_dir_update(&dp->i_danchor, "..",
	    INO_OFF_TO_H(dirp->dotdot_ino, 0));

	err = TRANS_DIR(dp, 0);
	if (err)
		fbrelse(fbp, S_OTHER);
	else
		err = ufs_fbwrite(fbp, dp);

	fbp = NULL;
	if (err)
		goto bad;

	rw_exit(&dp->i_contents);
	rw_exit(&dp->i_rwlock);

	/*
	 * Decrement the link count of the old parent inode and force it out.
	 */
	ASSERT(opdp);
	rw_enter(&opdp->i_contents, RW_WRITER);
	ASSERT(opdp->i_nlink > 0);
	opdp->i_nlink--;
	ufs_setreclaim(opdp);
	TRANS_INODE(opdp->i_ufsvfs, opdp);
	opdp->i_flag |= ICHG;
	opdp->i_seq++;
	ufs_iupdat(opdp, I_SYNC);
	rw_exit(&opdp->i_contents);
	return (0);

bad:
	if (fbp)
		fbrelse(fbp, S_OTHER);
	rw_exit(&dp->i_contents);
	rw_exit(&dp->i_rwlock);
	return (err);
}

/*
 * Enter the file sip in the directory tdp with name namep.
 */
static int
ufs_diraddentry(
	struct inode *tdp,
	char *namep,
	enum de_op op,
	int namlen,
	struct ufs_slot *slotp,
	struct inode *sip,
	struct inode *sdp,
	struct cred *cr)
{
	struct direct *ep, *nep;
	vnode_t *tdvp;
	dcanchor_t *dcap = &tdp->i_danchor;
	off_t offset;
	int err;
	ushort_t extra;

	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&tdp->i_contents));
	/*
	 * Prepare a new entry.  If the caller has not supplied an
	 * existing inode, make a new one.
	 */
	err = dirprepareentry(tdp, slotp, cr);
	if (err) {
		if (slotp->fbp) {
			fbrelse(slotp->fbp, S_OTHER);
			slotp->fbp = NULL;
		}
		return (err);
	}
	/*
	 * Check inode to be linked to see if it is in the
	 * same filesystem.
	 */
	if (ITOV(tdp)->v_vfsp != ITOV(sip)->v_vfsp) {
		err = EXDEV;
		goto bad;
	}

	/*
	 * If renaming a directory then fix up the ".." entry in the
	 * directory to point to the new parent.
	 */
	if ((op == DE_RENAME) && (((sip->i_mode & IFMT) == IFDIR) ||
	    ((sip->i_mode & IFMT) == IFATTRDIR)) && (sdp != tdp)) {
		err = ufs_dirfixdotdot(sip, sdp, tdp);
		if (err)
			goto bad;
	}

	/*
	 * Fill in entry data.
	 */
	ep = slotp->ep;
	ep->d_namlen = (ushort_t)namlen;
	(void) strncpy(ep->d_name, namep, (size_t)((namlen + 4) & ~3));
	ep->d_ino = (uint32_t)sip->i_number;
	tdvp = ITOV(tdp);
	dnlc_update(tdvp, namep, ITOV(sip));
	/*
	 * Note the offset supplied for any named entry is
	 * the offset of the previous one, unless it's the 1st.
	 * slotp->size is used to pass the length to
	 * the previous entry.
	 */
	if (slotp->size) {
		offset = slotp->offset - slotp->size;
	} else {
		offset = slotp->offset + 1;
	}

	if (slotp->cached) {
		/*
		 * Add back any usable unused space to the dnlc directory
		 * cache.
		 */
		extra = ep->d_reclen - DIRSIZ(ep);
		if (extra >= LDIRSIZ(1)) {
			(void) dnlc_dir_add_space(dcap, extra,
			    (uint64_t)slotp->offset);
		}

		(void) dnlc_dir_add_entry(dcap, namep,
		    INO_OFF_TO_H(ep->d_ino, offset));

		/* adjust the previous offset of the next entry */
		nep = (struct direct *)((char *)ep + ep->d_reclen);
		if ((uintptr_t)nep & (DIRBLKSIZ - 1)) {
			/*
			 * Not a new block.
			 *
			 * Check the validity of the next entry.
			 * If it's bad, then throw away the cache, and
			 * continue as before directory caching.
			 */
			if ((nep->d_reclen == 0) || (nep->d_reclen & 0x3) ||
			    dnlc_dir_update(dcap, nep->d_name,
			    INO_OFF_TO_H(nep->d_ino, slotp->offset))
			    == DNOENT) {
				dnlc_dir_purge(dcap);
				slotp->cached = 0;
			}
		}
	}

	/*
	 * Write out the directory block.
	 */
	err = TRANS_DIR(tdp, slotp->offset);
	if (err)
		fbrelse(slotp->fbp, S_OTHER);
	else
		err = ufs_fbwrite(slotp->fbp, tdp);

	slotp->fbp = NULL;
	/*
	 * If this is a rename of a directory, then we have already
	 * fixed the ".." entry to refer to the new parent. If err
	 * is true at this point, we have failed to update the new
	 * parent to refer to the renamed directory.
	 * XXX - we need to unwind the ".." fix.
	 */
	if (err)
		return (err);

	/*
	 * Mark the directory inode to reflect the changes.
	 * Truncate the directory to chop off blocks of empty entries.
	 */

	TRANS_INODE(tdp->i_ufsvfs, tdp);
	tdp->i_flag |= IUPD|ICHG;
	tdp->i_seq++;
	tdp->i_diroff = 0;
	ITIMES_NOLOCK(tdp);
	/*
	 * If the directory grew then dirprepareentry() will have
	 * set IATTCHG in tdp->i_flag, then the directory inode must
	 * be flushed out. This is because if fsync() is used later
	 * the directory size must be correct, otherwise a crash would
	 * cause fsck to move the file to lost+found. Also because later
	 * a file may be linked in more than one directory, then there
	 * is no way to flush the original directory. So it must be
	 * flushed out on creation. See bug 4293809.
	 */
	if (tdp->i_flag & IATTCHG) {
		ufs_iupdat(tdp, I_SYNC);
	}

	if (slotp->endoff && (slotp->endoff < tdp->i_size)) {
		if (!TRANS_ISTRANS(tdp->i_ufsvfs)) {
			(void) ufs_itrunc(tdp, (u_offset_t)slotp->endoff, 0,
			    cr);
		}
	}


	return (0);

bad:
	if (slotp->cached) {
		dnlc_dir_purge(dcap);
		fbrelse(slotp->fbp, S_OTHER);
		slotp->cached = 0;
		slotp->fbp = NULL;
		return (err);
	}

	/*
	 * Clear out entry prepared by dirprepareent.
	 */
	slotp->ep->d_ino = 0;
	slotp->ep->d_namlen = 0;

	/*
	 * Don't touch err so we don't clobber the real error that got us here.
	 */
	if (TRANS_DIR(tdp, slotp->offset))
		fbrelse(slotp->fbp, S_OTHER);
	else
		(void) ufs_fbwrite(slotp->fbp, tdp);
	slotp->fbp = NULL;
	return (err);
}

/*
 * Prepare a directory slot to receive an entry.
 */
static int
dirprepareentry(
	struct inode *dp,	/* directory we are working in */
	struct ufs_slot *slotp,	/* available slot info */
	struct cred *cr)
{
	struct direct *ep, *nep;
	off_t entryend;
	int err;
	slotstat_t status = slotp->status;
	ushort_t dsize;

	ASSERT((status == NONE) || (status == FOUND));
	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&dp->i_contents));
	/*
	 * If we didn't find a slot, then indicate that the
	 * new slot belongs at the end of the directory.
	 * If we found a slot, then the new entry can be
	 * put at slotp->offset.
	 */
	entryend = slotp->offset + slotp->size;
	if (status == NONE) {
		ASSERT((slotp->offset & (DIRBLKSIZ - 1)) == 0);
		if (DIRBLKSIZ > dp->i_fs->fs_fsize) {
			err = ufs_fault(ITOV(dp),
			    "dirprepareentry: bad fs_fsize, DIRBLKSIZ: %d"
			    " > dp->i_fs->fs_fsize: %d (%s)",
			    DIRBLKSIZ, dp->i_fs->fs_fsize, dp->i_fs->fs_fsmnt);
			return (err);
		}
		/*
		 * Allocate the new block.
		 */
		err = BMAPALLOC(dp, (u_offset_t)slotp->offset,
		    (int)(blkoff(dp->i_fs, slotp->offset) + DIRBLKSIZ), cr);
		if (err) {
			return (err);
		}
		dp->i_size = entryend;
		TRANS_INODE(dp->i_ufsvfs, dp);
		dp->i_flag |= IUPD|ICHG|IATTCHG;
		dp->i_seq++;
		ITIMES_NOLOCK(dp);
	} else if (entryend > dp->i_size) {
		/*
		 * Adjust directory size, if needed. This should never
		 * push the size past a new multiple of DIRBLKSIZ.
		 * This is an artifact of the old (4.2BSD) way of initializing
		 * directory sizes to be less than DIRBLKSIZ.
		 */
		dp->i_size = P2ROUNDUP_TYPED(entryend, DIRBLKSIZ, off_t);
		TRANS_INODE(dp->i_ufsvfs, dp);
		dp->i_flag |= IUPD|ICHG|IATTCHG;
		dp->i_seq++;
		ITIMES_NOLOCK(dp);
	}

	/*
	 * Get the block containing the space for the new directory entry.
	 */
	if (slotp->fbp == NULL) {
		err = blkatoff(dp, slotp->offset, (char **)&slotp->ep,
		    &slotp->fbp);
		if (err) {
			return (err);
		}
	}
	ep = slotp->ep;

	switch (status) {
	case NONE:
		/*
		 * No space in the directory. slotp->offset will be on a
		 * directory block boundary and we will write the new entry
		 * into a fresh block.
		 */
		ep->d_reclen = DIRBLKSIZ;
		slotp->size = 0; /* length of previous entry */
		break;
	case FOUND:
		/*
		 * An entry of the required size has been found. Use it.
		 */
		if (ep->d_ino == 0) {
			/* this is the 1st record in a block */
			slotp->size = 0; /* length of previous entry */
		} else {
			dsize = DIRSIZ(ep);
			nep = (struct direct *)((char *)ep + dsize);
			nep->d_reclen = ep->d_reclen - dsize;
			ep->d_reclen = dsize;
			slotp->ep = nep;
			slotp->offset += dsize;
			slotp->size = dsize; /* length of previous entry */
		}
		break;
	default:
		break;
	}
	return (0);
}

/*
 * Allocate and initialize a new inode that will go into directory tdp.
 * This routine is called from ufs_symlink(), as well as within this file.
 */
int
ufs_dirmakeinode(
	struct inode *tdp,
	struct inode **ipp,
	struct vattr *vap,
	enum de_op op,
	struct cred *cr)
{
	struct inode *ip;
	enum vtype type;
	int imode;			/* mode and format as in inode */
	ino_t ipref;
	int err;
	timestruc_t now;

	ASSERT(vap != NULL);
	ASSERT(op == DE_CREATE || op == DE_MKDIR || op == DE_ATTRDIR ||
	    op == DE_SYMLINK);
	ASSERT((vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));
	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&tdp->i_contents));
	/*
	 * Allocate a new inode.
	 */
	type = vap->va_type;
	if (type == VDIR) {
		ipref = dirpref(tdp);
	} else {
		ipref = tdp->i_number;
	}
	if (op == DE_ATTRDIR)
		imode = vap->va_mode;
	else
		imode = MAKEIMODE(type, vap->va_mode);
	*ipp = NULL;
	err = ufs_ialloc(tdp, ipref, imode, &ip, cr);
	if (err)
		return (err);

	/*
	 * We don't need to grab vfs_dqrwlock here because it is held
	 * in ufs_direnter_*() above us.
	 */
	ASSERT(RW_READ_HELD(&ip->i_ufsvfs->vfs_dqrwlock));
	rw_enter(&ip->i_contents, RW_WRITER);
	if (ip->i_dquot != NULL) {
		err = ufs_fault(ITOV(ip),
		    "ufs_dirmakeinode, ip->i_dquot != NULL: dquot (%s)",
		    tdp->i_fs->fs_fsmnt);
		rw_exit(&ip->i_contents);
		return (err);
	}
	*ipp = ip;
	ip->i_mode = (o_mode_t)imode;
	if (type == VBLK || type == VCHR) {
		dev_t d = vap->va_rdev;
		dev32_t dev32;

		/*
		 * Don't allow a special file to be created with a
		 * dev_t that cannot be represented by this filesystem
		 * format on disk.
		 */
		if (!cmpldev(&dev32, d)) {
			err = EOVERFLOW;
			goto fail;
		}

		ITOV(ip)->v_rdev = ip->i_rdev = d;

		if (dev32 & ~((O_MAXMAJ << L_BITSMINOR32) | O_MAXMIN)) {
			ip->i_ordev = dev32; /* can't use old format */
		} else {
			ip->i_ordev = cmpdev(d);
		}
	}
	ITOV(ip)->v_type = type;
	ufs_reset_vnode(ip->i_vnode);
	if (type == VDIR) {
		ip->i_nlink = 2; /* anticipating a call to dirmakedirect */
	} else {
		ip->i_nlink = 1;
	}

	if (op == DE_ATTRDIR) {
		ip->i_uid = vap->va_uid;
		ip->i_gid = vap->va_gid;
	} else
		ip->i_uid = crgetuid(cr);
	/*
	 * To determine the group-id of the created file:
	 *   1) If the gid is set in the attribute list (non-Sun & pre-4.0
	 *	clients are not likely to set the gid), then use it if
	 *	the process is privileged, belongs to the target group,
	 *	or the group is the same as the parent directory.
	 *   2) If the filesystem was not mounted with the Old-BSD-compatible
	 *	GRPID option, and the directory's set-gid bit is clear,
	 *	then use the process's gid.
	 *   3) Otherwise, set the group-id to the gid of the parent directory.
	 */
	if (op != DE_ATTRDIR && (vap->va_mask & AT_GID) &&
	    ((vap->va_gid == tdp->i_gid) || groupmember(vap->va_gid, cr) ||
	    secpolicy_vnode_create_gid(cr) == 0)) {
		/*
		 * XXX - is this only the case when a 4.0 NFS client, or a
		 * client derived from that code, makes a call over the wire?
		 */
		ip->i_gid = vap->va_gid;
	} else
		ip->i_gid = (tdp->i_mode & ISGID) ? tdp->i_gid : crgetgid(cr);

	/*
	 * For SunOS 5.0->5.4, the lines below read:
	 *
	 * ip->i_suid = (ip->i_uid > MAXUID) ? UID_LONG : ip->i_uid;
	 * ip->i_sgid = (ip->i_gid > MAXUID) ? GID_LONG : ip->i_gid;
	 *
	 * where MAXUID was set to 60002.  See notes on this in ufs_inode.c
	 */
	ip->i_suid =
	    (ulong_t)ip->i_uid > (ulong_t)USHRT_MAX ? UID_LONG : ip->i_uid;
	ip->i_sgid =
	    (ulong_t)ip->i_gid > (ulong_t)USHRT_MAX ? GID_LONG : ip->i_gid;

	/*
	 * If we're creating a directory, and the parent directory has the
	 * set-GID bit set, set it on the new directory.
	 * Otherwise, if the user is neither privileged nor a member of the
	 * file's new group, clear the file's set-GID bit.
	 */
	if ((tdp->i_mode & ISGID) && (type == VDIR))
		ip->i_mode |= ISGID;
	else {
		if ((ip->i_mode & ISGID) &&
		    secpolicy_vnode_setids_setgids(cr, ip->i_gid) != 0)
			ip->i_mode &= ~ISGID;
	}

	if (((vap->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&vap->va_atime)) ||
	    ((vap->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&vap->va_mtime))) {
		err = EOVERFLOW;
		goto fail;
	}

	/*
	 * Extended attribute directories are not subject to quotas.
	 */
	if (op != DE_ATTRDIR)
		ip->i_dquot = getinoquota(ip);
	else
		ip->i_dquot = NULL;

	if (op == DE_MKDIR || op == DE_ATTRDIR) {
		err = ufs_dirmakedirect(ip, tdp, (op == DE_MKDIR) ? 0 : 1, cr);
		if (err)
			goto fail;
	}

	/*
	 * generate the shadow inode and attach it to the new object
	 */
	ASSERT((tdp->i_shadow && tdp->i_ufs_acl) ||
	    (!tdp->i_shadow && !tdp->i_ufs_acl));
	if (tdp->i_shadow && tdp->i_ufs_acl &&
	    (((tdp->i_mode & IFMT) == IFDIR) ||
	    ((tdp->i_mode & IFMT) == IFATTRDIR))) {
		err = ufs_si_inherit(ip, tdp, ip->i_mode, cr);
		if (err) {
			if (op == DE_MKDIR) {
				/*
				 * clean up parent directory
				 *
				 * tdp->i_contents already locked from
				 * ufs_direnter_*()
				 */
				tdp->i_nlink--;
				TRANS_INODE(tdp->i_ufsvfs, tdp);
				tdp->i_flag |= ICHG;
				tdp->i_seq++;
				ufs_iupdat(tdp, I_SYNC);
			}
			goto fail;
		}
	}

	/*
	 * If the passed in attributes contain atime and/or mtime
	 * settings, then use them instead of using the current
	 * high resolution time.
	 */
	if (vap->va_mask & (AT_MTIME|AT_ATIME)) {
		if (vap->va_mask & AT_ATIME) {
			ip->i_atime.tv_sec = vap->va_atime.tv_sec;
			ip->i_atime.tv_usec = vap->va_atime.tv_nsec / 1000;
			ip->i_flag &= ~IACC;
		} else
			ip->i_flag |= IACC;
		if (vap->va_mask & AT_MTIME) {
			ip->i_mtime.tv_sec = vap->va_mtime.tv_sec;
			ip->i_mtime.tv_usec = vap->va_mtime.tv_nsec / 1000;
			gethrestime(&now);
			if (now.tv_sec > TIME32_MAX) {
				/*
				 * In 2038, ctime sticks forever..
				 */
				ip->i_ctime.tv_sec = TIME32_MAX;
				ip->i_ctime.tv_usec = 0;
			} else {
				ip->i_ctime.tv_sec = now.tv_sec;
				ip->i_ctime.tv_usec = now.tv_nsec / 1000;
			}
			ip->i_flag &= ~(IUPD|ICHG);
			ip->i_flag |= IMODTIME;
		} else
			ip->i_flag |= IUPD|ICHG;
		ip->i_flag |= IMOD;
	} else
		ip->i_flag |= IACC|IUPD|ICHG;
	ip->i_seq++;

	/*
	 * If this is an attribute tag it as one.
	 */
	if ((tdp->i_mode & IFMT) == IFATTRDIR) {
		ip->i_cflags |= IXATTR;
	}

	/*
	 * push inode before it's name appears in a directory
	 */
	TRANS_INODE(ip->i_ufsvfs, ip);
	ufs_iupdat(ip, I_SYNC);
	rw_exit(&ip->i_contents);
	return (0);

fail:
	/* Throw away inode we just allocated. */
	ip->i_nlink = 0;
	ufs_setreclaim(ip);
	TRANS_INODE(ip->i_ufsvfs, ip);
	ip->i_flag |= ICHG;
	ip->i_seq++;
	ITIMES_NOLOCK(ip);
	rw_exit(&ip->i_contents);
	return (err);
}

/*
 * Write a prototype directory into the empty inode ip, whose parent is dp.
 */
static int
ufs_dirmakedirect(
	struct inode *ip,		/* new directory */
	struct inode *dp,		/* parent directory */
	int	attrdir,
	struct cred *cr)
{
	struct dirtemplate *dirp;
	struct fbuf *fbp;
	int err;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&dp->i_contents));
	/*
	 * Allocate space for the directory we're creating.
	 */
	err = BMAPALLOC(ip, (u_offset_t)0, DIRBLKSIZ, cr);
	if (err)
		return (err);
	if (DIRBLKSIZ > dp->i_fs->fs_fsize) {
		err = ufs_fault(ITOV(dp),
"ufs_dirmakedirect: bad fs_fsize, DIRBLKSIZ: %d > dp->i_fs->fs_fsize: %d (%s)",
		    DIRBLKSIZ, dp->i_fs->fs_fsize,
		    dp->i_fs->fs_fsmnt);
		return (err);
	}
	ip->i_size = DIRBLKSIZ;
	TRANS_INODE(ip->i_ufsvfs, ip);
	ip->i_flag |= IUPD|ICHG|IATTCHG;
	ip->i_seq++;
	ITIMES_NOLOCK(ip);
	/*
	 * Update the tdp link count and write out the change.
	 * This reflects the ".." entry we'll soon write.
	 */
	if (dp->i_nlink == MAXLINK)
		return (EMLINK);
	if (attrdir == 0)
		dp->i_nlink++;
	TRANS_INODE(dp->i_ufsvfs, dp);
	dp->i_flag |= ICHG;
	dp->i_seq++;
	ufs_iupdat(dp, I_SYNC);
	/*
	 * Initialize directory with "."
	 * and ".." from static template.
	 *
	 * Since the parent directory is locked, we don't have to
	 * worry about anything changing when we drop the write
	 * lock on (ip).
	 *
	 */
	err = fbread(ITOV(ip), (offset_t)0, (uint_t)ip->i_fs->fs_fsize,
	    S_READ, &fbp);

	if (err) {
		goto fail;
	}
	dirp = (struct dirtemplate *)fbp->fb_addr;
	/*
	 * Now initialize the directory we're creating
	 * with the "." and ".." entries.
	 */
	*dirp = mastertemplate;			/* structure assignment */
	dirp->dot_ino = (uint32_t)ip->i_number;
	dirp->dotdot_ino = (uint32_t)dp->i_number;

	err = TRANS_DIR(ip, 0);
	if (err) {
		fbrelse(fbp, S_OTHER);
		goto fail;
	}

	err = ufs_fbwrite(fbp, ip);
	if (err) {
		goto fail;
	}

	return (0);

fail:
	if (attrdir == 0)
		dp->i_nlink--;
	TRANS_INODE(dp->i_ufsvfs, dp);
	dp->i_flag |= ICHG;
	dp->i_seq++;
	ufs_iupdat(dp, I_SYNC);
	return (err);
}

/*
 * Delete a directory entry.  If oip is nonzero the entry is checked
 * to make sure it still reflects oip.
 */
int
ufs_dirremove(
	struct inode *dp,
	char *namep,
	struct inode *oip,
	struct vnode *cdir,
	enum dr_op op,
	struct cred *cr)
{
	struct direct *ep, *pep, *nep;
	struct inode *ip;
	vnode_t *dvp, *vp;
	struct ufs_slot slot;
	int namlen;
	int err;
	int mode;
	ushort_t extra;

	namlen = (int)strlen(namep);
	if (namlen == 0) {
		struct fs	*fs = dp->i_fs;

		cmn_err(CE_WARN, "%s: ufs_dirremove: attempted to remove"
		    " nameless file in directory (directory inode %llu)",
		    fs->fs_fsmnt, (u_longlong_t)dp->i_number);
		ASSERT(namlen != 0);

		return (ENOENT);
	}

	/*
	 * return error when removing . and ..
	 */
	if (namep[0] == '.') {
		if (namlen == 1)
			return (EINVAL);
		else if (namlen == 2 && namep[1] == '.') {
			return (EEXIST);	/* SIGH should be ENOTEMPTY */
		}
	}

	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));

retry:
	/*
	 * Check accessibility of directory.
	 */
	if (err = ufs_diraccess(dp, IEXEC|IWRITE, cr))
		return (err);

	ip = NULL;
	slot.fbp = NULL;
	slot.status = FOUND;	/* don't need to look for empty slot */
	rw_enter(&dp->i_ufsvfs->vfs_dqrwlock, RW_READER);
	rw_enter(&dp->i_contents, RW_WRITER);

	err = ufs_dircheckforname(dp, namep, namlen, &slot, &ip, cr, 0);
	if (err)
		goto out_novfs;
	if (ip == NULL) {
		err = ENOENT;
		goto out_novfs;
	}
	vp = ITOV(ip);
	if (oip && oip != ip) {
		err = ENOENT;
		goto out_novfs;
	}

	mode = ip->i_mode & IFMT;
	if (mode == IFDIR || mode == IFATTRDIR) {

		/*
		 * vn_vfsrlock() prevents races between mount and rmdir.
		 */
		if (vn_vfsrlock(vp)) {
			err = EBUSY;
			goto out_novfs;
		}
		if (vn_mountedvfs(vp) != NULL && op != DR_RENAME) {
			err = EBUSY;
			goto out;
		}
		/*
		 * If we are removing a directory, get a lock on it.
		 * Taking a writer lock prevents a parallel ufs_dirlook from
		 * incorrectly entering a negative cache vnode entry in the dnlc
		 * If the directory is empty, it will stay empty until
		 * we can remove it.
		 */
		if (!rw_tryenter(&ip->i_rwlock, RW_WRITER)) {
			/*
			 * It is possible that a thread in rename would have
			 * acquired this rwlock. To prevent a deadlock we
			 * do a rw_tryenter. If we fail to get the lock
			 * we drop all the locks we have acquired, wait
			 * for 2 ticks and reacquire the
			 * directory's (dp) i_rwlock and try again.
			 * If we dont drop dp's i_rwlock then we will panic
			 * with a "Deadlock: cycle in blocking chain"
			 * since in ufs_dircheckpath we want dp's i_rwlock.
			 * dp is guaranteed to exist since ufs_dirremove is
			 * called after a VN_HOLD(dp) has been done.
			 */
			ufs_dirremove_retry_cnt++;
			vn_vfsunlock(vp);
			if (slot.fbp)
				fbrelse(slot.fbp, S_OTHER);
			rw_exit(&dp->i_contents);
			rw_exit(&dp->i_ufsvfs->vfs_dqrwlock);
			rw_exit(&dp->i_rwlock);
			VN_RELE(vp);
			delay(2);
			rw_enter(&dp->i_rwlock, RW_WRITER);
			goto retry;
		}
	}
	rw_enter(&ip->i_contents, RW_READER);

	/*
	 * Now check the restrictions that apply on sticky directories.
	 */
	if ((err = ufs_sticky_remove_access(dp, ip, cr)) != 0) {
		rw_exit(&ip->i_contents);
		if (mode == IFDIR || mode == IFATTRDIR)
			rw_exit(&ip->i_rwlock);
		goto out;
	}

	if (op == DR_RMDIR) {
		/*
		 * For rmdir(2), some special checks are required.
		 * (a) Don't remove any alias of the parent (e.g. ".").
		 * (b) Don't remove the current directory.
		 * (c) Make sure the entry is (still) a directory.
		 * (d) Make sure the directory is empty.
		 */

		if (dp == ip || vp == cdir)
			err = EINVAL;
		else if (((ip->i_mode & IFMT) != IFDIR) &&
		    ((ip->i_mode & IFMT) != IFATTRDIR))
			err = ENOTDIR;
		else if ((ip->i_nlink > 2) ||
		    !ufs_dirempty(ip, dp->i_number, cr)) {
			err = EEXIST;	/* SIGH should be ENOTEMPTY */
		}

		if (err) {
			rw_exit(&ip->i_contents);
			if (mode == IFDIR || mode == IFATTRDIR)
				rw_exit(&ip->i_rwlock);
			goto out;
		}
	} else if (op == DR_REMOVE)  {
		/*
		 * unlink(2) requires a different check: allow only
		 * privileged users to unlink a directory.
		 */
		if (vp->v_type == VDIR &&
		    secpolicy_fs_linkdir(cr, vp->v_vfsp)) {
			err = EPERM;
			rw_exit(&ip->i_contents);
			rw_exit(&ip->i_rwlock);
			goto out;
		}
	}

	rw_exit(&ip->i_contents);

	/*
	 * Remove the cache'd entry, if any.
	 */
	dvp = ITOV(dp);
	dnlc_remove(dvp, namep);
	ep = slot.ep;
	ep->d_ino = 0;

	if (slot.cached) {
		dcanchor_t *dcap = &dp->i_danchor;

		(void) dnlc_dir_rem_entry(dcap, namep, NULL);
		if (((int)ep->d_reclen - (int)DIRSIZ(ep)) >= LDIRSIZ(1)) {
			(void) dnlc_dir_rem_space_by_handle(dcap, slot.offset);
		}
		if (slot.offset & (DIRBLKSIZ - 1)) {
			/*
			 * Collapse new free space into previous entry.
			 * Note, the previous entry has already been
			 * validated in ufs_dircheckforname().
			 */
			ASSERT(slot.size);
			pep = (struct direct *)((char *)ep - slot.size);
			if ((pep->d_ino == 0) &&
			    ((uintptr_t)pep & (DIRBLKSIZ - 1))) {
				dnlc_dir_purge(dcap);
				slot.cached = 0;
				goto nocache;
			}
			if (pep->d_ino) {
				extra = pep->d_reclen - DIRSIZ(pep);
			} else {
				extra = pep->d_reclen;
			}
			if (extra >= LDIRSIZ(1)) {
				(void) dnlc_dir_rem_space_by_handle(dcap,
				    (uint64_t)(slot.offset - slot.size));
			}
			pep->d_reclen += ep->d_reclen;
			(void) dnlc_dir_add_space(dcap, extra + ep->d_reclen,
			    (uint64_t)(slot.offset - slot.size));
			/* adjust the previous pointer in the next entry */
			nep = (struct direct *)((char *)ep + ep->d_reclen);
			if ((uintptr_t)nep & (DIRBLKSIZ - 1)) {
				/*
				 * Not a new block.
				 *
				 * Check the validity of the entry.
				 * If it's bad, then throw away the cache and
				 * continue.
				 */
				if ((nep->d_reclen == 0) ||
				    (nep->d_reclen & 0x3) ||
				    (dnlc_dir_update(dcap, nep->d_name,
				    INO_OFF_TO_H(nep->d_ino,
				    slot.offset - slot.size)) == DNOENT)) {
					dnlc_dir_purge(dcap);
					slot.cached = 0;
				}
			}
		} else {
			(void) dnlc_dir_add_space(dcap, ep->d_reclen,
			    (uint64_t)slot.offset);
		}
	} else {
		/*
		 * If the entry isn't the first in the directory, we must
		 * reclaim the space of the now empty record by adding
		 * the record size to the size of the previous entry.
		 */
		if (slot.offset & (DIRBLKSIZ - 1)) {
			/*
			 * Collapse new free space into previous entry.
			 */
			pep = (struct direct *)((char *)ep - slot.size);
			pep->d_reclen += ep->d_reclen;
		}
	}
nocache:


	err = TRANS_DIR(dp, slot.offset);
	if (err)
		fbrelse(slot.fbp, S_OTHER);
	else
		err = ufs_fbwrite(slot.fbp, dp);
	slot.fbp = NULL;

	/*
	 * If we were removing a directory, it is 'gone' now, but we cannot
	 * unlock it as a thread may be waiting for the lock in ufs_create. If
	 * we did, it could then create a file in a deleted directory.
	 */

	if (err) {
		if (mode == IFDIR || mode == IFATTRDIR)
			rw_exit(&ip->i_rwlock);
		goto out;
	}

	rw_enter(&ip->i_contents, RW_WRITER);

	dp->i_flag |= IUPD|ICHG;
	dp->i_seq++;
	ip->i_flag |= ICHG;
	ip->i_seq++;

	TRANS_INODE(dp->i_ufsvfs, dp);
	TRANS_INODE(ip->i_ufsvfs, ip);
	/*
	 * Now dispose of the inode.
	 */
	if (ip->i_nlink > 0) {
		/*
		 * This is not done for IFATTRDIR's because they don't
		 * have entries in the dnlc and the link counts are
		 * not incremented when they are created.
		 */
		if (op == DR_RMDIR && (ip->i_mode & IFMT) == IFDIR) {
			/*
			 * Decrement by 2 because we're trashing the "."
			 * entry as well as removing the entry in dp.
			 * Clear the directory entry, but there may be
			 * other hard links so don't free the inode.
			 * Decrement the dp linkcount because we're
			 * trashing the ".." entry.
			 */
			ip->i_nlink -= 2;
			dp->i_nlink--;
			ufs_setreclaim(dp);
			/*
			 * XXX need to discard negative cache entries
			 * for vp.  See comment in ufs_delete().
			 */
			dnlc_remove(vp, ".");
			dnlc_remove(vp, "..");
			/*
			 * The return value is ignored here bacause if
			 * the directory purge fails we don't want to
			 * stop the delete. If ufs_dirpurgedotdot fails
			 * the delete will continue with the preexiting
			 * behavior.
			 */
			(void) ufs_dirpurgedotdot(ip, dp->i_number, cr);
		} else {
			ip->i_nlink--;
		}
		ufs_setreclaim(ip);
	}
	ITIMES_NOLOCK(dp);
	ITIMES_NOLOCK(ip);

	if (!TRANS_ISTRANS(dp->i_ufsvfs))
		ufs_iupdat(dp, I_SYNC);
	if (!TRANS_ISTRANS(ip->i_ufsvfs))
		ufs_iupdat(ip, I_SYNC);

	rw_exit(&ip->i_contents);
	if (mode == IFDIR || mode == IFATTRDIR)
		rw_exit(&ip->i_rwlock);
out:
	if (mode == IFDIR || mode == IFATTRDIR) {
		vn_vfsunlock(vp);
	}
out_novfs:
	ASSERT(RW_WRITE_HELD(&dp->i_contents));

	if (slot.fbp)
		fbrelse(slot.fbp, S_OTHER);

	rw_exit(&dp->i_contents);
	rw_exit(&dp->i_ufsvfs->vfs_dqrwlock);

	/*
	 * Release (and delete) the inode after we drop vfs_dqrwlock to
	 * avoid deadlock since ufs_delete() grabs vfs_dqrwlock as reader.
	 */
	if (ip)
		VN_RELE(vp);

	return (err);
}

/*
 * Return buffer with contents of block "offset"
 * from the beginning of directory "ip".  If "res"
 * is non-zero, fill it in with a pointer to the
 * remaining space in the directory.
 *
 */

int
blkatoff(
	struct inode *ip,
	off_t offset,
	char **res,
	struct fbuf **fbpp)
{
	struct fs *fs;
	struct fbuf *fbp;
	daddr_t lbn;
	uint_t bsize;
	int err;

	CPU_STATS_ADD_K(sys, ufsdirblk, 1);
	fs = ip->i_fs;
	lbn = (daddr_t)lblkno(fs, offset);
	bsize = (uint_t)blksize(fs, ip, lbn);
	err = fbread(ITOV(ip), (offset_t)(offset & fs->fs_bmask),
	    bsize, S_READ, &fbp);
	if (err) {
		*fbpp = (struct fbuf *)NULL;
		return (err);
	}
	if (res)
		*res = fbp->fb_addr + blkoff(fs, offset);
	*fbpp = fbp;
	return (0);
}

/*
 * Do consistency checking:
 *	record length must be multiple of 4
 *	entry must fit in rest of its DIRBLKSIZ block
 *	record must be large enough to contain entry
 *	name is not longer than MAXNAMLEN
 *	name must be as long as advertised, and null terminated
 * NOTE: record length must not be zero (should be checked previously).
 *       This routine is only called if dirchk is true.
 *       It would be nice to set the FSBAD flag in the super-block when
 *       this routine fails so that a fsck is forced on next reboot,
 *       but locking is a problem.
 */
static int
dirmangled(
	struct inode *dp,
	struct direct *ep,
	int entryoffsetinblock,
	off_t offset)
{
	int i;

	i = DIRBLKSIZ - (entryoffsetinblock & (DIRBLKSIZ - 1));
	if ((ep->d_reclen & 0x3) != 0 || (int)ep->d_reclen > i ||
	    (uint_t)ep->d_reclen < DIRSIZ(ep) || ep->d_namlen > MAXNAMLEN ||
	    ep->d_ino && dirbadname(ep->d_name, (int)ep->d_namlen)) {
		dirbad(dp, "mangled entry", offset);
		return (1);
	}
	return (0);
}

static void
dirbad(struct inode *ip, char *how, off_t offset)
{
	cmn_err(CE_NOTE, "%s: bad dir ino %d at offset %ld: %s",
	    ip->i_fs->fs_fsmnt, (int)ip->i_number, offset, how);
}

static int
dirbadname(char *sp, int l)
{
	while (l--) {			/* check for nulls */
		if (*sp++ == '\0') {
			return (1);
		}
	}
	return (*sp);			/* check for terminating null */
}

/*
 * Check if a directory is empty or not.
 */
static int
ufs_dirempty(
	struct inode *ip,
	ino_t parentino,
	struct cred *cr)
{
	return (ufs_dirscan(ip, parentino, cr, 0));
}

/*
 * clear the .. directory entry.
 */
static int
ufs_dirpurgedotdot(
	struct inode *ip,
	ino_t parentino,
	struct cred *cr)
{
	return (ufs_dirscan(ip, parentino, cr, 1));
}

/*
 * Scan the directoy. If clr_dotdot is true clear the ..
 * directory else check to see if the directory is empty.
 *
 * Using a struct dirtemplate here is not precisely
 * what we want, but better than using a struct direct.
 *
 * clr_dotdot is used as a flag to tell us if we need
 * to clear the dotdot entry
 *
 * N.B.: does not handle corrupted directories.
 */
static int
ufs_dirscan(
	struct inode *ip,
	ino_t parentino,
	struct cred *cr,
	int clr_dotdot)
{
	offset_t off;
	struct dirtemplate dbuf;
	struct direct *dp = (struct direct *)&dbuf;
	int err, count;
	int empty = 1;	/* Assume it's empty */
#define	MINDIRSIZ (sizeof (struct dirtemplate) / 2)

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	ASSERT(ip->i_size <= (offset_t)MAXOFF_T);
	for (off = 0; off < ip->i_size; off += dp->d_reclen) {
		err = ufs_rdwri(UIO_READ, FREAD, ip, (caddr_t)dp,
		    (ssize_t)MINDIRSIZ, off, UIO_SYSSPACE, &count, cr);
		/*
		 * Since we read MINDIRSIZ, residual must
		 * be 0 unless we're at end of file.
		 */
		if (err || count != 0 || dp->d_reclen == 0) {
			empty = 0;
			break;
		}
		/* skip empty entries */
		if (dp->d_ino == 0)
			continue;
		/* accept only "." and ".." */
		if (dp->d_namlen > 2 || dp->d_name[0] != '.') {
			empty = 0;
			break;
		}
		/*
		 * At this point d_namlen must be 1 or 2.
		 * 1 implies ".", 2 implies ".." if second
		 * char is also "."
		 */
		if (dp->d_namlen == 1)
			continue;
		if (dp->d_name[1] == '.' &&
		    (ino_t)dp->d_ino == parentino) {
			/*
			 * If we're doing a purge we need to check for
			 * the . and .. entries and clear the d_ino for ..
			 *
			 * if clr_dotdot is set ufs_dirscan does not
			 * check for an empty directory.
			 */
			if (clr_dotdot) {
				/*
				 * Have to actually zap the ..
				 * entry in the directory, as
				 * otherwise someone might have
				 * dp as its cwd and try to
				 * open .., which now points to
				 * an unallocated inode.
				 */
				empty = ufs_dirclrdotdot(ip, parentino);
				break;
			} else {
				continue;
			}
		}
		empty = 0;
		break;
	}
	return (empty);
}

clock_t retry_backoff_delay = 1; /* delay before retrying the i_rwlock */
uint64_t dircheck_retry_cnt;
/*
 * Check if source directory inode is in the path of the target directory.
 * Target is supplied locked.
 *
 * The source and target inode's should be different upon entry.
 */
int
ufs_dircheckpath(
	ino_t source_ino,
	struct inode *target,
	struct inode *sdp,
	struct cred *cr)
{
	struct fbuf *fbp;
	struct dirtemplate *dirp;
	struct inode *ip;
	struct ufsvfs *ufsvfsp;
	struct inode *tip;
	ino_t dotdotino;
	int err;

	ASSERT(target->i_ufsvfs != NULL);
	ASSERT(RW_LOCK_HELD(&target->i_rwlock));
	ASSERT(RW_LOCK_HELD(&sdp->i_rwlock));

	ip = target;
	if (ip->i_number == source_ino) {
		err = EINVAL;
		goto out;
	}
	if (ip->i_number == UFSROOTINO) {
		err = 0;
		goto out;
	}
	/*
	 * Search back through the directory tree, using the ".." entries.
	 * Fail any attempt to move a directory into an ancestor directory.
	 */
	fbp = NULL;
	for (;;) {
		struct vfs	*vfs;

		err = blkatoff(ip, (off_t)0, (char **)&dirp, &fbp);
		if (err)
			break;
		if (((ip->i_mode & IFMT) != IFDIR) || ip->i_nlink == 0 ||
		    ip->i_size < sizeof (struct dirtemplate)) {
			dirbad(ip, "bad size, unlinked or not dir", (off_t)0);
			err = ENOTDIR;
			break;
		}
		if (dirp->dotdot_namlen != 2 ||
		    dirp->dotdot_name[0] != '.' ||
		    dirp->dotdot_name[1] != '.') {
			dirbad(ip, "mangled .. entry", (off_t)0);
			err = ENOTDIR;		/* Sanity check */
			break;
		}
		dotdotino = (ino_t)dirp->dotdot_ino;
		if (dotdotino == source_ino) {
			err = EINVAL;
			break;
		}
		if (dotdotino == UFSROOTINO)
			break;
		if (fbp) {
			fbrelse(fbp, S_OTHER);
			fbp = NULL;
		}
		vfs = ip->i_vfs;
		ufsvfsp = ip->i_ufsvfs;

		if (ip != target) {
			rw_exit(&ip->i_rwlock);
			VN_RELE(ITOV(ip));
		}
		/*
		 * Race to get the inode.
		 */
		rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
		if (err = ufs_iget_alloced(vfs, dotdotino, &tip, cr)) {
			rw_exit(&ufsvfsp->vfs_dqrwlock);
			ip = NULL;
			break;
		}
		rw_exit(&ufsvfsp->vfs_dqrwlock);
		/*
		 * If the directory of the source inode (also a directory)
		 * is the same as this next entry up the chain, then
		 * we know the source directory itself can't be in the
		 * chain. This also prevents a panic because we already
		 * have sdp->i_rwlock locked.
		 */
		if (tip == sdp) {
			VN_RELE(ITOV(tip));
			ip = NULL;
			break;
		}
		ip = tip;

		/*
		 * If someone has set the WRITE_WANTED bit in this lock and if
		 * this happens to be a sdp or tdp of another parallel rename
		 * which is executing  the same code and in similar situation
		 * we end up in a 4 way deadlock. We need to make sure that
		 * the WRITE_WANTED bit is not  set.
		 */
retry_lock:
		if (!rw_tryenter(&ip->i_rwlock, RW_READER)) {
			/*
			 * If the lock held as WRITER thats fine but if it
			 * has WRITE_WANTED bit set we might end up in a
			 * deadlock. If WRITE_WANTED is set we return
			 * with EAGAIN else we just go back and try.
			 */
			if (RW_ISWRITER(&ip->i_rwlock) &&
			    !(RW_WRITE_HELD(&ip->i_rwlock))) {
				err = EAGAIN;
				if (fbp) {
					fbrelse(fbp, S_OTHER);
				}
				VN_RELE(ITOV(ip));
				return (err);
			} else {
				/*
				 * The lock is being write held. We could
				 * just do a rw_enter here but there is a
				 * window between the check and now, where
				 * the status could have changed, so to
				 * avoid looping we backoff and go back to
				 * try for the lock.
				 */
				delay(retry_backoff_delay);
				dircheck_retry_cnt++;
				goto retry_lock;
			}
		}
	}
	if (fbp) {
		fbrelse(fbp, S_OTHER);
	}
out:
	if (ip) {
		if (ip != target) {
			rw_exit(&ip->i_rwlock);
			VN_RELE(ITOV(ip));
		}
	}
	return (err);
}

int
ufs_xattrdirempty(struct inode *ip, ino_t parentino, struct cred *cr)
{
	offset_t off;
	struct dirtemplate dbuf;
	struct direct *dp = (struct direct *)&dbuf;
	int err, count;
	int empty = 1;	/* Assume it's empty */
#define	MINDIRSIZ (sizeof (struct dirtemplate) / 2)

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	ASSERT(ip->i_size <= (offset_t)MAXOFF_T);
	for (off = 0; off < ip->i_size; off += dp->d_reclen) {
		err = ufs_rdwri(UIO_READ, FREAD, ip, (caddr_t)dp,
		    (ssize_t)MINDIRSIZ, off, UIO_SYSSPACE, &count, cr);
		/*
		 * Since we read MINDIRSIZ, residual must
		 * be 0 unless we're at end of file.
		 */

		if (err || count != 0 || dp->d_reclen == 0) {
			empty = 0;
			break;
		}
		/* skip empty entries */
		if (dp->d_ino == 0)
			continue;
		/*
		 * At this point d_namlen must be 1 or 2.
		 * 1 implies ".", 2 implies ".." if second
		 * char is also "."
		 */

		if (dp->d_namlen == 1 && dp->d_name[0] == '.' &&
		    (ino_t)dp->d_ino == parentino)
			continue;

		if (dp->d_namlen == 2 && dp->d_name[0] == '.' &&
		    dp->d_name[1] == '.') {
			continue;
		}
		empty = 0;
		break;
	}
	return (empty);
}


/*
 * Allocate and initialize a new shadow inode to contain extended attributes.
 */
int
ufs_xattrmkdir(
	struct inode *tdp,
	struct inode **ipp,
	int flags,
	struct cred *cr)
{
	struct inode *ip;
	struct vattr va;
	int err;
	int retry = 1;
	struct ufsvfs *ufsvfsp;
	struct ulockfs *ulp;
	int issync;
	int trans_size;
	int dorwlock;		/* 0 = not yet taken, */
				/* 1 = taken outside the transaction, */
				/* 2 = taken inside the transaction */

	/*
	 * Validate permission to create attribute directory
	 */

	if ((err = ufs_iaccess(tdp, IWRITE, cr, 1)) != 0) {
		return (err);
	}

	if (vn_is_readonly(ITOV(tdp)))
		return (EROFS);

	/*
	 * No need to re-init err after again:, since it's set before
	 * the next use of it.
	 */
again:
	dorwlock = 0;
	va.va_type = VDIR;
	va.va_uid = tdp->i_uid;
	va.va_gid = tdp->i_gid;

	if ((tdp->i_mode & IFMT) == IFDIR) {
		va.va_mode = (o_mode_t)IFATTRDIR;
		va.va_mode |= tdp->i_mode & 0777;
	} else {
		va.va_mode = (o_mode_t)IFATTRDIR|0700;
		if (tdp->i_mode & 0040)
			va.va_mode |= 0750;
		if (tdp->i_mode & 0004)
			va.va_mode |= 0705;
	}
	va.va_mask = AT_TYPE|AT_MODE;

	ufsvfsp = tdp->i_ufsvfs;

	err = ufs_lockfs_begin(ufsvfsp, &ulp, ULOCKFS_MKDIR_MASK);
	if (err)
		return (err);

	/*
	 * Acquire i_rwlock before TRANS_BEGIN_CSYNC() if this is a file.
	 * This follows the protocol for read()/write().
	 */
	if (ITOV(tdp)->v_type != VDIR) {
		rw_enter(&tdp->i_rwlock, RW_WRITER);
		dorwlock = 1;
	}

	if (ulp) {
		trans_size = (int)TOP_MKDIR_SIZE(tdp);
		TRANS_BEGIN_CSYNC(ufsvfsp, issync, TOP_MKDIR, trans_size);
	}

	/*
	 * Acquire i_rwlock after TRANS_BEGIN_CSYNC() if this is a directory.
	 * This follows the protocol established by
	 * ufs_link/create/remove/rename/mkdir/rmdir/symlink.
	 */
	if (dorwlock == 0) {
		rw_enter(&tdp->i_rwlock, RW_WRITER);
		dorwlock = 2;
	}
	rw_enter(&ufsvfsp->vfs_dqrwlock, RW_READER);
	rw_enter(&tdp->i_contents, RW_WRITER);

	/*
	 * Suppress out of inodes messages if we will retry.
	 */
	if (retry)
		tdp->i_flag |= IQUIET;
	err = ufs_dirmakeinode(tdp, &ip, &va, DE_ATTRDIR, cr);
	tdp->i_flag &= ~IQUIET;

	if (err)
		goto fail;

	if (flags) {

		/*
		 * Now attach it to src file.
		 */

		tdp->i_oeftflag = ip->i_number;
	}

	ip->i_cflags |= IXATTR;
	ITOV(ip)->v_flag |= V_XATTRDIR;
	TRANS_INODE(ufsvfsp, tdp);
	tdp->i_flag |= ICHG | IUPD;
	tdp->i_seq++;
	ufs_iupdat(tdp, I_SYNC);
	rw_exit(&tdp->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);

	rw_enter(&ip->i_rwlock, RW_WRITER);
	rw_enter(&ip->i_contents, RW_WRITER);
	TRANS_INODE(ufsvfsp, ip);
	ip->i_flag |= ICHG| IUPD;
	ip->i_seq++;
	ufs_iupdat(ip, I_SYNC);
	rw_exit(&ip->i_contents);
	rw_exit(&ip->i_rwlock);
	if (dorwlock == 2)
		rw_exit(&tdp->i_rwlock);
	if (ulp) {
		int terr = 0;

		TRANS_END_CSYNC(ufsvfsp, err, issync, TOP_MKDIR, trans_size);
		ufs_lockfs_end(ulp);
		if (err == 0)
			err = terr;
	}
	if (dorwlock == 1)
		rw_exit(&tdp->i_rwlock);
	*ipp = ip;
	return (err);

fail:
	rw_exit(&tdp->i_contents);
	rw_exit(&ufsvfsp->vfs_dqrwlock);
	if (dorwlock == 2)
		rw_exit(&tdp->i_rwlock);
	if (ulp) {
		TRANS_END_CSYNC(ufsvfsp, err, issync, TOP_MKDIR, trans_size);
		ufs_lockfs_end(ulp);
	}
	if (dorwlock == 1)
		rw_exit(&tdp->i_rwlock);
	if (ip != NULL)
		VN_RELE(ITOV(ip));

	/*
	 * No inodes?  See if any are tied up in pending deletions.
	 * This has to be done outside of any of the above, because
	 * the draining operation can't be done from inside a transaction.
	 */
	if ((err == ENOSPC) && retry && TRANS_ISTRANS(ufsvfsp)) {
		ufs_delete_drain_wait(ufsvfsp, 1);
		retry = 0;
		goto again;
	}

	return (err);
}

/*
 * clear the dotdot directory entry.
 * Used by ufs_dirscan when clr_dotdot
 * flag is set and we're deleting a
 * directory.
 */
static int
ufs_dirclrdotdot(struct inode *ip, ino_t parentino)
{
	struct fbuf *fbp;
	struct direct *dotp, *dotdotp;
	int err = 0;

	ASSERT(RW_WRITE_HELD(&ip->i_rwlock));
	ASSERT(RW_LOCK_HELD(&ip->i_contents));
	err = blkatoff(ip, 0, NULL, &fbp);
	if (err) {
		return (err);
	}

	dotp = (struct direct *)fbp->fb_addr;
	if ((dotp->d_namlen < (MAXNAMLEN + 1)) &&
	    ((DIRBLKSIZ - DIRSIZ(dotp)) >= (sizeof (struct dirtemplate) / 2))) {
		dotdotp = (struct direct *)((char *)dotp + dotp->d_reclen);
		if ((dotdotp->d_namlen < (MAXNAMLEN + 1)) &&
		    ((DIRBLKSIZ - DIRSIZ(dotp)) >= dotdotp->d_reclen)) {

			dotp->d_reclen += dotdotp->d_reclen;
			if (parentino == dotdotp->d_ino) {
				dotdotp->d_ino = 0;
				dotdotp->d_namlen = 0;
				dotdotp->d_reclen = 0;
			}

			err = TRANS_DIR(ip, 0);
			if (err) {
				fbrelse(fbp, S_OTHER);
			} else {
				err = ufs_fbwrite(fbp, ip);
			}
		}
	} else {
		err = -1;
	}
	return (err);
}
