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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/buf.h>
#include <sys/ddi.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_snap.h>
#include <sys/fssnap_if.h>
#include <sys/sysmacros.h>
#include <sys/modctl.h>
#include <sys/fs/ufs_bio.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/inttypes.h>
#include <sys/vfs.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/policy.h>

static int ufs_snap_init_backfile(int  *, int, vnode_t ***, struct ufsvfs *);
static void release_backing_vnodes(vnode_t ***, int);
static int ufs_snap_find_candidates(void *, struct ufsvfs *, int);

/*
 * Create a snapshot on a file system
 */
int
ufs_snap_create(struct vnode *vp, struct fiosnapcreate_multi *fiosnapp,
    cred_t *cr)
{
	int		error = 0;
	struct ufsvfs	*ufsvfsp = VTOI(vp)->i_ufsvfs;
	struct fs	*fs = ufsvfsp->vfs_fs;
	vnode_t		**bfvpp = NULL;
	struct lockfs	lf;
	void		*snapid = NULL;

	u_offset_t	nchunks;
	uint_t		chunksize, fragsperchunk;

	/*
	 * Only privilege processes can create a snapshot for now.  This
	 * would be better if it was based on the permissions of the device
	 * file.
	 */
	if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
		return (EPERM);

	/*
	 * There is no reason to make a snapshot of a read-only file system
	 */
	if (fs->fs_ronly) {
		fiosnapp->error = FIOCOW_EREADONLY;
		return (EROFS);
	}

	/*
	 * Initialize the backing files to store old data.  This assumes any
	 * preallocation and setup has been done already.
	 * ufs_snap_init_backfile() allocates and returns a pointer to
	 * a null-terminated array of vnodes in bfvpp.
	 */
	error = ufs_snap_init_backfile(fiosnapp->backfiledesc,
	    fiosnapp->backfilecount, &bfvpp, ufsvfsp);
	if (error) {
		fiosnapp->error = FIOCOW_EBACKFILE;
		return (error);
	}

	/*
	 * File system must be write locked to prevent updates while
	 * the snapshot is being established.
	 */
	if ((error = ufs_fiolfss(vp, &lf)) != 0) {
		release_backing_vnodes(&bfvpp, fiosnapp->backfilecount);
		return (error);
	}

	if (!LOCKFS_IS_ULOCK(&lf)) {
		release_backing_vnodes(&bfvpp, fiosnapp->backfilecount);
		fiosnapp->error = FIOCOW_EULOCK;
		return (EINVAL);
	}

	lf.lf_lock = LOCKFS_WLOCK;
	lf.lf_flags = 0;
	lf.lf_comment = NULL;
	if ((error = ufs_fiolfs(vp, &lf, 1)) != 0) {
		release_backing_vnodes(&bfvpp, fiosnapp->backfilecount);
		fiosnapp->error = FIOCOW_EWLOCK;
		return (EINVAL);
	}

	/*
	 * File system must be fairly consistent to enable snapshots
	 */
	if (fs->fs_clean != FSACTIVE &&
	    fs->fs_clean != FSSTABLE &&
	    fs->fs_clean != FSCLEAN &&
	    fs->fs_clean != FSLOG) {
		fiosnapp->error = FIOCOW_ECLEAN;
		error = EINVAL;
		goto unlockout;
	}

	/*
	 * Only one snapshot is allowed per file system, so error if
	 * a snapshot is already enabled.
	 */
	if (ufsvfsp->vfs_snapshot) {
		fiosnapp->error = FIOCOW_EBUSY;
		error = EBUSY;
		goto unlockout;
	}

	/* Tell bio.c how to call our strategy routine.  XXX ugly hack */
	if (bio_snapshot_strategy == NULL)
		bio_snapshot_strategy =
		    (void (*) (void *, buf_t *))fssnap_strategy;

	/*
	 * use chunk size that is passed in, or the file system
	 * block size if it is zero.  For most cases, the file system
	 * block size will be reasonably efficient.  A larger
	 * chunksize uses less memory but may potentially induce more
	 * I/O copying the larger chunks aside.
	 */
	if (fiosnapp->chunksize != 0)
		chunksize = fiosnapp->chunksize;
	else
		chunksize = fs->fs_bsize * 4;


	/*
	 * compute the number of chunks in this whole file system.  Since
	 * the UFS allocation bitmaps are in units of fragments, we first
	 * compute the number of fragments per chunk.  Things work out
	 * nicer if the chunk size is a power-of-two multiple of the
	 * fragment size.
	 */
	if ((chunksize < fs->fs_fsize) || (chunksize % fs->fs_fsize != 0)) {
		fiosnapp->error = FIOCOW_ECHUNKSZ;
		error = EINVAL;
		goto unlockout;
	}
	fragsperchunk = chunksize >> fs->fs_fshift;
	nchunks = (fs->fs_size + fragsperchunk) / fragsperchunk;

	/*
	 * Create and initialize snapshot state and allocate/initialize
	 * translation table.  This does the real work of taking the snapshot.
	 */
	snapid = fssnap_create(nchunks, chunksize, fiosnapp->maxsize, vp,
	    fiosnapp->backfilecount, bfvpp, fiosnapp->backfilename,
	    fiosnapp->backfilesize);
	if (snapid == NULL) {
		fiosnapp->error = FIOCOW_ECREATE;
		error = EINVAL;
		goto unlockout;
	}

	error = ufs_snap_find_candidates(snapid, ufsvfsp, chunksize);
	fiosnapp->snapshotnumber = fssnap_create_done(snapid);

	if (error) {
		cmn_err(CE_WARN, "ufs_snap_create: failed scanning bitmaps, "
		    "error = %d.", error);
		fiosnapp->error = FIOCOW_EBITMAP;
		goto unlockout;
	}

	ufsvfsp->vfs_snapshot = snapid;

unlockout:
	/*
	 * Unlock the file system
	 */
	lf.lf_lock = LOCKFS_ULOCK;
	lf.lf_flags = 0;
	if ((ufs_fiolfs(vp, &lf, 1) != 0) && !error) {
		fiosnapp->error = FIOCOW_ENOULOCK;
		error = EINVAL;
	} else {
		fiosnapp->error = 0;
	}

	/* clean up the snapshot if an error occurred. */
	if (error && snapid != NULL)
		(void) fssnap_delete(&snapid);
	else if (error && bfvpp != NULL)
		release_backing_vnodes(&bfvpp, fiosnapp->backfilecount);

	return (error);
}

static int
ufs_snap_init_backfile(int *filedesc, int count, vnode_t ***vppp,
    struct ufsvfs *ufsvfsp)
{
	file_t *fp;
	vnode_t **vpp;
	int i;

	vpp = (vnode_t **)kmem_zalloc((count  + 1) * sizeof (vnode_t *),
	    KM_SLEEP);
	*vppp = vpp;
	for (i = 0; i < count; i++) {
		if ((fp = getf(*filedesc)) == NULL) {
			release_backing_vnodes(vppp, count);
			*vppp = NULL;
			return (EBADF);
		}

		ASSERT(fp->f_vnode != NULL);
		VN_HOLD(fp->f_vnode);

		*vpp = fp->f_vnode;
		releasef(*filedesc);
		filedesc++;

		/* make sure the backing file is on a different file system */
		if ((*vpp)->v_vfsp == ufsvfsp->vfs_vfs) {
			release_backing_vnodes(vppp, count);
			*vppp = NULL;
			return (EINVAL);
		}
		vpp++;
	}
	return (0);
}

static void
release_backing_vnodes(vnode_t ***bvppp, int count)
{
	vnode_t **vpp;

	vpp = *bvppp;
	while (*vpp) {
		VN_RELE(*vpp);
		*vpp++ = NULL;
	}
	kmem_free(*bvppp, (count + 1) * sizeof (vnode_t *));
	*bvppp = NULL;
}

static int
ufs_snap_find_candidates(void *snapid, struct ufsvfs *ufsvfsp, int chunksize)
{
	struct fs	*fs = ufsvfsp->vfs_fs;
	struct buf	*cgbp;	/* cylinder group buffer */
	struct cg	*cgp;	/* cylinder group data */
	ulong_t		cg;
	ulong_t		cgbase;
	ulong_t		chunk;
	uchar_t		*blksfree;

	ulong_t		curfrag;
	int		error = 0;

	/*
	 * read through each ufs cylinder group and fetch the fragment
	 * allocation bitmap.  UFS indicates a fragment is allocated by
	 * a zero bit (not a one bit) in the fragment offset.
	 */
	cgbase = 0LL;
	for (cg = 0; cg < fs->fs_ncg; cg++) {
		/* read the cylinder group in */
		cgbp = BREAD(ufsvfsp->vfs_dev,
		    (daddr_t)fsbtodb(fs, cgtod(fs, cg)), (int)fs->fs_cgsize);
		if ((error = geterror(cgbp)) != 0) {
			brelse(cgbp);
			goto errout;
		}
		cgp = cgbp->b_un.b_cg;

		/* check the magic number */
		if (cgp->cg_magic != CG_MAGIC) {
			cmn_err(CE_WARN, "ufs_snap_find_candidates: cg %lu "
			    "magic number (0x%x) does not match expected "
			    "magic number (0x%x)", cg, cgp->cg_magic, CG_MAGIC);
			error = EIO;
			goto errout;
		}

		blksfree = cg_blksfree(cgp);

		/*
		 * go through the allocation bitmap and set the
		 * corresponding bit in the candidate map.
		 */
		for (curfrag = 0; curfrag < cgp->cg_ndblk; curfrag++) {
			if (isclr(blksfree, curfrag)) {
				/*
				 * this assumes chunksize is a multiple of
				 * the fragment size
				 */
				chunk = (ulong_t)((cgbase + curfrag) /
				    (chunksize >> fs->fs_fshift));

				fssnap_set_candidate(snapid, chunk);
				/*
				 * no need to scan the rest of this chunk since
				 * it is already marked, so skip to the next
				 */
				curfrag += ((chunksize >> fs->fs_fshift) -
				    ((cgbase + curfrag) %
				    (chunksize >> fs->fs_fshift))) - 1;
			}
		}

		cgbase += cgp->cg_ndblk;
		ASSERT(cgbase <= fs->fs_size);
		brelse(cgbp);
	} /* cylinder group loop */

	ASSERT(cgbase == fs->fs_size);

errout:
	return (error);
}


int
ufs_snap_delete(struct vnode *vp, struct fiosnapdelete *fiosnapp, cred_t *cr)
{
	struct ufsvfs	*ufsvfsp = VTOI(vp)->i_ufsvfs;
	struct fs	*fs = ufsvfsp->vfs_fs;

	/*
	 * Initialize fields in the user's buffer
	 */
	fiosnapp->error = 0;

	/*
	 * No snapshot exists, we're done.
	 */
	if (ufsvfsp->vfs_snapshot == NULL)
		return (ENOENT);

	/*
	 * must have sufficient privileges.
	 */
	if (secpolicy_fs_config(cr, ufsvfsp->vfs_vfs) != 0)
		return (EPERM);

	/*
	 * Readonly file system
	 */
	if (fs->fs_ronly) {
		fiosnapp->error = FIOCOW_EREADONLY;
		return (EROFS);
	}

	/* free the data structures and clear the vfs_snapshot field. */
	fiosnapp->snapshotnumber = fssnap_delete(&ufsvfsp->vfs_snapshot);

	if (fiosnapp->snapshotnumber == -1)
		return (EINVAL);

	return (0);
}
