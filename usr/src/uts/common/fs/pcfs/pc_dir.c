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

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/fs/pc_label.h>
#include <sys/fs/pc_fs.h>
#include <sys/fs/pc_dir.h>
#include <sys/fs/pc_node.h>

static int pc_makedirentry(struct pcnode *dp, struct pcdir *direntries,
    int	ndirentries, struct vattr *vap, offset_t offset);
static int pc_dirempty(struct pcnode *);
static int pc_findentry(struct pcnode *, char *, struct pcslot *, offset_t *);
static int pc_parsename(char *, char *, char *);
static int pc_remove_long_fn(struct pcnode *pcp,
    offset_t lfn_offset);
static int generate_short_name(struct pcnode *dp, char *namep,
    struct pcdir *ep);
static struct pcdir *pc_name_to_pcdir(struct pcnode *dp, char *namep,
    int ndirentries, int *errret);
static offset_t pc_find_free_space(struct pcnode *pcp, int ndirentries);
static int direntries_needed(struct pcnode *dp, char *namep);
static int pc_is_short_file_name(char *namep, int foldcase);
static int shortname_exists(struct pcnode *dp, char *fname, char *fext);
static int pc_dirfixdotdot(struct pcnode *cdp, struct pcnode *opdp,
    struct pcnode *npdp);
/*
 * Tunables
 */
int enable_long_filenames = 1;

/*
 * Lookup a name in a directory. Return a pointer to the pc_node
 * which represents the entry.
 */
int
pc_dirlook(
	struct pcnode *dp,		/* parent directory */
	char *namep,			/* name to lookup */
	struct pcnode **pcpp)		/* result */
{
	struct vnode *vp;
	struct pcslot slot;
	int error;

	PC_DPRINTF2(4, "pc_dirlook (dp %p name %s)\n", (void *)dp, namep);

	if (!(dp->pc_entry.pcd_attr & PCA_DIR)) {
		return (ENOTDIR);
	}
	vp = PCTOV(dp);
	/*
	 * check now for changed disk, before any return(0)
	 */
	if (error = pc_verify(VFSTOPCFS(vp->v_vfsp)))
		return (error);

	/*
	 * Null component name is synonym for directory being searched.
	 */
	if (*namep == '\0') {
		VN_HOLD(vp);
		*pcpp = dp;
		return (0);
	}
	/*
	 * The root directory does not have "." and ".." entries,
	 * so they are faked here.
	 */
	if (vp->v_flag & VROOT) {
		if (bcmp(namep, ".", 2) == 0 || bcmp(namep, "..", 3) == 0) {
			VN_HOLD(vp);
			*pcpp = dp;
			return (0);
		}
	}
	error = pc_findentry(dp, namep, &slot, NULL);
	if (error == 0) {
		*pcpp = pc_getnode(VFSTOPCFS(vp->v_vfsp),
		    slot.sl_blkno, slot.sl_offset, slot.sl_ep);
		brelse(slot.sl_bp);
		PC_DPRINTF1(4, "pc_dirlook: FOUND pcp=%p\n", (void *)*pcpp);
	} else if (error == EINVAL) {
		error = ENOENT;
	}
	return (error);
}

/*
 * Enter a name in a directory.
 */
int
pc_direnter(
	struct pcnode *dp,		/* directory to make entry in */
	char *namep,			/* name of entry */
	struct vattr *vap,		/* attributes of new entry */
	struct pcnode **pcpp)
{
	int error;
	struct pcslot slot;
	struct vnode *vp = PCTOV(dp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	offset_t offset;
	daddr_t	blkno;
	int	boff;
	struct buf *bp = NULL;
	struct pcdir *ep;

	PC_DPRINTF4(4, "pc_dirent(dp %p, name %s, vap %p, pcpp %p\n",
	    (void *)dp, namep, (void *)vap, (void *)pcpp);

	if (pcpp != NULL)
		*pcpp = NULL;
	/*
	 * Leading spaces are not allowed in DOS.
	 */
	if (*namep == ' ')
		return (EINVAL);
	/*
	 * If name is "." or "..", just look it up.
	 */
	if (PC_NAME_IS_DOT(namep) || PC_NAME_IS_DOTDOT(namep)) {
		if (pcpp) {
			error = pc_dirlook(dp, namep, pcpp);
			if (error)
				return (error);
		}
		return (EEXIST);
	}
	if (PCA_IS_HIDDEN(fsp, dp->pc_entry.pcd_attr)) {
		return (EPERM);
	}
	/*
	 * Make sure directory has not been removed while fs was unlocked.
	 */
	if (dp->pc_entry.pcd_filename[0] == PCD_ERASED) {
		return (ENOENT);
	}
	error = pc_findentry(dp, namep, &slot, NULL);
	if (error == 0) {
		if (pcpp) {
			*pcpp =
			    pc_getnode(fsp, slot.sl_blkno, slot.sl_offset,
			    slot.sl_ep);
			error = EEXIST;
		}
		brelse(slot.sl_bp);
	} else if (error == ENOENT) {
		struct pcdir *direntries;
		int	ndirentries;

		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if (dp->pc_entry.pcd_attr & PCA_RDONLY) {
			return (EPERM);
		}
		error = 0;
		/*
		 * Make sure there is a slot.
		 */
		if (slot.sl_status == SL_NONE)
			panic("pc_direnter: no slot\n");
		ndirentries = direntries_needed(dp, namep);
		if (ndirentries == -1) {
			return (EINVAL);
		}

		offset = pc_find_free_space(dp, ndirentries);
		if (offset == -1) {
			return (ENOSPC);
		}

		/*
		 * Make an entry from the supplied attributes.
		 */
		direntries = pc_name_to_pcdir(dp, namep, ndirentries, &error);
		if (direntries == NULL) {
			return (error);
		}
		error = pc_makedirentry(dp, direntries, ndirentries, vap,
		    offset);
		kmem_free(direntries, ndirentries * sizeof (struct pcdir));
		if (error) {
			return (error);
		}
		offset += (ndirentries - 1)  * sizeof (struct pcdir);
		boff = pc_blkoff(fsp, offset);
		error = pc_blkatoff(dp, offset, &bp, &ep);
		if (error) {
			return (error);
		}
		blkno = pc_daddrdb(fsp, bp->b_blkno);
		/*
		 * Get a pcnode for the new entry.
		 */
		*pcpp = pc_getnode(fsp, blkno, boff, ep);
		brelse(bp);
		if (vap->va_type == VDIR)
			(*pcpp)->pc_size = fsp->pcfs_clsize;

		/*
		 * Write out the new entry in the parent directory.
		 */
		error = pc_syncfat(fsp);
		if (!error) {
			error = pc_nodeupdate(*pcpp);
		}
	}
	return (error);
}

/*
 * Template for "." and ".." directory entries.
 */
static struct {
	struct pcdir t_dot;		/* dot entry */
	struct pcdir t_dotdot;		/* dotdot entry */
} dirtemplate = {
	{
		".       ",
		"   ",
		PCA_DIR
	},
	{
		"..      ",
		"   ",
		PCA_DIR
	}
};

/*
 * Convert an attributes structure into the short filename entry
 * and write out the whole entry.
 */
static int
pc_makedirentry(struct pcnode *dp, struct pcdir *direntries,
    int ndirentries, struct vattr *vap, offset_t offset)
{
	struct vnode *vp = PCTOV(dp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int error;
	struct pcdir *ep;
	int	boff;
	int	i;
	struct buf *bp = NULL;
	timestruc_t now;

	if (vap != NULL && vap->va_mask & (AT_ATIME|AT_MTIME))
		return (EOPNOTSUPP);

	ep = &direntries[ndirentries - 1];
	gethrestime(&now);
	if (error = pc_tvtopct(&now, &ep->pcd_mtime))
		return (error);

	ep->pcd_crtime = ep->pcd_mtime;
	ep->pcd_ladate = ep->pcd_mtime.pct_date;
	ep->pcd_crtime_msec = 0;
	ep->pcd_size = 0;
	ep->pcd_attr = 0;
	/*
	 * Fields we don't use.
	 */
	ep->pcd_ntattr = 0;
	if (!IS_FAT32(fsp))
		ep->un.pcd_eattr = 0;

	if (vap && ((vap->va_mode & 0222) == 0))
		ep->pcd_attr |=  PCA_RDONLY;
	if (vap && (vap->va_type == VDIR)) {
		pc_cluster32_t cn;

		ep->pcd_attr |= PCA_DIR;
		/*
		 * Make dot and dotdot entries for a new directory.
		 */
		cn = pc_alloccluster(fsp, 0);
		switch (cn) {
		case PCF_FREECLUSTER:
			return (ENOSPC);
		case PCF_ERRORCLUSTER:
			return (EIO);
		}
		bp = ngeteblk(fsp->pcfs_clsize);
		bp->b_edev = fsp->pcfs_xdev;
		bp->b_dev = cmpdev(bp->b_edev);
		bp->b_blkno = pc_cldaddr(fsp, cn);
		clrbuf(bp);
		pc_setstartcluster(fsp, ep, cn);
		pc_setstartcluster(fsp, &dirtemplate.t_dot, cn);
		cn = pc_getstartcluster(fsp, &dp->pc_entry);
		pc_setstartcluster(fsp, &dirtemplate.t_dotdot, cn);
		dirtemplate.t_dot.pcd_mtime =
		    dirtemplate.t_dotdot.pcd_mtime = ep->pcd_mtime;
		dirtemplate.t_dot.pcd_crtime =
		    dirtemplate.t_dotdot.pcd_crtime = ep->pcd_crtime;
		dirtemplate.t_dot.pcd_ladate =
		    dirtemplate.t_dotdot.pcd_ladate = ep->pcd_ladate;
		dirtemplate.t_dot.pcd_crtime_msec =
		    dirtemplate.t_dotdot.pcd_crtime_msec = 0;
		bcopy(&dirtemplate,
		    bp->b_un.b_addr, sizeof (dirtemplate));
		bwrite2(bp);
		error = geterror(bp);
		brelse(bp);
		if (error) {
			PC_DPRINTF0(1, "pc_makedirentry error");
			pc_mark_irrecov(fsp);
			return (EIO);
		}
	} else {
		pc_setstartcluster(fsp, ep, 0);
	}
	bp = NULL;
	for (i = 0, ep = NULL; i < ndirentries; i++, ep++) {
		boff = pc_blkoff(fsp, offset);
		if (boff == 0 || bp == NULL || boff >= bp->b_bcount) {
			if (bp != NULL) {
				/* always modified */
				bwrite2(bp);
				error = geterror(bp);
				brelse(bp);
				if (error)
					return (error);
				bp = NULL;
			}
			error = pc_blkatoff(dp, offset, &bp, &ep);
			if (error)
				return (error);
		}

		*ep = direntries[i];
		offset += sizeof (struct pcdir);
	}
	if (bp != NULL) {
		/* always modified */
		bwrite2(bp);
		error = geterror(bp);
		brelse(bp);
		if (error)
			return (error);
	}
	return (0);
}

/*
 * Remove a name from a directory.
 */
int
pc_dirremove(
	struct pcnode *dp,
	char *namep,
	struct vnode *cdir,
	enum vtype type,
	caller_context_t *ctp)
{
	struct pcslot slot;
	struct pcnode *pcp;
	int error;
	struct vnode *vp = PCTOV(dp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	offset_t lfn_offset = -1;

	PC_DPRINTF2(4, "pc_dirremove (dp %p name %s)\n", (void *)dp, namep);
	if ((dp->pc_entry.pcd_attr & PCA_RDONLY) ||
	    PCA_IS_HIDDEN(fsp, dp->pc_entry.pcd_attr)) {
		return (EPERM);
	}
	error = pc_findentry(dp, namep, &slot, &lfn_offset);
	if (error)
		return (error);
	if (slot.sl_flags == SL_DOT) {
		error = EINVAL;
	} else if (slot.sl_flags == SL_DOTDOT) {
		error = ENOTEMPTY;
	} else {
		pcp =
		    pc_getnode(VFSTOPCFS(vp->v_vfsp),
		    slot.sl_blkno, slot.sl_offset, slot.sl_ep);
	}
	if (error) {
		brelse(slot.sl_bp);
		return (error);
	}
	if (type == VDIR) {
		if (pcp->pc_entry.pcd_attr & PCA_DIR) {
			if (PCTOV(pcp) == cdir)
				error = EINVAL;
			else if (!pc_dirempty(pcp))
				error = ENOTEMPTY;
		} else {
			error = ENOTDIR;
		}
	} else {
		if (pcp->pc_entry.pcd_attr & PCA_DIR)
			error = EISDIR;
	}
	if (error == 0) {
		/*
		 * Mark the in core node and on disk entry
		 * as removed. The slot may then be reused.
		 * The files clusters will be deallocated
		 * when the last reference goes away.
		 */
		pcp->pc_eblkno = -1;
		pcp->pc_entry.pcd_filename[0] = PCD_ERASED;
		if (lfn_offset != -1) {
			brelse(slot.sl_bp);
			error = pc_remove_long_fn(dp, lfn_offset);
			if (error) {
				VN_RELE(PCTOV(pcp));
				pc_mark_irrecov(VFSTOPCFS(vp->v_vfsp));
				return (EIO);
			}
		} else {
			slot.sl_ep->pcd_filename[0] = PCD_ERASED;
			bwrite2(slot.sl_bp);
			error = geterror(slot.sl_bp);
			brelse(slot.sl_bp);
		}
		if (error) {
			VN_RELE(PCTOV(pcp));
			pc_mark_irrecov(VFSTOPCFS(vp->v_vfsp));
			return (EIO);
		} else if (type == VDIR) {
			error = pc_truncate(pcp, 0L);
		}

	} else {
		brelse(slot.sl_bp);
	}

	if (error == 0) {
		if (type == VDIR) {
			vnevent_rmdir(PCTOV(pcp), vp, namep, ctp);
		} else {
			vnevent_remove(PCTOV(pcp), vp, namep, ctp);
		}
	}

	VN_RELE(PCTOV(pcp));

	return (error);
}

/*
 * Determine whether a directory is empty.
 */
static int
pc_dirempty(struct pcnode *pcp)
{
	struct buf *bp;
	struct pcdir *ep;
	offset_t offset;
	int boff;
	char c;
	int error;
	struct vnode *vp;

	vp = PCTOV(pcp);
	bp = NULL;

	offset = 0;
	for (;;) {

		/*
		 * If offset is on a block boundary,
		 * read in the next directory block.
		 * Release previous if it exists.
		 */
		boff = pc_blkoff(VFSTOPCFS(vp->v_vfsp), offset);
		if (boff == 0 || bp == NULL || boff >= bp->b_bcount) {
			if (bp != NULL)
				brelse(bp);
			if (error = pc_blkatoff(pcp, offset, &bp, &ep)) {
				return (error);
			}
		}
		if (PCDL_IS_LFN(ep)) {
			error = pc_extract_long_fn(pcp, NULL, &ep, &offset,
			    &bp);
			/*
			 * EINVAL means the lfn was invalid, so start with
			 * the next entry. Otherwise, an error occurred _or_
			 * the lfn is valid, either of which means the
			 * directory is not empty.
			 */
			if (error == EINVAL)
				continue;
			else {
				if (bp)
					brelse(bp);
				return (error);
			}
		}
		c = ep->pcd_filename[0];
		if (c == PCD_UNUSED)
			break;
		if ((c != '.') && (c != PCD_ERASED)) {
			brelse(bp);
			return (0);
		}
		if ((c == '.') && !PC_SHORTNAME_IS_DOT(ep->pcd_filename) &&
		    !PC_SHORTNAME_IS_DOTDOT(ep->pcd_filename)) {
			brelse(bp);
			return (0);
		}
		ep++;
		offset += sizeof (struct pcdir);
	}
	if (bp != NULL)
		brelse(bp);
	return (1);
}

/*
 * Rename a file.
 */
int
pc_rename(
	struct pcnode *dp,		/* parent directory */
	struct pcnode *tdp,		/* target directory */
	char *snm,			/* source file name */
	char *tnm,			/* target file name */
	caller_context_t *ctp)
{
	struct pcnode *pcp;	/* pcnode we are trying to rename */
	struct pcnode *tpcp;	/* pcnode that's in our way */
	struct pcslot slot;
	int error;
	struct vnode *vp = PCTOV(dp);
	struct vnode *svp = NULL;
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int filecasechange = 0;
	int oldisdir = 0;

	PC_DPRINTF3(4, "pc_rename(0x%p, %s, %s)\n", (void *)dp, snm, tnm);
	/*
	 * Leading spaces are not allowed in DOS.
	 */
	if (*tnm == ' ')
		return (EINVAL);
	/*
	 * No dot or dotdot.
	 */
	if (PC_NAME_IS_DOT(snm) || PC_NAME_IS_DOTDOT(snm) ||
	    PC_NAME_IS_DOT(tnm) || PC_NAME_IS_DOTDOT(tnm))
		return (EINVAL);
	/*
	 * Get the source node.  We'll jump back to here if trying to
	 * move on top of an existing file, after deleting that file.
	 */
top:
	error = pc_findentry(dp, snm, &slot, NULL);
	if (error) {
		return (error);
	}
	pcp = pc_getnode(VFSTOPCFS(vp->v_vfsp),
	    slot.sl_blkno, slot.sl_offset, slot.sl_ep);

	brelse(slot.sl_bp);

	if (pcp)
		svp = PCTOV(pcp);

	/*
	 * is the rename invalid, i.e. rename("a", "a/a")
	 */
	if (pcp == tdp) {
		if (svp)
			VN_RELE(svp);
		return (EINVAL);
	}

	/*
	 * Are we just changing the case of an existing name?
	 */
	if ((dp->pc_scluster == tdp->pc_scluster) &&
	    (u8_strcmp(snm, tnm, 0, U8_STRCMP_CI_UPPER, U8_UNICODE_LATEST,
	    &error) == 0)) {
		filecasechange = 1;
	}

	/*
	 * u8_strcmp detected an illegal character
	 */
	if (error)
		return (EINVAL);

	oldisdir = pcp->pc_entry.pcd_attr & PCA_DIR;

	/*
	 * see if the target exists
	 */
	error = pc_findentry(tdp, tnm, &slot, NULL);
	if (error == 0 && filecasechange == 0) {
		/*
		 * Target exists.  If it's a file, delete it.  If it's
		 * a directory, bail.
		 */
		int newisdir;

		tpcp = pc_getnode(VFSTOPCFS(vp->v_vfsp),
		    slot.sl_blkno, slot.sl_offset, slot.sl_ep);

		newisdir = tpcp->pc_entry.pcd_attr & PCA_DIR;

		brelse(slot.sl_bp);
		vnevent_rename_dest(PCTOV(tpcp), PCTOV(tdp), tnm, ctp);
		VN_RELE(PCTOV(tpcp));

		/*
		 * Error cases (from rename(2)):
		 * old is dir, new is dir: EEXIST
		 * old is dir, new is nondir: ENOTDIR
		 * old is nondir, new is dir: EISDIR
		 */
		if (!newisdir) {
			if (oldisdir) {
				error = ENOTDIR;
			} else {
				/* nondir/nondir, remove target */
				error = pc_dirremove(tdp, tnm,
				    (struct vnode *)NULL, VREG, ctp);
				if (error == 0) {
					VN_RELE(PCTOV(pcp));
					goto top;
				}
			}
		} else if (oldisdir) {
			/* dir/dir, remove target */
			error = pc_dirremove(tdp, tnm,
			    (struct vnode *)NULL, VDIR, ctp);
			if (error == 0) {
				VN_RELE(PCTOV(pcp));
				goto top;
			}
			/* Follow rename(2)'s spec... */
			if (error == ENOTEMPTY) {
				error = EEXIST;
			}
		} else {
			/* nondir/dir, bail */
			error = EISDIR;
		}
	}

	if ((error == 0) || (error == ENOENT)) {
		offset_t lfn_offset = -1;
		daddr_t	blkno;
		struct pcdir *direntries;
		struct pcdir *ep;
		int	ndirentries;
		pc_cluster16_t pct_lo;
		pc_cluster16_t pct_hi;
		offset_t offset;
		int	boff;
		struct buf *bp = NULL;
		uchar_t	attr;
		int	size;
		struct pctime mtime;
		struct pctime crtime;
		uchar_t	ntattr;
		ushort_t ladate;
		ushort_t eattr;
		uchar_t	crtime_msec;

		/*
		 * Rename the source.
		 */
		/*
		 * Delete the old name, and create a new name.
		 */
		if (filecasechange == 1 && error == 0)
			brelse(slot.sl_bp);
		ndirentries = direntries_needed(tdp, tnm);
		if (ndirentries == -1) {
			VN_RELE(PCTOV(pcp));
			return (EINVAL);
		}
		/*
		 * first see if we have enough space to create the new
		 * name before destroying the old one.
		 */
		offset = pc_find_free_space(tdp, ndirentries);
		if (offset == -1) {
			VN_RELE(PCTOV(pcp));
			return (ENOSPC);
		}

		error = pc_findentry(dp, snm, &slot, &lfn_offset);
		if (error) {
			VN_RELE(PCTOV(pcp));
			return (error);
		}
		pct_lo = slot.sl_ep->pcd_scluster_lo;
		if (IS_FAT32(fsp))
			pct_hi = slot.sl_ep->un.pcd_scluster_hi;
		else
			eattr = slot.sl_ep->un.pcd_eattr;
		size = slot.sl_ep->pcd_size;
		attr = slot.sl_ep->pcd_attr;
		mtime = slot.sl_ep->pcd_mtime;
		crtime = slot.sl_ep->pcd_crtime;
		crtime_msec = slot.sl_ep->pcd_crtime_msec;
		ntattr = slot.sl_ep->pcd_ntattr;
		ladate = slot.sl_ep->pcd_ladate;

		if (lfn_offset != -1) {
			brelse(slot.sl_bp);
			error = pc_remove_long_fn(dp, lfn_offset);
			if (error) {
				VN_RELE(PCTOV(pcp));
				pc_mark_irrecov(VFSTOPCFS(vp->v_vfsp));
				return (error);
			}
		} else {
			slot.sl_ep->pcd_filename[0] =
			    pcp->pc_entry.pcd_filename[0] = PCD_ERASED;
			bwrite2(slot.sl_bp);
			error = geterror(slot.sl_bp);
			brelse(slot.sl_bp);
		}
		if (error) {
			VN_RELE(PCTOV(pcp));
			pc_mark_irrecov(VFSTOPCFS(vp->v_vfsp));
			return (EIO);
		}

		/*
		 * Make an entry from the supplied attributes.
		 */
		direntries = pc_name_to_pcdir(tdp, tnm, ndirentries, &error);
		if (direntries == NULL) {
			VN_RELE(PCTOV(pcp));
			return (error);
		}
		error = pc_makedirentry(tdp, direntries, ndirentries, NULL,
		    offset);
		kmem_free(direntries, ndirentries * sizeof (struct pcdir));
		if (error) {
			VN_RELE(PCTOV(pcp));
			return (error);
		}
		/* advance to short name */
		offset += (ndirentries - 1)  * sizeof (struct pcdir);
		boff = pc_blkoff(fsp, offset);
		error = pc_blkatoff(tdp, offset, &bp, &ep);
		if (error) {
			VN_RELE(PCTOV(pcp));
			return (error);
		}
		blkno = pc_daddrdb(fsp, bp->b_blkno);
		ep->pcd_scluster_lo = pct_lo;
		if (IS_FAT32(fsp))
			ep->un.pcd_scluster_hi = pct_hi;
		else
			ep->un.pcd_eattr = eattr;
		ep->pcd_size = size;
		ep->pcd_attr = attr;
		ep->pcd_mtime = mtime;
		ep->pcd_crtime = crtime;
		ep->pcd_crtime_msec = crtime_msec;
		ep->pcd_ntattr = ntattr;
		ep->pcd_ladate = ladate;
		bwrite2(bp);
		error = geterror(bp);
		pcp->pc_eblkno = blkno;
		pcp->pc_eoffset = boff;
		pcp->pc_entry = *ep;
		pcp->pc_flags |= PC_CHG;
		brelse(bp);
		if (error) {
			VN_RELE(PCTOV(pcp));
			pc_mark_irrecov(VFSTOPCFS(vp->v_vfsp));
			return (EIO);
		}
		/* No need to fix ".." if we're renaming within a dir */
		if (oldisdir && dp != tdp) {
			if ((error = pc_dirfixdotdot(pcp, dp, tdp)) != 0) {
				VN_RELE(PCTOV(pcp));
				return (error);
			}
		}
		if ((error = pc_nodeupdate(pcp)) != 0) {
			VN_RELE(PCTOV(pcp));
			return (error);
		}
	}

	if (error == 0) {
		vnevent_rename_src(PCTOV(pcp), PCTOV(dp), snm, ctp);
		vnevent_rename_dest_dir(PCTOV(tdp), PCTOV(pcp), tnm, ctp);
	}

	VN_RELE(PCTOV(pcp));

	return (error);
}

/*
 * Fix the ".." entry of the child directory so that it points to the
 * new parent directory instead of the old one.
 */
static int
pc_dirfixdotdot(struct pcnode *dp,	/* child directory being moved */
	struct pcnode *opdp,		/* old parent directory */
	struct pcnode *npdp)		/* new parent directory */
{
	pc_cluster32_t cn;
	struct vnode *vp = PCTOV(dp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int error = 0;
	struct buf *bp = NULL;
	struct pcdir *ep = NULL;
	struct pcdir *tep = NULL;

	/*
	 * set the new child's ".." directory entry starting cluster to
	 * point to the new parent's starting cluster
	 */
	ASSERT(opdp != npdp);
	error = pc_blkatoff(dp, (offset_t)0, &bp, &ep);
	if (error) {
		PC_DPRINTF0(1, "pc_dirfixdotdot: error in blkatoff\n");
		return (error);
	}
	tep = ep;
	ep++;
	if (!PC_SHORTNAME_IS_DOT(tep->pcd_filename) &&
	    !PC_SHORTNAME_IS_DOTDOT(ep->pcd_filename)) {
		PC_DPRINTF0(1, "pc_dirfixdotdot: mangled directory entry\n");
		error = ENOTDIR;
		return (error);
	}
	cn = pc_getstartcluster(fsp, &npdp->pc_entry);
	pc_setstartcluster(fsp, ep, cn);

	bwrite2(bp);
	error = geterror(bp);
	brelse(bp);
	if (error) {
		PC_DPRINTF0(1, "pc_dirfixdotdot: error in write\n");
		pc_mark_irrecov(fsp);
		return (EIO);
	}
	return (0);
}


/*
 * Search a directory for an entry.
 * The directory should be locked as this routine
 * will sleep on I/O while searching.
 */
static int
pc_findentry(
	struct pcnode *dp,		/* parent directory */
	char *namep,			/* name to lookup */
	struct pcslot *slotp,
	offset_t *lfn_offset)
{
	offset_t offset;
	struct pcdir *ep = NULL;
	int boff;
	int error;
	struct vnode *vp;
	struct pcfs *fsp;

	vp = PCTOV(dp);
	PC_DPRINTF2(6, "pc_findentry: looking for %s in dir 0x%p\n", namep,
	    (void *)dp);
	slotp->sl_status = SL_NONE;
	if (!(dp->pc_entry.pcd_attr & PCA_DIR)) {
		return (ENOTDIR);
	}
	/*
	 * Verify that the dp is still valid on the disk
	 */
	fsp = VFSTOPCFS(vp->v_vfsp);
	error = pc_verify(fsp);
	if (error)
		return (error);

	slotp->sl_bp = NULL;
	offset = 0;
	for (;;) {
		/*
		 * If offset is on a block boundary,
		 * read in the next directory block.
		 * Release previous if it exists.
		 */
		boff = pc_blkoff(fsp, offset);
		if (boff == 0 || slotp->sl_bp == NULL ||
		    boff >= slotp->sl_bp->b_bcount) {
			if (slotp->sl_bp != NULL) {
				brelse(slotp->sl_bp);
				slotp->sl_bp = NULL;
			}
			error = pc_blkatoff(dp, offset, &slotp->sl_bp, &ep);
			if (error == ENOENT && slotp->sl_status == SL_NONE) {
				slotp->sl_status = SL_EXTEND;
				slotp->sl_offset = (int)offset;
			}
			if (error)
				return (error);
		}
		if ((ep->pcd_filename[0] == PCD_UNUSED) ||
		    (ep->pcd_filename[0] == PCD_ERASED)) {
			/*
			 * note empty slots, in case name is not found
			 */
			if (slotp->sl_status == SL_NONE) {
				slotp->sl_status = SL_FOUND;
				slotp->sl_blkno = pc_daddrdb(fsp,
				    slotp->sl_bp->b_blkno);
				slotp->sl_offset = boff;
			}
			/*
			 * If unused we've hit the end of the directory
			 */
			if (ep->pcd_filename[0] == PCD_UNUSED)
				break;
			offset += sizeof (struct pcdir);
			ep++;
			continue;
		}
		if (PCDL_IS_LFN(ep)) {
			offset_t t = offset;
			if (pc_match_long_fn(dp, namep, &ep,
			    slotp, &offset) == 0) {
				if (lfn_offset != NULL)
					*lfn_offset = t;
				return (0);
			}
			continue;
		}
		if (pc_match_short_fn(dp, namep, &ep, slotp, &offset) == 0)
			return (0);
	}
	if (slotp->sl_bp != NULL) {
		brelse(slotp->sl_bp);
		slotp->sl_bp = NULL;
	}
	return (ENOENT);
}

/*
 * Obtain the block at offset "offset" in file pcp.
 */
int
pc_blkatoff(
	struct pcnode *pcp,
	offset_t offset,
	struct buf **bpp,
	struct pcdir **epp)
{
	struct pcfs *fsp;
	struct buf *bp;
	int size;
	int error;
	daddr_t bn;

	fsp = VFSTOPCFS(PCTOV(pcp)->v_vfsp);
	size = pc_blksize(fsp, pcp, offset);
	if (pc_blkoff(fsp, offset) >= size) {
		PC_DPRINTF0(5, "pc_blkatoff: ENOENT\n");
		return (ENOENT);
	}
	error = pc_bmap(pcp, pc_lblkno(fsp, offset), &bn, (uint_t *)0);
	if (error)
		return (error);

	bp = bread(fsp->pcfs_xdev, bn, size);
	if (bp->b_flags & B_ERROR) {
		PC_DPRINTF0(1, "pc_blkatoff: error\n");
		brelse(bp);
		pc_mark_irrecov(fsp);
		return (EIO);
	}
	if (epp) {
		*epp =
		    (struct pcdir *)(bp->b_un.b_addr + pc_blkoff(fsp, offset));
	}
	*bpp = bp;
	return (0);
}

/*
 * Parse user filename into the pc form of "filename.extension".
 * If names are too long for the format (and enable_long_filenames is set)
 * it returns EINVAL (since either this name was read from the disk (so
 * it must fit), _or_ we're trying to match a long file name (so we
 * should fail).  Tests for characters that are invalid in PCDOS and
 * converts to upper case (unless foldcase is 0).
 */
static int
pc_parsename(
	char *namep,
	char *fnamep,
	char *fextp)
{
	int n;
	char c;

	n = PCFNAMESIZE;
	c = *namep++;
	if (c == 0)
		return (EINVAL);
	if (c == '.') {
		/*
		 * check for "." and "..".
		 */
		*fnamep++ = c;
		n--;
		if (c = *namep++) {
			if ((c != '.') || (c = *namep)) /* ".x" or "..x" */
				return (EINVAL);
			*fnamep++ = '.';
			n--;
		}
	} else {
		/*
		 * filename up to '.'
		 */
		do {
			if (n-- > 0) {
				c = toupper(c);
				if (!pc_validchar(c))
					return (EINVAL);
				*fnamep++ = c;
			} else {
				/* not short */
				if (enable_long_filenames)
					return (EINVAL);
			}
		} while ((c = *namep++) != '\0' && c != '.');
	}
	while (n-- > 0) {		/* fill with blanks */
		*fnamep++ = ' ';
	}
	/*
	 * remainder is extension
	 */
	n = PCFEXTSIZE;
	if (c == '.') {
		while ((c = *namep++) != '\0' && n--) {
			c = toupper(c);
			if (!pc_validchar(c))
				return (EINVAL);
			*fextp++ = c;
		}
		if (enable_long_filenames && (c != '\0')) {
			/* not short */
			return (EINVAL);
		}
	}
	while (n-- > 0) {		/* fill with blanks */
		*fextp++ = ' ';
	}
	return (0);
}

/*
 * Match a long filename entry with 'namep'. Also return failure
 * if the long filename isn't valid.
 */
int
pc_match_long_fn(struct pcnode *pcp, char *namep, struct pcdir **epp,
    struct pcslot *slotp, offset_t *offset)
{
	struct pcdir *ep = (struct pcdir *)*epp;
	struct vnode *vp = PCTOV(pcp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int	error = 0;
	char	lfn[PCMAXNAMLEN+1];

	error = pc_extract_long_fn(pcp, lfn, epp, offset, &slotp->sl_bp);
	if (error) {
		if (error == EINVAL) {
			return (ENOENT);
		} else
			return (error);
	}
	ep = *epp;
	if ((u8_strcmp(lfn, namep, 0, U8_STRCMP_CI_UPPER,
	    U8_UNICODE_LATEST, &error) == 0) && (error == 0)) {
		/* match */
		slotp->sl_flags = 0;
		slotp->sl_blkno = pc_daddrdb(fsp, slotp->sl_bp->b_blkno);
		slotp->sl_offset = pc_blkoff(fsp, *offset);
		slotp->sl_ep = ep;
		return (0);
	}
	*offset += sizeof (struct pcdir);
	ep++;
	*epp = ep;
	/* If u8_strcmp detected an error it's sufficient to rtn ENOENT */
	return (ENOENT);
}

/*
 * Match a short filename entry with namep.
 */
int
pc_match_short_fn(struct pcnode *pcp, char *namep, struct pcdir **epp,
    struct pcslot *slotp, offset_t *offset)
{
	char fname[PCFNAMESIZE];
	char fext[PCFEXTSIZE];
	struct pcdir *ep = *epp;
	int	error;
	struct vnode *vp = PCTOV(pcp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int boff = pc_blkoff(fsp, *offset);

	if (PCA_IS_HIDDEN(fsp, ep->pcd_attr)) {
		*offset += sizeof (struct pcdir);
		ep++;
		*epp = ep;
		return (ENOENT);
	}

	error = pc_parsename(namep, fname, fext);
	if (error) {
		*offset += sizeof (struct pcdir);
		ep++;
		*epp = ep;
		return (error);
	}

	if ((bcmp(fname, ep->pcd_filename, PCFNAMESIZE) == 0) &&
	    (bcmp(fext, ep->pcd_ext, PCFEXTSIZE) == 0)) {
		/*
		 * found the file
		 */
		if (fname[0] == '.') {
			if (fname[1] == '.')
				slotp->sl_flags = SL_DOTDOT;
			else
				slotp->sl_flags = SL_DOT;
		} else {
			slotp->sl_flags = 0;
		}
		slotp->sl_blkno =
		    pc_daddrdb(fsp, slotp->sl_bp->b_blkno);
		slotp->sl_offset = boff;
		slotp->sl_ep = ep;
		return (0);
	}
	*offset += sizeof (struct pcdir);
	ep++;
	*epp = ep;
	return (ENOENT);
}

/*
 * Remove a long filename entry starting at lfn_offset. It must be
 * a valid entry or we wouldn't have gotten here. Also remove the
 * short filename entry.
 */
static int
pc_remove_long_fn(struct pcnode *pcp, offset_t lfn_offset)
{
	struct vnode *vp = PCTOV(pcp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int boff;
	struct buf *bp = NULL;
	struct pcdir *ep = NULL;
	int	error = 0;

	/*
	 * if we're in here, we know that the lfn is in the proper format
	 * of <series-of-lfn-entries> followed by <sfn-entry>
	 */
	for (;;) {
		boff = pc_blkoff(fsp, lfn_offset);
		if (boff == 0 || bp == NULL || boff >= bp->b_bcount) {
			if (bp != NULL) {
				bwrite2(bp);
				error = geterror(bp);
				brelse(bp);
				if (error)
					return (error);
				bp = NULL;
			}
			error = pc_blkatoff(pcp, lfn_offset, &bp, &ep);
			if (error)
				return (error);
		}
		if (!PCDL_IS_LFN(ep)) {
			/* done */
			break;
		}
		/* zap it */
		ep->pcd_filename[0] = PCD_ERASED;
		ep->pcd_attr = 0;
		lfn_offset += sizeof (struct pcdir);
		ep++;
	}
	/* now we're on the short entry */

	ep->pcd_filename[0] = PCD_ERASED;
	ep->pcd_attr = 0;

	if (bp != NULL) {
		bwrite2(bp);
		error = geterror(bp);
		brelse(bp);
		if (error)
			return (error);
	}
	return (0);
}

/*
 * Find (and allocate) space in the directory denoted by
 * 'pcp'. for 'ndirentries' pcdir structures.
 * Return the offset at which to start, or -1 for failure.
 */
static offset_t
pc_find_free_space(struct pcnode *pcp, int ndirentries)
{
	offset_t offset = 0;
	offset_t spaceneeded = ndirentries * sizeof (struct pcdir);
	offset_t spaceoffset;
	offset_t spaceavail = 0;
	int boff;
	struct buf *bp = NULL;
	struct vnode *vp = PCTOV(pcp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	struct pcdir *ep;
	int	error;

	spaceoffset = offset;
	while (spaceneeded > spaceavail) {
		/*
		 * If offset is on a block boundary,
		 * read in the next directory block.
		 * Release previous if it exists.
		 */
		boff = pc_blkoff(fsp, offset);
		if (boff == 0 || bp == NULL || boff >= bp->b_bcount) {
			if (bp != NULL) {
				brelse(bp);
				bp = NULL;
			}
			error = pc_blkatoff(pcp, offset, &bp, &ep);
			if (error == ENOENT) {
				daddr_t bn;

				/* extend directory */
				if (!IS_FAT32(fsp) && (vp->v_flag & VROOT))
					return (-1);
				while (spaceneeded > spaceavail) {
					error = pc_balloc(pcp,
					    pc_lblkno(fsp, offset), 1, &bn);
					if (error)
						return (-1);
					pcp->pc_size += fsp->pcfs_clsize;
					spaceavail += fsp->pcfs_clsize;
					offset += fsp->pcfs_clsize;
				}
				return (spaceoffset);
			}
			if (error)
				return (-1);
		}
		if ((ep->pcd_filename[0] == PCD_UNUSED) ||
		    (ep->pcd_filename[0] == PCD_ERASED)) {
			offset += sizeof (struct pcdir);
			spaceavail += sizeof (struct pcdir);
			ep++;
			continue;
		}
		offset += sizeof (struct pcdir);
		spaceavail = 0;
		spaceoffset = offset;
		ep++;
	}
	if (bp != NULL) {
		brelse(bp);
	}
	return (spaceoffset);
}

/*
 * Return how many long filename entries are needed.
 * A maximum of PCLFNCHUNKSIZE characters per entry, plus one for a
 * short filename.
 */
static int
direntries_needed(struct pcnode *dp, char *namep)
{
	struct pcdir ep;
	uint16_t *w2_str;
	size_t  u8l, u16l;
	int ret;

	if (enable_long_filenames == 0) {
		return (1);
	}
	if (pc_is_short_file_name(namep, 0)) {
		(void) pc_parsename(namep, ep.pcd_filename, ep.pcd_ext);
		if (!shortname_exists(dp, ep.pcd_filename, ep.pcd_ext)) {
			return (1);
		}
	}
	if (pc_valid_long_fn(namep, 1)) {
		/*
		 * convert to UTF-16 or UNICODE for calculating the entries
		 * needed. Conversion will consume at the most 512 bytes
		 */
		u16l = PCMAXNAMLEN + 1;
		w2_str = (uint16_t *)kmem_zalloc(PCMAXNAM_UTF16, KM_SLEEP);
		u8l = strlen(namep);
		ret = uconv_u8tou16((const uchar_t *)namep, &u8l,
		    w2_str, &u16l, UCONV_OUT_LITTLE_ENDIAN);
		kmem_free((caddr_t)w2_str, PCMAXNAM_UTF16);
		if (ret == 0) {
			ret = 1 + u16l / PCLFNCHUNKSIZE;
			if (u16l % PCLFNCHUNKSIZE != 0)
				ret++;
			return (ret);
		}
	}
	return (-1);
}

/*
 * Allocate and return an array of pcdir structures for the passed-in
 * name. ndirentries tells how many are required (including the short
 * filename entry). Just allocate and fill them in properly here so they
 * can be written out.
 */
static struct pcdir *
pc_name_to_pcdir(struct pcnode *dp, char *namep, int ndirentries, int *errret)
{
	struct pcdir *bpcdir;
	struct pcdir *ep;
	struct pcdir_lfn *lep;
	int	i;
	uchar_t	cksum;
	int	nchars;
	int	error = 0;
	char	*nameend;
	uint16_t *w2_str;
	size_t  u8l, u16l;
	int ret;

	bpcdir = kmem_zalloc(ndirentries * sizeof (struct pcdir), KM_SLEEP);
	ep = &bpcdir[ndirentries - 1];
	if (ndirentries == 1) {
		(void) pc_parsename(namep, ep->pcd_filename, ep->pcd_ext);
		return (bpcdir);
	}

	/* Here we need to convert to UTF-16 or UNICODE for writing */

	u16l = PCMAXNAMLEN + 1;
	w2_str = (uint16_t *)kmem_zalloc(PCMAXNAM_UTF16, KM_SLEEP);
	u8l = strlen(namep);
	ret = uconv_u8tou16((const uchar_t *)namep, &u8l, w2_str, &u16l,
	    UCONV_OUT_LITTLE_ENDIAN);
	if (ret != 0) {
		kmem_free((caddr_t)w2_str, PCMAXNAM_UTF16);
		*errret = ret;
		return (NULL);
	}
	nameend = (char *)(w2_str + u16l);
	u16l %= PCLFNCHUNKSIZE;
	if (u16l != 0) {
		nchars = u16l + 1;
		nameend += 2;
	} else {
		nchars = PCLFNCHUNKSIZE;
	}
	nchars *= sizeof (uint16_t);

	/* short file name */
	error = generate_short_name(dp, namep, ep);
	if (error) {
		kmem_free(bpcdir, ndirentries * sizeof (struct pcdir));
		*errret = error;
		return (NULL);
	}
	cksum = pc_checksum_long_fn(ep->pcd_filename, ep->pcd_ext);
	for (i = 0; i < (ndirentries - 1); i++) {
		/* long file name */
		nameend -= nchars;
		lep = (struct pcdir_lfn *)&bpcdir[i];
		set_long_fn_chunk(lep, nameend, nchars);
		lep->pcdl_attr = PCDL_LFN_BITS;
		lep->pcdl_checksum = cksum;
		lep->pcdl_ordinal = (uchar_t)(ndirentries - i - 1);
		nchars = PCLFNCHUNKSIZE * sizeof (uint16_t);
	}
	kmem_free((caddr_t)w2_str, PCMAXNAM_UTF16);
	lep = (struct pcdir_lfn *)&bpcdir[0];
	lep->pcdl_ordinal |= 0x40;
	return (bpcdir);
}

static int
generate_short_name(struct pcnode *dp, char *namep, struct pcdir *inep)
{
	int	rev;
	int	nchars;
	int	i, j;
	char	*dot = NULL;
	char	fname[PCFNAMESIZE+1];
	char	fext[PCFEXTSIZE+1];
	char	scratch[8];
	int	error = 0;
	struct	pcslot slot;
	char	shortname[20];
	int	force_tilde = 0;

	/*
	 * generate a unique short file name based on the long input name.
	 *
	 * Say, for "This is a very long filename.txt" generate
	 * "THISIS~1.TXT", or "THISIS~2.TXT" if that's already there.
	 * Skip invalid short name characters in the long name, plus
	 * a couple NT skips (space and reverse backslash).
	 *
	 * Unfortunately, since this name would be hidden by the normal
	 * lookup routine, we need to look for it ourselves. But luckily
	 * we don't need to look at the lfn entries themselves.
	 */
	force_tilde = !pc_is_short_file_name(namep, 1);

	/*
	 * Strip off leading invalid characters.
	 * We need this because names like '.login' are now ok, but the
	 * short name needs to be something like LOGIN~1.
	 */
	for (; *namep != '\0'; namep++) {
		if (*namep == ' ')
			continue;
		if (!pc_validchar(*namep) && !pc_validchar(toupper(*namep)))
			continue;
		break;
	}
	dot = strrchr(namep, '.');
	if (dot != NULL) {
		dot++;
		for (j = 0, i = 0; j < PCFEXTSIZE; i++) {
			if (dot[i] == '\0')
				break;
			/* skip valid, but not generally good characters */
			if (dot[i] == ' ' || dot[i] == '\\')
				continue;
			if (pc_validchar(dot[i]))
				fext[j++] = dot[i];
			else if (pc_validchar(toupper(dot[i])))
				fext[j++] = toupper(dot[i]);
		}
		for (i = j; i < PCFEXTSIZE; i++)
			fext[i] = ' ';
		dot--;
	} else {
		for (i = 0; i < PCFEXTSIZE; i++) {
			fext[i] = ' ';
		}
	}
	/*
	 * We know we're a long name, not a short name (or we wouldn't
	 * be here at all. But if uppercasing ourselves would be a short
	 * name, then we can possibly avoid the ~N format.
	 */
	if (!force_tilde)
		rev = 0;
	else
		rev = 1;
	for (;;) {
		bzero(fname, sizeof (fname));
		nchars = PCFNAMESIZE;
		if (rev) {
			nchars--; /* ~ */
			i = rev;
			do {
				nchars--;
				i /= 10;
			} while (i);
			if (nchars <= 0) {
				return (ENOSPC);
			}
		}
		for (j = 0, i = 0; j < nchars; i++) {
			if ((&namep[i] == dot) || (namep[i] == '\0'))
				break;
			/* skip valid, but not generally good characters */
			if (namep[i] == ' ' || namep[i] == '\\')
				continue;
			if (pc_validchar(namep[i]))
				fname[j++] = namep[i];
			else if (pc_validchar(toupper(namep[i])))
				fname[j++] = toupper(namep[i]);
		}
		if (rev) {
			(void) sprintf(scratch, "~%d", rev);
			(void) strcat(fname, scratch);
		}
		for (i = strlen(fname); i < PCFNAMESIZE; i++)
			fname[i] = ' ';
		/* now see if it exists */
		(void) pc_fname_ext_to_name(shortname, fname, fext, 0);
		error = pc_findentry(dp, shortname, &slot, NULL);
		if (error == 0) {
			/* found it */
			brelse(slot.sl_bp);
			rev++;
			continue;
		}
		if (!shortname_exists(dp, fname, fext))
			break;
		rev++;
	}
	(void) strncpy(inep->pcd_filename, fname, PCFNAMESIZE);
	(void) strncpy(inep->pcd_ext, fext, PCFEXTSIZE);
	return (0);
}

/*
 * Returns 1 if the passed-in filename is a short name, 0 if not.
 */
static int
pc_is_short_file_name(char *namep, int foldcase)
{
	int	i;
	char	c;

	for (i = 0; i < PCFNAMESIZE; i++, namep++) {
		if (*namep == '\0')
			return (1);
		if (*namep == '.')
			break;
		if (foldcase)
			c = toupper(*namep);
		else
			c = *namep;
		if (!pc_validchar(c))
			return (0);
	}
	if (*namep == '\0')
		return (1);
	if (*namep != '.')
		return (0);
	namep++;
	for (i = 0; i < PCFEXTSIZE; i++, namep++) {
		if (*namep == '\0')
			return (1);
		if (foldcase)
			c = toupper(*namep);
		else
			c = *namep;
		if (!pc_validchar(c))
			return (0);
	}
	/* we should be done. If not... */
	if (*namep == '\0')
		return (1);
	return (0);

}

/*
 * We call this when we want to see if a short filename already exists
 * in the filesystem as part of a long filename. When creating a short
 * name (FILENAME.TXT from the user, or when generating one for a long
 * filename), we cannot allow one that is part of a long filename.
 * pc_findentry will find all the names that are visible (long or short),
 * but will not crack any long filename entries.
 */
static int
shortname_exists(struct pcnode *dp, char *fname, char *fext)
{
	struct buf *bp = NULL;
	int	offset = 0;
	int	match = 0;
	struct pcdir *ep;
	struct vnode *vp = PCTOV(dp);
	struct pcfs *fsp = VFSTOPCFS(vp->v_vfsp);
	int	boff;
	int	error = 0;

	for (;;) {
		boff = pc_blkoff(fsp, offset);
		if (boff == 0 || bp == NULL || boff >= bp->b_bcount) {
			if (bp != NULL) {
				brelse(bp);
				bp = NULL;
			}
			error = pc_blkatoff(dp, offset, &bp, &ep);
			if (error == ENOENT)
				break;
			if (error) {
				return (1);
			}
		}
		if (PCDL_IS_LFN(ep) ||
		    (ep->pcd_filename[0] == PCD_ERASED)) {
			offset += sizeof (struct pcdir);
			ep++;
			continue;
		}
		if (ep->pcd_filename[0] == PCD_UNUSED)
			break;
		/*
		 * in use, and a short file name (either standalone
		 * or associated with a long name
		 */
		if ((bcmp(fname, ep->pcd_filename, PCFNAMESIZE) == 0) &&
		    (bcmp(fext, ep->pcd_ext, PCFEXTSIZE) == 0)) {
			match = 1;
			break;
		}
		offset += sizeof (struct pcdir);
		ep++;
	}
	if (bp) {
		brelse(bp);
		bp = NULL;
	}
	return (match);
}

pc_cluster32_t
pc_getstartcluster(struct pcfs *fsp, struct pcdir *ep)
{
	if (IS_FAT32(fsp)) {
		pc_cluster32_t cn;
		pc_cluster16_t hi16;
		pc_cluster16_t lo16;

		hi16 = ltohs(ep->un.pcd_scluster_hi);
		lo16 = ltohs(ep->pcd_scluster_lo);
		cn = (hi16 << 16) | lo16;
		return (cn);
	} else {
		return (ltohs(ep->pcd_scluster_lo));
	}
}

void
pc_setstartcluster(struct pcfs *fsp, struct pcdir *ep, pc_cluster32_t cln)
{
	if (IS_FAT32(fsp)) {
		pc_cluster16_t hi16;
		pc_cluster16_t lo16;

		hi16 = (cln >> 16) & 0xFFFF;
		lo16 = cln & 0xFFFF;
		ep->un.pcd_scluster_hi = htols(hi16);
		ep->pcd_scluster_lo = htols(lo16);
	} else {
		pc_cluster16_t cln16;

		cln16 = (pc_cluster16_t)cln;
		ep->pcd_scluster_lo = htols(cln16);
	}
}
