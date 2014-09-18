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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/fbuf.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/policy.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/page.h>
#include <sys/swap.h>


#include <fs/fs_subr.h>


#include <sys/fs/udf_volume.h>
#include <sys/fs/udf_inode.h>


struct slot {
	enum	{NONE, COMPACT, FOUND, EXIST} status;
	off_t	offset;		/* offset of area with free space */
	int	size;		/* size of area at slotoffset */
	struct	fbuf *fbp;	/* dir buf where slot is */
	struct file_id *ep;	/* pointer to slot */
	off_t	endoff;		/* last useful location found in search */
};


int32_t ud_dircheckforname(struct ud_inode *, char *, int,
		struct slot *, struct ud_inode **, uint8_t *, struct cred *);
int32_t ud_dirempty(struct ud_inode *, uint64_t, struct cred *);
int32_t str2cmp(char *, int32_t, char *, int32_t, char *, int32_t);
int32_t ud_dircheckpath(int32_t, struct ud_inode *, struct cred *);
int32_t ud_dirmakeinode(struct ud_inode *, struct ud_inode **,
	struct vattr *, enum de_op, struct cred *);
int32_t ud_diraddentry(struct ud_inode *, char *,
	enum de_op, int, struct slot *, struct ud_inode *,
	struct ud_inode *, struct cred *);
int32_t ud_dirmakedirect(struct ud_inode *, struct ud_inode *, struct cred *);
int32_t ud_dirrename(struct ud_inode *, struct ud_inode *,
	struct ud_inode *, struct ud_inode *, char *, uint8_t *,
	struct slot *, struct cred *);
int32_t ud_dirprepareentry(struct ud_inode *,
	struct slot *, uint8_t *, struct cred *);
int32_t ud_dirfixdotdot(struct ud_inode *, struct ud_inode *,
		struct ud_inode *);
int32_t ud_write_fid(struct ud_inode *, struct slot *, uint8_t *);

int
ud_dirlook(struct ud_inode *dip,
	char *namep, struct ud_inode **ipp, struct cred *cr, int32_t skipdnlc)
{
	struct udf_vfs *udf_vfsp;
	int32_t error = 0, namelen, adhoc_search;
	u_offset_t offset, adhoc_offset, dirsize, end;
	struct vnode *dvp, *vp;
	struct fbuf *fbp;
	struct file_id *fid;
	uint8_t *fname, dummy[3];
	int32_t id_len, doingchk;
	uint32_t old_loc;
	uint16_t old_prn;

	uint8_t *dname;
	uint8_t *buf = NULL;

	ud_printf("ud_dirlook\n");

	udf_vfsp = dip->i_udf;

restart:
	doingchk = 0;
	old_prn = 0xFFFF;
	old_loc = 0;
	dvp = ITOV(dip);
	/*
	 * Check accessibility of directory.
	 */
	if (dip->i_type != VDIR) {
		return (ENOTDIR);
	}
	if (error = ud_iaccess(dip, IEXEC, cr, 1)) {
		return (error);
	}

	/*
	 * Null component name is synonym for directory being searched.
	 */
	if (*namep == '\0') {
		VN_HOLD(dvp);
		*ipp = dip;
		return (0);
	}
	namelen = strlen(namep);
	if ((namelen == 1) &&
	    (namep[0] == '.') && (namep[1] == '\0')) {
		/* Current directory */
		VN_HOLD(dvp);
		*ipp = dip;
		dnlc_enter(dvp, namep, ITOV(*ipp));
		return (0);
	}

	if ((!skipdnlc) && (vp = dnlc_lookup(dvp, namep))) {
		/* vp is already held from dnlc_lookup */

		*ipp = VTOI(vp);
		return (0);
	}

	dname = kmem_zalloc(1024, KM_SLEEP);
	buf = kmem_zalloc(udf_vfsp->udf_lbsize, KM_SLEEP);

	/*
	 * Read lock the inode we are searching.  You will notice that we
	 * didn't hold the read lock while searching the dnlc.  This means
	 * that the entry could now be in the dnlc.  This doesn't cause any
	 * problems because dnlc_enter won't add an entry if it is already
	 * there.
	 */
	rw_enter(&dip->i_rwlock, RW_READER);

	/*
	 * Take care to look at dip->i_diroff only once, as it
	 * may be changing due to other threads/cpus.
	 */

recheck:
	offset = dip->i_diroff;
	end = dirsize = dip->i_size;

	if (offset > dirsize) {
		offset = 0;
	}
	adhoc_offset = offset;
	adhoc_search = (offset == 0) ? 1 : 2;

	fbp = NULL;

	while (adhoc_search--) {
		while (offset < end) {
			error = ud_get_next_fid(dip, &fbp,
			    offset, &fid, &fname, buf);
			if (error != 0) {
				break;
			}
			if ((fid->fid_flags & FID_DELETED) == 0) {
				if (fid->fid_flags & FID_PARENT) {
					id_len = 2;
					fname = dummy;
					dummy[0] = '.';
					dummy[1] = '.';
					dummy[2] = '\0';
				} else {
					if ((error = ud_uncompress(
					    fid->fid_idlen, &id_len,
					    fname, dname)) != 0) {
						break;
					}
					fname = (uint8_t *)dname;
					fname[id_len] = '\0';
				}
				if ((namelen == id_len) &&
				    (strncmp(namep, (caddr_t)fname,
				    namelen) == 0)) {
					uint32_t loc;
					uint16_t prn;


					loc = SWAP_32(fid->fid_icb.lad_ext_loc);
					prn = SWAP_16(fid->fid_icb.lad_ext_prn);
					dip->i_diroff = offset + FID_LEN(fid);

					if (doingchk) {
						if ((loc == old_loc) &&
						    (prn == old_prn)) {
							goto checkok;
						} else {
							if (fbp != NULL) {
								fbrelse(fbp,
								    S_READ);
								fbp = NULL;
							}
							VN_RELE(ITOV(*ipp));
							rw_exit(&dip->i_rwlock);
							goto restart;
						}
						/* NOTREACHED */
					}

					if (namelen == 2 &&
					    fname[0] == '.' &&
					    fname[1] == '.') {

						struct timespec32 omtime;

						omtime = dip->i_mtime;
						rw_exit(&dip->i_rwlock);

						error = ud_iget(dip->i_vfs, prn,
						    loc, ipp, NULL, cr);

						rw_enter(&dip->i_rwlock,
						    RW_READER);

						if (error) {
							goto done;
						}

						if ((omtime.tv_sec !=
						    dip->i_mtime.tv_sec) ||
						    (omtime.tv_nsec !=
						    dip->i_mtime.tv_nsec)) {

							doingchk = 1;
							old_prn = prn;
							old_loc = loc;
							dip->i_diroff = 0;
							if (fbp != NULL) {
								fbrelse(fbp,
								    S_READ);
								fbp = NULL;
							}
							goto recheck;
						}
					} else {

						error = ud_iget(dip->i_vfs, prn,
						    loc, ipp, NULL, cr);
					}
checkok:
					if (error == 0) {
						dnlc_enter(dvp, namep,
						    ITOV(*ipp));
					}
					goto done;
				}
			}
			offset += FID_LEN(fid);
		}
		if (fbp != NULL) {
			fbrelse(fbp, S_READ);
			fbp = NULL;
		}
		end = adhoc_offset;
		offset = 0;
	}
	error = ENOENT;
done:
	kmem_free(buf, udf_vfsp->udf_lbsize);
	kmem_free(dname, 1024);
	if (fbp != NULL) {
		fbrelse(fbp, S_READ);
	}
	rw_exit(&dip->i_rwlock);
	return (error);
}

int
ud_direnter(
	struct ud_inode *tdp,
	char *namep,
	enum de_op op,
	struct ud_inode *sdp,
	struct ud_inode *sip,
	struct vattr *vap,
	struct ud_inode **ipp,
	struct cred *cr,
	caller_context_t *ctp)
{
	struct udf_vfs *udf_vfsp;
	struct ud_inode *tip;
	struct slot slot;
	int32_t namlen, err;
	char *s;

	uint8_t *buf = NULL;

	ud_printf("ud_direnter\n");

	udf_vfsp = tdp->i_udf;
	/* don't allow '/' characters in pathname component */
	for (s = namep, namlen = 0; *s; s++, namlen++) {
		if (*s == '/') {
			return (EACCES);
		}
	}

	if (namlen == 0) {
		cmn_err(CE_WARN, "name length == 0 in ud_direnter");
		return (EINVAL);
	}

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
		if (ipp) {
			/*
			 * ud_dirlook will acquire the i_rwlock
			 */
			rw_exit(&tdp->i_rwlock);
			if (err = ud_dirlook(tdp, namep, ipp, cr, 0)) {
				rw_enter(&tdp->i_rwlock, RW_WRITER);
				return (err);
			}
			rw_enter(&tdp->i_rwlock, RW_WRITER);
		}
		return (EEXIST);
	}

	tip = NULL;
	slot.status = NONE;
	slot.offset = 0;
	slot.size = 0;
	slot.fbp = NULL;
	slot.ep = NULL;
	slot.endoff = 0;

	/*
	 * For link and rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.  If not, we
	 * increment the link count and force the inode to disk to make sure
	 * that it is there before any directory entry that points to it.
	 */
	if (op == DE_LINK || op == DE_RENAME) {
		rw_enter(&sip->i_contents, RW_WRITER);
		if (sip->i_nlink == 0) {
			rw_exit(&sip->i_contents);
			return (ENOENT);
		}
		if (sip->i_nlink == MAXLINK) {
			rw_exit(&sip->i_contents);
			return (EMLINK);
		}

		sip->i_nlink++;
		mutex_enter(&sip->i_tlock);
		sip->i_flag |= ICHG;
		mutex_exit(&sip->i_tlock);
		ud_iupdat(sip, 1);
		rw_exit(&sip->i_contents);
	}
	/*
	 * If target directory has not been removed, then we can consider
	 * allowing file to be created.
	 */
	if (tdp->i_nlink == 0) {
		err = ENOENT;
		goto out2;
	}
	/*
	 * Check accessibility of directory.
	 */
	if (tdp->i_type != VDIR) {
		err = ENOTDIR;
		goto out2;
	}
	/*
	 * Execute access is required to search the directory.
	 */
	if (err = ud_iaccess(tdp, IEXEC, cr, 1)) {
		goto out2;
	}
	/*
	 * If this is a rename of a directory and the parent is
	 * different (".." must be changed), then the source
	 * directory must not be in the directory hierarchy
	 * above the target, as this would orphan everything
	 * below the source directory.  Also the user must have
	 * write permission in the source so as to be able to
	 * change "..".
	 */
	if (op == DE_RENAME) {
		if (sip == tdp) {
			err = EINVAL;
			goto out2;
		}
		rw_enter(&sip->i_contents, RW_READER);
		if ((sip->i_type == VDIR) && (sdp != tdp)) {
			uint32_t blkno;

			if ((err = ud_iaccess(sip, IWRITE, cr, 0))) {
				rw_exit(&sip->i_contents);
				goto out2;
			}
			blkno = sip->i_icb_lbano;
			rw_exit(&sip->i_contents);
			if ((err = ud_dircheckpath(blkno, tdp, cr))) {
				goto out2;
			}
		} else {
			rw_exit(&sip->i_contents);
		}
	}

	/*
	 * Search for the entry. Return VN_HELD tip if found.
	 */
	buf = kmem_zalloc(udf_vfsp->udf_lbsize, KM_SLEEP);
	rw_enter(&tdp->i_contents, RW_WRITER);
	if (err = ud_dircheckforname(tdp,
	    namep, namlen, &slot, &tip, buf, cr)) {
		goto out;
	}
	if (tip) {
		switch (op) {
			case DE_CREATE :
			case DE_MKDIR :
				if (ipp) {
					*ipp = tip;
					err = EEXIST;
				} else {
					VN_RELE(ITOV(tip));
				}
				break;
			case DE_RENAME :
				err = ud_dirrename(sdp, sip, tdp, tip,
				    namep, buf, &slot, cr);
				/*
				 * We used to VN_RELE() here, but this
				 * was moved down so that we could send
				 * a vnevent after the locks were dropped.
				 */
				break;
			case DE_LINK :
				/*
				 * Can't link to an existing file.
				 */
				VN_RELE(ITOV(tip));
				err = EEXIST;
				break;
		}
	} else {
		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created.
		 */
		if (err = ud_iaccess(tdp, IWRITE, cr, 0)) {
			goto out;
		}
		if ((op == DE_CREATE) || (op == DE_MKDIR)) {
			/*
			 * Make new inode and directory entry as required.
			 */
			if (err = ud_dirmakeinode(tdp, &sip, vap, op, cr))
				goto out;
		}
		if (err = ud_diraddentry(tdp, namep, op,
		    namlen, &slot, sip, sdp, cr)) {
			if ((op == DE_CREATE) || (op == DE_MKDIR)) {
				/*
				 * Unmake the inode we just made.
				 */
				rw_enter(&sip->i_contents, RW_WRITER);
				if (sip->i_type == VDIR) {
					tdp->i_nlink--;
				}
				sip->i_nlink = 0;
				mutex_enter(&sip->i_tlock);
				sip->i_flag |= ICHG;
				mutex_exit(&sip->i_tlock);
				rw_exit(&sip->i_contents);
				VN_RELE(ITOV(sip));
				sip = NULL;
			}
		} else if (ipp) {
			*ipp = sip;
		} else if ((op == DE_CREATE) || (op == DE_MKDIR)) {
			VN_RELE(ITOV(sip));
		}
	}
out:
	if (buf != NULL) {
		kmem_free(buf, udf_vfsp->udf_lbsize);
	}
	if (slot.fbp) {
		fbrelse(slot.fbp, S_OTHER);
	}
	rw_exit(&tdp->i_contents);

	if (op == DE_RENAME) {
		/*
		 * If it's all good, send events after locks are dropped
		 * but before vnodes are released.
		 */
		if (err == 0) {
			if (tip) {
				vnevent_rename_dest(ITOV(tip), ITOV(tdp),
				    namep, ctp);
			}

			vnevent_rename_dest_dir(ITOV(tdp), ITOV(tip),
			    namep, ctp);
		}

		/*
		 * The following VN_RELE() was moved from the
		 * DE_RENAME case above
		 */
		if (tip) {
			VN_RELE(ITOV(tip));
		}
	}

out2:
	if (err && ((op == DE_LINK) || (op == DE_RENAME))) {
		/*
		 * Undo bumped link count.
		 */
		rw_enter(&sip->i_contents, RW_WRITER);
		sip->i_nlink--;
		rw_exit(&sip->i_contents);

		mutex_enter(&sip->i_tlock);
		sip->i_flag |= ICHG;
		mutex_exit(&sip->i_tlock);
	}
	return (err);
}

/*
 * Locking i_contents in this
 * function seems to be really weird
 */
int
ud_dirremove(
	struct ud_inode *dp,
	char *namep,
	struct ud_inode *oip,
	struct vnode *cdir,
	enum dr_op op,
	struct cred *cr,
	caller_context_t *ctp)
{
	struct udf_vfs *udf_vfsp;
	int32_t namelen, err = 0;
	struct slot slot;
	struct ud_inode *ip;
	mode_t mode;
	struct file_id *fid;
	uint8_t *buf = NULL;
	uint32_t tbno;

	ud_printf("ud_dirremove\n");

	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));

	udf_vfsp = dp->i_udf;
	namelen = (int)strlen(namep);
	if (namelen == 0) {
		cmn_err(CE_WARN, "name length == 0 in ud_dirremove");
		return (EINVAL);
	}

	/*
	 * return err when removing . and ..
	 */
	if (namep[0] == '.') {
		if (namelen == 1) {
			return (EINVAL);
		} else if (namelen == 2 && namep[1] == '.') {
			return (EEXIST);	/* SIGH should be ENOTEMPTY */
		}
	}

	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));

	/*
	 * Check accessibility of directory.
	 */
	if (dp->i_type != VDIR) {
		return (ENOTDIR);
	}

	ip = NULL;
	slot.status = FOUND;	/* don't need to look for empty slot */
	slot.offset = 0;
	slot.size = 0;
	slot.fbp = NULL;
	slot.ep = NULL;
	slot.endoff = 0;
	/*
	 * Execute access is required to search the directory.
	 * Access for write is interpreted as allowing
	 * deletion of files in the directory.
	 */
	if (err = ud_iaccess(dp, IEXEC|IWRITE, cr, 1)) {
		return (err);
	}

	buf = (uint8_t *)kmem_zalloc(udf_vfsp->udf_lbsize, KM_SLEEP);

	rw_enter(&dp->i_contents, RW_WRITER);

	if (err = ud_dircheckforname(dp, namep, namelen, &slot, &ip,
	    buf, cr)) {
		goto out_novfs;
	}
	if (ip == NULL) {
		err = ENOENT;
		goto out_novfs;
	}
	if (oip && oip != ip) {
		err = ENOENT;
		goto out_novfs;
	}

	if ((mode = ip->i_type) == VDIR) {
		/*
		 * vn_vfswlock() prevents races between mount and rmdir.
		 */
		if (vn_vfswlock(ITOV(ip))) {
			err = EBUSY;
			goto out_novfs;
		}
		if (vn_mountedvfs(ITOV(ip)) != NULL && op != DR_RENAME) {
			err = EBUSY;
			goto out;
		}
		/*
		 * If we are removing a directory, get a lock on it.
		 * If the directory is empty, it will stay empty until
		 * we can remove it.
		 */
		rw_enter(&ip->i_rwlock, RW_READER);
	}
	/* We must be holding i_contents */
	rw_enter(&ip->i_contents, RW_READER);

	if (err = ud_sticky_remove_access(dp, ip, cr)) {
		rw_exit(&ip->i_contents);
		if (mode == VDIR) {
			rw_exit(&ip->i_rwlock);
		}
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

		if (dp == ip || ITOV(ip) == cdir) {
			err = EINVAL;
		} else if (ip->i_type != VDIR) {
			err = ENOTDIR;
		} else if ((ip->i_nlink != 1) ||
		    (!ud_dirempty(ip, dp->i_uniqid, cr))) {
			/*
			 * Directories do not have an
			 * entry for "." so only one link
			 * will be there
			 */
			err = EEXIST;	/* SIGH should be ENOTEMPTY */
		}
		if (err) {
			rw_exit(&ip->i_contents);
			if (mode == VDIR) {
				rw_exit(&ip->i_rwlock);
			}
			goto out;
		}
	} else if (op == DR_REMOVE)  {
		/*
		 * unlink(2) requires a different check: allow only
		 * privileged processes to unlink a directory.
		 */
		struct vnode *vp = ITOV(ip);

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
	dnlc_remove(ITOV(dp), namep);

	/*
	 * We can collapse all the directory
	 * entries that are deleted into one big entry
	 * but the better way is to
	 * defer it till next directory entry
	 * creation. where we can do this
	 * in a more efficient way
	 */
	fid = slot.ep;

	/*
	 * If this is the last entry
	 * just truncate the file instead
	 * of marking it deleted
	 */
	if ((slot.offset + FID_LEN(fid)) == dp->i_size) {
		fbrelse(slot.fbp, S_OTHER);
		if ((err = ud_itrunc(dp, slot.offset, 0, cr)) != 0) {
			goto out;
		}
	} else {
		fid->fid_flags |= FID_DELETED;

		if ((err = ud_ip_off2bno(dp, slot.offset, &tbno)) != 0) {
			goto out;
		}

		ud_make_tag(dp->i_udf, &fid->fid_tag,
		    UD_FILE_ID_DESC, tbno, FID_LEN(fid));

		err = ud_write_fid(dp, &slot, buf);
	}

	slot.fbp = NULL;

	/*
	 * If we were removing a directory, it is 'gone' now so we can
	 * unlock it.
	 */
	if (mode == VDIR) {
		rw_exit(&ip->i_rwlock);
	}

	mutex_enter(&dp->i_tlock);
	dp->i_flag |= IUPD|ICHG;
	mutex_exit(&dp->i_tlock);
	mutex_enter(&ip->i_tlock);
	ip->i_flag |= ICHG;
	mutex_exit(&ip->i_tlock);

	if (err != 0) {
		goto out;
	}

	rw_enter(&ip->i_contents, RW_WRITER);

	/*
	 * Now dispose of the inode.
	 */
	if (ip->i_nlink > 0) {
		if ((op == DR_RMDIR) && (ip->i_type == VDIR)) {
			/*
			 * Decrement by 1 because there is no "."
			 * Clear the inode, but there may be other hard
			 * links so don't free the inode.
			 * Decrement the dp linkcount because we're
			 * trashing the ".." entry.
			 */
			ip->i_nlink --;
			dp->i_nlink--;
			dnlc_remove(ITOV(ip), ".");
			dnlc_remove(ITOV(ip), "..");
/*
 *			(void) ud_itrunc(ip, 0, 0, cr);
 */
		} else {
			ip->i_nlink--;
		}
	}
	ITIMES_NOLOCK(dp);
	ITIMES_NOLOCK(ip);
	rw_exit(&ip->i_contents);
out:
	if (mode == VDIR) {
		vn_vfsunlock(ITOV(ip));
	}
out_novfs:
	ASSERT(RW_WRITE_HELD(&dp->i_contents));

	if (slot.fbp != NULL) {
		fbrelse(slot.fbp, S_OTHER);
	}
	rw_exit(&dp->i_contents);

	if (ip) {
		/*
		 * If no errors, send any events after locks are dropped,
		 * but before the VN_RELE().
		 */
		if (err == 0) {
			if (op == DR_REMOVE) {
				vnevent_remove(ITOV(ip), ITOV(dp), namep, ctp);
			} else if (op == DR_RMDIR) {
				vnevent_rmdir(ITOV(ip), ITOV(dp), namep, ctp);
			}
		}
		VN_RELE(ITOV(ip));
	}

	kmem_free(buf, udf_vfsp->udf_lbsize);
	return (err);
}

int
ud_dircheckforname(struct ud_inode *tdp,
	char *namep, int32_t namelen, struct slot *slotp,
	struct ud_inode **ipp, uint8_t *buf, struct cred *cr)
{
	struct udf_vfs *udf_vfsp;
	uint32_t dirsize, offset;
	struct fbuf *fbp;
	struct file_id *fid;
	int32_t sz, error = 0, sz_req, matched = 0;
	uint8_t *nm;

	uint8_t *dname;
	int32_t id_len;

	ud_printf("ud_dircheckforname\n");

	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	fbp = NULL;

	dname = (uint8_t *)kmem_zalloc(1024, KM_SLEEP);

	udf_vfsp = tdp->i_udf;

	offset = 0;
	dirsize = tdp->i_size;

	if (slotp->status != FOUND) {
		int32_t temp;

		temp = 1024; /* set to size of dname allocated above */
		if ((error = ud_compress(namelen, &temp,
		    (uint8_t *)namep, dname)) != 0) {
			goto end;
		}
		sz_req = F_LEN + temp;
		sz_req  = (sz_req + 3) & ~3;
	}

	while (offset < dirsize) {
		if ((error = ud_get_next_fid(tdp, &fbp,
		    offset, &fid, &nm, buf)) != 0) {
			break;
		}
		if ((error = ud_uncompress(fid->fid_idlen,
		    &id_len, nm, dname)) != 0) {
			break;
		}
		if ((fid->fid_flags & FID_DELETED) == 0) {
			/* Check for name match */
			if (((namelen == id_len) &&
			    (strncmp(namep, (caddr_t)dname, namelen) == 0)) ||
			    ((fid->fid_flags & FID_PARENT) &&
			    (namep[0] == '.' &&
			    (namelen == 1 ||
			    (namelen == 2 && namep[1] == '.'))))) {

				tdp->i_diroff = offset;
				if ((fid->fid_flags & FID_PARENT) &&
				    (namelen == 1) && (namep[0] == '.')) {
					struct vnode *vp = ITOV(tdp);

					*ipp = tdp;
					VN_HOLD(vp);
				} else {
					uint16_t prn;
					uint32_t loc;

					prn = SWAP_16(fid->fid_icb.lad_ext_prn);
					loc = SWAP_32(fid->fid_icb.lad_ext_loc);
					if ((error = ud_iget(tdp->i_vfs, prn,
					    loc, ipp, NULL, cr)) != 0) {

						fbrelse(fbp, S_OTHER);
						goto end;
					}
				}
				slotp->status = EXIST;
				slotp->offset = offset;
				slotp->size = FID_LEN(fid);
				slotp->fbp = fbp;
				slotp->ep = fid;
				slotp->endoff = 0;
				goto end;
			}
		} else {
			/*
			 * see if we need to find an
			 * empty slot and the current slot
			 * matches
			 */
			if ((slotp->status != FOUND) || (matched == 0)) {
				sz = FID_LEN(fid);
				if (sz == sz_req) {
					slotp->status = FOUND;
					slotp->offset = offset;
					slotp->size = sz;
				}
				if (matched == 0) {
					if ((namelen == id_len) &&
					    (strncmp(namep, (caddr_t)dname,
					    namelen) == 0)) {
						matched = 1;
						slotp->status = FOUND;
						slotp->offset = offset;
						slotp->size = sz;
					}
				}
			}
		}
		offset += FID_LEN(fid);
	}
	if (fbp) {
		fbrelse(fbp, S_OTHER);
	}
	if (slotp->status == NONE) {
		/*
		 * We didn't find a slot; the new directory entry should be put
		 * at the end of the directory.  Return an indication of where
		 * this is, and set "endoff" to zero; since we're going to have
		 * to extend the directory, we're certainly not going to
		 * trucate it.
		 */
		slotp->offset = dirsize;
		if (tdp->i_desc_type == ICB_FLAG_ONE_AD) {
			slotp->size = tdp->i_max_emb - tdp->i_size;
		} else {
			slotp->size = udf_vfsp->udf_lbsize -
			    slotp->offset & udf_vfsp->udf_lbmask;
		}
		slotp->endoff = 0;
	}

	*ipp = NULL;
end:
	kmem_free((caddr_t)dname, 1024);
	return (error);
}

/*
 * Return 1 if the dir has all files
 * deleted except the parent
 * else return 0
 */
/* ARGSUSED */
int
ud_dirempty(struct ud_inode *ip, uint64_t ino, struct cred *cr)
{
	offset_t off;
	int32_t empty = 1, error, count, entry_len, rcount;
	struct file_id *fid;
	caddr_t addr;
	uint32_t tbno;
	int32_t	desc_len;

	ud_printf("ud_dirempty\n");

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	if (ip->i_size == 0) {
		return (empty);
	}

	desc_len = 1024;
	addr = kmem_zalloc(desc_len, KM_SLEEP);
	fid = (struct file_id *)addr;

	for (off = 0; off < ip->i_size; off += entry_len) {

		/*
		 * First read fid
		 * and verify checksum
		 */

		rcount = sizeof (struct file_id);
		error = ud_rdwri(UIO_READ, FREAD, ip, addr, rcount, off,
		    UIO_SYSSPACE, &count, cr);
		if ((error != 0) || (count != 0)) {
			empty = 0;
			break;
		}

		if ((error = ud_ip_off2bno(ip, off, &tbno)) != 0) {
			empty = 0;
			break;
		}

		/*
		 * We verify the tag id and also the FID_LEN.
		 * FID_LEN should be <= desc_len.
		 */
		if (ud_verify_tag_and_desc(&fid->fid_tag,
		    UD_FILE_ID_DESC,
		    tbno, 0, desc_len) != 0) {
		/* Corrupted directory */
			empty = 0;
			break;
		}

		/*
		 * Read the fid + iulen + len
		 * Now verify both checksum andCRC
		 */

		rcount = FID_LEN(fid);
		error = ud_rdwri(UIO_READ, FREAD, ip, addr, rcount, off,
		    UIO_SYSSPACE, &count, cr);
		if ((error != 0) || (count != 0)) {
			empty = 0;
			break;
		}
		/*
		 * Now that the entire decsriptor is read we verify the
		 * crc.
		 */
		if (ud_verify_tag_and_desc(&fid->fid_tag,
		    UD_FILE_ID_DESC,
		    tbno,
		    1, rcount) != 0) {
			/* Corrupted directory */
			empty = 0;
			break;
		}

		/*
		 * Is the file deleted
		 */

		if ((fid->fid_flags & FID_DELETED) == 0) {
			if ((fid->fid_flags & FID_PARENT) == 0) {
				empty = 0;
				break;
			}
		}
		entry_len = FID_LEN(fid);
	}

	kmem_free(addr, 1024);

	return (empty);
}


int
ud_dircheckpath(int32_t blkno,
	struct ud_inode *target, struct cred *cr)
{
	int32_t err = 0;
	struct vfs *vfsp;
	struct udf_vfs *udf_vfsp;
	struct fbuf *fbp;
	struct file_id *fid;
	struct ud_inode *ip, *tip;
	uint16_t prn;
	uint32_t lbno, dummy, tbno;
	daddr_t parent_icb_loc;

	ud_printf("ud_dircheckpath\n");

	udf_vfsp = target->i_udf;
	ip = target;

	ASSERT(udf_vfsp != NULL);
	ASSERT(MUTEX_HELD(&target->i_udf->udf_rename_lck));
	ASSERT(RW_WRITE_HELD(&ip->i_rwlock));

	if (ip->i_icb_lbano == blkno) {
		err = EINVAL;
		goto out;
	}
	if (ip->i_icb_lbano == udf_vfsp->udf_root_blkno) {
		goto out;
	}

	/*
	 * Search back through the directory tree, using the PARENT entries
	 * Fail any attempt to move a directory into an ancestor directory.
	 */
	for (;;) {
		if ((err = fbread(ITOV(ip), 0,
		    udf_vfsp->udf_lbsize, S_READ, &fbp)) != 0) {
			break;
		}

		if ((err = ud_ip_off2bno(ip, 0, &tbno)) != 0) {
			break;
		}
		fid = (struct file_id *)fbp->fb_addr;
		/* IS this a valid file_identifier */
		if (ud_verify_tag_and_desc(&fid->fid_tag,
		    UD_FILE_ID_DESC,
		    tbno,
		    1, udf_vfsp->udf_lbsize) != 0) {
			break;
		}
		if ((fid->fid_flags & FID_DELETED) != 0) {
			break;
		}
		if ((fid->fid_flags & FID_PARENT) == 0) {
			/*
			 * This cannot happen unless
			 * something is grossly wrong
			 * First entry has to be parent
			 */
			break;
		}
		prn = SWAP_16(fid->fid_icb.lad_ext_prn);
		lbno = SWAP_32(fid->fid_icb.lad_ext_loc);
		parent_icb_loc =
		    ud_xlate_to_daddr(udf_vfsp, prn, lbno, 1, &dummy);
		ASSERT(dummy == 1);
		if (parent_icb_loc == blkno) {
			err = EINVAL;
			break;
		}
		vfsp = ip->i_vfs;
		udf_vfsp = ip->i_udf;
		if (parent_icb_loc == udf_vfsp->udf_root_blkno) {
			break;
		}
		if (fbp != NULL) {
			fbrelse(fbp, S_OTHER);
			fbp = NULL;
		}
		if (ip != target) {
			rw_exit(&ip->i_rwlock);
			VN_RELE(ITOV(ip));
		}

		/*
		 * Race to get the inode.
		 */
		if (err = ud_iget(vfsp, prn, lbno, &tip, NULL, cr)) {
			ip = NULL;
			break;
		}
		ip = tip;
		rw_enter(&ip->i_rwlock, RW_READER);
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
ud_dirmakeinode(struct ud_inode *tdp, struct ud_inode **ipp,
	struct vattr *vap, enum de_op op, struct cred *cr)
{
	struct ud_inode *ip;
	int32_t error;

	ASSERT(vap != NULL);
	ASSERT(op == DE_CREATE || op == DE_MKDIR);
	ASSERT((vap->va_mask & (AT_TYPE|AT_MODE)) == (AT_TYPE|AT_MODE));
	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));

	/*
	 * Allocate a new inode.
	 */
	if ((error = ud_ialloc(tdp, &ip, vap, cr)) != 0) {
		return (error);
	}

	ASSERT(ip != NULL);

	rw_enter(&ip->i_contents, RW_WRITER);

	if (op == DE_MKDIR) {
		error = ud_dirmakedirect(ip, tdp, cr);
	}

	ip->i_flag |= IACC|IUPD|ICHG;
	/*
	 * Clear IACC and/or IUPD if the caller specified the atime and/or
	 * mtime fields.  They were set from the passed in attributes in
	 * ud_ialloc().
	 */
	if (vap->va_mask & AT_ATIME)
		ip->i_flag &= ~IACC;
	if (vap->va_mask & AT_MTIME)
		ip->i_flag &= ~IUPD;
	/*
	 * push inode before it's name appears in a directory
	 */
	ud_iupdat(ip, 1);
	*ipp = ip;
	rw_exit(&ip->i_contents);
	return (error);
}

/*
 * Enter the file sip in the directory tdp with name namep.
 */
int
ud_diraddentry(struct ud_inode *tdp, char *namep,
	enum de_op op, int32_t namelen, struct slot *slotp,
	struct ud_inode *sip, struct ud_inode *sdp, struct cred *cr)
{
	struct udf_vfs *udf_vfsp;
	int32_t error, temp;
	struct file_id *fid;
	uint8_t *buf = NULL;

	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));

	ud_printf("ud_diraddentry\n");

	udf_vfsp = sip->i_udf;

	/*
	 * Check inode to be linked to see if it is in the
	 * same filesystem.
	 */
	if (ITOV(tdp)->v_vfsp != ITOV(sip)->v_vfsp) {
		error = EXDEV;
		goto bad;
	}

	if ((op == DE_RENAME) && (sip->i_type == VDIR)) {
		if ((error = ud_dirfixdotdot(sip, sdp, tdp)) != 0) {
			goto bad;
		}
	}

	buf = (uint8_t *)kmem_zalloc(udf_vfsp->udf_lbsize, KM_SLEEP);

	/*
	 * Fill in entry data.
	 */
	fid = (struct file_id *)buf;
	fid->fid_ver = SWAP_16(1);
	if (sip->i_type == VDIR) {
		fid->fid_flags = FID_DIR;
	} else {
		fid->fid_flags = 0;
	}
	fid->fid_iulen = 0;

	fid->fid_icb.lad_ext_len = SWAP_32(sip->i_udf->udf_lbsize);
	fid->fid_icb.lad_ext_loc = SWAP_32(sip->i_icb_block);
	fid->fid_icb.lad_ext_prn = SWAP_16(sip->i_icb_prn);
	fid->fid_iulen = 0;

	temp = MIN(udf_vfsp->udf_lbsize - F_LEN, MAXNAMELEN);
	if ((error = ud_compress(namelen, &temp,
	    (uint8_t *)namep, fid->fid_spec)) == 0) {
		fid->fid_idlen = (uint8_t)temp;
		error = ud_dirprepareentry(tdp, slotp, buf, cr);
	}

	kmem_free(buf, udf_vfsp->udf_lbsize);

bad:
	return (error);
}

/*
 * Write a prototype directory into the empty inode ip, whose parent is dp.
 */
/* ARGSUSED2 */
int
ud_dirmakedirect(struct ud_inode *ip,
	struct ud_inode *dp, struct cred *cr)
{
	int32_t err;
	uint32_t blkno, size, parent_len, tbno;
	struct fbuf *fbp;
	struct file_id *fid;
	struct icb_ext *iext;

	ud_printf("ud_dirmakedirect\n");

	ASSERT(RW_WRITE_HELD(&ip->i_contents));
	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));

	parent_len = sizeof (struct file_id);

	if ((ip->i_desc_type != ICB_FLAG_ONE_AD) ||
	    (parent_len > ip->i_max_emb)) {
		ASSERT(ip->i_ext);
		/*
		 * Allocate space for the directory we're creating.
		 */
		if ((err = ud_alloc_space(ip->i_vfs, ip->i_icb_prn,
		    0, 1, &blkno, &size, 0, 0)) != 0) {
			return (err);
		}
		/*
		 * init with the size of
		 * directory with just the
		 * parent
		 */
		ip->i_size = sizeof (struct file_id);
		ip->i_flag |= IUPD|ICHG|IATTCHG;
		iext = ip->i_ext;
		iext->ib_prn = ip->i_icb_prn;
		iext->ib_block = blkno;
		iext->ib_count = ip->i_size;
		iext->ib_offset = 0;
		ip->i_ext_used = 1;
	} else {
		ip->i_size = sizeof (struct file_id);
		ip->i_flag |= IUPD|ICHG|IATTCHG;
	}

	ITIMES_NOLOCK(ip);

	/*
	 * Update the dp link count and write out the change.
	 * This reflects the ".." entry we'll soon write.
	 */
	if (dp->i_nlink == MAXLINK) {
		return (EMLINK);
	}
	dp->i_nlink++;
	dp->i_flag |= ICHG;
	ud_iupdat(dp, 1);

	/*
	 * Initialize directory with ".."
	 * Since the parent directory is locked, we don't have to
	 * worry about anything changing when we drop the write
	 * lock on (ip).
	 */
	rw_exit(&ip->i_contents);
	if ((err = fbread(ITOV(ip), (offset_t)0,
	    ip->i_udf->udf_lbsize, S_WRITE, &fbp)) != 0) {
		rw_enter(&ip->i_contents, RW_WRITER);
		return (err);
	}

	bzero(fbp->fb_addr, ip->i_udf->udf_lbsize);

	fid = (struct file_id *)fbp->fb_addr;
	fid->fid_ver = SWAP_16(1);
	fid->fid_flags = FID_DIR | FID_PARENT;
	fid->fid_icb.lad_ext_len = SWAP_32(dp->i_udf->udf_lbsize);
	fid->fid_icb.lad_ext_loc = SWAP_32(dp->i_icb_block);
	fid->fid_icb.lad_ext_prn = SWAP_16(dp->i_icb_prn);

	/*
	 * fid_idlen, fid_iulen and fid_spec are zero
	 * due to bzero above
	 */

	if ((err = ud_ip_off2bno(ip, 0, &tbno)) == 0) {
		ud_make_tag(ip->i_udf, &fid->fid_tag,
		    UD_FILE_ID_DESC, tbno, FID_LEN(fid));
	}

	err = ud_fbwrite(fbp, ip);
	rw_enter(&ip->i_contents, RW_WRITER);

	return (err);
}

int
ud_dirrename(struct ud_inode *sdp, struct ud_inode *sip,
	struct ud_inode *tdp, struct ud_inode *tip, char *namep,
	uint8_t *buf, struct slot *slotp, struct cred *cr)
{
	int32_t error = 0, doingdirectory;
	struct file_id *fid;

	ud_printf("ud_dirrename\n");
	ASSERT(sdp->i_udf != NULL);
	ASSERT(MUTEX_HELD(&sdp->i_udf->udf_rename_lck));
	ASSERT(RW_WRITE_HELD(&tdp->i_rwlock));
	ASSERT(RW_WRITE_HELD(&tdp->i_contents));
	ASSERT(buf);
	ASSERT(slotp->ep);

	fid = slotp->ep;

	/*
	 * Short circuit rename of something to itself.
	 */
	if (sip->i_icb_lbano == tip->i_icb_lbano) {
		return (ESAME);		/* special KLUDGE error code */
	}
	/*
	 * Everything is protected under the vfs_rename_lock so the ordering
	 * of i_contents locks doesn't matter here.
	 */
	rw_enter(&sip->i_contents, RW_READER);
	rw_enter(&tip->i_contents, RW_READER);

	/*
	 * Check that everything is on the same filesystem.
	 */
	if ((ITOV(tip)->v_vfsp != ITOV(tdp)->v_vfsp) ||
	    (ITOV(tip)->v_vfsp != ITOV(sip)->v_vfsp)) {
		error = EXDEV;		/* XXX archaic */
		goto out;
	}

	/*
	 * Must have write permission to rewrite target entry.
	 */
	if ((error = ud_iaccess(tdp, IWRITE, cr, 0)) != 0 ||
	    (error = ud_sticky_remove_access(tdp, tip, cr)) != 0)
		goto out;

	/*
	 * Ensure source and target are compatible (both directories
	 * or both not directories).  If target is a directory it must
	 * be empty and have no links to it; in addition it must not
	 * be a mount point, and both the source and target must be
	 * writable.
	 */
	doingdirectory = (sip->i_type == VDIR);
	if (tip->i_type == VDIR) {
		if (!doingdirectory) {
			error = EISDIR;
			goto out;
		}
		/*
		 * vn_vfswlock will prevent mounts from using the directory
		 * until we are done.
		 */
		if (vn_vfswlock(ITOV(tip))) {
			error = EBUSY;
			goto out;
		}
		if (vn_mountedvfs(ITOV(tip)) != NULL) {
			vn_vfsunlock(ITOV(tip));
			error = EBUSY;
			goto out;
		}
		if (!ud_dirempty(tip, tdp->i_uniqid, cr) || tip->i_nlink > 2) {
			vn_vfsunlock(ITOV(tip));
			error = EEXIST;	/* SIGH should be ENOTEMPTY */
			goto out;
		}
	} else if (doingdirectory) {
		error = ENOTDIR;
		goto out;
	}

	/*
	 * Rewrite the inode pointer for target name entry
	 * from the target inode (ip) to the source inode (sip).
	 * This prevents the target entry from disappearing
	 * during a crash. Mark the directory inode to reflect the changes.
	 */
	dnlc_remove(ITOV(tdp), namep);
	fid->fid_icb.lad_ext_prn = SWAP_16(sip->i_icb_prn);
	fid->fid_icb.lad_ext_loc = SWAP_32(sip->i_icb_block);
	dnlc_enter(ITOV(tdp), namep, ITOV(sip));

	ud_make_tag(tdp->i_udf, &fid->fid_tag, UD_FILE_ID_DESC,
	    SWAP_32(fid->fid_tag.tag_loc), FID_LEN(fid));

	error = ud_write_fid(tdp, slotp, buf);

	if (error) {
		if (doingdirectory) {
			vn_vfsunlock(ITOV(tip));
		}
		goto out;
	}

	/*
	 * Upgrade to write lock on tip
	 */
	rw_exit(&tip->i_contents);
	rw_enter(&tip->i_contents, RW_WRITER);

	mutex_enter(&tdp->i_tlock);
	tdp->i_flag |= IUPD|ICHG;
	mutex_exit(&tdp->i_tlock);
	/*
	 * Decrement the link count of the target inode.
	 * Fix the ".." entry in sip to point to dp.
	 * This is done after the new entry is on the disk.
	 */
	tip->i_nlink--;
	mutex_enter(&tip->i_tlock);
	tip->i_flag |= ICHG;
	mutex_exit(&tip->i_tlock);

	if (doingdirectory) {
		/*
		 * The entry for tip no longer exists so I can unlock the
		 * vfslock.
		 */
		vn_vfsunlock(ITOV(tip));
		/*
		 * Decrement target link count once more if it was a directory.
		 */
		if (tip->i_nlink != 0) {
			cmn_err(CE_WARN,
			"ud_direnter: target directory link count != 0");
			rw_exit(&tip->i_contents);
			rw_exit(&sip->i_contents);
			return (EINVAL);
		}
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
		 * different, dirfixdotdot() will bump the link count
		 * back.
		 */
		tdp->i_nlink--;
		mutex_enter(&tdp->i_tlock);
		tdp->i_flag |= ICHG;
		mutex_exit(&tdp->i_tlock);
		ITIMES_NOLOCK(tdp);
		if (sdp != tdp) {
			rw_exit(&tip->i_contents);
			rw_exit(&sip->i_contents);
			error = ud_dirfixdotdot(sip, sdp, tdp);
			return (error);
		}
	}

out:
	rw_exit(&tip->i_contents);
	rw_exit(&sip->i_contents);
	return (error);
}


/*
 * 1. When we find a slot that belonged to a file which was deleted
 *      and is in the middle of the directory
 * 2. There is not empty slot available. The new entry
 *      will be at the end of the directory and fits in the same block.
 * 3. There is no empty slot available. The new
 *      entry will not fit the left over directory
 *      so we need to allocate a new block. If
 *      we cannot allocate a proximity block we need
 *      to allocate a new icb, and data block.
 */
int
ud_dirprepareentry(struct ud_inode *dp,
	struct slot *slotp, uint8_t *buf, struct cred *cr)
{
	struct fbuf *fbp;
	uint16_t old_dtype;
	int32_t error = 0;
	uint32_t entrysize, count, offset, tbno, old_size, off;
	struct file_id *fid;
	int32_t lbsize, lbmask, mask;

	ASSERT(RW_WRITE_HELD(&dp->i_rwlock));

	ASSERT((slotp->status == NONE) || (slotp->status == FOUND));

	ud_printf("ud_dirprepareentry\n");
	lbsize = dp->i_udf->udf_lbsize;
	lbmask = dp->i_udf->udf_lbmask;
	mask = ~lbmask;

	fid = (struct file_id *)buf;
	entrysize = FID_LEN(fid);

	/*
	 * If we didn't find a slot, then indicate that the
	 * new slot belongs at the end of the directory.
	 * If we found a slot, then the new entry can be
	 * put at slotp->offset.
	 */
	if (slotp->status == NONE) {
		/*
		 * We did not find a slot, the next
		 * entry will be in the end of the directory
		 * see if we can fit the new entry inside
		 * the old block. If not allocate a new block.
		 */
		if (entrysize > slotp->size) {
			/*
			 * extend the directory
			 * size by one new block
			 */
			old_dtype = dp->i_desc_type;
			old_size = (uint32_t)dp->i_size;
			error = ud_bmap_write(dp, slotp->offset,
			    blkoff(dp->i_udf, slotp->offset) + entrysize,
			    0, cr);
			if (error != 0) {
				return (error);
			}
			if (old_dtype != dp->i_desc_type) {
				/*
				 * oops we changed the astrat
				 * of the file, we have to
				 * recaliculate tags
				 * fortunately we donot have more
				 * than one lbsize to handle here
				 */
				if ((error = ud_ip_off2bno(dp,
				    0, &tbno)) != 0) {
					return (error);
				}
				if ((error = fbread(ITOV(dp), 0,
				    dp->i_udf->udf_lbsize,
				    S_WRITE, &fbp)) != 0) {
					return (error);
				}
				off = 0;
				while (off < old_size) {
					struct file_id *tfid;

					tfid = (struct file_id *)
					    (fbp->fb_addr + off);

					ud_make_tag(dp->i_udf, &tfid->fid_tag,
					    UD_FILE_ID_DESC, tbno,
					    FID_LEN(tfid));

					off += FID_LEN(tfid);
				}
				if (error = ud_fbwrite(fbp, dp)) {
					return (error);
				}
			}
		} else {
			/* Extend the directory size */
			if (dp->i_desc_type != ICB_FLAG_ONE_AD) {
				ASSERT(dp->i_ext);
				dp->i_ext[dp->i_ext_used - 1].ib_count +=
				    entrysize;
			}
		}
		dp->i_size += entrysize;
		dp->i_flag |= IUPD|ICHG|IATTCHG;
		ITIMES_NOLOCK(dp);
	} else if (slotp->status != FOUND) {
		cmn_err(CE_WARN, "status is not NONE/FOUND");
		return (EINVAL);
	}

	if ((error = ud_ip_off2bno(dp, slotp->offset, &tbno)) != 0) {
		return (error);
	}
	ud_make_tag(dp->i_udf, &fid->fid_tag, UD_FILE_ID_DESC,
	    tbno, FID_LEN(fid));

	/*
	 * fbread cannot cross a
	 * MAXBSIZE boundary so handle it here
	 */
	offset = slotp->offset;
	if ((error = fbread(ITOV(dp), offset & mask, lbsize,
	    S_WRITE, &fbp)) != 0) {
		return (error);
	}
	if ((offset & mask) != ((offset + entrysize) & mask)) {
		count = entrysize - ((offset + entrysize) & lbmask);
	} else {
		count = entrysize;
	}
	bcopy((caddr_t)buf, fbp->fb_addr + (offset & lbmask), count);

	if (error = ud_fbwrite(fbp, dp)) {
		return (error);
	}

	if (entrysize > count) {
		if ((error = fbread(ITOV(dp), (offset + entrysize) & mask,
		    lbsize, S_WRITE, &fbp)) != 0) {
			return (error);
		}
		bcopy((caddr_t)(buf + count), fbp->fb_addr, entrysize - count);
		if (error = ud_fbwrite(fbp, dp)) {
			return (error);
		}
	}

	dp->i_flag |= IUPD|ICHG|IATTCHG;
	ITIMES_NOLOCK(dp);
	return (error);
}


/*
 * Fix the FID_PARENT entry of the child directory so that it points
 * to the new parent directory instead of the old one.  Routine
 * assumes that dp is a directory and that all the inodes are on
 * the same file system.
 */
int
ud_dirfixdotdot(struct ud_inode *dp,
	struct ud_inode *opdp, struct ud_inode *npdp)
{
	int32_t err = 0;
	struct fbuf *fbp;
	struct file_id *fid;
	uint32_t loc, dummy, tbno;

	ud_printf("ud_dirfixdotdot\n");

	ASSERT(opdp->i_type == VDIR);
	ASSERT(npdp->i_type == VDIR);

	ASSERT(RW_WRITE_HELD(&npdp->i_rwlock));

	err = fbread(ITOV(dp), (offset_t)0,
	    dp->i_udf->udf_lbsize, S_WRITE, &fbp);

	if (err || dp->i_nlink == 0 ||
	    dp->i_size < sizeof (struct file_id)) {
		goto bad;
	}

	if ((err = ud_ip_off2bno(dp, 0, &tbno)) != 0) {
		goto bad;
	}

	fid = (struct file_id *)fbp->fb_addr;
	if ((ud_verify_tag_and_desc(&fid->fid_tag, UD_FILE_ID_DESC,
	    tbno,
	    1, dp->i_udf->udf_lbsize) != 0) ||
	    ((fid->fid_flags & (FID_DIR | FID_PARENT)) !=
	    (FID_DIR | FID_PARENT))) {
		err = ENOTDIR;
		goto bad;
	}

	loc = ud_xlate_to_daddr(dp->i_udf,
	    SWAP_16(fid->fid_icb.lad_ext_prn),
	    SWAP_32(fid->fid_icb.lad_ext_loc), 1, &dummy);
	ASSERT(dummy == 1);
	if (loc == npdp->i_icb_lbano) {
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
	mutex_enter(&npdp->i_tlock);
	npdp->i_flag |= ICHG;
	mutex_exit(&npdp->i_tlock);
	ud_iupdat(npdp, 1);

	/*
	 * Rewrite the child FID_PARENT entry and force it out.
	 */
	dnlc_remove(ITOV(dp), "..");
	fid->fid_icb.lad_ext_loc = SWAP_32(npdp->i_icb_block);
	fid->fid_icb.lad_ext_prn = SWAP_16(npdp->i_icb_prn);
	ud_make_tag(npdp->i_udf, &fid->fid_tag,
	    UD_FILE_ID_DESC, tbno, FID_LEN(fid));
	dnlc_enter(ITOV(dp), "..", ITOV(npdp));

	err = ud_fbwrite(fbp, dp);
	fbp = NULL;
	if (err != 0) {
		goto bad;
	}

	/*
	 * Decrement the link count of the old parent inode and force
	 * it out.  If opdp is NULL, then this is a new directory link;
	 * it has no parent, so we need not do anything.
	 */
	if (opdp != NULL) {
		rw_enter(&opdp->i_contents, RW_WRITER);
		if (opdp->i_nlink != 0) {
			opdp->i_nlink--;
			mutex_enter(&opdp->i_tlock);
			opdp->i_flag |= ICHG;
			mutex_exit(&opdp->i_tlock);
			ud_iupdat(opdp, 1);
		}
		rw_exit(&opdp->i_contents);
	}
	return (0);

bad:
	if (fbp) {
		fbrelse(fbp, S_OTHER);
	}
	return (err);
}

int32_t
ud_write_fid(struct ud_inode *dp, struct slot *slot, uint8_t *buf)
{
	struct udf_vfs *udf_vfsp;
	struct fbuf *lfbp;
	struct file_id *fid;
	int32_t error = 0;
	uint32_t lbsize, lbmask, count, old_count;


	ASSERT(slot->fbp);
	ASSERT(slot->ep);

	udf_vfsp = dp->i_udf;
	fid = slot->ep;
	lbsize = dp->i_udf->udf_lbsize;
	lbmask = dp->i_udf->udf_lbmask;

	if (((uint8_t *)fid >= buf) &&
	    ((uint8_t *)fid < &buf[udf_vfsp->udf_lbsize])) {

		if ((error = fbread(ITOV(dp),
		    (offset_t)(slot->offset & ~lbmask),
		    lbsize, S_WRITE, &lfbp)) != 0) {
			goto out;
		}


		/*
		 * We do not need to write the
		 * file name. So check if the entry
		 * does not cross a block boundary
		 * and write only required portions
		 */
		if (((slot->offset & lbmask) +
			sizeof (struct file_id)) > lbsize) {

			if ((slot->offset & lbmask) != 0) {
				old_count = lbsize -
					(slot->offset & lbmask);
				count = (slot->offset +
					sizeof (struct file_id)) &
					lbmask;
			} else {
				old_count = 0;
				count = sizeof (struct file_id);
			}

			bcopy(buf, lfbp->fb_addr +
				(slot->offset & lbmask), old_count);
			bcopy(buf + old_count,
				slot->fbp->fb_addr, count);

			error = ud_fbwrite(lfbp, dp);

			error = ud_fbwrite(slot->fbp, dp);
		} else {
			bcopy(buf, lfbp->fb_addr +
				(slot->offset & lbmask),
				sizeof (struct file_id));

			error = ud_fbwrite(lfbp, dp);

			fbrelse(slot->fbp, S_OTHER);
		}
	} else {
		if ((error = ud_fbwrite(slot->fbp, dp)) != 0) {
			fid->fid_flags &= ~FID_DELETED;
			ud_make_tag(dp->i_udf, &fid->fid_tag, UD_FILE_ID_DESC,
			    SWAP_32(fid->fid_tag.tag_loc), FID_LEN(fid));
		}
	}
	slot->fbp = NULL;

out:
	return (error);
}
