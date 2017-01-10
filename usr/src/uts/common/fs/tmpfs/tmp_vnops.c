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

/*
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2016 RackTop Systems.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <sys/vmsystm.h>
#include <sys/fs/tmp.h>
#include <sys/fs/tmpnode.h>
#include <sys/mman.h>
#include <vm/hat.h>
#include <vm/seg_vn.h>
#include <vm/seg_map.h>
#include <vm/seg.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/swap.h>
#include <sys/buf.h>
#include <sys/vm.h>
#include <sys/vtrace.h>
#include <sys/policy.h>
#include <fs/fs_subr.h>

static int	tmp_getapage(struct vnode *, u_offset_t, size_t, uint_t *,
	page_t **, size_t, struct seg *, caddr_t, enum seg_rw, struct cred *);
static int 	tmp_putapage(struct vnode *, page_t *, u_offset_t *, size_t *,
	int, struct cred *);

/* ARGSUSED1 */
static int
tmp_open(struct vnode **vpp, int flag, struct cred *cred, caller_context_t *ct)
{
	/*
	 * swapon to a tmpfs file is not supported so access
	 * is denied on open if VISSWAP is set.
	 */
	if ((*vpp)->v_flag & VISSWAP)
		return (EINVAL);
	return (0);
}

/* ARGSUSED1 */
static int
tmp_close(
	struct vnode *vp,
	int flag,
	int count,
	offset_t offset,
	struct cred *cred,
	caller_context_t *ct)
{
	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}

/*
 * wrtmp does the real work of write requests for tmpfs.
 */
static int
wrtmp(
	struct tmount *tm,
	struct tmpnode *tp,
	struct uio *uio,
	struct cred *cr,
	struct caller_context *ct)
{
	pgcnt_t pageoffset;	/* offset in pages */
	ulong_t segmap_offset;	/* pagesize byte offset into segmap */
	caddr_t base;		/* base of segmap */
	ssize_t bytes;		/* bytes to uiomove */
	pfn_t pagenumber;	/* offset in pages into tmp file */
	struct vnode *vp;
	int error = 0;
	int	pagecreate;	/* == 1 if we allocated a page */
	int	newpage;
	rlim64_t limit = uio->uio_llimit;
	long oresid = uio->uio_resid;
	timestruc_t now;

	long tn_size_changed = 0;
	long old_tn_size;
	long new_tn_size;

	vp = TNTOV(tp);
	ASSERT(vp->v_type == VREG);

	TRACE_1(TR_FAC_TMPFS, TR_TMPFS_RWTMP_START,
	    "tmp_wrtmp_start:vp %p", vp);

	ASSERT(RW_WRITE_HELD(&tp->tn_contents));
	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));

	if (MANDLOCK(vp, tp->tn_mode)) {
		rw_exit(&tp->tn_contents);
		/*
		 * tmp_getattr ends up being called by chklock
		 */
		error = chklock(vp, FWRITE, uio->uio_loffset, uio->uio_resid,
		    uio->uio_fmode, ct);
		rw_enter(&tp->tn_contents, RW_WRITER);
		if (error != 0) {
			TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
			    "tmp_wrtmp_end:vp %p error %d", vp, error);
			return (error);
		}
	}

	if (uio->uio_loffset < 0)
		return (EINVAL);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	if (uio->uio_loffset >= limit) {
		proc_t *p = ttoproc(curthread);

		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE], p->p_rctls,
		    p, RCA_UNSAFE_SIGINFO);
		mutex_exit(&p->p_lock);
		return (EFBIG);
	}

	if (uio->uio_loffset >= MAXOFF_T) {
		TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
		    "tmp_wrtmp_end:vp %p error %d", vp, EINVAL);
		return (EFBIG);
	}

	if (uio->uio_resid == 0) {
		TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
		    "tmp_wrtmp_end:vp %p error %d", vp, 0);
		return (0);
	}

	if (limit > MAXOFF_T)
		limit = MAXOFF_T;

	do {
		long	offset;
		long	delta;

		offset = (long)uio->uio_offset;
		pageoffset = offset & PAGEOFFSET;
		/*
		 * A maximum of PAGESIZE bytes of data is transferred
		 * each pass through this loop
		 */
		bytes = MIN(PAGESIZE - pageoffset, uio->uio_resid);

		if (offset + bytes >= limit) {
			if (offset >= limit) {
				error = EFBIG;
				goto out;
			}
			bytes = limit - offset;
		}
		pagenumber = btop(offset);

		/*
		 * delta is the amount of anonymous memory
		 * to reserve for the file.
		 * We always reserve in pagesize increments so
		 * unless we're extending the file into a new page,
		 * we don't need to call tmp_resv.
		 */
		delta = offset + bytes -
		    P2ROUNDUP_TYPED(tp->tn_size, PAGESIZE, u_offset_t);
		if (delta > 0) {
			pagecreate = 1;
			if (tmp_resv(tm, tp, delta, pagecreate)) {
				/*
				 * Log file system full in the zone that owns
				 * the tmpfs mount, as well as in the global
				 * zone if necessary.
				 */
				zcmn_err(tm->tm_vfsp->vfs_zone->zone_id,
				    CE_WARN, "%s: File system full, "
				    "swap space limit exceeded",
				    tm->tm_mntpath);

				if (tm->tm_vfsp->vfs_zone->zone_id !=
				    GLOBAL_ZONEID) {

					vfs_t *vfs = tm->tm_vfsp;

					zcmn_err(GLOBAL_ZONEID,
					    CE_WARN, "%s: File system full, "
					    "swap space limit exceeded",
					    vfs->vfs_vnodecovered->v_path);
				}
				error = ENOSPC;
				break;
			}
			tmpnode_growmap(tp, (ulong_t)offset + bytes);
		}
		/* grow the file to the new length */
		if (offset + bytes > tp->tn_size) {
			tn_size_changed = 1;
			old_tn_size = tp->tn_size;
			/*
			 * Postpone updating tp->tn_size until uiomove() is
			 * done.
			 */
			new_tn_size = offset + bytes;
		}
		if (bytes == PAGESIZE) {
			/*
			 * Writing whole page so reading from disk
			 * is a waste
			 */
			pagecreate = 1;
		} else {
			pagecreate = 0;
		}
		/*
		 * If writing past EOF or filling in a hole
		 * we need to allocate an anon slot.
		 */
		if (anon_get_ptr(tp->tn_anon, pagenumber) == NULL) {
			(void) anon_set_ptr(tp->tn_anon, pagenumber,
			    anon_alloc(vp, ptob(pagenumber)), ANON_SLEEP);
			pagecreate = 1;
			tp->tn_nblocks++;
		}

		/*
		 * We have to drop the contents lock to allow the VM
		 * system to reacquire it in tmp_getpage()
		 */
		rw_exit(&tp->tn_contents);

		/*
		 * Touch the page and fault it in if it is not in core
		 * before segmap_getmapflt or vpm_data_copy can lock it.
		 * This is to avoid the deadlock if the buffer is mapped
		 * to the same file through mmap which we want to write.
		 */
		uio_prefaultpages((long)bytes, uio);

		newpage = 0;
		if (vpm_enable) {
			/*
			 * Copy data. If new pages are created, part of
			 * the page that is not written will be initizliazed
			 * with zeros.
			 */
			error = vpm_data_copy(vp, offset, bytes, uio,
			    !pagecreate, &newpage, 1, S_WRITE);
		} else {
			/* Get offset within the segmap mapping */
			segmap_offset = (offset & PAGEMASK) & MAXBOFFSET;
			base = segmap_getmapflt(segkmap, vp,
			    (offset &  MAXBMASK), PAGESIZE, !pagecreate,
			    S_WRITE);
		}


		if (!vpm_enable && pagecreate) {
			/*
			 * segmap_pagecreate() returns 1 if it calls
			 * page_create_va() to allocate any pages.
			 */
			newpage = segmap_pagecreate(segkmap,
			    base + segmap_offset, (size_t)PAGESIZE, 0);
			/*
			 * Clear from the beginning of the page to the starting
			 * offset of the data.
			 */
			if (pageoffset != 0)
				(void) kzero(base + segmap_offset,
				    (size_t)pageoffset);
		}

		if (!vpm_enable) {
			error = uiomove(base + segmap_offset + pageoffset,
			    (long)bytes, UIO_WRITE, uio);
		}

		if (!vpm_enable && pagecreate &&
		    uio->uio_offset < P2ROUNDUP(offset + bytes, PAGESIZE)) {
			long	zoffset; /* zero from offset into page */
			/*
			 * We created pages w/o initializing them completely,
			 * thus we need to zero the part that wasn't set up.
			 * This happens on most EOF write cases and if
			 * we had some sort of error during the uiomove.
			 */
			long nmoved;

			nmoved = uio->uio_offset - offset;
			ASSERT((nmoved + pageoffset) <= PAGESIZE);

			/*
			 * Zero from the end of data in the page to the
			 * end of the page.
			 */
			if ((zoffset = pageoffset + nmoved) < PAGESIZE)
				(void) kzero(base + segmap_offset + zoffset,
				    (size_t)PAGESIZE - zoffset);
		}

		/*
		 * Unlock the pages which have been allocated by
		 * page_create_va() in segmap_pagecreate()
		 */
		if (!vpm_enable && newpage) {
			segmap_pageunlock(segkmap, base + segmap_offset,
			    (size_t)PAGESIZE, S_WRITE);
		}

		if (error) {
			/*
			 * If we failed on a write, we must
			 * be sure to invalidate any pages that may have
			 * been allocated.
			 */
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, offset, PAGESIZE,
				    SM_INVAL);
			} else {
				(void) segmap_release(segkmap, base, SM_INVAL);
			}
		} else {
			if (vpm_enable) {
				error = vpm_sync_pages(vp, offset, PAGESIZE,
				    0);
			} else {
				error = segmap_release(segkmap, base, 0);
			}
		}

		/*
		 * Re-acquire contents lock.
		 */
		rw_enter(&tp->tn_contents, RW_WRITER);

		/*
		 * Update tn_size.
		 */
		if (tn_size_changed)
			tp->tn_size = new_tn_size;

		/*
		 * If the uiomove failed, fix up tn_size.
		 */
		if (error) {
			if (tn_size_changed) {
				/*
				 * The uiomove failed, and we
				 * allocated blocks,so get rid
				 * of them.
				 */
				(void) tmpnode_trunc(tm, tp,
				    (ulong_t)old_tn_size);
			}
		} else {
			/*
			 * XXX - Can this be out of the loop?
			 */
			if ((tp->tn_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) &&
			    (tp->tn_mode & (S_ISUID | S_ISGID)) &&
			    secpolicy_vnode_setid_retain(cr,
			    (tp->tn_mode & S_ISUID) != 0 && tp->tn_uid == 0)) {
				/*
				 * Clear Set-UID & Set-GID bits on
				 * successful write if not privileged
				 * and at least one of the execute bits
				 * is set.  If we always clear Set-GID,
				 * mandatory file and record locking is
				 * unuseable.
				 */
				tp->tn_mode &= ~(S_ISUID | S_ISGID);
			}
			gethrestime(&now);
			tp->tn_mtime = now;
			tp->tn_ctime = now;
		}
	} while (error == 0 && uio->uio_resid > 0 && bytes != 0);

out:
	/*
	 * If we've already done a partial-write, terminate
	 * the write but return no error.
	 */
	if (oresid != uio->uio_resid)
		error = 0;
	TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
	    "tmp_wrtmp_end:vp %p error %d", vp, error);
	return (error);
}

/*
 * rdtmp does the real work of read requests for tmpfs.
 */
static int
rdtmp(
	struct tmount *tm,
	struct tmpnode *tp,
	struct uio *uio,
	struct caller_context *ct)
{
	ulong_t pageoffset;	/* offset in tmpfs file (uio_offset) */
	ulong_t segmap_offset;	/* pagesize byte offset into segmap */
	caddr_t base;		/* base of segmap */
	ssize_t bytes;		/* bytes to uiomove */
	struct vnode *vp;
	int error;
	long oresid = uio->uio_resid;

#if defined(lint)
	tm = tm;
#endif
	vp = TNTOV(tp);

	TRACE_1(TR_FAC_TMPFS, TR_TMPFS_RWTMP_START, "tmp_rdtmp_start:vp %p",
	    vp);

	ASSERT(RW_LOCK_HELD(&tp->tn_contents));

	if (MANDLOCK(vp, tp->tn_mode)) {
		rw_exit(&tp->tn_contents);
		/*
		 * tmp_getattr ends up being called by chklock
		 */
		error = chklock(vp, FREAD, uio->uio_loffset, uio->uio_resid,
		    uio->uio_fmode, ct);
		rw_enter(&tp->tn_contents, RW_READER);
		if (error != 0) {
			TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
			    "tmp_rdtmp_end:vp %p error %d", vp, error);
			return (error);
		}
	}
	ASSERT(tp->tn_type == VREG);

	if (uio->uio_loffset >= MAXOFF_T) {
		TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
		    "tmp_rdtmp_end:vp %p error %d", vp, EINVAL);
		return (0);
	}
	if (uio->uio_loffset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0) {
		TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
		    "tmp_rdtmp_end:vp %p error %d", vp, 0);
		return (0);
	}

	vp = TNTOV(tp);

	do {
		long diff;
		long offset;

		offset = uio->uio_offset;
		pageoffset = offset & PAGEOFFSET;
		bytes = MIN(PAGESIZE - pageoffset, uio->uio_resid);

		diff = tp->tn_size - offset;

		if (diff <= 0) {
			error = 0;
			goto out;
		}
		if (diff < bytes)
			bytes = diff;

		/*
		 * We have to drop the contents lock to allow the VM system
		 * to reacquire it in tmp_getpage() should the uiomove cause a
		 * pagefault.
		 */
		rw_exit(&tp->tn_contents);

		if (vpm_enable) {
			/*
			 * Copy data.
			 */
			error = vpm_data_copy(vp, offset, bytes, uio, 1, NULL,
			    0, S_READ);
		} else {
			segmap_offset = (offset & PAGEMASK) & MAXBOFFSET;
			base = segmap_getmapflt(segkmap, vp, offset & MAXBMASK,
			    bytes, 1, S_READ);

			error = uiomove(base + segmap_offset + pageoffset,
			    (long)bytes, UIO_READ, uio);
		}

		if (error) {
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, offset, PAGESIZE, 0);
			} else {
				(void) segmap_release(segkmap, base, 0);
			}
		} else {
			if (vpm_enable) {
				error = vpm_sync_pages(vp, offset, PAGESIZE,
				    0);
			} else {
				error = segmap_release(segkmap, base, 0);
			}
		}

		/*
		 * Re-acquire contents lock.
		 */
		rw_enter(&tp->tn_contents, RW_READER);

	} while (error == 0 && uio->uio_resid > 0);

out:
	gethrestime(&tp->tn_atime);

	/*
	 * If we've already done a partial read, terminate
	 * the read but return no error.
	 */
	if (oresid != uio->uio_resid)
		error = 0;

	TRACE_2(TR_FAC_TMPFS, TR_TMPFS_RWTMP_END,
	    "tmp_rdtmp_end:vp %x error %d", vp, error);
	return (error);
}

/* ARGSUSED2 */
static int
tmp_read(struct vnode *vp, struct uio *uiop, int ioflag, cred_t *cred,
    struct caller_context *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	struct tmount *tm = (struct tmount *)VTOTM(vp);
	int error;

	/*
	 * We don't currently support reading non-regular files
	 */
	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type != VREG)
		return (EINVAL);
	/*
	 * tmp_rwlock should have already been called from layers above
	 */
	ASSERT(RW_READ_HELD(&tp->tn_rwlock));

	rw_enter(&tp->tn_contents, RW_READER);

	error = rdtmp(tm, tp, uiop, ct);

	rw_exit(&tp->tn_contents);

	return (error);
}

static int
tmp_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cred,
    struct caller_context *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	struct tmount *tm = (struct tmount *)VTOTM(vp);
	int error;

	/*
	 * We don't currently support writing to non-regular files
	 */
	if (vp->v_type != VREG)
		return (EINVAL);	/* XXX EISDIR? */

	/*
	 * tmp_rwlock should have already been called from layers above
	 */
	ASSERT(RW_WRITE_HELD(&tp->tn_rwlock));

	rw_enter(&tp->tn_contents, RW_WRITER);

	if (ioflag & FAPPEND) {
		/*
		 * In append mode start at end of file.
		 */
		uiop->uio_loffset = tp->tn_size;
	}

	error = wrtmp(tm, tp, uiop, cred, ct);

	rw_exit(&tp->tn_contents);

	return (error);
}

/* ARGSUSED */
static int
tmp_ioctl(
	struct vnode *vp,
	int com,
	intptr_t data,
	int flag,
	struct cred *cred,
	int *rvalp,
	caller_context_t *ct)
{
	return (ENOTTY);
}

/* ARGSUSED2 */
static int
tmp_getattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	struct vnode *mvp;
	struct vattr va;
	int attrs = 1;

	/*
	 * A special case to handle the root tnode on a diskless nfs
	 * client who may have had its uid and gid inherited
	 * from an nfs vnode with nobody ownership.  Likely the
	 * root filesystem. After nfs is fully functional the uid/gid
	 * may be mapable so ask again.
	 * vfsp can't get unmounted because we hold vp.
	 */
	if (vp->v_flag & VROOT &&
	    (mvp = vp->v_vfsp->vfs_vnodecovered) != NULL) {
		mutex_enter(&tp->tn_tlock);
		if (tp->tn_uid == UID_NOBODY || tp->tn_gid == GID_NOBODY) {
			mutex_exit(&tp->tn_tlock);
			bzero(&va, sizeof (struct vattr));
			va.va_mask = AT_UID|AT_GID;
			attrs = VOP_GETATTR(mvp, &va, 0, cred, ct);
		} else {
			mutex_exit(&tp->tn_tlock);
		}
	}
	mutex_enter(&tp->tn_tlock);
	if (attrs == 0) {
		tp->tn_uid = va.va_uid;
		tp->tn_gid = va.va_gid;
	}
	vap->va_type = vp->v_type;
	vap->va_mode = tp->tn_mode & MODEMASK;
	vap->va_uid = tp->tn_uid;
	vap->va_gid = tp->tn_gid;
	vap->va_fsid = tp->tn_fsid;
	vap->va_nodeid = (ino64_t)tp->tn_nodeid;
	vap->va_nlink = tp->tn_nlink;
	vap->va_size = (u_offset_t)tp->tn_size;
	vap->va_atime = tp->tn_atime;
	vap->va_mtime = tp->tn_mtime;
	vap->va_ctime = tp->tn_ctime;
	vap->va_blksize = PAGESIZE;
	vap->va_rdev = tp->tn_rdev;
	vap->va_seq = tp->tn_seq;

	/*
	 * XXX Holes are not taken into account.  We could take the time to
	 * run through the anon array looking for allocated slots...
	 */
	vap->va_nblocks = (fsblkcnt64_t)btodb(ptob(btopr(vap->va_size)));
	mutex_exit(&tp->tn_tlock);
	return (0);
}

/*ARGSUSED4*/
static int
tmp_setattr(
	struct vnode *vp,
	struct vattr *vap,
	int flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct tmount *tm = (struct tmount *)VTOTM(vp);
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	int error = 0;
	struct vattr *get;
	long mask;

	/*
	 * Cannot set these attributes
	 */
	if ((vap->va_mask & AT_NOSET) || (vap->va_mask & AT_XVATTR))
		return (EINVAL);

	mutex_enter(&tp->tn_tlock);

	get = &tp->tn_attr;
	/*
	 * Change file access modes. Must be owner or have sufficient
	 * privileges.
	 */
	error = secpolicy_vnode_setattr(cred, vp, vap, get, flags, tmp_taccess,
	    tp);

	if (error)
		goto out;

	mask = vap->va_mask;

	if (mask & AT_MODE) {
		get->va_mode &= S_IFMT;
		get->va_mode |= vap->va_mode & ~S_IFMT;
	}

	if (mask & AT_UID)
		get->va_uid = vap->va_uid;
	if (mask & AT_GID)
		get->va_gid = vap->va_gid;
	if (mask & AT_ATIME)
		get->va_atime = vap->va_atime;
	if (mask & AT_MTIME)
		get->va_mtime = vap->va_mtime;

	if (mask & (AT_UID | AT_GID | AT_MODE | AT_MTIME))
		gethrestime(&tp->tn_ctime);

	if (mask & AT_SIZE) {
		ASSERT(vp->v_type != VDIR);

		/* Don't support large files. */
		if (vap->va_size > MAXOFF_T) {
			error = EFBIG;
			goto out;
		}
		mutex_exit(&tp->tn_tlock);

		rw_enter(&tp->tn_rwlock, RW_WRITER);
		rw_enter(&tp->tn_contents, RW_WRITER);
		error = tmpnode_trunc(tm, tp, (ulong_t)vap->va_size);
		rw_exit(&tp->tn_contents);
		rw_exit(&tp->tn_rwlock);

		if (error == 0 && vap->va_size == 0)
			vnevent_truncate(vp, ct);

		goto out1;
	}
out:
	mutex_exit(&tp->tn_tlock);
out1:
	return (error);
}

/* ARGSUSED2 */
static int
tmp_access(
	struct vnode *vp,
	int mode,
	int flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	int error;

	mutex_enter(&tp->tn_tlock);
	error = tmp_taccess(tp, mode, cred);
	mutex_exit(&tp->tn_tlock);
	return (error);
}

/* ARGSUSED3 */
static int
tmp_lookup(
	struct vnode *dvp,
	char *nm,
	struct vnode **vpp,
	struct pathname *pnp,
	int flags,
	struct vnode *rdir,
	struct cred *cred,
	caller_context_t *ct,
	int *direntflags,
	pathname_t *realpnp)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(dvp);
	struct tmpnode *ntp = NULL;
	int error;


	/* allow cd into @ dir */
	if (flags & LOOKUP_XATTR) {
		struct tmpnode *xdp;
		struct tmount *tm;

		/*
		 * don't allow attributes if not mounted XATTR support
		 */
		if (!(dvp->v_vfsp->vfs_flag & VFS_XATTR))
			return (EINVAL);

		if (tp->tn_flags & ISXATTR)
			/* No attributes on attributes */
			return (EINVAL);

		rw_enter(&tp->tn_rwlock, RW_WRITER);
		if (tp->tn_xattrdp == NULL) {
			if (!(flags & CREATE_XATTR_DIR)) {
				rw_exit(&tp->tn_rwlock);
				return (ENOENT);
			}

			/*
			 * No attribute directory exists for this
			 * node - create the attr dir as a side effect
			 * of this lookup.
			 */

			/*
			 * Make sure we have adequate permission...
			 */

			if ((error = tmp_taccess(tp, VWRITE, cred)) != 0) {
				rw_exit(&tp->tn_rwlock);
				return (error);
			}

			xdp = tmp_memalloc(sizeof (struct tmpnode),
			    TMP_MUSTHAVE);
			tm = VTOTM(dvp);
			tmpnode_init(tm, xdp, &tp->tn_attr, NULL);
			/*
			 * Fix-up fields unique to attribute directories.
			 */
			xdp->tn_flags = ISXATTR;
			xdp->tn_type = VDIR;
			if (tp->tn_type == VDIR) {
				xdp->tn_mode = tp->tn_attr.va_mode;
			} else {
				xdp->tn_mode = 0700;
				if (tp->tn_attr.va_mode & 0040)
					xdp->tn_mode |= 0750;
				if (tp->tn_attr.va_mode & 0004)
					xdp->tn_mode |= 0705;
			}
			xdp->tn_vnode->v_type = VDIR;
			xdp->tn_vnode->v_flag |= V_XATTRDIR;
			tdirinit(tp, xdp);
			tp->tn_xattrdp = xdp;
		} else {
			VN_HOLD(tp->tn_xattrdp->tn_vnode);
		}
		*vpp = TNTOV(tp->tn_xattrdp);
		rw_exit(&tp->tn_rwlock);
		return (0);
	}

	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}
	ASSERT(tp);

	error = tdirlookup(tp, nm, &ntp, cred);

	if (error == 0) {
		ASSERT(ntp);
		*vpp = TNTOV(ntp);
		/*
		 * If vnode is a device return special vnode instead
		 */
		if (IS_DEVVP(*vpp)) {
			struct vnode *newvp;

			newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type,
			    cred);
			VN_RELE(*vpp);
			*vpp = newvp;
		}
	}
	TRACE_4(TR_FAC_TMPFS, TR_TMPFS_LOOKUP,
	    "tmpfs lookup:vp %p name %s vpp %p error %d",
	    dvp, nm, vpp, error);
	return (error);
}

/*ARGSUSED7*/
static int
tmp_create(
	struct vnode *dvp,
	char *nm,
	struct vattr *vap,
	enum vcexcl exclusive,
	int mode,
	struct vnode **vpp,
	struct cred *cred,
	int flag,
	caller_context_t *ct,
	vsecattr_t *vsecp)
{
	struct tmpnode *parent;
	struct tmount *tm;
	struct tmpnode *self;
	int error;
	struct tmpnode *oldtp;

again:
	parent = (struct tmpnode *)VTOTN(dvp);
	tm = (struct tmount *)VTOTM(dvp);
	self = NULL;
	error = 0;
	oldtp = NULL;

	/* device files not allowed in ext. attr dirs */
	if ((parent->tn_flags & ISXATTR) &&
	    (vap->va_type == VBLK || vap->va_type == VCHR ||
	    vap->va_type == VFIFO || vap->va_type == VDOOR ||
	    vap->va_type == VSOCK || vap->va_type == VPORT))
			return (EINVAL);

	if (vap->va_type == VREG && (vap->va_mode & VSVTX)) {
		/* Must be privileged to set sticky bit */
		if (secpolicy_vnode_stky_modify(cred))
			vap->va_mode &= ~VSVTX;
	} else if (vap->va_type == VNON) {
		return (EINVAL);
	}

	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		oldtp = parent;
	} else {
		error = tdirlookup(parent, nm, &oldtp, cred);
	}

	if (error == 0) {	/* name found */
		boolean_t trunc = B_FALSE;

		ASSERT(oldtp);

		rw_enter(&oldtp->tn_rwlock, RW_WRITER);

		/*
		 * if create/read-only an existing
		 * directory, allow it
		 */
		if (exclusive == EXCL)
			error = EEXIST;
		else if ((oldtp->tn_type == VDIR) && (mode & VWRITE))
			error = EISDIR;
		else {
			error = tmp_taccess(oldtp, mode, cred);
		}

		if (error) {
			rw_exit(&oldtp->tn_rwlock);
			tmpnode_rele(oldtp);
			return (error);
		}
		*vpp = TNTOV(oldtp);
		if ((*vpp)->v_type == VREG && (vap->va_mask & AT_SIZE) &&
		    vap->va_size == 0) {
			rw_enter(&oldtp->tn_contents, RW_WRITER);
			(void) tmpnode_trunc(tm, oldtp, 0);
			rw_exit(&oldtp->tn_contents);
			trunc = B_TRUE;
		}
		rw_exit(&oldtp->tn_rwlock);
		if (IS_DEVVP(*vpp)) {
			struct vnode *newvp;

			newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type,
			    cred);
			VN_RELE(*vpp);
			if (newvp == NULL) {
				return (ENOSYS);
			}
			*vpp = newvp;
		}

		if (trunc)
			vnevent_create(*vpp, ct);

		return (0);
	}

	if (error != ENOENT)
		return (error);

	rw_enter(&parent->tn_rwlock, RW_WRITER);
	error = tdirenter(tm, parent, nm, DE_CREATE,
	    (struct tmpnode *)NULL, (struct tmpnode *)NULL,
	    vap, &self, cred, ct);
	rw_exit(&parent->tn_rwlock);

	if (error) {
		if (self)
			tmpnode_rele(self);

		if (error == EEXIST) {
			/*
			 * This means that the file was created sometime
			 * after we checked and did not find it and when
			 * we went to create it.
			 * Since creat() is supposed to truncate a file
			 * that already exits go back to the begining
			 * of the function. This time we will find it
			 * and go down the tmp_trunc() path
			 */
			goto again;
		}
		return (error);
	}

	*vpp = TNTOV(self);

	if (!error && IS_DEVVP(*vpp)) {
		struct vnode *newvp;

		newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cred);
		VN_RELE(*vpp);
		if (newvp == NULL)
			return (ENOSYS);
		*vpp = newvp;
	}
	TRACE_3(TR_FAC_TMPFS, TR_TMPFS_CREATE,
	    "tmpfs create:dvp %p nm %s vpp %p", dvp, nm, vpp);
	return (0);
}

/* ARGSUSED3 */
static int
tmp_remove(
	struct vnode *dvp,
	char *nm,
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	struct tmpnode *parent = (struct tmpnode *)VTOTN(dvp);
	int error;
	struct tmpnode *tp = NULL;

	error = tdirlookup(parent, nm, &tp, cred);
	if (error)
		return (error);

	ASSERT(tp);
	rw_enter(&parent->tn_rwlock, RW_WRITER);
	rw_enter(&tp->tn_rwlock, RW_WRITER);

	error = (tp->tn_type == VDIR) ? EPERM :
	    tdirdelete(parent, tp, nm, DR_REMOVE, cred);

	rw_exit(&tp->tn_rwlock);
	rw_exit(&parent->tn_rwlock);
	vnevent_remove(TNTOV(tp), dvp, nm, ct);
	tmpnode_rele(tp);

	TRACE_3(TR_FAC_TMPFS, TR_TMPFS_REMOVE,
	    "tmpfs remove:dvp %p nm %s error %d", dvp, nm, error);
	return (error);
}

/* ARGSUSED4 */
static int
tmp_link(
	struct vnode *dvp,
	struct vnode *srcvp,
	char *tnm,
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	struct tmpnode *parent;
	struct tmpnode *from;
	struct tmount *tm = (struct tmount *)VTOTM(dvp);
	int error;
	struct tmpnode *found = NULL;
	struct vnode *realvp;

	if (VOP_REALVP(srcvp, &realvp, ct) == 0)
		srcvp = realvp;

	parent = (struct tmpnode *)VTOTN(dvp);
	from = (struct tmpnode *)VTOTN(srcvp);

	if (srcvp->v_type == VDIR ||
	    (from->tn_uid != crgetuid(cred) && secpolicy_basic_link(cred)))
		return (EPERM);

	/*
	 * Make sure link for extended attributes is valid
	 * We only support hard linking of xattr's in xattrdir to an xattrdir
	 */
	if ((from->tn_flags & ISXATTR) != (parent->tn_flags & ISXATTR))
		return (EINVAL);

	error = tdirlookup(parent, tnm, &found, cred);
	if (error == 0) {
		ASSERT(found);
		tmpnode_rele(found);
		return (EEXIST);
	}

	if (error != ENOENT)
		return (error);

	rw_enter(&parent->tn_rwlock, RW_WRITER);
	error = tdirenter(tm, parent, tnm, DE_LINK, (struct tmpnode *)NULL,
	    from, NULL, (struct tmpnode **)NULL, cred, ct);
	rw_exit(&parent->tn_rwlock);
	if (error == 0) {
		vnevent_link(srcvp, ct);
	}
	return (error);
}

/* ARGSUSED5 */
static int
tmp_rename(
	struct vnode *odvp,	/* source parent vnode */
	char *onm,		/* source name */
	struct vnode *ndvp,	/* destination parent vnode */
	char *nnm,		/* destination name */
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	struct tmpnode *fromparent;
	struct tmpnode *toparent;
	struct tmpnode *fromtp = NULL;	/* source tmpnode */
	struct tmpnode *totp;		/* target tmpnode */
	struct tmount *tm = (struct tmount *)VTOTM(odvp);
	int error;
	int samedir = 0;	/* set if odvp == ndvp */
	struct vnode *realvp;

	if (VOP_REALVP(ndvp, &realvp, ct) == 0)
		ndvp = realvp;

	fromparent = (struct tmpnode *)VTOTN(odvp);
	toparent = (struct tmpnode *)VTOTN(ndvp);

	if ((fromparent->tn_flags & ISXATTR) != (toparent->tn_flags & ISXATTR))
		return (EINVAL);

	mutex_enter(&tm->tm_renamelck);

	/*
	 * Look up tmpnode of file we're supposed to rename.
	 */
	error = tdirlookup(fromparent, onm, &fromtp, cred);
	if (error) {
		mutex_exit(&tm->tm_renamelck);
		return (error);
	}

	/*
	 * Make sure we can delete the old (source) entry.  This
	 * requires write permission on the containing directory.  If
	 * that directory is "sticky" it requires further checks.
	 */
	if (((error = tmp_taccess(fromparent, VWRITE, cred)) != 0) ||
	    (error = tmp_sticky_remove_access(fromparent, fromtp, cred)) != 0)
		goto done;

	/*
	 * Check for renaming to or from '.' or '..' or that
	 * fromtp == fromparent
	 */
	if ((onm[0] == '.' &&
	    (onm[1] == '\0' || (onm[1] == '.' && onm[2] == '\0'))) ||
	    (nnm[0] == '.' &&
	    (nnm[1] == '\0' || (nnm[1] == '.' && nnm[2] == '\0'))) ||
	    (fromparent == fromtp)) {
		error = EINVAL;
		goto done;
	}

	samedir = (fromparent == toparent);
	/*
	 * Make sure we can search and rename into the new
	 * (destination) directory.
	 */
	if (!samedir) {
		error = tmp_taccess(toparent, VEXEC|VWRITE, cred);
		if (error)
			goto done;
	}

	if (tdirlookup(toparent, nnm, &totp, cred) == 0) {
		vnevent_pre_rename_dest(TNTOV(totp), ndvp, nnm, ct);
		tmpnode_rele(totp);
	}

	/* Notify the target dir. if not the same as the source dir. */
	if (ndvp != odvp) {
		vnevent_pre_rename_dest_dir(ndvp, TNTOV(fromtp), nnm, ct);
	}

	vnevent_pre_rename_src(TNTOV(fromtp), odvp, onm, ct);

	/*
	 * Link source to new target
	 */
	rw_enter(&toparent->tn_rwlock, RW_WRITER);
	error = tdirenter(tm, toparent, nnm, DE_RENAME,
	    fromparent, fromtp, (struct vattr *)NULL,
	    (struct tmpnode **)NULL, cred, ct);
	rw_exit(&toparent->tn_rwlock);

	if (error) {
		/*
		 * ESAME isn't really an error; it indicates that the
		 * operation should not be done because the source and target
		 * are the same file, but that no error should be reported.
		 */
		if (error == ESAME)
			error = 0;
		goto done;
	}

	/*
	 * Unlink from source.
	 */
	rw_enter(&fromparent->tn_rwlock, RW_WRITER);
	rw_enter(&fromtp->tn_rwlock, RW_WRITER);

	error = tdirdelete(fromparent, fromtp, onm, DR_RENAME, cred);

	/*
	 * The following handles the case where our source tmpnode was
	 * removed before we got to it.
	 *
	 * XXX We should also cleanup properly in the case where tdirdelete
	 * fails for some other reason.  Currently this case shouldn't happen.
	 * (see 1184991).
	 */
	if (error == ENOENT)
		error = 0;

	rw_exit(&fromtp->tn_rwlock);
	rw_exit(&fromparent->tn_rwlock);

	if (error == 0) {
		vnevent_rename_src(TNTOV(fromtp), odvp, onm, ct);
		/*
		 * vnevent_rename_dest is called in tdirenter().
		 * Notify the target dir if not same as source dir.
		 */
		if (ndvp != odvp)
			vnevent_rename_dest_dir(ndvp, ct);
	}

done:
	tmpnode_rele(fromtp);
	mutex_exit(&tm->tm_renamelck);

	TRACE_5(TR_FAC_TMPFS, TR_TMPFS_RENAME,
	    "tmpfs rename:ovp %p onm %s nvp %p nnm %s error %d", odvp, onm,
	    ndvp, nnm, error);
	return (error);
}

/* ARGSUSED5 */
static int
tmp_mkdir(
	struct vnode *dvp,
	char *nm,
	struct vattr *va,
	struct vnode **vpp,
	struct cred *cred,
	caller_context_t *ct,
	int flags,
	vsecattr_t *vsecp)
{
	struct tmpnode *parent = (struct tmpnode *)VTOTN(dvp);
	struct tmpnode *self = NULL;
	struct tmount *tm = (struct tmount *)VTOTM(dvp);
	int error;

	/* no new dirs allowed in xattr dirs */
	if (parent->tn_flags & ISXATTR)
		return (EINVAL);

	/*
	 * Might be dangling directory.  Catch it here,
	 * because a ENOENT return from tdirlookup() is
	 * an "o.k. return".
	 */
	if (parent->tn_nlink == 0)
		return (ENOENT);

	error = tdirlookup(parent, nm, &self, cred);
	if (error == 0) {
		ASSERT(self);
		tmpnode_rele(self);
		return (EEXIST);
	}
	if (error != ENOENT)
		return (error);

	rw_enter(&parent->tn_rwlock, RW_WRITER);
	error = tdirenter(tm, parent, nm, DE_MKDIR, (struct tmpnode *)NULL,
	    (struct tmpnode *)NULL, va, &self, cred, ct);
	if (error) {
		rw_exit(&parent->tn_rwlock);
		if (self)
			tmpnode_rele(self);
		return (error);
	}
	rw_exit(&parent->tn_rwlock);
	*vpp = TNTOV(self);
	return (0);
}

/* ARGSUSED4 */
static int
tmp_rmdir(
	struct vnode *dvp,
	char *nm,
	struct vnode *cdir,
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	struct tmpnode *parent = (struct tmpnode *)VTOTN(dvp);
	struct tmpnode *self = NULL;
	struct vnode *vp;
	int error = 0;

	/*
	 * Return error when removing . and ..
	 */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST); /* Should be ENOTEMPTY */
	error = tdirlookup(parent, nm, &self, cred);
	if (error)
		return (error);

	rw_enter(&parent->tn_rwlock, RW_WRITER);
	rw_enter(&self->tn_rwlock, RW_WRITER);

	vp = TNTOV(self);
	if (vp == dvp || vp == cdir) {
		error = EINVAL;
		goto done1;
	}
	if (self->tn_type != VDIR) {
		error = ENOTDIR;
		goto done1;
	}

	mutex_enter(&self->tn_tlock);
	if (self->tn_nlink > 2) {
		mutex_exit(&self->tn_tlock);
		error = EEXIST;
		goto done1;
	}
	mutex_exit(&self->tn_tlock);

	if (vn_vfswlock(vp)) {
		error = EBUSY;
		goto done1;
	}
	if (vn_mountedvfs(vp) != NULL) {
		error = EBUSY;
		goto done;
	}

	/*
	 * Check for an empty directory
	 * i.e. only includes entries for "." and ".."
	 */
	if (self->tn_dirents > 2) {
		error = EEXIST;		/* SIGH should be ENOTEMPTY */
		/*
		 * Update atime because checking tn_dirents is logically
		 * equivalent to reading the directory
		 */
		gethrestime(&self->tn_atime);
		goto done;
	}

	error = tdirdelete(parent, self, nm, DR_RMDIR, cred);
done:
	vn_vfsunlock(vp);
done1:
	rw_exit(&self->tn_rwlock);
	rw_exit(&parent->tn_rwlock);
	vnevent_rmdir(TNTOV(self), dvp, nm, ct);
	tmpnode_rele(self);

	return (error);
}

/* ARGSUSED2 */
static int
tmp_readdir(
	struct vnode *vp,
	struct uio *uiop,
	struct cred *cred,
	int *eofp,
	caller_context_t *ct,
	int flags)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	struct tdirent *tdp;
	int error = 0;
	size_t namelen;
	struct dirent64 *dp;
	ulong_t offset;
	ulong_t total_bytes_wanted;
	long outcount = 0;
	long bufsize;
	int reclen;
	caddr_t outbuf;

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}
	/*
	 * assuming system call has already called tmp_rwlock
	 */
	ASSERT(RW_READ_HELD(&tp->tn_rwlock));

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * There's a window here where someone could have removed
	 * all the entries in the directory after we put a hold on the
	 * vnode but before we grabbed the rwlock.  Just return.
	 */
	if (tp->tn_dir == NULL) {
		if (tp->tn_nlink) {
			panic("empty directory 0x%p", (void *)tp);
			/*NOTREACHED*/
		}
		return (0);
	}

	/*
	 * Get space for multiple directory entries
	 */
	total_bytes_wanted = uiop->uio_iov->iov_len;
	bufsize = total_bytes_wanted + sizeof (struct dirent64);
	outbuf = kmem_alloc(bufsize, KM_SLEEP);

	dp = (struct dirent64 *)outbuf;


	offset = 0;
	tdp = tp->tn_dir;
	while (tdp) {
		namelen = strlen(tdp->td_name);	/* no +1 needed */
		offset = tdp->td_offset;
		if (offset >= uiop->uio_offset) {
			reclen = (int)DIRENT64_RECLEN(namelen);
			if (outcount + reclen > total_bytes_wanted) {
				if (!outcount)
					/*
					 * Buffer too small for any entries.
					 */
					error = EINVAL;
				break;
			}
			ASSERT(tdp->td_tmpnode != NULL);

			/* use strncpy(9f) to zero out uninitialized bytes */

			(void) strncpy(dp->d_name, tdp->td_name,
			    DIRENT64_NAMELEN(reclen));
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = (ino64_t)tdp->td_tmpnode->tn_nodeid;
			dp->d_off = (offset_t)tdp->td_offset + 1;
			dp = (struct dirent64 *)
			    ((uintptr_t)dp + dp->d_reclen);
			outcount += reclen;
			ASSERT(outcount <= bufsize);
		}
		tdp = tdp->td_next;
	}

	if (!error)
		error = uiomove(outbuf, outcount, UIO_READ, uiop);

	if (!error) {
		/* If we reached the end of the list our offset */
		/* should now be just past the end. */
		if (!tdp) {
			offset += 1;
			if (eofp)
				*eofp = 1;
		} else if (eofp)
			*eofp = 0;
		uiop->uio_offset = offset;
	}
	gethrestime(&tp->tn_atime);
	kmem_free(outbuf, bufsize);
	return (error);
}

/* ARGSUSED5 */
static int
tmp_symlink(
	struct vnode *dvp,
	char *lnm,
	struct vattr *tva,
	char *tnm,
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	struct tmpnode *parent = (struct tmpnode *)VTOTN(dvp);
	struct tmpnode *self = (struct tmpnode *)NULL;
	struct tmount *tm = (struct tmount *)VTOTM(dvp);
	char *cp = NULL;
	int error;
	size_t len;

	/* no symlinks allowed to files in xattr dirs */
	if (parent->tn_flags & ISXATTR)
		return (EINVAL);

	error = tdirlookup(parent, lnm, &self, cred);
	if (error == 0) {
		/*
		 * The entry already exists
		 */
		tmpnode_rele(self);
		return (EEXIST);	/* was 0 */
	}

	if (error != ENOENT) {
		if (self != NULL)
			tmpnode_rele(self);
		return (error);
	}

	rw_enter(&parent->tn_rwlock, RW_WRITER);
	error = tdirenter(tm, parent, lnm, DE_CREATE, (struct tmpnode *)NULL,
	    (struct tmpnode *)NULL, tva, &self, cred, ct);
	rw_exit(&parent->tn_rwlock);

	if (error) {
		if (self)
			tmpnode_rele(self);
		return (error);
	}
	len = strlen(tnm) + 1;
	cp = tmp_memalloc(len, 0);
	if (cp == NULL) {
		tmpnode_rele(self);
		return (ENOSPC);
	}
	(void) strcpy(cp, tnm);

	self->tn_symlink = cp;
	self->tn_size = len - 1;
	tmpnode_rele(self);
	return (error);
}

/* ARGSUSED2 */
static int
tmp_readlink(
	struct vnode *vp,
	struct uio *uiop,
	struct cred *cred,
	caller_context_t *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	int error = 0;

	if (vp->v_type != VLNK)
		return (EINVAL);

	rw_enter(&tp->tn_rwlock, RW_READER);
	rw_enter(&tp->tn_contents, RW_READER);
	error = uiomove(tp->tn_symlink, tp->tn_size, UIO_READ, uiop);
	gethrestime(&tp->tn_atime);
	rw_exit(&tp->tn_contents);
	rw_exit(&tp->tn_rwlock);
	return (error);
}

/* ARGSUSED */
static int
tmp_fsync(
	struct vnode *vp,
	int syncflag,
	struct cred *cred,
	caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static void
tmp_inactive(struct vnode *vp, struct cred *cred, caller_context_t *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	struct tmount *tm = (struct tmount *)VFSTOTM(vp->v_vfsp);

	rw_enter(&tp->tn_rwlock, RW_WRITER);
top:
	mutex_enter(&tp->tn_tlock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);

	/*
	 * If we don't have the last hold or the link count is non-zero,
	 * there's little to do -- just drop our hold.
	 */
	if (vp->v_count > 1 || tp->tn_nlink != 0) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_exit(&tp->tn_tlock);
		rw_exit(&tp->tn_rwlock);
		return;
	}

	/*
	 * We have the last hold *and* the link count is zero, so this
	 * tmpnode is dead from the filesystem's viewpoint.  However,
	 * if the tmpnode has any pages associated with it (i.e. if it's
	 * a normal file with non-zero size), the tmpnode can still be
	 * discovered by pageout or fsflush via the page vnode pointers.
	 * In this case we must drop all our locks, truncate the tmpnode,
	 * and try the whole dance again.
	 */
	if (tp->tn_size != 0) {
		if (tp->tn_type == VREG) {
			mutex_exit(&vp->v_lock);
			mutex_exit(&tp->tn_tlock);
			rw_enter(&tp->tn_contents, RW_WRITER);
			(void) tmpnode_trunc(tm, tp, 0);
			rw_exit(&tp->tn_contents);
			ASSERT(tp->tn_size == 0);
			ASSERT(tp->tn_nblocks == 0);
			goto top;
		}
		if (tp->tn_type == VLNK)
			tmp_memfree(tp->tn_symlink, tp->tn_size + 1);
	}

	/*
	 * Remove normal file/dir's xattr dir and xattrs.
	 */
	if (tp->tn_xattrdp) {
		struct tmpnode *xtp = tp->tn_xattrdp;

		ASSERT(xtp->tn_flags & ISXATTR);
		tmpnode_hold(xtp);
		rw_enter(&xtp->tn_rwlock, RW_WRITER);
		tdirtrunc(xtp);
		DECR_COUNT(&xtp->tn_nlink, &xtp->tn_tlock);
		tp->tn_xattrdp = NULL;
		rw_exit(&xtp->tn_rwlock);
		tmpnode_rele(xtp);
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&tp->tn_tlock);
	/* Here's our chance to send invalid event while we're between locks */
	vn_invalid(TNTOV(tp));
	mutex_enter(&tm->tm_contents);
	if (tp->tn_forw == NULL)
		tm->tm_rootnode->tn_back = tp->tn_back;
	else
		tp->tn_forw->tn_back = tp->tn_back;
	tp->tn_back->tn_forw = tp->tn_forw;
	mutex_exit(&tm->tm_contents);
	rw_exit(&tp->tn_rwlock);
	rw_destroy(&tp->tn_rwlock);
	mutex_destroy(&tp->tn_tlock);
	vn_free(TNTOV(tp));
	tmp_memfree(tp, sizeof (struct tmpnode));
}

/* ARGSUSED2 */
static int
tmp_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ct)
{
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	struct tfid *tfid;

	if (fidp->fid_len < (sizeof (struct tfid) - sizeof (ushort_t))) {
		fidp->fid_len = sizeof (struct tfid) - sizeof (ushort_t);
		return (ENOSPC);
	}

	tfid = (struct tfid *)fidp;
	bzero(tfid, sizeof (struct tfid));
	tfid->tfid_len = (int)sizeof (struct tfid) - sizeof (ushort_t);

	tfid->tfid_ino = tp->tn_nodeid;
	tfid->tfid_gen = tp->tn_gen;

	return (0);
}


/*
 * Return all the pages from [off..off+len] in given file
 */
/* ARGSUSED */
static int
tmp_getpage(
	struct vnode *vp,
	offset_t off,
	size_t len,
	uint_t *protp,
	page_t *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr,
	caller_context_t *ct)
{
	int err = 0;
	struct tmpnode *tp = VTOTN(vp);
	anoff_t toff = (anoff_t)off;
	size_t tlen = len;
	u_offset_t tmpoff;
	timestruc_t now;

	rw_enter(&tp->tn_contents, RW_READER);

	if (off + len  > tp->tn_size + PAGEOFFSET) {
		err = EFAULT;
		goto out;
	}
	/*
	 * Look for holes (no anon slot) in faulting range. If there are
	 * holes we have to switch to a write lock and fill them in. Swap
	 * space for holes was already reserved when the file was grown.
	 */
	tmpoff = toff;
	if (non_anon(tp->tn_anon, btop(off), &tmpoff, &tlen)) {
		if (!rw_tryupgrade(&tp->tn_contents)) {
			rw_exit(&tp->tn_contents);
			rw_enter(&tp->tn_contents, RW_WRITER);
			/* Size may have changed when lock was dropped */
			if (off + len  > tp->tn_size + PAGEOFFSET) {
				err = EFAULT;
				goto out;
			}
		}
		for (toff = (anoff_t)off; toff < (anoff_t)off + len;
		    toff += PAGESIZE) {
			if (anon_get_ptr(tp->tn_anon, btop(toff)) == NULL) {
				/* XXX - may allocate mem w. write lock held */
				(void) anon_set_ptr(tp->tn_anon, btop(toff),
				    anon_alloc(vp, toff), ANON_SLEEP);
				tp->tn_nblocks++;
			}
		}
		rw_downgrade(&tp->tn_contents);
	}


	err = pvn_getpages(tmp_getapage, vp, (u_offset_t)off, len, protp,
	    pl, plsz, seg, addr, rw, cr);

	gethrestime(&now);
	tp->tn_atime = now;
	if (rw == S_WRITE)
		tp->tn_mtime = now;

out:
	rw_exit(&tp->tn_contents);
	return (err);
}

/*
 * Called from pvn_getpages to get a particular page.
 */
/*ARGSUSED*/
static int
tmp_getapage(
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	uint_t *protp,
	page_t *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr)
{
	struct page *pp;
	int flags;
	int err = 0;
	struct vnode *pvp;
	u_offset_t poff;

	if (protp != NULL)
		*protp = PROT_ALL;
again:
	if (pp = page_lookup(vp, off, rw == S_CREATE ? SE_EXCL : SE_SHARED)) {
		if (pl) {
			pl[0] = pp;
			pl[1] = NULL;
		} else {
			page_unlock(pp);
		}
	} else {
		pp = page_create_va(vp, off, PAGESIZE,
		    PG_WAIT | PG_EXCL, seg, addr);
		/*
		 * Someone raced in and created the page after we did the
		 * lookup but before we did the create, so go back and
		 * try to look it up again.
		 */
		if (pp == NULL)
			goto again;
		/*
		 * Fill page from backing store, if any. If none, then
		 * either this is a newly filled hole or page must have
		 * been unmodified and freed so just zero it out.
		 */
		err = swap_getphysname(vp, off, &pvp, &poff);
		if (err) {
			panic("tmp_getapage: no anon slot vp %p "
			    "off %llx pp %p\n", (void *)vp, off, (void *)pp);
		}
		if (pvp) {
			flags = (pl == NULL ? B_ASYNC|B_READ : B_READ);
			err = VOP_PAGEIO(pvp, pp, (u_offset_t)poff, PAGESIZE,
			    flags, cr, NULL);
			if (flags & B_ASYNC)
				pp = NULL;
		} else if (rw != S_CREATE) {
			pagezero(pp, 0, PAGESIZE);
		}
		if (err && pp)
			pvn_read_done(pp, B_ERROR);
		if (err == 0) {
			if (pl)
				pvn_plist_init(pp, pl, plsz, off, PAGESIZE, rw);
			else
				pvn_io_done(pp);
		}
	}
	return (err);
}


/*
 * Flags are composed of {B_INVAL, B_DIRTY B_FREE, B_DONTNEED}.
 * If len == 0, do from off to EOF.
 */
static int tmp_nopage = 0;	/* Don't do tmp_putpage's if set */

/* ARGSUSED */
int
tmp_putpage(
	register struct vnode *vp,
	offset_t off,
	size_t len,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	register page_t *pp;
	u_offset_t io_off;
	size_t io_len = 0;
	int err = 0;
	struct tmpnode *tp = VTOTN(vp);
	int dolock;

	if (tmp_nopage)
		return (0);

	ASSERT(vp->v_count != 0);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	/*
	 * This being tmpfs, we don't ever do i/o unless we really
	 * have to (when we're low on memory and pageout calls us
	 * with B_ASYNC | B_FREE or the user explicitly asks for it with
	 * B_DONTNEED).
	 * XXX to approximately track the mod time like ufs we should
	 * update the times here. The problem is, once someone does a
	 * store we never clear the mod bit and do i/o, thus fsflush
	 * will keep calling us every 30 seconds to do the i/o and we'll
	 * continually update the mod time. At least we update the mod
	 * time on the first store because this results in a call to getpage.
	 */
	if (flags != (B_ASYNC | B_FREE) && (flags & B_INVAL) == 0 &&
	    (flags & B_DONTNEED) == 0)
		return (0);
	/*
	 * If this thread owns the lock, i.e., this thread grabbed it
	 * as writer somewhere above, then we don't need to grab the
	 * lock as reader in this routine.
	 */
	dolock = (rw_owner(&tp->tn_contents) != curthread);

	/*
	 * If this is pageout don't block on the lock as you could deadlock
	 * when freemem == 0 (another thread has the read lock and is blocked
	 * creating a page, and a third thread is waiting to get the writers
	 * lock - waiting writers priority blocks us from getting the read
	 * lock). Of course, if the only freeable pages are on this tmpnode
	 * we're hosed anyways. A better solution might be a new lock type.
	 * Note: ufs has the same problem.
	 */
	if (curproc == proc_pageout) {
		if (!rw_tryenter(&tp->tn_contents, RW_READER))
			return (ENOMEM);
	} else if (dolock)
		rw_enter(&tp->tn_contents, RW_READER);

	if (!vn_has_cached_data(vp))
		goto out;

	if (len == 0) {
		if (curproc == proc_pageout) {
			panic("tmp: pageout can't block");
			/*NOTREACHED*/
		}

		/* Search the entire vp list for pages >= off. */
		err = pvn_vplist_dirty(vp, (u_offset_t)off, tmp_putapage,
		    flags, cr);
	} else {
		u_offset_t eoff;

		/*
		 * Loop over all offsets in the range [off...off + len]
		 * looking for pages to deal with.
		 */
		eoff = MIN(off + len, tp->tn_size);
		for (io_off = off; io_off < eoff; io_off += io_len) {
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || pvn_getdirty(pp, flags) == 0)
				io_len = PAGESIZE;
			else {
				err = tmp_putapage(vp, pp, &io_off, &io_len,
				    flags, cr);
				if (err != 0)
					break;
			}
		}
	}
	/* If invalidating, verify all pages on vnode list are gone. */
	if (err == 0 && off == 0 && len == 0 &&
	    (flags & B_INVAL) && vn_has_cached_data(vp)) {
		panic("tmp_putpage: B_INVAL, pages not gone");
		/*NOTREACHED*/
	}
out:
	if ((curproc == proc_pageout) || dolock)
		rw_exit(&tp->tn_contents);
	/*
	 * Only reason putapage is going to give us SE_NOSWAP as error
	 * is when we ask a page to be written to physical backing store
	 * and there is none. Ignore this because we might be dealing
	 * with a swap page which does not have any backing store
	 * on disk. In any other case we won't get this error over here.
	 */
	if (err == SE_NOSWAP)
		err = 0;
	return (err);
}

long tmp_putpagecnt, tmp_pagespushed;

/*
 * Write out a single page.
 * For tmpfs this means choose a physical swap slot and write the page
 * out using VOP_PAGEIO. For performance, we attempt to kluster; i.e.,
 * we try to find a bunch of other dirty pages adjacent in the file
 * and a bunch of contiguous swap slots, and then write all the pages
 * out in a single i/o.
 */
/*ARGSUSED*/
static int
tmp_putapage(
	struct vnode *vp,
	page_t *pp,
	u_offset_t *offp,
	size_t *lenp,
	int flags,
	struct cred *cr)
{
	int err;
	ulong_t klstart, kllen;
	page_t *pplist, *npplist;
	extern int klustsize;
	long tmp_klustsize;
	struct tmpnode *tp;
	size_t pp_off, pp_len;
	u_offset_t io_off;
	size_t io_len;
	struct vnode *pvp;
	u_offset_t pstart;
	u_offset_t offset;
	u_offset_t tmpoff;

	ASSERT(PAGE_LOCKED(pp));

	/* Kluster in tmp_klustsize chunks */
	tp = VTOTN(vp);
	tmp_klustsize = klustsize;
	offset = pp->p_offset;
	klstart = (offset / tmp_klustsize) * tmp_klustsize;
	kllen = MIN(tmp_klustsize, tp->tn_size - klstart);

	/* Get a kluster of pages */
	pplist =
	    pvn_write_kluster(vp, pp, &tmpoff, &pp_len, klstart, kllen, flags);

	pp_off = (size_t)tmpoff;

	/*
	 * Get a cluster of physical offsets for the pages; the amount we
	 * get may be some subrange of what we ask for (io_off, io_len).
	 */
	io_off = pp_off;
	io_len = pp_len;
	err = swap_newphysname(vp, offset, &io_off, &io_len, &pvp, &pstart);
	ASSERT(err != SE_NOANON); /* anon slot must have been filled */
	if (err) {
		pvn_write_done(pplist, B_ERROR | B_WRITE | flags);
		/*
		 * If this routine is called as a result of segvn_sync
		 * operation and we have no physical swap then we can get an
		 * error here. In such case we would return SE_NOSWAP as error.
		 * At this point, we expect only SE_NOSWAP.
		 */
		ASSERT(err == SE_NOSWAP);
		if (flags & B_INVAL)
			err = ENOMEM;
		goto out;
	}
	ASSERT(pp_off <= io_off && io_off + io_len <= pp_off + pp_len);
	ASSERT(io_off <= offset && offset < io_off + io_len);

	/* Toss pages at front/rear that we couldn't get physical backing for */
	if (io_off != pp_off) {
		npplist = NULL;
		page_list_break(&pplist, &npplist, btop(io_off - pp_off));
		ASSERT(pplist->p_offset == pp_off);
		ASSERT(pplist->p_prev->p_offset == io_off - PAGESIZE);
		pvn_write_done(pplist, B_ERROR | B_WRITE | flags);
		pplist = npplist;
	}
	if (io_off + io_len < pp_off + pp_len) {
		npplist = NULL;
		page_list_break(&pplist, &npplist, btop(io_len));
		ASSERT(npplist->p_offset == io_off + io_len);
		ASSERT(npplist->p_prev->p_offset == pp_off + pp_len - PAGESIZE);
		pvn_write_done(npplist, B_ERROR | B_WRITE | flags);
	}

	ASSERT(pplist->p_offset == io_off);
	ASSERT(pplist->p_prev->p_offset == io_off + io_len - PAGESIZE);
	ASSERT(btopr(io_len) <= btopr(kllen));

	/* Do i/o on the remaining kluster */
	err = VOP_PAGEIO(pvp, pplist, (u_offset_t)pstart, io_len,
	    B_WRITE | flags, cr, NULL);

	if ((flags & B_ASYNC) == 0) {
		pvn_write_done(pplist, ((err) ? B_ERROR : 0) | B_WRITE | flags);
	}
out:
	if (!err) {
		if (offp)
			*offp = io_off;
		if (lenp)
			*lenp = io_len;
		tmp_putpagecnt++;
		tmp_pagespushed += btop(io_len);
	}
	if (err && err != ENOMEM && err != SE_NOSWAP)
		cmn_err(CE_WARN, "tmp_putapage: err %d\n", err);
	return (err);
}

/* ARGSUSED */
static int
tmp_map(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t *addrp,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	struct tmpnode *tp = (struct tmpnode *)VTOTN(vp);
	int error;

#ifdef _ILP32
	if (len > MAXOFF_T)
		return (ENOMEM);
#endif

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < 0 || (offset_t)(off + len) < 0 ||
	    off > MAXOFF_T || (off + len) > MAXOFF_T)
		return (ENXIO);

	if (vp->v_type != VREG)
		return (ENODEV);

	/*
	 * Don't allow mapping to locked file
	 */
	if (vn_has_mandatory_locks(vp, tp->tn_mode)) {
		return (EAGAIN);
	}

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		return (error);
	}

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.cred = cred;
	vn_a.amp = NULL;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);
	return (error);
}

/*
 * tmp_addmap and tmp_delmap can't be called since the vp
 * maintained in the segvn mapping is NULL.
 */
/* ARGSUSED */
static int
tmp_addmap(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uchar_t prot,
	uchar_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
tmp_delmap(
	struct vnode *vp,
	offset_t off,
	struct as *as,
	caddr_t addr,
	size_t len,
	uint_t prot,
	uint_t maxprot,
	uint_t flags,
	struct cred *cred,
	caller_context_t *ct)
{
	return (0);
}

static int
tmp_freesp(struct vnode *vp, struct flock64 *lp, int flag)
{
	register int i;
	register struct tmpnode *tp = VTOTN(vp);
	int error;

	ASSERT(vp->v_type == VREG);
	ASSERT(lp->l_start >= 0);

	if (lp->l_len != 0)
		return (EINVAL);

	rw_enter(&tp->tn_rwlock, RW_WRITER);
	if (tp->tn_size == lp->l_start) {
		rw_exit(&tp->tn_rwlock);
		return (0);
	}

	/*
	 * Check for any mandatory locks on the range
	 */
	if (MANDLOCK(vp, tp->tn_mode)) {
		long save_start;

		save_start = lp->l_start;

		if (tp->tn_size < lp->l_start) {
			/*
			 * "Truncate up" case: need to make sure there
			 * is no lock beyond current end-of-file. To
			 * do so, we need to set l_start to the size
			 * of the file temporarily.
			 */
			lp->l_start = tp->tn_size;
		}
		lp->l_type = F_WRLCK;
		lp->l_sysid = 0;
		lp->l_pid = ttoproc(curthread)->p_pid;
		i = (flag & (FNDELAY|FNONBLOCK)) ? 0 : SLPFLCK;
		if ((i = reclock(vp, lp, i, 0, lp->l_start, NULL)) != 0 ||
		    lp->l_type != F_UNLCK) {
			rw_exit(&tp->tn_rwlock);
			return (i ? i : EAGAIN);
		}

		lp->l_start = save_start;
	}
	VFSTOTM(vp->v_vfsp);

	rw_enter(&tp->tn_contents, RW_WRITER);
	error = tmpnode_trunc((struct tmount *)VFSTOTM(vp->v_vfsp),
	    tp, (ulong_t)lp->l_start);
	rw_exit(&tp->tn_contents);
	rw_exit(&tp->tn_rwlock);
	return (error);
}

/* ARGSUSED */
static int
tmp_space(
	struct vnode *vp,
	int cmd,
	struct flock64 *bfp,
	int flag,
	offset_t offset,
	cred_t *cred,
	caller_context_t *ct)
{
	int error;

	if (cmd != F_FREESP)
		return (EINVAL);
	if ((error = convoff(vp, bfp, 0, (offset_t)offset)) == 0) {
		if ((bfp->l_start > MAXOFF_T) || (bfp->l_len > MAXOFF_T))
			return (EFBIG);
		error = tmp_freesp(vp, bfp, flag);

		if (error == 0 && bfp->l_start == 0)
			vnevent_truncate(vp, ct);
	}
	return (error);
}

/* ARGSUSED */
static int
tmp_seek(
	struct vnode *vp,
	offset_t ooff,
	offset_t *noffp,
	caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/* ARGSUSED2 */
static int
tmp_rwlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	struct tmpnode *tp = VTOTN(vp);

	if (write_lock) {
		rw_enter(&tp->tn_rwlock, RW_WRITER);
	} else {
		rw_enter(&tp->tn_rwlock, RW_READER);
	}
	return (write_lock);
}

/* ARGSUSED1 */
static void
tmp_rwunlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	struct tmpnode *tp = VTOTN(vp);

	rw_exit(&tp->tn_rwlock);
}

static int
tmp_pathconf(
	struct vnode *vp,
	int cmd,
	ulong_t *valp,
	cred_t *cr,
	caller_context_t *ct)
{
	struct tmpnode *tp = NULL;
	int error;

	switch (cmd) {
	case _PC_XATTR_EXISTS:
		if (vp->v_vfsp->vfs_flag & VFS_XATTR) {
			*valp = 0;	/* assume no attributes */
			error = 0;	/* okay to ask */
			tp = VTOTN(vp);
			rw_enter(&tp->tn_rwlock, RW_READER);
			if (tp->tn_xattrdp) {
				rw_enter(&tp->tn_xattrdp->tn_rwlock, RW_READER);
				/* do not count "." and ".." */
				if (tp->tn_xattrdp->tn_dirents > 2)
					*valp = 1;
				rw_exit(&tp->tn_xattrdp->tn_rwlock);
			}
			rw_exit(&tp->tn_rwlock);
		} else {
			error = EINVAL;
		}
		break;
	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = vfs_has_feature(vp->v_vfsp, VFSFT_SYSATTR_VIEWS) &&
		    (vp->v_type == VREG || vp->v_type == VDIR);
		error = 0;
		break;
	case _PC_TIMESTAMP_RESOLUTION:
		/* nanosecond timestamp resolution */
		*valp = 1L;
		error = 0;
		break;
	default:
		error = fs_pathconf(vp, cmd, valp, cr, ct);
	}
	return (error);
}


struct vnodeops *tmp_vnodeops;

const fs_operation_def_t tmp_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = tmp_open },
	VOPNAME_CLOSE,		{ .vop_close = tmp_close },
	VOPNAME_READ,		{ .vop_read = tmp_read },
	VOPNAME_WRITE,		{ .vop_write = tmp_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = tmp_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = tmp_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = tmp_setattr },
	VOPNAME_ACCESS,		{ .vop_access = tmp_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = tmp_lookup },
	VOPNAME_CREATE,		{ .vop_create = tmp_create },
	VOPNAME_REMOVE,		{ .vop_remove = tmp_remove },
	VOPNAME_LINK,		{ .vop_link = tmp_link },
	VOPNAME_RENAME,		{ .vop_rename = tmp_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = tmp_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = tmp_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = tmp_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = tmp_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = tmp_readlink },
	VOPNAME_FSYNC,		{ .vop_fsync = tmp_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = tmp_inactive },
	VOPNAME_FID,		{ .vop_fid = tmp_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = tmp_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = tmp_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = tmp_seek },
	VOPNAME_SPACE,		{ .vop_space = tmp_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = tmp_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = tmp_putpage },
	VOPNAME_MAP,		{ .vop_map = tmp_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = tmp_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = tmp_delmap },
	VOPNAME_PATHCONF,	{ .vop_pathconf = tmp_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};
