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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
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
#include <sys/map.h>
#include <sys/fs/xmem.h>
#include <sys/mman.h>
#include <vm/hat.h>
#include <vm/seg.h>
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

static int	xmem_getapage(struct vnode *, u_offset_t, size_t, uint_t *,
	page_t **, size_t, struct seg *, caddr_t, enum seg_rw, struct cred *);

#ifndef lint
static int 	xmem_putapage(struct vnode *, page_t *, u_offset_t *, size_t *,
	int, struct cred *);
#endif


/* ARGSUSED1 */
static int
xmem_open(struct vnode **vpp, int flag, struct cred *cred)
{
	/*
	 * swapon to a xmemfs file is not supported so access
	 * is denied on open if VISSWAP is set.
	 */
	if ((*vpp)->v_flag & VISSWAP)
		return (EINVAL);
	return (0);
}

/* ARGSUSED1 */
static int
xmem_close(struct vnode *vp, int flag, int count, offset_t offset,
	struct cred *cred)
{
	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}


/*
 * wrxmem does the real work of write requests for xmemfs.
 */
static int
wrxmem(struct xmount *xm, struct xmemnode *xp, struct uio *uio,
	struct cred *cr, struct caller_context *ct)
{
	uint_t		blockoffset;	/* offset in the block */
	uint_t		blkwr;		/* offset in blocks into xmem file */
	uint_t		blkcnt;
	caddr_t		base;
	ssize_t		bytes;		/* bytes to uiomove */
	struct vnode	*vp;
	int		error = 0;
	size_t		bsize = xm->xm_bsize;
	rlim64_t	limit = uio->uio_llimit;
	long		oresid = uio->uio_resid;
	timestruc_t 	now;
	offset_t	offset;

	/*
	 * xp->xn_size is incremented before the uiomove
	 * is done on a write.  If the move fails (bad user
	 * address) reset xp->xn_size.
	 * The better way would be to increment xp->xn_size
	 * only if the uiomove succeeds.
	 */
	long		xn_size_changed = 0;
	offset_t	old_xn_size;

	vp = XNTOV(xp);
	ASSERT(vp->v_type == VREG);

	XMEMPRINTF(1, ("wrxmem: vp %p resid %lx off %llx\n",
	    (void *)vp, uio->uio_resid, uio->uio_loffset));

	ASSERT(RW_WRITE_HELD(&xp->xn_contents));
	ASSERT(RW_WRITE_HELD(&xp->xn_rwlock));

	if (MANDLOCK(vp, xp->xn_mode)) {
		rw_exit(&xp->xn_contents);
		/*
		 * xmem_getattr ends up being called by chklock
		 */
		error = chklock(vp, FWRITE,
			uio->uio_loffset, uio->uio_resid, uio->uio_fmode, ct);

		rw_enter(&xp->xn_contents, RW_WRITER);
		if (error != 0) {
			XMEMPRINTF(8, ("wrxmem: vp %p error %x\n",
			    (void *)vp, error));
			return (error);
		}
	}

	if ((offset = uio->uio_loffset) < 0)
		return (EINVAL);

	if (offset >= limit) {
		proc_t *p = ttoproc(curthread);

		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE], p->p_rctls,
		    p, RCA_UNSAFE_SIGINFO);
		mutex_exit(&p->p_lock);
		return (EFBIG);
	}

	if (uio->uio_resid == 0) {
		XMEMPRINTF(8, ("wrxmem: vp %p resid %lx\n",
			(void *)vp, uio->uio_resid));
		return (0);
	}

	/*
	 * Get the highest blocknumber and allocate page array if needed.
	 * Note that if xm_bsize != PAGESIZE, each ppa[] is pointer to
	 * a page array rather than just a page.
	 */
	blkcnt = howmany((offset + uio->uio_resid), bsize);
	blkwr = offset >> xm->xm_bshift;	/* write begins here */

	XMEMPRINTF(1, ("wrxmem: vp %p blkcnt %x blkwr %x xn_ppasz %lx\n",
	    (void *)vp, blkcnt, blkwr, xp->xn_ppasz));

	/* file size increase */
	if (xp->xn_ppasz < blkcnt) {

		page_t		***ppa;
		int		ppasz;
		uint_t		blksinfile = howmany(xp->xn_size, bsize);

		/*
		 * check if sufficient blocks available for the given offset.
		 */
		if (blkcnt - blksinfile > xm->xm_max - xm->xm_mem)
			return (ENOSPC);

		/*
		 * to prevent reallocating every time the file grows by a
		 * single block, double the size of the array.
		 */
		if (blkcnt < xp->xn_ppasz * 2)
			ppasz = xp->xn_ppasz * 2;
		else
			ppasz = blkcnt;


		ppa = kmem_zalloc(ppasz * sizeof (page_t **), KM_SLEEP);

		ASSERT(ppa);

		if (xp->xn_ppasz) {
			bcopy(xp->xn_ppa, ppa, blksinfile * sizeof (*ppa));
			kmem_free(xp->xn_ppa, xp->xn_ppasz * sizeof (*ppa));
		}
		xp->xn_ppa = ppa;
		xp->xn_ppasz = ppasz;

		/*
		 * fill in the 'hole' if write offset beyond file size. This
		 * helps in creating large files quickly; an application can
		 * lseek to a large offset and perform a single write
		 * operation to create the large file.
		 */

		if (blksinfile < blkwr) {

			old_xn_size = xp->xn_size;
			xp->xn_size = (offset_t)blkwr * bsize;

			XMEMPRINTF(4, ("wrxmem: fill vp %p blks %x to %x\n",
			    (void *)vp, blksinfile, blkcnt - 1));
			error = xmem_fillpages(xp, vp,
				(offset_t)blksinfile * bsize,
				(offset_t)(blkcnt - blksinfile) * bsize, 1);
			if (error) {
				/* truncate file back to original size */
				(void) xmemnode_trunc(xm, xp, old_xn_size);
				return (error);
			}
			/*
			 * if error on blkwr, this allows truncation of the
			 * filled hole.
			 */
			xp->xn_size = old_xn_size;
		}
	}

	do {
		offset_t	pagestart, pageend;
		page_t		**ppp;

		blockoffset = (uint_t)offset & (bsize - 1);
		/*
		 * A maximum of xm->xm_bsize bytes of data is transferred
		 * each pass through this loop
		 */
		bytes = MIN(bsize - blockoffset, uio->uio_resid);

		ASSERT(bytes);

		if (offset + bytes >= limit) {
			if (offset >= limit) {
				error = EFBIG;
				goto out;
			}
			bytes = limit - offset;
		}


		if (!xp->xn_ppa[blkwr]) {
			/* zero fill new pages - simplify partial updates */
			error = xmem_fillpages(xp, vp, offset, bytes, 1);
			if (error)
				return (error);
		}

		/* grow the file to the new length */
		if (offset + bytes > xp->xn_size) {
			xn_size_changed = 1;
			old_xn_size = xp->xn_size;
			xp->xn_size = offset + bytes;
		}

#ifdef LOCKNEST
		xmem_getpage();
#endif

		/* xn_ppa[] is a page_t * if ppb == 1 */
		if (xm->xm_ppb == 1)
			ppp = (page_t **)&xp->xn_ppa[blkwr];
		else
			ppp = &xp->xn_ppa[blkwr][btop(blockoffset)];

		pagestart = offset & ~(offset_t)(PAGESIZE - 1);
		/*
		 * subtract 1 in case (offset + bytes) is mod PAGESIZE
		 * so that pageend is the actual index of last page.
		 */
		pageend = (offset + bytes - 1) & ~(offset_t)(PAGESIZE - 1);

		base = segxmem_getmap(xm->xm_map, vp,
			pagestart, pageend - pagestart + PAGESIZE,
			ppp, S_WRITE);

		rw_exit(&xp->xn_contents);

		error = uiomove(base + (offset - pagestart), bytes,
							UIO_WRITE, uio);
		segxmem_release(xm->xm_map, base,
				pageend - pagestart + PAGESIZE);

		/*
		 * Re-acquire contents lock.
		 */
		rw_enter(&xp->xn_contents, RW_WRITER);
		/*
		 * If the uiomove failed, fix up xn_size.
		 */
		if (error) {
			if (xn_size_changed) {
				/*
				 * The uiomove failed, and we
				 * allocated blocks,so get rid
				 * of them.
				 */
				(void) xmemnode_trunc(xm, xp, old_xn_size);
			}
		} else {
			if ((xp->xn_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) &&
			    (xp->xn_mode & (S_ISUID | S_ISGID)) &&
			    secpolicy_vnode_setid_retain(cr,
			    (xp->xn_mode & S_ISUID) != 0 && xp->xn_uid == 0)
				!= 0) {

				/*
				 * Clear Set-UID & Set-GID bits on
				 * successful write if not privileged
				 * and at least one of the execute bits
				 * is set.  If we always clear Set-GID,
				 * mandatory file and record locking is
				 * unuseable.
				 */
				xp->xn_mode &= ~(S_ISUID | S_ISGID);
			}
			gethrestime(&now);
			xp->xn_mtime = now;
			xp->xn_ctime = now;
		}
		offset = uio->uio_loffset;	/* uiomove sets uio_loffset */
		blkwr++;
	} while (error == 0 && uio->uio_resid > 0 && bytes != 0);

out:
	/*
	 * If we've already done a partial-write, terminate
	 * the write but return no error.
	 */
	if (oresid != uio->uio_resid)
		error = 0;
	return (error);
}

/*
 * rdxmem does the real work of read requests for xmemfs.
 */
static int
rdxmem(
	struct xmount *xm,
	struct xmemnode *xp,
	struct uio *uio,
	struct caller_context *ct)
{
	ulong_t blockoffset;	/* offset in xmemfs file (uio_offset) */
	caddr_t base;
	ssize_t bytes;		/* bytes to uiomove */
	struct vnode *vp;
	int error;
	uint_t	blocknumber;
	long oresid = uio->uio_resid;
	size_t	bsize = xm->xm_bsize;
	offset_t	offset;

	vp = XNTOV(xp);

	XMEMPRINTF(1, ("rdxmem: vp %p\n", (void *)vp));

	ASSERT(RW_LOCK_HELD(&xp->xn_contents));

	if (MANDLOCK(vp, xp->xn_mode)) {
		rw_exit(&xp->xn_contents);
		/*
		 * xmem_getattr ends up being called by chklock
		 */
		error = chklock(vp, FREAD,
			uio->uio_loffset, uio->uio_resid, uio->uio_fmode, ct);
		rw_enter(&xp->xn_contents, RW_READER);
		if (error != 0) {
			XMEMPRINTF(1,
			    ("rdxmem: vp %p error %x\n", (void *)vp, error));
			return (error);
		}
	}
	ASSERT(xp->xn_type == VREG);

	if ((offset = uio->uio_loffset) >= MAXOFF_T) {
		XMEMPRINTF(1, ("rdxmem: vp %p bad offset %llx\n",
		    (void *)vp, uio->uio_loffset));
		return (0);
	}
	if (offset < 0)
		return (EINVAL);

	if (uio->uio_resid == 0) {
		XMEMPRINTF(1, ("rdxmem: vp %p resid 0\n", (void *)vp));
		return (0);
	}

	blocknumber = offset >> xm->xm_bshift;
	do {
		offset_t diff, pagestart, pageend;
		uint_t	pageinblock;

		blockoffset = offset & (bsize - 1);
		/*
		 * A maximum of xm->xm_bsize bytes of data is transferred
		 * each pass through this loop
		 */
		bytes = MIN(bsize - blockoffset, uio->uio_resid);

		diff = xp->xn_size - offset;

		if (diff <= 0) {
			error = 0;
			goto out;
		}
		if (diff < bytes)
			bytes = diff;

		if (!xp->xn_ppa[blocknumber])
			if (error = xmem_fillpages(xp, vp, offset, bytes, 1)) {
				return (error);
			}
		/*
		 * We have to drop the contents lock to prevent the VM
		 * system from trying to reacquire it in xmem_getpage()
		 * should the uiomove cause a pagefault.
		 */
		rw_exit(&xp->xn_contents);

#ifdef LOCKNEST
		xmem_getpage();
#endif

		/* 2/10 panic in hat_memload_array - len & MMU_OFFSET */

		pagestart = offset & ~(offset_t)(PAGESIZE - 1);
		pageend = (offset + bytes - 1) & ~(offset_t)(PAGESIZE - 1);
		if (xm->xm_ppb == 1)
			base = segxmem_getmap(xm->xm_map, vp,
			    pagestart, pageend - pagestart + PAGESIZE,
			    (page_t **)&xp->xn_ppa[blocknumber], S_READ);
		else {
			pageinblock = btop(blockoffset);
			base = segxmem_getmap(xm->xm_map, vp,
			    pagestart, pageend - pagestart + PAGESIZE,
			    &xp->xn_ppa[blocknumber][pageinblock], S_READ);

		}
		error = uiomove(base + (blockoffset & (PAGESIZE - 1)),
			bytes, UIO_READ, uio);

		segxmem_release(xm->xm_map, base,
			pageend - pagestart + PAGESIZE);
		/*
		 * Re-acquire contents lock.
		 */
		rw_enter(&xp->xn_contents, RW_READER);

		offset = uio->uio_loffset;
		blocknumber++;
	} while (error == 0 && uio->uio_resid > 0);

out:
	gethrestime(&xp->xn_atime);

	/*
	 * If we've already done a partial read, terminate
	 * the read but return no error.
	 */
	if (oresid != uio->uio_resid)
		error = 0;

	return (error);
}

/* ARGSUSED2 */
static int
xmem_read(struct vnode *vp, struct uio *uiop, int ioflag, cred_t *cred,
	struct caller_context *ct)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	struct xmount *xm = (struct xmount *)VTOXM(vp);
	int error;

	/*
	 * We don't currently support reading non-regular files
	 */
	if (vp->v_type != VREG)
		return (EINVAL);
	/*
	 * xmem_rwlock should have already been called from layers above
	 */
	ASSERT(RW_READ_HELD(&xp->xn_rwlock));

	rw_enter(&xp->xn_contents, RW_READER);

	error = rdxmem(xm, xp, uiop, ct);

	rw_exit(&xp->xn_contents);

	return (error);
}

static int
xmem_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cred,
	struct caller_context *ct)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	struct xmount *xm = (struct xmount *)VTOXM(vp);
	int error;

	/*
	 * We don't currently support writing to non-regular files
	 */
	if (vp->v_type != VREG)
		return (EINVAL);	/* XXX EISDIR? */

	/*
	 * xmem_rwlock should have already been called from layers above
	 */
	ASSERT(RW_WRITE_HELD(&xp->xn_rwlock));

	rw_enter(&xp->xn_contents, RW_WRITER);

	if (ioflag & FAPPEND) {
		/*
		 * In append mode start at end of file.
		 */
		uiop->uio_loffset = xp->xn_size;
	}

	error = wrxmem(xm, xp, uiop, cred, ct);

	rw_exit(&xp->xn_contents);

	return (error);
}

/* ARGSUSED */
static int
xmem_ioctl(struct vnode *vp, int com, intptr_t data, int flag,
    struct cred *cred, int *rvalp)
{
	return (ENOTTY);
}

/* ARGSUSED2 */
static int
xmem_getattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cred)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	struct xmount *xm = (struct xmount *)VTOXM(vp);

	mutex_enter(&xp->xn_tlock);

	*vap = xp->xn_attr;

	vap->va_mode = xp->xn_mode & MODEMASK;
	vap->va_type = vp->v_type;
	vap->va_blksize = xm->xm_bsize;
	vap->va_nblocks = (fsblkcnt64_t)btodb(ptob(btopr(vap->va_size)));

	mutex_exit(&xp->xn_tlock);
	return (0);
}

/*ARGSUSED*/
static int
xmem_setattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cred,
	caller_context_t *ct)
{
	struct xmount *xm = (struct xmount *)VTOXM(vp);
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	int error;
	struct vattr *get;
	register long int mask = vap->va_mask;

	/*
	 * Cannot set these attributes
	 */
	if (mask & AT_NOSET)
		return (EINVAL);

	mutex_enter(&xp->xn_tlock);

	get = &xp->xn_attr;

	error = secpolicy_vnode_setattr(cred, vp, vap, get, flags,
			xmem_xaccess, xp);

	if (error != 0)
		goto out;

	mask = vap->va_mask;

	/*
	 * Change file access modes.
	 */
	if (mask & AT_MODE) {
		/* prevent execute permission to be set for regular files */
		if (S_ISREG(get->va_mode))
			vap->va_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);

		XMEMPRINTF(1, ("xmem_setattr: va_mode old %x new %x\n",
				get->va_mode, vap->va_mode));

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
		gethrestime(&get->va_ctime);

	if (mask & AT_SIZE) {
		if (vp->v_type == VDIR) {
			error =  EISDIR;
			goto out;
		}
		/* Don't support large files. */
		if (vap->va_size > MAXOFF_T) {
			error = EFBIG;
			goto out;
		}
		if (error = xmem_xaccess(xp, VWRITE, cred))
			goto out;
		mutex_exit(&xp->xn_tlock);

		rw_enter(&xp->xn_rwlock, RW_WRITER);
		rw_enter(&xp->xn_contents, RW_WRITER);
		error = xmemnode_trunc(xm, xp, vap->va_size);
		rw_exit(&xp->xn_contents);
		rw_exit(&xp->xn_rwlock);
		goto out1;
	}
out:
	mutex_exit(&xp->xn_tlock);
out1:
	return (error);
}

/* ARGSUSED2 */
static int
xmem_access(struct vnode *vp, int mode, int flags, struct cred *cred)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	int error;

	mutex_enter(&xp->xn_tlock);
	error = xmem_xaccess(xp, mode, cred);
	mutex_exit(&xp->xn_tlock);
	return (error);
}

/* ARGSUSED3 */
static int
xmem_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
	struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(dvp);
	struct xmemnode *nxp = NULL;
	int error;

	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}
	ASSERT(xp);

	error = xdirlookup(xp, nm, &nxp, cred);

	if (error == 0) {
		ASSERT(nxp);
		*vpp = XNTOV(nxp);
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
	return (error);
}

/*ARGSUSED7*/
static int
xmem_create(struct vnode *dvp, char *nm, struct vattr *vap,
	enum vcexcl exclusive, int mode, struct vnode **vpp, struct cred *cred,
	int flag)
{
	struct xmemnode *parent;
	struct xmount *xm;
	struct xmemnode *self;
	int error;
	struct xmemnode *oldxp;

again:
	parent = (struct xmemnode *)VTOXN(dvp);
	xm = (struct xmount *)VTOXM(dvp);
	self = NULL;
	error = 0;
	oldxp = NULL;

	if (vap->va_type == VREG && (vap->va_mode & VSVTX)) {
		/* Must be privileged to set sticky bit */
		if (secpolicy_vnode_stky_modify(cred) != 0)
			vap->va_mode &= ~VSVTX;
	} else if (vap->va_type == VNON) {
		return (EINVAL);
	}

	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		oldxp = parent;
	} else {
		error = xdirlookup(parent, nm, &oldxp, cred);
	}

	if (error == 0) {	/* name found */
		ASSERT(oldxp);

		rw_enter(&oldxp->xn_rwlock, RW_WRITER);

		/*
		 * if create/read-only an existing
		 * directory, allow it
		 */
		if (exclusive == EXCL)
			error = EEXIST;
		else if ((oldxp->xn_type == VDIR) && (mode & VWRITE))
			error = EISDIR;
		else {
			error = xmem_xaccess(oldxp, mode, cred);
		}

		if (error) {
			rw_exit(&oldxp->xn_rwlock);
			xmemnode_rele(oldxp);
			return (error);
		}
		*vpp = XNTOV(oldxp);
		if ((*vpp)->v_type == VREG && (vap->va_mask & AT_SIZE) &&
		    vap->va_size == 0) {
			rw_enter(&oldxp->xn_contents, RW_WRITER);
			(void) xmemnode_trunc(xm, oldxp, 0);
			rw_exit(&oldxp->xn_contents);
		}
		rw_exit(&oldxp->xn_rwlock);
		if (IS_DEVVP(*vpp)) {
			struct vnode *newvp;

			newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type,
			    cred);
			VN_RELE(*vpp);
			*vpp = newvp;
		}
		return (0);
	}

	if (error != ENOENT)
		return (error);

	rw_enter(&parent->xn_rwlock, RW_WRITER);
	error = xdirenter(xm, parent, nm, DE_CREATE,
	    (struct xmemnode *)NULL, (struct xmemnode *)NULL,
	    vap, &self, cred);
	rw_exit(&parent->xn_rwlock);

	if (error) {
		if (self)
			xmemnode_rele(self);

		if (error == EEXIST) {
			/*
			 * This means that the file was created sometime
			 * after we checked and did not find it and when
			 * we went to create it.
			 * Since creat() is supposed to truncate a file
			 * that already exits go back to the begining
			 * of the function. This time we will find it
			 * and go down the xmem_trunc() path
			 */
			goto again;
		}
		return (error);
	}

	*vpp = XNTOV(self);

	if (IS_DEVVP(*vpp)) {
		struct vnode *newvp;

		newvp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type,
		    cred);
		VN_RELE(*vpp);
		*vpp = newvp;
	}

	return (0);
}

static int
xmem_remove(struct vnode *dvp, char *nm, struct cred *cred)
{
	struct xmemnode *parent = (struct xmemnode *)VTOXN(dvp);
	int error;
	struct xmemnode *xp = NULL;

	error = xdirlookup(parent, nm, &xp, cred);
	if (error)
		return (error);

	ASSERT(xp);
	rw_enter(&parent->xn_rwlock, RW_WRITER);
	rw_enter(&xp->xn_rwlock, RW_WRITER);

	if (xp->xn_type != VDIR ||
	    (error = secpolicy_fs_linkdir(cred, dvp->v_vfsp)) == 0)
		error = xdirdelete(parent, xp, nm, DR_REMOVE, cred);

	rw_exit(&xp->xn_rwlock);
	rw_exit(&parent->xn_rwlock);
	xmemnode_rele(xp);

	return (error);
}

static int
xmem_link(struct vnode *dvp, struct vnode *srcvp, char *tnm, struct cred *cred)
{
	struct xmemnode *parent;
	struct xmemnode *from;
	struct xmount *xm = (struct xmount *)VTOXM(dvp);
	int error;
	struct xmemnode *found = NULL;
	struct vnode *realvp;

	if (VOP_REALVP(srcvp, &realvp) == 0)
		srcvp = realvp;

	parent = (struct xmemnode *)VTOXN(dvp);
	from = (struct xmemnode *)VTOXN(srcvp);

	if ((srcvp->v_type == VDIR &&
	    secpolicy_fs_linkdir(cred, dvp->v_vfsp) != 0) ||
	    (from->xn_uid != crgetuid(cred) && secpolicy_basic_link(cred) != 0))
		return (EPERM);

	error = xdirlookup(parent, tnm, &found, cred);
	if (error == 0) {
		ASSERT(found);
		xmemnode_rele(found);
		return (EEXIST);
	}

	if (error != ENOENT)
		return (error);

	rw_enter(&parent->xn_rwlock, RW_WRITER);
	error = xdirenter(xm, parent, tnm, DE_LINK, (struct xmemnode *)NULL,
		from, NULL, (struct xmemnode **)NULL, cred);
	rw_exit(&parent->xn_rwlock);
	return (error);
}

static int
xmem_rename(
	struct vnode *odvp,	/* source parent vnode */
	char *onm,		/* source name */
	struct vnode *ndvp,	/* destination parent vnode */
	char *nnm,		/* destination name */
	struct cred *cred)
{
	struct xmemnode *fromparent;
	struct xmemnode *toparent;
	struct xmemnode *fromxp = NULL;	/* source xmemnode */
	struct xmount *xm = (struct xmount *)VTOXM(odvp);
	int error;
	int samedir = 0;	/* set if odvp == ndvp */
	struct vnode *realvp;

	if (VOP_REALVP(ndvp, &realvp) == 0)
		ndvp = realvp;

	fromparent = (struct xmemnode *)VTOXN(odvp);
	toparent = (struct xmemnode *)VTOXN(ndvp);

	mutex_enter(&xm->xm_renamelck);

	/*
	 * Look up xmemnode of file we're supposed to rename.
	 */
	error = xdirlookup(fromparent, onm, &fromxp, cred);
	if (error) {
		mutex_exit(&xm->xm_renamelck);
		return (error);
	}

	/*
	 * Make sure we can delete the old (source) entry.  This
	 * requires write permission on the containing directory.  If
	 * that directory is "sticky" it further requires (except for
	 * for privileged users) that the user own the directory or
	 * the source entry, or else have permission to write the
	 * source entry.
	 */
	if (((error = xmem_xaccess(fromparent, VWRITE, cred)) != 0) ||
	    (error = xmem_sticky_remove_access(fromparent, fromxp, cred)) != 0)
		goto done;

	/*
	 * Check for renaming to or from '.' or '..' or that
	 * fromxp == fromparent
	 */
	if ((onm[0] == '.' &&
	    (onm[1] == '\0' || (onm[1] == '.' && onm[2] == '\0'))) ||
	    (nnm[0] == '.' &&
	    (nnm[1] == '\0' || (nnm[1] == '.' && nnm[2] == '\0'))) ||
	    (fromparent == fromxp)) {
		error = EINVAL;
		goto done;
	}

	samedir = (fromparent == toparent);
	/*
	 * Make sure we can search and rename into the new
	 * (destination) directory.
	 */
	if (!samedir) {
		error = xmem_xaccess(toparent, VEXEC|VWRITE, cred);
		if (error)
			goto done;
	}

	/*
	 * Link source to new target
	 */
	rw_enter(&toparent->xn_rwlock, RW_WRITER);
	error = xdirenter(xm, toparent, nnm, DE_RENAME,
	    fromparent, fromxp, (struct vattr *)NULL,
	    (struct xmemnode **)NULL, cred);
	rw_exit(&toparent->xn_rwlock);

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
	rw_enter(&fromparent->xn_rwlock, RW_WRITER);
	rw_enter(&fromxp->xn_rwlock, RW_WRITER);

	error = xdirdelete(fromparent, fromxp, onm, DR_RENAME, cred);

	/*
	 * The following handles the case where our source xmemnode was
	 * removed before we got to it.
	 *
	 * XXX We should also cleanup properly in the case where xdirdelete
	 * fails for some other reason.  Currently this case shouldn't happen.
	 * (see 1184991).
	 */
	if (error == ENOENT)
		error = 0;

	rw_exit(&fromxp->xn_rwlock);
	rw_exit(&fromparent->xn_rwlock);
done:
	xmemnode_rele(fromxp);
	mutex_exit(&xm->xm_renamelck);

	return (error);
}

static int
xmem_mkdir(struct vnode *dvp, char *nm, struct vattr *va, struct vnode **vpp,
	struct cred *cred)
{
	struct xmemnode *parent = (struct xmemnode *)VTOXN(dvp);
	struct xmemnode *self = NULL;
	struct xmount *xm = (struct xmount *)VTOXM(dvp);
	int error;

	/*
	 * Might be dangling directory.  Catch it here,
	 * because a ENOENT return from xdirlookup() is
	 * an "o.k. return".
	 */
	if (parent->xn_nlink == 0)
		return (ENOENT);

	error = xdirlookup(parent, nm, &self, cred);
	if (error == 0) {
		ASSERT(self);
		xmemnode_rele(self);
		return (EEXIST);
	}
	if (error != ENOENT)
		return (error);

	rw_enter(&parent->xn_rwlock, RW_WRITER);
	error = xdirenter(xm, parent, nm, DE_MKDIR,
		(struct xmemnode *)NULL, (struct xmemnode *)NULL, va,
		&self, cred);
	if (error) {
		rw_exit(&parent->xn_rwlock);
		if (self)
			xmemnode_rele(self);
		return (error);
	}
	rw_exit(&parent->xn_rwlock);
	*vpp = XNTOV(self);
	return (0);
}

static int
xmem_rmdir(struct vnode *dvp, char *nm, struct vnode *cdir, struct cred *cred)
{
	struct xmemnode *parent = (struct xmemnode *)VTOXN(dvp);
	struct xmemnode *self = NULL;
	struct vnode *vp;
	int error = 0;

	/*
	 * Return error when removing . and ..
	 */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST); /* Should be ENOTEMPTY */
	error = xdirlookup(parent, nm, &self, cred);
	if (error)
		return (error);

	rw_enter(&parent->xn_rwlock, RW_WRITER);
	rw_enter(&self->xn_rwlock, RW_WRITER);

	vp = XNTOV(self);
	if (vp == dvp || vp == cdir) {
		error = EINVAL;
		goto done1;
	}
	if (self->xn_type != VDIR) {
		error = ENOTDIR;
		goto done1;
	}

	mutex_enter(&self->xn_tlock);
	if (self->xn_nlink > 2) {
		mutex_exit(&self->xn_tlock);
		error = EEXIST;
		goto done1;
	}
	mutex_exit(&self->xn_tlock);

	if (vn_vfslock(vp)) {
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
	if (self->xn_dirents > 2) {
		error = EEXIST;		/* SIGH should be ENOTEMPTY */
		/*
		 * Update atime because checking xn_dirents is logically
		 * equivalent to reading the directory
		 */
		gethrestime(&self->xn_atime);
		goto done;
	}

	error = xdirdelete(parent, self, nm, DR_RMDIR, cred);
done:
	vn_vfsunlock(vp);
done1:
	rw_exit(&self->xn_rwlock);
	rw_exit(&parent->xn_rwlock);
	xmemnode_rele(self);

	return (error);
}

/* ARGSUSED2 */

static int
xmem_readdir(struct vnode *vp, struct uio *uiop, struct cred *cred, int *eofp)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	struct xdirent *xdp;
	int error;
	register struct dirent64 *dp;
	register ulong_t offset;
	register ulong_t total_bytes_wanted;
	register long outcount = 0;
	register long bufsize;
	int reclen;
	caddr_t outbuf;

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}
	/*
	 * assuming system call has already called xmem_rwlock
	 */
	ASSERT(RW_READ_HELD(&xp->xn_rwlock));

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/*
	 * There's a window here where someone could have removed
	 * all the entries in the directory after we put a hold on the
	 * vnode but before we grabbed the rwlock.  Just return unless
	 * there are still references to the current file in which case panic.
	 */
	if (xp->xn_dir == NULL) {
		if (xp->xn_nlink)
			cmn_err(CE_PANIC, "empty directory 0x%p", (void *)xp);
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
	xdp = xp->xn_dir;
	while (xdp) {
		offset = xdp->xd_offset;
		if (offset >= uiop->uio_offset) {
			reclen = (int)DIRENT64_RECLEN(strlen(xdp->xd_name));
			if (outcount + reclen > total_bytes_wanted)
				break;
			ASSERT(xdp->xd_xmemnode != NULL);

			/* use strncpy(9f) to zero out uninitialized bytes */

			ASSERT(strlen(xdp->xd_name) + 1 <=
			    DIRENT64_NAMELEN(reclen));
			(void) strncpy(dp->d_name, xdp->xd_name,
			    DIRENT64_NAMELEN(reclen));
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = (ino64_t)xdp->xd_xmemnode->xn_nodeid;
			dp->d_off = (offset_t)xdp->xd_offset + 1;
			dp = (struct dirent64 *)
			    ((uintptr_t)dp + dp->d_reclen);
			outcount += reclen;
			ASSERT(outcount <= bufsize);
		}
		xdp = xdp->xd_next;
	}
	error = uiomove(outbuf, outcount, UIO_READ, uiop);
	if (!error) {
		/* If we reached the end of the list our offset */
		/* should now be just past the end. */
		if (!xdp) {
			offset += 1;
			if (eofp)
				*eofp = 1;
		} else if (eofp)
			*eofp = 0;
		uiop->uio_offset = offset;
	}
	gethrestime(&xp->xn_atime);
	kmem_free(outbuf, bufsize);
	return (error);
}

static int
xmem_symlink(struct vnode *dvp, char *lnm, struct vattr *tva, char *tnm,
	struct cred *cred)
{
	struct xmemnode *parent = (struct xmemnode *)VTOXN(dvp);
	struct xmemnode *self = (struct xmemnode *)NULL;
	struct xmount *xm = (struct xmount *)VTOXM(dvp);
	char *cp = NULL;
	int error;
	size_t len;

	error = xdirlookup(parent, lnm, &self, cred);
	if (error == 0) {
		/*
		 * The entry already exists
		 */
		xmemnode_rele(self);
		return (EEXIST);	/* was 0 */
	}

	if (error != ENOENT) {
		if (self != NULL)
			xmemnode_rele(self);
		return (error);
	}

	rw_enter(&parent->xn_rwlock, RW_WRITER);
	error = xdirenter(xm, parent, lnm, DE_CREATE, (struct xmemnode *)NULL,
	    (struct xmemnode *)NULL, tva, &self, cred);
	rw_exit(&parent->xn_rwlock);

	if (error) {
		if (self)
			xmemnode_rele(self);
		return (error);
	}
	len = strlen(tnm) + 1;
	cp = xmem_memalloc(len, 0);
	if (cp == NULL) {
		xmemnode_rele(self);
		return (ENOSPC);
	}
	(void) strcpy(cp, tnm);

	self->xn_symlink = cp;
	self->xn_size = len - 1;
	xmemnode_rele(self);
	return (error);
}

/* ARGSUSED2 */
static int
xmem_readlink(struct vnode *vp, struct uio *uiop, struct cred *cred)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	int error = 0;

	if (vp->v_type != VLNK)
		return (EINVAL);

	rw_enter(&xp->xn_rwlock, RW_READER);
	rw_enter(&xp->xn_contents, RW_READER);
	error = uiomove(xp->xn_symlink, xp->xn_size, UIO_READ, uiop);
	gethrestime(&xp->xn_atime);
	rw_exit(&xp->xn_contents);
	rw_exit(&xp->xn_rwlock);
	return (error);
}

/* ARGSUSED */
static int
xmem_fsync(struct vnode *vp, int syncflag, struct cred *cred)
{
	return (0);
}

/* ARGSUSED */
static void
xmem_inactive(struct vnode *vp, struct cred *cred)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	struct xmount *xm = (struct xmount *)VFSTOXM(vp->v_vfsp);

	rw_enter(&xp->xn_rwlock, RW_WRITER);
top:
	mutex_enter(&xp->xn_tlock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);

	/*
	 * If we don't have the last hold or the link count is non-zero,
	 * there's little to do -- just drop our hold.
	 */
	if (vp->v_count > 1 || xp->xn_nlink != 0) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_exit(&xp->xn_tlock);
		rw_exit(&xp->xn_rwlock);
		return;
	}

	/*
	 * We have the last hold *and* the link count is zero, so this
	 * xmemnode is dead from the filesystem's viewpoint.  However,
	 * if the xmemnode has any pages associated with it (i.e. if it's
	 * a normal file with non-zero size), the xmemnode can still be
	 * discovered by pageout or fsflush via the page vnode pointers.
	 * In this case we must drop all our locks, truncate the xmemnode,
	 * and try the whole dance again.
	 */
	if (xp->xn_size != 0) {
		if (xp->xn_type == VREG) {
			mutex_exit(&vp->v_lock);
			mutex_exit(&xp->xn_tlock);
			rw_enter(&xp->xn_contents, RW_WRITER);
			(void) xmemnode_trunc(xm, xp, 0);
			rw_exit(&xp->xn_contents);
			ASSERT(xp->xn_size == 0);
			ASSERT(xp->xn_nblocks == 0);
			goto top;
		}
		if (xp->xn_type == VLNK)
			xmem_memfree(xp->xn_symlink, xp->xn_size + 1);
	}

	mutex_exit(&vp->v_lock);
	mutex_exit(&xp->xn_tlock);
	mutex_enter(&xm->xm_contents);
	if (xp->xn_forw == NULL)
		xm->xm_rootnode->xn_back = xp->xn_back;
	else
		xp->xn_forw->xn_back = xp->xn_back;
	xp->xn_back->xn_forw = xp->xn_forw;
	mutex_exit(&xm->xm_contents);
	rw_exit(&xp->xn_rwlock);
	rw_destroy(&xp->xn_rwlock);
	mutex_destroy(&xp->xn_tlock);
	vn_free(xp->xn_vnode);
	xmem_memfree(xp, sizeof (struct xmemnode));
}

static int
xmem_fid(struct vnode *vp, struct fid *fidp)
{
	struct xmemnode *xp = (struct xmemnode *)VTOXN(vp);
	struct xfid *xfid;

	if (fidp->fid_len < (sizeof (struct xfid) - sizeof (ushort_t))) {
		fidp->fid_len = sizeof (struct xfid) - sizeof (ushort_t);
		return (ENOSPC);
	}

	xfid = (struct xfid *)fidp;
	bzero(xfid, sizeof (struct xfid));
	xfid->xfid_len = (int)sizeof (struct xfid) - sizeof (ushort_t);

	xfid->xfid_ino = xp->xn_nodeid;
	xfid->xfid_gen = xp->xn_gen;

	return (0);
}


/*
 * Return all the pages from [off..off+len] in given file
 */
static int
xmem_getpage(struct vnode *vp, offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, struct cred *cr)
{
	int err = 0;
	struct xmemnode *xp = VTOXN(vp);
	struct xmount *xm = (struct xmount *)VTOXM(vp);
	timestruc_t now;

	cmn_err(CE_PANIC, "xmem_getpage");
	rw_enter(&xp->xn_contents, RW_READER);

	if (off + len  > xp->xn_size + xm->xm_bsize) {
		rw_exit(&xp->xn_contents);
		return (EFAULT);
	}
	rw_exit(&xp->xn_contents);

	if (len <= xm->xm_bsize)
		err = xmem_getapage(vp, (u_offset_t)off, len, protp, pl, plsz,
		    seg, addr, rw, cr);
	else
		err = pvn_getpages(xmem_getapage, vp, (u_offset_t)off, len,
		    protp, pl, plsz, seg, addr, rw, cr);

	rw_enter(&xp->xn_contents, RW_WRITER);
	gethrestime(&now);
	xp->xn_atime = now;
	if (rw == S_WRITE)
		xp->xn_mtime = now;
	rw_exit(&xp->xn_contents);

	return (err);
}

/*
 * Called from pvn_getpages to get a particular page.
 */
/*ARGSUSED*/
static int
xmem_getapage(struct vnode *vp, u_offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, struct cred *cr)
{
	cmn_err(CE_PANIC, "xmem_getapage");
	return (0);
}

/* ARGSUSED */
int
xmem_putpage(struct vnode *vp, offset_t off, size_t len, int flags,
	struct cred *cr)
{
	return (0);
}

#ifndef lint
/*
 * Write out a single page.
 * For xmemfs this means choose a physical swap slot and write the page
 * out using VOP_PAGEIO. For performance, we attempt to kluster; i.e.,
 * we try to find a bunch of other dirty pages adjacent in the file
 * and a bunch of contiguous swap slots, and then write all the pages
 * out in a single i/o.
 */
/*ARGSUSED*/
static int
xmem_putapage(struct vnode *vp, page_t *pp, u_offset_t *offp,
	size_t *lenp, int flags, struct cred *cr)
{
	cmn_err(CE_PANIC, "xmem putapage");
	return (1);
}
#endif


static int
xmem_map(struct vnode *vp, offset_t off, struct as *as, caddr_t *addrp,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	struct cred *cred)
{
	struct seg		*seg;
	struct segxmem_crargs	xmem_a;
	struct xmemnode 	*xp = (struct xmemnode *)VTOXN(vp);
	struct xmount 		*xm = (struct xmount *)VTOXM(vp);
	uint_t			blocknumber;
	int 			error;

#ifdef lint
	maxprot = maxprot;
#endif
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < 0)
		return (EINVAL);

	/* offset, length and address has to all be block aligned */

	if (off & (xm->xm_bsize - 1) || len & (xm->xm_bsize - 1) ||
		((ulong_t)*addrp) & (xm->xm_bsize - 1)) {

		return (EINVAL);
	}

	if (vp->v_type != VREG)
		return (ENODEV);

	if (flags & MAP_PRIVATE)
		return (EINVAL);	/* XXX need to be handled */

	/*
	 * Don't allow mapping to locked file
	 */
	if (vn_has_mandatory_locks(vp, xp->xn_mode)) {
		return (EAGAIN);
	}

	if (error = xmem_fillpages(xp, vp, off, len, 1)) {
		return (error);
	}

	blocknumber = off >> xm->xm_bshift;

	if (flags & MAP_FIXED) {
		/*
		 * User specified address - blow away any previous mappings
		 */
		AS_LOCK_ENTER(as, &as->a_lock, RW_WRITER);
		seg = as_findseg(as, *addrp, 0);

		/*
		 * Fast path. segxmem_remap will fail if this is the wrong
		 * segment or if the len is beyond end of seg. If it fails,
		 * we do the regular stuff thru as_* routines.
		 */

		if (seg && (segxmem_remap(seg, vp, *addrp, len,
				&xp->xn_ppa[blocknumber], prot) == 0)) {
			AS_LOCK_EXIT(as, &as->a_lock);
			return (0);
		}
		AS_LOCK_EXIT(as, &as->a_lock);
		if (seg)
			(void) as_unmap(as, *addrp, len);

		as_rangelock(as);

		error = valid_usr_range(*addrp, len, prot, as, as->a_userlimit);

		if (error != RANGE_OKAY ||
			as_gap(as, len, addrp, &len, AH_CONTAIN, *addrp)) {
			as_rangeunlock(as);
			return (EINVAL);
		}

	} else {
		as_rangelock(as);
		map_addr(addrp, len, (offset_t)off, 1, flags);
	}

	if (*addrp == NULL) {
		as_rangeunlock(as);
		return (ENOMEM);
	}

	xmem_a.xma_vp = vp;
	xmem_a.xma_offset = (u_offset_t)off;
	xmem_a.xma_prot = prot;
	xmem_a.xma_cred = cred;
	xmem_a.xma_ppa = &xp->xn_ppa[blocknumber];
	xmem_a.xma_bshift = xm->xm_bshift;

	error = as_map(as, *addrp, len, segxmem_create, &xmem_a);

	as_rangeunlock(as);
	return (error);
}

/* ARGSUSED */
static int
xmem_addmap(struct vnode *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
	struct cred *cred)
{
	return (0);
}

/* ARGSUSED */
static int
xmem_delmap(struct vnode *vp, offset_t off, struct as *as, caddr_t addr,
	size_t len, uint_t prot, uint_t maxprot, uint_t flags,
	struct cred *cred)
{
	return (0);
}

static int
xmem_freesp(struct vnode *vp, struct flock64 *lp, int flag)
{
	register int i;
	register struct xmemnode *xp = VTOXN(vp);
	int error;

	ASSERT(vp->v_type == VREG);
	ASSERT(lp->l_start >= 0);

	if (lp->l_len != 0)
		return (EINVAL);

	rw_enter(&xp->xn_rwlock, RW_WRITER);
	if (xp->xn_size == lp->l_start) {
		rw_exit(&xp->xn_rwlock);
		return (0);
	}

	/*
	 * Check for any mandatory locks on the range
	 */
	if (MANDLOCK(vp, xp->xn_mode)) {
		long save_start;

		save_start = lp->l_start;

		if (xp->xn_size < lp->l_start) {
			/*
			 * "Truncate up" case: need to make sure there
			 * is no lock beyond current end-of-file. To
			 * do so, we need to set l_start to the size
			 * of the file temporarily.
			 */
			lp->l_start = xp->xn_size;
		}
		lp->l_type = F_WRLCK;
		lp->l_sysid = 0;
		lp->l_pid = ttoproc(curthread)->p_pid;
		i = (flag & (FNDELAY|FNONBLOCK)) ? 0 : SLPFLCK;
		if ((i = reclock(vp, lp, i, 0, lp->l_start, NULL)) != 0 ||
		    lp->l_type != F_UNLCK) {
			rw_exit(&xp->xn_rwlock);
			return (i ? i : EAGAIN);
		}

		lp->l_start = save_start;
	}

	rw_enter(&xp->xn_contents, RW_WRITER);
	error = xmemnode_trunc((struct xmount *)VFSTOXM(vp->v_vfsp),
						xp, lp->l_start);
	rw_exit(&xp->xn_contents);
	rw_exit(&xp->xn_rwlock);
	return (error);
}

/* ARGSUSED */
static int
xmem_space(struct vnode *vp, int cmd, struct flock64 *bfp, int flag,
	offset_t offset, struct cred *cred, caller_context_t *ct)
{
	int error;

	if (cmd != F_FREESP)
		return (EINVAL);
	if ((error = convoff(vp, bfp, 0, (offset_t)offset)) == 0) {
		if ((bfp->l_start > MAXOFF_T) || (bfp->l_len > MAXOFF_T))
			return (EFBIG);
		error = xmem_freesp(vp, bfp, flag);
	}
	return (error);
}

/* ARGSUSED */
static int
xmem_seek(struct vnode *vp, offset_t ooff, offset_t *noffp)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/* ARGSUSED2 */
static int
xmem_rwlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	struct xmemnode *xp = VTOXN(vp);

	if (write_lock) {
		rw_enter(&xp->xn_rwlock, RW_WRITER);
	} else {
		rw_enter(&xp->xn_rwlock, RW_READER);
	}
	return (write_lock);
}

/* ARGSUSED1 */
static void
xmem_rwunlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	struct xmemnode *xp = VTOXN(vp);

	rw_exit(&xp->xn_rwlock);
}

struct vnodeops *xmem_vnodeops;

const fs_operation_def_t xmem_vnodeops_template[] = {
	VOPNAME_OPEN, xmem_open,
	VOPNAME_CLOSE, xmem_close,
	VOPNAME_READ, xmem_read,
	VOPNAME_WRITE, xmem_write,
	VOPNAME_IOCTL, xmem_ioctl,
	VOPNAME_GETATTR, xmem_getattr,
	VOPNAME_SETATTR, xmem_setattr,
	VOPNAME_ACCESS, xmem_access,
	VOPNAME_LOOKUP, xmem_lookup,
	VOPNAME_CREATE, xmem_create,
	VOPNAME_REMOVE, xmem_remove,
	VOPNAME_LINK, xmem_link,
	VOPNAME_RENAME, xmem_rename,
	VOPNAME_MKDIR, xmem_mkdir,
	VOPNAME_RMDIR, xmem_rmdir,
	VOPNAME_READDIR, xmem_readdir,
	VOPNAME_SYMLINK, xmem_symlink,
	VOPNAME_READLINK, xmem_readlink,
	VOPNAME_FSYNC, xmem_fsync,
	VOPNAME_INACTIVE, (fs_generic_func_p) xmem_inactive,
	VOPNAME_FID, xmem_fid,
	VOPNAME_RWLOCK, xmem_rwlock,
	VOPNAME_RWUNLOCK, (fs_generic_func_p) xmem_rwunlock,
	VOPNAME_SEEK, xmem_seek,
	VOPNAME_SPACE, xmem_space,
	VOPNAME_GETPAGE, xmem_getpage,
	VOPNAME_PUTPAGE, xmem_putpage,
	VOPNAME_MAP, (fs_generic_func_p) xmem_map,
	VOPNAME_ADDMAP, (fs_generic_func_p) xmem_addmap,
	VOPNAME_DELMAP, xmem_delmap,
	NULL, NULL
};
