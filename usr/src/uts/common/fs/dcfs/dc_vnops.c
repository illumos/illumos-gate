
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitmap.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/mman.h>
#include <sys/vmsystm.h>
#include <sys/open.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/zmod.h>
#include <sys/fs/decomp.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>

#include <fs/fs_subr.h>

/*
 * dcfs - A filesystem for automatic decompressing of fiocompressed files
 *
 * This filesystem is a layered filesystem that sits on top of a normal
 * persistent filesystem and provides automatic decompression of files
 * that have been previously compressed and stored on the host file system.
 * This is a pseudo filesystem in that it does not persist data, rather it
 * intercepts file lookup requests on the host filesystem and provides
 * transparent decompression of those files. Currently the only supported
 * host filesystem is ufs.
 *
 * A file is compressed via a userland utility (currently cmd/boot/fiocompress)
 * and marked by fiocompress as a compressed file via a flag in the on-disk
 * inode (set via a ufs ioctl() - see `ufs_vnops.c`ufs_ioctl()`_FIO_COMPRESSED
 * ufs_lookup checks for this flag and if set, passes control to decompvp
 * a function defined in this (dcfs) filesystem. decomvp uncompresses the file
 * and returns a dcfs vnode to the VFS layer.
 *
 * dcfs is layered on top of ufs and passes requests involving persistence
 * to the underlying ufs filesystem. The compressed files currently cannot be
 * written to.
 */


/*
 * Define data structures within this file.
 */
#define	DCSHFT		5
#define	DCTABLESIZE	16

#if ((DCTABLESIZE & (DCTABLESIZE - 1)) == 0)
#define	DCHASH(vp) (((uintptr_t)(vp) >> DCSHFT) & (DCTABLESIZE - 1))
#else
#define	DCHASH(vp) (((uintptr_t)(vp) >> DCSHFT) % DTABLESIZEC)
#endif

#define	DCLRUSIZE	16

#define	DCCACHESIZE	4

#define	rounddown(x, y)	((x) & ~((y) - 1))

struct dcnode	*dctable[DCTABLESIZE];

struct dcnode	*dclru;
static int	dclru_len;

kmutex_t	dctable_lock;

dev_t		dcdev;
struct vfs	dc_vfs;

struct kmem_cache *dcnode_cache;
struct kmem_cache *dcbuf_cache[DCCACHESIZE];

kmutex_t	dccache_lock;

static int dcinit(int, char *);

static struct dcnode	*dcnode_alloc(void);
static void		dcnode_free(struct dcnode *);
static void		dcnode_recycle(struct dcnode *);

static void		dcinsert(struct dcnode *);
static void		dcdelete(struct dcnode *);
static struct dcnode	*dcfind(struct vnode *);
static void		dclru_add(struct dcnode *);
static void		dclru_sub(struct dcnode *);


/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

struct vfsops *dc_vfsops;

static vfsdef_t vfw = {
	VFSDEF_VERSION,
	"dcfs",
	dcinit,
	VSW_ZMOUNT,
	NULL
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_fsops;

static struct modlfs modlfs = {
	&mod_fsops, "compressed filesystem", &vfw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlfs, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int dc_open(struct vnode **, int, struct cred *, caller_context_t *);
static int dc_close(struct vnode *, int, int, offset_t,
    struct cred *, caller_context_t *);
static int dc_read(struct vnode *, struct uio *, int, struct cred *,
    struct caller_context *);
static int dc_getattr(struct vnode *, struct vattr *, int,
    struct cred *, caller_context_t *);
static int dc_setattr(struct vnode *, struct vattr *, int, struct cred *,
    struct caller_context *);
static int dc_access(struct vnode *, int, int,
    struct cred *, caller_context_t *);
static int dc_fsync(struct vnode *, int, struct cred *, caller_context_t *);
static void dc_inactive(struct vnode *, struct cred *, caller_context_t *);
static int dc_fid(struct vnode *, struct fid *, caller_context_t *);
static int dc_seek(struct vnode *, offset_t, offset_t *, caller_context_t *);
static int dc_frlock(struct vnode *, int, struct flock64 *, int, offset_t,
    struct flk_callback *, struct cred *, caller_context_t *);
static int dc_realvp(struct vnode *, struct vnode **, caller_context_t *);
static int dc_getpage(struct vnode *, offset_t, size_t, uint_t *,
    struct page **, size_t, struct seg *, caddr_t, enum seg_rw,
    struct cred *, caller_context_t *);
static int dc_putpage(struct vnode *, offset_t, size_t, int,
    struct cred *, caller_context_t *);
static int dc_map(struct vnode *, offset_t, struct as *, caddr_t *, size_t,
    uchar_t, uchar_t, uint_t, struct cred *, caller_context_t *);
static int dc_addmap(struct vnode *, offset_t, struct as *, caddr_t, size_t,
    uchar_t, uchar_t, uint_t, struct cred *, caller_context_t *);
static int dc_delmap(struct vnode *, offset_t, struct as *, caddr_t, size_t,
    uint_t, uint_t, uint_t, struct cred *, caller_context_t *);

struct vnodeops *dc_vnodeops;

const fs_operation_def_t dc_vnodeops_template[] = {
	VOPNAME_OPEN,			{ .vop_open = dc_open },
	VOPNAME_CLOSE,			{ .vop_close = dc_close },
	VOPNAME_READ,			{ .vop_read = dc_read },
	VOPNAME_GETATTR,		{ .vop_getattr =  dc_getattr },
	VOPNAME_SETATTR,		{ .vop_setattr = dc_setattr },
	VOPNAME_ACCESS,			{ .vop_access = dc_access },
	VOPNAME_FSYNC,			{ .vop_fsync = dc_fsync },
	VOPNAME_INACTIVE,		{ .vop_inactive = dc_inactive },
	VOPNAME_FID,			{ .vop_fid = dc_fid },
	VOPNAME_SEEK,			{ .vop_seek = dc_seek },
	VOPNAME_FRLOCK,			{ .vop_frlock = dc_frlock },
	VOPNAME_REALVP,			{ .vop_realvp = dc_realvp },
	VOPNAME_GETPAGE,		{ .vop_getpage = dc_getpage },
	VOPNAME_PUTPAGE,		{ .vop_putpage = dc_putpage },
	VOPNAME_MAP,			{ .vop_map = dc_map },
	VOPNAME_ADDMAP,			{ .vop_addmap = dc_addmap },
	VOPNAME_DELMAP,			{ .vop_delmap = dc_delmap },
	NULL,				NULL
};

/*ARGSUSED*/
static int
dc_open(struct vnode **vpp, int flag, struct cred *cr, caller_context_t *ctp)
{
	return (0);
}

/*ARGSUSED*/
static int
dc_close(struct vnode *vp, int flag, int count, offset_t off,
    struct cred *cr, caller_context_t *ctp)
{
	(void) cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}

/*ARGSUSED*/
static int
dc_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cr,
	struct caller_context *ct)
{
	struct dcnode *dp = VTODC(vp);
	size_t rdsize = MAX(MAXBSIZE, dp->dc_hdr->ch_blksize);
	size_t fsize = dp->dc_hdr->ch_fsize;
	int error;

	/*
	 * Loop through file with segmap, decompression will occur
	 * in dc_getapage
	 */
	do {
		caddr_t base;
		size_t n;
		offset_t mapon;

		/*
		 * read to end of block or file
		 */
		mapon = uiop->uio_loffset & (rdsize - 1);
		n = MIN(rdsize - mapon, uiop->uio_resid);
		n = MIN(n, fsize - uiop->uio_loffset);
		if (n == 0)
			return (0);	/* at EOF */

		base = segmap_getmapflt(segkmap, vp, uiop->uio_loffset, n, 1,
		    S_READ);
		error = uiomove(base + mapon, n, UIO_READ, uiop);
		if (!error) {
			uint_t flags;

			if (n + mapon == rdsize || uiop->uio_loffset == fsize)
				flags = SM_DONTNEED;
			else
				flags = 0;
			error = segmap_release(segkmap, base, flags);
		} else
			(void) segmap_release(segkmap, base, 0);
	} while (!error && uiop->uio_resid);

	return (error);
}

static int
dc_getattr(struct vnode *vp, struct vattr *vap, int flags,
    cred_t *cred, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	struct vnode *subvp = dp->dc_subvp;
	int error;

	error = VOP_GETATTR(subvp, vap, flags, cred, ctp);

	/* substitute uncompressed size */
	vap->va_size = dp->dc_hdr->ch_fsize;
	return (error);
}

static int
dc_setattr(struct vnode *vp, struct vattr *vap, int flags, cred_t *cred,
    caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	struct vnode *subvp = dp->dc_subvp;

	return (VOP_SETATTR(subvp, vap, flags, cred, ctp));
}

static int
dc_access(struct vnode *vp, int mode, int flags,
    cred_t *cred, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	struct vnode *subvp = dp->dc_subvp;

	return (VOP_ACCESS(subvp, mode, flags, cred, ctp));
}

/*ARGSUSED*/
static int
dc_fsync(vnode_t *vp, int syncflag, cred_t *cred, caller_context_t *ctp)
{
	return (0);
}

/*ARGSUSED*/
static void
dc_inactive(struct vnode *vp, cred_t *cr, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);

	mutex_enter(&dctable_lock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);
	if (--vp->v_count != 0) {
		/*
		 * Somebody accessed the dcnode before we got a chance to
		 * remove it.  They will remove it when they do a vn_rele.
		 */
		mutex_exit(&vp->v_lock);
		mutex_exit(&dctable_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	dcnode_free(dp);

	mutex_exit(&dctable_lock);
}

static int
dc_fid(struct vnode *vp, struct fid *fidp, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	struct vnode *subvp = dp->dc_subvp;

	return (VOP_FID(subvp, fidp, ctp));
}

static int
dc_seek(struct vnode *vp, offset_t oof, offset_t *noffp, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	struct vnode *subvp = dp->dc_subvp;

	return (VOP_SEEK(subvp, oof, noffp, ctp));
}

static int
dc_frlock(struct vnode *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t offset, struct flk_callback *flk_cbp,
    cred_t *cr, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	int error;
	struct vattr vattr;

	/*
	 * If file is being mapped, disallow frlock.
	 */
	vattr.va_mask = AT_MODE;
	if (error = VOP_GETATTR(dp->dc_subvp, &vattr, 0, cr, ctp))
		return (error);
	if (dp->dc_mapcnt > 0 && MANDLOCK(vp, vattr.va_mode))
		return (EAGAIN);

	return (fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr, ctp));
}

/*ARGSUSED*/
static int
dc_getblock_miss(struct vnode *vp, offset_t off, size_t len, struct page **ppp,
    struct seg *seg, caddr_t addr, enum seg_rw rw, struct cred *cr)
{
	struct dcnode *dp = VTODC(vp);
	struct comphdr *hdr = dp->dc_hdr;
	struct page *pp;
	struct buf *bp;
	caddr_t saddr;
	off_t cblkno;
	size_t rdoff, rdsize, dsize;
	long xlen;
	int error, zerr;

	ASSERT(len == hdr->ch_blksize);
	/*
	 * Get destination pages and make them addressable
	 */
	pp = page_create_va(vp, off, len, PG_WAIT, seg, addr);
	bp = pageio_setup(pp, len, vp, B_READ);
	bp_mapin(bp);

	/*
	 * read compressed data from subordinate vnode
	 */
	saddr = kmem_cache_alloc(dp->dc_bufcache, KM_SLEEP);
	cblkno = off / len;
	rdoff = hdr->ch_blkmap[cblkno];
	rdsize = hdr->ch_blkmap[cblkno + 1] - rdoff;
	error = vn_rdwr(UIO_READ, dp->dc_subvp, saddr, rdsize, rdoff,
	    UIO_SYSSPACE, 0, 0, cr, NULL);
	if (error)
		goto cleanup;

	/*
	 * Uncompress
	 */
	dsize = len;
	zerr = z_uncompress(bp->b_un.b_addr, &dsize, saddr, dp->dc_zmax);
	if (zerr != Z_OK) {
		error = EIO;
		goto cleanup;
	}

	/*
	 * Handle EOF
	 */
	xlen = hdr->ch_fsize - off;
	if (xlen < len) {
		bzero(bp->b_un.b_addr + xlen, len - xlen);
		if (dsize != xlen)
			error = EIO;
	} else if (dsize != len)
		error = EIO;

	/*
	 * Clean up
	 */
cleanup:
	kmem_cache_free(dp->dc_bufcache, saddr);
	pageio_done(bp);
	*ppp = pp;
	return (error);
}

static int
dc_getblock(struct vnode *vp, offset_t off, size_t len, struct page **ppp,
    struct seg *seg, caddr_t addr, enum seg_rw rw, struct cred *cr)
{
	struct page *pp, *plist = NULL;
	offset_t pgoff;
	int rdblk;

	/*
	 * pvn_read_kluster() doesn't quite do what we want, since it
	 * thinks sub block reads are ok.  Here we always decompress
	 * a full block.
	 */

	/*
	 * Check page cache
	 */
	rdblk = 0;
	for (pgoff = off; pgoff < off + len; pgoff += PAGESIZE) {
		pp = page_lookup(vp, pgoff, SE_EXCL);
		if (pp == NULL) {
			rdblk = 1;
			break;
		}
		page_io_lock(pp);
		page_add(&plist, pp);
		plist = plist->p_next;
	}
	if (!rdblk) {
		*ppp = plist;
		return (0);	/* all pages in cache */
	}

	/*
	 * Undo any locks so getblock_miss has an open field
	 */
	if (plist != NULL)
		pvn_io_done(plist);

	return (dc_getblock_miss(vp, off, len, ppp, seg, addr, rw, cr));
}

static int
dc_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	struct vnode *rvp;

	vp = VTODC(vp)->dc_subvp;
	if (VOP_REALVP(vp, &rvp, ct) == 0)
		vp = rvp;
	*vpp = vp;
	return (0);
}

/*ARGSUSED10*/
static int
dc_getpage(struct vnode *vp, offset_t off, size_t len, uint_t *protp,
    struct page *pl[], size_t plsz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *cr, caller_context_t *ctp)
{
	struct dcnode *dp = VTODC(vp);
	struct comphdr *hdr = dp->dc_hdr;
	struct page *pp, *plist = NULL;
	caddr_t vp_baddr;
	offset_t vp_boff, vp_bend;
	size_t bsize = hdr->ch_blksize;
	int nblks, error;

	/* does not support write */
	if (rw == S_WRITE) {
		panic("write attempt on compressed file");
		/*NOTREACHED*/
	}

	if (protp)
		*protp = PROT_ALL;
	/*
	 * We don't support asynchronous operation at the moment, so
	 * just pretend we did it.  If the pages are ever actually
	 * needed, they'll get brought in then.
	 */
	if (pl == NULL)
		return (0);

	/*
	 * Calc block start and end offsets
	 */
	vp_boff = rounddown(off, bsize);
	vp_bend = roundup(off + len, bsize);
	vp_baddr = (caddr_t)rounddown((uintptr_t)addr, bsize);

	nblks = (vp_bend - vp_boff) / bsize;
	while (nblks--) {
		error = dc_getblock(vp, vp_boff, bsize, &pp, seg, vp_baddr,
		    rw, cr);
		page_list_concat(&plist, &pp);
		vp_boff += bsize;
		vp_baddr += bsize;
	}
	if (!error)
		pvn_plist_init(plist, pl, plsz, off, len, rw);
	else
		pvn_read_done(plist, B_ERROR);
	return (error);
}

/*
 * This function should never be called. We need to have it to pass
 * it as an argument to other functions.
 */
/*ARGSUSED*/
static int
dc_putapage(struct vnode *vp, struct page *pp, u_offset_t *offp, size_t *lenp,
    int flags, struct cred *cr)
{
	/* should never happen */
	cmn_err(CE_PANIC, "dcfs: dc_putapage: dirty page");
	/*NOTREACHED*/
	return (0);
}


/*
 * The only flags we support are B_INVAL, B_FREE and B_DONTNEED.
 * B_INVAL is set by:
 *
 *	1) the MC_SYNC command of memcntl(2) to support the MS_INVALIDATE flag.
 *	2) the MC_ADVISE command of memcntl(2) with the MADV_DONTNEED advice
 *	   which translates to an MC_SYNC with the MS_INVALIDATE flag.
 *
 * The B_FREE (as well as the B_DONTNEED) flag is set when the
 * MADV_SEQUENTIAL advice has been used. VOP_PUTPAGE is invoked
 * from SEGVN to release pages behind a pagefault.
 */
/*ARGSUSED5*/
static int
dc_putpage(struct vnode *vp, offset_t off, size_t len, int flags,
    struct cred *cr, caller_context_t *ctp)
{
	int error = 0;

	if (vp->v_count == 0) {
		panic("dcfs_putpage: bad v_count");
		/*NOTREACHED*/
	}

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (!vn_has_cached_data(vp))	/* no pages mapped */
		return (0);

	if (len == 0)		/* from 'off' to EOF */
		error = pvn_vplist_dirty(vp, off, dc_putapage, flags, cr);
	else {
		offset_t io_off;
		se_t se = (flags & (B_INVAL | B_FREE)) ? SE_EXCL : SE_SHARED;

		for (io_off = off; io_off < off + len; io_off += PAGESIZE) {
			page_t *pp;

			/*
			 * We insist on getting the page only if we are
			 * about to invalidate, free or write it and
			 * the B_ASYNC flag is not set.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0))
				pp = page_lookup(vp, io_off, se);
			else
				pp = page_lookup_nowait(vp, io_off, se);

			if (pp == NULL)
				continue;
			/*
			 * Normally pvn_getdirty() should return 0, which
			 * impies that it has done the job for us.
			 * The shouldn't-happen scenario is when it returns 1.
			 * This means that the page has been modified and
			 * needs to be put back.
			 * Since we can't write to a dcfs compressed file,
			 * we fake a failed I/O and force pvn_write_done()
			 * to destroy the page.
			 */
			if (pvn_getdirty(pp, flags) == 1) {
				cmn_err(CE_NOTE, "dc_putpage: dirty page");
				pvn_write_done(pp, flags |
				    B_ERROR | B_WRITE | B_INVAL | B_FORCE);
			}
		}
	}
	return (error);
}

static int
dc_map(struct vnode *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
    struct cred *cred, caller_context_t *ctp)
{
	struct vattr vattr;
	struct segvn_crargs vn_a;
	int error;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < (offset_t)0 || (offset_t)(off + len) < (offset_t)0)
		return (ENXIO);

	/*
	 * If file is being locked, disallow mapping.
	 */
	if (error = VOP_GETATTR(VTODC(vp)->dc_subvp, &vattr, 0, cred, ctp))
		return (error);
	if (vn_has_mandatory_locks(vp, vattr.va_mode))
		return (EAGAIN);

	as_rangelock(as);

	if ((flags & MAP_FIXED) == 0) {
		map_addr(addrp, len, off, 1, flags);
		if (*addrp == NULL) {
			as_rangeunlock(as);
			return (ENOMEM);
		}
	} else {
		/*
		 * User specified address - blow away any previous mappings
		 */
		(void) as_unmap(as, *addrp, len);
	}

	vn_a.vp = vp;
	vn_a.offset = off;
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

/*ARGSUSED*/
static int
dc_addmap(struct vnode *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
    struct cred *cr, caller_context_t *ctp)
{
	struct dcnode *dp;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	dp = VTODC(vp);
	mutex_enter(&dp->dc_lock);
	dp->dc_mapcnt += btopr(len);
	mutex_exit(&dp->dc_lock);
	return (0);
}

/*ARGSUSED*/
static int
dc_delmap(struct vnode *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags,
    struct cred *cr, caller_context_t *ctp)
{
	struct dcnode *dp;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	dp = VTODC(vp);
	mutex_enter(&dp->dc_lock);
	dp->dc_mapcnt -= btopr(len);
	ASSERT(dp->dc_mapcnt >= 0);
	mutex_exit(&dp->dc_lock);
	return (0);
}

/*
 * Constructor/destructor routines for dcnodes
 */
/*ARGSUSED1*/
static int
dcnode_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct dcnode *dp = buf;
	struct vnode *vp;

	vp = dp->dc_vp = vn_alloc(kmflags);
	if (vp == NULL) {
		return (-1);
	}
	vp->v_data = dp;
	vp->v_type = VREG;
	vp->v_flag = VNOSWAP;
	vp->v_vfsp = &dc_vfs;
	vn_setops(vp, dc_vnodeops);
	vn_exists(vp);

	mutex_init(&dp->dc_lock, NULL, MUTEX_DEFAULT, NULL);
	dp->dc_mapcnt = 0;
	dp->dc_lrunext = dp->dc_lruprev = NULL;
	dp->dc_hdr = NULL;
	dp->dc_subvp = NULL;
	return (0);
}

/*ARGSUSED*/
static void
dcnode_destructor(void *buf, void *cdrarg)
{
	struct dcnode *dp = buf;
	struct vnode *vp = DCTOV(dp);

	mutex_destroy(&dp->dc_lock);

	VERIFY(dp->dc_hdr == NULL);
	VERIFY(dp->dc_subvp == NULL);
	vn_invalid(vp);
	vn_free(vp);
}

static struct dcnode *
dcnode_alloc(void)
{
	struct dcnode *dp;

	/*
	 * If the free list is above DCLRUSIZE
	 * re-use one from it
	 */
	mutex_enter(&dctable_lock);
	if (dclru_len < DCLRUSIZE) {
		mutex_exit(&dctable_lock);
		dp = kmem_cache_alloc(dcnode_cache, KM_SLEEP);
	} else {
		ASSERT(dclru != NULL);
		dp = dclru;
		dclru_sub(dp);
		dcdelete(dp);
		mutex_exit(&dctable_lock);
		dcnode_recycle(dp);
	}
	return (dp);
}

static void
dcnode_free(struct dcnode *dp)
{
	struct vnode *vp = DCTOV(dp);

	ASSERT(MUTEX_HELD(&dctable_lock));

	/*
	 * If no cached pages, no need to put it on lru
	 */
	if (!vn_has_cached_data(vp)) {
		dcdelete(dp);
		dcnode_recycle(dp);
		kmem_cache_free(dcnode_cache, dp);
		return;
	}

	/*
	 * Add to lru, if it's over the limit, free from head
	 */
	dclru_add(dp);
	if (dclru_len > DCLRUSIZE) {
		dp = dclru;
		dclru_sub(dp);
		dcdelete(dp);
		dcnode_recycle(dp);
		kmem_cache_free(dcnode_cache, dp);
	}
}

static void
dcnode_recycle(struct dcnode *dp)
{
	struct vnode *vp;

	vp = DCTOV(dp);

	VN_RELE(dp->dc_subvp);
	dp->dc_subvp = NULL;
	(void) pvn_vplist_dirty(vp, 0, dc_putapage, B_INVAL, NULL);
	kmem_free(dp->dc_hdr, dp->dc_hdrsize);
	dp->dc_hdr = NULL;
	dp->dc_hdrsize = dp->dc_zmax = 0;
	dp->dc_bufcache = NULL;
	dp->dc_mapcnt = 0;
	vn_reinit(vp);
	vp->v_type = VREG;
	vp->v_flag = VNOSWAP;
	vp->v_vfsp = &dc_vfs;
}

static int
dcinit(int fstype, char *name)
{
	static const fs_operation_def_t dc_vfsops_template[] = {
		NULL, NULL
	};
	int error;
	major_t dev;

	error = vfs_setfsops(fstype, dc_vfsops_template, &dc_vfsops);
	if (error) {
		cmn_err(CE_WARN, "dcinit: bad vfs ops template");
		return (error);
	}
	VFS_INIT(&dc_vfs, dc_vfsops, NULL);
	dc_vfs.vfs_flag = VFS_RDONLY;
	dc_vfs.vfs_fstype = fstype;
	if ((dev = getudev()) == (major_t)-1)
		dev = 0;
	dcdev = makedevice(dev, 0);
	dc_vfs.vfs_dev = dcdev;

	error = vn_make_ops(name, dc_vnodeops_template, &dc_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		cmn_err(CE_WARN, "dcinit: bad vnode ops template");
		return (error);
	}

	mutex_init(&dctable_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&dccache_lock, NULL, MUTEX_DEFAULT, NULL);
	dcnode_cache = kmem_cache_create("dcnode_cache", sizeof (struct dcnode),
	    0, dcnode_constructor, dcnode_destructor, NULL, NULL, NULL, 0);

	return (0);
}

/*
 * Return shadow vnode with the given vp as its subordinate
 */
struct vnode *
decompvp(struct vnode *vp, cred_t *cred, caller_context_t *ctp)
{
	struct dcnode *dp, *ndp;
	struct comphdr thdr, *hdr;
	struct kmem_cache **cpp;
	struct vattr vattr;
	size_t hdrsize, bsize;
	int error;

	/*
	 * See if we have an existing shadow
	 * If none, we have to manufacture one
	 */
	mutex_enter(&dctable_lock);
	dp = dcfind(vp);
	mutex_exit(&dctable_lock);
	if (dp != NULL)
		return (DCTOV(dp));

	/*
	 * Make sure it's a valid compressed file
	 */
	hdr = &thdr;
	error = vn_rdwr(UIO_READ, vp, (caddr_t)hdr, sizeof (struct comphdr), 0,
	    UIO_SYSSPACE, 0, 0, cred, NULL);
	if (error || hdr->ch_magic != CH_MAGIC_ZLIB ||
	    hdr->ch_version != CH_VERSION || hdr->ch_algorithm != CH_ALG_ZLIB ||
	    hdr->ch_fsize == 0 || hdr->ch_blksize < PAGESIZE ||
	    hdr->ch_blksize > ptob(DCCACHESIZE) || !ISP2(hdr->ch_blksize))
		return (NULL);

	/* get underlying file size */
	if (VOP_GETATTR(vp, &vattr, 0, cred, ctp) != 0)
		return (NULL);

	/*
	 * Re-read entire header
	 */
	hdrsize = hdr->ch_blkmap[0] + sizeof (uint64_t);
	hdr = kmem_alloc(hdrsize, KM_SLEEP);
	error = vn_rdwr(UIO_READ, vp, (caddr_t)hdr, hdrsize, 0, UIO_SYSSPACE,
	    0, 0, cred, NULL);
	if (error) {
		kmem_free(hdr, hdrsize);
		return (NULL);
	}

	/*
	 * add extra blkmap entry to make dc_getblock()'s
	 * life easier
	 */
	bsize = hdr->ch_blksize;
	hdr->ch_blkmap[((hdr->ch_fsize-1) / bsize) + 1] = vattr.va_size;

	ndp = dcnode_alloc();
	ndp->dc_subvp = vp;
	VN_HOLD(vp);
	ndp->dc_hdr = hdr;
	ndp->dc_hdrsize = hdrsize;

	/*
	 * Allocate kmem cache if none there already
	 */
	ndp->dc_zmax = ZMAXBUF(bsize);
	cpp = &dcbuf_cache[btop(bsize)];
	mutex_enter(&dccache_lock);
	if (*cpp == NULL)
		*cpp = kmem_cache_create("dcbuf_cache", ndp->dc_zmax, 0, NULL,
		    NULL, NULL, NULL, NULL, 0);
	mutex_exit(&dccache_lock);
	ndp->dc_bufcache = *cpp;

	/*
	 * Recheck table in case someone else created shadow
	 * while we were blocked above.
	 */
	mutex_enter(&dctable_lock);
	dp = dcfind(vp);
	if (dp != NULL) {
		mutex_exit(&dctable_lock);
		dcnode_recycle(ndp);
		kmem_cache_free(dcnode_cache, ndp);
		return (DCTOV(dp));
	}
	dcinsert(ndp);
	mutex_exit(&dctable_lock);

	return (DCTOV(ndp));
}


/*
 * dcnode lookup table
 * These routines maintain a table of dcnodes hashed by their
 * subordinate vnode so that they can be found if they already
 * exist in the vnode cache
 */

/*
 * Put a dcnode in the table.
 */
static void
dcinsert(struct dcnode *newdp)
{
	int idx = DCHASH(newdp->dc_subvp);

	ASSERT(MUTEX_HELD(&dctable_lock));
	newdp->dc_hash = dctable[idx];
	dctable[idx] = newdp;
}

/*
 * Remove a dcnode from the hash table.
 */
void
dcdelete(struct dcnode *deldp)
{
	int idx = DCHASH(deldp->dc_subvp);
	struct dcnode *dp, *prevdp;

	ASSERT(MUTEX_HELD(&dctable_lock));
	dp = dctable[idx];
	if (dp == deldp)
		dctable[idx] = dp->dc_hash;
	else {
		for (prevdp = dp, dp = dp->dc_hash; dp != NULL;
		    prevdp = dp, dp = dp->dc_hash) {
			if (dp == deldp) {
				prevdp->dc_hash = dp->dc_hash;
				break;
			}
		}
	}
	ASSERT(dp != NULL);
}

/*
 * Find a shadow vnode in the dctable hash list.
 */
static struct dcnode *
dcfind(struct vnode *vp)
{
	struct dcnode *dp;

	ASSERT(MUTEX_HELD(&dctable_lock));
	for (dp = dctable[DCHASH(vp)]; dp != NULL; dp = dp->dc_hash)
		if (dp->dc_subvp == vp) {
			VN_HOLD(DCTOV(dp));
			if (dp->dc_lrunext)
				dclru_sub(dp);
			return (dp);
		}
	return (NULL);
}

#ifdef	DEBUG
static int
dclru_count(void)
{
	struct dcnode *dp;
	int i = 0;

	if (dclru == NULL)
		return (0);
	for (dp = dclru; dp->dc_lrunext != dclru; dp = dp->dc_lrunext)
		i++;
	return (i + 1);
}
#endif

static void
dclru_add(struct dcnode *dp)
{
	/*
	 * Add to dclru as double-link chain
	 */
	ASSERT(MUTEX_HELD(&dctable_lock));
	if (dclru == NULL) {
		dclru = dp;
		dp->dc_lruprev = dp->dc_lrunext = dp;
	} else {
		struct dcnode *last = dclru->dc_lruprev;

		dclru->dc_lruprev = dp;
		last->dc_lrunext = dp;
		dp->dc_lruprev = last;
		dp->dc_lrunext = dclru;
	}
	dclru_len++;
	ASSERT(dclru_len == dclru_count());
}

static void
dclru_sub(struct dcnode *dp)
{
	ASSERT(MUTEX_HELD(&dctable_lock));
	dp->dc_lrunext->dc_lruprev = dp->dc_lruprev;
	dp->dc_lruprev->dc_lrunext = dp->dc_lrunext;
	if (dp == dclru)
		dclru = dp->dc_lrunext == dp ? NULL : dp->dc_lrunext;
	dp->dc_lrunext = dp->dc_lruprev = NULL;
	dclru_len--;
	ASSERT(dclru_len == dclru_count());
}
