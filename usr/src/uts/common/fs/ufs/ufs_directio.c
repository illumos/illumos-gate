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

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
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
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/conf.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/filio.h>
#include <sys/atomic.h>

#include <sys/fssnap_if.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_lockfs.h>
#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_trans.h>
#include <sys/fs/ufs_panic.h>
#include <sys/dirent.h>		/* must be AFTER <sys/fs/fsdir.h>! */
#include <sys/errno.h>

#include <sys/filio.h>		/* _FIOIO */

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>
#include <vm/rm.h>
#include <sys/swap.h>
#include <sys/epm.h>

#include <fs/fs_subr.h>

static void	*ufs_directio_zero_buf;
static int	ufs_directio_zero_len	= 8192;

int	ufs_directio_enabled = 1;	/* feature is enabled */

/*
 * for kstats reader
 */
struct ufs_directio_kstats {
	kstat_named_t	logical_reads;
	kstat_named_t	phys_reads;
	kstat_named_t	hole_reads;
	kstat_named_t	nread;
	kstat_named_t	logical_writes;
	kstat_named_t	phys_writes;
	kstat_named_t	nwritten;
	kstat_named_t	nflushes;
} ufs_directio_kstats = {
	{ "logical_reads",	KSTAT_DATA_UINT64 },
	{ "phys_reads",		KSTAT_DATA_UINT64 },
	{ "hole_reads",		KSTAT_DATA_UINT64 },
	{ "nread",		KSTAT_DATA_UINT64 },
	{ "logical_writes",	KSTAT_DATA_UINT64 },
	{ "phys_writes",	KSTAT_DATA_UINT64 },
	{ "nwritten",		KSTAT_DATA_UINT64 },
	{ "nflushes",		KSTAT_DATA_UINT64 },
};

kstat_t	*ufs_directio_kstatsp;

/*
 * use kmem_cache_create for direct-physio buffers. This has shown
 * a better cache distribution compared to buffers on the
 * stack. It also avoids semaphore construction/deconstruction
 * per request
 */
struct directio_buf {
	struct directio_buf	*next;
	char		*addr;
	size_t		nbytes;
	struct buf	buf;
};
static struct kmem_cache *directio_buf_cache;


/* ARGSUSED */
static int
directio_buf_constructor(void *dbp, void *cdrarg, int kmflags)
{
	bioinit((struct buf *)&((struct directio_buf *)dbp)->buf);
	return (0);
}

/* ARGSUSED */
static void
directio_buf_destructor(void *dbp, void *cdrarg)
{
	biofini((struct buf *)&((struct directio_buf *)dbp)->buf);
}

void
directio_bufs_init(void)
{
	directio_buf_cache = kmem_cache_create("directio_buf_cache",
	    sizeof (struct directio_buf), 0,
	    directio_buf_constructor, directio_buf_destructor,
	    NULL, NULL, NULL, 0);
}

void
ufs_directio_init(void)
{
	/*
	 * kstats
	 */
	ufs_directio_kstatsp = kstat_create("ufs", 0,
	    "directio", "ufs", KSTAT_TYPE_NAMED,
	    sizeof (ufs_directio_kstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);
	if (ufs_directio_kstatsp) {
		ufs_directio_kstatsp->ks_data = (void *)&ufs_directio_kstats;
		kstat_install(ufs_directio_kstatsp);
	}
	/*
	 * kzero is broken so we have to use a private buf of zeroes
	 */
	ufs_directio_zero_buf = kmem_zalloc(ufs_directio_zero_len, KM_SLEEP);
	directio_bufs_init();
}

/*
 * Wait for the first direct IO operation to finish
 */
static int
directio_wait_one(struct directio_buf *dbp, long *bytes_iop)
{
	buf_t	*bp;
	int	error;

	/*
	 * Wait for IO to finish
	 */
	bp = &dbp->buf;
	error = biowait(bp);

	/*
	 * bytes_io will be used to figure out a resid
	 * for the caller. The resid is approximated by reporting
	 * the bytes following the first failed IO as the residual.
	 *
	 * I am cautious about using b_resid because I
	 * am not sure how well the disk drivers maintain it.
	 */
	if (error)
		if (bp->b_resid)
			*bytes_iop = bp->b_bcount - bp->b_resid;
		else
			*bytes_iop = 0;
	else
		*bytes_iop += bp->b_bcount;
	/*
	 * Release direct IO resources
	 */
	bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS|B_SHADOW);
	kmem_cache_free(directio_buf_cache, dbp);
	return (error);
}

/*
 * Wait for all of the direct IO operations to finish
 */

uint32_t	ufs_directio_drop_kpri = 0;	/* enable kpri hack */

static int
directio_wait(struct directio_buf *tail, long *bytes_iop)
{
	int	error = 0, newerror;
	struct directio_buf	*dbp;
	uint_t	kpri_req_save;

	/*
	 * The linked list of directio buf structures is maintained
	 * in reverse order (tail->last request->penultimate request->...)
	 */
	/*
	 * This is the k_pri_req hack. Large numbers of threads
	 * sleeping with kernel priority will cause scheduler thrashing
	 * on an MP machine. This can be seen running Oracle using
	 * directio to ufs files. Sleep at normal priority here to
	 * more closely mimic physio to a device partition. This
	 * workaround is disabled by default as a niced thread could
	 * be starved from running while holding i_rwlock and i_contents.
	 */
	if (ufs_directio_drop_kpri) {
		kpri_req_save = curthread->t_kpri_req;
		curthread->t_kpri_req = 0;
	}
	while ((dbp = tail) != NULL) {
		tail = dbp->next;
		newerror = directio_wait_one(dbp, bytes_iop);
		if (error == 0)
			error = newerror;
	}
	if (ufs_directio_drop_kpri)
		curthread->t_kpri_req = kpri_req_save;
	return (error);
}
/*
 * Initiate direct IO request
 */
static void
directio_start(struct ufsvfs *ufsvfsp, struct inode *ip, size_t nbytes,
	offset_t offset, char *addr, enum seg_rw rw, struct proc *procp,
	struct directio_buf **tailp, page_t **pplist)
{
	buf_t *bp;
	struct directio_buf *dbp;

	/*
	 * Allocate a directio buf header
	 *   Note - list is maintained in reverse order.
	 *   directio_wait_one() depends on this fact when
	 *   adjusting the ``bytes_io'' param. bytes_io
	 *   is used to compute a residual in the case of error.
	 */
	dbp = kmem_cache_alloc(directio_buf_cache, KM_SLEEP);
	dbp->next = *tailp;
	*tailp = dbp;

	/*
	 * Initialize buf header
	 */
	dbp->addr = addr;
	dbp->nbytes = nbytes;
	bp = &dbp->buf;
	bp->b_edev = ip->i_dev;
	bp->b_lblkno = btodt(offset);
	bp->b_bcount = nbytes;
	bp->b_un.b_addr = addr;
	bp->b_proc = procp;
	bp->b_file = ip->i_vnode;

	/*
	 * Note that S_WRITE implies B_READ and vice versa: a read(2)
	 * will B_READ data from the filesystem and S_WRITE it into
	 * the user's buffer; a write(2) will S_READ data from the
	 * user's buffer and B_WRITE it to the filesystem.
	 */
	if (rw == S_WRITE) {
		bp->b_flags = B_BUSY | B_PHYS | B_READ;
		ufs_directio_kstats.phys_reads.value.ui64++;
		ufs_directio_kstats.nread.value.ui64 += nbytes;
	} else {
		bp->b_flags = B_BUSY | B_PHYS | B_WRITE;
		ufs_directio_kstats.phys_writes.value.ui64++;
		ufs_directio_kstats.nwritten.value.ui64 += nbytes;
	}
	bp->b_shadow = pplist;
	if (pplist != NULL)
		bp->b_flags |= B_SHADOW;

	/*
	 * Issue I/O request.
	 */
	ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
	if (ufsvfsp->vfs_snapshot)
		fssnap_strategy(&ufsvfsp->vfs_snapshot, bp);
	else
		(void) bdev_strategy(bp);

	if (rw == S_WRITE)
		lwp_stat_update(LWP_STAT_OUBLK, 1);
	else
		lwp_stat_update(LWP_STAT_INBLK, 1);

}

uint32_t	ufs_shared_writes;	/* writes done w/ lock shared */
uint32_t	ufs_cur_writes;		/* # concurrent writes */
uint32_t	ufs_maxcur_writes;	/* high water concurrent writes */
uint32_t	ufs_posix_hits;		/* writes done /w lock excl. */

/*
 * Force POSIX syncronous data integrity on all writes for testing.
 */
uint32_t	ufs_force_posix_sdi = 0;

/*
 * Direct Write
 */

int
ufs_directio_write(struct inode *ip, uio_t *arg_uio, int ioflag, int rewrite,
	cred_t *cr, int *statusp)
{
	long		resid, bytes_written;
	u_offset_t	size, uoff;
	uio_t		*uio = arg_uio;
	rlim64_t	limit = uio->uio_llimit;
	int		on, n, error, newerror, len, has_holes;
	daddr_t		bn;
	size_t		nbytes;
	struct fs	*fs;
	vnode_t		*vp;
	iovec_t		*iov;
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;
	struct proc	*procp;
	struct as	*as;
	struct directio_buf	*tail;
	int		exclusive, ncur, bmap_peek;
	uio_t		copy_uio;
	iovec_t		copy_iov;
	char		*copy_base;
	long		copy_resid;

	/*
	 * assume that directio isn't possible (normal case)
	 */
	*statusp = DIRECTIO_FAILURE;

	/*
	 * Don't go direct
	 */
	if (ufs_directio_enabled == 0)
		return (0);

	/*
	 * mapped file; nevermind
	 */
	if (ip->i_mapcnt)
		return (0);

	/*
	 * CAN WE DO DIRECT IO?
	 */
	uoff = uio->uio_loffset;
	resid = uio->uio_resid;

	/*
	 * beyond limit
	 */
	if (uoff + resid > limit)
		return (0);

	/*
	 * must be sector aligned
	 */
	if ((uoff & (u_offset_t)(DEV_BSIZE - 1)) || (resid & (DEV_BSIZE - 1)))
		return (0);

	/*
	 * SHOULD WE DO DIRECT IO?
	 */
	size = ip->i_size;
	has_holes = -1;

	/*
	 * only on regular files; no metadata
	 */
	if (((ip->i_mode & IFMT) != IFREG) || ip->i_ufsvfs->vfs_qinod == ip)
		return (0);

	/*
	 * Synchronous, allocating writes run very slow in Direct-Mode
	 * 	XXX - can be fixed with bmap_write changes for large writes!!!
	 *	XXX - can be fixed for updates to "almost-full" files
	 *	XXX - WARNING - system hangs if bmap_write() has to
	 * 			allocate lots of pages since pageout
	 * 			suspends on locked inode
	 */
	if (!rewrite && (ip->i_flag & ISYNC)) {
		if ((uoff + resid) > size)
			return (0);
		has_holes = bmap_has_holes(ip);
		if (has_holes)
			return (0);
	}

	/*
	 * Each iovec must be short aligned and sector aligned.  If
	 * one is not, then kmem_alloc a new buffer and copy all of
	 * the smaller buffers into the new buffer.  This new
	 * buffer will be short aligned and sector aligned.
	 */
	iov = uio->uio_iov;
	nbytes = uio->uio_iovcnt;
	while (nbytes--) {
		if (((uint_t)iov->iov_len & (DEV_BSIZE - 1)) != 0 ||
		    (intptr_t)(iov->iov_base) & 1) {
			copy_resid = uio->uio_resid;
			copy_base = kmem_alloc(copy_resid, KM_NOSLEEP);
			if (copy_base == NULL)
				return (0);
			copy_iov.iov_base = copy_base;
			copy_iov.iov_len = copy_resid;
			copy_uio.uio_iov = &copy_iov;
			copy_uio.uio_iovcnt = 1;
			copy_uio.uio_segflg = UIO_SYSSPACE;
			copy_uio.uio_extflg = UIO_COPY_DEFAULT;
			copy_uio.uio_loffset = uio->uio_loffset;
			copy_uio.uio_resid = uio->uio_resid;
			copy_uio.uio_llimit = uio->uio_llimit;
			error = uiomove(copy_base, copy_resid, UIO_WRITE, uio);
			if (error) {
				kmem_free(copy_base, copy_resid);
				return (0);
			}
			uio = &copy_uio;
			break;
		}
		iov++;
	}

	/*
	 * From here on down, all error exits must go to errout and
	 * not simply return a 0.
	 */

	/*
	 * DIRECTIO
	 */

	fs = ip->i_fs;

	/*
	 * POSIX check. If attempting a concurrent re-write, make sure
	 * that this will be a single request to the driver to meet
	 * POSIX synchronous data integrity requirements.
	 */
	bmap_peek = 0;
	if (rewrite && ((ioflag & FDSYNC) || ufs_force_posix_sdi)) {
		int upgrade = 0;

		/* check easy conditions first */
		if (uio->uio_iovcnt != 1 || resid > ufsvfsp->vfs_ioclustsz) {
			upgrade = 1;
		} else {
			/* now look for contiguous allocation */
			len = (ssize_t)blkroundup(fs, resid);
			error = bmap_read(ip, uoff, &bn, &len);
			if (error || bn == UFS_HOLE || len == 0)
				goto errout;
			/* save a call to bmap_read later */
			bmap_peek = 1;
			if (len < resid)
				upgrade = 1;
		}
		if (upgrade) {
			rw_exit(&ip->i_contents);
			rw_enter(&ip->i_contents, RW_WRITER);
			ufs_posix_hits++;
		}
	}


	/*
	 * allocate space
	 */

	/*
	 * If attempting a re-write, there is no allocation to do.
	 * bmap_write would trip an ASSERT if i_contents is held shared.
	 */
	if (rewrite)
		goto skip_alloc;

	do {
		on = (int)blkoff(fs, uoff);
		n = (int)MIN(fs->fs_bsize - on, resid);
		if ((uoff + n) > ip->i_size) {
			error = bmap_write(ip, uoff, (int)(on + n),
			    (int)(uoff & (offset_t)MAXBOFFSET) == 0,
			    NULL, cr);
			/* Caller is responsible for updating i_seq if needed */
			if (error)
				break;
			ip->i_size = uoff + n;
			ip->i_flag |= IATTCHG;
		} else if (n == MAXBSIZE) {
			error = bmap_write(ip, uoff, (int)(on + n),
			    BI_ALLOC_ONLY, NULL, cr);
			/* Caller is responsible for updating i_seq if needed */
		} else {
			if (has_holes < 0)
				has_holes = bmap_has_holes(ip);
			if (has_holes) {
				uint_t	blk_size;
				u_offset_t offset;

				offset = uoff & (offset_t)fs->fs_bmask;
				blk_size = (int)blksize(fs, ip,
				    (daddr_t)lblkno(fs, offset));
				error = bmap_write(ip, uoff, blk_size,
				    BI_NORMAL, NULL, cr);
				/*
				 * Caller is responsible for updating
				 * i_seq if needed
				 */
			} else
				error = 0;
		}
		if (error)
			break;
		uoff += n;
		resid -= n;
		/*
		 * if file has grown larger than 2GB, set flag
		 * in superblock if not already set
		 */
		if ((ip->i_size > MAXOFF32_T) &&
		    !(fs->fs_flags & FSLARGEFILES)) {
			ASSERT(ufsvfsp->vfs_lfflags & UFS_LARGEFILES);
			mutex_enter(&ufsvfsp->vfs_lock);
			fs->fs_flags |= FSLARGEFILES;
			ufs_sbwrite(ufsvfsp);
			mutex_exit(&ufsvfsp->vfs_lock);
		}
	} while (resid);

	if (error) {
		/*
		 * restore original state
		 */
		if (resid) {
			if (size == ip->i_size)
				goto errout;
			(void) ufs_itrunc(ip, size, 0, cr);
		}
		/*
		 * try non-directio path
		 */
		goto errout;
	}
skip_alloc:

	/*
	 * get rid of cached pages
	 */
	vp = ITOV(ip);
	exclusive = rw_write_held(&ip->i_contents);
	if (vn_has_cached_data(vp)) {
		if (!exclusive) {
			/*
			 * Still holding i_rwlock, so no allocations
			 * can happen after dropping contents.
			 */
			rw_exit(&ip->i_contents);
			rw_enter(&ip->i_contents, RW_WRITER);
		}
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0,
		    B_INVAL, cr, NULL);
		if (vn_has_cached_data(vp))
			goto errout;
		if (!exclusive)
			rw_downgrade(&ip->i_contents);
		ufs_directio_kstats.nflushes.value.ui64++;
	}

	/*
	 * Direct Writes
	 */

	if (!exclusive) {
		ufs_shared_writes++;
		ncur = atomic_inc_32_nv(&ufs_cur_writes);
		if (ncur > ufs_maxcur_writes)
			ufs_maxcur_writes = ncur;
	}

	/*
	 * proc and as are for VM operations in directio_start()
	 */
	if (uio->uio_segflg == UIO_USERSPACE) {
		procp = ttoproc(curthread);
		as = procp->p_as;
	} else {
		procp = NULL;
		as = &kas;
	}
	*statusp = DIRECTIO_SUCCESS;
	error = 0;
	newerror = 0;
	resid = uio->uio_resid;
	bytes_written = 0;
	ufs_directio_kstats.logical_writes.value.ui64++;
	while (error == 0 && newerror == 0 && resid && uio->uio_iovcnt) {
		size_t pglck_len, pglck_size;
		caddr_t pglck_base;
		page_t **pplist, **spplist;

		tail = NULL;

		/*
		 * Adjust number of bytes
		 */
		iov = uio->uio_iov;
		pglck_len = (size_t)MIN(iov->iov_len, resid);
		pglck_base = iov->iov_base;
		if (pglck_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}

		/*
		 * Try to Lock down the largest chunck of pages possible.
		 */
		pglck_len = (size_t)MIN(pglck_len,  ufsvfsp->vfs_ioclustsz);
		error = as_pagelock(as, &pplist, pglck_base, pglck_len, S_READ);

		if (error)
			break;

		pglck_size = pglck_len;
		while (pglck_len) {

			nbytes = pglck_len;
			uoff = uio->uio_loffset;

			if (!bmap_peek) {

				/*
				 * Re-adjust number of bytes to contiguous
				 * range. May have already called bmap_read
				 * in the case of a concurrent rewrite.
				 */
				len = (ssize_t)blkroundup(fs, nbytes);
				error = bmap_read(ip, uoff, &bn, &len);
				if (error)
					break;
				if (bn == UFS_HOLE || len == 0)
					break;
			}
			nbytes = (size_t)MIN(nbytes, len);
			bmap_peek = 0;

			/*
			 * Get the pagelist pointer for this offset to be
			 * passed to directio_start.
			 */

			if (pplist != NULL)
				spplist = pplist +
				    btop((uintptr_t)iov->iov_base -
				    ((uintptr_t)pglck_base & PAGEMASK));
			else
				spplist = NULL;

			/*
			 * Kick off the direct write requests
			 */
			directio_start(ufsvfsp, ip, nbytes, ldbtob(bn),
			    iov->iov_base, S_READ, procp, &tail, spplist);

			/*
			 * Adjust pointers and counters
			 */
			iov->iov_len -= nbytes;
			iov->iov_base += nbytes;
			uio->uio_loffset += nbytes;
			resid -= nbytes;
			pglck_len -= nbytes;
		}

		/*
		 * Wait for outstanding requests
		 */
		newerror = directio_wait(tail, &bytes_written);

		/*
		 * Release VM resources
		 */
		as_pageunlock(as, pplist, pglck_base, pglck_size, S_READ);

	}

	if (!exclusive) {
		atomic_dec_32(&ufs_cur_writes);
		/*
		 * If this write was done shared, readers may
		 * have pulled in unmodified pages. Get rid of
		 * these potentially stale pages.
		 */
		if (vn_has_cached_data(vp)) {
			rw_exit(&ip->i_contents);
			rw_enter(&ip->i_contents, RW_WRITER);
			(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0,
			    B_INVAL, cr, NULL);
			ufs_directio_kstats.nflushes.value.ui64++;
			rw_downgrade(&ip->i_contents);
		}
	}

	/*
	 * If error, adjust resid to begin at the first
	 * un-writable byte.
	 */
	if (error == 0)
		error = newerror;
	if (error)
		resid = uio->uio_resid - bytes_written;
	arg_uio->uio_resid = resid;

	if (!rewrite) {
		ip->i_flag |= IUPD | ICHG;
		/* Caller will update i_seq */
		TRANS_INODE(ip->i_ufsvfs, ip);
	}
	/*
	 * If there is a residual; adjust the EOF if necessary
	 */
	if (resid) {
		if (size != ip->i_size) {
			if (uio->uio_loffset > size)
				size = uio->uio_loffset;
			(void) ufs_itrunc(ip, size, 0, cr);
		}
	}

	if (uio == &copy_uio)
		kmem_free(copy_base, copy_resid);

	return (error);

errout:
	if (uio == &copy_uio)
		kmem_free(copy_base, copy_resid);

	return (0);
}
/*
 * Direct read of a hole
 */
static int
directio_hole(struct uio *uio, size_t nbytes)
{
	int		error = 0, nzero;
	uio_t		phys_uio;
	iovec_t		phys_iov;

	ufs_directio_kstats.hole_reads.value.ui64++;
	ufs_directio_kstats.nread.value.ui64 += nbytes;

	phys_iov.iov_base = uio->uio_iov->iov_base;
	phys_iov.iov_len = nbytes;

	phys_uio.uio_iov = &phys_iov;
	phys_uio.uio_iovcnt = 1;
	phys_uio.uio_resid = phys_iov.iov_len;
	phys_uio.uio_segflg = uio->uio_segflg;
	phys_uio.uio_extflg = uio->uio_extflg;
	while (error == 0 && phys_uio.uio_resid) {
		nzero = (int)MIN(phys_iov.iov_len, ufs_directio_zero_len);
		error = uiomove(ufs_directio_zero_buf, nzero, UIO_READ,
		    &phys_uio);
	}
	return (error);
}

/*
 * Direct Read
 */
int
ufs_directio_read(struct inode *ip, uio_t *uio, cred_t *cr, int *statusp)
{
	ssize_t		resid, bytes_read;
	u_offset_t	size, uoff;
	int		error, newerror, len;
	size_t		nbytes;
	struct fs	*fs;
	vnode_t		*vp;
	daddr_t		bn;
	iovec_t		*iov;
	struct ufsvfs	*ufsvfsp = ip->i_ufsvfs;
	struct proc	*procp;
	struct as	*as;
	struct directio_buf	*tail;

	/*
	 * assume that directio isn't possible (normal case)
	 */
	*statusp = DIRECTIO_FAILURE;

	/*
	 * Don't go direct
	 */
	if (ufs_directio_enabled == 0)
		return (0);

	/*
	 * mapped file; nevermind
	 */
	if (ip->i_mapcnt)
		return (0);

	/*
	 * CAN WE DO DIRECT IO?
	 */
	/*
	 * must be sector aligned
	 */
	uoff = uio->uio_loffset;
	resid = uio->uio_resid;
	if ((uoff & (u_offset_t)(DEV_BSIZE - 1)) || (resid & (DEV_BSIZE - 1)))
		return (0);
	/*
	 * must be short aligned and sector aligned
	 */
	iov = uio->uio_iov;
	nbytes = uio->uio_iovcnt;
	while (nbytes--) {
		if (((size_t)iov->iov_len & (DEV_BSIZE - 1)) != 0)
			return (0);
		if ((intptr_t)(iov++->iov_base) & 1)
			return (0);
	}

	/*
	 * DIRECTIO
	 */
	fs = ip->i_fs;

	/*
	 * don't read past EOF
	 */
	size = ip->i_size;

	/*
	 * The file offset is past EOF so bail out here; we don't want
	 * to update uio_resid and make it look like we read something.
	 * We say that direct I/O was a success to avoid having rdip()
	 * go through the same "read past EOF logic".
	 */
	if (uoff >= size) {
		*statusp = DIRECTIO_SUCCESS;
		return (0);
	}

	/*
	 * The read would extend past EOF so make it smaller.
	 */
	if ((uoff + resid) > size) {
		resid = size - uoff;
		/*
		 * recheck sector alignment
		 */
		if (resid & (DEV_BSIZE - 1))
			return (0);
	}

	/*
	 * At this point, we know there is some real work to do.
	 */
	ASSERT(resid);

	/*
	 * get rid of cached pages
	 */
	vp = ITOV(ip);
	if (vn_has_cached_data(vp)) {
		rw_exit(&ip->i_contents);
		rw_enter(&ip->i_contents, RW_WRITER);
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0,
		    B_INVAL, cr, NULL);
		if (vn_has_cached_data(vp))
			return (0);
		rw_downgrade(&ip->i_contents);
		ufs_directio_kstats.nflushes.value.ui64++;
	}
	/*
	 * Direct Reads
	 */

	/*
	 * proc and as are for VM operations in directio_start()
	 */
	if (uio->uio_segflg == UIO_USERSPACE) {
		procp = ttoproc(curthread);
		as = procp->p_as;
	} else {
		procp = NULL;
		as = &kas;
	}

	*statusp = DIRECTIO_SUCCESS;
	error = 0;
	newerror = 0;
	bytes_read = 0;
	ufs_directio_kstats.logical_reads.value.ui64++;
	while (error == 0 && newerror == 0 && resid && uio->uio_iovcnt) {
		size_t pglck_len, pglck_size;
		caddr_t pglck_base;
		page_t **pplist, **spplist;

		tail = NULL;

		/*
		 * Adjust number of bytes
		 */
		iov = uio->uio_iov;
		pglck_len = (size_t)MIN(iov->iov_len, resid);
		pglck_base = iov->iov_base;
		if (pglck_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}

		/*
		 * Try to Lock down the largest chunck of pages possible.
		 */
		pglck_len = (size_t)MIN(pglck_len,  ufsvfsp->vfs_ioclustsz);
		error = as_pagelock(as, &pplist, pglck_base,
		    pglck_len, S_WRITE);

		if (error)
			break;

		pglck_size = pglck_len;
		while (pglck_len) {

			nbytes = pglck_len;
			uoff = uio->uio_loffset;

			/*
			 * Re-adjust number of bytes to contiguous range
			 */
			len = (ssize_t)blkroundup(fs, nbytes);
			error = bmap_read(ip, uoff, &bn, &len);
			if (error)
				break;

			if (bn == UFS_HOLE) {
				nbytes = (size_t)MIN(fs->fs_bsize -
				    (long)blkoff(fs, uoff), nbytes);
				error = directio_hole(uio, nbytes);
				/*
				 * Hole reads are not added to the list
				 * processed by directio_wait() below so
				 * account for bytes read here.
				 */
				if (!error)
					bytes_read += nbytes;
			} else {
				nbytes = (size_t)MIN(nbytes, len);

				/*
				 * Get the pagelist pointer for this offset
				 * to be passed to directio_start.
				 */
				if (pplist != NULL)
					spplist = pplist +
					    btop((uintptr_t)iov->iov_base -
					    ((uintptr_t)pglck_base & PAGEMASK));
				else
					spplist = NULL;

				/*
				 * Kick off the direct read requests
				 */
				directio_start(ufsvfsp, ip, nbytes,
				    ldbtob(bn), iov->iov_base,
				    S_WRITE, procp, &tail, spplist);
			}

			if (error)
				break;

			/*
			 * Adjust pointers and counters
			 */
			iov->iov_len -= nbytes;
			iov->iov_base += nbytes;
			uio->uio_loffset += nbytes;
			resid -= nbytes;
			pglck_len -= nbytes;
		}

		/*
		 * Wait for outstanding requests
		 */
		newerror = directio_wait(tail, &bytes_read);
		/*
		 * Release VM resources
		 */
		as_pageunlock(as, pplist, pglck_base, pglck_size, S_WRITE);

	}

	/*
	 * If error, adjust resid to begin at the first
	 * un-read byte.
	 */
	if (error == 0)
		error = newerror;
	uio->uio_resid -= bytes_read;
	return (error);
}
