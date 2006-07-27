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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/taskq.h>
#include <sys/uio.h>
#include <sys/vmsystm.h>
#include <sys/atomic.h>
#include <vm/seg_vn.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <sys/mman.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/sunddi.h>
#include <sys/filio.h>
#include "fs/fs_subr.h"
#include <sys/zfs_ctldir.h>
#include <sys/dnlc.h>
#include <sys/zfs_rlock.h>

/*
 * Programming rules.
 *
 * Each vnode op performs some logical unit of work.  To do this, the ZPL must
 * properly lock its in-core state, create a DMU transaction, do the work,
 * record this work in the intent log (ZIL), commit the DMU transaction,
 * and wait the the intent log to commit if it's is a synchronous operation.
 * Morover, the vnode ops must work in both normal and log replay context.
 * The ordering of events is important to avoid deadlocks and references
 * to freed memory.  The example below illustrates the following Big Rules:
 *
 *  (1) A check must be made in each zfs thread for a mounted file system.
 *	This is done avoiding races using ZFS_ENTER(zfsvfs).
 *	A ZFS_EXIT(zfsvfs) is needed before all returns.
 *
 *  (2)	VN_RELE() should always be the last thing except for zil_commit()
 *	and ZFS_EXIT(). This is for 3 reasons:
 *	First, if it's the last reference, the vnode/znode
 *	can be freed, so the zp may point to freed memory.  Second, the last
 *	reference will call zfs_zinactive(), which may induce a lot of work --
 *	pushing cached pages (which acquires range locks) and syncing out
 *	cached atime changes.  Third, zfs_zinactive() may require a new tx,
 *	which could deadlock the system if you were already holding one.
 *
 *  (3)	All range locks must be grabbed before calling dmu_tx_assign(),
 *	as they can span dmu_tx_assign() calls.
 *
 *  (4)	Always pass zfsvfs->z_assign as the second argument to dmu_tx_assign().
 *	In normal operation, this will be TXG_NOWAIT.  During ZIL replay,
 *	it will be a specific txg.  Either way, dmu_tx_assign() never blocks.
 *	This is critical because we don't want to block while holding locks.
 *	Note, in particular, that if a lock is sometimes acquired before
 *	the tx assigns, and sometimes after (e.g. z_lock), then failing to
 *	use a non-blocking assign can deadlock the system.  The scenario:
 *
 *	Thread A has grabbed a lock before calling dmu_tx_assign().
 *	Thread B is in an already-assigned tx, and blocks for this lock.
 *	Thread A calls dmu_tx_assign(TXG_WAIT) and blocks in txg_wait_open()
 *	forever, because the previous txg can't quiesce until B's tx commits.
 *
 *	If dmu_tx_assign() returns ERESTART and zfsvfs->z_assign is TXG_NOWAIT,
 *	then drop all locks, call dmu_tx_wait(), and try again.
 *
 *  (5)	If the operation succeeded, generate the intent log entry for it
 *	before dropping locks.  This ensures that the ordering of events
 *	in the intent log matches the order in which they actually occurred.
 *
 *  (6)	At the end of each vnode op, the DMU tx must always commit,
 *	regardless of whether there were any errors.
 *
 *  (7)	After dropping all locks, invoke zil_commit(zilog, seq, ioflag)
 *	to ensure that synchronous semantics are provided when necessary.
 *
 * In general, this is how things should be ordered in each vnode op:
 *
 *	ZFS_ENTER(zfsvfs);		// exit if unmounted
 * top:
 *	zfs_dirent_lock(&dl, ...)	// lock directory entry (may VN_HOLD())
 *	rw_enter(...);			// grab any other locks you need
 *	tx = dmu_tx_create(...);	// get DMU tx
 *	dmu_tx_hold_*();		// hold each object you might modify
 *	error = dmu_tx_assign(tx, zfsvfs->z_assign);	// try to assign
 *	if (error) {
 *		rw_exit(...);		// drop locks
 *		zfs_dirent_unlock(dl);	// unlock directory entry
 *		VN_RELE(...);		// release held vnodes
 *		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
 *			dmu_tx_wait(tx);
 *			dmu_tx_abort(tx);
 *			goto top;
 *		}
 *		dmu_tx_abort(tx);	// abort DMU tx
 *		ZFS_EXIT(zfsvfs);	// finished in zfs
 *		return (error);		// really out of space
 *	}
 *	error = do_real_work();		// do whatever this VOP does
 *	if (error == 0)
 *		seq = zfs_log_*(...);	// on success, make ZIL entry
 *	dmu_tx_commit(tx);		// commit DMU tx -- error or not
 *	rw_exit(...);			// drop locks
 *	zfs_dirent_unlock(dl);		// unlock directory entry
 *	VN_RELE(...);			// release held vnodes
 *	zil_commit(zilog, seq, ioflag);	// synchronous when necessary
 *	ZFS_EXIT(zfsvfs);		// finished in zfs
 *	return (error);			// done, report error
 */

/* ARGSUSED */
static int
zfs_open(vnode_t **vpp, int flag, cred_t *cr)
{
	return (0);
}

/* ARGSUSED */
static int
zfs_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr)
{
	/*
	 * Clean up any locks held by this process on the vp.
	 */
	cleanlocks(vp, ddi_get_pid(), 0);
	cleanshares(vp, ddi_get_pid());

	return (0);
}

/*
 * Lseek support for finding holes (cmd == _FIO_SEEK_HOLE) and
 * data (cmd == _FIO_SEEK_DATA). "off" is an in/out parameter.
 */
static int
zfs_holey(vnode_t *vp, int cmd, offset_t *off)
{
	znode_t	*zp = VTOZ(vp);
	uint64_t noff = (uint64_t)*off; /* new offset */
	uint64_t file_sz;
	int error;
	boolean_t hole;

	file_sz = zp->z_phys->zp_size;
	if (noff >= file_sz)  {
		return (ENXIO);
	}

	if (cmd == _FIO_SEEK_HOLE)
		hole = B_TRUE;
	else
		hole = B_FALSE;

	error = dmu_offset_next(zp->z_zfsvfs->z_os, zp->z_id, hole, &noff);

	/* end of file? */
	if ((error == ESRCH) || (noff > file_sz)) {
		/*
		 * Handle the virtual hole at the end of file.
		 */
		if (hole) {
			*off = file_sz;
			return (0);
		}
		return (ENXIO);
	}

	if (noff < *off)
		return (error);
	*off = noff;
	return (error);
}

/* ARGSUSED */
static int
zfs_ioctl(vnode_t *vp, int com, intptr_t data, int flag, cred_t *cred,
    int *rvalp)
{
	offset_t off;
	int error;
	zfsvfs_t *zfsvfs;

	switch (com) {
	    case _FIOFFS:
		return (zfs_sync(vp->v_vfsp, 0, cred));

		/*
		 * The following two ioctls are used by bfu.  Faking out,
		 * necessary to avoid bfu errors.
		 */
	    case _FIOGDIO:
	    case _FIOSDIO:
		return (0);

	    case _FIO_SEEK_DATA:
	    case _FIO_SEEK_HOLE:
		if (ddi_copyin((void *)data, &off, sizeof (off), flag))
			return (EFAULT);

		zfsvfs = VTOZ(vp)->z_zfsvfs;
		ZFS_ENTER(zfsvfs);

		/* offset parameter is in/out */
		error = zfs_holey(vp, com, &off);
		ZFS_EXIT(zfsvfs);
		if (error)
			return (error);
		if (ddi_copyout(&off, (void *)data, sizeof (off), flag))
			return (EFAULT);
		return (0);
	}
	return (ENOTTY);
}

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Write:	If we find a memory mapped page, we write to *both*
 *		the page and the dmu buffer.
 *
 * NOTE: We will always "break up" the IO into PAGESIZE uiomoves when
 *	the file is memory mapped.
 */
static int
mappedwrite(vnode_t *vp, uint64_t woff, int nbytes, uio_t *uio, dmu_tx_t *tx)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int64_t	start, off;
	int len = nbytes;
	int error = 0;

	start = uio->uio_loffset;
	off = start & PAGEOFFSET;
	for (start &= PAGEMASK; len > 0; start += PAGESIZE) {
		page_t *pp;
		uint64_t bytes = MIN(PAGESIZE - off, len);

		/*
		 * We don't want a new page to "appear" in the middle of
		 * the file update (because it may not get the write
		 * update data), so we grab a lock to block
		 * zfs_getpage().
		 */
		rw_enter(&zp->z_map_lock, RW_WRITER);
		if (pp = page_lookup(vp, start, SE_SHARED)) {
			caddr_t va;

			rw_exit(&zp->z_map_lock);
			va = ppmapin(pp, PROT_READ | PROT_WRITE, (caddr_t)-1L);
			error = uiomove(va+off, bytes, UIO_WRITE, uio);
			if (error == 0) {
				dmu_write(zfsvfs->z_os, zp->z_id,
				    woff, bytes, va+off, tx);
			}
			ppmapout(va);
			page_unlock(pp);
		} else {
			error = dmu_write_uio(zfsvfs->z_os, zp->z_id,
			    woff, bytes, uio, tx);
			rw_exit(&zp->z_map_lock);
		}
		len -= bytes;
		woff += bytes;
		off = 0;
		if (error)
			break;
	}
	return (error);
}

/*
 * When a file is memory mapped, we must keep the IO data synchronized
 * between the DMU cache and the memory mapped pages.  What this means:
 *
 * On Read:	We "read" preferentially from memory mapped pages,
 *		else we default from the dmu buffer.
 *
 * NOTE: We will always "break up" the IO into PAGESIZE uiomoves when
 *	the file is memory mapped.
 */
static int
mappedread(vnode_t *vp, char *addr, int nbytes, uio_t *uio)
{
	int64_t	start, off, bytes;
	int len = nbytes;
	int error = 0;

	start = uio->uio_loffset;
	off = start & PAGEOFFSET;
	for (start &= PAGEMASK; len > 0; start += PAGESIZE) {
		page_t *pp;

		bytes = MIN(PAGESIZE - off, len);
		if (pp = page_lookup(vp, start, SE_SHARED)) {
			caddr_t va;

			va = ppmapin(pp, PROT_READ | PROT_WRITE, (caddr_t)-1L);
			error = uiomove(va + off, bytes, UIO_READ, uio);
			ppmapout(va);
			page_unlock(pp);
		} else {
			/* XXX use dmu_read here? */
			error = uiomove(addr, bytes, UIO_READ, uio);
		}
		len -= bytes;
		addr += bytes;
		off = 0;
		if (error)
			break;
	}
	return (error);
}

uint_t zfs_read_chunk_size = 1024 * 1024; /* Tunable */

/*
 * Read bytes from specified file into supplied buffer.
 *
 *	IN:	vp	- vnode of file to be read from.
 *		uio	- structure supplying read location, range info,
 *			  and return buffer.
 *		ioflag	- SYNC flags; used to provide FRSYNC semantics.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- updated offset and range, buffer filled.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Side Effects:
 *	vp - atime updated if byte count > 0
 */
/* ARGSUSED */
static int
zfs_read(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint64_t	delta;
	ssize_t		n, size, cnt, ndone;
	int		error, i, numbufs;
	dmu_buf_t	*dbp, **dbpp;
	rl_t		*rl;

	ZFS_ENTER(zfsvfs);

	/*
	 * Validate file offset
	 */
	if (uio->uio_loffset < (offset_t)0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Fasttrack empty reads
	 */
	if (uio->uio_resid == 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/*
	 * Check for mandatory locks
	 */
	if (MANDMODE((mode_t)zp->z_phys->zp_mode)) {
		if (error = chklock(vp, FREAD,
		    uio->uio_loffset, uio->uio_resid, uio->uio_fmode, ct)) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	/*
	 * If we're in FRSYNC mode, sync out this znode before reading it.
	 */
	zil_commit(zfsvfs->z_log, zp->z_last_itx, ioflag & FRSYNC);

	/*
	 * Lock the range against changes.
	 */
	rl = zfs_range_lock(zp, uio->uio_loffset, uio->uio_resid, RL_READER);

	/*
	 * If we are reading past end-of-file we can skip
	 * to the end; but we might still need to set atime.
	 */
	if (uio->uio_loffset >= zp->z_phys->zp_size) {
		cnt = 0;
		error = 0;
		goto out;
	}

	cnt = MIN(uio->uio_resid, zp->z_phys->zp_size - uio->uio_loffset);

	for (ndone = 0; ndone < cnt; ndone += zfs_read_chunk_size) {
		ASSERT(uio->uio_loffset < zp->z_phys->zp_size);
		n = MIN(zfs_read_chunk_size,
		    zp->z_phys->zp_size - uio->uio_loffset);
		n = MIN(n, cnt);
		error = dmu_buf_hold_array_by_bonus(zp->z_dbuf,
		    uio->uio_loffset, n, TRUE, FTAG, &numbufs, &dbpp);
		if (error)
			goto out;
		/*
		 * Compute the adjustment to align the dmu buffers
		 * with the uio buffer.
		 */
		delta = uio->uio_loffset - dbpp[0]->db_offset;

		for (i = 0; i < numbufs; i++) {
			if (n < 0)
				break;
			dbp = dbpp[i];
			size = dbp->db_size - delta;
			/*
			 * XXX -- this is correct, but may be suboptimal.
			 * If the pages are all clean, we don't need to
			 * go through mappedread().  Maybe the VMODSORT
			 * stuff can help us here.
			 */
			if (vn_has_cached_data(vp)) {
				error = mappedread(vp, (caddr_t)dbp->db_data +
				    delta, (n < size ? n : size), uio);
			} else {
				error = uiomove((caddr_t)dbp->db_data + delta,
					(n < size ? n : size), UIO_READ, uio);
			}
			if (error) {
				dmu_buf_rele_array(dbpp, numbufs, FTAG);
				goto out;
			}
			n -= dbp->db_size;
			if (delta) {
				n += delta;
				delta = 0;
			}
		}
		dmu_buf_rele_array(dbpp, numbufs, FTAG);
	}
out:
	zfs_range_unlock(rl);

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Fault in the pages of the first n bytes specified by the uio structure.
 * 1 byte in each page is touched and the uio struct is unmodified.
 * Any error will exit this routine as this is only a best
 * attempt to get the pages resident. This is a copy of ufs_trans_touch().
 */
static void
zfs_prefault_write(ssize_t n, struct uio *uio)
{
	struct iovec *iov;
	ulong_t cnt, incr;
	caddr_t p;
	uint8_t tmp;

	iov = uio->uio_iov;

	while (n) {
		cnt = MIN(iov->iov_len, n);
		if (cnt == 0) {
			/* empty iov entry */
			iov++;
			continue;
		}
		n -= cnt;
		/*
		 * touch each page in this segment.
		 */
		p = iov->iov_base;
		while (cnt) {
			switch (uio->uio_segflg) {
			case UIO_USERSPACE:
			case UIO_USERISPACE:
				if (fuword8(p, &tmp))
					return;
				break;
			case UIO_SYSSPACE:
				if (kcopy(p, &tmp, 1))
					return;
				break;
			}
			incr = MIN(cnt, PAGESIZE);
			p += incr;
			cnt -= incr;
		}
		/*
		 * touch the last byte in case it straddles a page.
		 */
		p--;
		switch (uio->uio_segflg) {
		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (fuword8(p, &tmp))
				return;
			break;
		case UIO_SYSSPACE:
			if (kcopy(p, &tmp, 1))
				return;
			break;
		}
		iov++;
	}
}

/*
 * Write the bytes to a file.
 *
 *	IN:	vp	- vnode of file to be written to.
 *		uio	- structure supplying write location, range info,
 *			  and data buffer.
 *		ioflag	- FAPPEND flag set if in append mode.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- updated offset and range.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated if byte count > 0
 */
/* ARGSUSED */
static int
zfs_write(vnode_t *vp, uio_t *uio, int ioflag, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	rlim64_t	limit = uio->uio_llimit;
	ssize_t		start_resid = uio->uio_resid;
	ssize_t		tx_bytes;
	uint64_t	end_size;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	offset_t	woff;
	ssize_t		n, nbytes;
	rl_t		*rl;
	int		max_blksz = zfsvfs->z_max_blksz;
	int		error;

	/*
	 * Fasttrack empty write
	 */
	n = start_resid;
	if (n == 0)
		return (0);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	ZFS_ENTER(zfsvfs);

	/*
	 * Pre-fault the pages to ensure slow (eg NFS) pages
	 * don't hold up txg.
	 */
	zfs_prefault_write(n, uio);

	/*
	 * If in append mode, set the io offset pointer to eof.
	 */
	if (ioflag & FAPPEND) {
		/*
		 * Range lock for a file append:
		 * The value for the start of range will be determined by
		 * zfs_range_lock() (to guarantee append semantics).
		 * If this write will cause the block size to increase,
		 * zfs_range_lock() will lock the entire file, so we must
		 * later reduce the range after we grow the block size.
		 */
		rl = zfs_range_lock(zp, 0, n, RL_APPEND);
		if (rl->r_len == UINT64_MAX) {
			/* overlocked, zp_size can't change */
			woff = uio->uio_loffset = zp->z_phys->zp_size;
		} else {
			woff = uio->uio_loffset = rl->r_off;
		}
	} else {
		woff = uio->uio_loffset;
		/*
		 * Validate file offset
		 */
		if (woff < 0) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		/*
		 * If we need to grow the block size then zfs_range_lock()
		 * will lock a wider range than we request here.
		 * Later after growing the block size we reduce the range.
		 */
		rl = zfs_range_lock(zp, woff, n, RL_WRITER);
	}

	if (woff >= limit) {
		error = EFBIG;
		goto no_tx_done;
	}

	if ((woff + n) > limit || woff > (limit - n))
		n = limit - woff;

	/*
	 * Check for mandatory locks
	 */
	if (MANDMODE((mode_t)zp->z_phys->zp_mode) &&
	    (error = chklock(vp, FWRITE, woff, n, uio->uio_fmode, ct)) != 0)
		goto no_tx_done;
	end_size = MAX(zp->z_phys->zp_size, woff + n);
top:
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, zp->z_id);
	dmu_tx_hold_write(tx, zp->z_id, woff, MIN(n, max_blksz));
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto no_tx_done;
	}

	/*
	 * If zfs_range_lock() over-locked we grow the blocksize
	 * and then reduce the lock range.
	 */
	if (rl->r_len == UINT64_MAX) {
		uint64_t new_blksz;

		if (zp->z_blksz > max_blksz) {
			ASSERT(!ISP2(zp->z_blksz));
			new_blksz = MIN(end_size, SPA_MAXBLOCKSIZE);
		} else {
			new_blksz = MIN(end_size, max_blksz);
		}
		zfs_grow_blocksize(zp, new_blksz, tx);
		zfs_range_reduce(rl, woff, n);
	}

	/*
	 * The file data does not fit in the znode "cache", so we
	 * will be writing to the file block data buffers.
	 * Each buffer will be written in a separate transaction;
	 * this keeps the intent log records small and allows us
	 * to do more fine-grained space accounting.
	 */
	while (n > 0) {
		/*
		 * XXX - should we really limit each write to z_max_blksz?
		 * Perhaps we should use SPA_MAXBLOCKSIZE chunks?
		 */
		nbytes = MIN(n, max_blksz - P2PHASE(woff, max_blksz));
		rw_enter(&zp->z_map_lock, RW_READER);

		tx_bytes = uio->uio_resid;
		if (vn_has_cached_data(vp)) {
			rw_exit(&zp->z_map_lock);
			error = mappedwrite(vp, woff, nbytes, uio, tx);
		} else {
			error = dmu_write_uio(zfsvfs->z_os, zp->z_id,
			    woff, nbytes, uio, tx);
			rw_exit(&zp->z_map_lock);
		}
		tx_bytes -= uio->uio_resid;

		if (error) {
			/* XXX - do we need to "clean up" the dmu buffer? */
			break;
		}

		ASSERT(tx_bytes == nbytes);

		/*
		 * Clear Set-UID/Set-GID bits on successful write if not
		 * privileged and at least one of the excute bits is set.
		 *
		 * It would be nice to to this after all writes have
		 * been done, but that would still expose the ISUID/ISGID
		 * to another app after the partial write is committed.
		 */

		mutex_enter(&zp->z_acl_lock);
		if ((zp->z_phys->zp_mode & (S_IXUSR | (S_IXUSR >> 3) |
		    (S_IXUSR >> 6))) != 0 &&
		    (zp->z_phys->zp_mode & (S_ISUID | S_ISGID)) != 0 &&
		    secpolicy_vnode_setid_retain(cr,
		    (zp->z_phys->zp_mode & S_ISUID) != 0 &&
		    zp->z_phys->zp_uid == 0) != 0) {
			    zp->z_phys->zp_mode &= ~(S_ISUID | S_ISGID);
		}
		mutex_exit(&zp->z_acl_lock);

		n -= nbytes;
		if (n <= 0)
			break;

		/*
		 * We have more work ahead of us, so wrap up this transaction
		 * and start another.  Exact same logic as tx_done below.
		 */
		while ((end_size = zp->z_phys->zp_size) < uio->uio_loffset) {
			dmu_buf_will_dirty(zp->z_dbuf, tx);
			(void) atomic_cas_64(&zp->z_phys->zp_size, end_size,
			    uio->uio_loffset);
		}
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);
		seq = zfs_log_write(zilog, tx, TX_WRITE, zp, woff, tx_bytes,
		    ioflag, uio);
		dmu_tx_commit(tx);

		/*
		 * Start another transaction.
		 */
		woff = uio->uio_loffset;
		tx = dmu_tx_create(zfsvfs->z_os);
		dmu_tx_hold_bonus(tx, zp->z_id);
		dmu_tx_hold_write(tx, zp->z_id, woff, MIN(n, max_blksz));
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			goto no_tx_done;
		}
	}

tx_done:

	if (tx_bytes != 0) {
		/*
		 * Update the file size if it has changed; account
		 * for possible concurrent updates.
		 */
		while ((end_size = zp->z_phys->zp_size) < uio->uio_loffset) {
			dmu_buf_will_dirty(zp->z_dbuf, tx);
			(void) atomic_cas_64(&zp->z_phys->zp_size, end_size,
			    uio->uio_loffset);
		}
		zfs_time_stamper(zp, CONTENT_MODIFIED, tx);
		seq = zfs_log_write(zilog, tx, TX_WRITE, zp, woff, tx_bytes,
		    ioflag, uio);
	}
	dmu_tx_commit(tx);


no_tx_done:

	zfs_range_unlock(rl);

	/*
	 * If we're in replay mode, or we made no progress, return error.
	 * Otherwise, it's at least a partial write, so it's successful.
	 */
	if (zfsvfs->z_assign >= TXG_INITIAL || uio->uio_resid == start_resid) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	zil_commit(zilog, seq, ioflag & (FSYNC | FDSYNC));

	ZFS_EXIT(zfsvfs);
	return (0);
}

void
zfs_get_done(dmu_buf_t *db, void *vrl)
{
	rl_t *rl = (rl_t *)vrl;
	vnode_t *vp = ZTOV(rl->r_zp);

	dmu_buf_rele(db, rl);
	zfs_range_unlock(rl);
	VN_RELE(vp);
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
int
zfs_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio)
{
	zfsvfs_t *zfsvfs = arg;
	objset_t *os = zfsvfs->z_os;
	znode_t *zp;
	uint64_t off = lr->lr_offset;
	dmu_buf_t *db;
	rl_t *rl;
	int dlen = lr->lr_length;  		/* length of user data */
	int error = 0;

	ASSERT(dlen != 0);

	/*
	 * Nothing to do if the file has been removed
	 */
	if (zfs_zget(zfsvfs, lr->lr_foid, &zp) != 0)
		return (ENOENT);
	if (zp->z_reap) {
		VN_RELE(ZTOV(zp));
		return (ENOENT);
	}

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) { /* immediate write */
		rl = zfs_range_lock(zp, off, dlen, RL_READER);
		/* test for truncation needs to be done while range locked */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		VERIFY(0 == dmu_read(os, lr->lr_foid, off, dlen, buf));
	} else { /* indirect write */
		uint64_t boff; /* block starting offset */

		ASSERT3U(dlen, <=, zp->z_blksz);
		/*
		 * Have to lock the whole block to ensure when it's
		 * written out and it's checksum is being calculated
		 * that no one can change the data. We need to re-check
		 * blocksize after we get the lock in case it's changed!
		 */
		for (;;) {
			if (ISP2(zp->z_blksz)) {
				boff = P2ALIGN_TYPED(off, zp->z_blksz,
				    uint64_t);
			} else {
				boff = 0;
			}
			dlen = zp->z_blksz;
			rl = zfs_range_lock(zp, boff, dlen, RL_READER);
			if (zp->z_blksz == dlen)
				break;
			zfs_range_unlock(rl);
		}
		/* test for truncation needs to be done while range locked */
		if (off >= zp->z_phys->zp_size) {
			error = ENOENT;
			goto out;
		}
		VERIFY(0 == dmu_buf_hold(os, lr->lr_foid, boff, rl, &db));
		ASSERT(boff == db->db_offset);
		lr->lr_blkoff = off - boff;
		error = dmu_sync(zio, db, &lr->lr_blkptr,
		    lr->lr_common.lrc_txg, zio ? zfs_get_done : NULL, rl);
		/*
		 * If we get EINPROGRESS, then we need to wait for a
		 * write IO initiated by dmu_sync() to complete before
		 * we can release this dbuf.  We will finish everthing
		 * up in the zfs_get_done() callback.
		 */
		if (error == EINPROGRESS)
			return (0);
		dmu_buf_rele(db, rl);
	}
out:
	zfs_range_unlock(rl);
	VN_RELE(ZTOV(zp));
	return (error);
}

/*ARGSUSED*/
static int
zfs_access(vnode_t *vp, int mode, int flags, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	error = zfs_zaccess_rwx(zp, mode, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Lookup an entry in a directory, or an extended attribute directory.
 * If it exists, return a held vnode reference for it.
 *
 *	IN:	dvp	- vnode of directory to search.
 *		nm	- name of entry to lookup.
 *		pnp	- full pathname to lookup [UNUSED].
 *		flags	- LOOKUP_XATTR set if looking for an attribute.
 *		rdir	- root directory vnode [UNUSED].
 *		cr	- credentials of caller.
 *
 *	OUT:	vpp	- vnode of located entry, NULL if not found.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	NA
 */
/* ARGSUSED */
static int
zfs_lookup(vnode_t *dvp, char *nm, vnode_t **vpp, struct pathname *pnp,
    int flags, vnode_t *rdir, cred_t *cr)
{

	znode_t *zdp = VTOZ(dvp);
	zfsvfs_t *zfsvfs = zdp->z_zfsvfs;
	int	error;

	ZFS_ENTER(zfsvfs);

	*vpp = NULL;

	if (flags & LOOKUP_XATTR) {
		/*
		 * We don't allow recursive attributes..
		 * Maybe someday we will.
		 */
		if (zdp->z_phys->zp_flags & ZFS_XATTR) {
			ZFS_EXIT(zfsvfs);
			return (EINVAL);
		}

		if (error = zfs_get_xattrdir(VTOZ(dvp), vpp, cr)) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}

		/*
		 * Do we have permission to get into attribute directory?
		 */

		if (error = zfs_zaccess(VTOZ(*vpp), ACE_EXECUTE, cr)) {
			VN_RELE(*vpp);
		}

		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (dvp->v_type != VDIR) {
		ZFS_EXIT(zfsvfs);
		return (ENOTDIR);
	}

	/*
	 * Check accessibility of directory.
	 */

	if (error = zfs_zaccess(zdp, ACE_EXECUTE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if ((error = zfs_dirlook(zdp, nm, vpp)) == 0) {

		/*
		 * Convert device special files
		 */
		if (IS_DEVVP(*vpp)) {
			vnode_t	*svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL)
				error = ENOSYS;
			else
				*vpp = svp;
		}
	}

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Attempt to create a new entry in a directory.  If the entry
 * already exists, truncate the file if permissible, else return
 * an error.  Return the vp of the created or trunc'd file.
 *
 *	IN:	dvp	- vnode of directory to put new file entry in.
 *		name	- name of new file entry.
 *		vap	- attributes of new file.
 *		excl	- flag indicating exclusive or non-exclusive mode.
 *		mode	- mode to open file with.
 *		cr	- credentials of caller.
 *		flag	- large file flag [UNUSED].
 *
 *	OUT:	vpp	- vnode of created or trunc'd entry.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated if new entry created
 *	 vp - ctime|mtime always, atime if new
 */
/* ARGSUSED */
static int
zfs_create(vnode_t *dvp, char *name, vattr_t *vap, vcexcl_t excl,
    int mode, vnode_t **vpp, cred_t *cr, int flag)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	objset_t	*os = zfsvfs->z_os;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;
	uint64_t	zoid;

	ZFS_ENTER(zfsvfs);

top:
	*vpp = NULL;

	if ((vap->va_mode & VSVTX) && secpolicy_vnode_stky_modify(cr))
		vap->va_mode &= ~VSVTX;

	if (*name == '\0') {
		/*
		 * Null component name refers to the directory itself.
		 */
		VN_HOLD(dvp);
		zp = dzp;
		dl = NULL;
		error = 0;
	} else {
		/* possible VN_HOLD(zp) */
		if (error = zfs_dirent_lock(&dl, dzp, name, &zp, 0)) {
			if (strcmp(name, "..") == 0)
				error = EISDIR;
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	zoid = zp ? zp->z_id : -1ULL;

	if (zp == NULL) {
		/*
		 * Create a new file object and update the directory
		 * to reference it.
		 */
		if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
			goto out;
		}

		/*
		 * We only support the creation of regular files in
		 * extended attribute directories.
		 */
		if ((dzp->z_phys->zp_flags & ZFS_XATTR) &&
		    (vap->va_type != VREG)) {
			error = EINVAL;
			goto out;
		}

		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
		dmu_tx_hold_bonus(tx, dzp->z_id);
		dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
		if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, SPA_MAXBLOCKSIZE);
		error = dmu_tx_assign(tx, zfsvfs->z_assign);
		if (error) {
			zfs_dirent_unlock(dl);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				dmu_tx_wait(tx);
				dmu_tx_abort(tx);
				goto top;
			}
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);
		ASSERT(zp->z_id == zoid);
		(void) zfs_link_create(dl, zp, tx, ZNEW);
		seq = zfs_log_create(zilog, tx, TX_CREATE, dzp, zp, name);
		dmu_tx_commit(tx);
	} else {
		/*
		 * A directory entry already exists for this name.
		 */
		/*
		 * Can't truncate an existing file if in exclusive mode.
		 */
		if (excl == EXCL) {
			error = EEXIST;
			goto out;
		}
		/*
		 * Can't open a directory for writing.
		 */
		if ((ZTOV(zp)->v_type == VDIR) && (mode & S_IWRITE)) {
			error = EISDIR;
			goto out;
		}
		/*
		 * Verify requested access to file.
		 */
		if (mode && (error = zfs_zaccess_rwx(zp, mode, cr))) {
			goto out;
		}

		mutex_enter(&dzp->z_lock);
		dzp->z_seq++;
		mutex_exit(&dzp->z_lock);

		/*
		 * Truncate regular files if requested.
		 */
		if ((ZTOV(zp)->v_type == VREG) &&
		    (zp->z_phys->zp_size != 0) &&
		    (vap->va_mask & AT_SIZE) && (vap->va_size == 0)) {
			error = zfs_freesp(zp, 0, 0, mode, TRUE);
			if (error == ERESTART &&
			    zfsvfs->z_assign == TXG_NOWAIT) {
				/* NB: we already did dmu_tx_wait() */
				zfs_dirent_unlock(dl);
				VN_RELE(ZTOV(zp));
				goto top;
			}
		}
	}
out:

	if (dl)
		zfs_dirent_unlock(dl);

	if (error) {
		if (zp)
			VN_RELE(ZTOV(zp));
	} else {
		*vpp = ZTOV(zp);
		/*
		 * If vnode is for a device return a specfs vnode instead.
		 */
		if (IS_DEVVP(*vpp)) {
			struct vnode *svp;

			svp = specvp(*vpp, (*vpp)->v_rdev, (*vpp)->v_type, cr);
			VN_RELE(*vpp);
			if (svp == NULL) {
				error = ENOSYS;
			}
			*vpp = svp;
		}
	}

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Remove an entry from a directory.
 *
 *	IN:	dvp	- vnode of directory to remove entry from.
 *		name	- name of entry to remove.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime
 *	 vp - ctime (if nlink > 0)
 */
static int
zfs_remove(vnode_t *dvp, char *name, cred_t *cr)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	znode_t		*xzp = NULL;
	vnode_t		*vp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	uint64_t	acl_obj, xattr_obj;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		may_delete_now, delete_now = FALSE;
	int		reaped;
	int		error;

	ZFS_ENTER(zfsvfs);

top:
	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, name, &zp, ZEXISTS)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

	if (error = zfs_zaccess_delete(dzp, zp, cr)) {
		goto out;
	}

	/*
	 * Need to use rmdir for removing directories.
	 */
	if (vp->v_type == VDIR) {
		error = EPERM;
		goto out;
	}

	vnevent_remove(vp);

	dnlc_remove(dvp, name);

	mutex_enter(&vp->v_lock);
	may_delete_now = vp->v_count == 1 && !vn_has_cached_data(vp);
	mutex_exit(&vp->v_lock);

	/*
	 * We may delete the znode now, or we may put it on the delete queue;
	 * it depends on whether we're the last link, and on whether there are
	 * other holds on the vnode.  So we dmu_tx_hold() the right things to
	 * allow for either case.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_bonus(tx, zp->z_id);
	if (may_delete_now)
		dmu_tx_hold_free(tx, zp->z_id, 0, DMU_OBJECT_END);

	/* are there any extended attributes? */
	if ((xattr_obj = zp->z_phys->zp_xattr) != 0) {
		/*
		 * XXX - There is a possibility that the delete
		 * of the parent file could succeed, but then we get
		 * an ENOSPC when we try to delete the xattrs...
		 * so we would need to re-try the deletes periodically
		 */
		/* XXX - do we need this if we are deleting? */
		dmu_tx_hold_bonus(tx, xattr_obj);
	}

	/* are there any additional acls */
	if ((acl_obj = zp->z_phys->zp_acl.z_acl_extern_obj) != 0 &&
	    may_delete_now)
		dmu_tx_hold_free(tx, acl_obj, 0, DMU_OBJECT_END);

	/* charge as an update -- would be nice not to charge at all */
	dmu_tx_hold_zap(tx, zfsvfs->z_dqueue, FALSE, NULL);

	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Remove the directory entry.
	 */
	error = zfs_link_destroy(dl, zp, tx, 0, &reaped);

	if (error) {
		dmu_tx_commit(tx);
		goto out;
	}

	if (reaped) {
		mutex_enter(&vp->v_lock);
		delete_now = may_delete_now &&
		    vp->v_count == 1 && !vn_has_cached_data(vp) &&
		    zp->z_phys->zp_xattr == xattr_obj &&
		    zp->z_phys->zp_acl.z_acl_extern_obj == acl_obj;
		mutex_exit(&vp->v_lock);
	}

	if (delete_now) {
		if (zp->z_phys->zp_xattr) {
			error = zfs_zget(zfsvfs, zp->z_phys->zp_xattr, &xzp);
			ASSERT3U(error, ==, 0);
			ASSERT3U(xzp->z_phys->zp_links, ==, 2);
			dmu_buf_will_dirty(xzp->z_dbuf, tx);
			mutex_enter(&xzp->z_lock);
			xzp->z_reap = 1;
			xzp->z_phys->zp_links = 0;
			mutex_exit(&xzp->z_lock);
			zfs_dq_add(xzp, tx);
			zp->z_phys->zp_xattr = 0; /* probably unnecessary */
		}
		mutex_enter(&zp->z_lock);
		mutex_enter(&vp->v_lock);
		vp->v_count--;
		ASSERT3U(vp->v_count, ==, 0);
		mutex_exit(&vp->v_lock);
		zp->z_active = 0;
		mutex_exit(&zp->z_lock);
		zfs_znode_delete(zp, tx);
		VFS_RELE(zfsvfs->z_vfs);
	} else if (reaped) {
		zfs_dq_add(zp, tx);
	}

	seq = zfs_log_remove(zilog, tx, TX_REMOVE, dzp, name);

	dmu_tx_commit(tx);
out:
	zfs_dirent_unlock(dl);

	if (!delete_now) {
		VN_RELE(vp);
	} else if (xzp) {
		/* this rele delayed to prevent nesting transactions */
		VN_RELE(ZTOV(xzp));
	}

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Create a new directory and insert it into dvp using the name
 * provided.  Return a pointer to the inserted directory.
 *
 *	IN:	dvp	- vnode of directory to add subdir to.
 *		dirname	- name of new directory.
 *		vap	- attributes of new directory.
 *		cr	- credentials of caller.
 *
 *	OUT:	vpp	- vnode of created directory.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 *	 vp - ctime|mtime|atime updated
 */
static int
zfs_mkdir(vnode_t *dvp, char *dirname, vattr_t *vap, vnode_t **vpp, cred_t *cr)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	zfs_dirlock_t	*dl;
	uint64_t	zoid = 0;
	dmu_tx_t	*tx;
	int		error;

	ASSERT(vap->va_type == VDIR);

	ZFS_ENTER(zfsvfs);

	if (dzp->z_phys->zp_flags & ZFS_XATTR) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}
top:
	*vpp = NULL;

	/*
	 * First make sure the new directory doesn't exist.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, dirname, &zp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (error = zfs_zaccess(dzp, ACE_ADD_SUBDIRECTORY, cr)) {
		zfs_dirent_unlock(dl);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Add a new entry to the directory.
	 */
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, dirname);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
		    0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Create new node.
	 */
	zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);

	/*
	 * Now put new name in parent dir.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);

	*vpp = ZTOV(zp);

	seq = zfs_log_create(zilog, tx, TX_MKDIR, dzp, zp, dirname);
	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Remove a directory subdir entry.  If the current working
 * directory is the same as the subdir to be removed, the
 * remove will fail.
 *
 *	IN:	dvp	- vnode of directory to remove from.
 *		name	- name of directory to be removed.
 *		cwd	- vnode of current working directory.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
static int
zfs_rmdir(vnode_t *dvp, char *name, vnode_t *cwd, cred_t *cr)
{
	znode_t		*dzp = VTOZ(dvp);
	znode_t		*zp;
	vnode_t		*vp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	int		error;

	ZFS_ENTER(zfsvfs);

top:
	zp = NULL;

	/*
	 * Attempt to lock directory; fail if entry doesn't exist.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, name, &zp, ZEXISTS)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	vp = ZTOV(zp);

	if (error = zfs_zaccess_delete(dzp, zp, cr)) {
		goto out;
	}

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	if (vp == cwd) {
		error = EINVAL;
		goto out;
	}

	vnevent_rmdir(vp);

	/*
	 * Grab a lock on the parent pointer make sure we play well
	 * with the treewalk and directory rename code.
	 */
	rw_enter(&zp->z_parent_lock, RW_WRITER);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_zap(tx, dzp->z_id, FALSE, name);
	dmu_tx_hold_bonus(tx, zp->z_id);
	dmu_tx_hold_zap(tx, zfsvfs->z_dqueue, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		rw_exit(&zp->z_parent_lock);
		zfs_dirent_unlock(dl);
		VN_RELE(vp);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_destroy(dl, zp, tx, 0, NULL);

	if (error == 0)
		seq = zfs_log_remove(zilog, tx, TX_RMDIR, dzp, name);

	dmu_tx_commit(tx);

	rw_exit(&zp->z_parent_lock);
out:
	zfs_dirent_unlock(dl);

	VN_RELE(vp);

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Read as many directory entries as will fit into the provided
 * buffer from the given directory cursor position (specified in
 * the uio structure.
 *
 *	IN:	vp	- vnode of directory to read.
 *		uio	- structure supplying read location, range info,
 *			  and return buffer.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- updated offset and range, buffer filled.
 *		eofp	- set to true if end-of-file detected.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 *
 * Note that the low 4 bits of the cookie returned by zap is always zero.
 * This allows us to use the low range for "special" directory entries:
 * We use 0 for '.', and 1 for '..'.  If this is the root of the filesystem,
 * we use the offset 2 for the '.zfs' directory.
 */
/* ARGSUSED */
static int
zfs_readdir(vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp)
{
	znode_t		*zp = VTOZ(vp);
	iovec_t		*iovp;
	dirent64_t	*odp;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	objset_t	*os;
	caddr_t		outbuf;
	size_t		bufsize;
	zap_cursor_t	zc;
	zap_attribute_t	zap;
	uint_t		bytes_wanted;
	ushort_t	this_reclen;
	uint64_t	offset; /* must be unsigned; checks for < 1 */
	off64_t		*next;
	int		local_eof;
	int		outcount;
	int		error;
	uint8_t		prefetch;

	ZFS_ENTER(zfsvfs);

	/*
	 * If we are not given an eof variable,
	 * use a local one.
	 */
	if (eofp == NULL)
		eofp = &local_eof;

	/*
	 * Check for valid iov_len.
	 */
	if (uio->uio_iov->iov_len <= 0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Quit if directory has been removed (posix)
	 */
	if ((*eofp = zp->z_reap) != 0) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	error = 0;
	os = zfsvfs->z_os;
	offset = uio->uio_loffset;
	prefetch = zp->z_zn_prefetch;

	/*
	 * Initialize the iterator cursor.
	 */
	if (offset <= 3) {
		/*
		 * Start iteration from the beginning of the directory.
		 */
		zap_cursor_init(&zc, os, zp->z_id);
	} else {
		/*
		 * The offset is a serialized cursor.
		 */
		zap_cursor_init_serialized(&zc, os, zp->z_id, offset);
	}

	/*
	 * Get space to change directory entries into fs independent format.
	 */
	iovp = uio->uio_iov;
	bytes_wanted = iovp->iov_len;
	if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1) {
		bufsize = bytes_wanted;
		outbuf = kmem_alloc(bufsize, KM_SLEEP);
		odp = (struct dirent64 *)outbuf;
	} else {
		bufsize = bytes_wanted;
		odp = (struct dirent64 *)iovp->iov_base;
	}

	/*
	 * Transform to file-system independent format
	 */
	outcount = 0;
	while (outcount < bytes_wanted) {
		/*
		 * Special case `.', `..', and `.zfs'.
		 */
		if (offset == 0) {
			(void) strcpy(zap.za_name, ".");
			zap.za_first_integer = zp->z_id;
			this_reclen = DIRENT64_RECLEN(1);
		} else if (offset == 1) {
			(void) strcpy(zap.za_name, "..");
			zap.za_first_integer = zp->z_phys->zp_parent;
			this_reclen = DIRENT64_RECLEN(2);
		} else if (offset == 2 && zfs_show_ctldir(zp)) {
			(void) strcpy(zap.za_name, ZFS_CTLDIR_NAME);
			zap.za_first_integer = ZFSCTL_INO_ROOT;
			this_reclen =
			    DIRENT64_RECLEN(sizeof (ZFS_CTLDIR_NAME) - 1);
		} else {
			/*
			 * Grab next entry.
			 */
			if (error = zap_cursor_retrieve(&zc, &zap)) {
				if ((*eofp = (error == ENOENT)) != 0)
					break;
				else
					goto update;
			}

			if (zap.za_integer_length != 8 ||
			    zap.za_num_integers != 1) {
				cmn_err(CE_WARN, "zap_readdir: bad directory "
				    "entry, obj = %lld, offset = %lld\n",
				    (u_longlong_t)zp->z_id,
				    (u_longlong_t)offset);
				error = ENXIO;
				goto update;
			}
			this_reclen = DIRENT64_RECLEN(strlen(zap.za_name));
		}

		/*
		 * Will this entry fit in the buffer?
		 */
		if (outcount + this_reclen > bufsize) {
			/*
			 * Did we manage to fit anything in the buffer?
			 */
			if (!outcount) {
				error = EINVAL;
				goto update;
			}
			break;
		}
		/*
		 * Add this entry:
		 */
		odp->d_ino = (ino64_t)zap.za_first_integer;
		odp->d_reclen = (ushort_t)this_reclen;
		/* NOTE: d_off is the offset for the *next* entry */
		next = &(odp->d_off);
		(void) strncpy(odp->d_name, zap.za_name,
		    DIRENT64_NAMELEN(this_reclen));
		outcount += this_reclen;
		odp = (dirent64_t *)((intptr_t)odp + this_reclen);

		ASSERT(outcount <= bufsize);

		/* Prefetch znode */
		if (prefetch)
			dmu_prefetch(os, zap.za_first_integer, 0, 0);

		/*
		 * Move to the next entry, fill in the previous offset.
		 */
		if (offset > 2 || (offset == 2 && !zfs_show_ctldir(zp))) {
			zap_cursor_advance(&zc);
			offset = zap_cursor_serialize(&zc);
		} else {
			offset += 1;
		}
		*next = offset;
	}
	zp->z_zn_prefetch = B_FALSE; /* a lookup will re-enable pre-fetching */

	if (uio->uio_segflg == UIO_SYSSPACE && uio->uio_iovcnt == 1) {
		iovp->iov_base += outcount;
		iovp->iov_len -= outcount;
		uio->uio_resid -= outcount;
	} else if (error = uiomove(outbuf, (long)outcount, UIO_READ, uio)) {
		/*
		 * Reset the pointer.
		 */
		offset = uio->uio_loffset;
	}

update:
	zap_cursor_fini(&zc);
	if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1)
		kmem_free(outbuf, bufsize);

	if (error == ENOENT)
		error = 0;

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	uio->uio_loffset = offset;
	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_fsync(vnode_t *vp, int syncflag, cred_t *cr)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	/*
	 * Regardless of whether this is required for standards conformance,
	 * this is the logical behavior when fsync() is called on a file with
	 * dirty pages.  We use B_ASYNC since the ZIL transactions are already
	 * going to be pushed out as part of the zil_commit().
	 */
	if (vn_has_cached_data(vp) && !(syncflag & FNODSYNC) &&
	    (vp->v_type == VREG) && !(IS_SWAPVP(vp)))
		(void) VOP_PUTPAGE(vp, (offset_t)0, (size_t)0, B_ASYNC, cr);

	ZFS_ENTER(zfsvfs);
	zil_commit(zfsvfs->z_log, zp->z_last_itx, FSYNC);
	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Get the requested file attributes and place them in the provided
 * vattr structure.
 *
 *	IN:	vp	- vnode of file.
 *		vap	- va_mask identifies requested attributes.
 *		flags	- [UNUSED]
 *		cr	- credentials of caller.
 *
 *	OUT:	vap	- attribute values.
 *
 *	RETURN:	0 (always succeeds)
 */
/* ARGSUSED */
static int
zfs_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	znode_phys_t *pzp = zp->z_phys;
	int	error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Return all attributes.  It's cheaper to provide the answer
	 * than to determine whether we were asked the question.
	 */
	mutex_enter(&zp->z_lock);

	vap->va_type = vp->v_type;
	vap->va_mode = pzp->zp_mode & MODEMASK;
	vap->va_uid = zp->z_phys->zp_uid;
	vap->va_gid = zp->z_phys->zp_gid;
	vap->va_fsid = zp->z_zfsvfs->z_vfs->vfs_dev;
	vap->va_nodeid = zp->z_id;
	vap->va_nlink = MIN(pzp->zp_links, UINT32_MAX);	/* nlink_t limit! */
	vap->va_size = pzp->zp_size;
	vap->va_rdev = vp->v_rdev;
	vap->va_seq = zp->z_seq;

	ZFS_TIME_DECODE(&vap->va_atime, pzp->zp_atime);
	ZFS_TIME_DECODE(&vap->va_mtime, pzp->zp_mtime);
	ZFS_TIME_DECODE(&vap->va_ctime, pzp->zp_ctime);

	/*
	 * If ACL is trivial don't bother looking for ACE_READ_ATTRIBUTES.
	 * Also, if we are the owner don't bother, since owner should
	 * always be allowed to read basic attributes of file.
	 */
	if (!(zp->z_phys->zp_flags & ZFS_ACL_TRIVIAL) &&
	    (zp->z_phys->zp_uid != crgetuid(cr))) {
		if (error = zfs_zaccess(zp, ACE_READ_ATTRIBUTES, cr)) {
			mutex_exit(&zp->z_lock);
			ZFS_EXIT(zfsvfs);
			return (error);
		}
	}

	mutex_exit(&zp->z_lock);

	dmu_object_size_from_db(zp->z_dbuf, &vap->va_blksize, &vap->va_nblocks);

	if (zp->z_blksz == 0) {
		/*
		 * Block size hasn't been set; suggest maximal I/O transfers.
		 */
		vap->va_blksize = zfsvfs->z_max_blksz;
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}

/*
 * Set the file attributes to the values contained in the
 * vattr structure.
 *
 *	IN:	vp	- vnode of file to be modified.
 *		vap	- new attribute values.
 *		flags	- ATTR_UTIME set if non-default time values provided.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime updated, mtime updated if size changed.
 */
/* ARGSUSED */
static int
zfs_setattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
	caller_context_t *ct)
{
	struct znode	*zp = VTOZ(vp);
	znode_phys_t	*pzp = zp->z_phys;
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	dmu_tx_t	*tx;
	vattr_t		oldva;
	uint_t		mask = vap->va_mask;
	uint_t		saved_mask;
	int		trim_mask = FALSE;
	uint64_t	new_mode;
	znode_t		*attrzp;
	int		need_policy = FALSE;
	int		err;

	if (mask == 0)
		return (0);

	if (mask & AT_NOSET)
		return (EINVAL);

	if (mask & AT_SIZE && vp->v_type == VDIR)
		return (EISDIR);

	if (mask & AT_SIZE && vp->v_type != VREG && vp->v_type != VFIFO)
		return (EINVAL);

	ZFS_ENTER(zfsvfs);

top:
	attrzp = NULL;

	if (zfsvfs->z_vfs->vfs_flag & VFS_RDONLY) {
		ZFS_EXIT(zfsvfs);
		return (EROFS);
	}

	/*
	 * First validate permissions
	 */

	if (mask & AT_SIZE) {
		err = zfs_zaccess(zp, ACE_WRITE_DATA, cr);
		if (err) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
		/*
		 * XXX - Note, we are not providing any open
		 * mode flags here (like FNDELAY), so we may
		 * block if there are locks present... this
		 * should be addressed in openat().
		 */
		do {
			err = zfs_freesp(zp, vap->va_size, 0, 0, FALSE);
			/* NB: we already did dmu_tx_wait() if necessary */
		} while (err == ERESTART && zfsvfs->z_assign == TXG_NOWAIT);
		if (err) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}
	}

	if (mask & (AT_ATIME|AT_MTIME))
		need_policy = zfs_zaccess_v4_perm(zp, ACE_WRITE_ATTRIBUTES, cr);

	if (mask & (AT_UID|AT_GID)) {
		int	idmask = (mask & (AT_UID|AT_GID));
		int	take_owner;
		int	take_group;

		/*
		 * NOTE: even if a new mode is being set,
		 * we may clear S_ISUID/S_ISGID bits.
		 */

		if (!(mask & AT_MODE))
			vap->va_mode = pzp->zp_mode;

		/*
		 * Take ownership or chgrp to group we are a member of
		 */

		take_owner = (mask & AT_UID) && (vap->va_uid == crgetuid(cr));
		take_group = (mask & AT_GID) && groupmember(vap->va_gid, cr);

		/*
		 * If both AT_UID and AT_GID are set then take_owner and
		 * take_group must both be set in order to allow taking
		 * ownership.
		 *
		 * Otherwise, send the check through secpolicy_vnode_setattr()
		 *
		 */

		if (((idmask == (AT_UID|AT_GID)) && take_owner && take_group) ||
		    ((idmask == AT_UID) && take_owner) ||
		    ((idmask == AT_GID) && take_group)) {
			if (zfs_zaccess_v4_perm(zp, ACE_WRITE_OWNER, cr) == 0) {
				/*
				 * Remove setuid/setgid for non-privileged users
				 */
				secpolicy_setid_clear(vap, cr);
				trim_mask = TRUE;
				saved_mask = vap->va_mask;
			} else {
				need_policy =  TRUE;
			}
		} else {
			need_policy =  TRUE;
		}
	}

	if (mask & AT_MODE)
		need_policy = TRUE;

	if (need_policy) {
		mutex_enter(&zp->z_lock);
		oldva.va_mode = pzp->zp_mode;
		oldva.va_uid = zp->z_phys->zp_uid;
		oldva.va_gid = zp->z_phys->zp_gid;
		mutex_exit(&zp->z_lock);

		/*
		 * If trim_mask is set then take ownership
		 * has been granted.  In that case remove
		 * UID|GID from mask so that
		 * secpolicy_vnode_setattr() doesn't revoke it.
		 */
		if (trim_mask)
			vap->va_mask &= ~(AT_UID|AT_GID);

		err = secpolicy_vnode_setattr(cr, vp, vap, &oldva, flags,
		    (int (*)(void *, int, cred_t *))zfs_zaccess_rwx, zp);
		if (err) {
			ZFS_EXIT(zfsvfs);
			return (err);
		}

		if (trim_mask)
			vap->va_mask |= (saved_mask & (AT_UID|AT_GID));
	}

	/*
	 * secpolicy_vnode_setattr, or take ownership may have
	 * changed va_mask
	 */
	mask = vap->va_mask;

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, zp->z_id);

	if (mask & AT_MODE) {
		uint64_t pmode = pzp->zp_mode;

		new_mode = (pmode & S_IFMT) | (vap->va_mode & ~S_IFMT);

		if (zp->z_phys->zp_acl.z_acl_extern_obj)
			dmu_tx_hold_write(tx,
			    pzp->zp_acl.z_acl_extern_obj, 0, SPA_MAXBLOCKSIZE);
		else
			dmu_tx_hold_write(tx, DMU_NEW_OBJECT,
			    0, ZFS_ACL_SIZE(MAX_ACL_SIZE));
	}

	if ((mask & (AT_UID | AT_GID)) && zp->z_phys->zp_xattr != 0) {
		err = zfs_zget(zp->z_zfsvfs, zp->z_phys->zp_xattr, &attrzp);
		if (err) {
			dmu_tx_abort(tx);
			ZFS_EXIT(zfsvfs);
			return (err);
		}
		dmu_tx_hold_bonus(tx, attrzp->z_id);
	}

	err = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (err) {
		if (attrzp)
			VN_RELE(ZTOV(attrzp));
		if (err == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (err);
	}

	dmu_buf_will_dirty(zp->z_dbuf, tx);

	/*
	 * Set each attribute requested.
	 * We group settings according to the locks they need to acquire.
	 *
	 * Note: you cannot set ctime directly, although it will be
	 * updated as a side-effect of calling this function.
	 */

	mutex_enter(&zp->z_lock);

	if (mask & AT_MODE) {
		err = zfs_acl_chmod_setattr(zp, new_mode, tx);
		ASSERT3U(err, ==, 0);
	}

	if (attrzp)
		mutex_enter(&attrzp->z_lock);

	if (mask & AT_UID) {
		zp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		if (attrzp) {
			attrzp->z_phys->zp_uid = (uint64_t)vap->va_uid;
		}
	}

	if (mask & AT_GID) {
		zp->z_phys->zp_gid = (uint64_t)vap->va_gid;
		if (attrzp)
			attrzp->z_phys->zp_gid = (uint64_t)vap->va_gid;
	}

	if (attrzp)
		mutex_exit(&attrzp->z_lock);

	if (mask & AT_ATIME)
		ZFS_TIME_ENCODE(&vap->va_atime, pzp->zp_atime);

	if (mask & AT_MTIME)
		ZFS_TIME_ENCODE(&vap->va_mtime, pzp->zp_mtime);

	if (mask & AT_SIZE)
		zfs_time_stamper_locked(zp, CONTENT_MODIFIED, tx);
	else if (mask != 0)
		zfs_time_stamper_locked(zp, STATE_CHANGED, tx);

	if (mask != 0)
		seq = zfs_log_setattr(zilog, tx, TX_SETATTR, zp, vap, mask);

	mutex_exit(&zp->z_lock);

	if (attrzp)
		VN_RELE(ZTOV(attrzp));

	dmu_tx_commit(tx);

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (err);
}

/*
 * Search back through the directory tree, using the ".." entries.
 * Lock each directory in the chain to prevent concurrent renames.
 * Fail any attempt to move a directory into one of its own descendants.
 * XXX - z_parent_lock can overlap with map or grow locks
 */
typedef struct zfs_zlock {
	krwlock_t	*zl_rwlock;	/* lock we acquired */
	znode_t		*zl_znode;	/* znode we held */
	struct zfs_zlock *zl_next;	/* next in list */
} zfs_zlock_t;

static int
zfs_rename_lock(znode_t *szp, znode_t *tdzp, znode_t *sdzp, zfs_zlock_t **zlpp)
{
	zfs_zlock_t	*zl;
	znode_t 	*zp = tdzp;
	uint64_t	rootid = zp->z_zfsvfs->z_root;
	uint64_t	*oidp = &zp->z_id;
	krwlock_t	*rwlp = &szp->z_parent_lock;
	krw_t		rw = RW_WRITER;

	/*
	 * First pass write-locks szp and compares to zp->z_id.
	 * Later passes read-lock zp and compare to zp->z_parent.
	 */
	do {
		zl = kmem_alloc(sizeof (*zl), KM_SLEEP);
		zl->zl_rwlock = rwlp;
		zl->zl_znode = NULL;
		zl->zl_next = *zlpp;
		*zlpp = zl;

		rw_enter(rwlp, rw);

		if (*oidp == szp->z_id)		/* We're a descendant of szp */
			return (EINVAL);

		if (*oidp == rootid)		/* We've hit the top */
			return (0);

		if (rw == RW_READER) {		/* i.e. not the first pass */
			int error = zfs_zget(zp->z_zfsvfs, *oidp, &zp);
			if (error)
				return (error);
			zl->zl_znode = zp;
		}
		oidp = &zp->z_phys->zp_parent;
		rwlp = &zp->z_parent_lock;
		rw = RW_READER;

	} while (zp->z_id != sdzp->z_id);

	return (0);
}

/*
 * Drop locks and release vnodes that were held by zfs_rename_lock().
 */
static void
zfs_rename_unlock(zfs_zlock_t **zlpp)
{
	zfs_zlock_t *zl;

	while ((zl = *zlpp) != NULL) {
		if (zl->zl_znode != NULL)
			VN_RELE(ZTOV(zl->zl_znode));
		rw_exit(zl->zl_rwlock);
		*zlpp = zl->zl_next;
		kmem_free(zl, sizeof (*zl));
	}
}

/*
 * Move an entry from the provided source directory to the target
 * directory.  Change the entry name as indicated.
 *
 *	IN:	sdvp	- Source directory containing the "old entry".
 *		snm	- Old entry name.
 *		tdvp	- Target directory to contain the "new entry".
 *		tnm	- New entry name.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	sdvp,tdvp - ctime|mtime updated
 */
static int
zfs_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm, cred_t *cr)
{
	znode_t		*tdzp, *szp, *tzp;
	znode_t		*sdzp = VTOZ(sdvp);
	zfsvfs_t	*zfsvfs = sdzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	vnode_t		*realvp;
	zfs_dirlock_t	*sdl, *tdl;
	dmu_tx_t	*tx;
	zfs_zlock_t	*zl;
	int		cmp, serr, terr, error;

	ZFS_ENTER(zfsvfs);

	/*
	 * Make sure we have the real vp for the target directory.
	 */
	if (VOP_REALVP(tdvp, &realvp) == 0)
		tdvp = realvp;

	if (tdvp->v_vfsp != sdvp->v_vfsp) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}

	tdzp = VTOZ(tdvp);
top:
	szp = NULL;
	tzp = NULL;
	zl = NULL;

	/*
	 * This is to prevent the creation of links into attribute space
	 * by renaming a linked file into/outof an attribute directory.
	 * See the comment in zfs_link() for why this is considered bad.
	 */
	if ((tdzp->z_phys->zp_flags & ZFS_XATTR) !=
	    (sdzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * Lock source and target directory entries.  To prevent deadlock,
	 * a lock ordering must be defined.  We lock the directory with
	 * the smallest object id first, or if it's a tie, the one with
	 * the lexically first name.
	 */
	if (sdzp->z_id < tdzp->z_id) {
		cmp = -1;
	} else if (sdzp->z_id > tdzp->z_id) {
		cmp = 1;
	} else {
		cmp = strcmp(snm, tnm);
		if (cmp == 0) {
			/*
			 * POSIX: "If the old argument and the new argument
			 * both refer to links to the same existing file,
			 * the rename() function shall return successfully
			 * and perform no other action."
			 */
			ZFS_EXIT(zfsvfs);
			return (0);
		}
	}
	if (cmp < 0) {
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp, ZEXISTS);
		terr = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp, 0);
	} else {
		terr = zfs_dirent_lock(&tdl, tdzp, tnm, &tzp, 0);
		serr = zfs_dirent_lock(&sdl, sdzp, snm, &szp, ZEXISTS);
	}

	if (serr) {
		/*
		 * Source entry invalid or not there.
		 */
		if (!terr) {
			zfs_dirent_unlock(tdl);
			if (tzp)
				VN_RELE(ZTOV(tzp));
		}
		if (strcmp(snm, "..") == 0)
			serr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (serr);
	}
	if (terr) {
		zfs_dirent_unlock(sdl);
		VN_RELE(ZTOV(szp));
		if (strcmp(tnm, "..") == 0)
			terr = EINVAL;
		ZFS_EXIT(zfsvfs);
		return (terr);
	}

	/*
	 * Must have write access at the source to remove the old entry
	 * and write access at the target to create the new entry.
	 * Note that if target and source are the same, this can be
	 * done in a single check.
	 */

	if (error = zfs_zaccess_rename(sdzp, szp, tdzp, tzp, cr))
		goto out;

	if (ZTOV(szp)->v_type == VDIR) {
		/*
		 * Check to make sure rename is valid.
		 * Can't do a move like this: /usr/a/b to /usr/a/b/c/d
		 */
		if (error = zfs_rename_lock(szp, tdzp, sdzp, &zl))
			goto out;
	}

	/*
	 * Does target exist?
	 */
	if (tzp) {
		/*
		 * Source and target must be the same type.
		 */
		if (ZTOV(szp)->v_type == VDIR) {
			if (ZTOV(tzp)->v_type != VDIR) {
				error = ENOTDIR;
				goto out;
			}
		} else {
			if (ZTOV(tzp)->v_type == VDIR) {
				error = EISDIR;
				goto out;
			}
		}
		/*
		 * POSIX dictates that when the source and target
		 * entries refer to the same file object, rename
		 * must do nothing and exit without error.
		 */
		if (szp->z_id == tzp->z_id) {
			error = 0;
			goto out;
		}
	}

	vnevent_rename_src(ZTOV(szp));
	if (tzp)
		vnevent_rename_dest(ZTOV(tzp));

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);	/* nlink changes */
	dmu_tx_hold_bonus(tx, sdzp->z_id);	/* nlink changes */
	dmu_tx_hold_zap(tx, sdzp->z_id, FALSE, snm);
	dmu_tx_hold_zap(tx, tdzp->z_id, TRUE, tnm);
	if (sdzp != tdzp)
		dmu_tx_hold_bonus(tx, tdzp->z_id);	/* nlink changes */
	if (tzp)
		dmu_tx_hold_bonus(tx, tzp->z_id);	/* parent changes */
	dmu_tx_hold_zap(tx, zfsvfs->z_dqueue, FALSE, NULL);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		if (zl != NULL)
			zfs_rename_unlock(&zl);
		zfs_dirent_unlock(sdl);
		zfs_dirent_unlock(tdl);
		VN_RELE(ZTOV(szp));
		if (tzp)
			VN_RELE(ZTOV(tzp));
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (tzp)	/* Attempt to remove the existing target */
		error = zfs_link_destroy(tdl, tzp, tx, 0, NULL);

	if (error == 0) {
		error = zfs_link_create(tdl, szp, tx, ZRENAMING);
		if (error == 0) {
			error = zfs_link_destroy(sdl, szp, tx, ZRENAMING, NULL);
			ASSERT(error == 0);
			seq = zfs_log_rename(zilog, tx, TX_RENAME,
			    sdzp, sdl->dl_name, tdzp, tdl->dl_name, szp);
		}
	}

	dmu_tx_commit(tx);
out:
	if (zl != NULL)
		zfs_rename_unlock(&zl);

	zfs_dirent_unlock(sdl);
	zfs_dirent_unlock(tdl);

	VN_RELE(ZTOV(szp));
	if (tzp)
		VN_RELE(ZTOV(tzp));

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Insert the indicated symbolic reference entry into the directory.
 *
 *	IN:	dvp	- Directory to contain new symbolic link.
 *		link	- Name for new symlink entry.
 *		vap	- Attributes of new entry.
 *		target	- Target path of new symlink.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
static int
zfs_symlink(vnode_t *dvp, char *name, vattr_t *vap, char *link, cred_t *cr)
{
	znode_t		*zp, *dzp = VTOZ(dvp);
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	uint64_t	zoid;
	int		len = strlen(link);
	int		error;

	ASSERT(vap->va_type == VLNK);

	ZFS_ENTER(zfsvfs);
top:
	if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (len > MAXPATHLEN) {
		ZFS_EXIT(zfsvfs);
		return (ENAMETOOLONG);
	}

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, name, &zp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, MAX(1, len));
	dmu_tx_hold_bonus(tx, dzp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	if (dzp->z_phys->zp_flags & ZFS_INHERIT_ACE)
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	dmu_buf_will_dirty(dzp->z_dbuf, tx);

	/*
	 * Create a new object for the symlink.
	 * Put the link content into bonus buffer if it will fit;
	 * otherwise, store it just like any other file data.
	 */
	zoid = 0;
	if (sizeof (znode_phys_t) + len <= dmu_bonus_max()) {
		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, len);
		if (len != 0)
			bcopy(link, zp->z_phys + 1, len);
	} else {
		dmu_buf_t *dbp;

		zfs_mknode(dzp, vap, &zoid, tx, cr, 0, &zp, 0);

		/*
		 * Nothing can access the znode yet so no locking needed
		 * for growing the znode's blocksize.
		 */
		zfs_grow_blocksize(zp, len, tx);

		VERIFY(0 == dmu_buf_hold(zfsvfs->z_os, zoid, 0, FTAG, &dbp));
		dmu_buf_will_dirty(dbp, tx);

		ASSERT3U(len, <=, dbp->db_size);
		bcopy(link, dbp->db_data, len);
		dmu_buf_rele(dbp, FTAG);
	}
	zp->z_phys->zp_size = len;

	/*
	 * Insert the new object into the directory.
	 */
	(void) zfs_link_create(dl, zp, tx, ZNEW);
out:
	if (error == 0)
		seq = zfs_log_symlink(zilog, tx, TX_SYMLINK,
		    dzp, zp, name, link);

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	VN_RELE(ZTOV(zp));

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Return, in the buffer contained in the provided uio structure,
 * the symbolic path referred to by vp.
 *
 *	IN:	vp	- vnode of symbolic link.
 *		uoip	- structure to contain the link path.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- structure to contain the link path.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
static int
zfs_readlink(vnode_t *vp, uio_t *uio, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	size_t		bufsz;
	int		error;

	ZFS_ENTER(zfsvfs);

	bufsz = (size_t)zp->z_phys->zp_size;
	if (bufsz + sizeof (znode_phys_t) <= zp->z_dbuf->db_size) {
		error = uiomove(zp->z_phys + 1,
		    MIN((size_t)bufsz, uio->uio_resid), UIO_READ, uio);
	} else {
		dmu_buf_t *dbp;
		error = dmu_buf_hold(zfsvfs->z_os, zp->z_id, 0, FTAG, &dbp);
		if (error) {
			ZFS_EXIT(zfsvfs);
			return (error);
		}
		error = uiomove(dbp->db_data,
		    MIN((size_t)bufsz, uio->uio_resid), UIO_READ, uio);
		dmu_buf_rele(dbp, FTAG);
	}

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Insert a new entry into directory tdvp referencing svp.
 *
 *	IN:	tdvp	- Directory to contain new entry.
 *		svp	- vnode of new entry.
 *		name	- name of new entry.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	tdvp - ctime|mtime updated
 *	 svp - ctime updated
 */
/* ARGSUSED */
static int
zfs_link(vnode_t *tdvp, vnode_t *svp, char *name, cred_t *cr)
{
	znode_t		*dzp = VTOZ(tdvp);
	znode_t		*tzp, *szp;
	zfsvfs_t	*zfsvfs = dzp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	uint64_t	seq = 0;
	zfs_dirlock_t	*dl;
	dmu_tx_t	*tx;
	vnode_t		*realvp;
	int		error;

	ASSERT(tdvp->v_type == VDIR);

	ZFS_ENTER(zfsvfs);

	if (VOP_REALVP(svp, &realvp) == 0)
		svp = realvp;

	if (svp->v_vfsp != tdvp->v_vfsp) {
		ZFS_EXIT(zfsvfs);
		return (EXDEV);
	}

	szp = VTOZ(svp);
top:
	/*
	 * We do not support links between attributes and non-attributes
	 * because of the potential security risk of creating links
	 * into "normal" file space in order to circumvent restrictions
	 * imposed in attribute space.
	 */
	if ((szp->z_phys->zp_flags & ZFS_XATTR) !=
	    (dzp->z_phys->zp_flags & ZFS_XATTR)) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	/*
	 * POSIX dictates that we return EPERM here.
	 * Better choices include ENOTSUP or EISDIR.
	 */
	if (svp->v_type == VDIR) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

	if ((uid_t)szp->z_phys->zp_uid != crgetuid(cr) &&
	    secpolicy_basic_link(cr) != 0) {
		ZFS_EXIT(zfsvfs);
		return (EPERM);
	}

	if (error = zfs_zaccess(dzp, ACE_ADD_FILE, cr)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	/*
	 * Attempt to lock directory; fail if entry already exists.
	 */
	if (error = zfs_dirent_lock(&dl, dzp, name, &tzp, ZNEW)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_bonus(tx, szp->z_id);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, name);
	error = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	error = zfs_link_create(dl, szp, tx, 0);

	if (error == 0)
		seq = zfs_log_link(zilog, tx, TX_LINK, dzp, szp, name);

	dmu_tx_commit(tx);

	zfs_dirent_unlock(dl);

	zil_commit(zilog, seq, 0);

	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * zfs_null_putapage() is used when the file system has been force
 * unmounted. It just drops the pages.
 */
/* ARGSUSED */
static int
zfs_null_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp,
		size_t *lenp, int flags, cred_t *cr)
{
	pvn_write_done(pp, B_INVAL|B_FORCE|B_ERROR);
	return (0);
}

/* ARGSUSED */
static int
zfs_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp,
		size_t *lenp, int flags, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	zilog_t		*zilog = zfsvfs->z_log;
	dmu_tx_t	*tx;
	rl_t		*rl;
	u_offset_t	off;
	ssize_t		len;
	caddr_t		va;
	int		err;

top:
	off = pp->p_offset;
	rl = zfs_range_lock(zp, off, PAGESIZE, RL_WRITER);
	/*
	 * Can't push pages past end-of-file.
	 */
	if (off >= zp->z_phys->zp_size) {
		zfs_range_unlock(rl);
		return (EIO);
	}
	len = MIN(PAGESIZE, zp->z_phys->zp_size - off);

	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_write(tx, zp->z_id, off, len);
	dmu_tx_hold_bonus(tx, zp->z_id);
	err = dmu_tx_assign(tx, zfsvfs->z_assign);
	if (err != 0) {
		zfs_range_unlock(rl);
		if (err == ERESTART && zfsvfs->z_assign == TXG_NOWAIT) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	va = ppmapin(pp, PROT_READ | PROT_WRITE, (caddr_t)-1);

	dmu_write(zfsvfs->z_os, zp->z_id, off, len, va, tx);

	ppmapout(va);

	zfs_time_stamper(zp, CONTENT_MODIFIED, tx);
	(void) zfs_log_write(zilog, tx, TX_WRITE, zp, off, len, 0, NULL);
	dmu_tx_commit(tx);

	zfs_range_unlock(rl);

	pvn_write_done(pp, B_WRITE | flags);
	if (offp)
		*offp = off;
	if (lenp)
		*lenp = len;

out:
	return (err);
}

/*
 * Copy the portion of the file indicated from pages into the file.
 * The pages are stored in a page list attached to the files vnode.
 *
 *	IN:	vp	- vnode of file to push page data to.
 *		off	- position in file to put data.
 *		len	- amount of data to write.
 *		flags	- flags to control the operation.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated
 */
static int
zfs_putpage(vnode_t *vp, offset_t off, size_t len, int flags, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	page_t		*pp;
	size_t		io_len;
	u_offset_t	io_off;
	uint64_t	filesz;
	int		error = 0;

	ZFS_ENTER(zfsvfs);

	ASSERT(zp->z_dbuf_held && zp->z_phys);

	if (len == 0) {
		/*
		 * Search the entire vp list for pages >= off.
		 */
		error = pvn_vplist_dirty(vp, (u_offset_t)off, zfs_putapage,
		    flags, cr);
		goto out;
	}

	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if (off > filesz) {
		/* past end of file */
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	len = MIN(len, filesz - off);

	for (io_off = off; io_off < off + len; io_off += io_len) {
		if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
			pp = page_lookup(vp, io_off,
				(flags & (B_INVAL | B_FREE)) ?
					SE_EXCL : SE_SHARED);
		} else {
			pp = page_lookup_nowait(vp, io_off,
				(flags & B_FREE) ? SE_EXCL : SE_SHARED);
		}

		if (pp != NULL && pvn_getdirty(pp, flags)) {
			int err;

			/*
			 * Found a dirty page to push
			 */
			err = zfs_putapage(vp, pp, &io_off, &io_len, flags, cr);
			if (err)
				error = err;
		} else {
			io_len = PAGESIZE;
		}
	}
out:
	zil_commit(zfsvfs->z_log, UINT64_MAX, (flags & B_ASYNC) ? 0 : FDSYNC);
	ZFS_EXIT(zfsvfs);
	return (error);
}

void
zfs_inactive(vnode_t *vp, cred_t *cr)
{
	znode_t	*zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	rw_enter(&zfsvfs->z_um_lock, RW_READER);
	if (zfsvfs->z_unmounted2) {
		ASSERT(zp->z_dbuf_held == 0);

		if (vn_has_cached_data(vp)) {
			(void) pvn_vplist_dirty(vp, 0, zfs_null_putapage,
			    B_INVAL, cr);
		}

		mutex_enter(&zp->z_lock);
		vp->v_count = 0; /* count arrives as 1 */
		if (zp->z_dbuf == NULL) {
			mutex_exit(&zp->z_lock);
			zfs_znode_free(zp);
		} else {
			mutex_exit(&zp->z_lock);
		}
		rw_exit(&zfsvfs->z_um_lock);
		VFS_RELE(zfsvfs->z_vfs);
		return;
	}

	/*
	 * Attempt to push any data in the page cache.  If this fails
	 * we will get kicked out later in zfs_zinactive().
	 */
	if (vn_has_cached_data(vp)) {
		(void) pvn_vplist_dirty(vp, 0, zfs_putapage, B_INVAL|B_ASYNC,
		    cr);
	}

	if (zp->z_atime_dirty && zp->z_reap == 0) {
		dmu_tx_t *tx = dmu_tx_create(zfsvfs->z_os);

		dmu_tx_hold_bonus(tx, zp->z_id);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
		} else {
			dmu_buf_will_dirty(zp->z_dbuf, tx);
			mutex_enter(&zp->z_lock);
			zp->z_atime_dirty = 0;
			mutex_exit(&zp->z_lock);
			dmu_tx_commit(tx);
		}
	}

	zfs_zinactive(zp);
	rw_exit(&zfsvfs->z_um_lock);
}

/*
 * Bounds-check the seek operation.
 *
 *	IN:	vp	- vnode seeking within
 *		ooff	- old file offset
 *		noffp	- pointer to new file offset
 *
 *	RETURN:	0 if success
 *		EINVAL if new offset invalid
 */
/* ARGSUSED */
static int
zfs_seek(vnode_t *vp, offset_t ooff, offset_t *noffp)
{
	if (vp->v_type == VDIR)
		return (0);
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/*
 * Pre-filter the generic locking function to trap attempts to place
 * a mandatory lock on a memory mapped file.
 */
static int
zfs_frlock(vnode_t *vp, int cmd, flock64_t *bfp, int flag, offset_t offset,
    flk_callback_t *flk_cbp, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);

	/*
	 * We are following the UFS semantics with respect to mapcnt
	 * here: If we see that the file is mapped already, then we will
	 * return an error, but we don't worry about races between this
	 * function and zfs_map().
	 */
	if (zp->z_mapcnt > 0 && MANDMODE((mode_t)zp->z_phys->zp_mode)) {
		ZFS_EXIT(zfsvfs);
		return (EAGAIN);
	}
	error = fs_frlock(vp, cmd, bfp, flag, offset, flk_cbp, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * If we can't find a page in the cache, we will create a new page
 * and fill it with file data.  For efficiency, we may try to fill
 * multiple pages at once (klustering).
 */
static int
zfs_fillpage(vnode_t *vp, u_offset_t off, struct seg *seg,
    caddr_t addr, page_t *pl[], size_t plsz, enum seg_rw rw)
{
	znode_t *zp = VTOZ(vp);
	page_t *pp, *cur_pp;
	objset_t *os = zp->z_zfsvfs->z_os;
	caddr_t va;
	u_offset_t io_off, total;
	uint64_t oid = zp->z_id;
	size_t io_len;
	uint64_t filesz;
	int err;

	/*
	 * If we are only asking for a single page don't bother klustering.
	 */
	filesz = zp->z_phys->zp_size; /* get consistent copy of zp_size */
	if (plsz == PAGESIZE || zp->z_blksz <= PAGESIZE || off > filesz) {
		io_off = off;
		io_len = PAGESIZE;
		pp = page_create_va(vp, io_off, io_len, PG_WAIT, seg, addr);
	} else {
		/*
		 * Try to fill a kluster of pages (a blocks worth).
		 */
		size_t klen;
		u_offset_t koff;

		if (!ISP2(zp->z_blksz)) {
			/* Only one block in the file. */
			klen = P2ROUNDUP((ulong_t)zp->z_blksz, PAGESIZE);
			koff = 0;
		} else {
			klen = plsz;
			koff = P2ALIGN(off, (u_offset_t)klen);
		}
		ASSERT(koff <= filesz);
		if (koff + klen > filesz)
			klen = P2ROUNDUP(filesz, (uint64_t)PAGESIZE) - koff;
		pp = pvn_read_kluster(vp, off, seg, addr, &io_off,
			    &io_len, koff, klen, 0);
	}
	if (pp == NULL) {
		/*
		 * Some other thread entered the page before us.
		 * Return to zfs_getpage to retry the lookup.
		 */
		*pl = NULL;
		return (0);
	}

	/*
	 * Fill the pages in the kluster.
	 */
	cur_pp = pp;
	for (total = io_off + io_len; io_off < total; io_off += PAGESIZE) {
		ASSERT(io_off == cur_pp->p_offset);
		va = ppmapin(cur_pp, PROT_READ | PROT_WRITE, (caddr_t)-1);
		err = dmu_read(os, oid, io_off, PAGESIZE, va);
		ppmapout(va);
		if (err) {
			/* On error, toss the entire kluster */
			pvn_read_done(pp, B_ERROR);
			return (err);
		}
		cur_pp = cur_pp->p_next;
	}
out:
	/*
	 * Fill in the page list array from the kluster.  If
	 * there are too many pages in the kluster, return
	 * as many pages as possible starting from the desired
	 * offset `off'.
	 * NOTE: the page list will always be null terminated.
	 */
	pvn_plist_init(pp, pl, plsz, off, io_len, rw);

	return (0);
}

/*
 * Return pointers to the pages for the file region [off, off + len]
 * in the pl array.  If plsz is greater than len, this function may
 * also return page pointers from before or after the specified
 * region (i.e. some region [off', off' + plsz]).  These additional
 * pages are only returned if they are already in the cache, or were
 * created as part of a klustered read.
 *
 *	IN:	vp	- vnode of file to get data from.
 *		off	- position in file to get data from.
 *		len	- amount of data to retrieve.
 *		plsz	- length of provided page list.
 *		seg	- segment to obtain pages for.
 *		addr	- virtual address of fault.
 *		rw	- mode of created pages.
 *		cr	- credentials of caller.
 *
 *	OUT:	protp	- protection mode of created pages.
 *		pl	- list of pages created.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
static int
zfs_getpage(vnode_t *vp, offset_t off, size_t len, uint_t *protp,
	page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
	enum seg_rw rw, cred_t *cr)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	page_t		*pp, **pl0 = pl;
	rl_t		*rl;
	int		cnt = 0, need_unlock = 0, err = 0;

	ZFS_ENTER(zfsvfs);

	if (protp)
		*protp = PROT_ALL;

	ASSERT(zp->z_dbuf_held && zp->z_phys);

	/* no faultahead (for now) */
	if (pl == NULL) {
		ZFS_EXIT(zfsvfs);
		return (0);
	}

	/*
	 * Make sure nobody restructures the file in the middle of the getpage.
	 */
	rl = zfs_range_lock(zp, off, len, RL_READER);

	/* can't fault past EOF */
	if (off >= zp->z_phys->zp_size) {
		zfs_range_unlock(rl);
		ZFS_EXIT(zfsvfs);
		return (EFAULT);
	}

	/*
	 * If we already own the lock, then we must be page faulting
	 * in the middle of a write to this file (i.e., we are writing
	 * to this file using data from a mapped region of the file).
	 */
	if (!rw_owner(&zp->z_map_lock)) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}

	/*
	 * Loop through the requested range [off, off + len] looking
	 * for pages.  If we don't find a page, we will need to create
	 * a new page and fill it with data from the file.
	 */
	while (len > 0) {
		if (plsz < PAGESIZE)
			break;
		if (pp = page_lookup(vp, off, SE_SHARED)) {
			*pl++ = pp;
			off += PAGESIZE;
			addr += PAGESIZE;
			len -= PAGESIZE;
			plsz -= PAGESIZE;
		} else {
			err = zfs_fillpage(vp, off, seg, addr, pl, plsz, rw);
			/*
			 * klustering may have changed our region
			 * to be block aligned.
			 */
			if (((pp = *pl) != 0) && (off != pp->p_offset)) {
				int delta = off - pp->p_offset;
				len += delta;
				off -= delta;
				addr -= delta;
			}
			while (*pl) {
				pl++;
				cnt++;
				off += PAGESIZE;
				addr += PAGESIZE;
				plsz -= PAGESIZE;
				if (len > PAGESIZE)
					len -= PAGESIZE;
				else
					len = 0;
			}
			if (err) {
				/*
				 * Release any pages we have locked.
				 */
				while (pl > pl0)
					page_unlock(*--pl);
				goto out;
			}
		}
	}

	/*
	 * Fill out the page array with any pages already in the cache.
	 */
	while (plsz > 0) {
		pp = page_lookup_nowait(vp, off, SE_SHARED);
		if (pp == NULL)
			break;
		*pl++ = pp;
		off += PAGESIZE;
		plsz -= PAGESIZE;
	}

	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);
out:
	*pl = NULL;

	if (need_unlock)
		rw_exit(&zp->z_map_lock);
	zfs_range_unlock(rl);

	ZFS_EXIT(zfsvfs);
	return (err);
}

/*
 * Request a memory map for a section of a file.  This code interacts
 * with common code and the VM system as follows:
 *
 *	common code calls mmap(), which ends up in smmap_common()
 *
 *	this calls VOP_MAP(), which takes you into (say) zfs
 *
 *	zfs_map() calls as_map(), passing segvn_create() as the callback
 *
 *	segvn_create() creates the new segment and calls VOP_ADDMAP()
 *
 *	zfs_addmap() updates z_mapcnt
 */
static int
zfs_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	segvn_crargs_t	vn_a;
	int		error;

	ZFS_ENTER(zfsvfs);

	if (vp->v_flag & VNOMAP) {
		ZFS_EXIT(zfsvfs);
		return (ENOSYS);
	}

	if (off < 0 || len > MAXOFFSET_T - off) {
		ZFS_EXIT(zfsvfs);
		return (ENXIO);
	}

	if (vp->v_type != VREG) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}

	/*
	 * If file is locked, disallow mapping.
	 */
	if (MANDMODE((mode_t)zp->z_phys->zp_mode) && vn_has_flocks(vp)) {
		ZFS_EXIT(zfsvfs);
		return (EAGAIN);
	}

	as_rangelock(as);
	if ((flags & MAP_FIXED) == 0) {
		map_addr(addrp, len, off, 1, flags);
		if (*addrp == NULL) {
			as_rangeunlock(as);
			ZFS_EXIT(zfsvfs);
			return (ENOMEM);
		}
	} else {
		/*
		 * User specified address - blow away any previous mappings
		 */
		(void) as_unmap(as, *addrp, len);
	}

	vn_a.vp = vp;
	vn_a.offset = (u_offset_t)off;
	vn_a.type = flags & MAP_TYPE;
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = flags & ~MAP_TYPE;
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);

	as_rangeunlock(as);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/* ARGSUSED */
static int
zfs_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags, cred_t *cr)
{
	uint64_t pages = btopr(len);

	atomic_add_64(&VTOZ(vp)->z_mapcnt, pages);
	return (0);
}

/*
 * The reason we push dirty pages as part of zfs_delmap() is so that we get a
 * more accurate mtime for the associated file.  Since we don't have a way of
 * detecting when the data was actually modified, we have to resort to
 * heuristics.  If an explicit msync() is done, then we mark the mtime when the
 * last page is pushed.  The problem occurs when the msync() call is omitted,
 * which by far the most common case:
 *
 * 	open()
 * 	mmap()
 * 	<modify memory>
 * 	munmap()
 * 	close()
 * 	<time lapse>
 * 	putpage() via fsflush
 *
 * If we wait until fsflush to come along, we can have a modification time that
 * is some arbitrary point in the future.  In order to prevent this in the
 * common case, we flush pages whenever a (MAP_SHARED, PROT_WRITE) mapping is
 * torn down.
 */
/* ARGSUSED */
static int
zfs_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr)
{
	uint64_t pages = btopr(len);

	ASSERT3U(VTOZ(vp)->z_mapcnt, >=, pages);
	atomic_add_64(&VTOZ(vp)->z_mapcnt, -pages);

	if ((flags & MAP_SHARED) && (prot & PROT_WRITE) &&
	    vn_has_cached_data(vp))
		(void) VOP_PUTPAGE(vp, off, len, B_ASYNC, cr);

	return (0);
}

/*
 * Free or allocate space in a file.  Currently, this function only
 * supports the `F_FREESP' command.  However, this command is somewhat
 * misnamed, as its functionality includes the ability to allocate as
 * well as free space.
 *
 *	IN:	vp	- vnode of file to free data in.
 *		cmd	- action to take (only F_FREESP supported).
 *		bfp	- section of file to free/alloc.
 *		flag	- current file open mode flags.
 *		offset	- current file offset.
 *		cr	- credentials of caller [UNUSED].
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - ctime|mtime updated
 */
/* ARGSUSED */
static int
zfs_space(vnode_t *vp, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint64_t	off, len;
	int		error;

	ZFS_ENTER(zfsvfs);

top:
	if (cmd != F_FREESP) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	if (error = convoff(vp, bfp, 0, offset)) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	if (bfp->l_len < 0) {
		ZFS_EXIT(zfsvfs);
		return (EINVAL);
	}

	off = bfp->l_start;
	len = bfp->l_len; /* 0 means from off to end of file */

	do {
		error = zfs_freesp(zp, off, len, flag, TRUE);
		/* NB: we already did dmu_tx_wait() if necessary */
	} while (error == ERESTART && zfsvfs->z_assign == TXG_NOWAIT);

	ZFS_EXIT(zfsvfs);
	return (error);
}

static int
zfs_fid(vnode_t *vp, fid_t *fidp)
{
	znode_t		*zp = VTOZ(vp);
	zfsvfs_t	*zfsvfs = zp->z_zfsvfs;
	uint32_t	gen = (uint32_t)zp->z_phys->zp_gen;
	uint64_t	object = zp->z_id;
	zfid_short_t	*zfid;
	int		size, i;

	ZFS_ENTER(zfsvfs);

	size = (zfsvfs->z_parent != zfsvfs) ? LONG_FID_LEN : SHORT_FID_LEN;
	if (fidp->fid_len < size) {
		fidp->fid_len = size;
		ZFS_EXIT(zfsvfs);
		return (ENOSPC);
	}

	zfid = (zfid_short_t *)fidp;

	zfid->zf_len = size;

	for (i = 0; i < sizeof (zfid->zf_object); i++)
		zfid->zf_object[i] = (uint8_t)(object >> (8 * i));

	/* Must have a non-zero generation number to distinguish from .zfs */
	if (gen == 0)
		gen = 1;
	for (i = 0; i < sizeof (zfid->zf_gen); i++)
		zfid->zf_gen[i] = (uint8_t)(gen >> (8 * i));

	if (size == LONG_FID_LEN) {
		uint64_t	objsetid = dmu_objset_id(zfsvfs->z_os);
		zfid_long_t	*zlfid;

		zlfid = (zfid_long_t *)fidp;

		for (i = 0; i < sizeof (zlfid->zf_setid); i++)
			zlfid->zf_setid[i] = (uint8_t)(objsetid >> (8 * i));

		/* XXX - this should be the generation number for the objset */
		for (i = 0; i < sizeof (zlfid->zf_setgen); i++)
			zlfid->zf_setgen[i] = 0;
	}

	ZFS_EXIT(zfsvfs);
	return (0);
}

static int
zfs_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr)
{
	znode_t		*zp, *xzp;
	zfsvfs_t	*zfsvfs;
	zfs_dirlock_t	*dl;
	int		error;

	switch (cmd) {
	case _PC_LINK_MAX:
		*valp = ULONG_MAX;
		return (0);

	case _PC_FILESIZEBITS:
		*valp = 64;
		return (0);

	case _PC_XATTR_EXISTS:
		zp = VTOZ(vp);
		zfsvfs = zp->z_zfsvfs;
		ZFS_ENTER(zfsvfs);
		*valp = 0;
		error = zfs_dirent_lock(&dl, zp, "", &xzp,
		    ZXATTR | ZEXISTS | ZSHARED);
		if (error == 0) {
			zfs_dirent_unlock(dl);
			if (!zfs_dirempty(xzp))
				*valp = 1;
			VN_RELE(ZTOV(xzp));
		} else if (error == ENOENT) {
			/*
			 * If there aren't extended attributes, it's the
			 * same as having zero of them.
			 */
			error = 0;
		}
		ZFS_EXIT(zfsvfs);
		return (error);

	case _PC_ACL_ENABLED:
		*valp = _ACL_ACE_ENABLED;
		return (0);

	case _PC_MIN_HOLE_SIZE:
		*valp = (ulong_t)SPA_MINBLOCKSIZE;
		return (0);

	default:
		return (fs_pathconf(vp, cmd, valp, cr));
	}
}

/*ARGSUSED*/
static int
zfs_getsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	error = zfs_getacl(zp, vsecp, cr);
	ZFS_EXIT(zfsvfs);

	return (error);
}

/*ARGSUSED*/
static int
zfs_setsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;

	ZFS_ENTER(zfsvfs);
	error = zfs_setacl(zp, vsecp, cr);
	ZFS_EXIT(zfsvfs);
	return (error);
}

/*
 * Predeclare these here so that the compiler assumes that
 * this is an "old style" function declaration that does
 * not include arguments => we won't get type mismatch errors
 * in the initializations that follow.
 */
static int zfs_inval();
static int zfs_isdir();

static int
zfs_inval()
{
	return (EINVAL);
}

static int
zfs_isdir()
{
	return (EISDIR);
}
/*
 * Directory vnode operations template
 */
vnodeops_t *zfs_dvnodeops;
const fs_operation_def_t zfs_dvnodeops_template[] = {
	VOPNAME_OPEN, zfs_open,
	VOPNAME_CLOSE, zfs_close,
	VOPNAME_READ, zfs_isdir,
	VOPNAME_WRITE, zfs_isdir,
	VOPNAME_IOCTL, zfs_ioctl,
	VOPNAME_GETATTR, zfs_getattr,
	VOPNAME_SETATTR, zfs_setattr,
	VOPNAME_ACCESS, zfs_access,
	VOPNAME_LOOKUP, zfs_lookup,
	VOPNAME_CREATE, zfs_create,
	VOPNAME_REMOVE, zfs_remove,
	VOPNAME_LINK, zfs_link,
	VOPNAME_RENAME, zfs_rename,
	VOPNAME_MKDIR, zfs_mkdir,
	VOPNAME_RMDIR, zfs_rmdir,
	VOPNAME_READDIR, zfs_readdir,
	VOPNAME_SYMLINK, zfs_symlink,
	VOPNAME_FSYNC, zfs_fsync,
	VOPNAME_INACTIVE, (fs_generic_func_p) zfs_inactive,
	VOPNAME_FID, zfs_fid,
	VOPNAME_SEEK, zfs_seek,
	VOPNAME_PATHCONF, zfs_pathconf,
	VOPNAME_GETSECATTR, zfs_getsecattr,
	VOPNAME_SETSECATTR, zfs_setsecattr,
	NULL, NULL
};

/*
 * Regular file vnode operations template
 */
vnodeops_t *zfs_fvnodeops;
const fs_operation_def_t zfs_fvnodeops_template[] = {
	VOPNAME_OPEN, zfs_open,
	VOPNAME_CLOSE, zfs_close,
	VOPNAME_READ, zfs_read,
	VOPNAME_WRITE, zfs_write,
	VOPNAME_IOCTL, zfs_ioctl,
	VOPNAME_GETATTR, zfs_getattr,
	VOPNAME_SETATTR, zfs_setattr,
	VOPNAME_ACCESS, zfs_access,
	VOPNAME_LOOKUP, zfs_lookup,
	VOPNAME_RENAME, zfs_rename,
	VOPNAME_FSYNC, zfs_fsync,
	VOPNAME_INACTIVE, (fs_generic_func_p)zfs_inactive,
	VOPNAME_FID, zfs_fid,
	VOPNAME_SEEK, zfs_seek,
	VOPNAME_FRLOCK, zfs_frlock,
	VOPNAME_SPACE, zfs_space,
	VOPNAME_GETPAGE, zfs_getpage,
	VOPNAME_PUTPAGE, zfs_putpage,
	VOPNAME_MAP, (fs_generic_func_p) zfs_map,
	VOPNAME_ADDMAP, (fs_generic_func_p) zfs_addmap,
	VOPNAME_DELMAP, zfs_delmap,
	VOPNAME_PATHCONF, zfs_pathconf,
	VOPNAME_GETSECATTR, zfs_getsecattr,
	VOPNAME_SETSECATTR, zfs_setsecattr,
	VOPNAME_VNEVENT, fs_vnevent_support,
	NULL, NULL
};

/*
 * Symbolic link vnode operations template
 */
vnodeops_t *zfs_symvnodeops;
const fs_operation_def_t zfs_symvnodeops_template[] = {
	VOPNAME_GETATTR, zfs_getattr,
	VOPNAME_SETATTR, zfs_setattr,
	VOPNAME_ACCESS, zfs_access,
	VOPNAME_RENAME, zfs_rename,
	VOPNAME_READLINK, zfs_readlink,
	VOPNAME_INACTIVE, (fs_generic_func_p) zfs_inactive,
	VOPNAME_FID, zfs_fid,
	VOPNAME_PATHCONF, zfs_pathconf,
	VOPNAME_VNEVENT, fs_vnevent_support,
	NULL, NULL
};

/*
 * Extended attribute directory vnode operations template
 *	This template is identical to the directory vnodes
 *	operation template except for restricted operations:
 *		VOP_MKDIR()
 *		VOP_SYMLINK()
 * Note that there are other restrictions embedded in:
 *	zfs_create()	- restrict type to VREG
 *	zfs_link()	- no links into/out of attribute space
 *	zfs_rename()	- no moves into/out of attribute space
 */
vnodeops_t *zfs_xdvnodeops;
const fs_operation_def_t zfs_xdvnodeops_template[] = {
	VOPNAME_OPEN, zfs_open,
	VOPNAME_CLOSE, zfs_close,
	VOPNAME_IOCTL, zfs_ioctl,
	VOPNAME_GETATTR, zfs_getattr,
	VOPNAME_SETATTR, zfs_setattr,
	VOPNAME_ACCESS, zfs_access,
	VOPNAME_LOOKUP, zfs_lookup,
	VOPNAME_CREATE, zfs_create,
	VOPNAME_REMOVE, zfs_remove,
	VOPNAME_LINK, zfs_link,
	VOPNAME_RENAME, zfs_rename,
	VOPNAME_MKDIR, zfs_inval,
	VOPNAME_RMDIR, zfs_rmdir,
	VOPNAME_READDIR, zfs_readdir,
	VOPNAME_SYMLINK, zfs_inval,
	VOPNAME_FSYNC, zfs_fsync,
	VOPNAME_INACTIVE, (fs_generic_func_p) zfs_inactive,
	VOPNAME_FID, zfs_fid,
	VOPNAME_SEEK, zfs_seek,
	VOPNAME_PATHCONF, zfs_pathconf,
	VOPNAME_GETSECATTR, zfs_getsecattr,
	VOPNAME_SETSECATTR, zfs_setsecattr,
	VOPNAME_VNEVENT, fs_vnevent_support,
	NULL, NULL
};

/*
 * Error vnode operations template
 */
vnodeops_t *zfs_evnodeops;
const fs_operation_def_t zfs_evnodeops_template[] = {
	VOPNAME_INACTIVE, (fs_generic_func_p) zfs_inactive,
	VOPNAME_PATHCONF, zfs_pathconf,
	NULL, NULL
};
