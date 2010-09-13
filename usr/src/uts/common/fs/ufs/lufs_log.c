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

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/fssnap_if.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_log.h>
#include <sys/fs/ufs_bio.h>
#include <sys/atomic.h>

extern int		maxphys;
extern uint_t		bypass_snapshot_throttle_key;

extern struct kmem_cache	*lufs_sv;
extern struct kmem_cache	*lufs_bp;

static void
makebusy(ml_unit_t *ul, buf_t *bp)
{
	sema_p(&bp->b_sem);
	if ((bp->b_flags & B_ERROR) == 0)
		return;
	if (bp->b_flags & B_READ)
		ldl_seterror(ul, "Error reading ufs log");
	else
		ldl_seterror(ul, "Error writing ufs log");
}

static int
logdone(buf_t *bp)
{
	bp->b_flags |= B_DONE;

	if (bp->b_flags & B_WRITE)
		sema_v(&bp->b_sem);
	else
		/* wakeup the thread waiting on this buf */
		sema_v(&bp->b_io);
	return (0);
}

static int
ldl_strategy_done(buf_t *cb)
{
	lufs_save_t	*sv;
	lufs_buf_t	*lbp;
	buf_t		*bp;

	ASSERT(SEMA_HELD(&cb->b_sem));
	ASSERT((cb->b_flags & B_DONE) == 0);

	/*
	 * Compute address of the ``save'' struct
	 */
	lbp = (lufs_buf_t *)cb;
	sv = (lufs_save_t *)lbp->lb_ptr;

	if (cb->b_flags & B_ERROR)
		sv->sv_error = 1;

	/*
	 * If this is the last request, release the resources and
	 * ``done'' the original buffer header.
	 */
	if (atomic_add_long_nv(&sv->sv_nb_left, -cb->b_bcount)) {
		kmem_cache_free(lufs_bp, lbp);
		return (1);
	}
	/* Propagate any errors back to the original buffer header */
	bp = sv->sv_bp;
	if (sv->sv_error)
		bp->b_flags |= B_ERROR;
	kmem_cache_free(lufs_bp, lbp);
	kmem_cache_free(lufs_sv, sv);

	biodone(bp);
	return (0);
}

/*
 * Map the log logical block number to a physical disk block number
 */
static int
map_frag(
	ml_unit_t	*ul,
	daddr_t		lblkno,
	size_t		bcount,
	daddr_t		*pblkno,
	size_t		*pbcount)
{
	ic_extent_t	*ext = ul->un_ebp->ic_extents;
	uint32_t	e = ul->un_ebp->ic_nextents;
	uint32_t	s = 0;
	uint32_t	i = e >> 1;
	uint32_t	lasti = i;
	uint32_t	bno_off;

again:
	if (ext[i].ic_lbno <= lblkno) {
		if ((ext[i].ic_lbno + ext[i].ic_nbno) > lblkno) {
			/* FOUND IT */
			bno_off = lblkno - (uint32_t)ext[i].ic_lbno;
			*pbcount = MIN(bcount, dbtob(ext[i].ic_nbno - bno_off));
			*pblkno = ext[i].ic_pbno + bno_off;
			return (0);
		} else
			s = i;
	} else
		e = i;
	i = s + ((e - s) >> 1);

	if (i == lasti) {
		*pbcount = bcount;
		return (ENOENT);
	}
	lasti = i;

	goto again;
}

/*
 * The log is a set of extents (which typically will be only one, but
 * may be more if the disk was close to full when the log was created)
 * and hence the logical offsets into the log
 * have to be translated into their real device locations before
 * calling the device's strategy routine. The translation may result
 * in several IO requests if this request spans extents.
 */
void
ldl_strategy(ml_unit_t *ul, buf_t *pb)
{
	lufs_save_t	*sv;
	lufs_buf_t	*lbp;
	buf_t		*cb;
	ufsvfs_t	*ufsvfsp = ul->un_ufsvfs;
	daddr_t		lblkno, pblkno;
	size_t		nb_left, pbcount;
	off_t		offset;
	dev_t		dev	= ul->un_dev;
	int		error;
	int		read = pb->b_flags & B_READ;

	/*
	 * Allocate and initialise the save stucture,
	 */
	sv = kmem_cache_alloc(lufs_sv, KM_SLEEP);
	sv->sv_error = 0;
	sv->sv_bp = pb;
	nb_left = pb->b_bcount;
	sv->sv_nb_left = nb_left;

	lblkno = pb->b_blkno;
	offset = 0;

	do {
		error = map_frag(ul, lblkno, nb_left, &pblkno, &pbcount);

		lbp = kmem_cache_alloc(lufs_bp, KM_SLEEP);
		bioinit(&lbp->lb_buf);
		lbp->lb_ptr = sv;

		cb = bioclone(pb, offset, pbcount, dev,
		    pblkno, ldl_strategy_done, &lbp->lb_buf, KM_SLEEP);

		offset += pbcount;
		lblkno += btodb(pbcount);
		nb_left -= pbcount;

		if (error) {
			cb->b_flags |= B_ERROR;
			cb->b_resid = cb->b_bcount;
			biodone(cb);
		} else {
			if (read) {
				logstats.ls_ldlreads.value.ui64++;
				ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
				lwp_stat_update(LWP_STAT_INBLK, 1);
			} else {
				logstats.ls_ldlwrites.value.ui64++;
				lwp_stat_update(LWP_STAT_OUBLK, 1);
			}

			/*
			 * write through the snapshot driver if necessary
			 * We do not want this write to be throttled because
			 * we are holding the un_log mutex here. If we
			 * are throttled in fssnap_translate, the fssnap_taskq
			 * thread which can wake us up can get blocked on
			 * the un_log mutex resulting in a deadlock.
			 */
			if (ufsvfsp->vfs_snapshot) {
				(void) tsd_set(bypass_snapshot_throttle_key,
				    (void *)1);
				fssnap_strategy(&ufsvfsp->vfs_snapshot, cb);

				(void) tsd_set(bypass_snapshot_throttle_key,
				    (void *)0);
			} else {
				(void) bdev_strategy(cb);
			}
		}

	} while (nb_left);
}

static void
writelog(ml_unit_t *ul, buf_t *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));

	/*
	 * This is really an B_ASYNC write but we want Presto to
	 * cache this write.  The iodone routine, logdone, processes
	 * the buf correctly.
	 */
	bp->b_flags = B_WRITE;
	bp->b_edev = ul->un_dev;
	bp->b_iodone = logdone;

	/*
	 * return EIO for every IO if in hard error state
	 */
	if (ul->un_flags & LDL_ERROR) {
		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
		biodone(bp);
		return;
	}

	ldl_strategy(ul, bp);
}

static void
readlog(ml_unit_t *ul, buf_t *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	ASSERT(bp->b_bcount);

	bp->b_flags = B_READ;
	bp->b_edev = ul->un_dev;
	bp->b_iodone = logdone;

	/* all IO returns errors when in error state */
	if (ul->un_flags & LDL_ERROR) {
		bp->b_flags |= B_ERROR;
		bp->b_error = EIO;
		biodone(bp);
		(void) trans_wait(bp);
		return;
	}

	ldl_strategy(ul, bp);

	if (trans_wait(bp))
		ldl_seterror(ul, "Error reading ufs log");
}

/*
 * NOTE: writers are single threaded thru the log layer.
 * This means we can safely reference and change the cb and bp fields
 * that ldl_read does not reference w/o holding the cb_rwlock or
 * the bp makebusy lock.
 */
static void
push_dirty_bp(ml_unit_t *ul, buf_t *bp)
{
	buf_t		*newbp;
	cirbuf_t	*cb		= &ul->un_wrbuf;

	ASSERT(bp == cb->cb_bp && bp == cb->cb_dirty);
	ASSERT((bp->b_bcount & (DEV_BSIZE-1)) == 0);

	/*
	 * async write the buf
	 */
	writelog(ul, bp);

	/*
	 * no longer filling any buf
	 */
	cb->cb_dirty = NULL;

	/*
	 * no extra buffer space; all done
	 */
	if (bp->b_bcount == bp->b_bufsize)
		return;

	/*
	 * give extra buffer space to a new bp
	 * 	try to take buf off of free list
	 */
	if ((newbp = cb->cb_free) != NULL) {
		cb->cb_free = newbp->b_forw;
	} else {
		newbp = kmem_zalloc(sizeof (buf_t), KM_SLEEP);
		sema_init(&newbp->b_sem, 1, NULL, SEMA_DEFAULT, NULL);
		sema_init(&newbp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
	}
	newbp->b_flags = 0;
	newbp->b_bcount = 0;
	newbp->b_file = NULL;
	newbp->b_offset = -1;
	newbp->b_bufsize = bp->b_bufsize - bp->b_bcount;
	newbp->b_un.b_addr = bp->b_un.b_addr + bp->b_bcount;
	bp->b_bufsize = bp->b_bcount;

	/*
	 * lock out readers and put new buf at LRU position
	 */
	rw_enter(&cb->cb_rwlock, RW_WRITER);
	newbp->b_forw = bp->b_forw;
	newbp->b_back = bp;
	bp->b_forw->b_back = newbp;
	bp->b_forw = newbp;
	rw_exit(&cb->cb_rwlock);
}

static void
inval_range(ml_unit_t *ul, cirbuf_t *cb, off_t lof, off_t nb)
{
	buf_t		*bp;
	off_t		elof	= lof + nb;
	off_t		buflof;
	off_t		bufelof;

	/*
	 * discard all bufs that overlap the range (lof, lof + nb)
	 */
	rw_enter(&cb->cb_rwlock, RW_WRITER);
	bp = cb->cb_bp;
	do {
		if (bp == cb->cb_dirty || bp->b_bcount == 0) {
			bp = bp->b_forw;
			continue;
		}
		buflof = dbtob(bp->b_blkno);
		bufelof = buflof + bp->b_bcount;
		if ((buflof < lof && bufelof <= lof) ||
		    (buflof >= elof && bufelof > elof)) {
			bp = bp->b_forw;
			continue;
		}
		makebusy(ul, bp);
		bp->b_flags = 0;
		bp->b_bcount = 0;
		sema_v(&bp->b_sem);
		bp = bp->b_forw;
	} while (bp != cb->cb_bp);
	rw_exit(&cb->cb_rwlock);
}

/*
 * NOTE: writers are single threaded thru the log layer.
 * This means we can safely reference and change the cb and bp fields
 * that ldl_read does not reference w/o holding the cb_rwlock or
 * the bp makebusy lock.
 */
static buf_t *
get_write_bp(ml_unit_t *ul)
{
	cirbuf_t	*cb = &ul->un_wrbuf;
	buf_t		*bp;

	/*
	 * cb_dirty is the buffer we are currently filling; if any
	 */
	if ((bp = cb->cb_dirty) != NULL) {
		makebusy(ul, bp);
		return (bp);
	}
	/*
	 * discard any bp that overlaps the current tail since we are
	 * about to overwrite it.
	 */
	inval_range(ul, cb, ul->un_tail_lof, 1);

	/*
	 * steal LRU buf
	 */
	rw_enter(&cb->cb_rwlock, RW_WRITER);
	bp = cb->cb_bp->b_forw;
	makebusy(ul, bp);

	cb->cb_dirty = bp;
	cb->cb_bp = bp;

	bp->b_flags = 0;
	bp->b_bcount = 0;
	bp->b_blkno = btodb(ul->un_tail_lof);
	ASSERT(dbtob(bp->b_blkno) == ul->un_tail_lof);
	rw_exit(&cb->cb_rwlock);

	/*
	 * NOTE:
	 *	1. un_tail_lof never addresses >= un_eol_lof
	 *	2. b_blkno + btodb(b_bufsize) may > un_eol_lof
	 *		this case is handled in storebuf
	 */
	return (bp);
}

void
alloc_wrbuf(cirbuf_t *cb, size_t bufsize)
{
	int	i;
	buf_t	*bp;

	/*
	 * Clear previous allocation
	 */
	if (cb->cb_nb)
		free_cirbuf(cb);

	bzero(cb, sizeof (*cb));
	rw_init(&cb->cb_rwlock, NULL, RW_DRIVER, NULL);

	rw_enter(&cb->cb_rwlock, RW_WRITER);

	/*
	 * preallocate 3 bp's and put them on the free list.
	 */
	for (i = 0; i < 3; ++i) {
		bp = kmem_zalloc(sizeof (buf_t), KM_SLEEP);
		sema_init(&bp->b_sem, 1, NULL, SEMA_DEFAULT, NULL);
		sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
		bp->b_offset = -1;
		bp->b_forw = cb->cb_free;
		cb->cb_free = bp;
	}

	cb->cb_va = kmem_alloc(bufsize, KM_SLEEP);
	cb->cb_nb = bufsize;

	/*
	 * first bp claims entire write buffer
	 */
	bp = cb->cb_free;
	cb->cb_free = bp->b_forw;

	bp->b_forw = bp;
	bp->b_back = bp;
	cb->cb_bp = bp;
	bp->b_un.b_addr = cb->cb_va;
	bp->b_bufsize = cb->cb_nb;

	rw_exit(&cb->cb_rwlock);
}

void
alloc_rdbuf(cirbuf_t *cb, size_t bufsize, size_t blksize)
{
	caddr_t	va;
	size_t	nb;
	buf_t	*bp;

	/*
	 * Clear previous allocation
	 */
	if (cb->cb_nb)
		free_cirbuf(cb);

	bzero(cb, sizeof (*cb));
	rw_init(&cb->cb_rwlock, NULL, RW_DRIVER, NULL);

	rw_enter(&cb->cb_rwlock, RW_WRITER);

	cb->cb_va = kmem_alloc(bufsize, KM_SLEEP);
	cb->cb_nb = bufsize;

	/*
	 * preallocate N bufs that are hard-sized to blksize
	 *	in other words, the read buffer pool is a linked list
	 *	of statically sized bufs.
	 */
	va = cb->cb_va;
	while ((nb = bufsize) != 0) {
		if (nb > blksize)
			nb = blksize;
		bp = kmem_alloc(sizeof (buf_t), KM_SLEEP);
		bzero(bp, sizeof (buf_t));
		sema_init(&bp->b_sem, 1, NULL, SEMA_DEFAULT, NULL);
		sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
		bp->b_un.b_addr = va;
		bp->b_bufsize = nb;
		if (cb->cb_bp) {
			bp->b_forw = cb->cb_bp->b_forw;
			bp->b_back = cb->cb_bp;
			cb->cb_bp->b_forw->b_back = bp;
			cb->cb_bp->b_forw = bp;
		} else
			bp->b_forw = bp->b_back = bp;
		cb->cb_bp = bp;
		bufsize -= nb;
		va += nb;
	}

	rw_exit(&cb->cb_rwlock);
}

void
free_cirbuf(cirbuf_t *cb)
{
	buf_t	*bp;

	if (cb->cb_nb == 0)
		return;

	rw_enter(&cb->cb_rwlock, RW_WRITER);
	ASSERT(cb->cb_dirty == NULL);

	/*
	 * free the active bufs
	 */
	while ((bp = cb->cb_bp) != NULL) {
		if (bp == bp->b_forw)
			cb->cb_bp = NULL;
		else
			cb->cb_bp = bp->b_forw;
		bp->b_back->b_forw = bp->b_forw;
		bp->b_forw->b_back = bp->b_back;
		sema_destroy(&bp->b_sem);
		sema_destroy(&bp->b_io);
		kmem_free(bp, sizeof (buf_t));
	}

	/*
	 * free the free bufs
	 */
	while ((bp = cb->cb_free) != NULL) {
		cb->cb_free = bp->b_forw;
		sema_destroy(&bp->b_sem);
		sema_destroy(&bp->b_io);
		kmem_free(bp, sizeof (buf_t));
	}
	kmem_free(cb->cb_va, cb->cb_nb);
	cb->cb_va = NULL;
	cb->cb_nb = 0;
	rw_exit(&cb->cb_rwlock);
	rw_destroy(&cb->cb_rwlock);
}

static int
within_range(off_t lof, daddr_t blkno, ulong_t bcount)
{
	off_t	blof	= dbtob(blkno);

	return ((lof >= blof) && (lof < (blof + bcount)));
}

static buf_t *
find_bp(ml_unit_t *ul, cirbuf_t *cb, off_t lof)
{
	buf_t *bp;

	/*
	 * find a buf that contains the offset lof
	 */
	rw_enter(&cb->cb_rwlock, RW_READER);
	bp = cb->cb_bp;
	do {
		if (bp->b_bcount &&
		    within_range(lof, bp->b_blkno, bp->b_bcount)) {
			makebusy(ul, bp);
			rw_exit(&cb->cb_rwlock);
			return (bp);
		}
		bp = bp->b_forw;
	} while (bp != cb->cb_bp);
	rw_exit(&cb->cb_rwlock);

	return (NULL);
}

static off_t
find_read_lof(ml_unit_t *ul, cirbuf_t *cb, off_t lof)
{
	buf_t	*bp, *bpend;
	off_t	rlof;

	/*
	 * we mustn't:
	 *	o read past eol
	 *	o read past the tail
	 *	o read data that may be being written.
	 */
	rw_enter(&cb->cb_rwlock, RW_READER);
	bpend = bp = cb->cb_bp->b_forw;
	rlof = ul->un_tail_lof;
	do {
		if (bp->b_bcount) {
			rlof = dbtob(bp->b_blkno);
			break;
		}
		bp = bp->b_forw;
	} while (bp != bpend);
	rw_exit(&cb->cb_rwlock);

	if (lof <= rlof)
		/* lof is prior to the range represented by the write buf */
		return (rlof);
	else
		/* lof follows the range represented by the write buf */
		return ((off_t)ul->un_eol_lof);
}

static buf_t *
get_read_bp(ml_unit_t *ul, off_t lof)
{
	cirbuf_t	*cb;
	buf_t		*bp;
	off_t		rlof;

	/*
	 * retrieve as much data as possible from the incore buffers
	 */
	if ((bp = find_bp(ul, &ul->un_wrbuf, lof)) != NULL) {
		logstats.ls_lreadsinmem.value.ui64++;
		return (bp);
	}
	if ((bp = find_bp(ul, &ul->un_rdbuf, lof)) != NULL) {
		logstats.ls_lreadsinmem.value.ui64++;
		return (bp);
	}

	/*
	 * steal the LRU buf
	 */
	cb = &ul->un_rdbuf;
	rw_enter(&cb->cb_rwlock, RW_WRITER);
	bp = cb->cb_bp->b_forw;
	makebusy(ul, bp);
	bp->b_flags = 0;
	bp->b_bcount = 0;
	cb->cb_bp = bp;
	rw_exit(&cb->cb_rwlock);

	/*
	 * don't read past the tail or the end-of-log
	 */
	bp->b_blkno = btodb(lof);
	lof = dbtob(bp->b_blkno);
	rlof = find_read_lof(ul, &ul->un_wrbuf, lof);
	bp->b_bcount = MIN(bp->b_bufsize, rlof - lof);
	readlog(ul, bp);
	return (bp);
}

/*
 * NOTE: writers are single threaded thru the log layer.
 * This means we can safely reference and change the cb and bp fields
 * that ldl_read does not reference w/o holding the cb_rwlock or
 * the bp makebusy lock.
 */
static int
extend_write_bp(ml_unit_t *ul, cirbuf_t *cb, buf_t *bp)
{
	buf_t	*bpforw	= bp->b_forw;

	ASSERT(bp == cb->cb_bp && bp == cb->cb_dirty);

	/*
	 * there is no `next' bp; do nothing
	 */
	if (bpforw == bp)
		return (0);

	/*
	 * buffer space is not adjacent; do nothing
	 */
	if ((bp->b_un.b_addr + bp->b_bufsize) != bpforw->b_un.b_addr)
		return (0);

	/*
	 * locking protocol requires giving up any bp locks before
	 * acquiring cb_rwlock.  This is okay because we hold
	 * un_log_mutex.
	 */
	sema_v(&bp->b_sem);

	/*
	 * lock out ldl_read
	 */
	rw_enter(&cb->cb_rwlock, RW_WRITER);

	/*
	 * wait for current IO to finish w/next bp; if necessary
	 */
	makebusy(ul, bpforw);

	/*
	 * free the next bp and steal its space
	 */
	bp->b_forw = bpforw->b_forw;
	bpforw->b_forw->b_back = bp;
	bp->b_bufsize += bpforw->b_bufsize;
	sema_v(&bpforw->b_sem);
	bpforw->b_forw = cb->cb_free;
	cb->cb_free = bpforw;
	makebusy(ul, bp);
	rw_exit(&cb->cb_rwlock);

	return (1);
}

static size_t
storebuf(ml_unit_t *ul, buf_t *bp, caddr_t va, size_t nb)
{
	size_t		copy_nb;
	size_t		nb_in_sec;
	sect_trailer_t	*st;
	size_t		nb_left = nb;
	cirbuf_t	*cb	= &ul->un_wrbuf;

again:
	nb_in_sec = NB_LEFT_IN_SECTOR(bp->b_bcount);
	copy_nb = MIN(nb_left, nb_in_sec);

	ASSERT(copy_nb);

	bcopy(va, bp->b_un.b_addr + bp->b_bcount, copy_nb);
	bp->b_bcount += copy_nb;
	va += copy_nb;
	nb_left -= copy_nb;
	ul->un_tail_lof += copy_nb;

	if ((nb_in_sec -= copy_nb) == 0) {
		st = (sect_trailer_t *)(bp->b_un.b_addr + bp->b_bcount);

		st->st_tid = ul->un_logmap->mtm_tid;
		st->st_ident = ul->un_tail_ident++;
		bp->b_bcount += sizeof (sect_trailer_t);
		ul->un_tail_lof += sizeof (sect_trailer_t);
		/*
		 * log wrapped; async write this bp
		 */
		if (ul->un_tail_lof == ul->un_eol_lof) {
			ul->un_tail_lof = ul->un_bol_lof;
			push_dirty_bp(ul, bp);
			return (nb - nb_left);
		}
		/*
		 * out of bp space; get more or async write buf
		 */
		if (bp->b_bcount == bp->b_bufsize) {
			if (!extend_write_bp(ul, cb, bp)) {
				push_dirty_bp(ul, bp);
				return (nb - nb_left);
			}
		}
	}
	if (nb_left)
		goto again;

	sema_v(&bp->b_sem);
	return (nb);
}

static void
fetchzeroes(caddr_t dst_va, offset_t dst_mof, ulong_t dst_nb, mapentry_t *me)
{
	offset_t	src_mof	= me->me_mof;
	size_t		src_nb	= me->me_nb;

	if (src_mof > dst_mof) {
		ASSERT(src_mof < (dst_mof + dst_nb));
		dst_va += (src_mof - dst_mof);
		dst_nb -= (src_mof - dst_mof);
	} else {
		ASSERT(dst_mof < (src_mof + src_nb));
		src_nb -= (dst_mof - src_mof);
	}

	src_nb = MIN(src_nb, dst_nb);
	ASSERT(src_nb);
	bzero(dst_va, src_nb);
}

/*
 * dst_va == NULL means don't copy anything
 */
static ulong_t
fetchbuf(
	ml_unit_t *ul,
	buf_t *bp,
	caddr_t dst_va,
	size_t dst_nb,
	off_t *dst_lofp)
{
	caddr_t	copy_va;
	size_t	copy_nb;
	size_t	nb_sec;
	off_t	dst_lof		= *dst_lofp;
	ulong_t	sav_dst_nb	= dst_nb;
	ulong_t	src_nb		= bp->b_bcount;
	off_t	src_lof		= dbtob(bp->b_blkno);
	off_t	src_elof	= src_lof + src_nb;
	caddr_t	src_va		= bp->b_un.b_addr;

	/*
	 * copy from bp to dst_va
	 */
	while (dst_nb) {
		/*
		 * compute address within bp
		 */
		copy_va = src_va + (dst_lof - src_lof);

		/*
		 * adjust copy size to amount of data in bp
		 */
		copy_nb = MIN(dst_nb, src_elof - dst_lof);

		/*
		 * adjust copy size to amount of data in sector
		 */
		nb_sec = NB_LEFT_IN_SECTOR(dst_lof);
		copy_nb = MIN(copy_nb, nb_sec);

		/*
		 * dst_va == NULL means don't do copy (see logseek())
		 */
		if (dst_va) {
			bcopy(copy_va, dst_va, copy_nb);
			dst_va += copy_nb;
		}
		dst_lof += copy_nb;
		dst_nb -= copy_nb;
		nb_sec -= copy_nb;

		/*
		 * advance over sector trailer
		 */
		if (nb_sec == 0)
			dst_lof += sizeof (sect_trailer_t);

		/*
		 * exhausted buffer
		 *	return current lof for next read
		 */
		if (dst_lof == src_elof) {
			sema_v(&bp->b_sem);
			if (dst_lof == ul->un_eol_lof)
				dst_lof = ul->un_bol_lof;
			*dst_lofp = dst_lof;
			return (sav_dst_nb - dst_nb);
		}
	}

	/*
	 * copy complete - return current lof
	 */
	sema_v(&bp->b_sem);
	*dst_lofp = dst_lof;
	return (sav_dst_nb);
}

void
ldl_round_commit(ml_unit_t *ul)
{
	int		wrapped;
	buf_t		*bp;
	sect_trailer_t	*st;
	size_t		bcount;
	cirbuf_t	*cb	= &ul->un_wrbuf;

	/*
	 * if nothing to write; then do nothing
	 */
	if ((bp = cb->cb_dirty) == NULL)
		return;
	makebusy(ul, bp);

	/*
	 * round up to sector boundary and set new tail
	 *	don't readjust st_ident if buf is already rounded
	 */
	bcount = P2ROUNDUP(bp->b_bcount, DEV_BSIZE);
	if (bcount == bp->b_bcount) {
		sema_v(&bp->b_sem);
		return;
	}
	bp->b_bcount = bcount;
	ul->un_tail_lof = dbtob(bp->b_blkno) + bcount;
	wrapped = 0;
	if (ul->un_tail_lof == ul->un_eol_lof) {
		ul->un_tail_lof = ul->un_bol_lof;
		++wrapped;
	}
	ASSERT(ul->un_tail_lof != ul->un_head_lof);

	/*
	 * fix up the sector trailer
	 */
	/* LINTED */
	st = (sect_trailer_t *)
	    ((bp->b_un.b_addr + bcount) - sizeof (*st));
	st->st_tid = ul->un_logmap->mtm_tid;
	st->st_ident = ul->un_tail_ident++;

	/*
	 * if tail wrapped or we have exhausted this buffer
	 *	async write the buffer
	 */
	if (wrapped || bcount == bp->b_bufsize)
		push_dirty_bp(ul, bp);
	else
		sema_v(&bp->b_sem);
}

void
ldl_push_commit(ml_unit_t *ul)
{
	buf_t		*bp;
	cirbuf_t	*cb	= &ul->un_wrbuf;

	/*
	 * if nothing to write; then do nothing
	 */
	if ((bp = cb->cb_dirty) == NULL)
		return;
	makebusy(ul, bp);
	push_dirty_bp(ul, bp);
}

int
ldl_need_commit(ml_unit_t *ul)
{
	return (ul->un_resv > (ul->un_maxresv - (ul->un_maxresv>>2)));
}

int
ldl_has_space(ml_unit_t *ul, mapentry_t *me)
{
	off_t	nfb;
	off_t	nb;

	ASSERT(MUTEX_HELD(&ul->un_log_mutex));

	/*
	 * Add up the size used by the deltas
	 * round nb up to a sector length plus an extra sector
	 *	w/o the extra sector we couldn't distinguish
	 *	a full log (head == tail) from an empty log (head == tail)
	 */
	for (nb = DEV_BSIZE; me; me = me->me_hash) {
		nb += sizeof (struct delta);
		if (me->me_dt != DT_CANCEL)
			nb += me->me_nb;
	}
	nb = P2ROUNDUP(nb, DEV_BSIZE);

	if (ul->un_head_lof <= ul->un_tail_lof)
		nfb = (ul->un_head_lof - ul->un_bol_lof) +
		    (ul->un_eol_lof - ul->un_tail_lof);
	else
		nfb = ul->un_head_lof - ul->un_tail_lof;

	return (nb < nfb);
}

void
ldl_write(ml_unit_t *ul, caddr_t bufp, offset_t bufmof, struct mapentry *me)
{
	buf_t		*bp;
	caddr_t		va;
	size_t		nb;
	size_t		actual;

	ASSERT(MUTEX_HELD(&ul->un_log_mutex));

	/* Write the delta */

	nb = sizeof (struct delta);
	va = (caddr_t)&me->me_delta;
	bp = get_write_bp(ul);

	while (nb) {
		if (ul->un_flags & LDL_ERROR) {
			sema_v(&bp->b_sem);
			return;
		}
		actual = storebuf(ul, bp, va, nb);
		ASSERT(actual);
		va += actual;
		nb -= actual;
		if (nb)
			bp = get_write_bp(ul);
	}

	/* If a commit, cancel, or 0's; we're almost done */
	switch (me->me_dt) {
		case DT_COMMIT:
		case DT_CANCEL:
		case DT_ABZERO:
			/* roll needs to know where the next delta will go */
			me->me_lof = ul->un_tail_lof;
			return;
		default:
			break;
	}

	/* Now write the data */

	ASSERT(me->me_nb != 0);

	nb = me->me_nb;
	va = (me->me_mof - bufmof) + bufp;
	bp = get_write_bp(ul);

	/* Save where we will put the data */
	me->me_lof = ul->un_tail_lof;

	while (nb) {
		if (ul->un_flags & LDL_ERROR) {
			sema_v(&bp->b_sem);
			return;
		}
		actual = storebuf(ul, bp, va, nb);
		ASSERT(actual);
		va += actual;
		nb -= actual;
		if (nb)
			bp = get_write_bp(ul);
	}
}

void
ldl_waito(ml_unit_t *ul)
{
	buf_t		*bp;
	cirbuf_t	*cb	= &ul->un_wrbuf;

	rw_enter(&cb->cb_rwlock, RW_WRITER);
	/*
	 * wait on them
	 */
	bp = cb->cb_bp;
	do {
		if ((bp->b_flags & B_DONE) == 0) {
			makebusy(ul, bp);
			sema_v(&bp->b_sem);
		}
		bp = bp->b_forw;
	} while (bp != cb->cb_bp);
	rw_exit(&cb->cb_rwlock);
}

/*
 * seek nb bytes from location lof
 */
static int
logseek(ml_unit_t *ul, off_t lof, size_t nb, off_t *lofp)
{
	buf_t	*bp;
	ulong_t	actual;

	while (nb) {
		bp = get_read_bp(ul, lof);
		if (bp->b_flags & B_ERROR) {
			sema_v(&bp->b_sem);
			return (EIO);
		}
		actual = fetchbuf(ul, bp, NULL, nb, &lof);
		ASSERT(actual);
		nb -= actual;
	}
	*lofp = lof;
	ASSERT(nb == 0);
	return (0);
}

int
ldl_read(
	ml_unit_t *ul,		/* Log unit */
	caddr_t va,		/* address of buffer to read into */
	offset_t mof,		/* mof of buffer */
	off_t nb,		/* length of buffer */
	mapentry_t *me)		/* Map entry list */
{
	buf_t	*bp;
	crb_t   *crb;
	caddr_t	rva;			/* address to read into */
	size_t	rnb;			/* # of bytes to read */
	off_t	lof;			/* log device offset to read from */
	off_t   skip;
	ulong_t	actual;
	int	error;
	caddr_t	eva	= va + nb;	/* end of buffer */

	for (; me; me = me->me_agenext) {
		ASSERT(me->me_dt != DT_CANCEL);

		/*
		 * check for an cached roll buffer
		 */
		crb = me->me_crb;
		if (crb) {
			if (mof > crb->c_mof) {
				/*
				 * This mapentry overlaps with the beginning of
				 * the supplied buffer
				 */
				skip = mof - crb->c_mof;
				bcopy(crb->c_buf + skip, va,
				    MIN(nb, crb->c_nb - skip));
			} else {
				/*
				 * This mapentry starts at or after
				 * the supplied buffer.
				 */
				skip = crb->c_mof - mof;
				bcopy(crb->c_buf, va + skip,
				    MIN(crb->c_nb, nb - skip));
			}
			logstats.ls_lreadsinmem.value.ui64++;
			continue;
		}

		/*
		 * check for a delta full of zeroes - there's no log data
		 */
		if (me->me_dt == DT_ABZERO) {
			fetchzeroes(va, mof, nb, me);
			continue;
		}

		if (mof > me->me_mof) {
			rnb = (size_t)(mof - me->me_mof);
			error = logseek(ul, me->me_lof, rnb, &lof);
			if (error)
				return (EIO);
			rva = va;
			rnb = me->me_nb - rnb;
			rnb = ((rva + rnb) > eva) ? eva - rva : rnb;
		} else {
			lof = me->me_lof;
			rva = (me->me_mof - mof) + va;
			rnb = ((rva + me->me_nb) > eva) ? eva - rva : me->me_nb;
		}

		while (rnb) {
			bp = get_read_bp(ul, lof);
			if (bp->b_flags & B_ERROR) {
				sema_v(&bp->b_sem);
				return (EIO);
			}
			ASSERT(((me->me_flags & ME_ROLL) == 0) ||
			    (bp != ul->un_wrbuf.cb_dirty));
			actual = fetchbuf(ul, bp, rva, rnb, &lof);
			ASSERT(actual);
			rva += actual;
			rnb -= actual;
		}
	}
	return (0);
}

void
ldl_savestate(ml_unit_t *ul)
{
	int		error;
	buf_t		*bp	= ul->un_bp;
	ml_odunit_t	*ud	= (void *)bp->b_un.b_addr;
	ml_odunit_t	*ud2	= (void *)(bp->b_un.b_addr + DEV_BSIZE);

#if	DEBUG
	/*
	 * Scan test is running; don't update intermediate state
	 */
	if (ul->un_logmap && ul->un_logmap->mtm_trimlof)
		return;
#endif	/* DEBUG */

	mutex_enter(&ul->un_state_mutex);
	bcopy(&ul->un_ondisk, ud, sizeof (*ud));
	ud->od_chksum = ud->od_head_ident + ud->od_tail_ident;
	bcopy(ud, ud2, sizeof (*ud));

	/* If a snapshot is enabled write through the shapshot driver. */
	if (ul->un_ufsvfs->vfs_snapshot)
		UFS_BWRITE2(ul->un_ufsvfs, bp);
	else
		BWRITE2(bp);
	logstats.ls_ldlwrites.value.ui64++;
	error = bp->b_flags & B_ERROR;
	mutex_exit(&ul->un_state_mutex);
	if (error)
		ldl_seterror(ul, "Error writing ufs log state");
}

/*
 * The head will be set to (new_lof - header) since ldl_sethead is
 * called with the new_lof of the data portion of a delta.
 */
void
ldl_sethead(ml_unit_t *ul, off_t data_lof, uint32_t tid)
{
	off_t		nb;
	off_t		new_lof;
	uint32_t	new_ident;
	daddr_t		beg_blkno;
	daddr_t		end_blkno;

	ASSERT(MUTEX_HELD(&ul->un_log_mutex));

	if (data_lof == -1) {
		/* log is empty */
		new_ident = lufs_hd_genid(ul);
		new_lof = ul->un_tail_lof;

	} else {
		/* compute header's lof */
		new_ident = ul->un_head_ident;
		new_lof = data_lof - sizeof (struct delta);

		/* whoops, header spans sectors; subtract out sector trailer */
		if (btodb(new_lof) != btodb(data_lof))
			new_lof -= sizeof (sect_trailer_t);

		/* whoops, header wrapped the log; go to last sector */
		if (new_lof < ul->un_bol_lof) {
			/* sector offset */
			new_lof -= dbtob(btodb(new_lof));
			/* add to last sector's lof */
			new_lof += (ul->un_eol_lof - DEV_BSIZE);
		}
		ul->un_head_tid = tid;
	}

	/*
	 * check for nop
	 */
	if (new_lof == ul->un_head_lof)
		return;

	/*
	 * invalidate the affected bufs and calculate new ident
	 */
	if (new_lof > ul->un_head_lof) {
		nb = new_lof - ul->un_head_lof;
		inval_range(ul, &ul->un_wrbuf, ul->un_head_lof, nb);
		inval_range(ul, &ul->un_rdbuf, ul->un_head_lof, nb);

		end_blkno = btodb(new_lof);
		beg_blkno = btodb(ul->un_head_lof);
		new_ident += (end_blkno - beg_blkno);
	} else {
		nb = ul->un_eol_lof - ul->un_head_lof;
		inval_range(ul, &ul->un_wrbuf, ul->un_head_lof, nb);
		inval_range(ul, &ul->un_rdbuf, ul->un_head_lof, nb);

		end_blkno = btodb(ul->un_eol_lof);
		beg_blkno = btodb(ul->un_head_lof);
		new_ident += (end_blkno - beg_blkno);

		nb = new_lof - ul->un_bol_lof;
		inval_range(ul, &ul->un_wrbuf, ul->un_bol_lof, nb);
		inval_range(ul, &ul->un_rdbuf, ul->un_bol_lof, nb);

		end_blkno = btodb(new_lof);
		beg_blkno = btodb(ul->un_bol_lof);
		new_ident += (end_blkno - beg_blkno);
	}
	/*
	 * don't update the head if there has been an error
	 */
	if (ul->un_flags & LDL_ERROR)
		return;

	/* Fix up the head and ident */
	ASSERT(new_lof >= ul->un_bol_lof);
	ul->un_head_lof = new_lof;
	ul->un_head_ident = new_ident;
	if (data_lof == -1) {
		ul->un_tail_ident = ul->un_head_ident;
	}


	/* Commit to the database */
	ldl_savestate(ul);

	ASSERT(((ul->un_logmap->mtm_debug & MT_SCAN) == 0) ||
	    ldl_sethead_debug(ul));
}

/*
 * The tail will be set to the sector following lof+nb
 *	lof + nb == size of the last delta + commit record
 *	this function is called once after the log scan has completed.
 */
void
ldl_settail(ml_unit_t *ul, off_t lof, size_t nb)
{
	off_t		new_lof;
	uint32_t	new_ident;
	daddr_t		beg_blkno;
	daddr_t		end_blkno;

	ASSERT(MUTEX_HELD(&ul->un_log_mutex));

	if (lof == -1) {
		ul->un_tail_lof = dbtob(btodb(ul->un_head_lof));
		ul->un_head_lof = ul->un_tail_lof;
		ul->un_head_ident = lufs_hd_genid(ul);
		ul->un_tail_ident = ul->un_head_ident;

		/* Commit to the database */
		ldl_savestate(ul);

		return;
	}

	/*
	 * new_lof is the offset of the sector following the last commit
	 */
	(void) logseek(ul, lof, nb, &new_lof);
	ASSERT(new_lof != dbtob(btodb(ul->un_head_lof)));

	/*
	 * calculate new ident
	 */
	if (new_lof > ul->un_head_lof) {
		end_blkno = btodb(new_lof);
		beg_blkno = btodb(ul->un_head_lof);
		new_ident = ul->un_head_ident + (end_blkno - beg_blkno);
	} else {
		end_blkno = btodb(ul->un_eol_lof);
		beg_blkno = btodb(ul->un_head_lof);
		new_ident = ul->un_head_ident + (end_blkno - beg_blkno);

		end_blkno = btodb(new_lof);
		beg_blkno = btodb(ul->un_bol_lof);
		new_ident += (end_blkno - beg_blkno);
	}

	/* Fix up the tail and ident */
	ul->un_tail_lof = new_lof;
	ul->un_tail_ident = new_ident;

	/* Commit to the database */
	ldl_savestate(ul);
}

/*
 * LOGSCAN STUFF
 */
static int
ldl_logscan_ident(ml_unit_t *ul, buf_t *bp, off_t lof)
{
	ulong_t		ident;
	size_t		nblk, i;
	sect_trailer_t	*st;

	/*
	 * compute ident for first sector in the buffer
	 */
	ident = ul->un_head_ident;
	if (bp->b_blkno >= btodb(ul->un_head_lof)) {
		ident += (bp->b_blkno - btodb(ul->un_head_lof));
	} else {
		ident += (btodb(ul->un_eol_lof) - btodb(ul->un_head_lof));
		ident += (bp->b_blkno - btodb(ul->un_bol_lof));
	}
	/*
	 * truncate the buffer down to the last valid sector
	 */
	nblk = btodb(bp->b_bcount);
	bp->b_bcount = 0;
	/* LINTED */
	st = (sect_trailer_t *)(bp->b_un.b_addr + LDL_USABLE_BSIZE);
	for (i = 0; i < nblk; ++i) {
		if (st->st_ident != ident)
			break;

		/* remember last valid tid for ldl_logscan_error() */
		ul->un_tid = st->st_tid;

		/* LINTED */
		st = (sect_trailer_t *)(((caddr_t)st) + DEV_BSIZE);
		++ident;
		bp->b_bcount += DEV_BSIZE;
	}
	/*
	 * make sure that lof is still within range
	 */
	return (within_range(lof, bp->b_blkno, bp->b_bcount));
}

ulong_t
ldl_logscan_nbcommit(off_t lof)
{
	/*
	 * lof is the offset following the commit header.  However,
	 * if the commit header fell on the end-of-sector, then lof
	 * has already been advanced to the beginning of the next
	 * sector.  So do nothing.  Otherwise, return the remaining
	 * bytes in the sector.
	 */
	if ((lof & (DEV_BSIZE - 1)) == 0)
		return (0);
	return (NB_LEFT_IN_SECTOR(lof));
}

int
ldl_logscan_read(ml_unit_t *ul, off_t *lofp, size_t nb, caddr_t va)
{
	buf_t	*bp;
	ulong_t	actual;

	ASSERT(ul->un_head_lof != ul->un_tail_lof);

	/*
	 * Check the log data doesn't go out of bounds
	 */
	if (ul->un_head_lof < ul->un_tail_lof) {
		if (!WITHIN(*lofp, nb, ul->un_head_lof,
		    (ul->un_tail_lof - ul->un_head_lof))) {
			return (EIO);
		}
	} else {
		if (OVERLAP(*lofp, nb, ul->un_tail_lof,
		    (ul->un_head_lof - ul->un_tail_lof))) {
			return (EIO);
		}
	}

	while (nb) {
		bp = get_read_bp(ul, *lofp);
		if (bp->b_flags & B_ERROR) {
			sema_v(&bp->b_sem);
			return (EIO);
		}
		/*
		 * out-of-seq idents means partial transaction
		 *	panic, non-corrupting powerfail, ...
		 */
		if (!ldl_logscan_ident(ul, bp, *lofp)) {
			sema_v(&bp->b_sem);
			return (EIO);
		}
		/*
		 * copy the header into the caller's buf
		 */
		actual = fetchbuf(ul, bp, va, nb, lofp);
		if (va)
			va += actual;
		nb -= actual;
	}
	return (0);
}

void
ldl_logscan_begin(ml_unit_t *ul)
{
	size_t	bufsize;

	ASSERT(ul->un_wrbuf.cb_dirty == NULL);

	/*
	 * logscan has begun
	 */
	ul->un_flags |= LDL_SCAN;

	/*
	 * reset the circular bufs
	 */
	bufsize = ldl_bufsize(ul);
	alloc_rdbuf(&ul->un_rdbuf, bufsize, bufsize);
	alloc_wrbuf(&ul->un_wrbuf, bufsize);

	/*
	 * set the tail to reflect a full log
	 */
	ul->un_tail_lof = dbtob(btodb(ul->un_head_lof)) - DEV_BSIZE;

	if (ul->un_tail_lof < ul->un_bol_lof)
		ul->un_tail_lof = ul->un_eol_lof - DEV_BSIZE;
	if (ul->un_tail_lof >= ul->un_eol_lof)
		ul->un_tail_lof = ul->un_bol_lof;

	/*
	 * un_tid is used during error processing; it is initialized to
	 * the tid of the delta at un_head_lof;
	 */
	ul->un_tid = ul->un_head_tid;
}

void
ldl_logscan_end(ml_unit_t *ul)
{
	size_t	bufsize;

	/*
	 * reset the circular bufs
	 */
	bufsize = ldl_bufsize(ul);
	alloc_rdbuf(&ul->un_rdbuf, MAPBLOCKSIZE, MAPBLOCKSIZE);
	alloc_wrbuf(&ul->un_wrbuf, bufsize);

	/*
	 * Done w/scan
	 */
	ul->un_flags &= ~LDL_SCAN;
}

int
ldl_need_roll(ml_unit_t *ul)
{
	off_t	busybytes;
	off_t	head;
	off_t	tail;
	off_t	bol;
	off_t	eol;
	off_t	nb;

	/*
	 * snapshot the log state
	 */
	head = ul->un_head_lof;
	tail = ul->un_tail_lof;
	bol = ul->un_bol_lof;
	eol = ul->un_eol_lof;
	nb = ul->un_logsize;

	/*
	 * compute number of busy (inuse) bytes
	 */
	if (head <= tail)
		busybytes = tail - head;
	else
		busybytes = (eol - head) + (tail - bol);

	/*
	 * return TRUE if > 75% full
	 */
	return (busybytes > (nb - (nb >> 2)));
}

void
ldl_seterror(ml_unit_t *ul, char *why)
{
	/*
	 * already in error state; do nothing
	 */
	if (ul->un_flags & LDL_ERROR)
		return;

	ul->un_flags |= LDL_ERROR;	/* incore */
	ul->un_badlog = 1;		/* ondisk (cleared by fsck) */

	/*
	 * Commit to state sectors
	 */
	uniqtime(&ul->un_timestamp);
	ldl_savestate(ul);

	/* Pretty print */
	cmn_err(CE_WARN, "%s", why);
	cmn_err(CE_WARN, "ufs log for %s changed state to Error",
	    ul->un_ufsvfs->vfs_fs->fs_fsmnt);
	cmn_err(CE_WARN, "Please umount(1M) %s and run fsck(1M)",
	    ul->un_ufsvfs->vfs_fs->fs_fsmnt);

	/*
	 * If we aren't in the middle of scan (aka snarf); tell ufs
	 * to hard lock itself.
	 */
	if ((ul->un_flags & LDL_SCAN) == 0)
		ufs_trans_onerror();
}

size_t
ldl_bufsize(ml_unit_t *ul)
{
	size_t		bufsize;
	extern uint32_t	ldl_minbufsize;

	/*
	 * initial guess is the maxtransfer value for this log device
	 * 	increase if too small
	 * 	decrease if too large
	 */
	bufsize = dbtob(btod(ul->un_maxtransfer));
	if (bufsize < ldl_minbufsize)
		bufsize = ldl_minbufsize;
	if (bufsize > maxphys)
		bufsize = maxphys;
	if (bufsize > ul->un_maxtransfer)
		bufsize = ul->un_maxtransfer;
	return (bufsize);
}
