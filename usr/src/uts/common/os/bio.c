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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 */

/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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
#include <sys/t_lock.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/buf.h>
#include <sys/var.h>
#include <sys/vnode.h>
#include <sys/bitmap.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/atomic.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <sys/vtrace.h>
#include <sys/tnf_probe.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_bio.h>
#include <sys/fs/ufs_log.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/sdt.h>

/* Locks */
static	kmutex_t	blist_lock;	/* protects b_list */
static	kmutex_t	bhdr_lock;	/* protects the bhdrlist */
static	kmutex_t	bfree_lock;	/* protects the bfreelist structure */

struct hbuf	*hbuf;			/* Hash buckets */
struct dwbuf	*dwbuf;			/* Delayed write buckets */
static struct buf *bhdrlist;		/* buf header free list */
static int 	nbuf;			/* number of buffer headers allocated */

static int	lastindex;		/* Reference point on where to start */
					/* when looking for free buffers */

#define	bio_bhash(dev, bn)	(hash2ints((dev), (int)(bn)) & v.v_hmask)
#define	EMPTY_LIST	((struct buf *)-1)

static kcondvar_t	bio_mem_cv; 	/* Condition variables */
static kcondvar_t	bio_flushinval_cv;
static int	bio_doingflush;		/* flush in progress */
static int	bio_doinginval;		/* inval in progress */
static int	bio_flinv_cv_wanted;	/* someone waiting for cv */

/*
 * Statistics on the buffer cache
 */
struct biostats biostats = {
	{ "buffer_cache_lookups",		KSTAT_DATA_UINT32 },
	{ "buffer_cache_hits",			KSTAT_DATA_UINT32 },
	{ "new_buffer_requests",		KSTAT_DATA_UINT32 },
	{ "waits_for_buffer_allocs",		KSTAT_DATA_UINT32 },
	{ "buffers_locked_by_someone",		KSTAT_DATA_UINT32 },
	{ "duplicate_buffers_found",		KSTAT_DATA_UINT32 }
};

/*
 * kstat data
 */
kstat_named_t	*biostats_ptr = (kstat_named_t *)&biostats;
uint_t		biostats_ndata = (uint_t)(sizeof (biostats) /
					sizeof (kstat_named_t));

/*
 * Statistics on ufs buffer cache
 * Not protected by locks
 */
struct ufsbiostats ub = {
	{ "breads",			KSTAT_DATA_UINT32 },
	{ "bwrites",			KSTAT_DATA_UINT32 },
	{ "fbiwrites",			KSTAT_DATA_UINT32 },
	{ "getpages",			KSTAT_DATA_UINT32 },
	{ "getras",			KSTAT_DATA_UINT32 },
	{ "putsyncs",			KSTAT_DATA_UINT32 },
	{ "putasyncs",			KSTAT_DATA_UINT32 },
	{ "putpageios",			KSTAT_DATA_UINT32 },
};

/*
 * more UFS Logging eccentricities...
 *
 * required since "#pragma weak ..." doesn't work in reverse order.
 * i.e.:  genunix (bio.c) is loaded before the ufs modules and pointers
 *        to ufs routines don't get plugged into bio.c calls so
 *        we initialize it when setting up the "lufsops" table
 *        in "lufs.c:_init()"
 */
void (*bio_lufs_strategy)(void *, buf_t *);
void (*bio_snapshot_strategy)(void *, buf_t *);


/* Private routines */
static struct buf	*bio_getfreeblk(long);
static void 		bio_mem_get(long);
static void		bio_bhdr_free(struct buf *);
static struct buf	*bio_bhdr_alloc(void);
static void		bio_recycle(int, long);
static void 		bio_pageio_done(struct buf *);
static int 		bio_incore(dev_t, daddr_t);

/*
 * Buffer cache constants
 */
#define	BIO_BUF_PERCENT	(100/2)		/* default: 2% of memory */
#define	BIO_MAX_PERCENT	(100/20)	/* max is 20% of real memory */
#define	BIO_BHDR_POOL	100		/* Default bhdr pool size */
#define	BIO_MIN_HDR	10		/* Minimum number of buffer headers */
#define	BIO_MIN_HWM	(BIO_MIN_HDR * MAXBSIZE / 1024)
#define	BIO_HASHLEN	4		/* Target length of hash chains */


/* Flags for bio_recycle() */
#define	BIO_HEADER	0x01
#define	BIO_MEM		0x02

extern	int bufhwm;		/* User tunable - high water mark for mem  */
extern	int bufhwm_pct;		/* ditto - given in % of physmem  */

/*
 * The following routines allocate and free
 * buffers with various side effects.  In general the
 * arguments to an allocate routine are a device and
 * a block number, and the value is a pointer to
 * to the buffer header; the buffer returned is locked with a
 * binary semaphore so that no one else can touch it. If the block was
 * already in core, no I/O need be done; if it is
 * already locked, the process waits until it becomes free.
 * The following routines allocate a buffer:
 *	getblk
 *	bread/BREAD
 *	breada
 * Eventually the buffer must be released, possibly with the
 * side effect of writing it out, by using one of
 *	bwrite/BWRITE/brwrite
 *	bdwrite/bdrwrite
 *	bawrite
 *	brelse
 *
 * The B_WANTED/B_BUSY bits are NOT used by these routines for synchronization.
 * Instead, a binary semaphore, b_sem is used to gain exclusive access to
 * a buffer and a binary semaphore, b_io is used for I/O synchronization.
 * B_DONE is still used to denote a buffer with I/O complete on it.
 *
 * The bfreelist.b_bcount field is computed everytime fsflush runs. It is
 * should not be used where a very accurate count of the free buffers is
 * needed.
 */

/*
 * Read in (if necessary) the block and return a buffer pointer.
 *
 * This interface is provided for binary compatibility.  Using
 * BREAD() directly avoids the extra function call overhead invoked
 * by calling this routine.
 */
struct buf *
bread(dev_t dev, daddr_t blkno, long bsize)
{
	return (BREAD(dev, blkno, bsize));
}

/*
 * Common code for reading a buffer with various options
 *
 * Read in (if necessary) the block and return a buffer pointer.
 */
struct buf *
bread_common(void *arg, dev_t dev, daddr_t blkno, long bsize)
{
	struct ufsvfs *ufsvfsp = (struct ufsvfs *)arg;
	struct buf *bp;
	klwp_t *lwp = ttolwp(curthread);

	CPU_STATS_ADD_K(sys, lread, 1);
	bp = getblk_common(ufsvfsp, dev, blkno, bsize, /* errflg */ 1);
	if (bp->b_flags & B_DONE)
		return (bp);
	bp->b_flags |= B_READ;
	ASSERT(bp->b_bcount == bsize);
	if (ufsvfsp == NULL) {					/* !ufs */
		(void) bdev_strategy(bp);
	} else if (ufsvfsp->vfs_log && bio_lufs_strategy != NULL) {
							/* ufs && logging */
		(*bio_lufs_strategy)(ufsvfsp->vfs_log, bp);
	} else if (ufsvfsp->vfs_snapshot && bio_snapshot_strategy != NULL) {
							/* ufs && snapshots */
		(*bio_snapshot_strategy)(&ufsvfsp->vfs_snapshot, bp);
	} else {
		ufsvfsp->vfs_iotstamp = ddi_get_lbolt();
		ub.ub_breads.value.ul++;		/* ufs && !logging */
		(void) bdev_strategy(bp);
	}
	if (lwp != NULL)
		lwp->lwp_ru.inblock++;
	CPU_STATS_ADD_K(sys, bread, 1);
	(void) biowait(bp);
	return (bp);
}

/*
 * Read in the block, like bread, but also start I/O on the
 * read-ahead block (which is not allocated to the caller).
 */
struct buf *
breada(dev_t dev, daddr_t blkno, daddr_t rablkno, long bsize)
{
	struct buf *bp, *rabp;
	klwp_t *lwp = ttolwp(curthread);

	bp = NULL;
	if (!bio_incore(dev, blkno)) {
		CPU_STATS_ADD_K(sys, lread, 1);
		bp = GETBLK(dev, blkno, bsize);
		if ((bp->b_flags & B_DONE) == 0) {
			bp->b_flags |= B_READ;
			bp->b_bcount = bsize;
			(void) bdev_strategy(bp);
			if (lwp != NULL)
				lwp->lwp_ru.inblock++;
			CPU_STATS_ADD_K(sys, bread, 1);
		}
	}
	if (rablkno && bfreelist.b_bcount > 1 &&
	    !bio_incore(dev, rablkno)) {
		rabp = GETBLK(dev, rablkno, bsize);
		if (rabp->b_flags & B_DONE)
			brelse(rabp);
		else {
			rabp->b_flags |= B_READ|B_ASYNC;
			rabp->b_bcount = bsize;
			(void) bdev_strategy(rabp);
			if (lwp != NULL)
				lwp->lwp_ru.inblock++;
			CPU_STATS_ADD_K(sys, bread, 1);
		}
	}
	if (bp == NULL)
		return (BREAD(dev, blkno, bsize));
	(void) biowait(bp);
	return (bp);
}

/*
 * Common code for writing a buffer with various options.
 *
 * force_wait  - wait for write completion regardless of B_ASYNC flag
 * do_relse    - release the buffer when we are done
 * clear_flags - flags to clear from the buffer
 */
void
bwrite_common(void *arg, struct buf *bp, int force_wait,
    int do_relse, int clear_flags)
{
	register int do_wait;
	struct ufsvfs *ufsvfsp = (struct ufsvfs *)arg;
	int flag;
	klwp_t *lwp = ttolwp(curthread);
	struct cpu *cpup;

	ASSERT(SEMA_HELD(&bp->b_sem));
	flag = bp->b_flags;
	bp->b_flags &= ~clear_flags;
	if (lwp != NULL)
		lwp->lwp_ru.oublock++;
	CPU_STATS_ENTER_K();
	cpup = CPU;		/* get pointer AFTER preemption is disabled */
	CPU_STATS_ADDQ(cpup, sys, lwrite, 1);
	CPU_STATS_ADDQ(cpup, sys, bwrite, 1);
	do_wait = ((flag & B_ASYNC) == 0 || force_wait);
	if (do_wait == 0)
		CPU_STATS_ADDQ(cpup, sys, bawrite, 1);
	CPU_STATS_EXIT_K();
	if (ufsvfsp == NULL) {
		(void) bdev_strategy(bp);
	} else if (ufsvfsp->vfs_log && bio_lufs_strategy != NULL) {
							/* ufs && logging */
		(*bio_lufs_strategy)(ufsvfsp->vfs_log, bp);
	} else if (ufsvfsp->vfs_snapshot && bio_snapshot_strategy != NULL) {
							/* ufs && snapshots */
		(*bio_snapshot_strategy)(&ufsvfsp->vfs_snapshot, bp);
	} else {
		ub.ub_bwrites.value.ul++;		/* ufs && !logging */
		(void) bdev_strategy(bp);
	}
	if (do_wait) {
		(void) biowait(bp);
		if (do_relse) {
			brelse(bp);
		}
	}
}

/*
 * Write the buffer, waiting for completion (unless B_ASYNC is set).
 * Then release the buffer.
 * This interface is provided for binary compatibility.  Using
 * BWRITE() directly avoids the extra function call overhead invoked
 * by calling this routine.
 */
void
bwrite(struct buf *bp)
{
	BWRITE(bp);
}

/*
 * Write the buffer, waiting for completion.
 * But don't release the buffer afterwards.
 * This interface is provided for binary compatibility.  Using
 * BWRITE2() directly avoids the extra function call overhead.
 */
void
bwrite2(struct buf *bp)
{
	BWRITE2(bp);
}

/*
 * Release the buffer, marking it so that if it is grabbed
 * for another purpose it will be written out before being
 * given up (e.g. when writing a partial block where it is
 * assumed that another write for the same block will soon follow).
 * Also save the time that the block is first marked as delayed
 * so that it will be written in a reasonable time.
 */
void
bdwrite(struct buf *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	CPU_STATS_ADD_K(sys, lwrite, 1);
	if ((bp->b_flags & B_DELWRI) == 0)
		bp->b_start = ddi_get_lbolt();
	/*
	 * B_DONE allows others to use the buffer, B_DELWRI causes the
	 * buffer to be written before being reused, and setting b_resid
	 * to zero says the buffer is complete.
	 */
	bp->b_flags |= B_DELWRI | B_DONE;
	bp->b_resid = 0;
	brelse(bp);
}

/*
 * Release the buffer, start I/O on it, but don't wait for completion.
 */
void
bawrite(struct buf *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));

	/* Use bfreelist.b_bcount as a weird-ass heuristic */
	if (bfreelist.b_bcount > 4)
		bp->b_flags |= B_ASYNC;
	BWRITE(bp);
}

/*
 * Release the buffer, with no I/O implied.
 */
void
brelse(struct buf *bp)
{
	struct buf	**backp;
	uint_t		index;
	kmutex_t	*hmp;
	struct	buf	*dp;
	struct	hbuf	*hp;


	ASSERT(SEMA_HELD(&bp->b_sem));

	/*
	 * Clear the retry write flag if the buffer was written without
	 * error.  The presence of B_DELWRI means the buffer has not yet
	 * been written and the presence of B_ERROR means that an error
	 * is still occurring.
	 */
	if ((bp->b_flags & (B_ERROR | B_DELWRI | B_RETRYWRI)) == B_RETRYWRI) {
		bp->b_flags &= ~B_RETRYWRI;
	}

	/* Check for anomalous conditions */
	if (bp->b_flags & (B_ERROR|B_NOCACHE)) {
		if (bp->b_flags & B_NOCACHE) {
			/* Don't add to the freelist. Destroy it now */
			kmem_free(bp->b_un.b_addr, bp->b_bufsize);
			sema_destroy(&bp->b_sem);
			sema_destroy(&bp->b_io);
			kmem_free(bp, sizeof (struct buf));
			return;
		}
		/*
		 * If a write failed and we are supposed to retry write,
		 * don't toss the buffer.  Keep it around and mark it
		 * delayed write in the hopes that it will eventually
		 * get flushed (and still keep the system running.)
		 */
		if ((bp->b_flags & (B_READ | B_RETRYWRI)) == B_RETRYWRI) {
			bp->b_flags |= B_DELWRI;
			/* keep fsflush from trying continuously to flush */
			bp->b_start = ddi_get_lbolt();
		} else
			bp->b_flags |= B_AGE|B_STALE;
		bp->b_flags &= ~B_ERROR;
		bp->b_error = 0;
	}

	/*
	 * If delayed write is set then put in on the delayed
	 * write list instead of the free buffer list.
	 */
	index = bio_bhash(bp->b_edev, bp->b_blkno);
	hmp   = &hbuf[index].b_lock;

	mutex_enter(hmp);
	hp = &hbuf[index];
	dp = (struct buf *)hp;

	/*
	 * Make sure that the number of entries on this list are
	 * Zero <= count <= total # buffers
	 */
	ASSERT(hp->b_length >= 0);
	ASSERT(hp->b_length < nbuf);

	hp->b_length++;		/* We are adding this buffer */

	if (bp->b_flags & B_DELWRI) {
		/*
		 * This buffer goes on the delayed write buffer list
		 */
		dp = (struct buf *)&dwbuf[index];
	}
	ASSERT(bp->b_bufsize > 0);
	ASSERT(bp->b_bcount > 0);
	ASSERT(bp->b_un.b_addr != NULL);

	if (bp->b_flags & B_AGE) {
		backp = &dp->av_forw;
		(*backp)->av_back = bp;
		bp->av_forw = *backp;
		*backp = bp;
		bp->av_back = dp;
	} else {
		backp = &dp->av_back;
		(*backp)->av_forw = bp;
		bp->av_back = *backp;
		*backp = bp;
		bp->av_forw = dp;
	}
	mutex_exit(hmp);

	if (bfreelist.b_flags & B_WANTED) {
		/*
		 * Should come here very very rarely.
		 */
		mutex_enter(&bfree_lock);
		if (bfreelist.b_flags & B_WANTED) {
			bfreelist.b_flags &= ~B_WANTED;
			cv_broadcast(&bio_mem_cv);
		}
		mutex_exit(&bfree_lock);
	}

	bp->b_flags &= ~(B_WANTED|B_BUSY|B_ASYNC);
	/*
	 * Don't let anyone get the buffer off the freelist before we
	 * release our hold on it.
	 */
	sema_v(&bp->b_sem);
}

/*
 * Return a count of the number of B_BUSY buffers in the system
 * Can only be used as a good estimate.  If 'cleanit' is set,
 * try to flush all bufs.
 */
int
bio_busy(int cleanit)
{
	struct buf *bp, *dp;
	int busy = 0;
	int i;
	kmutex_t *hmp;

	for (i = 0; i < v.v_hbuf; i++) {
		dp = (struct buf *)&hbuf[i];
		hmp = &hbuf[i].b_lock;

		mutex_enter(hmp);
		for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
			if (bp->b_flags & B_BUSY)
				busy++;
		}
		mutex_exit(hmp);
	}

	if (cleanit && busy != 0) {
		bflush(NODEV);
	}

	return (busy);
}

/*
 * this interface is provided for binary compatibility.
 *
 * Assign a buffer for the given block.  If the appropriate
 * block is already associated, return it; otherwise search
 * for the oldest non-busy buffer and reassign it.
 */
struct buf *
getblk(dev_t dev, daddr_t blkno, long bsize)
{
	return (getblk_common(/* ufsvfsp */ NULL, dev,
	    blkno, bsize, /* errflg */ 0));
}

/*
 * Assign a buffer for the given block.  If the appropriate
 * block is already associated, return it; otherwise search
 * for the oldest non-busy buffer and reassign it.
 */
struct buf *
getblk_common(void * arg, dev_t dev, daddr_t blkno, long bsize, int errflg)
{
	ufsvfs_t *ufsvfsp = (struct ufsvfs *)arg;
	struct buf *bp;
	struct buf *dp;
	struct buf *nbp = NULL;
	struct buf *errbp;
	uint_t		index;
	kmutex_t	*hmp;
	struct	hbuf	*hp;

	if (getmajor(dev) >= devcnt)
		cmn_err(CE_PANIC, "blkdev");

	biostats.bio_lookup.value.ui32++;

	index = bio_bhash(dev, blkno);
	hp    = &hbuf[index];
	dp    = (struct buf *)hp;
	hmp   = &hp->b_lock;

	mutex_enter(hmp);
loop:
	for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
		if (bp->b_blkno != blkno || bp->b_edev != dev ||
		    (bp->b_flags & B_STALE))
			continue;
		/*
		 * Avoid holding the hash lock in the event that
		 * the buffer is locked by someone. Since the hash chain
		 * may change when we drop the hash lock
		 * we have to start at the beginning of the chain if the
		 * buffer identity/contents aren't valid.
		 */
		if (!sema_tryp(&bp->b_sem)) {
			biostats.bio_bufbusy.value.ui32++;
			mutex_exit(hmp);
			/*
			 * OK, we are dealing with a busy buffer.
			 * In the case that we are panicking and we
			 * got called from bread(), we have some chance
			 * for error recovery. So better bail out from
			 * here since sema_p() won't block. If we got
			 * called directly from ufs routines, there is
			 * no way to report an error yet.
			 */
			if (panicstr && errflg)
				goto errout;
			/*
			 * For the following line of code to work
			 * correctly never kmem_free the buffer "header".
			 */
			sema_p(&bp->b_sem);
			if (bp->b_blkno != blkno || bp->b_edev != dev ||
			    (bp->b_flags & B_STALE)) {
				sema_v(&bp->b_sem);
				mutex_enter(hmp);
				goto loop;	/* start over */
			}
			mutex_enter(hmp);
		}
		/* Found */
		biostats.bio_hit.value.ui32++;
		bp->b_flags &= ~B_AGE;

		/*
		 * Yank it off the free/delayed write lists
		 */
		hp->b_length--;
		notavail(bp);
		mutex_exit(hmp);

		ASSERT((bp->b_flags & B_NOCACHE) == NULL);

		if (nbp == NULL) {
			/*
			 * Make the common path short.
			 */
			ASSERT(SEMA_HELD(&bp->b_sem));
			return (bp);
		}

		biostats.bio_bufdup.value.ui32++;

		/*
		 * The buffer must have entered during the lock upgrade
		 * so free the new buffer we allocated and return the
		 * found buffer.
		 */
		kmem_free(nbp->b_un.b_addr, nbp->b_bufsize);
		nbp->b_un.b_addr = NULL;

		/*
		 * Account for the memory
		 */
		mutex_enter(&bfree_lock);
		bfreelist.b_bufsize += nbp->b_bufsize;
		mutex_exit(&bfree_lock);

		/*
		 * Destroy buf identity, and place on avail list
		 */
		nbp->b_dev = (o_dev_t)NODEV;
		nbp->b_edev = NODEV;
		nbp->b_flags = 0;
		nbp->b_file = NULL;
		nbp->b_offset = -1;

		sema_v(&nbp->b_sem);
		bio_bhdr_free(nbp);

		ASSERT(SEMA_HELD(&bp->b_sem));
		return (bp);
	}

	/*
	 * bio_getfreeblk may block so check the hash chain again.
	 */
	if (nbp == NULL) {
		mutex_exit(hmp);
		nbp = bio_getfreeblk(bsize);
		mutex_enter(hmp);
		goto loop;
	}

	/*
	 * New buffer. Assign nbp and stick it on the hash.
	 */
	nbp->b_flags = B_BUSY;
	nbp->b_edev = dev;
	nbp->b_dev = (o_dev_t)cmpdev(dev);
	nbp->b_blkno = blkno;
	nbp->b_iodone = NULL;
	nbp->b_bcount = bsize;
	/*
	 * If we are given a ufsvfsp and the vfs_root field is NULL
	 * then this must be I/O for a superblock.  A superblock's
	 * buffer is set up in mountfs() and there is no root vnode
	 * at that point.
	 */
	if (ufsvfsp && ufsvfsp->vfs_root) {
		nbp->b_vp = ufsvfsp->vfs_root;
	} else {
		nbp->b_vp = NULL;
	}

	ASSERT((nbp->b_flags & B_NOCACHE) == NULL);

	binshash(nbp, dp);
	mutex_exit(hmp);

	ASSERT(SEMA_HELD(&nbp->b_sem));

	return (nbp);


	/*
	 * Come here in case of an internal error. At this point we couldn't
	 * get a buffer, but he have to return one. Hence we allocate some
	 * kind of error reply buffer on the fly. This buffer is marked as
	 * B_NOCACHE | B_AGE | B_ERROR | B_DONE to assure the following:
	 *	- B_ERROR will indicate error to the caller.
	 *	- B_DONE will prevent us from reading the buffer from
	 *	  the device.
	 *	- B_NOCACHE will cause that this buffer gets free'd in
	 *	  brelse().
	 */

errout:
	errbp = geteblk();
	sema_p(&errbp->b_sem);
	errbp->b_flags &= ~B_BUSY;
	errbp->b_flags |= (B_ERROR | B_DONE);
	return (errbp);
}

/*
 * Get an empty block, not assigned to any particular device.
 * Returns a locked buffer that is not on any hash or free list.
 */
struct buf *
ngeteblk(long bsize)
{
	struct buf *bp;

	bp = kmem_alloc(sizeof (struct buf), KM_SLEEP);
	bioinit(bp);
	bp->av_forw = bp->av_back = NULL;
	bp->b_un.b_addr = kmem_alloc(bsize, KM_SLEEP);
	bp->b_bufsize = bsize;
	bp->b_flags = B_BUSY | B_NOCACHE | B_AGE;
	bp->b_dev = (o_dev_t)NODEV;
	bp->b_edev = NODEV;
	bp->b_lblkno = 0;
	bp->b_bcount = bsize;
	bp->b_iodone = NULL;
	return (bp);
}

/*
 * Interface of geteblk() is kept intact to maintain driver compatibility.
 * Use ngeteblk() to allocate block size other than 1 KB.
 */
struct buf *
geteblk(void)
{
	return (ngeteblk((long)1024));
}

/*
 * Return a buffer w/o sleeping
 */
struct buf *
trygetblk(dev_t dev, daddr_t blkno)
{
	struct buf	*bp;
	struct buf	*dp;
	struct hbuf	*hp;
	kmutex_t	*hmp;
	uint_t		index;

	index = bio_bhash(dev, blkno);
	hp = &hbuf[index];
	hmp = &hp->b_lock;

	if (!mutex_tryenter(hmp))
		return (NULL);

	dp = (struct buf *)hp;
	for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
		if (bp->b_blkno != blkno || bp->b_edev != dev ||
		    (bp->b_flags & B_STALE))
			continue;
		/*
		 * Get access to a valid buffer without sleeping
		 */
		if (sema_tryp(&bp->b_sem)) {
			if (bp->b_flags & B_DONE) {
				hp->b_length--;
				notavail(bp);
				mutex_exit(hmp);
				return (bp);
			} else {
				sema_v(&bp->b_sem);
				break;
			}
		}
		break;
	}
	mutex_exit(hmp);
	return (NULL);
}

/*
 * Wait for I/O completion on the buffer; return errors
 * to the user.
 */
int
iowait(struct buf *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	return (biowait(bp));
}

/*
 * Mark I/O complete on a buffer, release it if I/O is asynchronous,
 * and wake up anyone waiting for it.
 */
void
iodone(struct buf *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	(void) biodone(bp);
}

/*
 * Zero the core associated with a buffer.
 */
void
clrbuf(struct buf *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	bzero(bp->b_un.b_addr, bp->b_bcount);
	bp->b_resid = 0;
}


/*
 * Make sure all write-behind blocks on dev (or NODEV for all)
 * are flushed out.
 */
void
bflush(dev_t dev)
{
	struct buf *bp, *dp;
	struct hbuf *hp;
	struct buf *delwri_list = EMPTY_LIST;
	int i, index;
	kmutex_t *hmp;

	mutex_enter(&blist_lock);
	/*
	 * Wait for any invalidates or flushes ahead of us to finish.
	 * We really could split blist_lock up per device for better
	 * parallelism here.
	 */
	while (bio_doinginval || bio_doingflush) {
		bio_flinv_cv_wanted = 1;
		cv_wait(&bio_flushinval_cv, &blist_lock);
	}
	bio_doingflush++;
	/*
	 * Gather all B_DELWRI buffer for device.
	 * Lock ordering is b_sem > hash lock (brelse).
	 * Since we are finding the buffer via the delayed write list,
	 * it may be busy and we would block trying to get the
	 * b_sem lock while holding hash lock. So transfer all the
	 * candidates on the delwri_list and then drop the hash locks.
	 */
	for (i = 0; i < v.v_hbuf; i++) {
		hmp = &hbuf[i].b_lock;
		dp = (struct buf *)&dwbuf[i];
		mutex_enter(hmp);
		for (bp = dp->av_forw; bp != dp; bp = bp->av_forw) {
			if (dev == NODEV || bp->b_edev == dev) {
				if (bp->b_list == NULL) {
					bp->b_list = delwri_list;
					delwri_list = bp;
				}
			}
		}
		mutex_exit(hmp);
	}
	mutex_exit(&blist_lock);

	/*
	 * Now that the hash locks have been dropped grab the semaphores
	 * and write back all the buffers that have B_DELWRI set.
	 */
	while (delwri_list != EMPTY_LIST) {
		bp = delwri_list;

		sema_p(&bp->b_sem);	/* may block */
		if ((dev != bp->b_edev && dev != NODEV) ||
		    (panicstr && bp->b_flags & B_BUSY)) {
			sema_v(&bp->b_sem);
			delwri_list = bp->b_list;
			bp->b_list = NULL;
			continue;	/* No longer a candidate */
		}
		if (bp->b_flags & B_DELWRI) {
			index = bio_bhash(bp->b_edev, bp->b_blkno);
			hp = &hbuf[index];
			hmp = &hp->b_lock;
			dp = (struct buf *)hp;

			bp->b_flags |= B_ASYNC;
			mutex_enter(hmp);
			hp->b_length--;
			notavail(bp);
			mutex_exit(hmp);
			if (bp->b_vp == NULL) {		/* !ufs */
				BWRITE(bp);
			} else {			/* ufs */
				UFS_BWRITE(VTOI(bp->b_vp)->i_ufsvfs, bp);
			}
		} else {
			sema_v(&bp->b_sem);
		}
		delwri_list = bp->b_list;
		bp->b_list = NULL;
	}
	mutex_enter(&blist_lock);
	bio_doingflush--;
	if (bio_flinv_cv_wanted) {
		bio_flinv_cv_wanted = 0;
		cv_broadcast(&bio_flushinval_cv);
	}
	mutex_exit(&blist_lock);
}

/*
 * Ensure that a specified block is up-to-date on disk.
 */
void
blkflush(dev_t dev, daddr_t blkno)
{
	struct buf *bp, *dp;
	struct hbuf *hp;
	struct buf *sbp = NULL;
	uint_t index;
	kmutex_t *hmp;

	index = bio_bhash(dev, blkno);
	hp    = &hbuf[index];
	dp    = (struct buf *)hp;
	hmp   = &hp->b_lock;

	/*
	 * Identify the buffer in the cache belonging to
	 * this device and blkno (if any).
	 */
	mutex_enter(hmp);
	for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
		if (bp->b_blkno != blkno || bp->b_edev != dev ||
		    (bp->b_flags & B_STALE))
			continue;
		sbp = bp;
		break;
	}
	mutex_exit(hmp);
	if (sbp == NULL)
		return;
	/*
	 * Now check the buffer we have identified and
	 * make sure it still belongs to the device and is B_DELWRI
	 */
	sema_p(&sbp->b_sem);
	if (sbp->b_blkno == blkno && sbp->b_edev == dev &&
	    (sbp->b_flags & (B_DELWRI|B_STALE)) == B_DELWRI) {
		mutex_enter(hmp);
		hp->b_length--;
		notavail(sbp);
		mutex_exit(hmp);
		/*
		 * XXX - There is nothing to guarantee a synchronous
		 * write here if the B_ASYNC flag is set.  This needs
		 * some investigation.
		 */
		if (sbp->b_vp == NULL) {		/* !ufs */
			BWRITE(sbp);	/* synchronous write */
		} else {				/* ufs */
			UFS_BWRITE(VTOI(sbp->b_vp)->i_ufsvfs, sbp);
		}
	} else {
		sema_v(&sbp->b_sem);
	}
}

/*
 * Same as binval, except can force-invalidate delayed-write buffers
 * (which are not be already flushed because of device errors).  Also
 * makes sure that the retry write flag is cleared.
 */
int
bfinval(dev_t dev, int force)
{
	struct buf *dp;
	struct buf *bp;
	struct buf *binval_list = EMPTY_LIST;
	int i, error = 0;
	kmutex_t *hmp;
	uint_t index;
	struct buf **backp;

	mutex_enter(&blist_lock);
	/*
	 * Wait for any flushes ahead of us to finish, it's ok to
	 * do invalidates in parallel.
	 */
	while (bio_doingflush) {
		bio_flinv_cv_wanted = 1;
		cv_wait(&bio_flushinval_cv, &blist_lock);
	}
	bio_doinginval++;

	/* Gather bp's */
	for (i = 0; i < v.v_hbuf; i++) {
		dp = (struct buf *)&hbuf[i];
		hmp = &hbuf[i].b_lock;

		mutex_enter(hmp);
		for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
			if (bp->b_edev == dev) {
				if (bp->b_list == NULL) {
					bp->b_list = binval_list;
					binval_list = bp;
				}
			}
		}
		mutex_exit(hmp);
	}
	mutex_exit(&blist_lock);

	/* Invalidate all bp's found */
	while (binval_list != EMPTY_LIST) {
		bp = binval_list;

		sema_p(&bp->b_sem);
		if (bp->b_edev == dev) {
			if (force && (bp->b_flags & B_DELWRI)) {
				/* clear B_DELWRI, move to non-dw freelist */
				index = bio_bhash(bp->b_edev, bp->b_blkno);
				hmp = &hbuf[index].b_lock;
				dp = (struct buf *)&hbuf[index];
				mutex_enter(hmp);

				/* remove from delayed write freelist */
				notavail(bp);

				/* add to B_AGE side of non-dw freelist */
				backp = &dp->av_forw;
				(*backp)->av_back = bp;
				bp->av_forw = *backp;
				*backp = bp;
				bp->av_back = dp;

				/*
				 * make sure write retries and busy are cleared
				 */
				bp->b_flags &=
				    ~(B_BUSY | B_DELWRI | B_RETRYWRI);
				mutex_exit(hmp);
			}
			if ((bp->b_flags & B_DELWRI) == 0)
				bp->b_flags |= B_STALE|B_AGE;
			else
				error = EIO;
		}
		sema_v(&bp->b_sem);
		binval_list = bp->b_list;
		bp->b_list = NULL;
	}
	mutex_enter(&blist_lock);
	bio_doinginval--;
	if (bio_flinv_cv_wanted) {
		cv_broadcast(&bio_flushinval_cv);
		bio_flinv_cv_wanted = 0;
	}
	mutex_exit(&blist_lock);
	return (error);
}

/*
 * If possible, invalidate blocks for a dev on demand
 */
void
binval(dev_t dev)
{
	(void) bfinval(dev, 0);
}

/*
 * Initialize the buffer I/O system by freeing
 * all buffers and setting all device hash buffer lists to empty.
 */
void
binit(void)
{
	struct buf *bp;
	unsigned int i, pct;
	ulong_t	bio_max_hwm, bio_default_hwm;

	/*
	 * Maximum/Default values for bufhwm are set to the smallest of:
	 *	- BIO_MAX_PERCENT resp. BIO_BUF_PERCENT of real memory
	 *	- 1/4 of kernel virtual memory
	 *	- INT32_MAX to prevent overflows of v.v_bufhwm (which is int).
	 * Additionally, in order to allow simple tuning by percentage of
	 * physical memory, bufhwm_pct is used to calculate the default if
	 * the value of this tunable is between 0 and BIO_MAX_PERCENT.
	 *
	 * Since the unit for v.v_bufhwm is kilobytes, this allows for
	 * a maximum of 1024 * 2GB == 2TB memory usage by buffer headers.
	 */
	bio_max_hwm = MIN(physmem / BIO_MAX_PERCENT,
	    btop(vmem_size(heap_arena, VMEM_FREE)) / 4) * (PAGESIZE / 1024);
	bio_max_hwm = MIN(INT32_MAX, bio_max_hwm);

	pct = BIO_BUF_PERCENT;
	if (bufhwm_pct != 0 &&
	    ((pct = 100 / bufhwm_pct) < BIO_MAX_PERCENT)) {
		pct = BIO_BUF_PERCENT;
		/*
		 * Invalid user specified value, emit a warning.
		 */
		cmn_err(CE_WARN, "binit: bufhwm_pct(%d) out of \
		    range(1..%d). Using %d as default.",
		    bufhwm_pct,
		    100 / BIO_MAX_PERCENT, 100 / BIO_BUF_PERCENT);
	}

	bio_default_hwm = MIN(physmem / pct,
	    btop(vmem_size(heap_arena, VMEM_FREE)) / 4) * (PAGESIZE / 1024);
	bio_default_hwm = MIN(INT32_MAX, bio_default_hwm);

	if ((v.v_bufhwm = bufhwm) == 0)
		v.v_bufhwm = bio_default_hwm;

	if (v.v_bufhwm < BIO_MIN_HWM || v.v_bufhwm > bio_max_hwm) {
		v.v_bufhwm = (int)bio_max_hwm;
		/*
		 * Invalid user specified value, emit a warning.
		 */
		cmn_err(CE_WARN,
		    "binit: bufhwm(%d) out \
		    of range(%d..%lu). Using %lu as default",
		    bufhwm,
		    BIO_MIN_HWM, bio_max_hwm, bio_max_hwm);
	}

	/*
	 * Determine the number of hash buckets. Default is to
	 * create ~BIO_HASHLEN entries per chain based on MAXBSIZE buffers.
	 * Round up number to the next power of 2.
	 */
	v.v_hbuf = 1 << highbit((((ulong_t)v.v_bufhwm * 1024) / MAXBSIZE) /
	    BIO_HASHLEN);
	v.v_hmask = v.v_hbuf - 1;
	v.v_buf = BIO_BHDR_POOL;

	hbuf = kmem_zalloc(v.v_hbuf * sizeof (struct hbuf), KM_SLEEP);

	dwbuf = kmem_zalloc(v.v_hbuf * sizeof (struct dwbuf), KM_SLEEP);

	bfreelist.b_bufsize = (size_t)v.v_bufhwm * 1024;
	bp = &bfreelist;
	bp->b_forw = bp->b_back = bp->av_forw = bp->av_back = bp;

	for (i = 0; i < v.v_hbuf; i++) {
		hbuf[i].b_forw = hbuf[i].b_back = (struct buf *)&hbuf[i];
		hbuf[i].av_forw = hbuf[i].av_back = (struct buf *)&hbuf[i];

		/*
		 * Initialize the delayed write buffer list.
		 */
		dwbuf[i].b_forw = dwbuf[i].b_back = (struct buf *)&dwbuf[i];
		dwbuf[i].av_forw = dwbuf[i].av_back = (struct buf *)&dwbuf[i];
	}
}

/*
 * Wait for I/O completion on the buffer; return error code.
 * If bp was for synchronous I/O, bp is invalid and associated
 * resources are freed on return.
 */
int
biowait(struct buf *bp)
{
	int error = 0;
	struct cpu *cpup;

	ASSERT(SEMA_HELD(&bp->b_sem));

	cpup = CPU;
	atomic_inc_64(&cpup->cpu_stats.sys.iowait);
	DTRACE_IO1(wait__start, struct buf *, bp);

	/*
	 * In case of panic, busy wait for completion
	 */
	if (panicstr) {
		while ((bp->b_flags & B_DONE) == 0)
			drv_usecwait(10);
	} else
		sema_p(&bp->b_io);

	DTRACE_IO1(wait__done, struct buf *, bp);
	atomic_dec_64(&cpup->cpu_stats.sys.iowait);

	error = geterror(bp);
	if ((bp->b_flags & B_ASYNC) == 0) {
		if (bp->b_flags & B_REMAPPED)
			bp_mapout(bp);
	}
	return (error);
}

static void
biodone_tnf_probe(struct buf *bp)
{
	/* Kernel probe */
	TNF_PROBE_3(biodone, "io blockio", /* CSTYLED */,
	    tnf_device,		device,		bp->b_edev,
	    tnf_diskaddr,	block,		bp->b_lblkno,
	    tnf_opaque,		buf,		bp);
}

/*
 * Mark I/O complete on a buffer, release it if I/O is asynchronous,
 * and wake up anyone waiting for it.
 */
void
biodone(struct buf *bp)
{
	if (bp->b_flags & B_STARTED) {
		DTRACE_IO1(done, struct buf *, bp);
		bp->b_flags &= ~B_STARTED;
	}

	/*
	 * Call the TNF probe here instead of the inline code
	 * to force our compiler to use the tail call optimization.
	 */
	biodone_tnf_probe(bp);

	if (bp->b_iodone != NULL) {
		(*(bp->b_iodone))(bp);
		return;
	}
	ASSERT((bp->b_flags & B_DONE) == 0);
	ASSERT(SEMA_HELD(&bp->b_sem));
	bp->b_flags |= B_DONE;
	if (bp->b_flags & B_ASYNC) {
		if (bp->b_flags & (B_PAGEIO|B_REMAPPED))
			bio_pageio_done(bp);
		else
			brelse(bp);	/* release bp to freelist */
	} else {
		sema_v(&bp->b_io);
	}
}

/*
 * Pick up the device's error number and pass it to the user;
 * if there is an error but the number is 0 set a generalized code.
 */
int
geterror(struct buf *bp)
{
	int error = 0;

	ASSERT(SEMA_HELD(&bp->b_sem));
	if (bp->b_flags & B_ERROR) {
		error = bp->b_error;
		if (!error)
			error = EIO;
	}
	return (error);
}

/*
 * Support for pageio buffers.
 *
 * This stuff should be generalized to provide a generalized bp
 * header facility that can be used for things other than pageio.
 */

/*
 * Allocate and initialize a buf struct for use with pageio.
 */
struct buf *
pageio_setup(struct page *pp, size_t len, struct vnode *vp, int flags)
{
	struct buf *bp;
	struct cpu *cpup;

	if (flags & B_READ) {
		CPU_STATS_ENTER_K();
		cpup = CPU;	/* get pointer AFTER preemption is disabled */
		CPU_STATS_ADDQ(cpup, vm, pgin, 1);
		CPU_STATS_ADDQ(cpup, vm, pgpgin, btopr(len));

		atomic_add_64(&curzone->zone_pgpgin, btopr(len));

		if ((flags & B_ASYNC) == 0) {
			klwp_t *lwp = ttolwp(curthread);
			if (lwp != NULL)
				lwp->lwp_ru.majflt++;
			CPU_STATS_ADDQ(cpup, vm, maj_fault, 1);
			/* Kernel probe */
			TNF_PROBE_2(major_fault, "vm pagefault", /* CSTYLED */,
			    tnf_opaque,		vnode,		pp->p_vnode,
			    tnf_offset,		offset,		pp->p_offset);
		}
		/*
		 * Update statistics for pages being paged in
		 */
		if (pp != NULL && pp->p_vnode != NULL) {
			if (IS_SWAPFSVP(pp->p_vnode)) {
				CPU_STATS_ADDQ(cpup, vm, anonpgin, btopr(len));
				atomic_add_64(&curzone->zone_anonpgin,
				    btopr(len));
			} else {
				if (pp->p_vnode->v_flag & VVMEXEC) {
					CPU_STATS_ADDQ(cpup, vm, execpgin,
					    btopr(len));
					atomic_add_64(&curzone->zone_execpgin,
					    btopr(len));
				} else {
					CPU_STATS_ADDQ(cpup, vm, fspgin,
					    btopr(len));
					atomic_add_64(&curzone->zone_fspgin,
					    btopr(len));
				}
			}
		}
		CPU_STATS_EXIT_K();
		TRACE_1(TR_FAC_VM, TR_PAGE_WS_IN,
		    "page_ws_in:pp %p", pp);
		/* Kernel probe */
		TNF_PROBE_3(pagein, "vm pageio io", /* CSTYLED */,
		    tnf_opaque,	vnode,	pp->p_vnode,
		    tnf_offset,	offset,	pp->p_offset,
		    tnf_size,	size,	len);
	}

	bp = kmem_zalloc(sizeof (struct buf), KM_SLEEP);
	bp->b_bcount = len;
	bp->b_bufsize = len;
	bp->b_pages = pp;
	bp->b_flags = B_PAGEIO | B_NOCACHE | B_BUSY | flags;
	bp->b_offset = -1;
	sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);

	/* Initialize bp->b_sem in "locked" state */
	sema_init(&bp->b_sem, 0, NULL, SEMA_DEFAULT, NULL);

	VN_HOLD(vp);
	bp->b_vp = vp;
	THREAD_KPRI_RELEASE_N(btopr(len)); /* release kpri from page_locks */

	/*
	 * Caller sets dev & blkno and can adjust
	 * b_addr for page offset and can use bp_mapin
	 * to make pages kernel addressable.
	 */
	return (bp);
}

void
pageio_done(struct buf *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	if (bp->b_flags & B_REMAPPED)
		bp_mapout(bp);
	VN_RELE(bp->b_vp);
	bp->b_vp = NULL;
	ASSERT((bp->b_flags & B_NOCACHE) != 0);

	/* A sema_v(bp->b_sem) is implied if we are destroying it */
	sema_destroy(&bp->b_sem);
	sema_destroy(&bp->b_io);
	kmem_free(bp, sizeof (struct buf));
}

/*
 * Check to see whether the buffers, except the one pointed by sbp,
 * associated with the device are busy.
 * NOTE: This expensive operation shall be improved together with ufs_icheck().
 */
int
bcheck(dev_t dev, struct buf *sbp)
{
	struct buf	*bp;
	struct buf	*dp;
	int i;
	kmutex_t *hmp;

	/*
	 * check for busy bufs for this filesystem
	 */
	for (i = 0; i < v.v_hbuf; i++) {
		dp = (struct buf *)&hbuf[i];
		hmp = &hbuf[i].b_lock;

		mutex_enter(hmp);
		for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
			/*
			 * if buf is busy or dirty, then filesystem is busy
			 */
			if ((bp->b_edev == dev) &&
			    ((bp->b_flags & B_STALE) == 0) &&
			    (bp->b_flags & (B_DELWRI|B_BUSY)) &&
			    (bp != sbp)) {
				mutex_exit(hmp);
				return (1);
			}
		}
		mutex_exit(hmp);
	}
	return (0);
}

/*
 * Hash two 32 bit entities.
 */
int
hash2ints(int x, int y)
{
	int hash = 0;

	hash = x - 1;
	hash = ((hash * 7) + (x >> 8)) - 1;
	hash = ((hash * 7) + (x >> 16)) - 1;
	hash = ((hash * 7) + (x >> 24)) - 1;
	hash = ((hash * 7) + y) - 1;
	hash = ((hash * 7) + (y >> 8)) - 1;
	hash = ((hash * 7) + (y >> 16)) - 1;
	hash = ((hash * 7) + (y >> 24)) - 1;

	return (hash);
}


/*
 * Return a new buffer struct.
 *	Create a new buffer if we haven't gone over our high water
 *	mark for memory, otherwise try to get one off the freelist.
 *
 * Returns a locked buf that has no id and is not on any hash or free
 * list.
 */
static struct buf *
bio_getfreeblk(long bsize)
{
	struct buf *bp, *dp;
	struct hbuf *hp;
	kmutex_t	*hmp;
	uint_t		start, end;

	/*
	 * mutex_enter(&bfree_lock);
	 * bfreelist.b_bufsize represents the amount of memory
	 * mutex_exit(&bfree_lock); protect ref to bfreelist
	 * we are allowed to allocate in the cache before we hit our hwm.
	 */
	bio_mem_get(bsize);	/* Account for our memory request */

again:
	bp = bio_bhdr_alloc();	/* Get a buf hdr */
	sema_p(&bp->b_sem);	/* Should never fail */

	ASSERT(bp->b_un.b_addr == NULL);
	bp->b_un.b_addr = kmem_alloc(bsize, KM_NOSLEEP);
	if (bp->b_un.b_addr != NULL) {
		/*
		 * Make the common path short
		 */
		bp->b_bufsize = bsize;
		ASSERT(SEMA_HELD(&bp->b_sem));
		return (bp);
	} else {
		struct buf *save;

		save = bp;	/* Save bp we allocated */
		start = end = lastindex;

		biostats.bio_bufwant.value.ui32++;

		/*
		 * Memory isn't available from the system now. Scan
		 * the hash buckets till enough space is found.
		 */
		do {
			hp = &hbuf[start];
			hmp = &hp->b_lock;
			dp = (struct buf *)hp;

			mutex_enter(hmp);
			bp = dp->av_forw;

			while (bp != dp) {

				ASSERT(bp != NULL);

				if (!sema_tryp(&bp->b_sem)) {
					bp = bp->av_forw;
					continue;
				}

				/*
				 * Since we are going down the freelist
				 * associated with this hash bucket the
				 * B_DELWRI flag should not be set.
				 */
				ASSERT(!(bp->b_flags & B_DELWRI));

				if (bp->b_bufsize == bsize) {
					hp->b_length--;
					notavail(bp);
					bremhash(bp);
					mutex_exit(hmp);

					/*
					 * Didn't kmem_alloc any more, so don't
					 * count it twice.
					 */
					mutex_enter(&bfree_lock);
					bfreelist.b_bufsize += bsize;
					mutex_exit(&bfree_lock);

					/*
					 * Update the lastindex value.
					 */
					lastindex = start;

					/*
					 * Put our saved bp back on the list
					 */
					sema_v(&save->b_sem);
					bio_bhdr_free(save);
					ASSERT(SEMA_HELD(&bp->b_sem));
					return (bp);
				}
				sema_v(&bp->b_sem);
				bp = bp->av_forw;
			}
			mutex_exit(hmp);
			start = ((start + 1) % v.v_hbuf);
		} while (start != end);

		biostats.bio_bufwait.value.ui32++;
		bp = save;		/* Use original bp */
		bp->b_un.b_addr = kmem_alloc(bsize, KM_SLEEP);
	}

	bp->b_bufsize = bsize;
	ASSERT(SEMA_HELD(&bp->b_sem));
	return (bp);
}

/*
 * Allocate a buffer header. If none currently available, allocate
 * a new pool.
 */
static struct buf *
bio_bhdr_alloc(void)
{
	struct buf *dp, *sdp;
	struct buf *bp;
	int i;

	for (;;) {
		mutex_enter(&bhdr_lock);
		if (bhdrlist != NULL) {
			bp = bhdrlist;
			bhdrlist = bp->av_forw;
			mutex_exit(&bhdr_lock);
			bp->av_forw = NULL;
			return (bp);
		}
		mutex_exit(&bhdr_lock);

		/*
		 * Need to allocate a new pool. If the system is currently
		 * out of memory, then try freeing things on the freelist.
		 */
		dp = kmem_zalloc(sizeof (struct buf) * v.v_buf, KM_NOSLEEP);
		if (dp == NULL) {
			/*
			 * System can't give us a pool of headers, try
			 * recycling from the free lists.
			 */
			bio_recycle(BIO_HEADER, 0);
		} else {
			sdp = dp;
			for (i = 0; i < v.v_buf; i++, dp++) {
				/*
				 * The next two lines are needed since NODEV
				 * is -1 and not NULL
				 */
				dp->b_dev = (o_dev_t)NODEV;
				dp->b_edev = NODEV;
				dp->av_forw = dp + 1;
				sema_init(&dp->b_sem, 1, NULL, SEMA_DEFAULT,
				    NULL);
				sema_init(&dp->b_io, 0, NULL, SEMA_DEFAULT,
				    NULL);
				dp->b_offset = -1;
			}
			mutex_enter(&bhdr_lock);
			(--dp)->av_forw = bhdrlist;	/* Fix last pointer */
			bhdrlist = sdp;
			nbuf += v.v_buf;
			bp = bhdrlist;
			bhdrlist = bp->av_forw;
			mutex_exit(&bhdr_lock);

			bp->av_forw = NULL;
			return (bp);
		}
	}
}

static  void
bio_bhdr_free(struct buf *bp)
{
	ASSERT(bp->b_back == NULL);
	ASSERT(bp->b_forw == NULL);
	ASSERT(bp->av_back == NULL);
	ASSERT(bp->av_forw == NULL);
	ASSERT(bp->b_un.b_addr == NULL);
	ASSERT(bp->b_dev == (o_dev_t)NODEV);
	ASSERT(bp->b_edev == NODEV);
	ASSERT(bp->b_flags == 0);

	mutex_enter(&bhdr_lock);
	bp->av_forw = bhdrlist;
	bhdrlist = bp;
	mutex_exit(&bhdr_lock);
}

/*
 * If we haven't gone over the high water mark, it's o.k. to
 * allocate more buffer space, otherwise recycle buffers
 * from the freelist until enough memory is free for a bsize request.
 *
 * We account for this memory, even though
 * we don't allocate it here.
 */
static void
bio_mem_get(long bsize)
{
	mutex_enter(&bfree_lock);
	if (bfreelist.b_bufsize > bsize) {
		bfreelist.b_bufsize -= bsize;
		mutex_exit(&bfree_lock);
		return;
	}
	mutex_exit(&bfree_lock);
	bio_recycle(BIO_MEM, bsize);
}

/*
 * flush a list of delayed write buffers.
 * (currently used only by bio_recycle below.)
 */
static void
bio_flushlist(struct buf *delwri_list)
{
	struct buf *bp;

	while (delwri_list != EMPTY_LIST) {
		bp = delwri_list;
		bp->b_flags |= B_AGE | B_ASYNC;
		if (bp->b_vp == NULL) {		/* !ufs */
			BWRITE(bp);
		} else {			/* ufs */
			UFS_BWRITE(VTOI(bp->b_vp)->i_ufsvfs, bp);
		}
		delwri_list = bp->b_list;
		bp->b_list = NULL;
	}
}

/*
 * Start recycling buffers on the freelist for one of 2 reasons:
 *	- we need a buffer header
 *	- we need to free up memory
 * Once started we continue to recycle buffers until the B_AGE
 * buffers are gone.
 */
static void
bio_recycle(int want, long bsize)
{
	struct buf *bp, *dp, *dwp, *nbp;
	struct hbuf *hp;
	int	found = 0;
	kmutex_t	*hmp;
	int		start, end;
	struct buf *delwri_list = EMPTY_LIST;

	/*
	 * Recycle buffers.
	 */
top:
	start = end = lastindex;
	do {
		hp = &hbuf[start];
		hmp = &hp->b_lock;
		dp = (struct buf *)hp;

		mutex_enter(hmp);
		bp = dp->av_forw;

		while (bp != dp) {

			ASSERT(bp != NULL);

			if (!sema_tryp(&bp->b_sem)) {
				bp = bp->av_forw;
				continue;
			}
			/*
			 * Do we really want to nuke all of the B_AGE stuff??
			 */
			if ((bp->b_flags & B_AGE) == 0 && found) {
				sema_v(&bp->b_sem);
				mutex_exit(hmp);
				lastindex = start;
				return;	/* All done */
			}

			ASSERT(MUTEX_HELD(&hp->b_lock));
			ASSERT(!(bp->b_flags & B_DELWRI));
			hp->b_length--;
			notavail(bp);

			/*
			 * Remove bhdr from cache, free up memory,
			 * and add the hdr to the freelist.
			 */
			bremhash(bp);
			mutex_exit(hmp);

			if (bp->b_bufsize) {
				kmem_free(bp->b_un.b_addr, bp->b_bufsize);
				bp->b_un.b_addr = NULL;
				mutex_enter(&bfree_lock);
				bfreelist.b_bufsize += bp->b_bufsize;
				mutex_exit(&bfree_lock);
			}

			bp->b_dev = (o_dev_t)NODEV;
			bp->b_edev = NODEV;
			bp->b_flags = 0;
			sema_v(&bp->b_sem);
			bio_bhdr_free(bp);
			if (want == BIO_HEADER) {
				found = 1;
			} else {
				ASSERT(want == BIO_MEM);
				if (!found && bfreelist.b_bufsize >= bsize) {
					/* Account for the memory we want */
					mutex_enter(&bfree_lock);
					if (bfreelist.b_bufsize >= bsize) {
						bfreelist.b_bufsize -= bsize;
						found = 1;
					}
					mutex_exit(&bfree_lock);
				}
			}

			/*
			 * Since we dropped hmp start from the
			 * begining.
			 */
			mutex_enter(hmp);
			bp = dp->av_forw;
		}
		mutex_exit(hmp);

		/*
		 * Look at the delayed write list.
		 * First gather into a private list, then write them.
		 */
		dwp = (struct buf *)&dwbuf[start];
		mutex_enter(&blist_lock);
		bio_doingflush++;
		mutex_enter(hmp);
		for (bp = dwp->av_forw; bp != dwp; bp = nbp) {

			ASSERT(bp != NULL);
			nbp = bp->av_forw;

			if (!sema_tryp(&bp->b_sem))
				continue;
			ASSERT(bp->b_flags & B_DELWRI);
			/*
			 * Do we really want to nuke all of the B_AGE stuff??
			 */

			if ((bp->b_flags & B_AGE) == 0 && found) {
				sema_v(&bp->b_sem);
				mutex_exit(hmp);
				lastindex = start;
				mutex_exit(&blist_lock);
				bio_flushlist(delwri_list);
				mutex_enter(&blist_lock);
				bio_doingflush--;
				if (bio_flinv_cv_wanted) {
					bio_flinv_cv_wanted = 0;
					cv_broadcast(&bio_flushinval_cv);
				}
				mutex_exit(&blist_lock);
				return; /* All done */
			}

			/*
			 * If the buffer is already on a flush or
			 * invalidate list then just skip it.
			 */
			if (bp->b_list != NULL) {
				sema_v(&bp->b_sem);
				continue;
			}
			/*
			 * We are still on the same bucket.
			 */
			hp->b_length--;
			notavail(bp);
			bp->b_list = delwri_list;
			delwri_list = bp;
		}
		mutex_exit(hmp);
		mutex_exit(&blist_lock);
		bio_flushlist(delwri_list);
		delwri_list = EMPTY_LIST;
		mutex_enter(&blist_lock);
		bio_doingflush--;
		if (bio_flinv_cv_wanted) {
			bio_flinv_cv_wanted = 0;
			cv_broadcast(&bio_flushinval_cv);
		}
		mutex_exit(&blist_lock);
		start = (start + 1) % v.v_hbuf;

	} while (start != end);

	if (found)
		return;

	/*
	 * Free lists exhausted and we haven't satisfied the request.
	 * Wait here for more entries to be added to freelist.
	 * Because this might have just happened, make it timed.
	 */
	mutex_enter(&bfree_lock);
	bfreelist.b_flags |= B_WANTED;
	(void) cv_reltimedwait(&bio_mem_cv, &bfree_lock, hz, TR_CLOCK_TICK);
	mutex_exit(&bfree_lock);
	goto top;
}

/*
 * See if the block is associated with some buffer
 * (mainly to avoid getting hung up on a wait in breada).
 */
static int
bio_incore(dev_t dev, daddr_t blkno)
{
	struct buf *bp;
	struct buf *dp;
	uint_t index;
	kmutex_t *hmp;

	index = bio_bhash(dev, blkno);
	dp = (struct buf *)&hbuf[index];
	hmp = &hbuf[index].b_lock;

	mutex_enter(hmp);
	for (bp = dp->b_forw; bp != dp; bp = bp->b_forw) {
		if (bp->b_blkno == blkno && bp->b_edev == dev &&
		    (bp->b_flags & B_STALE) == 0) {
			mutex_exit(hmp);
			return (1);
		}
	}
	mutex_exit(hmp);
	return (0);
}

static void
bio_pageio_done(struct buf *bp)
{
	if (bp->b_flags & B_PAGEIO) {

		if (bp->b_flags & B_REMAPPED)
			bp_mapout(bp);

		if (bp->b_flags & B_READ)
			pvn_read_done(bp->b_pages, bp->b_flags);
		else
			pvn_write_done(bp->b_pages, B_WRITE | bp->b_flags);
		pageio_done(bp);
	} else {
		ASSERT(bp->b_flags & B_REMAPPED);
		bp_mapout(bp);
		brelse(bp);
	}
}

/*
 * bioerror(9F) - indicate error in buffer header
 * If 'error' is zero, remove the error indication.
 */
void
bioerror(struct buf *bp, int error)
{
	ASSERT(bp != NULL);
	ASSERT(error >= 0);
	ASSERT(SEMA_HELD(&bp->b_sem));

	if (error != 0) {
		bp->b_flags |= B_ERROR;
	} else {
		bp->b_flags &= ~B_ERROR;
	}
	bp->b_error = error;
}

/*
 * bioreset(9F) - reuse a private buffer header after I/O is complete
 */
void
bioreset(struct buf *bp)
{
	ASSERT(bp != NULL);

	biofini(bp);
	bioinit(bp);
}

/*
 * biosize(9F) - return size of a buffer header
 */
size_t
biosize(void)
{
	return (sizeof (struct buf));
}

/*
 * biomodified(9F) - check if buffer is modified
 */
int
biomodified(struct buf *bp)
{
	int npf;
	int ppattr;
	struct page *pp;

	ASSERT(bp != NULL);

	if ((bp->b_flags & B_PAGEIO) == 0) {
		return (-1);
	}
	pp = bp->b_pages;
	npf = btopr(bp->b_bcount + ((uintptr_t)bp->b_un.b_addr & PAGEOFFSET));

	while (npf > 0) {
		ppattr = hat_pagesync(pp, HAT_SYNC_DONTZERO |
		    HAT_SYNC_STOPON_MOD);
		if (ppattr & P_MOD)
			return (1);
		pp = pp->p_next;
		npf--;
	}

	return (0);
}

/*
 * bioinit(9F) - initialize a buffer structure
 */
void
bioinit(struct buf *bp)
{
	bzero(bp, sizeof (struct buf));
	sema_init(&bp->b_sem, 0, NULL, SEMA_DEFAULT, NULL);
	sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
	bp->b_offset = -1;
}

/*
 * biofini(9F) - uninitialize a buffer structure
 */
void
biofini(struct buf *bp)
{
	sema_destroy(&bp->b_io);
	sema_destroy(&bp->b_sem);
}

/*
 * bioclone(9F) - clone a buffer
 */
struct buf *
bioclone(struct buf *bp, off_t off, size_t len, dev_t dev, daddr_t blkno,
    int (*iodone)(struct buf *), struct buf *bp_mem, int sleep)
{
	struct buf *bufp;

	ASSERT(bp);
	if (bp_mem == NULL) {
		bufp = kmem_alloc(sizeof (struct buf), sleep);
		if (bufp == NULL) {
			return (NULL);
		}
		bioinit(bufp);
	} else {
		bufp = bp_mem;
		bioreset(bufp);
	}

#define	BUF_CLONE_FLAGS	(B_READ|B_WRITE|B_SHADOW|B_PHYS|B_PAGEIO|B_FAILFAST|\
	B_ABRWRITE)

	/*
	 * The cloned buffer does not inherit the B_REMAPPED flag.
	 */
	bufp->b_flags = (bp->b_flags & BUF_CLONE_FLAGS)  | B_BUSY;
	bufp->b_bcount = len;
	bufp->b_blkno = blkno;
	bufp->b_iodone = iodone;
	bufp->b_proc = bp->b_proc;
	bufp->b_edev = dev;
	bufp->b_file = bp->b_file;
	bufp->b_offset = bp->b_offset;

	if (bp->b_flags & B_SHADOW) {
		ASSERT(bp->b_shadow);
		ASSERT(bp->b_flags & B_PHYS);

		bufp->b_shadow = bp->b_shadow +
		    btop(((uintptr_t)bp->b_un.b_addr & PAGEOFFSET) + off);
		bufp->b_un.b_addr = (caddr_t)((uintptr_t)bp->b_un.b_addr + off);
		if (bp->b_flags & B_REMAPPED)
			bufp->b_proc = NULL;
	} else {
		if (bp->b_flags & B_PAGEIO) {
			struct page *pp;
			off_t o;
			int i;

			pp = bp->b_pages;
			o = ((uintptr_t)bp->b_un.b_addr & PAGEOFFSET) + off;
			for (i = btop(o); i > 0; i--) {
				pp = pp->p_next;
			}
			bufp->b_pages = pp;
			bufp->b_un.b_addr = (caddr_t)(o & PAGEOFFSET);
		} else {
			bufp->b_un.b_addr =
			    (caddr_t)((uintptr_t)bp->b_un.b_addr + off);
			if (bp->b_flags & B_REMAPPED)
				bufp->b_proc = NULL;
		}
	}
	return (bufp);
}
