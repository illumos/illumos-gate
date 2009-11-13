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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/tuneable.h>
#include <sys/inline.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/var.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/swap.h>
#include <sys/vm.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/sysinfo.h>
#include <sys/callb.h>
#include <sys/reboot.h>
#include <sys/time.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_bio.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg_kmem.h>

int doiflush = 1;	/* non-zero to turn inode flushing on */
int dopageflush = 1;	/* non-zero to turn page flushing on */

/*
 * To improve boot performance, don't run the inode flushing loop until
 * the specified number of seconds after boot.  To revert to the old
 * behavior, set fsflush_iflush_delay to 0.  We have not created any new
 * filesystem danger that did not exist previously, since there is always a
 * window in between when fsflush does the inode flush loop during which the
 * system could crash, fail to sync the filesystem, and fsck will be needed
 * to recover.  We have, however, widened this window.  Finally,
 * we never delay inode flushing if we're booting into single user mode,
 * where the administrator may be modifying files or using fsck.  This
 * modification avoids inode flushes during boot whose only purpose is to
 * update atimes on files which have been accessed during boot.
 */
int fsflush_iflush_delay = 60;

kcondvar_t fsflush_cv;
static kmutex_t fsflush_lock;	/* just for the cv_wait */
ksema_t fsflush_sema;		/* to serialize with reboot */

/*
 * some statistics for fsflush_do_pages
 */
typedef struct {
	ulong_t fsf_scan;	/* number of pages scanned */
	ulong_t fsf_examined;	/* number of page_t's actually examined, can */
				/* be less than fsf_scan due to large pages */
	ulong_t fsf_locked;	/* pages we actually page_lock()ed */
	ulong_t fsf_modified;	/* number of modified pages found */
	ulong_t fsf_coalesce;	/* number of page coalesces done */
	ulong_t fsf_time;	/* nanoseconds of run time */
	ulong_t fsf_releases;	/* number of page_release() done */
} fsf_stat_t;

fsf_stat_t fsf_recent;	/* counts for most recent duty cycle */
fsf_stat_t fsf_total;	/* total of counts */
ulong_t fsf_cycles;	/* number of runs refelected in fsf_total */

/*
 * data used to determine when we can coalesce consecutive free pages
 * into larger pages.
 */
#define	MAX_PAGESIZES	32
static ulong_t		fsf_npgsz;
static pgcnt_t		fsf_pgcnt[MAX_PAGESIZES];
static pgcnt_t		fsf_mask[MAX_PAGESIZES];


/*
 * Scan page_t's and issue I/O's for modified pages.
 *
 * Also coalesces consecutive small sized free pages into the next larger
 * pagesize. This costs a tiny bit of time in fsflush, but will reduce time
 * spent scanning on later passes and for anybody allocating large pages.
 */
static void
fsflush_do_pages()
{
	vnode_t		*vp;
	ulong_t		pcount;
	hrtime_t	timer = gethrtime();
	ulong_t		releases = 0;
	ulong_t		nexamined = 0;
	ulong_t		nlocked = 0;
	ulong_t		nmodified = 0;
	ulong_t		ncoalesce = 0;
	ulong_t		cnt;
	int		mod;
	int		fspage = 1;
	u_offset_t	offset;
	uint_t		szc;

	page_t		*coal_page = NULL;  /* 1st page in group to coalesce */
	uint_t		coal_szc = 0;	    /* size code, coal_page->p_szc */
	uint_t		coal_cnt = 0;	    /* count of pages seen */

	static ulong_t	nscan = 0;
	static pgcnt_t	last_total_pages = 0;
	static page_t	*pp = NULL;

	/*
	 * Check to see if total_pages has changed.
	 */
	if (total_pages != last_total_pages) {
		last_total_pages = total_pages;
		nscan = (last_total_pages * (tune.t_fsflushr))/v.v_autoup;
	}

	if (pp == NULL)
		pp = memsegs->pages;

	pcount = 0;
	while (pcount < nscan) {

		/*
		 * move to the next page, skipping over large pages
		 * and issuing prefetches.
		 */
		if (pp->p_szc && fspage == 0) {
			pfn_t pfn;

			pfn  = page_pptonum(pp);
			cnt = page_get_pagecnt(pp->p_szc);
			cnt -= pfn & (cnt - 1);
		} else
			cnt = 1;

		pp = page_nextn(pp, cnt);
		prefetch_page_r((void *)pp);
		ASSERT(pp != NULL);
		pcount += cnt;

		/*
		 * Do a bunch of dirty tests (ie. no locking) to determine
		 * if we can quickly skip this page. These tests are repeated
		 * after acquiring the page lock.
		 */
		++nexamined;
		if (PP_ISSWAP(pp)) {
			fspage = 0;
			coal_page = NULL;
			continue;
		}

		/*
		 * skip free pages too, but try coalescing them into larger
		 * pagesizes
		 */
		if (PP_ISFREE(pp)) {
			/*
			 * skip pages with a file system identity or that
			 * are already maximum size
			 */
			fspage = 0;
			szc = pp->p_szc;
			if (pp->p_vnode != NULL || szc == fsf_npgsz - 1) {
				coal_page = NULL;
				continue;
			}

			/*
			 * If not in a coalescing candidate page or the size
			 * codes are different, start a new candidate.
			 */
			if (coal_page == NULL || coal_szc != szc) {

				/*
				 * page must be properly aligned
				 */
				if ((page_pptonum(pp) & fsf_mask[szc]) != 0) {
					coal_page = NULL;
					continue;
				}
				coal_page = pp;
				coal_szc = szc;
				coal_cnt = 1;
				continue;
			}

			/*
			 * acceptable to add this to existing candidate page
			 */
			++coal_cnt;
			if (coal_cnt < fsf_pgcnt[coal_szc])
				continue;

			/*
			 * We've got enough pages to coalesce, so do it.
			 * After promoting, we clear coal_page, so it will
			 * take another pass to promote this to an even
			 * larger page.
			 */
			++ncoalesce;
			(void) page_promote_size(coal_page, coal_szc);
			coal_page = NULL;
			continue;
		} else {
			coal_page = NULL;
		}

		if (PP_ISKAS(pp) ||
		    PAGE_LOCKED(pp) ||
		    pp->p_lckcnt != 0 ||
		    pp->p_cowcnt != 0) {
			fspage = 0;
			continue;
		}


		/*
		 * Reject pages that can't be "exclusively" locked.
		 */
		if (!page_trylock(pp, SE_EXCL))
			continue;
		++nlocked;


		/*
		 * After locking the page, redo the above checks.
		 * Since we locked the page, leave out the PAGE_LOCKED() test.
		 */
		vp = pp->p_vnode;
		if (PP_ISSWAP(pp) ||
		    PP_ISFREE(pp) ||
		    vp == NULL ||
		    PP_ISKAS(pp) ||
		    (vp->v_flag & VISSWAP) != 0) {
			page_unlock(pp);
			fspage = 0;
			continue;
		}
		if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
			page_unlock(pp);
			continue;
		}

		fspage = 1;
		ASSERT(vp->v_type != VCHR);

		/*
		 * Check the modified bit. Leaving the bit alone in hardware.
		 * It will be cleared if we do the putpage.
		 */
		if (IS_VMODSORT(vp))
			mod = hat_ismod(pp);
		else
			mod = hat_pagesync(pp,
			    HAT_SYNC_DONTZERO | HAT_SYNC_STOPON_MOD) & P_MOD;

		if (mod) {
			++nmodified;
			offset = pp->p_offset;

			/*
			 * Hold the vnode before releasing the page lock
			 * to prevent it from being freed and re-used by
			 * some other thread.
			 */
			VN_HOLD(vp);

			page_unlock(pp);

			(void) VOP_PUTPAGE(vp, offset, PAGESIZE, B_ASYNC,
			    kcred, NULL);

			VN_RELE(vp);
		} else {

			/*
			 * Catch any pages which should be on the cache list,
			 * but aren't yet.
			 */
			if (hat_page_is_mapped(pp) == 0) {
				++releases;
				(void) page_release(pp, 1);
			} else {
				page_unlock(pp);
			}
		}
	}

	/*
	 * maintain statistics
	 * reset every million wakeups, just to avoid overflow
	 */
	if (++fsf_cycles == 1000000) {
		fsf_cycles = 0;
		fsf_total.fsf_scan = 0;
		fsf_total.fsf_examined = 0;
		fsf_total.fsf_locked = 0;
		fsf_total.fsf_modified = 0;
		fsf_total.fsf_coalesce = 0;
		fsf_total.fsf_time = 0;
		fsf_total.fsf_releases = 0;
	} else {
		fsf_total.fsf_scan += fsf_recent.fsf_scan = nscan;
		fsf_total.fsf_examined += fsf_recent.fsf_examined = nexamined;
		fsf_total.fsf_locked += fsf_recent.fsf_locked = nlocked;
		fsf_total.fsf_modified += fsf_recent.fsf_modified = nmodified;
		fsf_total.fsf_coalesce += fsf_recent.fsf_coalesce = ncoalesce;
		fsf_total.fsf_time += fsf_recent.fsf_time = gethrtime() - timer;
		fsf_total.fsf_releases += fsf_recent.fsf_releases = releases;
	}
}

/*
 * As part of file system hardening, this daemon is awakened
 * every second to flush cached data which includes the
 * buffer cache, the inode cache and mapped pages.
 */
void
fsflush()
{
	struct buf *bp, *dwp;
	struct hbuf *hp;
	int autoup;
	unsigned int ix, icount, count = 0;
	callb_cpr_t cprinfo;
	uint_t		bcount;
	kmutex_t	*hmp;
	struct vfssw *vswp;

	proc_fsflush = ttoproc(curthread);
	proc_fsflush->p_cstime = 0;
	proc_fsflush->p_stime =  0;
	proc_fsflush->p_cutime =  0;
	proc_fsflush->p_utime = 0;
	bcopy("fsflush", curproc->p_user.u_psargs, 8);
	bcopy("fsflush", curproc->p_user.u_comm, 7);

	mutex_init(&fsflush_lock, NULL, MUTEX_DEFAULT, NULL);
	sema_init(&fsflush_sema, 0, NULL, SEMA_DEFAULT, NULL);

	/*
	 * Setup page coalescing.
	 */
	fsf_npgsz = page_num_pagesizes();
	ASSERT(fsf_npgsz < MAX_PAGESIZES);
	for (ix = 0; ix < fsf_npgsz - 1; ++ix) {
		fsf_pgcnt[ix] =
		    page_get_pagesize(ix + 1) / page_get_pagesize(ix);
		fsf_mask[ix] = page_get_pagecnt(ix + 1) - 1;
	}

	autoup = v.v_autoup * hz;
	icount = v.v_autoup / tune.t_fsflushr;
	CALLB_CPR_INIT(&cprinfo, &fsflush_lock, callb_generic_cpr, "fsflush");
loop:
	sema_v(&fsflush_sema);
	mutex_enter(&fsflush_lock);
	CALLB_CPR_SAFE_BEGIN(&cprinfo);
	cv_wait(&fsflush_cv, &fsflush_lock);		/* wait for clock */
	CALLB_CPR_SAFE_END(&cprinfo, &fsflush_lock);
	mutex_exit(&fsflush_lock);
	sema_p(&fsflush_sema);

	/*
	 * Write back all old B_DELWRI buffers on the freelist.
	 */
	bcount = 0;
	for (ix = 0; ix < v.v_hbuf; ix++) {

		hp = &hbuf[ix];
		dwp = (struct buf *)&dwbuf[ix];

		bcount += (hp->b_length);

		if (dwp->av_forw == dwp) {
			continue;
		}

		hmp = &hbuf[ix].b_lock;
		mutex_enter(hmp);
		bp = dwp->av_forw;

		/*
		 * Go down only on the delayed write lists.
		 */
		while (bp != dwp) {

			ASSERT(bp->b_flags & B_DELWRI);

			if ((bp->b_flags & B_DELWRI) &&
			    (ddi_get_lbolt() - bp->b_start >= autoup) &&
			    sema_tryp(&bp->b_sem)) {
				bp->b_flags |= B_ASYNC;
				hp->b_length--;
				notavail(bp);
				mutex_exit(hmp);
				if (bp->b_vp == NULL) {
					BWRITE(bp);
				} else {
					UFS_BWRITE(VTOI(bp->b_vp)->i_ufsvfs,
					    bp);
				}
				mutex_enter(hmp);
				bp = dwp->av_forw;
			} else {
				bp = bp->av_forw;
			}
		}
		mutex_exit(hmp);
	}

	/*
	 *
	 * There is no need to wakeup any thread waiting on bio_mem_cv
	 * since brelse will wake them up as soon as IO is complete.
	 */
	bfreelist.b_bcount = bcount;

	if (dopageflush)
		fsflush_do_pages();

	if (!doiflush)
		goto loop;

	/*
	 * If the system was not booted to single user mode, skip the
	 * inode flushing until after fsflush_iflush_delay secs have elapsed.
	 */
	if ((boothowto & RB_SINGLE) == 0 &&
	    (ddi_get_lbolt64() / hz) < fsflush_iflush_delay)
		goto loop;

	/*
	 * Flush cached attribute information (e.g. inodes).
	 */
	if (++count >= icount) {
		count = 0;

		/*
		 * Sync back cached data.
		 */
		RLOCK_VFSSW();
		for (vswp = &vfssw[1]; vswp < &vfssw[nfstype]; vswp++) {
			if (ALLOCATED_VFSSW(vswp) && VFS_INSTALLED(vswp)) {
				vfs_refvfssw(vswp);
				RUNLOCK_VFSSW();
				(void) fsop_sync_by_kind(vswp - vfssw,
				    SYNC_ATTR, kcred);
				vfs_unrefvfssw(vswp);
				RLOCK_VFSSW();
			}
		}
		RUNLOCK_VFSSW();
	}
	goto loop;
}
