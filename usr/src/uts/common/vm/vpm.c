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
 * VM - generic vnode page mapping interfaces.
 *
 * Mechanism to provide temporary mappings to vnode pages.
 * The typical use would be to copy/access file data.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/thread.h>
#include <sys/dumphdr.h>
#include <sys/bitmap.h>
#include <sys/lgrp.h>

#include <vm/seg_kmem.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/rm.h>
#include <vm/vpm.h>


#ifdef	SEGKPM_SUPPORT
/*
 * VPM can be disabled by setting vpm_enable = 0 in
 * /etc/system.
 *
 */
int vpm_enable = 1;

#else

int vpm_enable = 0;

#endif

#ifdef	SEGKPM_SUPPORT


int	vpm_cache_enable = 1;
long	vpm_cache_percent = 12;
long	vpm_cache_size;
int	vpm_nfreelist = 0;
int	vpmd_freemsk = 0;

#define	VPM_S_PAD	64
union vpm_cpu {
	struct {
		int	vcpu_free_ndx;
		ulong_t	vcpu_hits;
		ulong_t vcpu_misses;
	} vcpu;
	char vpm_pad[VPM_S_PAD];
};
static union vpm_cpu	*vpmd_cpu;

#define	vfree_ndx	vcpu.vcpu_free_ndx

int	vpm_cachemode = VPMCACHE_LRU;

#define	PPMTX(pp) (&(pp)->p_ilock)

static struct vpmap *vpmd_vpmap;	/* list of vpmap structs preallocated */
static struct vpmfree *vpmd_free;
#define	VPMAPMTX(vpm)	(&vpm->vpm_mtx)
#define	VPMAP2VMF(vpm)	(&vpmd_free[(vpm - vpmd_vpmap) & vpmd_freemsk])
#define	VPMAP2VMF_NDX(vpm)	(ushort_t)((vpm - vpmd_vpmap) & vpmd_freemsk)
#define	VPMP(id)	(&vpmd_vpmap[id - 1])
#define	VPMID(vpm)	(uint_t)((vpm - vpmd_vpmap) + 1)


#ifdef	DEBUG

struct	vpm_debug {
	int vpmd_steals;
	int vpmd_contend;
	int vpmd_prevpagelocked;
	int vpmd_getpagefailed;
	int vpmd_zerostart;
	int vpmd_emptyfreelist;
	int vpmd_nofreevpms;
} vpm_debug;

#define	VPM_DEBUG(x)	((vpm_debug.x)++)

int	steals;
int	steals_mtbf = 7;
int	contend;
int	contend_mtbf = 127;

#define	VPM_MTBF(v, f)	(((++(v)) & (f)) != (f))

#else	/* DEBUG */

#define	VPM_MTBF(v, f)	(1)
#define	VPM_DEBUG(x)	/* nothing */

#endif

/*
 * The vpm cache.
 *
 * The main purpose of having a cache here is to speed up page_lookup()
 * operations and also provide an LRU(default) behaviour of file pages. The
 * page_lookup() operation tends to be expensive if a page has to be
 * reclaimed from the system page cache("cachelist"). Once we speed up the
 * page_lookup()->page_reclaim() path then there there should be no need for
 * this cache. The system page cache(cachelist) should effectively serve the
 * purpose of caching file pages.
 *
 * This cache is very similar to segmap's smap cache. Each page in the
 * cache is tracked by the structure vpmap_t. But unlike segmap, there is no
 * hash table. The page_t has a reference to the vpmap_t when cached. For a
 * given vnode, offset the page is found by means of a page_lookup() operation.
 * Any page which has a mapping(i.e when cached) will not be in the
 * system 'cachelist'. Hence the page_lookup() will not have to do a
 * page_reclaim(). That is how the cache serves to speed up page_lookup()
 * operations.
 *
 * This cache can be disabled by setting vpm_cache_enable = 0 in /etc/system.
 */

void
vpm_init()
{
	long  npages;
	struct vpmap *vpm;
	struct vpmfree *vpmflp;
	int i, ndx;
	extern void prefetch_smap_w(void *);

	if (!kpm_enable) {
		vpm_enable = 0;
	}

	if (!vpm_enable || !vpm_cache_enable) {
		return;
	}

	/*
	 * Set the size of the cache.
	 */
	vpm_cache_size = mmu_ptob((physmem * vpm_cache_percent)/100);
	if (vpm_cache_size < VPMAP_MINCACHE) {
		vpm_cache_size = VPMAP_MINCACHE;
	}

	if (vpm_cache_size > VPMAP_MAXCACHE) {
		vpm_cache_size = VPMAP_MAXCACHE;
	}

	/*
	 * Number of freelists.
	 */
	if (vpm_nfreelist == 0) {
		vpm_nfreelist = max_ncpus;
	} else if (vpm_nfreelist < 0 || vpm_nfreelist > 2 * max_ncpus) {
		cmn_err(CE_WARN, "vpmap create : number of freelist "
		"vpm_nfreelist %d using %d", vpm_nfreelist, max_ncpus);
		vpm_nfreelist = 2 * max_ncpus;
	}

	/*
	 * Round it up to the next power of 2
	 */
	if (!ISP2(vpm_nfreelist)) {
		vpm_nfreelist = 1 << (highbit(vpm_nfreelist));
	}
	vpmd_freemsk = vpm_nfreelist - 1;

	/*
	 * Use a per cpu rotor index to spread the allocations evenly
	 * across the available vpm freelists.
	 */
	vpmd_cpu = kmem_zalloc(sizeof (union vpm_cpu) * max_ncpus, KM_SLEEP);
	ndx = 0;
	for (i = 0; i < max_ncpus; i++) {

		vpmd_cpu[i].vfree_ndx = ndx;
		ndx = (ndx + 1) & vpmd_freemsk;
	}

	/*
	 * Allocate and initialize the freelist.
	 */
	vpmd_free = kmem_zalloc(vpm_nfreelist * sizeof (struct vpmfree),
	    KM_SLEEP);
	for (i = 0; i < vpm_nfreelist; i++) {

		vpmflp = &vpmd_free[i];
		/*
		 * Set up initial queue pointers. They will get flipped
		 * back and forth.
		 */
		vpmflp->vpm_allocq = &vpmflp->vpm_freeq[VPMALLOCQ];
		vpmflp->vpm_releq = &vpmflp->vpm_freeq[VPMRELEQ];
	}

	npages = mmu_btop(vpm_cache_size);


	/*
	 * Allocate and initialize the vpmap structs. We need to
	 * walk the array backwards as the prefetch happens in reverse
	 * order.
	 */
	vpmd_vpmap = kmem_alloc(sizeof (struct vpmap) * npages, KM_SLEEP);
	for (vpm = &vpmd_vpmap[npages - 1]; vpm >= vpmd_vpmap; vpm--) {
		struct vpmfree *vpmflp;
		union vpm_freeq *releq;
		struct vpmap *vpmapf;

		/*
		 * Use prefetch as we have to walk thru a large number of
		 * these data structures. We just use the smap's prefetch
		 * routine as it does the same.
		 */
		prefetch_smap_w((void *)vpm);

		vpm->vpm_vp = NULL;
		vpm->vpm_off = 0;
		vpm->vpm_pp = NULL;
		vpm->vpm_refcnt = 0;
		mutex_init(&vpm->vpm_mtx, NULL, MUTEX_DEFAULT, NULL);
		vpm->vpm_free_ndx = VPMAP2VMF_NDX(vpm);

		vpmflp = VPMAP2VMF(vpm);
		releq = vpmflp->vpm_releq;

		vpmapf = releq->vpmq_free;
		if (vpmapf == NULL) {
			releq->vpmq_free = vpm->vpm_next = vpm->vpm_prev = vpm;
		} else {
			vpm->vpm_next = vpmapf;
			vpm->vpm_prev = vpmapf->vpm_prev;
			vpmapf->vpm_prev = vpm;
			vpm->vpm_prev->vpm_next = vpm;
			releq->vpmq_free = vpm->vpm_next;
		}

		/*
		 * Indicate that the vpmap is on the releq at start
		 */
		vpm->vpm_ndxflg = VPMRELEQ;
	}
}


/*
 * unhooks vpm from the freelist if it is still on the freelist.
 */
#define	VPMAP_RMFREELIST(vpm) \
	{ \
		if (vpm->vpm_next != NULL) { \
			union vpm_freeq *freeq; \
			struct vpmfree *vpmflp; \
			vpmflp = &vpmd_free[vpm->vpm_free_ndx]; \
			freeq = &vpmflp->vpm_freeq[vpm->vpm_ndxflg]; \
			mutex_enter(&freeq->vpmq_mtx); \
			if (freeq->vpmq_free != vpm) { \
				vpm->vpm_prev->vpm_next = vpm->vpm_next; \
				vpm->vpm_next->vpm_prev = vpm->vpm_prev; \
			} else if (vpm == vpm->vpm_next) { \
				freeq->vpmq_free = NULL; \
			} else { \
				freeq->vpmq_free = vpm->vpm_next; \
				vpm->vpm_prev->vpm_next = vpm->vpm_next; \
				vpm->vpm_next->vpm_prev = vpm->vpm_prev; \
			} \
			mutex_exit(&freeq->vpmq_mtx); \
			vpm->vpm_next = vpm->vpm_prev = NULL; \
		} \
	}

static int
get_freelndx(int mode)
{
	int ndx;

	ndx = vpmd_cpu[CPU->cpu_seqid].vfree_ndx & vpmd_freemsk;
	switch (mode) {

	case	VPMCACHE_LRU:
	default:
			vpmd_cpu[CPU->cpu_seqid].vfree_ndx++;
			break;
	}
	return (ndx);
}


/*
 * Find one vpmap structure from the free lists and use it for the newpage.
 * The previous page it cached is dissociated and released. The page_t's
 * p_vpmref is cleared only when the vpm it is pointing to is locked(or
 * for AMD64 when the page is exclusively locked in page_unload. That is
 * because the p_vpmref is treated as mapping).
 *
 * The page's p_vpmref is set when the page is
 * locked(at least SHARED locked).
 */
static struct vpmap *
get_free_vpmap(page_t *newpage)
{
	struct vpmfree *vpmflp;
	kmutex_t *vmtx;
	struct vpmap *vpm, *first;
	union vpm_freeq *allocq, *releq;
	page_t *pp = NULL;
	int end_ndx, page_locked = 0;
	int free_ndx;

	/*
	 * get the freelist bin index.
	 */
	free_ndx = get_freelndx(vpm_cachemode);

	end_ndx = free_ndx;
	vpmflp = &vpmd_free[free_ndx];

retry_queue:
	allocq = vpmflp->vpm_allocq;
	mutex_enter(&allocq->vpmq_mtx);

	if ((vpm = allocq->vpmq_free) == NULL) {

skip_queue:
		/*
		 * The alloc list is empty or this queue is being skipped;
		 * first see if the allocq toggled.
		 */
		if (vpmflp->vpm_allocq != allocq) {
			/* queue changed */
			mutex_exit(&allocq->vpmq_mtx);
			goto retry_queue;
		}
		releq = vpmflp->vpm_releq;
		if (!mutex_tryenter(&releq->vpmq_mtx)) {
			/* cannot get releq; a free vpmap may be there now */
			mutex_exit(&allocq->vpmq_mtx);

			/*
			 * This loop could spin forever if this thread has
			 * higher priority than the thread that is holding
			 * releq->vpmq_mtx. In order to force the other thread
			 * to run, we'll lock/unlock the mutex which is safe
			 * since we just unlocked the allocq mutex.
			 */
			mutex_enter(&releq->vpmq_mtx);
			mutex_exit(&releq->vpmq_mtx);
			goto retry_queue;
		}
		if (releq->vpmq_free == NULL) {
			VPM_DEBUG(vpmd_emptyfreelist);
			/*
			 * This freelist is empty.
			 * This should not happen unless clients
			 * are failing to release the vpmap after
			 * accessing the data. Before resorting
			 * to sleeping, try the next list of the same color.
			 */
			free_ndx = (free_ndx + 1) & vpmd_freemsk;
			if (free_ndx != end_ndx) {
				mutex_exit(&releq->vpmq_mtx);
				mutex_exit(&allocq->vpmq_mtx);
				vpmflp = &vpmd_free[free_ndx];
				goto retry_queue;
			}
			/*
			 * Tried all freelists.
			 * wait on this list and hope something gets freed.
			 */
			vpmflp->vpm_want++;
			mutex_exit(&vpmflp->vpm_freeq[1].vpmq_mtx);
			cv_wait(&vpmflp->vpm_free_cv,
			    &vpmflp->vpm_freeq[0].vpmq_mtx);
			vpmflp->vpm_want--;
			mutex_exit(&vpmflp->vpm_freeq[0].vpmq_mtx);
			vpmflp = &vpmd_free[free_ndx];
			VPM_DEBUG(vpmd_nofreevpms);
			goto retry_queue;
		} else {
			/*
			 * Something on the rele queue; flip the alloc
			 * and rele queues and retry.
			 */
			vpmflp->vpm_allocq = releq;
			vpmflp->vpm_releq = allocq;
			mutex_exit(&allocq->vpmq_mtx);
			mutex_exit(&releq->vpmq_mtx);
			if (page_locked) {
				delay(hz >> 2);
				page_locked = 0;
			}
			goto retry_queue;
		}
	} else {
		int gotnewvpm;
		kmutex_t *pmtx;
		uint_t vpmref;

		/*
		 * Fastpath the case we get the vpmap mutex
		 * on the first try.
		 */
		first = vpm;
next_vpmap:
		vmtx = VPMAPMTX(vpm);
		if (!mutex_tryenter(vmtx)) {
			/*
			 * Another thread is trying to reclaim this slot.
			 * Skip to the next queue or vpmap.
			 */
			if ((vpm = vpm->vpm_next) == first) {
				goto skip_queue;
			} else {
				goto next_vpmap;
			}
		}

		/*
		 * Assign this vpm to the newpage.
		 */
		pmtx = PPMTX(newpage);
		gotnewvpm = 0;
		mutex_enter(pmtx);

		/*
		 * Check if some other thread already assigned a vpm to
		 * this page.
		 */
		if ((vpmref = newpage->p_vpmref) == 0) {
			newpage->p_vpmref = VPMID(vpm);
			gotnewvpm = 1;
		} else {
			VPM_DEBUG(vpmd_contend);
			mutex_exit(vmtx);
		}
		mutex_exit(pmtx);

		if (gotnewvpm) {

			/*
			 * At this point, we've selected the vpm. Remove vpm
			 * from its freelist. If vpm is the first one in
			 * the freelist, update the head of the freelist.
			 */
			if (first == vpm) {
				ASSERT(first == allocq->vpmq_free);
				allocq->vpmq_free = vpm->vpm_next;
			}

			/*
			 * If the head of the freelist still points to vpm,
			 * then there are no more free vpmaps in that list.
			 */
			if (allocq->vpmq_free == vpm)
				/*
				 * Took the last one
				 */
				allocq->vpmq_free = NULL;
			else {
				vpm->vpm_prev->vpm_next = vpm->vpm_next;
				vpm->vpm_next->vpm_prev = vpm->vpm_prev;
			}
			mutex_exit(&allocq->vpmq_mtx);
			vpm->vpm_prev = vpm->vpm_next = NULL;

			/*
			 * Disassociate the previous page.
			 * p_vpmref is used as a mapping reference to the page.
			 */
			if ((pp = vpm->vpm_pp) != NULL &&
			    vpm->vpm_vp == pp->p_vnode &&
			    vpm->vpm_off == pp->p_offset) {

				pmtx = PPMTX(pp);
				if (page_trylock(pp, SE_SHARED)) {
					/*
					 * Now verify that it is the correct
					 * page. If not someone else stole it,
					 * so just unlock it and leave.
					 */
					mutex_enter(pmtx);
					if (PP_ISFREE(pp) ||
					    vpm->vpm_vp != pp->p_vnode ||
					    vpm->vpm_off != pp->p_offset ||
					    pp->p_vpmref != VPMID(vpm)) {
						mutex_exit(pmtx);

						page_unlock(pp);
					} else {
						/*
						 * Release the page.
						 */
						pp->p_vpmref = 0;
						mutex_exit(pmtx);
						(void) page_release(pp, 1);
					}
				} else {
					/*
					 * If the page cannot be locked, just
					 * clear the p_vpmref and go.
					 */
					mutex_enter(pmtx);
					if (pp->p_vpmref == VPMID(vpm)) {
						pp->p_vpmref = 0;
					}
					mutex_exit(pmtx);
					VPM_DEBUG(vpmd_prevpagelocked);
				}
			}

			/*
			 * Setup vpm to point to the new page.
			 */
			vpm->vpm_pp = newpage;
			vpm->vpm_vp = newpage->p_vnode;
			vpm->vpm_off = newpage->p_offset;

		} else {
			int steal = !VPM_MTBF(steals, steals_mtbf);
			/*
			 * Page already has a vpm assigned just use that.
			 * Grab the vpm mutex and verify that it is still
			 * the correct one. The pp->p_vpmref should not change
			 * once we have the vpm mutex and the page lock.
			 */
			mutex_exit(&allocq->vpmq_mtx);
			vpm = VPMP(vpmref);
			vmtx = VPMAPMTX(vpm);
			mutex_enter(vmtx);
			if ((steal && vpm->vpm_refcnt == 0) ||
			    vpm->vpm_pp != newpage) {
				/*
				 * The vpm got stolen, retry.
				 * clear the p_vpmref.
				 */
				pmtx = PPMTX(newpage);
				mutex_enter(pmtx);
				if (newpage->p_vpmref == vpmref) {
					newpage->p_vpmref = 0;
				}
				mutex_exit(pmtx);

				mutex_exit(vmtx);
				VPM_DEBUG(vpmd_steals);
				goto retry_queue;
			} else if (vpm->vpm_refcnt == 0) {
				/*
				 * Remove it from the free list if it
				 * exists there.
				 */
				VPMAP_RMFREELIST(vpm);
			}
		}
		return (vpm);
	}
}

static void
free_vpmap(struct vpmap *vpm)
{
	struct vpmfree *vpmflp;
	struct vpmap *vpmfreelist;
	union vpm_freeq *releq;

	ASSERT(MUTEX_HELD(VPMAPMTX(vpm)));

	if (vpm->vpm_refcnt != 0) {
		panic("free_vpmap");
		/*NOTREACHED*/
	}

	vpmflp = &vpmd_free[vpm->vpm_free_ndx];
	/*
	 * Add to the tail of the release queue
	 * Note that vpm_releq and vpm_allocq could toggle
	 * before we get the lock. This does not affect
	 * correctness as the 2 queues are only maintained
	 * to reduce lock pressure.
	 */
	releq = vpmflp->vpm_releq;
	if (releq == &vpmflp->vpm_freeq[0]) {
		vpm->vpm_ndxflg = 0;
	} else {
		vpm->vpm_ndxflg = 1;
	}
	mutex_enter(&releq->vpmq_mtx);
	vpmfreelist = releq->vpmq_free;
	if (vpmfreelist == 0) {
		int want;

		releq->vpmq_free = vpm->vpm_next = vpm->vpm_prev = vpm;
		/*
		 * Both queue mutexes are held to set vpm_want;
		 * snapshot the value before dropping releq mutex.
		 * If vpm_want appears after the releq mutex is dropped,
		 * then the vpmap just freed is already gone.
		 */
		want = vpmflp->vpm_want;
		mutex_exit(&releq->vpmq_mtx);
		/*
		 * See if there was a waiter before dropping the releq mutex
		 * then recheck after obtaining vpm_freeq[0] mutex as
		 * the another thread may have already signaled.
		 */
		if (want) {
			mutex_enter(&vpmflp->vpm_freeq[0].vpmq_mtx);
			if (vpmflp->vpm_want)
				cv_signal(&vpmflp->vpm_free_cv);
			mutex_exit(&vpmflp->vpm_freeq[0].vpmq_mtx);
		}
	} else {
		vpm->vpm_next = vpmfreelist;
		vpm->vpm_prev = vpmfreelist->vpm_prev;
		vpmfreelist->vpm_prev = vpm;
		vpm->vpm_prev->vpm_next = vpm;
		mutex_exit(&releq->vpmq_mtx);
	}
}

/*
 * Get the vpmap for the page.
 * The refcnt of this vpm is incremented.
 */
static struct vpmap *
get_vpmap(page_t *pp)
{
	struct vpmap *vpm = NULL;
	kmutex_t *vmtx;
	kmutex_t *pmtx;
	unsigned int refid;

	ASSERT((pp != NULL) && PAGE_LOCKED(pp));

	if (VPM_MTBF(contend, contend_mtbf) && (refid = pp->p_vpmref) != 0) {
		vpm = VPMP(refid);
		vmtx = VPMAPMTX(vpm);
		mutex_enter(vmtx);
		/*
		 * Since we have the page lock and the vpm mutex, the
		 * pp->p_vpmref cannot change.
		 */
		if (vpm->vpm_pp != pp) {
			pmtx = PPMTX(pp);

			/*
			 * Clear the p_vpmref as it is incorrect.
			 * This can happen if the page was stolen.
			 * On x64 this should not happen as p_vpmref
			 * is treated as a mapping on the page. So
			 * if the page is stolen, the mapping would have
			 * been cleared in page_unload().
			 */
			mutex_enter(pmtx);
			if (pp->p_vpmref == refid)
				pp->p_vpmref = 0;
			mutex_exit(pmtx);

			mutex_exit(vmtx);
			vpm = NULL;
		} else if (vpm->vpm_refcnt == 0) {
			/*
			 * Got the vpm, remove it from the free
			 * list if it exists there.
			 */
			VPMAP_RMFREELIST(vpm);
		}
	}
	if (vpm == NULL) {
		/*
		 * get_free_vpmap() returns with the vpmap mutex held.
		 */
		vpm = get_free_vpmap(pp);
		vmtx = VPMAPMTX(vpm);
		vpmd_cpu[CPU->cpu_seqid].vcpu.vcpu_misses++;
	} else {
		vpmd_cpu[CPU->cpu_seqid].vcpu.vcpu_hits++;
	}

	vpm->vpm_refcnt++;
	mutex_exit(vmtx);

	return (vpm);
}

/* END --- vpm cache ---- */

/*
 * The vnode page mapping(vpm) interface routines.
 */

/*
 * Find or create the pages starting form baseoff for specified
 * length 'len'.
 */
static int
vpm_pagecreate(
	struct vnode *vp,
	u_offset_t baseoff,
	size_t len,
	vmap_t vml[],
	int nseg,
	int *newpage)
{

	page_t *pp = NULL;
	caddr_t base;
	u_offset_t off = baseoff;
	int i;
	ASSERT(nseg >= MINVMAPS && nseg <= MAXVMAPS);

	for (i = 0; len > 0; len -= PAGESIZE, i++) {
		struct vpmap *vpm;


		if ((pp = page_lookup(vp, off, SE_SHARED)) == NULL) {

			base = segkpm_create_va(off);

			/*
			 * the seg pointer passed in is just advisor. Just
			 * pass segkmap for now like segmap does with
			 * segmap_kpm enabled.
			 */
			if ((pp = page_create_va(vp, off, PAGESIZE, PG_WAIT,
			    segkmap, base)) == NULL) {
				panic("segmap_pagecreate_vpm: "
				    "page_create failed");
				/*NOTREACHED*/
			}
			if (newpage != NULL)
				*newpage = 1;

			page_io_unlock(pp);
		}

		/*
		 * Get the vpm for this page_t.
		 */
		if (vpm_cache_enable) {
			vpm = get_vpmap(pp);
			vml[i].vs_data = (void *)&vpm->vpm_pp;
		} else {
			vml[i].vs_data = (void *)pp;
			pp->p_vpmref = 0;
		}

		vml[i].vs_addr = hat_kpm_mapin(pp, 0);
		vml[i].vs_len = PAGESIZE;

		off += PAGESIZE;
	}
	vml[i].vs_data = NULL;
	vml[i].vs_addr = (caddr_t)NULL;
	return (0);
}


/*
 * Returns vpm mappings of pages in the range [off, off+len], where
 * len is rounded up to the PAGESIZE boundary. The list of pages and
 * the page addresses are returned in the SGL vml (vmap_t) array passed in.
 * The nseg is the number of vmap_t entries in the array.
 *
 * The segmap's SM_LOCKPROTO  usage is not supported by these interfaces.
 * For such cases, use the seg_map interfaces.
 */
int
vpm_map_pages(
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	int fetchpage,
	vmap_t *vml,
	int nseg,
	int  *newpage,
	enum seg_rw rw)
{
	extern struct vnode *common_specvp();
	u_offset_t baseoff;
	uint_t prot;
	caddr_t base;
	page_t *pp, *pplist[MAXVMAPS];
	struct vpmap *vpm;
	int i, error = 0;
	size_t tlen;

	ASSERT(nseg >= MINVMAPS && nseg <= MAXVMAPS);
	baseoff = off & (offset_t)PAGEMASK;
	vml[0].vs_data = NULL;
	vml[0].vs_addr = (caddr_t)NULL;

	tlen = P2ROUNDUP(off + len, PAGESIZE) - baseoff;
	/*
	 * Restrict it to VPMMAXLEN.
	 */
	if (tlen > (VPMMAXPGS * PAGESIZE)) {
		tlen = VPMMAXPGS * PAGESIZE;
	}
	/*
	 * Ensure length fits within the vml[] array. One element of
	 * the array is used to mark the end of the scatter/gather list
	 * of valid mappings by setting its vs_addr = NULL. Leave space
	 * for this element.
	 */
	if (tlen > ((nseg - 1) * PAGESIZE)) {
		tlen = ((nseg - 1) * PAGESIZE);
	}
	len = tlen;

	/*
	 * If this is a block device we have to be sure to use the
	 * "common" block device vnode for the mapping.
	 */
	if (vp->v_type == VBLK)
		vp = common_specvp(vp);


	if (!fetchpage)
		return (vpm_pagecreate(vp, baseoff, len, vml, nseg, newpage));

	for (i = 0; len > 0; len -= PAGESIZE, i++, pplist[i] = NULL) {

		pp = page_lookup(vp, baseoff, SE_SHARED);

		/*
		 * If we did not find the page or if this page was not
		 * in vpm cache(p_vpmref == 0), then let VOP_GETPAGE get
		 * all the pages.
		 * We need to call VOP_GETPAGE so that filesytems can do some
		 * (un)necessary tracking for sequential access.
		 */

		if (pp == NULL || (vpm_cache_enable && pp->p_vpmref == 0) ||
		    (rw == S_WRITE && hat_page_getattr(pp, P_MOD | P_REF)
		    != (P_MOD | P_REF))) {
			int j;
			if (pp != NULL) {
				page_unlock(pp);
			}
			/*
			 * If we did not find the desired set of pages,
			 * from the page cache, just call VOP_GETPAGE to get
			 * all the pages.
			 */
			for (j = 0; j < i; j++) {
				page_unlock(pplist[j]);
			}


			baseoff = off & (offset_t)PAGEMASK;
			/*
			 * Pass a dummy address as it will be required
			 * by page_create_va(). We pass segkmap as the seg
			 * as some file systems(UFS) check it.
			 */
			base = segkpm_create_va(baseoff);

			error = VOP_GETPAGE(vp, baseoff, tlen, &prot, pplist,
			    tlen, segkmap, base, rw, CRED(), NULL);
			if (error) {
				VPM_DEBUG(vpmd_getpagefailed);
				pplist[0] = NULL;
			}
			break;
		} else {
			pplist[i] = pp;
			baseoff += PAGESIZE;
		}
	}

	if (error) {
		for (i = 0; pplist[i] != NULL; i++) {
			page_unlock(pplist[i]);
			pplist[i] = NULL;
		}
		vml[0].vs_addr = NULL;
		vml[0].vs_data = NULL;
		return (error);
	}

	/*
	 * Get the vpm's for pages.
	 */
	for (i = 0; pplist[i] != NULL; i++) {
		if (vpm_cache_enable) {
			vpm = get_vpmap(pplist[i]);
			vml[i].vs_data = (void *)&(vpm->vpm_pp);
		} else {
			vml[i].vs_data = (void *)pplist[i];
			pplist[i]->p_vpmref = 0;
		}

		vml[i].vs_addr = hat_kpm_mapin(pplist[i], 0);
		vml[i].vs_len = PAGESIZE;
	}

	vml[i].vs_data = NULL;
	vml[i].vs_addr = (caddr_t)NULL;

	return (0);
}

/*
 * Release the vpm mappings on the pages and unlock them.
 */
void
vpm_unmap_pages(vmap_t vml[], enum seg_rw rw)
{
	int i;
	struct vpmap *vpm;
	kmutex_t *mtx;
	page_t *pp;

	for (i = 0; vml[i].vs_data != NULL; i++) {
		ASSERT(IS_KPM_ADDR(vml[i].vs_addr));

		if (vpm_cache_enable) {
			pp = *(((page_t **)vml[i].vs_data));
		} else {
			pp = (page_t *)vml[i].vs_data;
		}

		/*
		 * Mark page as being modified or referenced, bacause vpm pages
		 * would not cause faults where it would be set normally.
		 */
		if (rw == S_WRITE) {
			hat_setrefmod(pp);
		} else {
			ASSERT(rw == S_READ);
			hat_setref(pp);
		}

		if (vpm_cache_enable) {
			vpm = (struct vpmap *)((char *)vml[i].vs_data
			    - offsetof(struct vpmap, vpm_pp));
			hat_kpm_mapout(pp, 0, vml[i].vs_addr);
			page_unlock(pp);
			mtx = VPMAPMTX(vpm);
			mutex_enter(mtx);

			if (--vpm->vpm_refcnt == 0) {
				free_vpmap(vpm);
			}
			mutex_exit(mtx);
		} else {
			hat_kpm_mapout(pp, 0, vml[i].vs_addr);
			(void) page_release(pp, 1);
		}
		vml[i].vs_data = NULL;
		vml[i].vs_addr = NULL;
	}
}

/*
 * Given the vp, off and the uio structure, this routine will do the
 * the copy (uiomove). If the last page created is partially written,
 * the rest of the page is zeroed out. It also zeros the beginning of
 * the first page till the start offset if requested(zerostart).
 * If pages are to be fetched, it will call the filesystem's getpage
 * function (VOP_GETPAGE) to get them, otherwise they will be created if
 * not already present in the page cache.
 */
int
vpm_data_copy(struct vnode *vp,
	u_offset_t off,
	size_t len,
	struct uio *uio,
	int fetchpage,
	int *newpage,
	int zerostart,
	enum seg_rw rw)
{
	int error;
	struct vmap vml[MINVMAPS];
	enum uio_rw uiorw;
	int npages = 0;

	uiorw = (rw == S_WRITE) ? UIO_WRITE : UIO_READ;
	/*
	 * 'off' will be the offset where the I/O starts.
	 * We get the pages starting at the (off & PAGEMASK)
	 * page boundary.
	 */
	error = vpm_map_pages(vp, off, (uint_t)len,
	    fetchpage, vml, MINVMAPS, &npages,  rw);

	if (newpage != NULL)
		*newpage = npages;
	if (!error) {
		int i, pn, slen = len;
		int pon = off & PAGEOFFSET;

		/*
		 * Clear from the beginning of the page to start offset
		 * if requested.
		 */
		if (!fetchpage && zerostart) {
			(void) kzero(vml[0].vs_addr,  (uint_t)pon);
			VPM_DEBUG(vpmd_zerostart);
		}

		for (i = 0; !error && slen > 0 &&
		    vml[i].vs_addr != NULL; i++) {
			pn = (int)MIN(slen, (PAGESIZE - pon));
			error = uiomove(vml[i].vs_addr + pon,
			    (long)pn, uiorw, uio);
			slen -= pn;
			pon = 0;
		}

		/*
		 * When new pages are created, zero out part of the
		 * page we did not copy to.
		 */
		if (!fetchpage && npages &&
		    uio->uio_loffset < roundup(off + len, PAGESIZE)) {
			int nzero;

			pon = (uio->uio_loffset & PAGEOFFSET);
			nzero = PAGESIZE  - pon;
			i = (uio->uio_loffset - (off & PAGEMASK)) / PAGESIZE;
			(void) kzero(vml[i].vs_addr + pon, (uint_t)nzero);
		}
		vpm_unmap_pages(vml, rw);
	}
	return (error);
}

/*
 * called to flush pages for the given vnode covering
 * [off, off+len] range.
 */
int
vpm_sync_pages(struct vnode *vp,
		u_offset_t off,
		size_t len,
		uint_t flags)
{
	extern struct vnode *common_specvp();
	int bflags = 0;
	int error = 0;
	size_t psize = roundup(len, PAGESIZE);

	/*
	 * If this is a block device we have to be sure to use the
	 * "common" block device vnode for the mapping.
	 */
	if (vp->v_type == VBLK)
		vp = common_specvp(vp);

	if ((flags & ~SM_DONTNEED) != 0) {
		if (flags & SM_ASYNC)
			bflags |= B_ASYNC;
		if (flags & SM_INVAL)
			bflags |= B_INVAL;
		if (flags & SM_DESTROY)
			bflags |= (B_INVAL|B_TRUNC);
		if (flags & SM_FREE)
			bflags |= B_FREE;
		if (flags & SM_DONTNEED)
			bflags |= B_DONTNEED;

		error = VOP_PUTPAGE(vp, off, psize, bflags, CRED(), NULL);
	}

	return (error);
}


#else	/* SEGKPM_SUPPORT */

/* vpm stubs */
void
vpm_init()
{
}

/*ARGSUSED*/
int
vpm_pagecreate(
	struct vnode *vp,
	u_offset_t baseoff,
	size_t len,
	vmap_t vml[],
	int nseg,
	int *newpage)
{
	return (0);
}

/*ARGSUSED*/
int
vpm_map_pages(
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	int fetchpage,
	vmap_t vml[],
	int nseg,
	int *newpage,
	enum seg_rw rw)
{
	return (0);
}

/*ARGSUSED*/
int
vpm_data_copy(struct vnode *vp,
	u_offset_t off,
	size_t len,
	struct uio *uio,
	int fetchpage,
	int *newpage,
	int zerostart,
	enum seg_rw rw)
{
	return (0);
}

/*ARGSUSED*/
void
vpm_unmap_pages(vmap_t vml[], enum seg_rw rw)
{
}
/*ARGSUSED*/
int
vpm_sync_pages(struct vnode *vp,
		u_offset_t off,
		size_t len,
		uint_t flags)
{
	return (0);
}
#endif	/* SEGKPM_SUPPORT */
