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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * segkp is a segment driver that administers the allocation and deallocation
 * of pageable variable size chunks of kernel virtual address space. Each
 * allocated resource is page-aligned.
 *
 * The user may specify whether the resource should be initialized to 0,
 * include a redzone, or locked in memory.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/swap.h>
#include <sys/tuneable.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/cred.h>
#include <sys/dumphdr.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/stack.h>
#include <sys/atomic.h>
#include <sys/archsystm.h>
#include <sys/lgrp.h>

#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kp.h>
#include <vm/seg_kmem.h>
#include <vm/anon.h>
#include <vm/page.h>
#include <vm/hat.h>
#include <sys/bitmap.h>

/*
 * Private seg op routines
 */
static void	segkp_badop(void);
static void	segkp_dump(struct seg *seg);
static int	segkp_checkprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t prot);
static int	segkp_kluster(struct seg *seg, caddr_t addr, ssize_t delta);
static int	segkp_pagelock(struct seg *seg, caddr_t addr, size_t len,
			struct page ***page, enum lock_type type,
			enum seg_rw rw);
static void	segkp_insert(struct seg *seg, struct segkp_data *kpd);
static void	segkp_delete(struct seg *seg, struct segkp_data *kpd);
static caddr_t	segkp_get_internal(struct seg *seg, size_t len, uint_t flags,
			struct segkp_data **tkpd, struct anon_map *amp);
static void	segkp_release_internal(struct seg *seg,
			struct segkp_data *kpd, size_t len);
static int	segkp_unlock(struct hat *hat, struct seg *seg, caddr_t vaddr,
			size_t len, struct segkp_data *kpd, uint_t flags);
static int	segkp_load(struct hat *hat, struct seg *seg, caddr_t vaddr,
			size_t len, struct segkp_data *kpd, uint_t flags);
static struct	segkp_data *segkp_find(struct seg *seg, caddr_t vaddr);
static int	segkp_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp);
static lgrp_mem_policy_info_t	*segkp_getpolicy(struct seg *seg,
    caddr_t addr);
static int	segkp_capable(struct seg *seg, segcapability_t capability);

/*
 * Lock used to protect the hash table(s) and caches.
 */
static kmutex_t	segkp_lock;

/*
 * The segkp caches
 */
static struct segkp_cache segkp_cache[SEGKP_MAX_CACHE];

#define	SEGKP_BADOP(t)	(t(*)())segkp_badop

/*
 * When there are fewer than red_minavail bytes left on the stack,
 * segkp_map_red() will map in the redzone (if called).  5000 seems
 * to work reasonably well...
 */
long		red_minavail = 5000;

/*
 * will be set to 1 for 32 bit x86 systems only, in startup.c
 */
int	segkp_fromheap = 0;
ulong_t *segkp_bitmap;

/*
 * If segkp_map_red() is called with the redzone already mapped and
 * with less than RED_DEEP_THRESHOLD bytes available on the stack,
 * then the stack situation has become quite serious;  if much more stack
 * is consumed, we have the potential of scrogging the next thread/LWP
 * structure.  To help debug the "can't happen" panics which may
 * result from this condition, we record hrestime and the calling thread
 * in red_deep_hires and red_deep_thread respectively.
 */
#define	RED_DEEP_THRESHOLD	2000

hrtime_t	red_deep_hires;
kthread_t	*red_deep_thread;

uint32_t	red_nmapped;
uint32_t	red_closest = UINT_MAX;
uint32_t	red_ndoubles;

pgcnt_t anon_segkp_pages_locked;	/* See vm/anon.h */
pgcnt_t anon_segkp_pages_resv;		/* anon reserved by seg_kp */

static struct	seg_ops segkp_ops = {
	SEGKP_BADOP(int),		/* dup */
	SEGKP_BADOP(int),		/* unmap */
	SEGKP_BADOP(void),		/* free */
	segkp_fault,
	SEGKP_BADOP(faultcode_t),	/* faulta */
	SEGKP_BADOP(int),		/* setprot */
	segkp_checkprot,
	segkp_kluster,
	SEGKP_BADOP(size_t),		/* swapout */
	SEGKP_BADOP(int),		/* sync */
	SEGKP_BADOP(size_t),		/* incore */
	SEGKP_BADOP(int),		/* lockop */
	SEGKP_BADOP(int),		/* getprot */
	SEGKP_BADOP(u_offset_t),		/* getoffset */
	SEGKP_BADOP(int),		/* gettype */
	SEGKP_BADOP(int),		/* getvp */
	SEGKP_BADOP(int),		/* advise */
	segkp_dump,			/* dump */
	segkp_pagelock,			/* pagelock */
	SEGKP_BADOP(int),		/* setpgsz */
	segkp_getmemid,			/* getmemid */
	segkp_getpolicy,		/* getpolicy */
	segkp_capable,			/* capable */
};


static void
segkp_badop(void)
{
	panic("segkp_badop");
	/*NOTREACHED*/
}

static void segkpinit_mem_config(struct seg *);

static uint32_t segkp_indel;

/*
 * Allocate the segment specific private data struct and fill it in
 * with the per kp segment mutex, anon ptr. array and hash table.
 */
int
segkp_create(struct seg *seg)
{
	struct segkp_segdata *kpsd;
	size_t	np;

	ASSERT(seg != NULL && seg->s_as == &kas);
	ASSERT(RW_WRITE_HELD(&seg->s_as->a_lock));

	if (seg->s_size & PAGEOFFSET) {
		panic("Bad segkp size");
		/*NOTREACHED*/
	}

	kpsd = kmem_zalloc(sizeof (struct segkp_segdata), KM_SLEEP);

	/*
	 * Allocate the virtual memory for segkp and initialize it
	 */
	if (segkp_fromheap) {
		np = btop(kvseg.s_size);
		segkp_bitmap = kmem_zalloc(BT_SIZEOFMAP(np), KM_SLEEP);
		kpsd->kpsd_arena = vmem_create("segkp", NULL, 0, PAGESIZE,
		    vmem_alloc, vmem_free, heap_arena, 5 * PAGESIZE, VM_SLEEP);
	} else {
		segkp_bitmap = NULL;
		np = btop(seg->s_size);
		kpsd->kpsd_arena = vmem_create("segkp", seg->s_base,
		    seg->s_size, PAGESIZE, NULL, NULL, NULL, 5 * PAGESIZE,
		    VM_SLEEP);
	}

	kpsd->kpsd_anon = anon_create(np, ANON_SLEEP | ANON_ALLOC_FORCE);

	kpsd->kpsd_hash = kmem_zalloc(SEGKP_HASHSZ * sizeof (struct segkp *),
	    KM_SLEEP);
	seg->s_data = (void *)kpsd;
	seg->s_ops = &segkp_ops;
	segkpinit_mem_config(seg);
	return (0);
}


/*
 * Find a free 'freelist' and initialize it with the appropriate attributes
 */
void *
segkp_cache_init(struct seg *seg, int maxsize, size_t len, uint_t flags)
{
	int i;

	if ((flags & KPD_NO_ANON) && !(flags & KPD_LOCKED))
		return ((void *)-1);

	mutex_enter(&segkp_lock);
	for (i = 0; i < SEGKP_MAX_CACHE; i++) {
		if (segkp_cache[i].kpf_inuse)
			continue;
		segkp_cache[i].kpf_inuse = 1;
		segkp_cache[i].kpf_max = maxsize;
		segkp_cache[i].kpf_flags = flags;
		segkp_cache[i].kpf_seg = seg;
		segkp_cache[i].kpf_len = len;
		mutex_exit(&segkp_lock);
		return ((void *)(uintptr_t)i);
	}
	mutex_exit(&segkp_lock);
	return ((void *)-1);
}

/*
 * Free all the cache resources.
 */
void
segkp_cache_free(void)
{
	struct segkp_data *kpd;
	struct seg *seg;
	int i;

	mutex_enter(&segkp_lock);
	for (i = 0; i < SEGKP_MAX_CACHE; i++) {
		if (!segkp_cache[i].kpf_inuse)
			continue;
		/*
		 * Disconnect the freelist and process each element
		 */
		kpd = segkp_cache[i].kpf_list;
		seg = segkp_cache[i].kpf_seg;
		segkp_cache[i].kpf_list = NULL;
		segkp_cache[i].kpf_count = 0;
		mutex_exit(&segkp_lock);

		while (kpd != NULL) {
			struct segkp_data *next;

			next = kpd->kp_next;
			segkp_release_internal(seg, kpd, kpd->kp_len);
			kpd = next;
		}
		mutex_enter(&segkp_lock);
	}
	mutex_exit(&segkp_lock);
}

/*
 * There are 2 entries into segkp_get_internal. The first includes a cookie
 * used to access a pool of cached segkp resources. The second does not
 * use the cache.
 */
caddr_t
segkp_get(struct seg *seg, size_t len, uint_t flags)
{
	struct segkp_data *kpd = NULL;

	if (segkp_get_internal(seg, len, flags, &kpd, NULL) != NULL) {
		kpd->kp_cookie = -1;
		return (stom(kpd->kp_base, flags));
	}
	return (NULL);
}

/*
 * Return a 'cached' segkp address
 */
caddr_t
segkp_cache_get(void *cookie)
{
	struct segkp_cache *freelist = NULL;
	struct segkp_data *kpd = NULL;
	int index = (int)(uintptr_t)cookie;
	struct seg *seg;
	size_t len;
	uint_t flags;

	if (index < 0 || index >= SEGKP_MAX_CACHE)
		return (NULL);
	freelist = &segkp_cache[index];

	mutex_enter(&segkp_lock);
	seg = freelist->kpf_seg;
	flags = freelist->kpf_flags;
	if (freelist->kpf_list != NULL) {
		kpd = freelist->kpf_list;
		freelist->kpf_list = kpd->kp_next;
		freelist->kpf_count--;
		mutex_exit(&segkp_lock);
		kpd->kp_next = NULL;
		segkp_insert(seg, kpd);
		return (stom(kpd->kp_base, flags));
	}
	len = freelist->kpf_len;
	mutex_exit(&segkp_lock);
	if (segkp_get_internal(seg, len, flags, &kpd, NULL) != NULL) {
		kpd->kp_cookie = index;
		return (stom(kpd->kp_base, flags));
	}
	return (NULL);
}

caddr_t
segkp_get_withanonmap(
	struct seg *seg,
	size_t len,
	uint_t flags,
	struct anon_map *amp)
{
	struct segkp_data *kpd = NULL;

	ASSERT(amp != NULL);
	flags |= KPD_HASAMP;
	if (segkp_get_internal(seg, len, flags, &kpd, amp) != NULL) {
		kpd->kp_cookie = -1;
		return (stom(kpd->kp_base, flags));
	}
	return (NULL);
}

/*
 * This does the real work of segkp allocation.
 * Return to client base addr. len must be page-aligned. A null value is
 * returned if there are no more vm resources (e.g. pages, swap). The len
 * and base recorded in the private data structure include the redzone
 * and the redzone length (if applicable). If the user requests a redzone
 * either the first or last page is left unmapped depending whether stacks
 * grow to low or high memory.
 *
 * The client may also specify a no-wait flag. If that is set then the
 * request will choose a non-blocking path when requesting resources.
 * The default is make the client wait.
 */
static caddr_t
segkp_get_internal(
	struct seg *seg,
	size_t len,
	uint_t flags,
	struct segkp_data **tkpd,
	struct anon_map *amp)
{
	struct segkp_segdata	*kpsd = (struct segkp_segdata *)seg->s_data;
	struct segkp_data	*kpd;
	caddr_t vbase = NULL;	/* always first virtual, may not be mapped */
	pgcnt_t np = 0;		/* number of pages in the resource */
	pgcnt_t segkpindex;
	long i;
	caddr_t va;
	pgcnt_t pages = 0;
	ulong_t anon_idx = 0;
	int kmflag = (flags & KPD_NOWAIT) ? KM_NOSLEEP : KM_SLEEP;
	caddr_t s_base = (segkp_fromheap) ? kvseg.s_base : seg->s_base;

	if (len & PAGEOFFSET) {
		panic("segkp_get: len is not page-aligned");
		/*NOTREACHED*/
	}

	ASSERT(((flags & KPD_HASAMP) == 0) == (amp == NULL));

	/* Only allow KPD_NO_ANON if we are going to lock it down */
	if ((flags & (KPD_LOCKED|KPD_NO_ANON)) == KPD_NO_ANON)
		return (NULL);

	if ((kpd = kmem_zalloc(sizeof (struct segkp_data), kmflag)) == NULL)
		return (NULL);
	/*
	 * Fix up the len to reflect the REDZONE if applicable
	 */
	if (flags & KPD_HASREDZONE)
		len += PAGESIZE;
	np = btop(len);

	vbase = vmem_alloc(SEGKP_VMEM(seg), len, kmflag | VM_BESTFIT);
	if (vbase == NULL) {
		kmem_free(kpd, sizeof (struct segkp_data));
		return (NULL);
	}

	/* If locking, reserve physical memory */
	if (flags & KPD_LOCKED) {
		pages = btop(SEGKP_MAPLEN(len, flags));
		if (page_resv(pages, kmflag) == 0) {
			vmem_free(SEGKP_VMEM(seg), vbase, len);
			kmem_free(kpd, sizeof (struct segkp_data));
			return (NULL);
		}
		if ((flags & KPD_NO_ANON) == 0)
			atomic_add_long(&anon_segkp_pages_locked, pages);
	}

	/*
	 * Reserve sufficient swap space for this vm resource.  We'll
	 * actually allocate it in the loop below, but reserving it
	 * here allows us to back out more gracefully than if we
	 * had an allocation failure in the body of the loop.
	 *
	 * Note that we don't need swap space for the red zone page.
	 */
	if (amp != NULL) {
		/*
		 * The swap reservation has been done, if required, and the
		 * anon_hdr is separate.
		 */
		anon_idx = 0;
		kpd->kp_anon_idx = anon_idx;
		kpd->kp_anon = amp->ahp;

		TRACE_5(TR_FAC_VM, TR_ANON_SEGKP, "anon segkp:%p %p %lu %u %u",
		    kpd, vbase, len, flags, 1);

	} else if ((flags & KPD_NO_ANON) == 0) {
		if (anon_resv_zone(SEGKP_MAPLEN(len, flags), NULL) == 0) {
			if (flags & KPD_LOCKED) {
				atomic_add_long(&anon_segkp_pages_locked,
				    -pages);
				page_unresv(pages);
			}
			vmem_free(SEGKP_VMEM(seg), vbase, len);
			kmem_free(kpd, sizeof (struct segkp_data));
			return (NULL);
		}
		atomic_add_long(&anon_segkp_pages_resv,
		    btop(SEGKP_MAPLEN(len, flags)));
		anon_idx = ((uintptr_t)(vbase - s_base)) >> PAGESHIFT;
		kpd->kp_anon_idx = anon_idx;
		kpd->kp_anon = kpsd->kpsd_anon;

		TRACE_5(TR_FAC_VM, TR_ANON_SEGKP, "anon segkp:%p %p %lu %u %u",
		    kpd, vbase, len, flags, 1);
	} else {
		kpd->kp_anon = NULL;
		kpd->kp_anon_idx = 0;
	}

	/*
	 * Allocate page and anon resources for the virtual address range
	 * except the redzone
	 */
	if (segkp_fromheap)
		segkpindex = btop((uintptr_t)(vbase - kvseg.s_base));
	for (i = 0, va = vbase; i < np; i++, va += PAGESIZE) {
		page_t		*pl[2];
		struct vnode	*vp;
		anoff_t		off;
		int		err;
		page_t		*pp = NULL;

		/*
		 * Mark this page to be a segkp page in the bitmap.
		 */
		if (segkp_fromheap) {
			BT_ATOMIC_SET(segkp_bitmap, segkpindex);
			segkpindex++;
		}

		/*
		 * If this page is the red zone page, we don't need swap
		 * space for it.  Note that we skip over the code that
		 * establishes MMU mappings, so that the page remains
		 * invalid.
		 */
		if ((flags & KPD_HASREDZONE) && KPD_REDZONE(kpd) == i)
			continue;

		if (kpd->kp_anon != NULL) {
			struct anon *ap;

			ASSERT(anon_get_ptr(kpd->kp_anon, anon_idx + i)
			    == NULL);
			/*
			 * Determine the "vp" and "off" of the anon slot.
			 */
			ap = anon_alloc(NULL, 0);
			if (amp != NULL)
				ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
			(void) anon_set_ptr(kpd->kp_anon, anon_idx + i,
			    ap, ANON_SLEEP);
			if (amp != NULL)
				ANON_LOCK_EXIT(&amp->a_rwlock);
			swap_xlate(ap, &vp, &off);

			/*
			 * Create a page with the specified identity.  The
			 * page is returned with the "shared" lock held.
			 */
			err = VOP_GETPAGE(vp, (offset_t)off, PAGESIZE,
			    NULL, pl, PAGESIZE, seg, va, S_CREATE,
			    kcred, NULL);
			if (err) {
				/*
				 * XXX - This should not fail.
				 */
				panic("segkp_get: no pages");
				/*NOTREACHED*/
			}
			pp = pl[0];
		} else {
			ASSERT(page_exists(&kvp,
			    (u_offset_t)(uintptr_t)va) == NULL);

			if ((pp = page_create_va(&kvp,
			    (u_offset_t)(uintptr_t)va, PAGESIZE,
			    (flags & KPD_NOWAIT ? 0 : PG_WAIT) | PG_EXCL |
			    PG_NORELOC, seg, va)) == NULL) {
				/*
				 * Legitimize resource; then destroy it.
				 * Easier than trying to unwind here.
				 */
				kpd->kp_flags = flags;
				kpd->kp_base = vbase;
				kpd->kp_len = len;
				segkp_release_internal(seg, kpd, va - vbase);
				return (NULL);
			}
			page_io_unlock(pp);
		}

		if (flags & KPD_ZERO)
			pagezero(pp, 0, PAGESIZE);

		/*
		 * Load and lock an MMU translation for the page.
		 */
		hat_memload(seg->s_as->a_hat, va, pp, (PROT_READ|PROT_WRITE),
		    ((flags & KPD_LOCKED) ? HAT_LOAD_LOCK : HAT_LOAD));

		/*
		 * Now, release lock on the page.
		 */
		if (flags & KPD_LOCKED) {
			/*
			 * Indicate to page_retire framework that this
			 * page can only be retired when it is freed.
			 */
			PP_SETRAF(pp);
			page_downgrade(pp);
		} else
			page_unlock(pp);
	}

	kpd->kp_flags = flags;
	kpd->kp_base = vbase;
	kpd->kp_len = len;
	segkp_insert(seg, kpd);
	*tkpd = kpd;
	return (stom(kpd->kp_base, flags));
}

/*
 * Release the resource to cache if the pool(designate by the cookie)
 * has less than the maximum allowable. If inserted in cache,
 * segkp_delete insures element is taken off of active list.
 */
void
segkp_release(struct seg *seg, caddr_t vaddr)
{
	struct segkp_cache *freelist;
	struct segkp_data *kpd = NULL;

	if ((kpd = segkp_find(seg, vaddr)) == NULL) {
		panic("segkp_release: null kpd");
		/*NOTREACHED*/
	}

	if (kpd->kp_cookie != -1) {
		freelist = &segkp_cache[kpd->kp_cookie];
		mutex_enter(&segkp_lock);
		if (!segkp_indel && freelist->kpf_count < freelist->kpf_max) {
			segkp_delete(seg, kpd);
			kpd->kp_next = freelist->kpf_list;
			freelist->kpf_list = kpd;
			freelist->kpf_count++;
			mutex_exit(&segkp_lock);
			return;
		} else {
			mutex_exit(&segkp_lock);
			kpd->kp_cookie = -1;
		}
	}
	segkp_release_internal(seg, kpd, kpd->kp_len);
}

/*
 * Free the entire resource. segkp_unlock gets called with the start of the
 * mapped portion of the resource. The length is the size of the mapped
 * portion
 */
static void
segkp_release_internal(struct seg *seg, struct segkp_data *kpd, size_t len)
{
	caddr_t		va;
	long		i;
	long		redzone;
	size_t		np;
	page_t		*pp;
	struct vnode 	*vp;
	anoff_t		off;
	struct anon	*ap;
	pgcnt_t		segkpindex;

	ASSERT(kpd != NULL);
	ASSERT((kpd->kp_flags & KPD_HASAMP) == 0 || kpd->kp_cookie == -1);
	np = btop(len);

	/* Remove from active hash list */
	if (kpd->kp_cookie == -1) {
		mutex_enter(&segkp_lock);
		segkp_delete(seg, kpd);
		mutex_exit(&segkp_lock);
	}

	/*
	 * Precompute redzone page index.
	 */
	redzone = -1;
	if (kpd->kp_flags & KPD_HASREDZONE)
		redzone = KPD_REDZONE(kpd);


	va = kpd->kp_base;

	hat_unload(seg->s_as->a_hat, va, (np << PAGESHIFT),
	    ((kpd->kp_flags & KPD_LOCKED) ? HAT_UNLOAD_UNLOCK : HAT_UNLOAD));
	/*
	 * Free up those anon resources that are quiescent.
	 */
	if (segkp_fromheap)
		segkpindex = btop((uintptr_t)(va - kvseg.s_base));
	for (i = 0; i < np; i++, va += PAGESIZE) {

		/*
		 * Clear the bit for this page from the bitmap.
		 */
		if (segkp_fromheap) {
			BT_ATOMIC_CLEAR(segkp_bitmap, segkpindex);
			segkpindex++;
		}

		if (i == redzone)
			continue;
		if (kpd->kp_anon) {
			/*
			 * Free up anon resources and destroy the
			 * associated pages.
			 *
			 * Release the lock if there is one. Have to get the
			 * page to do this, unfortunately.
			 */
			if (kpd->kp_flags & KPD_LOCKED) {
				ap = anon_get_ptr(kpd->kp_anon,
				    kpd->kp_anon_idx + i);
				swap_xlate(ap, &vp, &off);
				/* Find the shared-locked page. */
				pp = page_find(vp, (u_offset_t)off);
				if (pp == NULL) {
					panic("segkp_release: "
					    "kp_anon: no page to unlock ");
					/*NOTREACHED*/
				}
				if (PP_ISRAF(pp))
					PP_CLRRAF(pp);

				page_unlock(pp);
			}
			if ((kpd->kp_flags & KPD_HASAMP) == 0) {
				anon_free(kpd->kp_anon, kpd->kp_anon_idx + i,
				    PAGESIZE);
				anon_unresv_zone(PAGESIZE, NULL);
				atomic_dec_ulong(&anon_segkp_pages_resv);
			}
			TRACE_5(TR_FAC_VM,
			    TR_ANON_SEGKP, "anon segkp:%p %p %lu %u %u",
			    kpd, va, PAGESIZE, 0, 0);
		} else {
			if (kpd->kp_flags & KPD_LOCKED) {
				pp = page_find(&kvp, (u_offset_t)(uintptr_t)va);
				if (pp == NULL) {
					panic("segkp_release: "
					    "no page to unlock");
					/*NOTREACHED*/
				}
				if (PP_ISRAF(pp))
					PP_CLRRAF(pp);
				/*
				 * We should just upgrade the lock here
				 * but there is no upgrade that waits.
				 */
				page_unlock(pp);
			}
			pp = page_lookup(&kvp, (u_offset_t)(uintptr_t)va,
			    SE_EXCL);
			if (pp != NULL)
				page_destroy(pp, 0);
		}
	}

	/* If locked, release physical memory reservation */
	if (kpd->kp_flags & KPD_LOCKED) {
		pgcnt_t pages = btop(SEGKP_MAPLEN(kpd->kp_len, kpd->kp_flags));
		if ((kpd->kp_flags & KPD_NO_ANON) == 0)
			atomic_add_long(&anon_segkp_pages_locked, -pages);
		page_unresv(pages);
	}

	vmem_free(SEGKP_VMEM(seg), kpd->kp_base, kpd->kp_len);
	kmem_free(kpd, sizeof (struct segkp_data));
}

/*
 * segkp_map_red() will check the current frame pointer against the
 * stack base.  If the amount of stack remaining is questionable
 * (less than red_minavail), then segkp_map_red() will map in the redzone
 * and return 1.  Otherwise, it will return 0.  segkp_map_red() can
 * _only_ be called when:
 *
 *   - it is safe to sleep on page_create_va().
 *   - the caller is non-swappable.
 *
 * It is up to the caller to remember whether segkp_map_red() successfully
 * mapped the redzone, and, if so, to call segkp_unmap_red() at a later
 * time.  Note that the caller must _remain_ non-swappable until after
 * calling segkp_unmap_red().
 *
 * Currently, this routine is only called from pagefault() (which necessarily
 * satisfies the above conditions).
 */
#if defined(STACK_GROWTH_DOWN)
int
segkp_map_red(void)
{
	uintptr_t fp = STACK_BIAS + (uintptr_t)getfp();
#ifndef _LP64
	caddr_t stkbase;
#endif

	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);

	/*
	 * Optimize for the common case where we simply return.
	 */
	if ((curthread->t_red_pp == NULL) &&
	    (fp - (uintptr_t)curthread->t_stkbase >= red_minavail))
		return (0);

#if defined(_LP64)
	/*
	 * XXX	We probably need something better than this.
	 */
	panic("kernel stack overflow");
	/*NOTREACHED*/
#else /* _LP64 */
	if (curthread->t_red_pp == NULL) {
		page_t *red_pp;
		struct seg kseg;

		caddr_t red_va = (caddr_t)
		    (((uintptr_t)curthread->t_stkbase & (uintptr_t)PAGEMASK) -
		    PAGESIZE);

		ASSERT(page_exists(&kvp, (u_offset_t)(uintptr_t)red_va) ==
		    NULL);

		/*
		 * Allocate the physical for the red page.
		 */
		/*
		 * No PG_NORELOC here to avoid waits. Unlikely to get
		 * a relocate happening in the short time the page exists
		 * and it will be OK anyway.
		 */

		kseg.s_as = &kas;
		red_pp = page_create_va(&kvp, (u_offset_t)(uintptr_t)red_va,
		    PAGESIZE, PG_WAIT | PG_EXCL, &kseg, red_va);
		ASSERT(red_pp != NULL);

		/*
		 * So we now have a page to jam into the redzone...
		 */
		page_io_unlock(red_pp);

		hat_memload(kas.a_hat, red_va, red_pp,
		    (PROT_READ|PROT_WRITE), HAT_LOAD_LOCK);
		page_downgrade(red_pp);

		/*
		 * The page is left SE_SHARED locked so we can hold on to
		 * the page_t pointer.
		 */
		curthread->t_red_pp = red_pp;

		atomic_inc_32(&red_nmapped);
		while (fp - (uintptr_t)curthread->t_stkbase < red_closest) {
			(void) atomic_cas_32(&red_closest, red_closest,
			    (uint32_t)(fp - (uintptr_t)curthread->t_stkbase));
		}
		return (1);
	}

	stkbase = (caddr_t)(((uintptr_t)curthread->t_stkbase &
	    (uintptr_t)PAGEMASK) - PAGESIZE);

	atomic_inc_32(&red_ndoubles);

	if (fp - (uintptr_t)stkbase < RED_DEEP_THRESHOLD) {
		/*
		 * Oh boy.  We're already deep within the mapped-in
		 * redzone page, and the caller is trying to prepare
		 * for a deep stack run.  We're running without a
		 * redzone right now:  if the caller plows off the
		 * end of the stack, it'll plow another thread or
		 * LWP structure.  That situation could result in
		 * a very hard-to-debug panic, so, in the spirit of
		 * recording the name of one's killer in one's own
		 * blood, we're going to record hrestime and the calling
		 * thread.
		 */
		red_deep_hires = hrestime.tv_nsec;
		red_deep_thread = curthread;
	}

	/*
	 * If this is a DEBUG kernel, and we've run too deep for comfort, toss.
	 */
	ASSERT(fp - (uintptr_t)stkbase >= RED_DEEP_THRESHOLD);
	return (0);
#endif /* _LP64 */
}

void
segkp_unmap_red(void)
{
	page_t *pp;
	caddr_t red_va = (caddr_t)(((uintptr_t)curthread->t_stkbase &
	    (uintptr_t)PAGEMASK) - PAGESIZE);

	ASSERT(curthread->t_red_pp != NULL);
	ASSERT(curthread->t_schedflag & TS_DONT_SWAP);

	/*
	 * Because we locked the mapping down, we can't simply rely
	 * on page_destroy() to clean everything up;  we need to call
	 * hat_unload() to explicitly unlock the mapping resources.
	 */
	hat_unload(kas.a_hat, red_va, PAGESIZE, HAT_UNLOAD_UNLOCK);

	pp = curthread->t_red_pp;

	ASSERT(pp == page_find(&kvp, (u_offset_t)(uintptr_t)red_va));

	/*
	 * Need to upgrade the SE_SHARED lock to SE_EXCL.
	 */
	if (!page_tryupgrade(pp)) {
		/*
		 * As there is now wait for upgrade, release the
		 * SE_SHARED lock and wait for SE_EXCL.
		 */
		page_unlock(pp);
		pp = page_lookup(&kvp, (u_offset_t)(uintptr_t)red_va, SE_EXCL);
		/* pp may be NULL here, hence the test below */
	}

	/*
	 * Destroy the page, with dontfree set to zero (i.e. free it).
	 */
	if (pp != NULL)
		page_destroy(pp, 0);
	curthread->t_red_pp = NULL;
}
#else
#error Red stacks only supported with downwards stack growth.
#endif

/*
 * Handle a fault on an address corresponding to one of the
 * resources in the segkp segment.
 */
faultcode_t
segkp_fault(
	struct hat	*hat,
	struct seg	*seg,
	caddr_t		vaddr,
	size_t		len,
	enum fault_type	type,
	enum seg_rw rw)
{
	struct segkp_data	*kpd = NULL;
	int			err;

	ASSERT(seg->s_as == &kas && RW_READ_HELD(&seg->s_as->a_lock));

	/*
	 * Sanity checks.
	 */
	if (type == F_PROT) {
		panic("segkp_fault: unexpected F_PROT fault");
		/*NOTREACHED*/
	}

	if ((kpd = segkp_find(seg, vaddr)) == NULL)
		return (FC_NOMAP);

	mutex_enter(&kpd->kp_lock);

	if (type == F_SOFTLOCK) {
		ASSERT(!(kpd->kp_flags & KPD_LOCKED));
		/*
		 * The F_SOFTLOCK case has more stringent
		 * range requirements: the given range must exactly coincide
		 * with the resource's mapped portion. Note reference to
		 * redzone is handled since vaddr would not equal base
		 */
		if (vaddr != stom(kpd->kp_base, kpd->kp_flags) ||
		    len != SEGKP_MAPLEN(kpd->kp_len, kpd->kp_flags)) {
			mutex_exit(&kpd->kp_lock);
			return (FC_MAKE_ERR(EFAULT));
		}

		if ((err = segkp_load(hat, seg, vaddr, len, kpd, KPD_LOCKED))) {
			mutex_exit(&kpd->kp_lock);
			return (FC_MAKE_ERR(err));
		}
		kpd->kp_flags |= KPD_LOCKED;
		mutex_exit(&kpd->kp_lock);
		return (0);
	}

	if (type == F_INVAL) {
		ASSERT(!(kpd->kp_flags & KPD_NO_ANON));

		/*
		 * Check if we touched the redzone. Somewhat optimistic
		 * here if we are touching the redzone of our own stack
		 * since we wouldn't have a stack to get this far...
		 */
		if ((kpd->kp_flags & KPD_HASREDZONE) &&
		    btop((uintptr_t)(vaddr - kpd->kp_base)) == KPD_REDZONE(kpd))
			panic("segkp_fault: accessing redzone");

		/*
		 * This fault may occur while the page is being F_SOFTLOCK'ed.
		 * Return since a 2nd segkp_load is unnecessary and also would
		 * result in the page being locked twice and eventually
		 * hang the thread_reaper thread.
		 */
		if (kpd->kp_flags & KPD_LOCKED) {
			mutex_exit(&kpd->kp_lock);
			return (0);
		}

		err = segkp_load(hat, seg, vaddr, len, kpd, kpd->kp_flags);
		mutex_exit(&kpd->kp_lock);
		return (err ? FC_MAKE_ERR(err) : 0);
	}

	if (type == F_SOFTUNLOCK) {
		uint_t	flags;

		/*
		 * Make sure the addr is LOCKED and it has anon backing
		 * before unlocking
		 */
		if ((kpd->kp_flags & (KPD_LOCKED|KPD_NO_ANON)) != KPD_LOCKED) {
			panic("segkp_fault: bad unlock");
			/*NOTREACHED*/
		}

		if (vaddr != stom(kpd->kp_base, kpd->kp_flags) ||
		    len != SEGKP_MAPLEN(kpd->kp_len, kpd->kp_flags)) {
			panic("segkp_fault: bad range");
			/*NOTREACHED*/
		}

		if (rw == S_WRITE)
			flags = kpd->kp_flags | KPD_WRITEDIRTY;
		else
			flags = kpd->kp_flags;
		err = segkp_unlock(hat, seg, vaddr, len, kpd, flags);
		kpd->kp_flags &= ~KPD_LOCKED;
		mutex_exit(&kpd->kp_lock);
		return (err ? FC_MAKE_ERR(err) : 0);
	}
	mutex_exit(&kpd->kp_lock);
	panic("segkp_fault: bogus fault type: %d\n", type);
	/*NOTREACHED*/
}

/*
 * Check that the given protections suffice over the range specified by
 * vaddr and len.  For this segment type, the only issue is whether or
 * not the range lies completely within the mapped part of an allocated
 * resource.
 */
/* ARGSUSED */
static int
segkp_checkprot(struct seg *seg, caddr_t vaddr, size_t len, uint_t prot)
{
	struct segkp_data *kpd = NULL;
	caddr_t mbase;
	size_t mlen;

	if ((kpd = segkp_find(seg, vaddr)) == NULL)
		return (EACCES);

	mutex_enter(&kpd->kp_lock);
	mbase = stom(kpd->kp_base, kpd->kp_flags);
	mlen = SEGKP_MAPLEN(kpd->kp_len, kpd->kp_flags);
	if (len > mlen || vaddr < mbase ||
	    ((vaddr + len) > (mbase + mlen))) {
		mutex_exit(&kpd->kp_lock);
		return (EACCES);
	}
	mutex_exit(&kpd->kp_lock);
	return (0);
}


/*
 * Check to see if it makes sense to do kluster/read ahead to
 * addr + delta relative to the mapping at addr.  We assume here
 * that delta is a signed PAGESIZE'd multiple (which can be negative).
 *
 * For seg_u we always "approve" of this action from our standpoint.
 */
/*ARGSUSED*/
static int
segkp_kluster(struct seg *seg, caddr_t addr, ssize_t delta)
{
	return (0);
}

/*
 * Load and possibly lock intra-slot resources in the range given by
 * vaddr and len.
 */
static int
segkp_load(
	struct hat *hat,
	struct seg *seg,
	caddr_t vaddr,
	size_t len,
	struct segkp_data *kpd,
	uint_t flags)
{
	caddr_t va;
	caddr_t vlim;
	ulong_t i;
	uint_t lock;

	ASSERT(MUTEX_HELD(&kpd->kp_lock));

	len = P2ROUNDUP(len, PAGESIZE);

	/* If locking, reserve physical memory */
	if (flags & KPD_LOCKED) {
		pgcnt_t pages = btop(len);
		if ((kpd->kp_flags & KPD_NO_ANON) == 0)
			atomic_add_long(&anon_segkp_pages_locked, pages);
		(void) page_resv(pages, KM_SLEEP);
	}

	/*
	 * Loop through the pages in the given range.
	 */
	va = (caddr_t)((uintptr_t)vaddr & (uintptr_t)PAGEMASK);
	vaddr = va;
	vlim = va + len;
	lock = flags & KPD_LOCKED;
	i = ((uintptr_t)(va - kpd->kp_base)) >> PAGESHIFT;
	for (; va < vlim; va += PAGESIZE, i++) {
		page_t		*pl[2];	/* second element NULL terminator */
		struct vnode    *vp;
		anoff_t		off;
		int		err;
		struct anon	*ap;

		/*
		 * Summon the page.  If it's not resident, arrange
		 * for synchronous i/o to pull it in.
		 */
		ap = anon_get_ptr(kpd->kp_anon, kpd->kp_anon_idx + i);
		swap_xlate(ap, &vp, &off);

		/*
		 * The returned page list will have exactly one entry,
		 * which is returned to us already kept.
		 */
		err = VOP_GETPAGE(vp, (offset_t)off, PAGESIZE, NULL,
		    pl, PAGESIZE, seg, va, S_READ, kcred, NULL);

		if (err) {
			/*
			 * Back out of what we've done so far.
			 */
			(void) segkp_unlock(hat, seg, vaddr,
			    (va - vaddr), kpd, flags);
			return (err);
		}

		/*
		 * Load an MMU translation for the page.
		 */
		hat_memload(hat, va, pl[0], (PROT_READ|PROT_WRITE),
		    lock ? HAT_LOAD_LOCK : HAT_LOAD);

		if (!lock) {
			/*
			 * Now, release "shared" lock on the page.
			 */
			page_unlock(pl[0]);
		}
	}
	return (0);
}

/*
 * At the very least unload the mmu-translations and unlock the range if locked
 * Can be called with the following flag value KPD_WRITEDIRTY which specifies
 * any dirty pages should be written to disk.
 */
static int
segkp_unlock(
	struct hat *hat,
	struct seg *seg,
	caddr_t vaddr,
	size_t len,
	struct segkp_data *kpd,
	uint_t flags)
{
	caddr_t va;
	caddr_t vlim;
	ulong_t i;
	struct page *pp;
	struct vnode *vp;
	anoff_t off;
	struct anon *ap;

#ifdef lint
	seg = seg;
#endif /* lint */

	ASSERT(MUTEX_HELD(&kpd->kp_lock));

	/*
	 * Loop through the pages in the given range. It is assumed
	 * segkp_unlock is called with page aligned base
	 */
	va = vaddr;
	vlim = va + len;
	i = ((uintptr_t)(va - kpd->kp_base)) >> PAGESHIFT;
	hat_unload(hat, va, len,
	    ((flags & KPD_LOCKED) ? HAT_UNLOAD_UNLOCK : HAT_UNLOAD));
	for (; va < vlim; va += PAGESIZE, i++) {
		/*
		 * Find the page associated with this part of the
		 * slot, tracking it down through its associated swap
		 * space.
		 */
		ap = anon_get_ptr(kpd->kp_anon, kpd->kp_anon_idx + i);
		swap_xlate(ap, &vp, &off);

		if (flags & KPD_LOCKED) {
			if ((pp = page_find(vp, off)) == NULL) {
				if (flags & KPD_LOCKED) {
					panic("segkp_softunlock: missing page");
					/*NOTREACHED*/
				}
			}
		} else {
			/*
			 * Nothing to do if the slot is not locked and the
			 * page doesn't exist.
			 */
			if ((pp = page_lookup(vp, off, SE_SHARED)) == NULL)
				continue;
		}

		/*
		 * If the page doesn't have any translations, is
		 * dirty and not being shared, then push it out
		 * asynchronously and avoid waiting for the
		 * pageout daemon to do it for us.
		 *
		 * XXX - Do we really need to get the "exclusive"
		 * lock via an upgrade?
		 */
		if ((flags & KPD_WRITEDIRTY) && !hat_page_is_mapped(pp) &&
		    hat_ismod(pp) && page_tryupgrade(pp)) {
			/*
			 * Hold the vnode before releasing the page lock to
			 * prevent it from being freed and re-used by some
			 * other thread.
			 */
			VN_HOLD(vp);
			page_unlock(pp);

			/*
			 * Want most powerful credentials we can get so
			 * use kcred.
			 */
			(void) VOP_PUTPAGE(vp, (offset_t)off, PAGESIZE,
			    B_ASYNC | B_FREE, kcred, NULL);
			VN_RELE(vp);
		} else {
			page_unlock(pp);
		}
	}

	/* If unlocking, release physical memory */
	if (flags & KPD_LOCKED) {
		pgcnt_t pages = btopr(len);
		if ((kpd->kp_flags & KPD_NO_ANON) == 0)
			atomic_add_long(&anon_segkp_pages_locked, -pages);
		page_unresv(pages);
	}
	return (0);
}

/*
 * Insert the kpd in the hash table.
 */
static void
segkp_insert(struct seg *seg, struct segkp_data *kpd)
{
	struct segkp_segdata *kpsd = (struct segkp_segdata *)seg->s_data;
	int index;

	/*
	 * Insert the kpd based on the address that will be returned
	 * via segkp_release.
	 */
	index = SEGKP_HASH(stom(kpd->kp_base, kpd->kp_flags));
	mutex_enter(&segkp_lock);
	kpd->kp_next = kpsd->kpsd_hash[index];
	kpsd->kpsd_hash[index] = kpd;
	mutex_exit(&segkp_lock);
}

/*
 * Remove kpd from the hash table.
 */
static void
segkp_delete(struct seg *seg, struct segkp_data *kpd)
{
	struct segkp_segdata *kpsd = (struct segkp_segdata *)seg->s_data;
	struct segkp_data **kpp;
	int index;

	ASSERT(MUTEX_HELD(&segkp_lock));

	index = SEGKP_HASH(stom(kpd->kp_base, kpd->kp_flags));
	for (kpp = &kpsd->kpsd_hash[index];
	    *kpp != NULL; kpp = &((*kpp)->kp_next)) {
		if (*kpp == kpd) {
			*kpp = kpd->kp_next;
			return;
		}
	}
	panic("segkp_delete: unable to find element to delete");
	/*NOTREACHED*/
}

/*
 * Find the kpd associated with a vaddr.
 *
 * Most of the callers of segkp_find will pass the vaddr that
 * hashes to the desired index, but there are cases where
 * this is not true in which case we have to (potentially) scan
 * the whole table looking for it. This should be very rare
 * (e.g. a segkp_fault(F_INVAL) on an address somewhere in the
 * middle of the segkp_data region).
 */
static struct segkp_data *
segkp_find(struct seg *seg, caddr_t vaddr)
{
	struct segkp_segdata *kpsd = (struct segkp_segdata *)seg->s_data;
	struct segkp_data *kpd;
	int	i;
	int	stop;

	i = stop = SEGKP_HASH(vaddr);
	mutex_enter(&segkp_lock);
	do {
		for (kpd = kpsd->kpsd_hash[i]; kpd != NULL;
		    kpd = kpd->kp_next) {
			if (vaddr >= kpd->kp_base &&
			    vaddr < kpd->kp_base + kpd->kp_len) {
				mutex_exit(&segkp_lock);
				return (kpd);
			}
		}
		if (--i < 0)
			i = SEGKP_HASHSZ - 1;	/* Wrap */
	} while (i != stop);
	mutex_exit(&segkp_lock);
	return (NULL);		/* Not found */
}

/*
 * returns size of swappable area.
 */
size_t
swapsize(caddr_t v)
{
	struct segkp_data *kpd;

	if ((kpd = segkp_find(segkp, v)) != NULL)
		return (SEGKP_MAPLEN(kpd->kp_len, kpd->kp_flags));
	else
		return (NULL);
}

/*
 * Dump out all the active segkp pages
 */
static void
segkp_dump(struct seg *seg)
{
	int i;
	struct segkp_data *kpd;
	struct segkp_segdata *kpsd = (struct segkp_segdata *)seg->s_data;

	for (i = 0; i < SEGKP_HASHSZ; i++) {
		for (kpd = kpsd->kpsd_hash[i];
		    kpd != NULL; kpd = kpd->kp_next) {
			pfn_t pfn;
			caddr_t addr;
			caddr_t eaddr;

			addr = kpd->kp_base;
			eaddr = addr + kpd->kp_len;
			while (addr < eaddr) {
				ASSERT(seg->s_as == &kas);
				pfn = hat_getpfnum(seg->s_as->a_hat, addr);
				if (pfn != PFN_INVALID)
					dump_addpage(seg->s_as, addr, pfn);
				addr += PAGESIZE;
				dump_timeleft = dump_timeout;
			}
		}
	}
}

/*ARGSUSED*/
static int
segkp_pagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
segkp_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	return (ENODEV);
}

/*ARGSUSED*/
static lgrp_mem_policy_info_t	*
segkp_getpolicy(struct seg *seg, caddr_t addr)
{
	return (NULL);
}

/*ARGSUSED*/
static int
segkp_capable(struct seg *seg, segcapability_t capability)
{
	return (0);
}

#include <sys/mem_config.h>

/*ARGSUSED*/
static void
segkp_mem_config_post_add(void *arg, pgcnt_t delta_pages)
{}

/*
 * During memory delete, turn off caches so that pages are not held.
 * A better solution may be to unlock the pages while they are
 * in the cache so that they may be collected naturally.
 */

/*ARGSUSED*/
static int
segkp_mem_config_pre_del(void *arg, pgcnt_t delta_pages)
{
	atomic_inc_32(&segkp_indel);
	segkp_cache_free();
	return (0);
}

/*ARGSUSED*/
static void
segkp_mem_config_post_del(void *arg, pgcnt_t delta_pages, int cancelled)
{
	atomic_dec_32(&segkp_indel);
}

static kphysm_setup_vector_t segkp_mem_config_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	segkp_mem_config_post_add,
	segkp_mem_config_pre_del,
	segkp_mem_config_post_del,
};

static void
segkpinit_mem_config(struct seg *seg)
{
	int ret;

	ret = kphysm_setup_func_register(&segkp_mem_config_vec, (void *)seg);
	ASSERT(ret == 0);
}
