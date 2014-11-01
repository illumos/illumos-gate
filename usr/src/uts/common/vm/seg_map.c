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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * VM - generic vnode mapping segment.
 *
 * The segmap driver is used only by the kernel to get faster (than seg_vn)
 * mappings [lower routine overhead; more persistent cache] to random
 * vnode/offsets.  Note than the kernel may (and does) use seg_vn as well.
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

/*
 * Private seg op routines.
 */
static void	segmap_free(struct seg *seg);
faultcode_t segmap_fault(struct hat *hat, struct seg *seg, caddr_t addr,
			size_t len, enum fault_type type, enum seg_rw rw);
static faultcode_t segmap_faulta(struct seg *seg, caddr_t addr);
static int	segmap_checkprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t prot);
static int	segmap_kluster(struct seg *seg, caddr_t addr, ssize_t);
static int	segmap_getprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t *protv);
static u_offset_t	segmap_getoffset(struct seg *seg, caddr_t addr);
static int	segmap_gettype(struct seg *seg, caddr_t addr);
static int	segmap_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp);
static void	segmap_dump(struct seg *seg);
static int	segmap_pagelock(struct seg *seg, caddr_t addr, size_t len,
			struct page ***ppp, enum lock_type type,
			enum seg_rw rw);
static void	segmap_badop(void);
static int	segmap_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp);
static lgrp_mem_policy_info_t	*segmap_getpolicy(struct seg *seg,
    caddr_t addr);
static int	segmap_capable(struct seg *seg, segcapability_t capability);

/* segkpm support */
static caddr_t	segmap_pagecreate_kpm(struct seg *, vnode_t *, u_offset_t,
			struct smap *, enum seg_rw);
struct smap	*get_smap_kpm(caddr_t, page_t **);

#define	SEGMAP_BADOP(t)	(t(*)())segmap_badop

static struct seg_ops segmap_ops = {
	SEGMAP_BADOP(int),	/* dup */
	SEGMAP_BADOP(int),	/* unmap */
	segmap_free,
	segmap_fault,
	segmap_faulta,
	SEGMAP_BADOP(int),	/* setprot */
	segmap_checkprot,
	segmap_kluster,
	SEGMAP_BADOP(size_t),	/* swapout */
	SEGMAP_BADOP(int),	/* sync */
	SEGMAP_BADOP(size_t),	/* incore */
	SEGMAP_BADOP(int),	/* lockop */
	segmap_getprot,
	segmap_getoffset,
	segmap_gettype,
	segmap_getvp,
	SEGMAP_BADOP(int),	/* advise */
	segmap_dump,
	segmap_pagelock,	/* pagelock */
	SEGMAP_BADOP(int),	/* setpgsz */
	segmap_getmemid,	/* getmemid */
	segmap_getpolicy,	/* getpolicy */
	segmap_capable,		/* capable */
};

/*
 * Private segmap routines.
 */
static void	segmap_unlock(struct hat *hat, struct seg *seg, caddr_t addr,
			size_t len, enum seg_rw rw, struct smap *smp);
static void	segmap_smapadd(struct smap *smp);
static struct smap *segmap_hashin(struct smap *smp, struct vnode *vp,
			u_offset_t off, int hashid);
static void	segmap_hashout(struct smap *smp);


/*
 * Statistics for segmap operations.
 *
 * No explicit locking to protect these stats.
 */
struct segmapcnt segmapcnt = {
	{ "fault",		KSTAT_DATA_ULONG },
	{ "faulta",		KSTAT_DATA_ULONG },
	{ "getmap",		KSTAT_DATA_ULONG },
	{ "get_use",		KSTAT_DATA_ULONG },
	{ "get_reclaim",	KSTAT_DATA_ULONG },
	{ "get_reuse",		KSTAT_DATA_ULONG },
	{ "get_unused",		KSTAT_DATA_ULONG },
	{ "get_nofree",		KSTAT_DATA_ULONG },
	{ "rel_async",		KSTAT_DATA_ULONG },
	{ "rel_write",		KSTAT_DATA_ULONG },
	{ "rel_free",		KSTAT_DATA_ULONG },
	{ "rel_abort",		KSTAT_DATA_ULONG },
	{ "rel_dontneed",	KSTAT_DATA_ULONG },
	{ "release",		KSTAT_DATA_ULONG },
	{ "pagecreate",		KSTAT_DATA_ULONG },
	{ "free_notfree",	KSTAT_DATA_ULONG },
	{ "free_dirty",		KSTAT_DATA_ULONG },
	{ "free",		KSTAT_DATA_ULONG },
	{ "stolen",		KSTAT_DATA_ULONG },
	{ "get_nomtx",		KSTAT_DATA_ULONG }
};

kstat_named_t *segmapcnt_ptr = (kstat_named_t *)&segmapcnt;
uint_t segmapcnt_ndata = sizeof (segmapcnt) / sizeof (kstat_named_t);

/*
 * Return number of map pages in segment.
 */
#define	MAP_PAGES(seg)		((seg)->s_size >> MAXBSHIFT)

/*
 * Translate addr into smap number within segment.
 */
#define	MAP_PAGE(seg, addr)  (((addr) - (seg)->s_base) >> MAXBSHIFT)

/*
 * Translate addr in seg into struct smap pointer.
 */
#define	GET_SMAP(seg, addr)	\
	&(((struct segmap_data *)((seg)->s_data))->smd_sm[MAP_PAGE(seg, addr)])

/*
 * Bit in map (16 bit bitmap).
 */
#define	SMAP_BIT_MASK(bitindex)	(1 << ((bitindex) & 0xf))

static int smd_colormsk = 0;
static int smd_ncolor = 0;
static int smd_nfree = 0;
static int smd_freemsk = 0;
#ifdef DEBUG
static int *colors_used;
#endif
static struct smap *smd_smap;
static struct smaphash *smd_hash;
#ifdef SEGMAP_HASHSTATS
static unsigned int *smd_hash_len;
#endif
static struct smfree *smd_free;
static ulong_t smd_hashmsk = 0;

#define	SEGMAP_MAXCOLOR		2
#define	SEGMAP_CACHE_PAD	64

union segmap_cpu {
	struct {
		uint32_t	scpu_free_ndx[SEGMAP_MAXCOLOR];
		struct smap	*scpu_last_smap;
		ulong_t		scpu_getmap;
		ulong_t		scpu_release;
		ulong_t		scpu_get_reclaim;
		ulong_t		scpu_fault;
		ulong_t		scpu_pagecreate;
		ulong_t		scpu_get_reuse;
	} scpu;
	char	scpu_pad[SEGMAP_CACHE_PAD];
};
static union segmap_cpu *smd_cpu;

/*
 * There are three locks in seg_map:
 *	- per freelist mutexes
 *	- per hashchain mutexes
 *	- per smap mutexes
 *
 * The lock ordering is to get the smap mutex to lock down the slot
 * first then the hash lock (for hash in/out (vp, off) list) or the
 * freelist lock to put the slot back on the free list.
 *
 * The hash search is done by only holding the hashchain lock, when a wanted
 * slot is found, we drop the hashchain lock then lock the slot so there
 * is no overlapping of hashchain and smap locks. After the slot is
 * locked, we verify again if the slot is still what we are looking
 * for.
 *
 * Allocation of a free slot is done by holding the freelist lock,
 * then locking the smap slot at the head of the freelist. This is
 * in reversed lock order so mutex_tryenter() is used.
 *
 * The smap lock protects all fields in smap structure except for
 * the link fields for hash/free lists which are protected by
 * hashchain and freelist locks.
 */

#define	SHASHMTX(hashid)	(&smd_hash[hashid].sh_mtx)

#define	SMP2SMF(smp)		(&smd_free[(smp - smd_smap) & smd_freemsk])
#define	SMP2SMF_NDX(smp)	(ushort_t)((smp - smd_smap) & smd_freemsk)

#define	SMAPMTX(smp) (&smp->sm_mtx)

#define	SMAP_HASHFUNC(vp, off, hashid) \
	{ \
	hashid = ((((uintptr_t)(vp) >> 6) + ((uintptr_t)(vp) >> 3) + \
		((off) >> MAXBSHIFT)) & smd_hashmsk); \
	}

/*
 * The most frequently updated kstat counters are kept in the
 * per cpu array to avoid hot cache blocks. The update function
 * sums the cpu local counters to update the global counters.
 */

/* ARGSUSED */
int
segmap_kstat_update(kstat_t *ksp, int rw)
{
	int i;
	ulong_t	getmap, release, get_reclaim;
	ulong_t	fault, pagecreate, get_reuse;

	if (rw == KSTAT_WRITE)
		return (EACCES);
	getmap = release = get_reclaim = (ulong_t)0;
	fault = pagecreate = get_reuse = (ulong_t)0;
	for (i = 0; i < max_ncpus; i++) {
		getmap += smd_cpu[i].scpu.scpu_getmap;
		release  += smd_cpu[i].scpu.scpu_release;
		get_reclaim += smd_cpu[i].scpu.scpu_get_reclaim;
		fault  += smd_cpu[i].scpu.scpu_fault;
		pagecreate  += smd_cpu[i].scpu.scpu_pagecreate;
		get_reuse += smd_cpu[i].scpu.scpu_get_reuse;
	}
	segmapcnt.smp_getmap.value.ul = getmap;
	segmapcnt.smp_release.value.ul = release;
	segmapcnt.smp_get_reclaim.value.ul = get_reclaim;
	segmapcnt.smp_fault.value.ul = fault;
	segmapcnt.smp_pagecreate.value.ul = pagecreate;
	segmapcnt.smp_get_reuse.value.ul = get_reuse;
	return (0);
}

int
segmap_create(struct seg *seg, void *argsp)
{
	struct segmap_data *smd;
	struct smap *smp;
	struct smfree *sm;
	struct segmap_crargs *a = (struct segmap_crargs *)argsp;
	struct smaphash *shashp;
	union segmap_cpu *scpu;
	long i, npages;
	size_t hashsz;
	uint_t nfreelist;
	extern void prefetch_smap_w(void *);
	extern int max_ncpus;

	ASSERT(seg->s_as && RW_WRITE_HELD(&seg->s_as->a_lock));

	if (((uintptr_t)seg->s_base | seg->s_size) & MAXBOFFSET) {
		panic("segkmap not MAXBSIZE aligned");
		/*NOTREACHED*/
	}

	smd = kmem_zalloc(sizeof (struct segmap_data), KM_SLEEP);

	seg->s_data = (void *)smd;
	seg->s_ops = &segmap_ops;
	smd->smd_prot = a->prot;

	/*
	 * Scale the number of smap freelists to be
	 * proportional to max_ncpus * number of virtual colors.
	 * The caller can over-ride this scaling by providing
	 * a non-zero a->nfreelist argument.
	 */
	nfreelist = a->nfreelist;
	if (nfreelist == 0)
		nfreelist = max_ncpus;
	else if (nfreelist < 0 || nfreelist > 4 * max_ncpus) {
		cmn_err(CE_WARN, "segmap_create: nfreelist out of range "
		"%d, using %d", nfreelist, max_ncpus);
		nfreelist = max_ncpus;
	}
	if (!ISP2(nfreelist)) {
		/* round up nfreelist to the next power of two. */
		nfreelist = 1 << (highbit(nfreelist));
	}

	/*
	 * Get the number of virtual colors - must be a power of 2.
	 */
	if (a->shmsize)
		smd_ncolor = a->shmsize >> MAXBSHIFT;
	else
		smd_ncolor = 1;
	ASSERT((smd_ncolor & (smd_ncolor - 1)) == 0);
	ASSERT(smd_ncolor <= SEGMAP_MAXCOLOR);
	smd_colormsk = smd_ncolor - 1;
	smd->smd_nfree = smd_nfree = smd_ncolor * nfreelist;
	smd_freemsk = smd_nfree - 1;

	/*
	 * Allocate and initialize the freelist headers.
	 * Note that sm_freeq[1] starts out as the release queue. This
	 * is known when the smap structures are initialized below.
	 */
	smd_free = smd->smd_free =
	    kmem_zalloc(smd_nfree * sizeof (struct smfree), KM_SLEEP);
	for (i = 0; i < smd_nfree; i++) {
		sm = &smd->smd_free[i];
		mutex_init(&sm->sm_freeq[0].smq_mtx, NULL, MUTEX_DEFAULT, NULL);
		mutex_init(&sm->sm_freeq[1].smq_mtx, NULL, MUTEX_DEFAULT, NULL);
		sm->sm_allocq = &sm->sm_freeq[0];
		sm->sm_releq = &sm->sm_freeq[1];
	}

	/*
	 * Allocate and initialize the smap hash chain headers.
	 * Compute hash size rounding down to the next power of two.
	 */
	npages = MAP_PAGES(seg);
	smd->smd_npages = npages;
	hashsz = npages / SMAP_HASHAVELEN;
	hashsz = 1 << (highbit(hashsz)-1);
	smd_hashmsk = hashsz - 1;
	smd_hash = smd->smd_hash =
	    kmem_alloc(hashsz * sizeof (struct smaphash), KM_SLEEP);
#ifdef SEGMAP_HASHSTATS
	smd_hash_len =
	    kmem_zalloc(hashsz * sizeof (unsigned int), KM_SLEEP);
#endif
	for (i = 0, shashp = smd_hash; i < hashsz; i++, shashp++) {
		shashp->sh_hash_list = NULL;
		mutex_init(&shashp->sh_mtx, NULL, MUTEX_DEFAULT, NULL);
	}

	/*
	 * Allocate and initialize the smap structures.
	 * Link all slots onto the appropriate freelist.
	 * The smap array is large enough to affect boot time
	 * on large systems, so use memory prefetching and only
	 * go through the array 1 time. Inline a optimized version
	 * of segmap_smapadd to add structures to freelists with
	 * knowledge that no locks are needed here.
	 */
	smd_smap = smd->smd_sm =
	    kmem_alloc(sizeof (struct smap) * npages, KM_SLEEP);

	for (smp = &smd->smd_sm[MAP_PAGES(seg) - 1];
	    smp >= smd->smd_sm; smp--) {
		struct smap *smpfreelist;
		struct sm_freeq *releq;

		prefetch_smap_w((char *)smp);

		smp->sm_vp = NULL;
		smp->sm_hash = NULL;
		smp->sm_off = 0;
		smp->sm_bitmap = 0;
		smp->sm_refcnt = 0;
		mutex_init(&smp->sm_mtx, NULL, MUTEX_DEFAULT, NULL);
		smp->sm_free_ndx = SMP2SMF_NDX(smp);

		sm = SMP2SMF(smp);
		releq = sm->sm_releq;

		smpfreelist = releq->smq_free;
		if (smpfreelist == 0) {
			releq->smq_free = smp->sm_next = smp->sm_prev = smp;
		} else {
			smp->sm_next = smpfreelist;
			smp->sm_prev = smpfreelist->sm_prev;
			smpfreelist->sm_prev = smp;
			smp->sm_prev->sm_next = smp;
			releq->smq_free = smp->sm_next;
		}

		/*
		 * sm_flag = 0 (no SM_QNDX_ZERO) implies smap on sm_freeq[1]
		 */
		smp->sm_flags = 0;

#ifdef	SEGKPM_SUPPORT
		/*
		 * Due to the fragile prefetch loop no
		 * separate function is used here.
		 */
		smp->sm_kpme_next = NULL;
		smp->sm_kpme_prev = NULL;
		smp->sm_kpme_page = NULL;
#endif
	}

	/*
	 * Allocate the per color indices that distribute allocation
	 * requests over the free lists. Each cpu will have a private
	 * rotor index to spread the allocations even across the available
	 * smap freelists. Init the scpu_last_smap field to the first
	 * smap element so there is no need to check for NULL.
	 */
	smd_cpu =
	    kmem_zalloc(sizeof (union segmap_cpu) * max_ncpus, KM_SLEEP);
	for (i = 0, scpu = smd_cpu; i < max_ncpus; i++, scpu++) {
		int j;
		for (j = 0; j < smd_ncolor; j++)
			scpu->scpu.scpu_free_ndx[j] = j;
		scpu->scpu.scpu_last_smap = smd_smap;
	}

	vpm_init();

#ifdef DEBUG
	/*
	 * Keep track of which colors are used more often.
	 */
	colors_used = kmem_zalloc(smd_nfree * sizeof (int), KM_SLEEP);
#endif /* DEBUG */

	return (0);
}

static void
segmap_free(seg)
	struct seg *seg;
{
	ASSERT(seg->s_as && RW_WRITE_HELD(&seg->s_as->a_lock));
}

/*
 * Do a F_SOFTUNLOCK call over the range requested.
 * The range must have already been F_SOFTLOCK'ed.
 */
static void
segmap_unlock(
	struct hat *hat,
	struct seg *seg,
	caddr_t addr,
	size_t len,
	enum seg_rw rw,
	struct smap *smp)
{
	page_t *pp;
	caddr_t adr;
	u_offset_t off;
	struct vnode *vp;
	kmutex_t *smtx;

	ASSERT(smp->sm_refcnt > 0);

#ifdef lint
	seg = seg;
#endif

	if (segmap_kpm && IS_KPM_ADDR(addr)) {

		/*
		 * We're called only from segmap_fault and this was a
		 * NOP in case of a kpm based smap, so dangerous things
		 * must have happened in the meantime. Pages are prefaulted
		 * and locked in segmap_getmapflt and they will not be
		 * unlocked until segmap_release.
		 */
		panic("segmap_unlock: called with kpm addr %p", (void *)addr);
		/*NOTREACHED*/
	}

	vp = smp->sm_vp;
	off = smp->sm_off + (u_offset_t)((uintptr_t)addr & MAXBOFFSET);

	hat_unlock(hat, addr, P2ROUNDUP(len, PAGESIZE));
	for (adr = addr; adr < addr + len; adr += PAGESIZE, off += PAGESIZE) {
		ushort_t bitmask;

		/*
		 * Use page_find() instead of page_lookup() to
		 * find the page since we know that it has
		 * "shared" lock.
		 */
		pp = page_find(vp, off);
		if (pp == NULL) {
			panic("segmap_unlock: page not found");
			/*NOTREACHED*/
		}

		if (rw == S_WRITE) {
			hat_setrefmod(pp);
		} else if (rw != S_OTHER) {
			TRACE_3(TR_FAC_VM, TR_SEGMAP_FAULT,
			"segmap_fault:pp %p vp %p offset %llx", pp, vp, off);
			hat_setref(pp);
		}

		/*
		 * Clear bitmap, if the bit corresponding to "off" is set,
		 * since the page and translation are being unlocked.
		 */
		bitmask = SMAP_BIT_MASK((off - smp->sm_off) >> PAGESHIFT);

		/*
		 * Large Files: Following assertion is to verify
		 * the correctness of the cast to (int) above.
		 */
		ASSERT((u_offset_t)(off - smp->sm_off) <= INT_MAX);
		smtx = SMAPMTX(smp);
		mutex_enter(smtx);
		if (smp->sm_bitmap & bitmask) {
			smp->sm_bitmap &= ~bitmask;
		}
		mutex_exit(smtx);

		page_unlock(pp);
	}
}

#define	MAXPPB	(MAXBSIZE/4096)	/* assumes minimum page size of 4k */

/*
 * This routine is called via a machine specific fault handling
 * routine.  It is also called by software routines wishing to
 * lock or unlock a range of addresses.
 *
 * Note that this routine expects a page-aligned "addr".
 */
faultcode_t
segmap_fault(
	struct hat *hat,
	struct seg *seg,
	caddr_t addr,
	size_t len,
	enum fault_type type,
	enum seg_rw rw)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;
	struct smap *smp;
	page_t *pp, **ppp;
	struct vnode *vp;
	u_offset_t off;
	page_t *pl[MAXPPB + 1];
	uint_t prot;
	u_offset_t addroff;
	caddr_t adr;
	int err;
	u_offset_t sm_off;
	int hat_flag;

	if (segmap_kpm && IS_KPM_ADDR(addr)) {
		int newpage;
		kmutex_t *smtx;

		/*
		 * Pages are successfully prefaulted and locked in
		 * segmap_getmapflt and can't be unlocked until
		 * segmap_release. No hat mappings have to be locked
		 * and they also can't be unlocked as long as the
		 * caller owns an active kpm addr.
		 */
#ifndef DEBUG
		if (type != F_SOFTUNLOCK)
			return (0);
#endif

		if ((smp = get_smap_kpm(addr, NULL)) == NULL) {
			panic("segmap_fault: smap not found "
			    "for addr %p", (void *)addr);
			/*NOTREACHED*/
		}

		smtx = SMAPMTX(smp);
#ifdef	DEBUG
		newpage = smp->sm_flags & SM_KPM_NEWPAGE;
		if (newpage) {
			cmn_err(CE_WARN, "segmap_fault: newpage? smp %p",
			    (void *)smp);
		}

		if (type != F_SOFTUNLOCK) {
			mutex_exit(smtx);
			return (0);
		}
#endif
		mutex_exit(smtx);
		vp = smp->sm_vp;
		sm_off = smp->sm_off;

		if (vp == NULL)
			return (FC_MAKE_ERR(EIO));

		ASSERT(smp->sm_refcnt > 0);

		addroff = (u_offset_t)((uintptr_t)addr & MAXBOFFSET);
		if (addroff + len > MAXBSIZE)
			panic("segmap_fault: endaddr %p exceeds MAXBSIZE chunk",
			    (void *)(addr + len));

		off = sm_off + addroff;

		pp = page_find(vp, off);

		if (pp == NULL)
			panic("segmap_fault: softunlock page not found");

		/*
		 * Set ref bit also here in case of S_OTHER to avoid the
		 * overhead of supporting other cases than F_SOFTUNLOCK
		 * with segkpm. We can do this because the underlying
		 * pages are locked anyway.
		 */
		if (rw == S_WRITE) {
			hat_setrefmod(pp);
		} else {
			TRACE_3(TR_FAC_VM, TR_SEGMAP_FAULT,
			    "segmap_fault:pp %p vp %p offset %llx",
			    pp, vp, off);
			hat_setref(pp);
		}

		return (0);
	}

	smd_cpu[CPU->cpu_seqid].scpu.scpu_fault++;
	smp = GET_SMAP(seg, addr);
	vp = smp->sm_vp;
	sm_off = smp->sm_off;

	if (vp == NULL)
		return (FC_MAKE_ERR(EIO));

	ASSERT(smp->sm_refcnt > 0);

	addroff = (u_offset_t)((uintptr_t)addr & MAXBOFFSET);
	if (addroff + len > MAXBSIZE) {
		panic("segmap_fault: endaddr %p "
		    "exceeds MAXBSIZE chunk", (void *)(addr + len));
		/*NOTREACHED*/
	}
	off = sm_off + addroff;

	/*
	 * First handle the easy stuff
	 */
	if (type == F_SOFTUNLOCK) {
		segmap_unlock(hat, seg, addr, len, rw, smp);
		return (0);
	}

	TRACE_3(TR_FAC_VM, TR_SEGMAP_GETPAGE,
	    "segmap_getpage:seg %p addr %p vp %p", seg, addr, vp);
	err = VOP_GETPAGE(vp, (offset_t)off, len, &prot, pl, MAXBSIZE,
	    seg, addr, rw, CRED(), NULL);

	if (err)
		return (FC_MAKE_ERR(err));

	prot &= smd->smd_prot;

	/*
	 * Handle all pages returned in the pl[] array.
	 * This loop is coded on the assumption that if
	 * there was no error from the VOP_GETPAGE routine,
	 * that the page list returned will contain all the
	 * needed pages for the vp from [off..off + len].
	 */
	ppp = pl;
	while ((pp = *ppp++) != NULL) {
		u_offset_t poff;
		ASSERT(pp->p_vnode == vp);
		hat_flag = HAT_LOAD;

		/*
		 * Verify that the pages returned are within the range
		 * of this segmap region.  Note that it is theoretically
		 * possible for pages outside this range to be returned,
		 * but it is not very likely.  If we cannot use the
		 * page here, just release it and go on to the next one.
		 */
		if (pp->p_offset < sm_off ||
		    pp->p_offset >= sm_off + MAXBSIZE) {
			(void) page_release(pp, 1);
			continue;
		}

		ASSERT(hat == kas.a_hat);
		poff = pp->p_offset;
		adr = addr + (poff - off);
		if (adr >= addr && adr < addr + len) {
			hat_setref(pp);
			TRACE_3(TR_FAC_VM, TR_SEGMAP_FAULT,
			    "segmap_fault:pp %p vp %p offset %llx",
			    pp, vp, poff);
			if (type == F_SOFTLOCK)
				hat_flag = HAT_LOAD_LOCK;
		}

		/*
		 * Deal with VMODSORT pages here. If we know this is a write
		 * do the setmod now and allow write protection.
		 * As long as it's modified or not S_OTHER, remove write
		 * protection. With S_OTHER it's up to the FS to deal with this.
		 */
		if (IS_VMODSORT(vp)) {
			if (rw == S_WRITE)
				hat_setmod(pp);
			else if (rw != S_OTHER && !hat_ismod(pp))
				prot &= ~PROT_WRITE;
		}

		hat_memload(hat, adr, pp, prot, hat_flag);
		if (hat_flag != HAT_LOAD_LOCK)
			page_unlock(pp);
	}
	return (0);
}

/*
 * This routine is used to start I/O on pages asynchronously.
 */
static faultcode_t
segmap_faulta(struct seg *seg, caddr_t addr)
{
	struct smap *smp;
	struct vnode *vp;
	u_offset_t off;
	int err;

	if (segmap_kpm && IS_KPM_ADDR(addr)) {
		int	newpage;
		kmutex_t *smtx;

		/*
		 * Pages are successfully prefaulted and locked in
		 * segmap_getmapflt and can't be unlocked until
		 * segmap_release. No hat mappings have to be locked
		 * and they also can't be unlocked as long as the
		 * caller owns an active kpm addr.
		 */
#ifdef	DEBUG
		if ((smp = get_smap_kpm(addr, NULL)) == NULL) {
			panic("segmap_faulta: smap not found "
			    "for addr %p", (void *)addr);
			/*NOTREACHED*/
		}

		smtx = SMAPMTX(smp);
		newpage = smp->sm_flags & SM_KPM_NEWPAGE;
		mutex_exit(smtx);
		if (newpage)
			cmn_err(CE_WARN, "segmap_faulta: newpage? smp %p",
			    (void *)smp);
#endif
		return (0);
	}

	segmapcnt.smp_faulta.value.ul++;
	smp = GET_SMAP(seg, addr);

	ASSERT(smp->sm_refcnt > 0);

	vp = smp->sm_vp;
	off = smp->sm_off;

	if (vp == NULL) {
		cmn_err(CE_WARN, "segmap_faulta - no vp");
		return (FC_MAKE_ERR(EIO));
	}

	TRACE_3(TR_FAC_VM, TR_SEGMAP_GETPAGE,
	    "segmap_getpage:seg %p addr %p vp %p", seg, addr, vp);

	err = VOP_GETPAGE(vp, (offset_t)(off + ((offset_t)((uintptr_t)addr
	    & MAXBOFFSET))), PAGESIZE, (uint_t *)NULL, (page_t **)NULL, 0,
	    seg, addr, S_READ, CRED(), NULL);

	if (err)
		return (FC_MAKE_ERR(err));
	return (0);
}

/*ARGSUSED*/
static int
segmap_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;

	ASSERT(seg->s_as && RW_LOCK_HELD(&seg->s_as->a_lock));

	/*
	 * Need not acquire the segment lock since
	 * "smd_prot" is a read-only field.
	 */
	return (((smd->smd_prot & prot) != prot) ? EACCES : 0);
}

static int
segmap_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;
	size_t pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	if (pgno != 0) {
		do {
			protv[--pgno] = smd->smd_prot;
		} while (pgno != 0);
	}
	return (0);
}

static u_offset_t
segmap_getoffset(struct seg *seg, caddr_t addr)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;

	ASSERT(seg->s_as && RW_READ_HELD(&seg->s_as->a_lock));

	return ((u_offset_t)smd->smd_sm->sm_off + (addr - seg->s_base));
}

/*ARGSUSED*/
static int
segmap_gettype(struct seg *seg, caddr_t addr)
{
	ASSERT(seg->s_as && RW_READ_HELD(&seg->s_as->a_lock));

	return (MAP_SHARED);
}

/*ARGSUSED*/
static int
segmap_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;

	ASSERT(seg->s_as && RW_READ_HELD(&seg->s_as->a_lock));

	/* XXX - This doesn't make any sense */
	*vpp = smd->smd_sm->sm_vp;
	return (0);
}

/*
 * Check to see if it makes sense to do kluster/read ahead to
 * addr + delta relative to the mapping at addr.  We assume here
 * that delta is a signed PAGESIZE'd multiple (which can be negative).
 *
 * For segmap we always "approve" of this action from our standpoint.
 */
/*ARGSUSED*/
static int
segmap_kluster(struct seg *seg, caddr_t addr, ssize_t delta)
{
	return (0);
}

static void
segmap_badop()
{
	panic("segmap_badop");
	/*NOTREACHED*/
}

/*
 * Special private segmap operations
 */

/*
 * Add smap to the appropriate free list.
 */
static void
segmap_smapadd(struct smap *smp)
{
	struct smfree *sm;
	struct smap *smpfreelist;
	struct sm_freeq *releq;

	ASSERT(MUTEX_HELD(SMAPMTX(smp)));

	if (smp->sm_refcnt != 0) {
		panic("segmap_smapadd");
		/*NOTREACHED*/
	}

	sm = &smd_free[smp->sm_free_ndx];
	/*
	 * Add to the tail of the release queue
	 * Note that sm_releq and sm_allocq could toggle
	 * before we get the lock. This does not affect
	 * correctness as the 2 queues are only maintained
	 * to reduce lock pressure.
	 */
	releq = sm->sm_releq;
	if (releq == &sm->sm_freeq[0])
		smp->sm_flags |= SM_QNDX_ZERO;
	else
		smp->sm_flags &= ~SM_QNDX_ZERO;
	mutex_enter(&releq->smq_mtx);
	smpfreelist = releq->smq_free;
	if (smpfreelist == 0) {
		int want;

		releq->smq_free = smp->sm_next = smp->sm_prev = smp;
		/*
		 * Both queue mutexes held to set sm_want;
		 * snapshot the value before dropping releq mutex.
		 * If sm_want appears after the releq mutex is dropped,
		 * then the smap just freed is already gone.
		 */
		want = sm->sm_want;
		mutex_exit(&releq->smq_mtx);
		/*
		 * See if there was a waiter before dropping the releq mutex
		 * then recheck after obtaining sm_freeq[0] mutex as
		 * the another thread may have already signaled.
		 */
		if (want) {
			mutex_enter(&sm->sm_freeq[0].smq_mtx);
			if (sm->sm_want)
				cv_signal(&sm->sm_free_cv);
			mutex_exit(&sm->sm_freeq[0].smq_mtx);
		}
	} else {
		smp->sm_next = smpfreelist;
		smp->sm_prev = smpfreelist->sm_prev;
		smpfreelist->sm_prev = smp;
		smp->sm_prev->sm_next = smp;
		mutex_exit(&releq->smq_mtx);
	}
}


static struct smap *
segmap_hashin(struct smap *smp, struct vnode *vp, u_offset_t off, int hashid)
{
	struct smap **hpp;
	struct smap *tmp;
	kmutex_t *hmtx;

	ASSERT(MUTEX_HELD(SMAPMTX(smp)));
	ASSERT(smp->sm_vp == NULL);
	ASSERT(smp->sm_hash == NULL);
	ASSERT(smp->sm_prev == NULL);
	ASSERT(smp->sm_next == NULL);
	ASSERT(hashid >= 0 && hashid <= smd_hashmsk);

	hmtx = SHASHMTX(hashid);

	mutex_enter(hmtx);
	/*
	 * First we need to verify that no one has created a smp
	 * with (vp,off) as its tag before we us.
	 */
	for (tmp = smd_hash[hashid].sh_hash_list;
	    tmp != NULL; tmp = tmp->sm_hash)
		if (tmp->sm_vp == vp && tmp->sm_off == off)
			break;

	if (tmp == NULL) {
		/*
		 * No one created one yet.
		 *
		 * Funniness here - we don't increment the ref count on the
		 * vnode * even though we have another pointer to it here.
		 * The reason for this is that we don't want the fact that
		 * a seg_map entry somewhere refers to a vnode to prevent the
		 * vnode * itself from going away.  This is because this
		 * reference to the vnode is a "soft one".  In the case where
		 * a mapping is being used by a rdwr [or directory routine?]
		 * there already has to be a non-zero ref count on the vnode.
		 * In the case where the vp has been freed and the the smap
		 * structure is on the free list, there are no pages in memory
		 * that can refer to the vnode.  Thus even if we reuse the same
		 * vnode/smap structure for a vnode which has the same
		 * address but represents a different object, we are ok.
		 */
		smp->sm_vp = vp;
		smp->sm_off = off;

		hpp = &smd_hash[hashid].sh_hash_list;
		smp->sm_hash = *hpp;
		*hpp = smp;
#ifdef SEGMAP_HASHSTATS
		smd_hash_len[hashid]++;
#endif
	}
	mutex_exit(hmtx);

	return (tmp);
}

static void
segmap_hashout(struct smap *smp)
{
	struct smap **hpp, *hp;
	struct vnode *vp;
	kmutex_t *mtx;
	int hashid;
	u_offset_t off;

	ASSERT(MUTEX_HELD(SMAPMTX(smp)));

	vp = smp->sm_vp;
	off = smp->sm_off;

	SMAP_HASHFUNC(vp, off, hashid);	/* macro assigns hashid */
	mtx = SHASHMTX(hashid);
	mutex_enter(mtx);

	hpp = &smd_hash[hashid].sh_hash_list;
	for (;;) {
		hp = *hpp;
		if (hp == NULL) {
			panic("segmap_hashout");
			/*NOTREACHED*/
		}
		if (hp == smp)
			break;
		hpp = &hp->sm_hash;
	}

	*hpp = smp->sm_hash;
	smp->sm_hash = NULL;
#ifdef SEGMAP_HASHSTATS
	smd_hash_len[hashid]--;
#endif
	mutex_exit(mtx);

	smp->sm_vp = NULL;
	smp->sm_off = (u_offset_t)0;

}

/*
 * Attempt to free unmodified, unmapped, and non locked segmap
 * pages.
 */
void
segmap_pagefree(struct vnode *vp, u_offset_t off)
{
	u_offset_t pgoff;
	page_t  *pp;

	for (pgoff = off; pgoff < off + MAXBSIZE; pgoff += PAGESIZE) {

		if ((pp = page_lookup_nowait(vp, pgoff, SE_EXCL)) == NULL)
			continue;

		switch (page_release(pp, 1)) {
		case PGREL_NOTREL:
			segmapcnt.smp_free_notfree.value.ul++;
			break;
		case PGREL_MOD:
			segmapcnt.smp_free_dirty.value.ul++;
			break;
		case PGREL_CLEAN:
			segmapcnt.smp_free.value.ul++;
			break;
		}
	}
}

/*
 * Locks held on entry: smap lock
 * Locks held on exit : smap lock.
 */

static void
grab_smp(struct smap *smp, page_t *pp)
{
	ASSERT(MUTEX_HELD(SMAPMTX(smp)));
	ASSERT(smp->sm_refcnt == 0);

	if (smp->sm_vp != (struct vnode *)NULL) {
		struct vnode	*vp = smp->sm_vp;
		u_offset_t 	off = smp->sm_off;
		/*
		 * Destroy old vnode association and
		 * unload any hardware translations to
		 * the old object.
		 */
		smd_cpu[CPU->cpu_seqid].scpu.scpu_get_reuse++;
		segmap_hashout(smp);

		/*
		 * This node is off freelist and hashlist,
		 * so there is no reason to drop/reacquire sm_mtx
		 * across calls to hat_unload.
		 */
		if (segmap_kpm) {
			caddr_t vaddr;
			int hat_unload_needed = 0;

			/*
			 * unload kpm mapping
			 */
			if (pp != NULL) {
				vaddr = hat_kpm_page2va(pp, 1);
				hat_kpm_mapout(pp, GET_KPME(smp), vaddr);
				page_unlock(pp);
			}

			/*
			 * Check if we have (also) the rare case of a
			 * non kpm mapping.
			 */
			if (smp->sm_flags & SM_NOTKPM_RELEASED) {
				hat_unload_needed = 1;
				smp->sm_flags &= ~SM_NOTKPM_RELEASED;
			}

			if (hat_unload_needed) {
				hat_unload(kas.a_hat, segkmap->s_base +
				    ((smp - smd_smap) * MAXBSIZE),
				    MAXBSIZE, HAT_UNLOAD);
			}

		} else {
			ASSERT(smp->sm_flags & SM_NOTKPM_RELEASED);
			smp->sm_flags &= ~SM_NOTKPM_RELEASED;
			hat_unload(kas.a_hat, segkmap->s_base +
			    ((smp - smd_smap) * MAXBSIZE),
			    MAXBSIZE, HAT_UNLOAD);
		}
		segmap_pagefree(vp, off);
	}
}

static struct smap *
get_free_smp(int free_ndx)
{
	struct smfree *sm;
	kmutex_t *smtx;
	struct smap *smp, *first;
	struct sm_freeq *allocq, *releq;
	struct kpme *kpme;
	page_t *pp = NULL;
	int end_ndx, page_locked = 0;

	end_ndx = free_ndx;
	sm = &smd_free[free_ndx];

retry_queue:
	allocq = sm->sm_allocq;
	mutex_enter(&allocq->smq_mtx);

	if ((smp = allocq->smq_free) == NULL) {

skip_queue:
		/*
		 * The alloc list is empty or this queue is being skipped;
		 * first see if the allocq toggled.
		 */
		if (sm->sm_allocq != allocq) {
			/* queue changed */
			mutex_exit(&allocq->smq_mtx);
			goto retry_queue;
		}
		releq = sm->sm_releq;
		if (!mutex_tryenter(&releq->smq_mtx)) {
			/* cannot get releq; a free smp may be there now */
			mutex_exit(&allocq->smq_mtx);

			/*
			 * This loop could spin forever if this thread has
			 * higher priority than the thread that is holding
			 * releq->smq_mtx. In order to force the other thread
			 * to run, we'll lock/unlock the mutex which is safe
			 * since we just unlocked the allocq mutex.
			 */
			mutex_enter(&releq->smq_mtx);
			mutex_exit(&releq->smq_mtx);
			goto retry_queue;
		}
		if (releq->smq_free == NULL) {
			/*
			 * This freelist is empty.
			 * This should not happen unless clients
			 * are failing to release the segmap
			 * window after accessing the data.
			 * Before resorting to sleeping, try
			 * the next list of the same color.
			 */
			free_ndx = (free_ndx + smd_ncolor) & smd_freemsk;
			if (free_ndx != end_ndx) {
				mutex_exit(&releq->smq_mtx);
				mutex_exit(&allocq->smq_mtx);
				sm = &smd_free[free_ndx];
				goto retry_queue;
			}
			/*
			 * Tried all freelists of the same color once,
			 * wait on this list and hope something gets freed.
			 */
			segmapcnt.smp_get_nofree.value.ul++;
			sm->sm_want++;
			mutex_exit(&sm->sm_freeq[1].smq_mtx);
			cv_wait(&sm->sm_free_cv,
			    &sm->sm_freeq[0].smq_mtx);
			sm->sm_want--;
			mutex_exit(&sm->sm_freeq[0].smq_mtx);
			sm = &smd_free[free_ndx];
			goto retry_queue;
		} else {
			/*
			 * Something on the rele queue; flip the alloc
			 * and rele queues and retry.
			 */
			sm->sm_allocq = releq;
			sm->sm_releq = allocq;
			mutex_exit(&allocq->smq_mtx);
			mutex_exit(&releq->smq_mtx);
			if (page_locked) {
				delay(hz >> 2);
				page_locked = 0;
			}
			goto retry_queue;
		}
	} else {
		/*
		 * Fastpath the case we get the smap mutex
		 * on the first try.
		 */
		first = smp;
next_smap:
		smtx = SMAPMTX(smp);
		if (!mutex_tryenter(smtx)) {
			/*
			 * Another thread is trying to reclaim this slot.
			 * Skip to the next queue or smap.
			 */
			if ((smp = smp->sm_next) == first) {
				goto skip_queue;
			} else {
				goto next_smap;
			}
		} else {
			/*
			 * if kpme exists, get shared lock on the page
			 */
			if (segmap_kpm && smp->sm_vp != NULL) {

				kpme = GET_KPME(smp);
				pp = kpme->kpe_page;

				if (pp != NULL) {
					if (!page_trylock(pp, SE_SHARED)) {
						smp = smp->sm_next;
						mutex_exit(smtx);
						page_locked = 1;

						pp = NULL;

						if (smp == first) {
							goto skip_queue;
						} else {
							goto next_smap;
						}
					} else {
						if (kpme->kpe_page == NULL) {
							page_unlock(pp);
							pp = NULL;
						}
					}
				}
			}

			/*
			 * At this point, we've selected smp.  Remove smp
			 * from its freelist.  If smp is the first one in
			 * the freelist, update the head of the freelist.
			 */
			if (first == smp) {
				ASSERT(first == allocq->smq_free);
				allocq->smq_free = smp->sm_next;
			}

			/*
			 * if the head of the freelist still points to smp,
			 * then there are no more free smaps in that list.
			 */
			if (allocq->smq_free == smp)
				/*
				 * Took the last one
				 */
				allocq->smq_free = NULL;
			else {
				smp->sm_prev->sm_next = smp->sm_next;
				smp->sm_next->sm_prev = smp->sm_prev;
			}
			mutex_exit(&allocq->smq_mtx);
			smp->sm_prev = smp->sm_next = NULL;

			/*
			 * if pp != NULL, pp must have been locked;
			 * grab_smp() unlocks pp.
			 */
			ASSERT((pp == NULL) || PAGE_LOCKED(pp));
			grab_smp(smp, pp);
			/* return smp locked. */
			ASSERT(SMAPMTX(smp) == smtx);
			ASSERT(MUTEX_HELD(smtx));
			return (smp);
		}
	}
}

/*
 * Special public segmap operations
 */

/*
 * Create pages (without using VOP_GETPAGE) and load up translations to them.
 * If softlock is TRUE, then set things up so that it looks like a call
 * to segmap_fault with F_SOFTLOCK.
 *
 * Returns 1, if a page is created by calling page_create_va(), or 0 otherwise.
 *
 * All fields in the generic segment (struct seg) are considered to be
 * read-only for "segmap" even though the kernel address space (kas) may
 * not be locked, hence no lock is needed to access them.
 */
int
segmap_pagecreate(struct seg *seg, caddr_t addr, size_t len, int softlock)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;
	page_t *pp;
	u_offset_t off;
	struct smap *smp;
	struct vnode *vp;
	caddr_t eaddr;
	int newpage = 0;
	uint_t prot;
	kmutex_t *smtx;
	int hat_flag;

	ASSERT(seg->s_as == &kas);

	if (segmap_kpm && IS_KPM_ADDR(addr)) {
		/*
		 * Pages are successfully prefaulted and locked in
		 * segmap_getmapflt and can't be unlocked until
		 * segmap_release. The SM_KPM_NEWPAGE flag is set
		 * in segmap_pagecreate_kpm when new pages are created.
		 * and it is returned as "newpage" indication here.
		 */
		if ((smp = get_smap_kpm(addr, NULL)) == NULL) {
			panic("segmap_pagecreate: smap not found "
			    "for addr %p", (void *)addr);
			/*NOTREACHED*/
		}

		smtx = SMAPMTX(smp);
		newpage = smp->sm_flags & SM_KPM_NEWPAGE;
		smp->sm_flags &= ~SM_KPM_NEWPAGE;
		mutex_exit(smtx);

		return (newpage);
	}

	smd_cpu[CPU->cpu_seqid].scpu.scpu_pagecreate++;

	eaddr = addr + len;
	addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);

	smp = GET_SMAP(seg, addr);

	/*
	 * We don't grab smp mutex here since we assume the smp
	 * has a refcnt set already which prevents the slot from
	 * changing its id.
	 */
	ASSERT(smp->sm_refcnt > 0);

	vp = smp->sm_vp;
	off = smp->sm_off + ((u_offset_t)((uintptr_t)addr & MAXBOFFSET));
	prot = smd->smd_prot;

	for (; addr < eaddr; addr += PAGESIZE, off += PAGESIZE) {
		hat_flag = HAT_LOAD;
		pp = page_lookup(vp, off, SE_SHARED);
		if (pp == NULL) {
			ushort_t bitindex;

			if ((pp = page_create_va(vp, off,
			    PAGESIZE, PG_WAIT, seg, addr)) == NULL) {
				panic("segmap_pagecreate: page_create failed");
				/*NOTREACHED*/
			}
			newpage = 1;
			page_io_unlock(pp);

			/*
			 * Since pages created here do not contain valid
			 * data until the caller writes into them, the
			 * "exclusive" lock will not be dropped to prevent
			 * other users from accessing the page.  We also
			 * have to lock the translation to prevent a fault
			 * from occurring when the virtual address mapped by
			 * this page is written into.  This is necessary to
			 * avoid a deadlock since we haven't dropped the
			 * "exclusive" lock.
			 */
			bitindex = (ushort_t)((off - smp->sm_off) >> PAGESHIFT);

			/*
			 * Large Files: The following assertion is to
			 * verify the cast above.
			 */
			ASSERT((u_offset_t)(off - smp->sm_off) <= INT_MAX);
			smtx = SMAPMTX(smp);
			mutex_enter(smtx);
			smp->sm_bitmap |= SMAP_BIT_MASK(bitindex);
			mutex_exit(smtx);

			hat_flag = HAT_LOAD_LOCK;
		} else if (softlock) {
			hat_flag = HAT_LOAD_LOCK;
		}

		if (IS_VMODSORT(pp->p_vnode) && (prot & PROT_WRITE))
			hat_setmod(pp);

		hat_memload(kas.a_hat, addr, pp, prot, hat_flag);

		if (hat_flag != HAT_LOAD_LOCK)
			page_unlock(pp);

		TRACE_5(TR_FAC_VM, TR_SEGMAP_PAGECREATE,
		    "segmap_pagecreate:seg %p addr %p pp %p vp %p offset %llx",
		    seg, addr, pp, vp, off);
	}

	return (newpage);
}

void
segmap_pageunlock(struct seg *seg, caddr_t addr, size_t len, enum seg_rw rw)
{
	struct smap	*smp;
	ushort_t	bitmask;
	page_t		*pp;
	struct	vnode	*vp;
	u_offset_t	off;
	caddr_t		eaddr;
	kmutex_t	*smtx;

	ASSERT(seg->s_as == &kas);

	eaddr = addr + len;
	addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);

	if (segmap_kpm && IS_KPM_ADDR(addr)) {
		/*
		 * Pages are successfully prefaulted and locked in
		 * segmap_getmapflt and can't be unlocked until
		 * segmap_release, so no pages or hat mappings have
		 * to be unlocked at this point.
		 */
#ifdef DEBUG
		if ((smp = get_smap_kpm(addr, NULL)) == NULL) {
			panic("segmap_pageunlock: smap not found "
			    "for addr %p", (void *)addr);
			/*NOTREACHED*/
		}

		ASSERT(smp->sm_refcnt > 0);
		mutex_exit(SMAPMTX(smp));
#endif
		return;
	}

	smp = GET_SMAP(seg, addr);
	smtx = SMAPMTX(smp);

	ASSERT(smp->sm_refcnt > 0);

	vp = smp->sm_vp;
	off = smp->sm_off + ((u_offset_t)((uintptr_t)addr & MAXBOFFSET));

	for (; addr < eaddr; addr += PAGESIZE, off += PAGESIZE) {
		bitmask = SMAP_BIT_MASK((int)(off - smp->sm_off) >> PAGESHIFT);

		/*
		 * Large Files: Following assertion is to verify
		 * the correctness of the cast to (int) above.
		 */
		ASSERT((u_offset_t)(off - smp->sm_off) <= INT_MAX);

		/*
		 * If the bit corresponding to "off" is set,
		 * clear this bit in the bitmap, unlock translations,
		 * and release the "exclusive" lock on the page.
		 */
		if (smp->sm_bitmap & bitmask) {
			mutex_enter(smtx);
			smp->sm_bitmap &= ~bitmask;
			mutex_exit(smtx);

			hat_unlock(kas.a_hat, addr, PAGESIZE);

			/*
			 * Use page_find() instead of page_lookup() to
			 * find the page since we know that it has
			 * "exclusive" lock.
			 */
			pp = page_find(vp, off);
			if (pp == NULL) {
				panic("segmap_pageunlock: page not found");
				/*NOTREACHED*/
			}
			if (rw == S_WRITE) {
				hat_setrefmod(pp);
			} else if (rw != S_OTHER) {
				hat_setref(pp);
			}

			page_unlock(pp);
		}
	}
}

caddr_t
segmap_getmap(struct seg *seg, struct vnode *vp, u_offset_t off)
{
	return (segmap_getmapflt(seg, vp, off, MAXBSIZE, 0, S_OTHER));
}

/*
 * This is the magic virtual address that offset 0 of an ELF
 * file gets mapped to in user space. This is used to pick
 * the vac color on the freelist.
 */
#define	ELF_OFFZERO_VA	(0x10000)
/*
 * segmap_getmap allocates a MAXBSIZE big slot to map the vnode vp
 * in the range <off, off + len). off doesn't need to be MAXBSIZE aligned.
 * The return address is  always MAXBSIZE aligned.
 *
 * If forcefault is nonzero and the MMU translations haven't yet been created,
 * segmap_getmap will call segmap_fault(..., F_INVAL, rw) to create them.
 */
caddr_t
segmap_getmapflt(
	struct seg *seg,
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	int forcefault,
	enum seg_rw rw)
{
	struct smap *smp, *nsmp;
	extern struct vnode *common_specvp();
	caddr_t baseaddr;			/* MAXBSIZE aligned */
	u_offset_t baseoff;
	int newslot;
	caddr_t vaddr;
	int color, hashid;
	kmutex_t *hashmtx, *smapmtx;
	struct smfree *sm;
	page_t	*pp;
	struct kpme *kpme;
	uint_t	prot;
	caddr_t base;
	page_t	*pl[MAXPPB + 1];
	int	error;
	int	is_kpm = 1;

	ASSERT(seg->s_as == &kas);
	ASSERT(seg == segkmap);

	baseoff = off & (offset_t)MAXBMASK;
	if (off + len > baseoff + MAXBSIZE) {
		panic("segmap_getmap bad len");
		/*NOTREACHED*/
	}

	/*
	 * If this is a block device we have to be sure to use the
	 * "common" block device vnode for the mapping.
	 */
	if (vp->v_type == VBLK)
		vp = common_specvp(vp);

	smd_cpu[CPU->cpu_seqid].scpu.scpu_getmap++;

	if (segmap_kpm == 0 ||
	    (forcefault == SM_PAGECREATE && rw != S_WRITE)) {
		is_kpm = 0;
	}

	SMAP_HASHFUNC(vp, off, hashid);	/* macro assigns hashid */
	hashmtx = SHASHMTX(hashid);

retry_hash:
	mutex_enter(hashmtx);
	for (smp = smd_hash[hashid].sh_hash_list;
	    smp != NULL; smp = smp->sm_hash)
		if (smp->sm_vp == vp && smp->sm_off == baseoff)
			break;
	mutex_exit(hashmtx);

vrfy_smp:
	if (smp != NULL) {

		ASSERT(vp->v_count != 0);

		/*
		 * Get smap lock and recheck its tag. The hash lock
		 * is dropped since the hash is based on (vp, off)
		 * and (vp, off) won't change when we have smap mtx.
		 */
		smapmtx = SMAPMTX(smp);
		mutex_enter(smapmtx);
		if (smp->sm_vp != vp || smp->sm_off != baseoff) {
			mutex_exit(smapmtx);
			goto retry_hash;
		}

		if (smp->sm_refcnt == 0) {

			smd_cpu[CPU->cpu_seqid].scpu.scpu_get_reclaim++;

			/*
			 * Could still be on the free list. However, this
			 * could also be an smp that is transitioning from
			 * the free list when we have too much contention
			 * for the smapmtx's. In this case, we have an
			 * unlocked smp that is not on the free list any
			 * longer, but still has a 0 refcnt.  The only way
			 * to be sure is to check the freelist pointers.
			 * Since we now have the smapmtx, we are guaranteed
			 * that the (vp, off) won't change, so we are safe
			 * to reclaim it.  get_free_smp() knows that this
			 * can happen, and it will check the refcnt.
			 */

			if ((smp->sm_next != NULL)) {
				struct sm_freeq *freeq;

				ASSERT(smp->sm_prev != NULL);
				sm = &smd_free[smp->sm_free_ndx];

				if (smp->sm_flags & SM_QNDX_ZERO)
					freeq = &sm->sm_freeq[0];
				else
					freeq = &sm->sm_freeq[1];

				mutex_enter(&freeq->smq_mtx);
				if (freeq->smq_free != smp) {
					/*
					 * fastpath normal case
					 */
					smp->sm_prev->sm_next = smp->sm_next;
					smp->sm_next->sm_prev = smp->sm_prev;
				} else if (smp == smp->sm_next) {
					/*
					 * Taking the last smap on freelist
					 */
					freeq->smq_free = NULL;
				} else {
					/*
					 * Reclaiming 1st smap on list
					 */
					freeq->smq_free = smp->sm_next;
					smp->sm_prev->sm_next = smp->sm_next;
					smp->sm_next->sm_prev = smp->sm_prev;
				}
				mutex_exit(&freeq->smq_mtx);
				smp->sm_prev = smp->sm_next = NULL;
			} else {
				ASSERT(smp->sm_prev == NULL);
				segmapcnt.smp_stolen.value.ul++;
			}

		} else {
			segmapcnt.smp_get_use.value.ul++;
		}
		smp->sm_refcnt++;		/* another user */

		/*
		 * We don't invoke segmap_fault via TLB miss, so we set ref
		 * and mod bits in advance. For S_OTHER  we set them in
		 * segmap_fault F_SOFTUNLOCK.
		 */
		if (is_kpm) {
			if (rw == S_WRITE) {
				smp->sm_flags |= SM_WRITE_DATA;
			} else if (rw == S_READ) {
				smp->sm_flags |= SM_READ_DATA;
			}
		}
		mutex_exit(smapmtx);

		newslot = 0;
	} else {

		uint32_t free_ndx, *free_ndxp;
		union segmap_cpu *scpu;

		/*
		 * On a PAC machine or a machine with anti-alias
		 * hardware, smd_colormsk will be zero.
		 *
		 * On a VAC machine- pick color by offset in the file
		 * so we won't get VAC conflicts on elf files.
		 * On data files, color does not matter but we
		 * don't know what kind of file it is so we always
		 * pick color by offset. This causes color
		 * corresponding to file offset zero to be used more
		 * heavily.
		 */
		color = (baseoff >> MAXBSHIFT) & smd_colormsk;
		scpu = smd_cpu+CPU->cpu_seqid;
		free_ndxp = &scpu->scpu.scpu_free_ndx[color];
		free_ndx = (*free_ndxp += smd_ncolor) & smd_freemsk;
#ifdef DEBUG
		colors_used[free_ndx]++;
#endif /* DEBUG */

		/*
		 * Get a locked smp slot from the free list.
		 */
		smp = get_free_smp(free_ndx);
		smapmtx = SMAPMTX(smp);

		ASSERT(smp->sm_vp == NULL);

		if ((nsmp = segmap_hashin(smp, vp, baseoff, hashid)) != NULL) {
			/*
			 * Failed to hashin, there exists one now.
			 * Return the smp we just allocated.
			 */
			segmap_smapadd(smp);
			mutex_exit(smapmtx);

			smp = nsmp;
			goto vrfy_smp;
		}
		smp->sm_refcnt++;		/* another user */

		/*
		 * We don't invoke segmap_fault via TLB miss, so we set ref
		 * and mod bits in advance. For S_OTHER  we set them in
		 * segmap_fault F_SOFTUNLOCK.
		 */
		if (is_kpm) {
			if (rw == S_WRITE) {
				smp->sm_flags |= SM_WRITE_DATA;
			} else if (rw == S_READ) {
				smp->sm_flags |= SM_READ_DATA;
			}
		}
		mutex_exit(smapmtx);

		newslot = 1;
	}

	if (!is_kpm)
		goto use_segmap_range;

	/*
	 * Use segkpm
	 */
	/* Lint directive required until 6746211 is fixed */
	/*CONSTCOND*/
	ASSERT(PAGESIZE == MAXBSIZE);

	/*
	 * remember the last smp faulted on this cpu.
	 */
	(smd_cpu+CPU->cpu_seqid)->scpu.scpu_last_smap = smp;

	if (forcefault == SM_PAGECREATE) {
		baseaddr = segmap_pagecreate_kpm(seg, vp, baseoff, smp, rw);
		return (baseaddr);
	}

	if (newslot == 0 &&
	    (pp = GET_KPME(smp)->kpe_page) != NULL) {

		/* fastpath */
		switch (rw) {
		case S_READ:
		case S_WRITE:
			if (page_trylock(pp, SE_SHARED)) {
				if (PP_ISFREE(pp) ||
				    !(pp->p_vnode == vp &&
				    pp->p_offset == baseoff)) {
					page_unlock(pp);
					pp = page_lookup(vp, baseoff,
					    SE_SHARED);
				}
			} else {
				pp = page_lookup(vp, baseoff, SE_SHARED);
			}

			if (pp == NULL) {
				ASSERT(GET_KPME(smp)->kpe_page == NULL);
				break;
			}

			if (rw == S_WRITE &&
			    hat_page_getattr(pp, P_MOD | P_REF) !=
			    (P_MOD | P_REF)) {
				page_unlock(pp);
				break;
			}

			/*
			 * We have the p_selock as reader, grab_smp
			 * can't hit us, we have bumped the smap
			 * refcnt and hat_pageunload needs the
			 * p_selock exclusive.
			 */
			kpme = GET_KPME(smp);
			if (kpme->kpe_page == pp) {
				baseaddr = hat_kpm_page2va(pp, 0);
			} else if (kpme->kpe_page == NULL) {
				baseaddr = hat_kpm_mapin(pp, kpme);
			} else {
				panic("segmap_getmapflt: stale "
				    "kpme page, kpme %p", (void *)kpme);
				/*NOTREACHED*/
			}

			/*
			 * We don't invoke segmap_fault via TLB miss,
			 * so we set ref and mod bits in advance.
			 * For S_OTHER and we set them in segmap_fault
			 * F_SOFTUNLOCK.
			 */
			if (rw == S_READ && !hat_isref(pp))
				hat_setref(pp);

			return (baseaddr);
		default:
			break;
		}
	}

	base = segkpm_create_va(baseoff);
	error = VOP_GETPAGE(vp, (offset_t)baseoff, len, &prot, pl, MAXBSIZE,
	    seg, base, rw, CRED(), NULL);

	pp = pl[0];
	if (error || pp == NULL) {
		/*
		 * Use segmap address slot and let segmap_fault deal
		 * with the error cases. There is no error return
		 * possible here.
		 */
		goto use_segmap_range;
	}

	ASSERT(pl[1] == NULL);

	/*
	 * When prot is not returned w/ PROT_ALL the returned pages
	 * are not backed by fs blocks. For most of the segmap users
	 * this is no problem, they don't write to the pages in the
	 * same request and therefore don't rely on a following
	 * trap driven segmap_fault. With SM_LOCKPROTO users it
	 * is more secure to use segkmap adresses to allow
	 * protection segmap_fault's.
	 */
	if (prot != PROT_ALL && forcefault == SM_LOCKPROTO) {
		/*
		 * Use segmap address slot and let segmap_fault
		 * do the error return.
		 */
		ASSERT(rw != S_WRITE);
		ASSERT(PAGE_LOCKED(pp));
		page_unlock(pp);
		forcefault = 0;
		goto use_segmap_range;
	}

	/*
	 * We have the p_selock as reader, grab_smp can't hit us, we
	 * have bumped the smap refcnt and hat_pageunload needs the
	 * p_selock exclusive.
	 */
	kpme = GET_KPME(smp);
	if (kpme->kpe_page == pp) {
		baseaddr = hat_kpm_page2va(pp, 0);
	} else if (kpme->kpe_page == NULL) {
		baseaddr = hat_kpm_mapin(pp, kpme);
	} else {
		panic("segmap_getmapflt: stale kpme page after "
		    "VOP_GETPAGE, kpme %p", (void *)kpme);
		/*NOTREACHED*/
	}

	smd_cpu[CPU->cpu_seqid].scpu.scpu_fault++;

	return (baseaddr);


use_segmap_range:
	baseaddr = seg->s_base + ((smp - smd_smap) * MAXBSIZE);
	TRACE_4(TR_FAC_VM, TR_SEGMAP_GETMAP,
	    "segmap_getmap:seg %p addr %p vp %p offset %llx",
	    seg, baseaddr, vp, baseoff);

	/*
	 * Prefault the translations
	 */
	vaddr = baseaddr + (off - baseoff);
	if (forcefault && (newslot || !hat_probe(kas.a_hat, vaddr))) {

		caddr_t pgaddr = (caddr_t)((uintptr_t)vaddr &
		    (uintptr_t)PAGEMASK);

		(void) segmap_fault(kas.a_hat, seg, pgaddr,
		    (vaddr + len - pgaddr + PAGESIZE - 1) & (uintptr_t)PAGEMASK,
		    F_INVAL, rw);
	}

	return (baseaddr);
}

int
segmap_release(struct seg *seg, caddr_t addr, uint_t flags)
{
	struct smap	*smp;
	int 		error;
	int		bflags = 0;
	struct vnode	*vp;
	u_offset_t	offset;
	kmutex_t	*smtx;
	int		is_kpm = 0;
	page_t		*pp;

	if (segmap_kpm && IS_KPM_ADDR(addr)) {

		if (((uintptr_t)addr & MAXBOFFSET) != 0) {
			panic("segmap_release: addr %p not "
			    "MAXBSIZE aligned", (void *)addr);
			/*NOTREACHED*/
		}

		if ((smp = get_smap_kpm(addr, &pp)) == NULL) {
			panic("segmap_release: smap not found "
			    "for addr %p", (void *)addr);
			/*NOTREACHED*/
		}

		TRACE_3(TR_FAC_VM, TR_SEGMAP_RELMAP,
		    "segmap_relmap:seg %p addr %p smp %p",
		    seg, addr, smp);

		smtx = SMAPMTX(smp);

		/*
		 * For compatibility reasons segmap_pagecreate_kpm sets this
		 * flag to allow a following segmap_pagecreate to return
		 * this as "newpage" flag. When segmap_pagecreate is not
		 * called at all we clear it now.
		 */
		smp->sm_flags &= ~SM_KPM_NEWPAGE;
		is_kpm = 1;
		if (smp->sm_flags & SM_WRITE_DATA) {
			hat_setrefmod(pp);
		} else if (smp->sm_flags & SM_READ_DATA) {
			hat_setref(pp);
		}
	} else {
		if (addr < seg->s_base || addr >= seg->s_base + seg->s_size ||
		    ((uintptr_t)addr & MAXBOFFSET) != 0) {
			panic("segmap_release: bad addr %p", (void *)addr);
			/*NOTREACHED*/
		}
		smp = GET_SMAP(seg, addr);

		TRACE_3(TR_FAC_VM, TR_SEGMAP_RELMAP,
		    "segmap_relmap:seg %p addr %p smp %p",
		    seg, addr, smp);

		smtx = SMAPMTX(smp);
		mutex_enter(smtx);
		smp->sm_flags |= SM_NOTKPM_RELEASED;
	}

	ASSERT(smp->sm_refcnt > 0);

	/*
	 * Need to call VOP_PUTPAGE() if any flags (except SM_DONTNEED)
	 * are set.
	 */
	if ((flags & ~SM_DONTNEED) != 0) {
		if (flags & SM_WRITE)
			segmapcnt.smp_rel_write.value.ul++;
		if (flags & SM_ASYNC) {
			bflags |= B_ASYNC;
			segmapcnt.smp_rel_async.value.ul++;
		}
		if (flags & SM_INVAL) {
			bflags |= B_INVAL;
			segmapcnt.smp_rel_abort.value.ul++;
		}
		if (flags & SM_DESTROY) {
			bflags |= (B_INVAL|B_TRUNC);
			segmapcnt.smp_rel_abort.value.ul++;
		}
		if (smp->sm_refcnt == 1) {
			/*
			 * We only bother doing the FREE and DONTNEED flags
			 * if no one else is still referencing this mapping.
			 */
			if (flags & SM_FREE) {
				bflags |= B_FREE;
				segmapcnt.smp_rel_free.value.ul++;
			}
			if (flags & SM_DONTNEED) {
				bflags |= B_DONTNEED;
				segmapcnt.smp_rel_dontneed.value.ul++;
			}
		}
	} else {
		smd_cpu[CPU->cpu_seqid].scpu.scpu_release++;
	}

	vp = smp->sm_vp;
	offset = smp->sm_off;

	if (--smp->sm_refcnt == 0) {

		smp->sm_flags &= ~(SM_WRITE_DATA | SM_READ_DATA);

		if (flags & (SM_INVAL|SM_DESTROY)) {
			segmap_hashout(smp);	/* remove map info */
			if (is_kpm) {
				hat_kpm_mapout(pp, GET_KPME(smp), addr);
				if (smp->sm_flags & SM_NOTKPM_RELEASED) {
					smp->sm_flags &= ~SM_NOTKPM_RELEASED;
					hat_unload(kas.a_hat, segkmap->s_base +
					    ((smp - smd_smap) * MAXBSIZE),
					    MAXBSIZE, HAT_UNLOAD);
				}

			} else {
				if (segmap_kpm)
					segkpm_mapout_validkpme(GET_KPME(smp));

				smp->sm_flags &= ~SM_NOTKPM_RELEASED;
				hat_unload(kas.a_hat, addr, MAXBSIZE,
				    HAT_UNLOAD);
			}
		}
		segmap_smapadd(smp);	/* add to free list */
	}

	mutex_exit(smtx);

	if (is_kpm)
		page_unlock(pp);
	/*
	 * Now invoke VOP_PUTPAGE() if any flags (except SM_DONTNEED)
	 * are set.
	 */
	if ((flags & ~SM_DONTNEED) != 0) {
		error = VOP_PUTPAGE(vp, offset, MAXBSIZE,
		    bflags, CRED(), NULL);
	} else {
		error = 0;
	}

	return (error);
}

/*
 * Dump the pages belonging to this segmap segment.
 */
static void
segmap_dump(struct seg *seg)
{
	struct segmap_data *smd;
	struct smap *smp, *smp_end;
	page_t *pp;
	pfn_t pfn;
	u_offset_t off;
	caddr_t addr;

	smd = (struct segmap_data *)seg->s_data;
	addr = seg->s_base;
	for (smp = smd->smd_sm, smp_end = smp + smd->smd_npages;
	    smp < smp_end; smp++) {

		if (smp->sm_refcnt) {
			for (off = 0; off < MAXBSIZE; off += PAGESIZE) {
				int we_own_it = 0;

				/*
				 * If pp == NULL, the page either does
				 * not exist or is exclusively locked.
				 * So determine if it exists before
				 * searching for it.
				 */
				if ((pp = page_lookup_nowait(smp->sm_vp,
				    smp->sm_off + off, SE_SHARED)))
					we_own_it = 1;
				else
					pp = page_exists(smp->sm_vp,
					    smp->sm_off + off);

				if (pp) {
					pfn = page_pptonum(pp);
					dump_addpage(seg->s_as,
					    addr + off, pfn);
					if (we_own_it)
						page_unlock(pp);
				}
				dump_timeleft = dump_timeout;
			}
		}
		addr += MAXBSIZE;
	}
}

/*ARGSUSED*/
static int
segmap_pagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

static int
segmap_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	struct segmap_data *smd = (struct segmap_data *)seg->s_data;

	memidp->val[0] = (uintptr_t)smd->smd_sm->sm_vp;
	memidp->val[1] = smd->smd_sm->sm_off + (uintptr_t)(addr - seg->s_base);
	return (0);
}

/*ARGSUSED*/
static lgrp_mem_policy_info_t *
segmap_getpolicy(struct seg *seg, caddr_t addr)
{
	return (NULL);
}

/*ARGSUSED*/
static int
segmap_capable(struct seg *seg, segcapability_t capability)
{
	return (0);
}


#ifdef	SEGKPM_SUPPORT

/*
 * segkpm support routines
 */

static caddr_t
segmap_pagecreate_kpm(struct seg *seg, vnode_t *vp, u_offset_t off,
	struct smap *smp, enum seg_rw rw)
{
	caddr_t	base;
	page_t	*pp;
	int	newpage = 0;
	struct kpme	*kpme;

	ASSERT(smp->sm_refcnt > 0);

	if ((pp = page_lookup(vp, off, SE_SHARED)) == NULL) {
		kmutex_t *smtx;

		base = segkpm_create_va(off);

		if ((pp = page_create_va(vp, off, PAGESIZE, PG_WAIT,
		    seg, base)) == NULL) {
			panic("segmap_pagecreate_kpm: "
			    "page_create failed");
			/*NOTREACHED*/
		}

		newpage = 1;
		page_io_unlock(pp);
		ASSERT((u_offset_t)(off - smp->sm_off) <= INT_MAX);

		/*
		 * Mark this here until the following segmap_pagecreate
		 * or segmap_release.
		 */
		smtx = SMAPMTX(smp);
		mutex_enter(smtx);
		smp->sm_flags |= SM_KPM_NEWPAGE;
		mutex_exit(smtx);
	}

	kpme = GET_KPME(smp);
	if (!newpage && kpme->kpe_page == pp)
		base = hat_kpm_page2va(pp, 0);
	else
		base = hat_kpm_mapin(pp, kpme);

	/*
	 * FS code may decide not to call segmap_pagecreate and we
	 * don't invoke segmap_fault via TLB miss, so we have to set
	 * ref and mod bits in advance.
	 */
	if (rw == S_WRITE) {
		hat_setrefmod(pp);
	} else {
		ASSERT(rw == S_READ);
		hat_setref(pp);
	}

	smd_cpu[CPU->cpu_seqid].scpu.scpu_pagecreate++;

	return (base);
}

/*
 * Find the smap structure corresponding to the
 * KPM addr and return it locked.
 */
struct smap *
get_smap_kpm(caddr_t addr, page_t **ppp)
{
	struct smap	*smp;
	struct vnode	*vp;
	u_offset_t	offset;
	caddr_t		baseaddr = (caddr_t)((uintptr_t)addr & MAXBMASK);
	int		hashid;
	kmutex_t	*hashmtx;
	page_t		*pp;
	union segmap_cpu *scpu;

	pp = hat_kpm_vaddr2page(baseaddr);

	ASSERT(pp && !PP_ISFREE(pp));
	ASSERT(PAGE_LOCKED(pp));
	ASSERT(((uintptr_t)pp->p_offset & MAXBOFFSET) == 0);

	vp = pp->p_vnode;
	offset = pp->p_offset;
	ASSERT(vp != NULL);

	/*
	 * Assume the last smap used on this cpu is the one needed.
	 */
	scpu = smd_cpu+CPU->cpu_seqid;
	smp = scpu->scpu.scpu_last_smap;
	mutex_enter(&smp->sm_mtx);
	if (smp->sm_vp == vp && smp->sm_off == offset) {
		ASSERT(smp->sm_refcnt > 0);
	} else {
		/*
		 * Assumption wrong, find the smap on the hash chain.
		 */
		mutex_exit(&smp->sm_mtx);
		SMAP_HASHFUNC(vp, offset, hashid); /* macro assigns hashid */
		hashmtx = SHASHMTX(hashid);

		mutex_enter(hashmtx);
		smp = smd_hash[hashid].sh_hash_list;
		for (; smp != NULL; smp = smp->sm_hash) {
			if (smp->sm_vp == vp && smp->sm_off == offset)
				break;
		}
		mutex_exit(hashmtx);
		if (smp) {
			mutex_enter(&smp->sm_mtx);
			ASSERT(smp->sm_vp == vp && smp->sm_off == offset);
		}
	}

	if (ppp)
		*ppp = smp ? pp : NULL;

	return (smp);
}

#else	/* SEGKPM_SUPPORT */

/* segkpm stubs */

/*ARGSUSED*/
static caddr_t
segmap_pagecreate_kpm(struct seg *seg, vnode_t *vp, u_offset_t off,
	struct smap *smp, enum seg_rw rw)
{
	return (NULL);
}

/*ARGSUSED*/
struct smap *
get_smap_kpm(caddr_t addr, page_t **ppp)
{
	return (NULL);
}

#endif	/* SEGKPM_SUPPORT */
