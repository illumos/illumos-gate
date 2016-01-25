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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/param.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/as.h>
#include <vm/anon.h>
#include <vm/page.h>
#include <sys/buf.h>
#include <sys/swap.h>
#include <sys/atomic.h>
#include <vm/seg_spt.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/shm.h>
#include <sys/shm_impl.h>
#include <sys/lgrp.h>
#include <sys/vmsystm.h>
#include <sys/policy.h>
#include <sys/project.h>
#include <sys/tnf_probe.h>
#include <sys/zone.h>

#define	SEGSPTADDR	(caddr_t)0x0

/*
 * # pages used for spt
 */
size_t	spt_used;

/*
 * segspt_minfree is the memory left for system after ISM
 * locked its pages; it is set up to 5% of availrmem in
 * sptcreate when ISM is created.  ISM should not use more
 * than ~90% of availrmem; if it does, then the performance
 * of the system may decrease. Machines with large memories may
 * be able to use up more memory for ISM so we set the default
 * segspt_minfree to 5% (which gives ISM max 95% of availrmem.
 * If somebody wants even more memory for ISM (risking hanging
 * the system) they can patch the segspt_minfree to smaller number.
 */
pgcnt_t segspt_minfree = 0;

static int segspt_create(struct seg *seg, caddr_t argsp);
static int segspt_unmap(struct seg *seg, caddr_t raddr, size_t ssize);
static void segspt_free(struct seg *seg);
static void segspt_free_pages(struct seg *seg, caddr_t addr, size_t len);
static lgrp_mem_policy_info_t *segspt_getpolicy(struct seg *seg, caddr_t addr);

static void
segspt_badop()
{
	panic("segspt_badop called");
	/*NOTREACHED*/
}

#define	SEGSPT_BADOP(t)	(t(*)())segspt_badop

struct seg_ops segspt_ops = {
	SEGSPT_BADOP(int),		/* dup */
	segspt_unmap,
	segspt_free,
	SEGSPT_BADOP(int),		/* fault */
	SEGSPT_BADOP(faultcode_t),	/* faulta */
	SEGSPT_BADOP(int),		/* setprot */
	SEGSPT_BADOP(int),		/* checkprot */
	SEGSPT_BADOP(int),		/* kluster */
	SEGSPT_BADOP(size_t),		/* swapout */
	SEGSPT_BADOP(int),		/* sync */
	SEGSPT_BADOP(size_t),		/* incore */
	SEGSPT_BADOP(int),		/* lockop */
	SEGSPT_BADOP(int),		/* getprot */
	SEGSPT_BADOP(u_offset_t), 	/* getoffset */
	SEGSPT_BADOP(int),		/* gettype */
	SEGSPT_BADOP(int),		/* getvp */
	SEGSPT_BADOP(int),		/* advise */
	SEGSPT_BADOP(void),		/* dump */
	SEGSPT_BADOP(int),		/* pagelock */
	SEGSPT_BADOP(int),		/* setpgsz */
	SEGSPT_BADOP(int),		/* getmemid */
	segspt_getpolicy,		/* getpolicy */
	SEGSPT_BADOP(int),		/* capable */
	seg_inherit_notsup		/* inherit */
};

static int segspt_shmdup(struct seg *seg, struct seg *newseg);
static int segspt_shmunmap(struct seg *seg, caddr_t raddr, size_t ssize);
static void segspt_shmfree(struct seg *seg);
static faultcode_t segspt_shmfault(struct hat *hat, struct seg *seg,
		caddr_t addr, size_t len, enum fault_type type, enum seg_rw rw);
static faultcode_t segspt_shmfaulta(struct seg *seg, caddr_t addr);
static int segspt_shmsetprot(register struct seg *seg, register caddr_t addr,
			register size_t len, register uint_t prot);
static int segspt_shmcheckprot(struct seg *seg, caddr_t addr, size_t size,
			uint_t prot);
static int	segspt_shmkluster(struct seg *seg, caddr_t addr, ssize_t delta);
static size_t	segspt_shmswapout(struct seg *seg);
static size_t segspt_shmincore(struct seg *seg, caddr_t addr, size_t len,
			register char *vec);
static int segspt_shmsync(struct seg *seg, register caddr_t addr, size_t len,
			int attr, uint_t flags);
static int segspt_shmlockop(struct seg *seg, caddr_t addr, size_t len,
			int attr, int op, ulong_t *lockmap, size_t pos);
static int segspt_shmgetprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t *protv);
static u_offset_t segspt_shmgetoffset(struct seg *seg, caddr_t addr);
static int segspt_shmgettype(struct seg *seg, caddr_t addr);
static int segspt_shmgetvp(struct seg *seg, caddr_t addr, struct vnode **vpp);
static int segspt_shmadvise(struct seg *seg, caddr_t addr, size_t len,
			uint_t behav);
static void segspt_shmdump(struct seg *seg);
static int segspt_shmpagelock(struct seg *, caddr_t, size_t,
			struct page ***, enum lock_type, enum seg_rw);
static int segspt_shmsetpgsz(struct seg *, caddr_t, size_t, uint_t);
static int segspt_shmgetmemid(struct seg *, caddr_t, memid_t *);
static lgrp_mem_policy_info_t *segspt_shmgetpolicy(struct seg *, caddr_t);
static int segspt_shmcapable(struct seg *, segcapability_t);

struct seg_ops segspt_shmops = {
	segspt_shmdup,
	segspt_shmunmap,
	segspt_shmfree,
	segspt_shmfault,
	segspt_shmfaulta,
	segspt_shmsetprot,
	segspt_shmcheckprot,
	segspt_shmkluster,
	segspt_shmswapout,
	segspt_shmsync,
	segspt_shmincore,
	segspt_shmlockop,
	segspt_shmgetprot,
	segspt_shmgetoffset,
	segspt_shmgettype,
	segspt_shmgetvp,
	segspt_shmadvise,	/* advise */
	segspt_shmdump,
	segspt_shmpagelock,
	segspt_shmsetpgsz,
	segspt_shmgetmemid,
	segspt_shmgetpolicy,
	segspt_shmcapable,
	seg_inherit_notsup
};

static void segspt_purge(struct seg *seg);
static int segspt_reclaim(void *, caddr_t, size_t, struct page **,
		enum seg_rw, int);
static int spt_anon_getpages(struct seg *seg, caddr_t addr, size_t len,
		page_t **ppa);



/*ARGSUSED*/
int
sptcreate(size_t size, struct seg **sptseg, struct anon_map *amp,
	uint_t prot, uint_t flags, uint_t share_szc)
{
	int 	err;
	struct  as	*newas;
	struct	segspt_crargs sptcargs;

#ifdef DEBUG
	TNF_PROBE_1(sptcreate, "spt", /* CSTYLED */,
			tnf_ulong, size, size );
#endif
	if (segspt_minfree == 0)	/* leave min 5% of availrmem for */
		segspt_minfree = availrmem/20;	/* for the system */

	if (!hat_supported(HAT_SHARED_PT, (void *)0))
		return (EINVAL);

	/*
	 * get a new as for this shared memory segment
	 */
	newas = as_alloc();
	newas->a_proc = NULL;
	sptcargs.amp = amp;
	sptcargs.prot = prot;
	sptcargs.flags = flags;
	sptcargs.szc = share_szc;
	/*
	 * create a shared page table (spt) segment
	 */

	if (err = as_map(newas, SEGSPTADDR, size, segspt_create, &sptcargs)) {
		as_free(newas);
		return (err);
	}
	*sptseg = sptcargs.seg_spt;
	return (0);
}

void
sptdestroy(struct as *as, struct anon_map *amp)
{

#ifdef DEBUG
	TNF_PROBE_0(sptdestroy, "spt", /* CSTYLED */);
#endif
	(void) as_unmap(as, SEGSPTADDR, amp->size);
	as_free(as);
}

/*
 * called from seg_free().
 * free (i.e., unlock, unmap, return to free list)
 *  all the pages in the given seg.
 */
void
segspt_free(struct seg	*seg)
{
	struct spt_data *sptd = (struct spt_data *)seg->s_data;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	if (sptd != NULL) {
		if (sptd->spt_realsize)
			segspt_free_pages(seg, seg->s_base, sptd->spt_realsize);

	if (sptd->spt_ppa_lckcnt)
		kmem_free(sptd->spt_ppa_lckcnt,
		    sizeof (*sptd->spt_ppa_lckcnt)
		    * btopr(sptd->spt_amp->size));
		kmem_free(sptd->spt_vp, sizeof (*sptd->spt_vp));
		cv_destroy(&sptd->spt_cv);
		mutex_destroy(&sptd->spt_lock);
		kmem_free(sptd, sizeof (*sptd));
	}
}

/*ARGSUSED*/
static int
segspt_shmsync(struct seg *seg, caddr_t addr, size_t len, int attr,
	uint_t flags)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (0);
}

/*ARGSUSED*/
static size_t
segspt_shmincore(struct seg *seg, caddr_t addr, size_t len, char *vec)
{
	caddr_t	eo_seg;
	pgcnt_t	npages;
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct seg	*sptseg;
	struct spt_data *sptd;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));
#ifdef lint
	seg = seg;
#endif
	sptseg = shmd->shm_sptseg;
	sptd = sptseg->s_data;

	if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
		eo_seg = addr + len;
		while (addr < eo_seg) {
			/* page exists, and it's locked. */
			*vec++ = SEG_PAGE_INCORE | SEG_PAGE_LOCKED |
			    SEG_PAGE_ANON;
			addr += PAGESIZE;
		}
		return (len);
	} else {
		struct  anon_map *amp = shmd->shm_amp;
		struct  anon	*ap;
		page_t		*pp;
		pgcnt_t 	anon_index;
		struct vnode 	*vp;
		u_offset_t 	off;
		ulong_t		i;
		int		ret;
		anon_sync_obj_t	cookie;

		addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
		anon_index = seg_page(seg, addr);
		npages = btopr(len);
		if (anon_index + npages > btopr(shmd->shm_amp->size)) {
			return (EINVAL);
		}
		ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
		for (i = 0; i < npages; i++, anon_index++) {
			ret = 0;
			anon_array_enter(amp, anon_index, &cookie);
			ap = anon_get_ptr(amp->ahp, anon_index);
			if (ap != NULL) {
				swap_xlate(ap, &vp, &off);
				anon_array_exit(&cookie);
				pp = page_lookup_nowait(vp, off, SE_SHARED);
				if (pp != NULL) {
					ret |= SEG_PAGE_INCORE | SEG_PAGE_ANON;
					page_unlock(pp);
				}
			} else {
				anon_array_exit(&cookie);
			}
			if (shmd->shm_vpage[anon_index] & DISM_PG_LOCKED) {
				ret |= SEG_PAGE_LOCKED;
			}
			*vec++ = (char)ret;
		}
		ANON_LOCK_EXIT(&amp->a_rwlock);
		return (len);
	}
}

static int
segspt_unmap(struct seg *seg, caddr_t raddr, size_t ssize)
{
	size_t share_size;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	/*
	 * seg.s_size may have been rounded up to the largest page size
	 * in shmat().
	 * XXX This should be cleanedup. sptdestroy should take a length
	 * argument which should be the same as sptcreate. Then
	 * this rounding would not be needed (or is done in shm.c)
	 * Only the check for full segment will be needed.
	 *
	 * XXX -- shouldn't raddr == 0 always? These tests don't seem
	 * to be useful at all.
	 */
	share_size = page_get_pagesize(seg->s_szc);
	ssize = P2ROUNDUP(ssize, share_size);

	if (raddr == seg->s_base && ssize == seg->s_size) {
		seg_free(seg);
		return (0);
	} else
		return (EINVAL);
}

int
segspt_create(struct seg *seg, caddr_t argsp)
{
	int		err;
	caddr_t		addr = seg->s_base;
	struct spt_data *sptd;
	struct 	segspt_crargs *sptcargs = (struct segspt_crargs *)argsp;
	struct anon_map *amp = sptcargs->amp;
	struct kshmid	*sp = amp->a_sp;
	struct	cred	*cred = CRED();
	ulong_t		i, j, anon_index = 0;
	pgcnt_t		npages = btopr(amp->size);
	struct vnode	*vp;
	page_t		**ppa;
	uint_t		hat_flags;
	size_t		pgsz;
	pgcnt_t		pgcnt;
	caddr_t		a;
	pgcnt_t		pidx;
	size_t		sz;
	proc_t		*procp = curproc;
	rctl_qty_t	lockedbytes = 0;
	kproject_t	*proj;

	/*
	 * We are holding the a_lock on the underlying dummy as,
	 * so we can make calls to the HAT layer.
	 */
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));
	ASSERT(sp != NULL);

#ifdef DEBUG
	TNF_PROBE_2(segspt_create, "spt", /* CSTYLED */,
	    tnf_opaque, addr, addr, tnf_ulong, len, seg->s_size);
#endif
	if ((sptcargs->flags & SHM_PAGEABLE) == 0) {
		if (err = anon_swap_adjust(npages))
			return (err);
	}
	err = ENOMEM;

	if ((sptd = kmem_zalloc(sizeof (*sptd), KM_NOSLEEP)) == NULL)
		goto out1;

	if ((sptcargs->flags & SHM_PAGEABLE) == 0) {
		if ((ppa = kmem_zalloc(((sizeof (page_t *)) * npages),
		    KM_NOSLEEP)) == NULL)
			goto out2;
	}

	mutex_init(&sptd->spt_lock, NULL, MUTEX_DEFAULT, NULL);

	if ((vp = kmem_zalloc(sizeof (*vp), KM_NOSLEEP)) == NULL)
		goto out3;

	seg->s_ops = &segspt_ops;
	sptd->spt_vp = vp;
	sptd->spt_amp = amp;
	sptd->spt_prot = sptcargs->prot;
	sptd->spt_flags = sptcargs->flags;
	seg->s_data = (caddr_t)sptd;
	sptd->spt_ppa = NULL;
	sptd->spt_ppa_lckcnt = NULL;
	seg->s_szc = sptcargs->szc;
	cv_init(&sptd->spt_cv, NULL, CV_DEFAULT, NULL);
	sptd->spt_gen = 0;

	ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
	if (seg->s_szc > amp->a_szc) {
		amp->a_szc = seg->s_szc;
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);

	/*
	 * Set policy to affect initial allocation of pages in
	 * anon_map_createpages()
	 */
	(void) lgrp_shm_policy_set(LGRP_MEM_POLICY_DEFAULT, amp, anon_index,
	    NULL, 0, ptob(npages));

	if (sptcargs->flags & SHM_PAGEABLE) {
		size_t  share_sz;
		pgcnt_t new_npgs, more_pgs;
		struct anon_hdr *nahp;
		zone_t *zone;

		share_sz = page_get_pagesize(seg->s_szc);
		if (!IS_P2ALIGNED(amp->size, share_sz)) {
			/*
			 * We are rounding up the size of the anon array
			 * on 4 M boundary because we always create 4 M
			 * of page(s) when locking, faulting pages and we
			 * don't have to check for all corner cases e.g.
			 * if there is enough space to allocate 4 M
			 * page.
			 */
			new_npgs = btop(P2ROUNDUP(amp->size, share_sz));
			more_pgs = new_npgs - npages;

			/*
			 * The zone will never be NULL, as a fully created
			 * shm always has an owning zone.
			 */
			zone = sp->shm_perm.ipc_zone_ref.zref_zone;
			ASSERT(zone != NULL);
			if (anon_resv_zone(ptob(more_pgs), zone) == 0) {
				err = ENOMEM;
				goto out4;
			}

			nahp = anon_create(new_npgs, ANON_SLEEP);
			ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
			(void) anon_copy_ptr(amp->ahp, 0, nahp, 0, npages,
			    ANON_SLEEP);
			anon_release(amp->ahp, npages);
			amp->ahp = nahp;
			ASSERT(amp->swresv == ptob(npages));
			amp->swresv = amp->size = ptob(new_npgs);
			ANON_LOCK_EXIT(&amp->a_rwlock);
			npages = new_npgs;
		}

		sptd->spt_ppa_lckcnt = kmem_zalloc(npages *
		    sizeof (*sptd->spt_ppa_lckcnt), KM_SLEEP);
		sptd->spt_pcachecnt = 0;
		sptd->spt_realsize = ptob(npages);
		sptcargs->seg_spt = seg;
		return (0);
	}

	/*
	 * get array of pages for each anon slot in amp
	 */
	if ((err = anon_map_createpages(amp, anon_index, ptob(npages), ppa,
	    seg, addr, S_CREATE, cred)) != 0)
		goto out4;

	mutex_enter(&sp->shm_mlock);

	/* May be partially locked, so, count bytes to charge for locking */
	for (i = 0; i < npages; i++)
		if (ppa[i]->p_lckcnt == 0)
			lockedbytes += PAGESIZE;

	proj = sp->shm_perm.ipc_proj;

	if (lockedbytes > 0) {
		mutex_enter(&procp->p_lock);
		if (rctl_incr_locked_mem(procp, proj, lockedbytes, 0)) {
			mutex_exit(&procp->p_lock);
			mutex_exit(&sp->shm_mlock);
			for (i = 0; i < npages; i++)
				page_unlock(ppa[i]);
			err = ENOMEM;
			goto out4;
		}
		mutex_exit(&procp->p_lock);
	}

	/*
	 * addr is initial address corresponding to the first page on ppa list
	 */
	for (i = 0; i < npages; i++) {
		/* attempt to lock all pages */
		if (page_pp_lock(ppa[i], 0, 1) == 0) {
			/*
			 * if unable to lock any page, unlock all
			 * of them and return error
			 */
			for (j = 0; j < i; j++)
				page_pp_unlock(ppa[j], 0, 1);
			for (i = 0; i < npages; i++)
				page_unlock(ppa[i]);
			rctl_decr_locked_mem(NULL, proj, lockedbytes, 0);
			mutex_exit(&sp->shm_mlock);
			err = ENOMEM;
			goto out4;
		}
	}
	mutex_exit(&sp->shm_mlock);

	/*
	 * Some platforms assume that ISM mappings are HAT_LOAD_LOCK
	 * for the entire life of the segment. For example platforms
	 * that do not support Dynamic Reconfiguration.
	 */
	hat_flags = HAT_LOAD_SHARE;
	if (!hat_supported(HAT_DYNAMIC_ISM_UNMAP, NULL))
		hat_flags |= HAT_LOAD_LOCK;

	/*
	 * Load translations one lare page at a time
	 * to make sure we don't create mappings bigger than
	 * segment's size code in case underlying pages
	 * are shared with segvn's segment that uses bigger
	 * size code than we do.
	 */
	pgsz = page_get_pagesize(seg->s_szc);
	pgcnt = page_get_pagecnt(seg->s_szc);
	for (a = addr, pidx = 0; pidx < npages; a += pgsz, pidx += pgcnt) {
		sz = MIN(pgsz, ptob(npages - pidx));
		hat_memload_array(seg->s_as->a_hat, a, sz,
		    &ppa[pidx], sptd->spt_prot, hat_flags);
	}

	/*
	 * On platforms that do not support HAT_DYNAMIC_ISM_UNMAP,
	 * we will leave the pages locked SE_SHARED for the life
	 * of the ISM segment. This will prevent any calls to
	 * hat_pageunload() on this ISM segment for those platforms.
	 */
	if (!(hat_flags & HAT_LOAD_LOCK)) {
		/*
		 * On platforms that support HAT_DYNAMIC_ISM_UNMAP,
		 * we no longer need to hold the SE_SHARED lock on the pages,
		 * since L_PAGELOCK and F_SOFTLOCK calls will grab the
		 * SE_SHARED lock on the pages as necessary.
		 */
		for (i = 0; i < npages; i++)
			page_unlock(ppa[i]);
	}
	sptd->spt_pcachecnt = 0;
	kmem_free(ppa, ((sizeof (page_t *)) * npages));
	sptd->spt_realsize = ptob(npages);
	atomic_add_long(&spt_used, npages);
	sptcargs->seg_spt = seg;
	return (0);

out4:
	seg->s_data = NULL;
	kmem_free(vp, sizeof (*vp));
	cv_destroy(&sptd->spt_cv);
out3:
	mutex_destroy(&sptd->spt_lock);
	if ((sptcargs->flags & SHM_PAGEABLE) == 0)
		kmem_free(ppa, (sizeof (*ppa) * npages));
out2:
	kmem_free(sptd, sizeof (*sptd));
out1:
	if ((sptcargs->flags & SHM_PAGEABLE) == 0)
		anon_swap_restore(npages);
	return (err);
}

/*ARGSUSED*/
void
segspt_free_pages(struct seg *seg, caddr_t addr, size_t len)
{
	struct page 	*pp;
	struct spt_data *sptd = (struct spt_data *)seg->s_data;
	pgcnt_t		npages;
	ulong_t		anon_idx;
	struct anon_map *amp;
	struct anon 	*ap;
	struct vnode 	*vp;
	u_offset_t 	off;
	uint_t		hat_flags;
	int		root = 0;
	pgcnt_t		pgs, curnpgs = 0;
	page_t		*rootpp;
	rctl_qty_t	unlocked_bytes = 0;
	kproject_t	*proj;
	kshmid_t	*sp;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	len = P2ROUNDUP(len, PAGESIZE);

	npages = btop(len);

	hat_flags = HAT_UNLOAD_UNLOCK | HAT_UNLOAD_UNMAP;
	if ((hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0)) ||
	    (sptd->spt_flags & SHM_PAGEABLE)) {
		hat_flags = HAT_UNLOAD_UNMAP;
	}

	hat_unload(seg->s_as->a_hat, addr, len, hat_flags);

	amp = sptd->spt_amp;
	if (sptd->spt_flags & SHM_PAGEABLE)
		npages = btop(amp->size);

	ASSERT(amp != NULL);

	if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
		sp = amp->a_sp;
		proj = sp->shm_perm.ipc_proj;
		mutex_enter(&sp->shm_mlock);
	}
	for (anon_idx = 0; anon_idx < npages; anon_idx++) {
		if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
			if ((ap = anon_get_ptr(amp->ahp, anon_idx)) == NULL) {
				panic("segspt_free_pages: null app");
				/*NOTREACHED*/
			}
		} else {
			if ((ap = anon_get_next_ptr(amp->ahp, &anon_idx))
			    == NULL)
				continue;
		}
		ASSERT(ANON_ISBUSY(anon_get_slot(amp->ahp, anon_idx)) == 0);
		swap_xlate(ap, &vp, &off);

		/*
		 * If this platform supports HAT_DYNAMIC_ISM_UNMAP,
		 * the pages won't be having SE_SHARED lock at this
		 * point.
		 *
		 * On platforms that do not support HAT_DYNAMIC_ISM_UNMAP,
		 * the pages are still held SE_SHARED locked from the
		 * original segspt_create()
		 *
		 * Our goal is to get SE_EXCL lock on each page, remove
		 * permanent lock on it and invalidate the page.
		 */
		if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
			if (hat_flags == HAT_UNLOAD_UNMAP)
				pp = page_lookup(vp, off, SE_EXCL);
			else {
				if ((pp = page_find(vp, off)) == NULL) {
					panic("segspt_free_pages: "
					    "page not locked");
					/*NOTREACHED*/
				}
				if (!page_tryupgrade(pp)) {
					page_unlock(pp);
					pp = page_lookup(vp, off, SE_EXCL);
				}
			}
			if (pp == NULL) {
				panic("segspt_free_pages: "
				    "page not in the system");
				/*NOTREACHED*/
			}
			ASSERT(pp->p_lckcnt > 0);
			page_pp_unlock(pp, 0, 1);
			if (pp->p_lckcnt == 0)
				unlocked_bytes += PAGESIZE;
		} else {
			if ((pp = page_lookup(vp, off, SE_EXCL)) == NULL)
				continue;
		}
		/*
		 * It's logical to invalidate the pages here as in most cases
		 * these were created by segspt.
		 */
		if (pp->p_szc != 0) {
			if (root == 0) {
				ASSERT(curnpgs == 0);
				root = 1;
				rootpp = pp;
				pgs = curnpgs = page_get_pagecnt(pp->p_szc);
				ASSERT(pgs > 1);
				ASSERT(IS_P2ALIGNED(pgs, pgs));
				ASSERT(!(page_pptonum(pp) & (pgs - 1)));
				curnpgs--;
			} else if ((page_pptonum(pp) & (pgs - 1)) == pgs - 1) {
				ASSERT(curnpgs == 1);
				ASSERT(page_pptonum(pp) ==
				    page_pptonum(rootpp) + (pgs - 1));
				page_destroy_pages(rootpp);
				root = 0;
				curnpgs = 0;
			} else {
				ASSERT(curnpgs > 1);
				ASSERT(page_pptonum(pp) ==
				    page_pptonum(rootpp) + (pgs - curnpgs));
				curnpgs--;
			}
		} else {
			if (root != 0 || curnpgs != 0) {
				panic("segspt_free_pages: bad large page");
				/*NOTREACHED*/
			}
			/*
			 * Before destroying the pages, we need to take care
			 * of the rctl locked memory accounting. For that
			 * we need to calculte the unlocked_bytes.
			 */
			if (pp->p_lckcnt > 0)
				unlocked_bytes += PAGESIZE;
			/*LINTED: constant in conditional context */
			VN_DISPOSE(pp, B_INVAL, 0, kcred);
		}
	}
	if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
		if (unlocked_bytes > 0)
			rctl_decr_locked_mem(NULL, proj, unlocked_bytes, 0);
		mutex_exit(&sp->shm_mlock);
	}
	if (root != 0 || curnpgs != 0) {
		panic("segspt_free_pages: bad large page");
		/*NOTREACHED*/
	}

	/*
	 * mark that pages have been released
	 */
	sptd->spt_realsize = 0;

	if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
		atomic_add_long(&spt_used, -npages);
		anon_swap_restore(npages);
	}
}

/*
 * Get memory allocation policy info for specified address in given segment
 */
static lgrp_mem_policy_info_t *
segspt_getpolicy(struct seg *seg, caddr_t addr)
{
	struct anon_map		*amp;
	ulong_t			anon_index;
	lgrp_mem_policy_info_t	*policy_info;
	struct spt_data		*spt_data;

	ASSERT(seg != NULL);

	/*
	 * Get anon_map from segspt
	 *
	 * Assume that no lock needs to be held on anon_map, since
	 * it should be protected by its reference count which must be
	 * nonzero for an existing segment
	 * Need to grab readers lock on policy tree though
	 */
	spt_data = (struct spt_data *)seg->s_data;
	if (spt_data == NULL)
		return (NULL);
	amp = spt_data->spt_amp;
	ASSERT(amp->refcnt != 0);

	/*
	 * Get policy info
	 *
	 * Assume starting anon index of 0
	 */
	anon_index = seg_page(seg, addr);
	policy_info = lgrp_shm_policy_get(amp, anon_index, NULL, 0);

	return (policy_info);
}

/*
 * DISM only.
 * Return locked pages over a given range.
 *
 * We will cache all DISM locked pages and save the pplist for the
 * entire segment in the ppa field of the underlying DISM segment structure.
 * Later, during a call to segspt_reclaim() we will use this ppa array
 * to page_unlock() all of the pages and then we will free this ppa list.
 */
/*ARGSUSED*/
static int
segspt_dismpagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	struct  shm_data *shmd = (struct shm_data *)seg->s_data;
	struct  seg	*sptseg = shmd->shm_sptseg;
	struct  spt_data *sptd = sptseg->s_data;
	pgcnt_t pg_idx, npages, tot_npages, npgs;
	struct  page **pplist, **pl, **ppa, *pp;
	struct  anon_map *amp;
	spgcnt_t	an_idx;
	int 	ret = ENOTSUP;
	uint_t	pl_built = 0;
	struct  anon *ap;
	struct  vnode *vp;
	u_offset_t off;
	pgcnt_t claim_availrmem = 0;
	uint_t	szc;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));
	ASSERT(type == L_PAGELOCK || type == L_PAGEUNLOCK);

	/*
	 * We want to lock/unlock the entire ISM segment. Therefore,
	 * we will be using the underlying sptseg and it's base address
	 * and length for the caching arguments.
	 */
	ASSERT(sptseg);
	ASSERT(sptd);

	pg_idx = seg_page(seg, addr);
	npages = btopr(len);

	/*
	 * check if the request is larger than number of pages covered
	 * by amp
	 */
	if (pg_idx + npages > btopr(sptd->spt_amp->size)) {
		*ppp = NULL;
		return (ENOTSUP);
	}

	if (type == L_PAGEUNLOCK) {
		ASSERT(sptd->spt_ppa != NULL);

		seg_pinactive(seg, NULL, seg->s_base, sptd->spt_amp->size,
		    sptd->spt_ppa, S_WRITE, SEGP_FORCE_WIRED, segspt_reclaim);

		/*
		 * If someone is blocked while unmapping, we purge
		 * segment page cache and thus reclaim pplist synchronously
		 * without waiting for seg_pasync_thread. This speeds up
		 * unmapping in cases where munmap(2) is called, while
		 * raw async i/o is still in progress or where a thread
		 * exits on data fault in a multithreaded application.
		 */
		if ((sptd->spt_flags & DISM_PPA_CHANGED) ||
		    (AS_ISUNMAPWAIT(seg->s_as) &&
		    shmd->shm_softlockcnt > 0)) {
			segspt_purge(seg);
		}
		return (0);
	}

	/* The L_PAGELOCK case ... */

	if (sptd->spt_flags & DISM_PPA_CHANGED) {
		segspt_purge(seg);
		/*
		 * for DISM ppa needs to be rebuild since
		 * number of locked pages could be changed
		 */
		*ppp = NULL;
		return (ENOTSUP);
	}

	/*
	 * First try to find pages in segment page cache, without
	 * holding the segment lock.
	 */
	pplist = seg_plookup(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    S_WRITE, SEGP_FORCE_WIRED);
	if (pplist != NULL) {
		ASSERT(sptd->spt_ppa != NULL);
		ASSERT(sptd->spt_ppa == pplist);
		ppa = sptd->spt_ppa;
		for (an_idx = pg_idx; an_idx < pg_idx + npages; ) {
			if (ppa[an_idx] == NULL) {
				seg_pinactive(seg, NULL, seg->s_base,
				    sptd->spt_amp->size, ppa,
				    S_WRITE, SEGP_FORCE_WIRED, segspt_reclaim);
				*ppp = NULL;
				return (ENOTSUP);
			}
			if ((szc = ppa[an_idx]->p_szc) != 0) {
				npgs = page_get_pagecnt(szc);
				an_idx = P2ROUNDUP(an_idx + 1, npgs);
			} else {
				an_idx++;
			}
		}
		/*
		 * Since we cache the entire DISM segment, we want to
		 * set ppp to point to the first slot that corresponds
		 * to the requested addr, i.e. pg_idx.
		 */
		*ppp = &(sptd->spt_ppa[pg_idx]);
		return (0);
	}

	mutex_enter(&sptd->spt_lock);
	/*
	 * try to find pages in segment page cache with mutex
	 */
	pplist = seg_plookup(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    S_WRITE, SEGP_FORCE_WIRED);
	if (pplist != NULL) {
		ASSERT(sptd->spt_ppa != NULL);
		ASSERT(sptd->spt_ppa == pplist);
		ppa = sptd->spt_ppa;
		for (an_idx = pg_idx; an_idx < pg_idx + npages; ) {
			if (ppa[an_idx] == NULL) {
				mutex_exit(&sptd->spt_lock);
				seg_pinactive(seg, NULL, seg->s_base,
				    sptd->spt_amp->size, ppa,
				    S_WRITE, SEGP_FORCE_WIRED, segspt_reclaim);
				*ppp = NULL;
				return (ENOTSUP);
			}
			if ((szc = ppa[an_idx]->p_szc) != 0) {
				npgs = page_get_pagecnt(szc);
				an_idx = P2ROUNDUP(an_idx + 1, npgs);
			} else {
				an_idx++;
			}
		}
		/*
		 * Since we cache the entire DISM segment, we want to
		 * set ppp to point to the first slot that corresponds
		 * to the requested addr, i.e. pg_idx.
		 */
		mutex_exit(&sptd->spt_lock);
		*ppp = &(sptd->spt_ppa[pg_idx]);
		return (0);
	}
	if (seg_pinsert_check(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    SEGP_FORCE_WIRED) == SEGP_FAIL) {
		mutex_exit(&sptd->spt_lock);
		*ppp = NULL;
		return (ENOTSUP);
	}

	/*
	 * No need to worry about protections because DISM pages are always rw.
	 */
	pl = pplist = NULL;
	amp = sptd->spt_amp;

	/*
	 * Do we need to build the ppa array?
	 */
	if (sptd->spt_ppa == NULL) {
		pgcnt_t lpg_cnt = 0;

		pl_built = 1;
		tot_npages = btopr(sptd->spt_amp->size);

		ASSERT(sptd->spt_pcachecnt == 0);
		pplist = kmem_zalloc(sizeof (page_t *) * tot_npages, KM_SLEEP);
		pl = pplist;

		ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
		for (an_idx = 0; an_idx < tot_npages; ) {
			ap = anon_get_ptr(amp->ahp, an_idx);
			/*
			 * Cache only mlocked pages. For large pages
			 * if one (constituent) page is mlocked
			 * all pages for that large page
			 * are cached also. This is for quick
			 * lookups of ppa array;
			 */
			if ((ap != NULL) && (lpg_cnt != 0 ||
			    (sptd->spt_ppa_lckcnt[an_idx] != 0))) {

				swap_xlate(ap, &vp, &off);
				pp = page_lookup(vp, off, SE_SHARED);
				ASSERT(pp != NULL);
				if (lpg_cnt == 0) {
					lpg_cnt++;
					/*
					 * For a small page, we are done --
					 * lpg_count is reset to 0 below.
					 *
					 * For a large page, we are guaranteed
					 * to find the anon structures of all
					 * constituent pages and a non-zero
					 * lpg_cnt ensures that we don't test
					 * for mlock for these. We are done
					 * when lpg_count reaches (npgs + 1).
					 * If we are not the first constituent
					 * page, restart at the first one.
					 */
					npgs = page_get_pagecnt(pp->p_szc);
					if (!IS_P2ALIGNED(an_idx, npgs)) {
						an_idx = P2ALIGN(an_idx, npgs);
						page_unlock(pp);
						continue;
					}
				}
				if (++lpg_cnt > npgs)
					lpg_cnt = 0;

				/*
				 * availrmem is decremented only
				 * for unlocked pages
				 */
				if (sptd->spt_ppa_lckcnt[an_idx] == 0)
					claim_availrmem++;
				pplist[an_idx] = pp;
			}
			an_idx++;
		}
		ANON_LOCK_EXIT(&amp->a_rwlock);

		if (claim_availrmem) {
			mutex_enter(&freemem_lock);
			if (availrmem < tune.t_minarmem + claim_availrmem) {
				mutex_exit(&freemem_lock);
				ret = ENOTSUP;
				claim_availrmem = 0;
				goto insert_fail;
			} else {
				availrmem -= claim_availrmem;
			}
			mutex_exit(&freemem_lock);
		}

		sptd->spt_ppa = pl;
	} else {
		/*
		 * We already have a valid ppa[].
		 */
		pl = sptd->spt_ppa;
	}

	ASSERT(pl != NULL);

	ret = seg_pinsert(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    sptd->spt_amp->size, pl, S_WRITE, SEGP_FORCE_WIRED,
	    segspt_reclaim);
	if (ret == SEGP_FAIL) {
		/*
		 * seg_pinsert failed. We return
		 * ENOTSUP, so that the as_pagelock() code will
		 * then try the slower F_SOFTLOCK path.
		 */
		if (pl_built) {
			/*
			 * No one else has referenced the ppa[].
			 * We created it and we need to destroy it.
			 */
			sptd->spt_ppa = NULL;
		}
		ret = ENOTSUP;
		goto insert_fail;
	}

	/*
	 * In either case, we increment softlockcnt on the 'real' segment.
	 */
	sptd->spt_pcachecnt++;
	atomic_inc_ulong((ulong_t *)(&(shmd->shm_softlockcnt)));

	ppa = sptd->spt_ppa;
	for (an_idx = pg_idx; an_idx < pg_idx + npages; ) {
		if (ppa[an_idx] == NULL) {
			mutex_exit(&sptd->spt_lock);
			seg_pinactive(seg, NULL, seg->s_base,
			    sptd->spt_amp->size,
			    pl, S_WRITE, SEGP_FORCE_WIRED, segspt_reclaim);
			*ppp = NULL;
			return (ENOTSUP);
		}
		if ((szc = ppa[an_idx]->p_szc) != 0) {
			npgs = page_get_pagecnt(szc);
			an_idx = P2ROUNDUP(an_idx + 1, npgs);
		} else {
			an_idx++;
		}
	}
	/*
	 * We can now drop the sptd->spt_lock since the ppa[]
	 * exists and he have incremented pacachecnt.
	 */
	mutex_exit(&sptd->spt_lock);

	/*
	 * Since we cache the entire segment, we want to
	 * set ppp to point to the first slot that corresponds
	 * to the requested addr, i.e. pg_idx.
	 */
	*ppp = &(sptd->spt_ppa[pg_idx]);
	return (0);

insert_fail:
	/*
	 * We will only reach this code if we tried and failed.
	 *
	 * And we can drop the lock on the dummy seg, once we've failed
	 * to set up a new ppa[].
	 */
	mutex_exit(&sptd->spt_lock);

	if (pl_built) {
		if (claim_availrmem) {
			mutex_enter(&freemem_lock);
			availrmem += claim_availrmem;
			mutex_exit(&freemem_lock);
		}

		/*
		 * We created pl and we need to destroy it.
		 */
		pplist = pl;
		for (an_idx = 0; an_idx < tot_npages; an_idx++) {
			if (pplist[an_idx] != NULL)
				page_unlock(pplist[an_idx]);
		}
		kmem_free(pl, sizeof (page_t *) * tot_npages);
	}

	if (shmd->shm_softlockcnt <= 0) {
		if (AS_ISUNMAPWAIT(seg->s_as)) {
			mutex_enter(&seg->s_as->a_contents);
			if (AS_ISUNMAPWAIT(seg->s_as)) {
				AS_CLRUNMAPWAIT(seg->s_as);
				cv_broadcast(&seg->s_as->a_cv);
			}
			mutex_exit(&seg->s_as->a_contents);
		}
	}
	*ppp = NULL;
	return (ret);
}



/*
 * return locked pages over a given range.
 *
 * We will cache the entire ISM segment and save the pplist for the
 * entire segment in the ppa field of the underlying ISM segment structure.
 * Later, during a call to segspt_reclaim() we will use this ppa array
 * to page_unlock() all of the pages and then we will free this ppa list.
 */
/*ARGSUSED*/
static int
segspt_shmpagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct seg	*sptseg = shmd->shm_sptseg;
	struct spt_data *sptd = sptseg->s_data;
	pgcnt_t np, page_index, npages;
	caddr_t a, spt_base;
	struct page **pplist, **pl, *pp;
	struct anon_map *amp;
	ulong_t anon_index;
	int ret = ENOTSUP;
	uint_t	pl_built = 0;
	struct anon *ap;
	struct vnode *vp;
	u_offset_t off;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));
	ASSERT(type == L_PAGELOCK || type == L_PAGEUNLOCK);


	/*
	 * We want to lock/unlock the entire ISM segment. Therefore,
	 * we will be using the underlying sptseg and it's base address
	 * and length for the caching arguments.
	 */
	ASSERT(sptseg);
	ASSERT(sptd);

	if (sptd->spt_flags & SHM_PAGEABLE) {
		return (segspt_dismpagelock(seg, addr, len, ppp, type, rw));
	}

	page_index = seg_page(seg, addr);
	npages = btopr(len);

	/*
	 * check if the request is larger than number of pages covered
	 * by amp
	 */
	if (page_index + npages > btopr(sptd->spt_amp->size)) {
		*ppp = NULL;
		return (ENOTSUP);
	}

	if (type == L_PAGEUNLOCK) {

		ASSERT(sptd->spt_ppa != NULL);

		seg_pinactive(seg, NULL, seg->s_base, sptd->spt_amp->size,
		    sptd->spt_ppa, S_WRITE, SEGP_FORCE_WIRED, segspt_reclaim);

		/*
		 * If someone is blocked while unmapping, we purge
		 * segment page cache and thus reclaim pplist synchronously
		 * without waiting for seg_pasync_thread. This speeds up
		 * unmapping in cases where munmap(2) is called, while
		 * raw async i/o is still in progress or where a thread
		 * exits on data fault in a multithreaded application.
		 */
		if (AS_ISUNMAPWAIT(seg->s_as) && (shmd->shm_softlockcnt > 0)) {
			segspt_purge(seg);
		}
		return (0);
	}

	/* The L_PAGELOCK case... */

	/*
	 * First try to find pages in segment page cache, without
	 * holding the segment lock.
	 */
	pplist = seg_plookup(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    S_WRITE, SEGP_FORCE_WIRED);
	if (pplist != NULL) {
		ASSERT(sptd->spt_ppa == pplist);
		ASSERT(sptd->spt_ppa[page_index]);
		/*
		 * Since we cache the entire ISM segment, we want to
		 * set ppp to point to the first slot that corresponds
		 * to the requested addr, i.e. page_index.
		 */
		*ppp = &(sptd->spt_ppa[page_index]);
		return (0);
	}

	mutex_enter(&sptd->spt_lock);

	/*
	 * try to find pages in segment page cache
	 */
	pplist = seg_plookup(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    S_WRITE, SEGP_FORCE_WIRED);
	if (pplist != NULL) {
		ASSERT(sptd->spt_ppa == pplist);
		/*
		 * Since we cache the entire segment, we want to
		 * set ppp to point to the first slot that corresponds
		 * to the requested addr, i.e. page_index.
		 */
		mutex_exit(&sptd->spt_lock);
		*ppp = &(sptd->spt_ppa[page_index]);
		return (0);
	}

	if (seg_pinsert_check(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    SEGP_FORCE_WIRED) == SEGP_FAIL) {
		mutex_exit(&sptd->spt_lock);
		*ppp = NULL;
		return (ENOTSUP);
	}

	/*
	 * No need to worry about protections because ISM pages
	 * are always rw.
	 */
	pl = pplist = NULL;

	/*
	 * Do we need to build the ppa array?
	 */
	if (sptd->spt_ppa == NULL) {
		ASSERT(sptd->spt_ppa == pplist);

		spt_base = sptseg->s_base;
		pl_built = 1;

		/*
		 * availrmem is decremented once during anon_swap_adjust()
		 * and is incremented during the anon_unresv(), which is
		 * called from shm_rm_amp() when the segment is destroyed.
		 */
		amp = sptd->spt_amp;
		ASSERT(amp != NULL);

		/* pcachecnt is protected by sptd->spt_lock */
		ASSERT(sptd->spt_pcachecnt == 0);
		pplist = kmem_zalloc(sizeof (page_t *)
		    * btopr(sptd->spt_amp->size), KM_SLEEP);
		pl = pplist;

		anon_index = seg_page(sptseg, spt_base);

		ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
		for (a = spt_base; a < (spt_base + sptd->spt_amp->size);
		    a += PAGESIZE, anon_index++, pplist++) {
			ap = anon_get_ptr(amp->ahp, anon_index);
			ASSERT(ap != NULL);
			swap_xlate(ap, &vp, &off);
			pp = page_lookup(vp, off, SE_SHARED);
			ASSERT(pp != NULL);
			*pplist = pp;
		}
		ANON_LOCK_EXIT(&amp->a_rwlock);

		if (a < (spt_base + sptd->spt_amp->size)) {
			ret = ENOTSUP;
			goto insert_fail;
		}
		sptd->spt_ppa = pl;
	} else {
		/*
		 * We already have a valid ppa[].
		 */
		pl = sptd->spt_ppa;
	}

	ASSERT(pl != NULL);

	ret = seg_pinsert(seg, NULL, seg->s_base, sptd->spt_amp->size,
	    sptd->spt_amp->size, pl, S_WRITE, SEGP_FORCE_WIRED,
	    segspt_reclaim);
	if (ret == SEGP_FAIL) {
		/*
		 * seg_pinsert failed. We return
		 * ENOTSUP, so that the as_pagelock() code will
		 * then try the slower F_SOFTLOCK path.
		 */
		if (pl_built) {
			/*
			 * No one else has referenced the ppa[].
			 * We created it and we need to destroy it.
			 */
			sptd->spt_ppa = NULL;
		}
		ret = ENOTSUP;
		goto insert_fail;
	}

	/*
	 * In either case, we increment softlockcnt on the 'real' segment.
	 */
	sptd->spt_pcachecnt++;
	atomic_inc_ulong((ulong_t *)(&(shmd->shm_softlockcnt)));

	/*
	 * We can now drop the sptd->spt_lock since the ppa[]
	 * exists and he have incremented pacachecnt.
	 */
	mutex_exit(&sptd->spt_lock);

	/*
	 * Since we cache the entire segment, we want to
	 * set ppp to point to the first slot that corresponds
	 * to the requested addr, i.e. page_index.
	 */
	*ppp = &(sptd->spt_ppa[page_index]);
	return (0);

insert_fail:
	/*
	 * We will only reach this code if we tried and failed.
	 *
	 * And we can drop the lock on the dummy seg, once we've failed
	 * to set up a new ppa[].
	 */
	mutex_exit(&sptd->spt_lock);

	if (pl_built) {
		/*
		 * We created pl and we need to destroy it.
		 */
		pplist = pl;
		np = (((uintptr_t)(a - spt_base)) >> PAGESHIFT);
		while (np) {
			page_unlock(*pplist);
			np--;
			pplist++;
		}
		kmem_free(pl, sizeof (page_t *) * btopr(sptd->spt_amp->size));
	}
	if (shmd->shm_softlockcnt <= 0) {
		if (AS_ISUNMAPWAIT(seg->s_as)) {
			mutex_enter(&seg->s_as->a_contents);
			if (AS_ISUNMAPWAIT(seg->s_as)) {
				AS_CLRUNMAPWAIT(seg->s_as);
				cv_broadcast(&seg->s_as->a_cv);
			}
			mutex_exit(&seg->s_as->a_contents);
		}
	}
	*ppp = NULL;
	return (ret);
}

/*
 * purge any cached pages in the I/O page cache
 */
static void
segspt_purge(struct seg *seg)
{
	seg_ppurge(seg, NULL, SEGP_FORCE_WIRED);
}

static int
segspt_reclaim(void *ptag, caddr_t addr, size_t len, struct page **pplist,
	enum seg_rw rw, int async)
{
	struct seg *seg = (struct seg *)ptag;
	struct	shm_data *shmd = (struct shm_data *)seg->s_data;
	struct	seg	*sptseg;
	struct	spt_data *sptd;
	pgcnt_t npages, i, free_availrmem = 0;
	int	done = 0;

#ifdef lint
	addr = addr;
#endif
	sptseg = shmd->shm_sptseg;
	sptd = sptseg->s_data;
	npages = (len >> PAGESHIFT);
	ASSERT(npages);
	ASSERT(sptd->spt_pcachecnt != 0);
	ASSERT(sptd->spt_ppa == pplist);
	ASSERT(npages == btopr(sptd->spt_amp->size));
	ASSERT(async || AS_LOCK_HELD(seg->s_as));

	/*
	 * Acquire the lock on the dummy seg and destroy the
	 * ppa array IF this is the last pcachecnt.
	 */
	mutex_enter(&sptd->spt_lock);
	if (--sptd->spt_pcachecnt == 0) {
		for (i = 0; i < npages; i++) {
			if (pplist[i] == NULL) {
				continue;
			}
			if (rw == S_WRITE) {
				hat_setrefmod(pplist[i]);
			} else {
				hat_setref(pplist[i]);
			}
			if ((sptd->spt_flags & SHM_PAGEABLE) &&
			    (sptd->spt_ppa_lckcnt[i] == 0))
				free_availrmem++;
			page_unlock(pplist[i]);
		}
		if ((sptd->spt_flags & SHM_PAGEABLE) && free_availrmem) {
			mutex_enter(&freemem_lock);
			availrmem += free_availrmem;
			mutex_exit(&freemem_lock);
		}
		/*
		 * Since we want to cach/uncache the entire ISM segment,
		 * we will track the pplist in a segspt specific field
		 * ppa, that is initialized at the time we add an entry to
		 * the cache.
		 */
		ASSERT(sptd->spt_pcachecnt == 0);
		kmem_free(pplist, sizeof (page_t *) * npages);
		sptd->spt_ppa = NULL;
		sptd->spt_flags &= ~DISM_PPA_CHANGED;
		sptd->spt_gen++;
		cv_broadcast(&sptd->spt_cv);
		done = 1;
	}
	mutex_exit(&sptd->spt_lock);

	/*
	 * If we are pcache async thread or called via seg_ppurge_wiredpp() we
	 * may not hold AS lock (in this case async argument is not 0). This
	 * means if softlockcnt drops to 0 after the decrement below address
	 * space may get freed. We can't allow it since after softlock
	 * derement to 0 we still need to access as structure for possible
	 * wakeup of unmap waiters. To prevent the disappearance of as we take
	 * this segment's shm_segfree_syncmtx. segspt_shmfree() also takes
	 * this mutex as a barrier to make sure this routine completes before
	 * segment is freed.
	 *
	 * The second complication we have to deal with in async case is a
	 * possibility of missed wake up of unmap wait thread. When we don't
	 * hold as lock here we may take a_contents lock before unmap wait
	 * thread that was first to see softlockcnt was still not 0. As a
	 * result we'll fail to wake up an unmap wait thread. To avoid this
	 * race we set nounmapwait flag in as structure if we drop softlockcnt
	 * to 0 if async is not 0.  unmapwait thread
	 * will not block if this flag is set.
	 */
	if (async)
		mutex_enter(&shmd->shm_segfree_syncmtx);

	/*
	 * Now decrement softlockcnt.
	 */
	ASSERT(shmd->shm_softlockcnt > 0);
	atomic_dec_ulong((ulong_t *)(&(shmd->shm_softlockcnt)));

	if (shmd->shm_softlockcnt <= 0) {
		if (async || AS_ISUNMAPWAIT(seg->s_as)) {
			mutex_enter(&seg->s_as->a_contents);
			if (async)
				AS_SETNOUNMAPWAIT(seg->s_as);
			if (AS_ISUNMAPWAIT(seg->s_as)) {
				AS_CLRUNMAPWAIT(seg->s_as);
				cv_broadcast(&seg->s_as->a_cv);
			}
			mutex_exit(&seg->s_as->a_contents);
		}
	}

	if (async)
		mutex_exit(&shmd->shm_segfree_syncmtx);

	return (done);
}

/*
 * Do a F_SOFTUNLOCK call over the range requested.
 * The range must have already been F_SOFTLOCK'ed.
 *
 * The calls to acquire and release the anon map lock mutex were
 * removed in order to avoid a deadly embrace during a DR
 * memory delete operation.  (Eg. DR blocks while waiting for a
 * exclusive lock on a page that is being used for kaio; the
 * thread that will complete the kaio and call segspt_softunlock
 * blocks on the anon map lock; another thread holding the anon
 * map lock blocks on another page lock via the segspt_shmfault
 * -> page_lookup -> page_lookup_create -> page_lock_es code flow.)
 *
 * The appropriateness of the removal is based upon the following:
 * 1. If we are holding a segment's reader lock and the page is held
 * shared, then the corresponding element in anonmap which points to
 * anon struct cannot change and there is no need to acquire the
 * anonymous map lock.
 * 2. Threads in segspt_softunlock have a reader lock on the segment
 * and already have the shared page lock, so we are guaranteed that
 * the anon map slot cannot change and therefore can call anon_get_ptr()
 * without grabbing the anonymous map lock.
 * 3. Threads that softlock a shared page break copy-on-write, even if
 * its a read.  Thus cow faults can be ignored with respect to soft
 * unlocking, since the breaking of cow means that the anon slot(s) will
 * not be shared.
 */
static void
segspt_softunlock(struct seg *seg, caddr_t sptseg_addr,
	size_t len, enum seg_rw rw)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct seg	*sptseg;
	struct spt_data *sptd;
	page_t *pp;
	caddr_t adr;
	struct vnode *vp;
	u_offset_t offset;
	ulong_t anon_index;
	struct anon_map *amp;		/* XXX - for locknest */
	struct anon *ap = NULL;
	pgcnt_t npages;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	sptseg = shmd->shm_sptseg;
	sptd = sptseg->s_data;

	/*
	 * Some platforms assume that ISM mappings are HAT_LOAD_LOCK
	 * and therefore their pages are SE_SHARED locked
	 * for the entire life of the segment.
	 */
	if ((!hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0)) &&
	    ((sptd->spt_flags & SHM_PAGEABLE) == 0)) {
		goto softlock_decrement;
	}

	/*
	 * Any thread is free to do a page_find and
	 * page_unlock() on the pages within this seg.
	 *
	 * We are already holding the as->a_lock on the user's
	 * real segment, but we need to hold the a_lock on the
	 * underlying dummy as. This is mostly to satisfy the
	 * underlying HAT layer.
	 */
	AS_LOCK_ENTER(sptseg->s_as, RW_READER);
	hat_unlock(sptseg->s_as->a_hat, sptseg_addr, len);
	AS_LOCK_EXIT(sptseg->s_as);

	amp = sptd->spt_amp;
	ASSERT(amp != NULL);
	anon_index = seg_page(sptseg, sptseg_addr);

	for (adr = sptseg_addr; adr < sptseg_addr + len; adr += PAGESIZE) {
		ap = anon_get_ptr(amp->ahp, anon_index++);
		ASSERT(ap != NULL);
		swap_xlate(ap, &vp, &offset);

		/*
		 * Use page_find() instead of page_lookup() to
		 * find the page since we know that it has a
		 * "shared" lock.
		 */
		pp = page_find(vp, offset);
		ASSERT(ap == anon_get_ptr(amp->ahp, anon_index - 1));
		if (pp == NULL) {
			panic("segspt_softunlock: "
			    "addr %p, ap %p, vp %p, off %llx",
			    (void *)adr, (void *)ap, (void *)vp, offset);
			/*NOTREACHED*/
		}

		if (rw == S_WRITE) {
			hat_setrefmod(pp);
		} else if (rw != S_OTHER) {
			hat_setref(pp);
		}
		page_unlock(pp);
	}

softlock_decrement:
	npages = btopr(len);
	ASSERT(shmd->shm_softlockcnt >= npages);
	atomic_add_long((ulong_t *)(&(shmd->shm_softlockcnt)), -npages);
	if (shmd->shm_softlockcnt == 0) {
		/*
		 * All SOFTLOCKS are gone. Wakeup any waiting
		 * unmappers so they can try again to unmap.
		 * Check for waiters first without the mutex
		 * held so we don't always grab the mutex on
		 * softunlocks.
		 */
		if (AS_ISUNMAPWAIT(seg->s_as)) {
			mutex_enter(&seg->s_as->a_contents);
			if (AS_ISUNMAPWAIT(seg->s_as)) {
				AS_CLRUNMAPWAIT(seg->s_as);
				cv_broadcast(&seg->s_as->a_cv);
			}
			mutex_exit(&seg->s_as->a_contents);
		}
	}
}

int
segspt_shmattach(struct seg *seg, caddr_t *argsp)
{
	struct shm_data *shmd_arg = (struct shm_data *)argsp;
	struct shm_data *shmd;
	struct anon_map *shm_amp = shmd_arg->shm_amp;
	struct spt_data *sptd;
	int error = 0;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	shmd = kmem_zalloc((sizeof (*shmd)), KM_NOSLEEP);
	if (shmd == NULL)
		return (ENOMEM);

	shmd->shm_sptas = shmd_arg->shm_sptas;
	shmd->shm_amp = shm_amp;
	shmd->shm_sptseg = shmd_arg->shm_sptseg;

	(void) lgrp_shm_policy_set(LGRP_MEM_POLICY_DEFAULT, shm_amp, 0,
	    NULL, 0, seg->s_size);

	mutex_init(&shmd->shm_segfree_syncmtx, NULL, MUTEX_DEFAULT, NULL);

	seg->s_data = (void *)shmd;
	seg->s_ops = &segspt_shmops;
	seg->s_szc = shmd->shm_sptseg->s_szc;
	sptd = shmd->shm_sptseg->s_data;

	if (sptd->spt_flags & SHM_PAGEABLE) {
		if ((shmd->shm_vpage = kmem_zalloc(btopr(shm_amp->size),
		    KM_NOSLEEP)) == NULL) {
			seg->s_data = (void *)NULL;
			kmem_free(shmd, (sizeof (*shmd)));
			return (ENOMEM);
		}
		shmd->shm_lckpgs = 0;
		if (hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0)) {
			if ((error = hat_share(seg->s_as->a_hat, seg->s_base,
			    shmd_arg->shm_sptas->a_hat, SEGSPTADDR,
			    seg->s_size, seg->s_szc)) != 0) {
				kmem_free(shmd->shm_vpage,
				    btopr(shm_amp->size));
			}
		}
	} else {
		error = hat_share(seg->s_as->a_hat, seg->s_base,
		    shmd_arg->shm_sptas->a_hat, SEGSPTADDR,
		    seg->s_size, seg->s_szc);
	}
	if (error) {
		seg->s_szc = 0;
		seg->s_data = (void *)NULL;
		kmem_free(shmd, (sizeof (*shmd)));
	} else {
		ANON_LOCK_ENTER(&shm_amp->a_rwlock, RW_WRITER);
		shm_amp->refcnt++;
		ANON_LOCK_EXIT(&shm_amp->a_rwlock);
	}
	return (error);
}

int
segspt_shmunmap(struct seg *seg, caddr_t raddr, size_t ssize)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	int reclaim = 1;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));
retry:
	if (shmd->shm_softlockcnt > 0) {
		if (reclaim == 1) {
			segspt_purge(seg);
			reclaim = 0;
			goto retry;
		}
		return (EAGAIN);
	}

	if (ssize != seg->s_size) {
#ifdef DEBUG
		cmn_err(CE_WARN, "Incompatible ssize %lx s_size %lx\n",
		    ssize, seg->s_size);
#endif
		return (EINVAL);
	}

	(void) segspt_shmlockop(seg, raddr, shmd->shm_amp->size, 0, MC_UNLOCK,
	    NULL, 0);
	hat_unshare(seg->s_as->a_hat, raddr, ssize, seg->s_szc);

	seg_free(seg);

	return (0);
}

void
segspt_shmfree(struct seg *seg)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct anon_map *shm_amp = shmd->shm_amp;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	(void) segspt_shmlockop(seg, seg->s_base, shm_amp->size, 0,
	    MC_UNLOCK, NULL, 0);

	/*
	 * Need to increment refcnt when attaching
	 * and decrement when detaching because of dup().
	 */
	ANON_LOCK_ENTER(&shm_amp->a_rwlock, RW_WRITER);
	shm_amp->refcnt--;
	ANON_LOCK_EXIT(&shm_amp->a_rwlock);

	if (shmd->shm_vpage) {	/* only for DISM */
		kmem_free(shmd->shm_vpage, btopr(shm_amp->size));
		shmd->shm_vpage = NULL;
	}

	/*
	 * Take shm_segfree_syncmtx lock to let segspt_reclaim() finish if it's
	 * still working with this segment without holding as lock.
	 */
	ASSERT(shmd->shm_softlockcnt == 0);
	mutex_enter(&shmd->shm_segfree_syncmtx);
	mutex_destroy(&shmd->shm_segfree_syncmtx);

	kmem_free(shmd, sizeof (*shmd));
}

/*ARGSUSED*/
int
segspt_shmsetprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * Shared page table is more than shared mapping.
	 *  Individual process sharing page tables can't change prot
	 *  because there is only one set of page tables.
	 *  This will be allowed after private page table is
	 *  supported.
	 */
/* need to return correct status error? */
	return (0);
}


faultcode_t
segspt_dismfault(struct hat *hat, struct seg *seg, caddr_t addr,
    size_t len, enum fault_type type, enum seg_rw rw)
{
	struct  shm_data 	*shmd = (struct shm_data *)seg->s_data;
	struct  seg		*sptseg = shmd->shm_sptseg;
	struct  as		*curspt = shmd->shm_sptas;
	struct  spt_data 	*sptd = sptseg->s_data;
	pgcnt_t npages;
	size_t  size;
	caddr_t segspt_addr, shm_addr;
	page_t  **ppa;
	int	i;
	ulong_t an_idx = 0;
	int	err = 0;
	int	dyn_ism_unmap = hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0);
	size_t	pgsz;
	pgcnt_t	pgcnt;
	caddr_t	a;
	pgcnt_t	pidx;

#ifdef lint
	hat = hat;
#endif
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * Because of the way spt is implemented
	 * the realsize of the segment does not have to be
	 * equal to the segment size itself. The segment size is
	 * often in multiples of a page size larger than PAGESIZE.
	 * The realsize is rounded up to the nearest PAGESIZE
	 * based on what the user requested. This is a bit of
	 * ungliness that is historical but not easily fixed
	 * without re-designing the higher levels of ISM.
	 */
	ASSERT(addr >= seg->s_base);
	if (((addr + len) - seg->s_base) > sptd->spt_realsize)
		return (FC_NOMAP);
	/*
	 * For all of the following cases except F_PROT, we need to
	 * make any necessary adjustments to addr and len
	 * and get all of the necessary page_t's into an array called ppa[].
	 *
	 * The code in shmat() forces base addr and len of ISM segment
	 * to be aligned to largest page size supported. Therefore,
	 * we are able to handle F_SOFTLOCK and F_INVAL calls in "large
	 * pagesize" chunks. We want to make sure that we HAT_LOAD_LOCK
	 * in large pagesize chunks, or else we will screw up the HAT
	 * layer by calling hat_memload_array() with differing page sizes
	 * over a given virtual range.
	 */
	pgsz = page_get_pagesize(sptseg->s_szc);
	pgcnt = page_get_pagecnt(sptseg->s_szc);
	shm_addr = (caddr_t)P2ALIGN((uintptr_t)(addr), pgsz);
	size = P2ROUNDUP((uintptr_t)(((addr + len) - shm_addr)), pgsz);
	npages = btopr(size);

	/*
	 * Now we need to convert from addr in segshm to addr in segspt.
	 */
	an_idx = seg_page(seg, shm_addr);
	segspt_addr = sptseg->s_base + ptob(an_idx);

	ASSERT((segspt_addr + ptob(npages)) <=
	    (sptseg->s_base + sptd->spt_realsize));
	ASSERT(segspt_addr < (sptseg->s_base + sptseg->s_size));

	switch (type) {

	case F_SOFTLOCK:

		atomic_add_long((ulong_t *)(&(shmd->shm_softlockcnt)), npages);
		/*
		 * Fall through to the F_INVAL case to load up the hat layer
		 * entries with the HAT_LOAD_LOCK flag.
		 */
		/* FALLTHRU */
	case F_INVAL:

		if ((rw == S_EXEC) && !(sptd->spt_prot & PROT_EXEC))
			return (FC_NOMAP);

		ppa = kmem_zalloc(npages * sizeof (page_t *), KM_SLEEP);

		err = spt_anon_getpages(sptseg, segspt_addr, size, ppa);
		if (err != 0) {
			if (type == F_SOFTLOCK) {
				atomic_add_long((ulong_t *)(
				    &(shmd->shm_softlockcnt)), -npages);
			}
			goto dism_err;
		}
		AS_LOCK_ENTER(sptseg->s_as, RW_READER);
		a = segspt_addr;
		pidx = 0;
		if (type == F_SOFTLOCK) {

			/*
			 * Load up the translation keeping it
			 * locked and don't unlock the page.
			 */
			for (; pidx < npages; a += pgsz, pidx += pgcnt) {
				hat_memload_array(sptseg->s_as->a_hat,
				    a, pgsz, &ppa[pidx], sptd->spt_prot,
				    HAT_LOAD_LOCK | HAT_LOAD_SHARE);
			}
		} else {
			/*
			 * Migrate pages marked for migration
			 */
			if (lgrp_optimizations())
				page_migrate(seg, shm_addr, ppa, npages);

			for (; pidx < npages; a += pgsz, pidx += pgcnt) {
				hat_memload_array(sptseg->s_as->a_hat,
				    a, pgsz, &ppa[pidx],
				    sptd->spt_prot,
				    HAT_LOAD_SHARE);
			}

			/*
			 * And now drop the SE_SHARED lock(s).
			 */
			if (dyn_ism_unmap) {
				for (i = 0; i < npages; i++) {
					page_unlock(ppa[i]);
				}
			}
		}

		if (!dyn_ism_unmap) {
			if (hat_share(seg->s_as->a_hat, shm_addr,
			    curspt->a_hat, segspt_addr, ptob(npages),
			    seg->s_szc) != 0) {
				panic("hat_share err in DISM fault");
				/* NOTREACHED */
			}
			if (type == F_INVAL) {
				for (i = 0; i < npages; i++) {
					page_unlock(ppa[i]);
				}
			}
		}
		AS_LOCK_EXIT(sptseg->s_as);
dism_err:
		kmem_free(ppa, npages * sizeof (page_t *));
		return (err);

	case F_SOFTUNLOCK:

		/*
		 * This is a bit ugly, we pass in the real seg pointer,
		 * but the segspt_addr is the virtual address within the
		 * dummy seg.
		 */
		segspt_softunlock(seg, segspt_addr, size, rw);
		return (0);

	case F_PROT:

		/*
		 * This takes care of the unusual case where a user
		 * allocates a stack in shared memory and a register
		 * window overflow is written to that stack page before
		 * it is otherwise modified.
		 *
		 * We can get away with this because ISM segments are
		 * always rw. Other than this unusual case, there
		 * should be no instances of protection violations.
		 */
		return (0);

	default:
#ifdef DEBUG
		panic("segspt_dismfault default type?");
#else
		return (FC_NOMAP);
#endif
	}
}


faultcode_t
segspt_shmfault(struct hat *hat, struct seg *seg, caddr_t addr,
    size_t len, enum fault_type type, enum seg_rw rw)
{
	struct shm_data 	*shmd = (struct shm_data *)seg->s_data;
	struct seg		*sptseg = shmd->shm_sptseg;
	struct as		*curspt = shmd->shm_sptas;
	struct spt_data 	*sptd   = sptseg->s_data;
	pgcnt_t npages;
	size_t size;
	caddr_t sptseg_addr, shm_addr;
	page_t *pp, **ppa;
	int	i;
	u_offset_t offset;
	ulong_t anon_index = 0;
	struct vnode *vp;
	struct anon_map *amp;		/* XXX - for locknest */
	struct anon *ap = NULL;
	size_t		pgsz;
	pgcnt_t		pgcnt;
	caddr_t		a;
	pgcnt_t		pidx;
	size_t		sz;

#ifdef lint
	hat = hat;
#endif

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	if (sptd->spt_flags & SHM_PAGEABLE) {
		return (segspt_dismfault(hat, seg, addr, len, type, rw));
	}

	/*
	 * Because of the way spt is implemented
	 * the realsize of the segment does not have to be
	 * equal to the segment size itself. The segment size is
	 * often in multiples of a page size larger than PAGESIZE.
	 * The realsize is rounded up to the nearest PAGESIZE
	 * based on what the user requested. This is a bit of
	 * ungliness that is historical but not easily fixed
	 * without re-designing the higher levels of ISM.
	 */
	ASSERT(addr >= seg->s_base);
	if (((addr + len) - seg->s_base) > sptd->spt_realsize)
		return (FC_NOMAP);
	/*
	 * For all of the following cases except F_PROT, we need to
	 * make any necessary adjustments to addr and len
	 * and get all of the necessary page_t's into an array called ppa[].
	 *
	 * The code in shmat() forces base addr and len of ISM segment
	 * to be aligned to largest page size supported. Therefore,
	 * we are able to handle F_SOFTLOCK and F_INVAL calls in "large
	 * pagesize" chunks. We want to make sure that we HAT_LOAD_LOCK
	 * in large pagesize chunks, or else we will screw up the HAT
	 * layer by calling hat_memload_array() with differing page sizes
	 * over a given virtual range.
	 */
	pgsz = page_get_pagesize(sptseg->s_szc);
	pgcnt = page_get_pagecnt(sptseg->s_szc);
	shm_addr = (caddr_t)P2ALIGN((uintptr_t)(addr), pgsz);
	size = P2ROUNDUP((uintptr_t)(((addr + len) - shm_addr)), pgsz);
	npages = btopr(size);

	/*
	 * Now we need to convert from addr in segshm to addr in segspt.
	 */
	anon_index = seg_page(seg, shm_addr);
	sptseg_addr = sptseg->s_base + ptob(anon_index);

	/*
	 * And now we may have to adjust npages downward if we have
	 * exceeded the realsize of the segment or initial anon
	 * allocations.
	 */
	if ((sptseg_addr + ptob(npages)) >
	    (sptseg->s_base + sptd->spt_realsize))
		size = (sptseg->s_base + sptd->spt_realsize) - sptseg_addr;

	npages = btopr(size);

	ASSERT(sptseg_addr < (sptseg->s_base + sptseg->s_size));
	ASSERT((sptd->spt_flags & SHM_PAGEABLE) == 0);

	switch (type) {

	case F_SOFTLOCK:

		/*
		 * availrmem is decremented once during anon_swap_adjust()
		 * and is incremented during the anon_unresv(), which is
		 * called from shm_rm_amp() when the segment is destroyed.
		 */
		atomic_add_long((ulong_t *)(&(shmd->shm_softlockcnt)), npages);
		/*
		 * Some platforms assume that ISM pages are SE_SHARED
		 * locked for the entire life of the segment.
		 */
		if (!hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0))
			return (0);
		/*
		 * Fall through to the F_INVAL case to load up the hat layer
		 * entries with the HAT_LOAD_LOCK flag.
		 */

		/* FALLTHRU */
	case F_INVAL:

		if ((rw == S_EXEC) && !(sptd->spt_prot & PROT_EXEC))
			return (FC_NOMAP);

		/*
		 * Some platforms that do NOT support DYNAMIC_ISM_UNMAP
		 * may still rely on this call to hat_share(). That
		 * would imply that those hat's can fault on a
		 * HAT_LOAD_LOCK translation, which would seem
		 * contradictory.
		 */
		if (!hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0)) {
			if (hat_share(seg->s_as->a_hat, seg->s_base,
			    curspt->a_hat, sptseg->s_base,
			    sptseg->s_size, sptseg->s_szc) != 0) {
				panic("hat_share error in ISM fault");
				/*NOTREACHED*/
			}
			return (0);
		}
		ppa = kmem_zalloc(sizeof (page_t *) * npages, KM_SLEEP);

		/*
		 * I see no need to lock the real seg,
		 * here, because all of our work will be on the underlying
		 * dummy seg.
		 *
		 * sptseg_addr and npages now account for large pages.
		 */
		amp = sptd->spt_amp;
		ASSERT(amp != NULL);
		anon_index = seg_page(sptseg, sptseg_addr);

		ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
		for (i = 0; i < npages; i++) {
			ap = anon_get_ptr(amp->ahp, anon_index++);
			ASSERT(ap != NULL);
			swap_xlate(ap, &vp, &offset);
			pp = page_lookup(vp, offset, SE_SHARED);
			ASSERT(pp != NULL);
			ppa[i] = pp;
		}
		ANON_LOCK_EXIT(&amp->a_rwlock);
		ASSERT(i == npages);

		/*
		 * We are already holding the as->a_lock on the user's
		 * real segment, but we need to hold the a_lock on the
		 * underlying dummy as. This is mostly to satisfy the
		 * underlying HAT layer.
		 */
		AS_LOCK_ENTER(sptseg->s_as, RW_READER);
		a = sptseg_addr;
		pidx = 0;
		if (type == F_SOFTLOCK) {
			/*
			 * Load up the translation keeping it
			 * locked and don't unlock the page.
			 */
			for (; pidx < npages; a += pgsz, pidx += pgcnt) {
				sz = MIN(pgsz, ptob(npages - pidx));
				hat_memload_array(sptseg->s_as->a_hat, a,
				    sz, &ppa[pidx], sptd->spt_prot,
				    HAT_LOAD_LOCK | HAT_LOAD_SHARE);
			}
		} else {
			/*
			 * Migrate pages marked for migration.
			 */
			if (lgrp_optimizations())
				page_migrate(seg, shm_addr, ppa, npages);

			for (; pidx < npages; a += pgsz, pidx += pgcnt) {
				sz = MIN(pgsz, ptob(npages - pidx));
				hat_memload_array(sptseg->s_as->a_hat,
				    a, sz, &ppa[pidx],
				    sptd->spt_prot, HAT_LOAD_SHARE);
			}

			/*
			 * And now drop the SE_SHARED lock(s).
			 */
			for (i = 0; i < npages; i++)
				page_unlock(ppa[i]);
		}
		AS_LOCK_EXIT(sptseg->s_as);

		kmem_free(ppa, sizeof (page_t *) * npages);
		return (0);
	case F_SOFTUNLOCK:

		/*
		 * This is a bit ugly, we pass in the real seg pointer,
		 * but the sptseg_addr is the virtual address within the
		 * dummy seg.
		 */
		segspt_softunlock(seg, sptseg_addr, ptob(npages), rw);
		return (0);

	case F_PROT:

		/*
		 * This takes care of the unusual case where a user
		 * allocates a stack in shared memory and a register
		 * window overflow is written to that stack page before
		 * it is otherwise modified.
		 *
		 * We can get away with this because ISM segments are
		 * always rw. Other than this unusual case, there
		 * should be no instances of protection violations.
		 */
		return (0);

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "segspt_shmfault default type?");
#endif
		return (FC_NOMAP);
	}
}

/*ARGSUSED*/
static faultcode_t
segspt_shmfaulta(struct seg *seg, caddr_t addr)
{
	return (0);
}

/*ARGSUSED*/
static int
segspt_shmkluster(struct seg *seg, caddr_t addr, ssize_t delta)
{
	return (0);
}

/*ARGSUSED*/
static size_t
segspt_shmswapout(struct seg *seg)
{
	return (0);
}

/*
 * duplicate the shared page tables
 */
int
segspt_shmdup(struct seg *seg, struct seg *newseg)
{
	struct shm_data		*shmd = (struct shm_data *)seg->s_data;
	struct anon_map 	*amp = shmd->shm_amp;
	struct shm_data 	*shmd_new;
	struct seg		*spt_seg = shmd->shm_sptseg;
	struct spt_data		*sptd = spt_seg->s_data;
	int			error = 0;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	shmd_new = kmem_zalloc((sizeof (*shmd_new)), KM_SLEEP);
	newseg->s_data = (void *)shmd_new;
	shmd_new->shm_sptas = shmd->shm_sptas;
	shmd_new->shm_amp = amp;
	shmd_new->shm_sptseg = shmd->shm_sptseg;
	newseg->s_ops = &segspt_shmops;
	newseg->s_szc = seg->s_szc;
	ASSERT(seg->s_szc == shmd->shm_sptseg->s_szc);

	ANON_LOCK_ENTER(&amp->a_rwlock, RW_WRITER);
	amp->refcnt++;
	ANON_LOCK_EXIT(&amp->a_rwlock);

	if (sptd->spt_flags & SHM_PAGEABLE) {
		shmd_new->shm_vpage = kmem_zalloc(btopr(amp->size), KM_SLEEP);
		shmd_new->shm_lckpgs = 0;
		if (hat_supported(HAT_DYNAMIC_ISM_UNMAP, (void *)0)) {
			if ((error = hat_share(newseg->s_as->a_hat,
			    newseg->s_base, shmd->shm_sptas->a_hat, SEGSPTADDR,
			    seg->s_size, seg->s_szc)) != 0) {
				kmem_free(shmd_new->shm_vpage,
				    btopr(amp->size));
			}
		}
		return (error);
	} else {
		return (hat_share(newseg->s_as->a_hat, newseg->s_base,
		    shmd->shm_sptas->a_hat, SEGSPTADDR, seg->s_size,
		    seg->s_szc));

	}
}

/*ARGSUSED*/
int
segspt_shmcheckprot(struct seg *seg, caddr_t addr, size_t size, uint_t prot)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct spt_data *sptd = (struct spt_data *)shmd->shm_sptseg->s_data;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * ISM segment is always rw.
	 */
	return (((sptd->spt_prot & prot) != prot) ? EACCES : 0);
}

/*
 * Return an array of locked large pages, for empty slots allocate
 * private zero-filled anon pages.
 */
static int
spt_anon_getpages(
	struct seg *sptseg,
	caddr_t sptaddr,
	size_t len,
	page_t *ppa[])
{
	struct  spt_data *sptd = sptseg->s_data;
	struct  anon_map *amp = sptd->spt_amp;
	enum 	seg_rw rw = sptd->spt_prot;
	uint_t	szc = sptseg->s_szc;
	size_t	pg_sz, share_sz = page_get_pagesize(szc);
	pgcnt_t	lp_npgs;
	caddr_t	lp_addr, e_sptaddr;
	uint_t	vpprot, ppa_szc = 0;
	struct  vpage *vpage = NULL;
	ulong_t	j, ppa_idx;
	int	err, ierr = 0;
	pgcnt_t	an_idx;
	anon_sync_obj_t cookie;
	int anon_locked = 0;
	pgcnt_t amp_pgs;


	ASSERT(IS_P2ALIGNED(sptaddr, share_sz) && IS_P2ALIGNED(len, share_sz));
	ASSERT(len != 0);

	pg_sz = share_sz;
	lp_npgs = btop(pg_sz);
	lp_addr = sptaddr;
	e_sptaddr = sptaddr + len;
	an_idx = seg_page(sptseg, sptaddr);
	ppa_idx = 0;

	ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);

	amp_pgs = page_get_pagecnt(amp->a_szc);

	/*CONSTCOND*/
	while (1) {
		for (; lp_addr < e_sptaddr;
		    an_idx += lp_npgs, lp_addr += pg_sz, ppa_idx += lp_npgs) {

			/*
			 * If we're currently locked, and we get to a new
			 * page, unlock our current anon chunk.
			 */
			if (anon_locked && P2PHASE(an_idx, amp_pgs) == 0) {
				anon_array_exit(&cookie);
				anon_locked = 0;
			}
			if (!anon_locked) {
				anon_array_enter(amp, an_idx, &cookie);
				anon_locked = 1;
			}
			ppa_szc = (uint_t)-1;
			ierr = anon_map_getpages(amp, an_idx, szc, sptseg,
			    lp_addr, sptd->spt_prot, &vpprot, &ppa[ppa_idx],
			    &ppa_szc, vpage, rw, 0, segvn_anypgsz, 0, kcred);

			if (ierr != 0) {
				if (ierr > 0) {
					err = FC_MAKE_ERR(ierr);
					goto lpgs_err;
				}
				break;
			}
		}
		if (lp_addr == e_sptaddr) {
			break;
		}
		ASSERT(lp_addr < e_sptaddr);

		/*
		 * ierr == -1 means we failed to allocate a large page.
		 * so do a size down operation.
		 *
		 * ierr == -2 means some other process that privately shares
		 * pages with this process has allocated a larger page and we
		 * need to retry with larger pages. So do a size up
		 * operation. This relies on the fact that large pages are
		 * never partially shared i.e. if we share any constituent
		 * page of a large page with another process we must share the
		 * entire large page. Note this cannot happen for SOFTLOCK
		 * case, unless current address (lpaddr) is at the beginning
		 * of the next page size boundary because the other process
		 * couldn't have relocated locked pages.
		 */
		ASSERT(ierr == -1 || ierr == -2);
		if (segvn_anypgsz) {
			ASSERT(ierr == -2 || szc != 0);
			ASSERT(ierr == -1 || szc < sptseg->s_szc);
			szc = (ierr == -1) ? szc - 1 : szc + 1;
		} else {
			/*
			 * For faults and segvn_anypgsz == 0
			 * we need to be careful not to loop forever
			 * if existing page is found with szc other
			 * than 0 or seg->s_szc. This could be due
			 * to page relocations on behalf of DR or
			 * more likely large page creation. For this
			 * case simply re-size to existing page's szc
			 * if returned by anon_map_getpages().
			 */
			if (ppa_szc == (uint_t)-1) {
				szc = (ierr == -1) ? 0 : sptseg->s_szc;
			} else {
				ASSERT(ppa_szc <= sptseg->s_szc);
				ASSERT(ierr == -2 || ppa_szc < szc);
				ASSERT(ierr == -1 || ppa_szc > szc);
				szc = ppa_szc;
			}
		}
		pg_sz = page_get_pagesize(szc);
		lp_npgs = btop(pg_sz);
		ASSERT(IS_P2ALIGNED(lp_addr, pg_sz));
	}
	if (anon_locked) {
		anon_array_exit(&cookie);
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);
	return (0);

lpgs_err:
	if (anon_locked) {
		anon_array_exit(&cookie);
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);
	for (j = 0; j < ppa_idx; j++)
		page_unlock(ppa[j]);
	return (err);
}

/*
 * count the number of bytes in a set of spt pages that are currently not
 * locked
 */
static rctl_qty_t
spt_unlockedbytes(pgcnt_t npages, page_t **ppa)
{
	ulong_t	i;
	rctl_qty_t unlocked = 0;

	for (i = 0; i < npages; i++) {
		if (ppa[i]->p_lckcnt == 0)
			unlocked += PAGESIZE;
	}
	return (unlocked);
}

extern	u_longlong_t randtick(void);
/* number of locks to reserve/skip by spt_lockpages() and spt_unlockpages() */
#define	NLCK	(NCPU_P2)
/* Random number with a range [0, n-1], n must be power of two */
#define	RAND_P2(n)	\
	((((long)curthread >> PTR24_LSB) ^ (long)randtick()) & ((n) - 1))

int
spt_lockpages(struct seg *seg, pgcnt_t anon_index, pgcnt_t npages,
    page_t **ppa, ulong_t *lockmap, size_t pos,
    rctl_qty_t *locked)
{
	struct	shm_data *shmd = seg->s_data;
	struct	spt_data *sptd = shmd->shm_sptseg->s_data;
	ulong_t	i;
	int	kernel;
	pgcnt_t	nlck = 0;
	int	rv = 0;
	int	use_reserved = 1;

	/* return the number of bytes actually locked */
	*locked = 0;

	/*
	 * To avoid contention on freemem_lock, availrmem and pages_locked
	 * global counters are updated only every nlck locked pages instead of
	 * every time.  Reserve nlck locks up front and deduct from this
	 * reservation for each page that requires a lock.  When the reservation
	 * is consumed, reserve again.  nlck is randomized, so the competing
	 * threads do not fall into a cyclic lock contention pattern. When
	 * memory is low, the lock ahead is disabled, and instead page_pp_lock()
	 * is used to lock pages.
	 */
	for (i = 0; i < npages; anon_index++, pos++, i++) {
		if (nlck == 0 && use_reserved == 1) {
			nlck = NLCK + RAND_P2(NLCK);
			/* if fewer loops left, decrease nlck */
			nlck = MIN(nlck, npages - i);
			/*
			 * Reserve nlck locks up front and deduct from this
			 * reservation for each page that requires a lock.  When
			 * the reservation is consumed, reserve again.
			 */
			mutex_enter(&freemem_lock);
			if ((availrmem - nlck) < pages_pp_maximum) {
				/* Do not do advance memory reserves */
				use_reserved = 0;
			} else {
				availrmem	-= nlck;
				pages_locked	+= nlck;
			}
			mutex_exit(&freemem_lock);
		}
		if (!(shmd->shm_vpage[anon_index] & DISM_PG_LOCKED)) {
			if (sptd->spt_ppa_lckcnt[anon_index] <
			    (ushort_t)DISM_LOCK_MAX) {
				if (++sptd->spt_ppa_lckcnt[anon_index] ==
				    (ushort_t)DISM_LOCK_MAX) {
					cmn_err(CE_WARN,
					    "DISM page lock limit "
					    "reached on DISM offset 0x%lx\n",
					    anon_index << PAGESHIFT);
				}
				kernel = (sptd->spt_ppa &&
				    sptd->spt_ppa[anon_index]);
				if (!page_pp_lock(ppa[i], 0, kernel ||
				    use_reserved)) {
					sptd->spt_ppa_lckcnt[anon_index]--;
					rv = EAGAIN;
					break;
				}
				/* if this is a newly locked page, count it */
				if (ppa[i]->p_lckcnt == 1) {
					if (kernel == 0 && use_reserved == 1)
						nlck--;
					*locked += PAGESIZE;
				}
				shmd->shm_lckpgs++;
				shmd->shm_vpage[anon_index] |= DISM_PG_LOCKED;
				if (lockmap != NULL)
					BT_SET(lockmap, pos);
			}
		}
	}
	/* Return unused lock reservation */
	if (nlck != 0 && use_reserved == 1) {
		mutex_enter(&freemem_lock);
		availrmem	+= nlck;
		pages_locked	-= nlck;
		mutex_exit(&freemem_lock);
	}

	return (rv);
}

int
spt_unlockpages(struct seg *seg, pgcnt_t anon_index, pgcnt_t npages,
    rctl_qty_t *unlocked)
{
	struct shm_data	*shmd = seg->s_data;
	struct spt_data	*sptd = shmd->shm_sptseg->s_data;
	struct anon_map	*amp = sptd->spt_amp;
	struct anon 	*ap;
	struct vnode 	*vp;
	u_offset_t 	off;
	struct page	*pp;
	int		kernel;
	anon_sync_obj_t	cookie;
	ulong_t		i;
	pgcnt_t		nlck = 0;
	pgcnt_t		nlck_limit = NLCK;

	ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
	for (i = 0; i < npages; i++, anon_index++) {
		if (shmd->shm_vpage[anon_index] & DISM_PG_LOCKED) {
			anon_array_enter(amp, anon_index, &cookie);
			ap = anon_get_ptr(amp->ahp, anon_index);
			ASSERT(ap);

			swap_xlate(ap, &vp, &off);
			anon_array_exit(&cookie);
			pp = page_lookup(vp, off, SE_SHARED);
			ASSERT(pp);
			/*
			 * availrmem is decremented only for pages which are not
			 * in seg pcache, for pages in seg pcache availrmem was
			 * decremented in _dismpagelock()
			 */
			kernel = (sptd->spt_ppa && sptd->spt_ppa[anon_index]);
			ASSERT(pp->p_lckcnt > 0);

			/*
			 * lock page but do not change availrmem, we do it
			 * ourselves every nlck loops.
			 */
			page_pp_unlock(pp, 0, 1);
			if (pp->p_lckcnt == 0) {
				if (kernel == 0)
					nlck++;
				*unlocked += PAGESIZE;
			}
			page_unlock(pp);
			shmd->shm_vpage[anon_index] &= ~DISM_PG_LOCKED;
			sptd->spt_ppa_lckcnt[anon_index]--;
			shmd->shm_lckpgs--;
		}

		/*
		 * To reduce freemem_lock contention, do not update availrmem
		 * until at least NLCK pages have been unlocked.
		 * 1. No need to update if nlck is zero
		 * 2. Always update if the last iteration
		 */
		if (nlck > 0 && (nlck == nlck_limit || i == npages - 1)) {
			mutex_enter(&freemem_lock);
			availrmem	+= nlck;
			pages_locked	-= nlck;
			mutex_exit(&freemem_lock);
			nlck = 0;
			nlck_limit = NLCK + RAND_P2(NLCK);
		}
	}
	ANON_LOCK_EXIT(&amp->a_rwlock);

	return (0);
}

/*ARGSUSED*/
static int
segspt_shmlockop(struct seg *seg, caddr_t addr, size_t len,
    int attr, int op, ulong_t *lockmap, size_t pos)
{
	struct shm_data *shmd = seg->s_data;
	struct seg	*sptseg = shmd->shm_sptseg;
	struct spt_data *sptd = sptseg->s_data;
	struct kshmid	*sp = sptd->spt_amp->a_sp;
	pgcnt_t		npages, a_npages;
	page_t		**ppa;
	pgcnt_t 	an_idx, a_an_idx, ppa_idx;
	caddr_t		spt_addr, a_addr;	/* spt and aligned address */
	size_t		a_len;			/* aligned len */
	size_t		share_sz;
	ulong_t		i;
	int		sts = 0;
	rctl_qty_t	unlocked = 0;
	rctl_qty_t	locked = 0;
	struct proc	*p = curproc;
	kproject_t	*proj;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));
	ASSERT(sp != NULL);

	if ((sptd->spt_flags & SHM_PAGEABLE) == 0) {
		return (0);
	}

	addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	an_idx = seg_page(seg, addr);
	npages = btopr(len);

	if (an_idx + npages > btopr(shmd->shm_amp->size)) {
		return (ENOMEM);
	}

	/*
	 * A shm's project never changes, so no lock needed.
	 * The shm has a hold on the project, so it will not go away.
	 * Since we have a mapping to shm within this zone, we know
	 * that the zone will not go away.
	 */
	proj = sp->shm_perm.ipc_proj;

	if (op == MC_LOCK) {

		/*
		 * Need to align addr and size request if they are not
		 * aligned so we can always allocate large page(s) however
		 * we only lock what was requested in initial request.
		 */
		share_sz = page_get_pagesize(sptseg->s_szc);
		a_addr = (caddr_t)P2ALIGN((uintptr_t)(addr), share_sz);
		a_len = P2ROUNDUP((uintptr_t)(((addr + len) - a_addr)),
		    share_sz);
		a_npages = btop(a_len);
		a_an_idx = seg_page(seg, a_addr);
		spt_addr = sptseg->s_base + ptob(a_an_idx);
		ppa_idx = an_idx - a_an_idx;

		if ((ppa = kmem_zalloc(((sizeof (page_t *)) * a_npages),
		    KM_NOSLEEP)) == NULL) {
			return (ENOMEM);
		}

		/*
		 * Don't cache any new pages for IO and
		 * flush any cached pages.
		 */
		mutex_enter(&sptd->spt_lock);
		if (sptd->spt_ppa != NULL)
			sptd->spt_flags |= DISM_PPA_CHANGED;

		sts = spt_anon_getpages(sptseg, spt_addr, a_len, ppa);
		if (sts != 0) {
			mutex_exit(&sptd->spt_lock);
			kmem_free(ppa, ((sizeof (page_t *)) * a_npages));
			return (sts);
		}

		mutex_enter(&sp->shm_mlock);
		/* enforce locked memory rctl */
		unlocked = spt_unlockedbytes(npages, &ppa[ppa_idx]);

		mutex_enter(&p->p_lock);
		if (rctl_incr_locked_mem(p, proj, unlocked, 0)) {
			mutex_exit(&p->p_lock);
			sts = EAGAIN;
		} else {
			mutex_exit(&p->p_lock);
			sts = spt_lockpages(seg, an_idx, npages,
			    &ppa[ppa_idx], lockmap, pos, &locked);

			/*
			 * correct locked count if not all pages could be
			 * locked
			 */
			if ((unlocked - locked) > 0) {
				rctl_decr_locked_mem(NULL, proj,
				    (unlocked - locked), 0);
			}
		}
		/*
		 * unlock pages
		 */
		for (i = 0; i < a_npages; i++)
			page_unlock(ppa[i]);
		if (sptd->spt_ppa != NULL)
			sptd->spt_flags |= DISM_PPA_CHANGED;
		mutex_exit(&sp->shm_mlock);
		mutex_exit(&sptd->spt_lock);

		kmem_free(ppa, ((sizeof (page_t *)) * a_npages));

	} else if (op == MC_UNLOCK) { /* unlock */
		page_t		**ppa;

		mutex_enter(&sptd->spt_lock);
		if (shmd->shm_lckpgs == 0) {
			mutex_exit(&sptd->spt_lock);
			return (0);
		}
		/*
		 * Don't cache new IO pages.
		 */
		if (sptd->spt_ppa != NULL)
			sptd->spt_flags |= DISM_PPA_CHANGED;

		mutex_enter(&sp->shm_mlock);
		sts = spt_unlockpages(seg, an_idx, npages, &unlocked);
		if ((ppa = sptd->spt_ppa) != NULL)
			sptd->spt_flags |= DISM_PPA_CHANGED;
		mutex_exit(&sptd->spt_lock);

		rctl_decr_locked_mem(NULL, proj, unlocked, 0);
		mutex_exit(&sp->shm_mlock);

		if (ppa != NULL)
			seg_ppurge_wiredpp(ppa);
	}
	return (sts);
}

/*ARGSUSED*/
int
segspt_shmgetprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct spt_data *sptd = (struct spt_data *)shmd->shm_sptseg->s_data;
	spgcnt_t pgno = seg_page(seg, addr+len) - seg_page(seg, addr) + 1;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * ISM segment is always rw.
	 */
	while (--pgno >= 0)
		*protv++ = sptd->spt_prot;
	return (0);
}

/*ARGSUSED*/
u_offset_t
segspt_shmgetoffset(struct seg *seg, caddr_t addr)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/* Offset does not matter in ISM memory */

	return ((u_offset_t)0);
}

/* ARGSUSED */
int
segspt_shmgettype(struct seg *seg, caddr_t addr)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct spt_data *sptd = (struct spt_data *)shmd->shm_sptseg->s_data;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * The shared memory mapping is always MAP_SHARED, SWAP is only
	 * reserved for DISM
	 */
	return (MAP_SHARED |
	    ((sptd->spt_flags & SHM_PAGEABLE) ? 0 : MAP_NORESERVE));
}

/*ARGSUSED*/
int
segspt_shmgetvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct spt_data *sptd = (struct spt_data *)shmd->shm_sptseg->s_data;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	*vpp = sptd->spt_vp;
	return (0);
}

/*
 * We need to wait for pending IO to complete to a DISM segment in order for
 * pages to get kicked out of the seg_pcache.  120 seconds should be more
 * than enough time to wait.
 */
static clock_t spt_pcache_wait = 120;

/*ARGSUSED*/
static int
segspt_shmadvise(struct seg *seg, caddr_t addr, size_t len, uint_t behav)
{
	struct shm_data	*shmd = (struct shm_data *)seg->s_data;
	struct spt_data	*sptd = (struct spt_data *)shmd->shm_sptseg->s_data;
	struct anon_map	*amp;
	pgcnt_t pg_idx;
	ushort_t gen;
	clock_t	end_lbolt;
	int writer;
	page_t **ppa;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	if (behav == MADV_FREE) {
		if ((sptd->spt_flags & SHM_PAGEABLE) == 0)
			return (0);

		amp = sptd->spt_amp;
		pg_idx = seg_page(seg, addr);

		mutex_enter(&sptd->spt_lock);
		if ((ppa = sptd->spt_ppa) == NULL) {
			mutex_exit(&sptd->spt_lock);
			ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
			anon_disclaim(amp, pg_idx, len);
			ANON_LOCK_EXIT(&amp->a_rwlock);
			return (0);
		}

		sptd->spt_flags |= DISM_PPA_CHANGED;
		gen = sptd->spt_gen;

		mutex_exit(&sptd->spt_lock);

		/*
		 * Purge all DISM cached pages
		 */
		seg_ppurge_wiredpp(ppa);

		/*
		 * Drop the AS_LOCK so that other threads can grab it
		 * in the as_pageunlock path and hopefully get the segment
		 * kicked out of the seg_pcache.  We bump the shm_softlockcnt
		 * to keep this segment resident.
		 */
		writer = AS_WRITE_HELD(seg->s_as);
		atomic_inc_ulong((ulong_t *)(&(shmd->shm_softlockcnt)));
		AS_LOCK_EXIT(seg->s_as);

		mutex_enter(&sptd->spt_lock);

		end_lbolt = ddi_get_lbolt() + (hz * spt_pcache_wait);

		/*
		 * Try to wait for pages to get kicked out of the seg_pcache.
		 */
		while (sptd->spt_gen == gen &&
		    (sptd->spt_flags & DISM_PPA_CHANGED) &&
		    ddi_get_lbolt() < end_lbolt) {
			if (!cv_timedwait_sig(&sptd->spt_cv,
			    &sptd->spt_lock, end_lbolt)) {
				break;
			}
		}

		mutex_exit(&sptd->spt_lock);

		/* Regrab the AS_LOCK and release our hold on the segment */
		AS_LOCK_ENTER(seg->s_as, writer ? RW_WRITER : RW_READER);
		atomic_dec_ulong((ulong_t *)(&(shmd->shm_softlockcnt)));
		if (shmd->shm_softlockcnt <= 0) {
			if (AS_ISUNMAPWAIT(seg->s_as)) {
				mutex_enter(&seg->s_as->a_contents);
				if (AS_ISUNMAPWAIT(seg->s_as)) {
					AS_CLRUNMAPWAIT(seg->s_as);
					cv_broadcast(&seg->s_as->a_cv);
				}
				mutex_exit(&seg->s_as->a_contents);
			}
		}

		ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
		anon_disclaim(amp, pg_idx, len);
		ANON_LOCK_EXIT(&amp->a_rwlock);
	} else if (lgrp_optimizations() && (behav == MADV_ACCESS_LWP ||
	    behav == MADV_ACCESS_MANY || behav == MADV_ACCESS_DEFAULT)) {
		int			already_set;
		ulong_t			anon_index;
		lgrp_mem_policy_t	policy;
		caddr_t			shm_addr;
		size_t			share_size;
		size_t			size;
		struct seg		*sptseg = shmd->shm_sptseg;
		caddr_t			sptseg_addr;

		/*
		 * Align address and length to page size of underlying segment
		 */
		share_size = page_get_pagesize(shmd->shm_sptseg->s_szc);
		shm_addr = (caddr_t)P2ALIGN((uintptr_t)(addr), share_size);
		size = P2ROUNDUP((uintptr_t)(((addr + len) - shm_addr)),
		    share_size);

		amp = shmd->shm_amp;
		anon_index = seg_page(seg, shm_addr);

		/*
		 * And now we may have to adjust size downward if we have
		 * exceeded the realsize of the segment or initial anon
		 * allocations.
		 */
		sptseg_addr = sptseg->s_base + ptob(anon_index);
		if ((sptseg_addr + size) >
		    (sptseg->s_base + sptd->spt_realsize))
			size = (sptseg->s_base + sptd->spt_realsize) -
			    sptseg_addr;

		/*
		 * Set memory allocation policy for this segment
		 */
		policy = lgrp_madv_to_policy(behav, len, MAP_SHARED);
		already_set = lgrp_shm_policy_set(policy, amp, anon_index,
		    NULL, 0, len);

		/*
		 * If random memory allocation policy set already,
		 * don't bother reapplying it.
		 */
		if (already_set && !LGRP_MEM_POLICY_REAPPLICABLE(policy))
			return (0);

		/*
		 * Mark any existing pages in the given range for
		 * migration, flushing the I/O page cache, and using
		 * underlying segment to calculate anon index and get
		 * anonmap and vnode pointer from
		 */
		if (shmd->shm_softlockcnt > 0)
			segspt_purge(seg);

		page_mark_migrate(seg, shm_addr, size, amp, 0, NULL, 0, 0);
	}

	return (0);
}

/*ARGSUSED*/
void
segspt_shmdump(struct seg *seg)
{
	/* no-op for ISM segment */
}

/*ARGSUSED*/
static faultcode_t
segspt_shmsetpgsz(struct seg *seg, caddr_t addr, size_t len, uint_t szc)
{
	return (ENOTSUP);
}

/*
 * get a memory ID for an addr in a given segment
 */
static int
segspt_shmgetmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	struct shm_data *shmd = (struct shm_data *)seg->s_data;
	struct anon 	*ap;
	size_t		anon_index;
	struct anon_map	*amp = shmd->shm_amp;
	struct spt_data	*sptd = shmd->shm_sptseg->s_data;
	struct seg	*sptseg = shmd->shm_sptseg;
	anon_sync_obj_t	cookie;

	anon_index = seg_page(seg, addr);

	if (addr > (seg->s_base + sptd->spt_realsize)) {
		return (EFAULT);
	}

	ANON_LOCK_ENTER(&amp->a_rwlock, RW_READER);
	anon_array_enter(amp, anon_index, &cookie);
	ap = anon_get_ptr(amp->ahp, anon_index);
	if (ap == NULL) {
		struct page *pp;
		caddr_t spt_addr = sptseg->s_base + ptob(anon_index);

		pp = anon_zero(sptseg, spt_addr, &ap, kcred);
		if (pp == NULL) {
			anon_array_exit(&cookie);
			ANON_LOCK_EXIT(&amp->a_rwlock);
			return (ENOMEM);
		}
		(void) anon_set_ptr(amp->ahp, anon_index, ap, ANON_SLEEP);
		page_unlock(pp);
	}
	anon_array_exit(&cookie);
	ANON_LOCK_EXIT(&amp->a_rwlock);
	memidp->val[0] = (uintptr_t)ap;
	memidp->val[1] = (uintptr_t)addr & PAGEOFFSET;
	return (0);
}

/*
 * Get memory allocation policy info for specified address in given segment
 */
static lgrp_mem_policy_info_t *
segspt_shmgetpolicy(struct seg *seg, caddr_t addr)
{
	struct anon_map		*amp;
	ulong_t			anon_index;
	lgrp_mem_policy_info_t	*policy_info;
	struct shm_data		*shm_data;

	ASSERT(seg != NULL);

	/*
	 * Get anon_map from segshm
	 *
	 * Assume that no lock needs to be held on anon_map, since
	 * it should be protected by its reference count which must be
	 * nonzero for an existing segment
	 * Need to grab readers lock on policy tree though
	 */
	shm_data = (struct shm_data *)seg->s_data;
	if (shm_data == NULL)
		return (NULL);
	amp = shm_data->shm_amp;
	ASSERT(amp->refcnt != 0);

	/*
	 * Get policy info
	 *
	 * Assume starting anon index of 0
	 */
	anon_index = seg_page(seg, addr);
	policy_info = lgrp_shm_policy_get(amp, anon_index, NULL, 0);

	return (policy_info);
}

/*ARGSUSED*/
static int
segspt_shmcapable(struct seg *seg, segcapability_t capability)
{
	return (0);
}
