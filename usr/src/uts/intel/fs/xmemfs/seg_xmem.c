/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The segxmem driver is used by the xmemfs to get faster (than seg_map)
 * mappings [lower routine overhead] to random vnode/offsets.
 * Mappings are made to a very limited kernel address range and to a
 * potentially much larger user address range. It is the speed of mmap
 * and munmaps to the user address space that we are concerned with.
 * We also need to ensure very low overhead for I/O similar to seg_spt
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
#include <sys/map.h>
#include <sys/atomic.h>

#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/rm.h>
#include <sys/vfs.h>
#include <sys/fs/seg_xmem.h>
#include <sys/fs/xmem.h>
#include <sys/lgrp.h>

/*
 * Private seg op routines.
 */
static void	segxmem_free(struct seg *seg);
static int	segxmem_dup(struct seg *seg, struct seg *newseg);
static int	segxmem_unmap(struct seg *seg, caddr_t raddr, size_t ssize);
static faultcode_t segxmem_fault(struct hat *hat, struct seg *seg, caddr_t addr,
			size_t len, enum fault_type type, enum seg_rw rw);
static int	segxmem_setprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t prot);
static int	segxmem_checkprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t prot);
static size_t segxmem_incore(struct seg *seg, caddr_t addr, size_t len,
			register char *vec);
static int segxmem_sync(struct seg *seg, register caddr_t addr, size_t len,
			int attr, uint_t flags);
static int	segxmem_lockop(struct seg *seg, caddr_t addr, size_t len,
			int attr, int op, ulong_t *lockmap, size_t pos);
static int	segxmem_getprot(struct seg *seg, caddr_t addr, size_t len,
			uint_t *protv);
static u_offset_t	segxmem_getoffset(struct seg *seg, caddr_t addr);
static int	segxmem_gettype(struct seg *seg, caddr_t addr);
static int	segxmem_getvp(struct seg *, caddr_t, struct vnode **);
static int segxmem_advise(struct seg *seg, caddr_t addr, size_t len,
			uint_t behav);
static void	segxmem_dump(struct seg *seg);
static int	segxmem_pagelock(struct seg *seg, caddr_t addr, size_t len,
			struct page ***ppp, enum lock_type type,
			enum seg_rw rw);
static int	segxmem_setpgsz(struct seg *, caddr_t, size_t, uint_t);
static int	segxmem_getmemid(struct seg *, caddr_t, memid_t *);

#define	SEGXMEM_NULLOP(t)	(t(*)())NULL

static struct seg_ops segxmem_ops = {
	segxmem_dup,		/* dup */
	segxmem_unmap,
	segxmem_free,
	segxmem_fault,		/* Change if HAT_DYNAMIC_ISM_UNMAP suported */
	SEGXMEM_NULLOP(int),	/* faulta */
	segxmem_setprot,
	segxmem_checkprot,
	SEGXMEM_NULLOP(int),	/* kluster */
	SEGXMEM_NULLOP(size_t),	/* swapout */
	segxmem_sync,		/* sync */
	segxmem_incore,		/* incore */
	segxmem_lockop,		/* lockop */
	segxmem_getprot,
	segxmem_getoffset,
	segxmem_gettype,
	segxmem_getvp,
	segxmem_advise,		/* advise */
	segxmem_dump,
	segxmem_pagelock,	/* pagelock */
	segxmem_setpgsz,
	segxmem_getmemid,	/* getmemid */
	SEGXMEM_NULLOP(lgrp_mem_policy_info_t *),	/* getpolicy */
};


/*
 * Statistics for segxmem operations.
 *
 * No explicit locking to protect these stats.
 */
struct segxmemcnt segxmemcnt = {
	{ "fault",		KSTAT_DATA_ULONG },
	{ "getmap",		KSTAT_DATA_ULONG },
	{ "pagecreate",		KSTAT_DATA_ULONG }
};

kstat_named_t *segxmemcnt_ptr = (kstat_named_t *)&segxmemcnt;
uint_t segxmemcnt_ndata = sizeof (segxmemcnt) / sizeof (kstat_named_t);


int		segxmem_DR = -1;	/* Indicate if hat supports DR */

int		remap_broken = 0;


int
segxmem_create(struct seg *seg, struct segxmem_crargs *xmem_a)
{
	struct segxmem_data *sxd;
	uint_t	prot;
	caddr_t	taddr;
	uint_t	blocknumber, lastblock;
	page_t	***ppa;
	struct	hat	*hat;
	size_t	tlen;

	ASSERT(seg->s_as && RW_WRITE_HELD(&seg->s_as->a_lock));

	if (((uintptr_t)seg->s_base | seg->s_size) & PAGEOFFSET)
		panic("segxmem not PAGESIZE aligned");

	sxd = kmem_zalloc(sizeof (struct segxmem_data), KM_SLEEP);

	seg->s_data = (void *)sxd;
	seg->s_ops = &segxmem_ops;

	sxd->sxd_prot = xmem_a->xma_prot;
	sxd->sxd_vp = xmem_a->xma_vp;
	sxd->sxd_offset = xmem_a->xma_offset;
	sxd->sxd_bshift = xmem_a->xma_bshift;
	sxd->sxd_bsize = 1 << xmem_a->xma_bshift;

	blocknumber = 0;
	lastblock = (seg->s_size - 1) >> sxd->sxd_bshift;
	taddr = seg->s_base;
	tlen = sxd->sxd_bsize;
	ppa = xmem_a->xma_ppa;
	hat = seg->s_as->a_hat;
	prot = xmem_a->xma_prot;
	while (blocknumber <= lastblock) {
		page_t		**ppp;

		if (VTOXM(sxd->sxd_vp)->xm_ppb == 1)
			ppp = (page_t **)ppa;
		else
			ppp = *ppa;

		hat_memload_array(hat, taddr, tlen, ppp, prot | HAT_NOSYNC,
			HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);

		blocknumber++;
		ppa++;
		taddr += tlen;
	}

	return (0);
}

static void
segxmem_free(seg)
	struct seg *seg;
{
	struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;
	ASSERT(seg->s_as && RW_WRITE_HELD(&seg->s_as->a_lock));
	kmem_free(sxd, sizeof (struct segxmem_data));

}

static int
segxmem_dup(struct seg *seg, struct seg *newseg)
{
	struct segxmem_data	*sxd = (struct segxmem_data *)seg->s_data;
	struct segxmem_data	*newsxd;
	caddr_t			vaddr;
	ulong_t			pfn;
	page_t			*pp, **ppa;
	int			i;
	int			ppb;

	newsxd = kmem_zalloc(sizeof (struct segxmem_data), KM_SLEEP);

	newsxd->sxd_vp = sxd->sxd_vp;
	newsxd->sxd_offset = sxd->sxd_offset;
	newsxd->sxd_bsize = sxd->sxd_bsize;
	newsxd->sxd_bshift = sxd->sxd_bshift;
	newsxd->sxd_prot = sxd->sxd_prot;

	newsxd->sxd_softlockcnt = sxd->sxd_softlockcnt;

	newseg->s_ops = &segxmem_ops;
	newseg->s_data = (void *)newsxd;

	ppb = btop(sxd->sxd_bsize);
	if (ppb > 1)
		ppa = kmem_alloc(ppb * sizeof (page_t *), KM_SLEEP);
	else
		ppa = &pp;

	for (vaddr = seg->s_base; vaddr < seg->s_base + seg->s_size;
		vaddr += sxd->sxd_bsize) {

		/* ### sxd->sxd_vp->xn_ppa[(vaddr - s_base)]->p_pagenum */

		pfn = hat_getpfnum(seg->s_as->a_hat, vaddr);

		if (pfn == PFN_INVALID)
			continue;

		for (i = 0; i < ppb; i++) {
			ppa[i] = page_numtopp_nolock(pfn);
			pfn++;
		}
		hat_memload_array(newseg->s_as->a_hat, vaddr, sxd->sxd_bsize,
			ppa, sxd->sxd_prot | HAT_NOSYNC,
			HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
	}
	if (ppb > 1)
		kmem_free(ppa, ppb * sizeof (page_t *));

	return (0);
}

/*
 * This routine is called via a machine specific fault handling
 * routine.  It is also called by software routines wishing to
 * lock or unlock a range of addresses.
 */
static faultcode_t
segxmem_fault(
	struct hat *hat,
	struct seg *seg,
	caddr_t addr,
	size_t len,
	enum fault_type type,
	enum seg_rw rw)
{
	struct segxmem_data	*sxd;
	size_t			npages = btopr(len);

#ifdef lint
	hat = hat;
	addr = addr;
#endif

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	sxd = (struct segxmem_data *)seg->s_data;

	ASSERT(addr >= seg->s_base);
	ASSERT(((addr + len) - seg->s_base) <= seg->s_size);

	switch (type) {

	case F_SOFTLOCK:

		/*
		 * Because we know that every shared memory is
		 * already locked and called in the same context.
		 */
		atomic_add_long(&sxd->sxd_softlockcnt, npages);
		return (0);

	case F_SOFTUNLOCK:

		atomic_add_long(&sxd->sxd_softlockcnt, -npages);

		/*
		 * Check for softlock
		 */
		if (sxd->sxd_softlockcnt == 0) {
			/*
			 * All SOFTLOCKS are gone. Wakeup any waiting
			 * unmappers so they can try again to unmap.
			 * As an optimization check for waiters first
			 * without the mutex held, so we're not always
			 * grabbing it on softunlocks.
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
		return (0);

	case F_INVAL:

		if ((rw == S_EXEC) && !(sxd->sxd_prot & PROT_EXEC))
			return (FC_NOMAP);

		/*
		 * all xmem pages should already be mapped - desired mapping
		 * unknown
		 */

		panic("xmem page fault");
		/*NOTREACHED*/

	case F_PROT:
		/*
		 * We can get away with this because ISM segments are
		 * always rw. Other than this unusual case, there
		 * should be no instances of protection violations.
		 */
		return (0);

	default:
		XMEMPRINTF(8, ("segxmem_fault: type %x\n", type));
		return (FC_NOMAP);
	}
}

static int
segxmem_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;

	ASSERT(seg->s_as && RW_LOCK_HELD(&seg->s_as->a_lock));

	if (seg->s_base == addr && seg->s_size == len) {
		sxd->sxd_prot = prot;
		hat_chgprot(seg->s_as->a_hat, addr, len, prot);
	} else {
		return (IE_NOMEM);
	}
	return (0);
}

/*ARGSUSED*/
static int
segxmem_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;

	ASSERT(seg->s_as && RW_LOCK_HELD(&seg->s_as->a_lock));

	/*
	 * Need not acquire the segment lock since
	 * "sxd_prot" is a read-only field.
	 */
	return (((sxd->sxd_prot & prot) != prot) ? EACCES : 0);
}

static int
segxmem_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;
	size_t pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	if (pgno != 0) {
		do
			protv[--pgno] = sxd->sxd_prot;
		while (pgno != 0);
	}
	return (0);
}

static u_offset_t
segxmem_getoffset(struct seg *seg, caddr_t addr)
{
	register struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;

	ASSERT(seg->s_as && RW_LOCK_HELD(&seg->s_as->a_lock));

	return ((u_offset_t)sxd->sxd_offset + (addr - seg->s_base));
}

/*ARGSUSED*/
static int
segxmem_gettype(struct seg *seg, caddr_t addr)
{
	ASSERT(seg->s_as && RW_LOCK_HELD(&seg->s_as->a_lock));

	return (MAP_SHARED);
}

/*ARGSUSED*/
static int
segxmem_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	register struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;

	ASSERT(seg->s_as && RW_LOCK_HELD(&seg->s_as->a_lock));

	*vpp = sxd->sxd_vp;
	return (0);
}

#ifndef lint		/* currently unused */
/*
 * Check to see if it makes sense to do kluster/read ahead to
 * addr + delta relative to the mapping at addr.  We assume here
 * that delta is a signed PAGESIZE'd multiple (which can be negative).
 *
 * For segxmem we always "approve" of this action from our standpoint.
 */
/*ARGSUSED*/
static int
segxmem_kluster(struct seg *seg, caddr_t addr, ssize_t delta)
{
	return (0);
}

static void
segxmem_badop()
{
	panic("segxmem_badop");
	/*NOTREACHED*/
}

#endif

/*
 * Special public segxmem operations
 */


void
segxmem_pageunlock(struct seg *seg, caddr_t addr, size_t len, enum seg_rw rw)
{
	page_t			*pp;
	struct segxmem_data	*sxd = (struct segxmem_data *)(seg->s_data);
	struct	vnode		*vp = sxd->sxd_vp;
	u_offset_t		off = sxd->sxd_offset;
	caddr_t			eaddr;

	ASSERT(seg->s_as == &kas);

	panic("segxmem_pageunlock");

	eaddr = addr + len;
	addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);

	for (; addr < eaddr; addr += PAGESIZE, off += PAGESIZE) {
		hat_unlock(kas.a_hat, addr, PAGESIZE);

		/*
		 * Use page_find() instead of page_lookup() to
		 * find the page since we know that it has
		 * "exclusive" lock.
		 */
		pp = page_find(vp, off);
		if (pp == NULL)
			panic("segxmem_pageunlock");
		if (rw == S_WRITE) {
			hat_setrefmod(pp);
		} else if (rw != S_OTHER) {
			hat_setref(pp);
		}

		page_unlock(pp);
	}
}

/*
 * segxmem_getmap allocates from the map an address range to map the vnode vp
 * in the range <off, off + len).
 *
 * If pagecreate is nonzero, segxmem_getmap will create the page(s).
 * calls hat_memload_array to load the translations.
 * **ppa can be NULL if pagecreate is 0.
 */
caddr_t
segxmem_getmap(struct map *map, struct vnode *vp, u_offset_t off, size_t len,
	page_t	**ppa, enum seg_rw rw)
{
	caddr_t baseaddr;
	uint_t	attr = (rw == S_WRITE)?PROT_WRITE|PROT_READ:PROT_READ;

#ifdef lint
	vp = vp;
	off = off;
#endif

	segxmemcnt.sx_getmapflt.value.ul++;

	baseaddr = (caddr_t)rmalloc_wait(map, len);

	hat_memload_array(kas.a_hat, baseaddr, len, ppa, attr | HAT_NOSYNC,
		HAT_LOAD);

	return (baseaddr);
}

void
segxmem_release(struct map *map, caddr_t addr, size_t len)
{

	hat_unload(kas.a_hat, addr, len, HAT_UNLOAD_NOSYNC);
	rmfree(map, len, (ulong_t)addr);
}

int
segxmem_remap(struct seg *seg, struct vnode *vp, caddr_t addr, size_t len,
					page_t ***ppa, uchar_t prot)
{
	struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;
	uint_t	blocknumber, lastblock, flags;
	caddr_t	taddr;
	size_t	tlen;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	if (addr < seg->s_base || addr + len > seg->s_base + seg->s_size ||
		(seg->s_ops != &segxmem_ops) || (sxd->sxd_vp != vp))
			return (1);	/* Fail */

	ASSERT(sxd->sxd_prot == prot);	/* remove this later */

	/* aligned addr and length */

	blocknumber = (addr - seg->s_base) >> sxd->sxd_bshift;
	lastblock = (addr + len - 1 - seg->s_base) >> sxd->sxd_bshift;
	taddr = addr;
	tlen = sxd->sxd_bsize;
	while (blocknumber <= lastblock) {

		/*
		 * entire xmem segment mapped on mmap() call - if in the
		 * segment range(checked above), there should be a mapping
		 * therefore flags always HAT_LOAD_REMAP.
		 *
		 */
		if (hat_getpfnum(seg->s_as->a_hat, taddr) != PFN_INVALID) {
#ifdef DEBUG
			if (remap_broken)
				hat_unload(seg->s_as->a_hat, taddr,
					tlen, HAT_UNLOAD);
#endif

			/*
			 * assume the hat would leave mapping HAT_LOAD_LOCK'ed
			 * on REMAP.
			 */
			flags = HAT_LOAD | HAT_LOAD_NOCONSIST | HAT_LOAD_REMAP;
		} else {
			XMEMPRINTF(4,
			    ("segxmem_remap: taddr %p pfn inv\n",
			    (void *)taddr));
			flags = HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST;
		}

		prot |= HAT_NOSYNC;

		if (btop(sxd->sxd_bsize) == 1)
			hat_memload_array(seg->s_as->a_hat, taddr, tlen,
				(page_t **)ppa, prot, flags);
		else
			hat_memload_array(seg->s_as->a_hat, taddr, tlen, *ppa,
				prot, flags);

		blocknumber++;
		ppa++;
		taddr += tlen;
	}
	return (0);
}

/* ARGSUSED */
static int
segxmem_sync(struct seg *seg, caddr_t addr, size_t len, int attr, uint_t flags)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return (0);
}

/*
 * segxmem pages are always "in core" since the memory is locked down.
 */
/* ARGSUSED */
static size_t
segxmem_incore(struct seg *seg, caddr_t addr, size_t len, char *vec)
{

	caddr_t eo_seg;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));
#ifdef lint
	seg = seg;
#endif

	eo_seg = addr + len;
	while (addr < eo_seg) {
		/* page exist, and it's locked. */
		*vec++ = (char)0x9;
		addr += PAGESIZE;
	}
	return (len);
}

static int segxmem_advise(struct seg *seg, caddr_t addr, size_t len,
			uint_t behav)
{
#ifdef lint
	seg = seg;
	addr = addr;
	len = len;
	behav = behav;
#endif
	return (0);
}

/*
 * called from as_ctl(, MC_LOCK,)
 *
 */
/* ARGSUSED */
static int
segxmem_lockop(struct seg *seg, caddr_t addr, size_t len, int attr,
    int op, ulong_t *lockmap, size_t pos)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));
	/*
	 * for spt, as->a_paglck is never set
	 * so this routine should not be called.
	 */
	return (0);
}

static int
segxmem_unmap(struct seg *seg, caddr_t addr, size_t ssize)
{
	struct segxmem_data *sxd, *nsxd;
	struct	seg *nseg;
	caddr_t	segend, delsegend;

	XMEMPRINTF(1, ("segxmem_unmap: seg %p addr %p size %lx\n",
		(void *)seg, (void *)addr, ssize));

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as, &seg->s_as->a_lock));

	hat_unload(seg->s_as->a_hat, addr, ssize, HAT_UNLOAD_UNLOCK);
	if (addr == seg->s_base && ssize == seg->s_size) {
		seg_free(seg);
		return (0);
	}
	sxd = (struct segxmem_data *)seg->s_data;

	/* partial unmap of the segment - begin, end and middle */

	/* check for deleting at the beginning */

	if (addr == seg->s_base) {
		seg->s_base += ssize;
		seg->s_size -= ssize;
		return (0);
	}
	delsegend = addr + ssize;
	segend = seg->s_base + seg->s_size;

	/* check for deleting at the end */
	if (delsegend == segend) {
		seg->s_size -= ssize;
		return (0);
	}

	/* Now for the tough one. Make a new one at end and cut the current */

	seg->s_size = addr - seg->s_base;	/* adjust original segment */

	nseg = seg_alloc(seg->s_as, delsegend, segend - delsegend);
	if (nseg == NULL)
		panic("segxmem seg_alloc");

	nsxd = kmem_zalloc(sizeof (struct segxmem_data), KM_SLEEP);

	nsxd->sxd_vp = sxd->sxd_vp;
	nsxd->sxd_offset = sxd->sxd_offset;		/* unused */
	nsxd->sxd_bsize = sxd->sxd_bsize;
	nsxd->sxd_bshift = sxd->sxd_bshift;
	nsxd->sxd_prot = sxd->sxd_prot;
	nsxd->sxd_softlockcnt = sxd->sxd_softlockcnt;	/* ### */

	nseg->s_ops = &segxmem_ops;
	nseg->s_data = (void *)nsxd;

	return (0);
}

/*
 * Dump the pages belonging to this segxmem segment.
 */
static void
segxmem_dump(struct seg *seg)
{
	struct segxmem_data	*sxd;
	caddr_t			addr;
	int			i, j;
	uint_t			nblocks;
	pgcnt_t			npages;

	sxd = (struct segxmem_data *)seg->s_data;
	nblocks = howmany(seg->s_size, sxd->sxd_bsize);
	npages = nblocks << (sxd->sxd_bshift - PAGESHIFT);
	addr = seg->s_base;

	/* XXX figure out if we need something else here */
	for (i = 0; i < nblocks; i++) {
		pfn_t	pfn = hat_getpfnum(seg->s_as->a_hat, addr);

		for (j = 0; j < npages; j++) {
			dump_addpage(seg->s_as, addr, pfn);
			pfn++;
			addr += PAGESIZE;
		}
	}
}
/*ARGSUSED*/
static int
segxmem_setpgsz(struct seg *seg, caddr_t addr, size_t len, uint_t szc)
{
	return (ENOTSUP);
}

static int
segxmem_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	struct segxmem_data *sxd = (struct segxmem_data *)seg->s_data;

	memidp->val[0] = (uintptr_t)sxd->sxd_vp;
	memidp->val[1] = sxd->sxd_offset + (uintptr_t)(addr - seg->s_base);
	return (0);
}

/*ARGSUSED*/
static int
segxmem_pagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

#define	XMEMBUFSZ	16384
#define	XMEMPAD		128		/* larger than max len xmem string */

char		xmembuf[XMEMBUFSZ + XMEMPAD];
uint_t		xmembufi;
int		xmemlevel = 4;

void
xmemprintf(const char *fmt, ...)
{
	va_list		args;
	int		len;
	char		localbuf[XMEMPAD];
	uint_t		newval, oldxmembufi;

	va_start(args, fmt);

	len = snprintf(localbuf, INT_MAX, "%d: ", (int)CPU->cpu_id);
	len += vsnprintf(localbuf + len, INT_MAX, fmt, args);

	ASSERT(len < XMEMPAD);

	do {
		oldxmembufi = xmembufi;
		newval = oldxmembufi + len;
		if (newval > XMEMBUFSZ)
			newval = 0;
	} while (cas32(&xmembufi, oldxmembufi, newval) != oldxmembufi);

	bcopy(localbuf, xmembuf + oldxmembufi, len);

	va_end(args);
}
