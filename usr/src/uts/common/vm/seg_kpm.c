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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Kernel Physical Mapping (kpm) segment driver (segkpm).
 *
 * This driver delivers along with the hat_kpm* interfaces an alternative
 * mechanism for kernel mappings within the 64-bit Solaris operating system,
 * which allows the mapping of all physical memory into the kernel address
 * space at once. This is feasible in 64 bit kernels, e.g. for Ultrasparc II
 * and beyond processors, since the available VA range is much larger than
 * possible physical memory. Momentarily all physical memory is supported,
 * that is represented by the list of memory segments (memsegs).
 *
 * Segkpm mappings have also very low overhead and large pages are used
 * (when possible) to minimize the TLB and TSB footprint. It is also
 * extentable for other than Sparc architectures (e.g. AMD64). Main
 * advantage is the avoidance of the TLB-shootdown X-calls, which are
 * normally needed when a kernel (global) mapping has to be removed.
 *
 * First example of a kernel facility that uses the segkpm mapping scheme
 * is seg_map, where it is used as an alternative to hat_memload().
 * See also hat layer for more information about the hat_kpm* routines.
 * The kpm facilty can be turned off at boot time (e.g. /etc/system).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/bitmap.h>
#include <sys/atomic.h>
#include <sys/lgrp.h>

#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/page.h>

/*
 * Global kpm controls.
 * See also platform and mmu specific controls.
 *
 * kpm_enable -- global on/off switch for segkpm.
 * . Set by default on 64bit platforms that have kpm support.
 * . Will be disabled from platform layer if not supported.
 * . Can be disabled via /etc/system.
 *
 * kpm_smallpages -- use only regular/system pagesize for kpm mappings.
 * . Can be useful for critical debugging of kpm clients.
 * . Set to zero by default for platforms that support kpm large pages.
 *   The use of kpm large pages reduces the footprint of kpm meta data
 *   and has all the other advantages of using large pages (e.g TLB
 *   miss reduction).
 * . Set by default for platforms that don't support kpm large pages or
 *   where large pages cannot be used for other reasons (e.g. there are
 *   only few full associative TLB entries available for large pages).
 *
 * segmap_kpm -- separate on/off switch for segmap using segkpm:
 * . Set by default.
 * . Will be disabled when kpm_enable is zero.
 * . Will be disabled when MAXBSIZE != PAGESIZE.
 * . Can be disabled via /etc/system.
 *
 */
int kpm_enable = 1;
int kpm_smallpages = 0;
int segmap_kpm = 1;

/*
 * Private seg op routines.
 */
faultcode_t segkpm_fault(struct hat *hat, struct seg *seg, caddr_t addr,
			size_t len, enum fault_type type, enum seg_rw rw);
static void	segkpm_dump(struct seg *);
static void	segkpm_badop(void);
static int	segkpm_notsup(void);
static int	segkpm_capable(struct seg *, segcapability_t);

#define	SEGKPM_BADOP(t)	(t(*)())segkpm_badop
#define	SEGKPM_NOTSUP	(int(*)())segkpm_notsup

static struct seg_ops segkpm_ops = {
	SEGKPM_BADOP(int),	/* dup */
	SEGKPM_BADOP(int),	/* unmap */
	SEGKPM_BADOP(void),	/* free */
	segkpm_fault,
	SEGKPM_BADOP(int),	/* faulta */
	SEGKPM_BADOP(int),	/* setprot */
	SEGKPM_BADOP(int),	/* checkprot */
	SEGKPM_BADOP(int),	/* kluster */
	SEGKPM_BADOP(size_t),	/* swapout */
	SEGKPM_BADOP(int),	/* sync */
	SEGKPM_BADOP(size_t),	/* incore */
	SEGKPM_BADOP(int),	/* lockop */
	SEGKPM_BADOP(int),	/* getprot */
	SEGKPM_BADOP(u_offset_t), /* getoffset */
	SEGKPM_BADOP(int),	/* gettype */
	SEGKPM_BADOP(int),	/* getvp */
	SEGKPM_BADOP(int),	/* advise */
	segkpm_dump,		/* dump */
	SEGKPM_NOTSUP,		/* pagelock */
	SEGKPM_BADOP(int),	/* setpgsz */
	SEGKPM_BADOP(int),	/* getmemid */
	SEGKPM_BADOP(lgrp_mem_policy_info_t *),	/* getpolicy */
	segkpm_capable,		/* capable */
	seg_inherit_notsup	/* inherit */
};

/*
 * kpm_pgsz and kpm_pgshft are set by platform layer.
 */
size_t		kpm_pgsz;	/* kpm page size */
uint_t		kpm_pgshft;	/* kpm page shift */
u_offset_t	kpm_pgoff;	/* kpm page offset mask */
uint_t		kpmp2pshft;	/* kpm page to page shift */
pgcnt_t		kpmpnpgs;	/* how many pages per kpm page */


#ifdef	SEGKPM_SUPPORT

int
segkpm_create(struct seg *seg, void *argsp)
{
	struct segkpm_data *skd;
	struct segkpm_crargs *b = (struct segkpm_crargs *)argsp;
	ushort_t *p;
	int i, j;

	ASSERT(seg->s_as && RW_WRITE_HELD(&seg->s_as->a_lock));
	ASSERT(btokpmp(seg->s_size) >= 1 &&
	    kpmpageoff((uintptr_t)seg->s_base) == 0 &&
	    kpmpageoff((uintptr_t)seg->s_base + seg->s_size) == 0);

	skd = kmem_zalloc(sizeof (struct segkpm_data), KM_SLEEP);

	seg->s_data = (void *)skd;
	seg->s_ops = &segkpm_ops;
	skd->skd_prot = b->prot;

	/*
	 * (1) Segkpm virtual addresses are based on physical adresses.
	 * From this and in opposite to other segment drivers it is
	 * often required to allocate a page first to be able to
	 * calculate the final segkpm virtual address.
	 * (2) Page  allocation is done by calling page_create_va(),
	 * one important input argument is a virtual address (also
	 * expressed by the "va" in the function name). This function
	 * is highly optimized to select the right page for an optimal
	 * processor and platform support (e.g. virtual addressed
	 * caches (VAC), physical addressed caches, NUMA).
	 *
	 * Because of (1) the approach is to generate a faked virtual
	 * address for calling page_create_va(). In order to exploit
	 * the abilities of (2), especially to utilize the cache
	 * hierarchy (3) and to avoid VAC alias conflicts (4) the
	 * selection has to be done carefully. For each virtual color
	 * a separate counter is provided (4). The count values are
	 * used for the utilization of all cache lines (3) and are
	 * corresponding to the cache bins.
	 */
	skd->skd_nvcolors = b->nvcolors;

	p = skd->skd_va_select =
	    kmem_zalloc(NCPU * b->nvcolors * sizeof (ushort_t), KM_SLEEP);

	for (i = 0; i < NCPU; i++)
		for (j = 0; j < b->nvcolors; j++, p++)
			*p = j;

	return (0);
}

/*
 * This routine is called via a machine specific fault handling
 * routine.
 */
/* ARGSUSED */
faultcode_t
segkpm_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
	enum fault_type type, enum seg_rw rw)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	switch (type) {
	case F_INVAL:
		return (hat_kpm_fault(hat, addr));
	case F_SOFTLOCK:
	case F_SOFTUNLOCK:
		return (0);
	default:
		return (FC_NOSUPPORT);
	}
	/*NOTREACHED*/
}

#define	addr_to_vcolor(addr, vcolors) \
	((int)(((uintptr_t)(addr) & ((vcolors << PAGESHIFT) - 1)) >> PAGESHIFT))

/*
 * Create a virtual address that can be used for invocations of
 * page_create_va. Goal is to utilize the cache hierarchy (round
 * robin bins) and to select the right color for virtual indexed
 * caches. It isn't exact since we also increment the bin counter
 * when the caller uses VOP_GETPAGE and gets a hit in the page
 * cache, but we keep the bins turning for cache distribution
 * (see also segkpm_create block comment).
 */
caddr_t
segkpm_create_va(u_offset_t off)
{
	int vcolor;
	ushort_t *p;
	struct segkpm_data *skd = (struct segkpm_data *)segkpm->s_data;
	int nvcolors = skd->skd_nvcolors;
	caddr_t	va;

	vcolor = (nvcolors > 1) ? addr_to_vcolor(off, nvcolors) : 0;
	p = &skd->skd_va_select[(CPU->cpu_id * nvcolors) + vcolor];
	va = (caddr_t)ptob(*p);

	atomic_add_16(p, nvcolors);

	return (va);
}

/*
 * Unload mapping if the instance has an active kpm mapping.
 */
void
segkpm_mapout_validkpme(struct kpme *kpme)
{
	caddr_t vaddr;
	page_t *pp;

retry:
	if ((pp = kpme->kpe_page) == NULL) {
		return;
	}

	if (page_lock(pp, SE_SHARED, (kmutex_t *)NULL, P_RECLAIM) == 0)
		goto retry;

	/*
	 * Check if segkpm mapping is not unloaded in the meantime
	 */
	if (kpme->kpe_page == NULL) {
		page_unlock(pp);
		return;
	}

	vaddr = hat_kpm_page2va(pp, 1);
	hat_kpm_mapout(pp, kpme, vaddr);
	page_unlock(pp);
}

static void
segkpm_badop()
{
	panic("segkpm_badop");
}

#else	/* SEGKPM_SUPPORT */

/* segkpm stubs */

/*ARGSUSED*/
int segkpm_create(struct seg *seg, void *argsp) { return (0); }

/* ARGSUSED */
faultcode_t
segkpm_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
	enum fault_type type, enum seg_rw rw)
{
	return ((faultcode_t)0);
}

/* ARGSUSED */
caddr_t segkpm_create_va(u_offset_t off) { return (NULL); }

/* ARGSUSED */
void segkpm_mapout_validkpme(struct kpme *kpme) {}

static void
segkpm_badop() {}

#endif	/* SEGKPM_SUPPORT */

static int
segkpm_notsup()
{
	return (ENOTSUP);
}

/*
 * segkpm pages are not dumped, so we just return
 */
/*ARGSUSED*/
static void
segkpm_dump(struct seg *seg)
{}

/*
 * We claim to have no special capabilities.
 */
/*ARGSUSED*/
static int
segkpm_capable(struct seg *seg, segcapability_t capability)
{
	return (0);
}
