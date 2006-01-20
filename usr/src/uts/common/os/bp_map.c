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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/buf.h>
#include <sys/vmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/machparam.h>
#include <vm/page.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>

#ifdef __sparc
#include <sys/cpu_module.h>
#define	BP_FLUSH(addr, size)	flush_instr_mem((void *)addr, size);
#else
#define	BP_FLUSH(addr, size)
#endif

static vmem_t *bp_map_arena;
static size_t bp_align;
static uint_t bp_devload_flags = PROT_READ | PROT_WRITE | HAT_NOSYNC;
int	bp_max_cache = 1 << 17;		/* 128K default; tunable */
int	bp_mapin_kpm_enable = 1;	/* enable default; tunable */

static void *
bp_vmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	return (vmem_xalloc(vmp, size, bp_align, 0, 0, NULL, NULL, vmflag));
}

void
bp_init(size_t align, uint_t devload_flags)
{
	bp_align = MAX(align, PAGESIZE);
	bp_devload_flags |= devload_flags;

	if (bp_align <= bp_max_cache)
		bp_map_arena = vmem_create("bp_map", NULL, 0, bp_align,
		    bp_vmem_alloc, vmem_free, heap_arena,
		    MIN(8 * bp_align, bp_max_cache), VM_SLEEP);
}

/*
 * common routine so can be called with/without VM_SLEEP
 */
void *
bp_mapin_common(struct buf *bp, int flag)
{
	struct as	*as;
	pfn_t		pfnum;
	page_t		*pp;
	page_t		**pplist;
	caddr_t		kaddr;
	caddr_t		addr;
	uintptr_t	off;
	size_t		size;
	pgcnt_t		npages;
	int		color;

	/* return if already mapped in, no pageio/physio, or physio to kas */
	if ((bp->b_flags & B_REMAPPED) ||
	    !(bp->b_flags & (B_PAGEIO | B_PHYS)) ||
	    (((bp->b_flags & (B_PAGEIO | B_PHYS)) == B_PHYS) &&
	    ((bp->b_proc == NULL) || (bp->b_proc->p_as == &kas))))
		return (bp->b_un.b_addr);

	ASSERT((bp->b_flags & (B_PAGEIO | B_PHYS)) != (B_PAGEIO | B_PHYS));

	addr = (caddr_t)bp->b_un.b_addr;
	off = (uintptr_t)addr & PAGEOFFSET;
	size = P2ROUNDUP(bp->b_bcount + off, PAGESIZE);
	npages = btop(size);

	/* Fastpath single page IO to locked memory by using kpm. */
	if ((bp->b_flags & (B_SHADOW | B_PAGEIO)) && (npages == 1) &&
	    kpm_enable && bp_mapin_kpm_enable) {
		if (bp->b_flags & B_SHADOW)
			pp = *bp->b_shadow;
		else
			pp = bp->b_pages;
		kaddr = hat_kpm_mapin(pp, NULL);
		bp->b_un.b_addr = kaddr + off;
		bp->b_flags |= B_REMAPPED;
		return (bp->b_un.b_addr);
	}

	/*
	 * Allocate kernel virtual space for remapping.
	 */
	color = bp_color(bp);
	ASSERT(color < bp_align);

	if (bp_map_arena != NULL) {
		kaddr = (caddr_t)vmem_alloc(bp_map_arena,
		    P2ROUNDUP(color + size, bp_align), flag);
		if (kaddr == NULL)
			return (NULL);
		kaddr += color;
	} else {
		kaddr = vmem_xalloc(heap_arena, size, bp_align, color,
		    0, NULL, NULL, flag);
		if (kaddr == NULL)
			return (NULL);
	}

	ASSERT(P2PHASE((uintptr_t)kaddr, bp_align) == color);

	/*
	 * Map bp into the virtual space we just allocated.
	 */
	if (bp->b_flags & B_PAGEIO) {
		pp = bp->b_pages;
		pplist = NULL;
	} else if (bp->b_flags & B_SHADOW) {
		pp = NULL;
		pplist = bp->b_shadow;
	} else {
		pp = NULL;
		pplist = NULL;
		if (bp->b_proc == NULL || (as = bp->b_proc->p_as) == NULL)
			as = &kas;
	}

	bp->b_flags |= B_REMAPPED;
	bp->b_un.b_addr = kaddr + off;

	while (npages-- != 0) {
		if (pp) {
			pfnum = pp->p_pagenum;
			pp = pp->p_next;
		} else if (pplist == NULL) {
			pfnum = hat_getpfnum(as->a_hat,
			    (caddr_t)((uintptr_t)addr & MMU_PAGEMASK));
			if (pfnum == PFN_INVALID)
				panic("bp_mapin_common: hat_getpfnum for"
				    " addr %p failed\n", (void *)addr);
			addr += PAGESIZE;
		} else {
			pfnum = (*pplist)->p_pagenum;
			pplist++;
		}

		hat_devload(kas.a_hat, kaddr, PAGESIZE, pfnum,
		    bp_devload_flags, HAT_LOAD_LOCK);

		kaddr += PAGESIZE;
	}
	return (bp->b_un.b_addr);
}

/*
 * Convert bp for pageio/physio to a kernel addressable location.
 */
void
bp_mapin(struct buf *bp)
{
	(void) bp_mapin_common(bp, VM_SLEEP);
}

/*
 * Release all the resources associated with a previous bp_mapin() call.
 */
void
bp_mapout(struct buf *bp)
{
	caddr_t		addr;
	uintptr_t	off;
	uintptr_t	base;
	uintptr_t	color;
	size_t		size;
	pgcnt_t		npages;
	page_t		*pp;

	if ((bp->b_flags & B_REMAPPED) == 0)
		return;

	addr = bp->b_un.b_addr;
	off = (uintptr_t)addr & PAGEOFFSET;
	size = P2ROUNDUP(bp->b_bcount + off, PAGESIZE);
	npages = btop(size);

	bp->b_un.b_addr = (caddr_t)off;		/* debugging aid */

	if ((bp->b_flags & (B_SHADOW | B_PAGEIO)) && (npages == 1) &&
	    kpm_enable && bp_mapin_kpm_enable) {
		if (bp->b_flags & B_SHADOW)
			pp = *bp->b_shadow;
		else
			pp = bp->b_pages;
		hat_kpm_mapout(pp, NULL, addr);
		bp->b_flags &= ~B_REMAPPED;
		return;
	}

	base = (uintptr_t)addr & MMU_PAGEMASK;
	BP_FLUSH(base, size);
	hat_unload(kas.a_hat, (void *)base, size,
	    HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK);
	if (bp_map_arena != NULL) {
		color = P2PHASE(base, bp_align);
		vmem_free(bp_map_arena, (void *)(base - color),
		    P2ROUNDUP(color + size, bp_align));
	} else
		vmem_free(heap_arena, (void *)base, size);
	bp->b_flags &= ~B_REMAPPED;
}
