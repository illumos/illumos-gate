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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "umem.h"

#include <sys/vmem_impl_user.h>
#include <umem_impl.h>

#include <alloca.h>
#include <libproc.h>
#include <stdio.h>
#include <string.h>
#include <sys/stack.h>

#include "leaky_impl.h"
#include "misc.h"
#include "proc_kludges.h"

#include "umem_pagesize.h"

/*
 * This file defines the libumem target for ../genunix/leaky.c.
 *
 * See ../genunix/leaky_impl.h for the target interface definition.
 */

/*
 * leaky_subr_dump_start()/_end() depend on the ordering of TYPE_VMEM,
 * TYPE_MMAP and TYPE_SBRK.
 */
#define	TYPE_MMAP	0		/* lkb_data is the size */
#define	TYPE_SBRK	1		/* lkb_data is the size */
#define	TYPE_VMEM	2		/* lkb_data is the vmem_seg's size */
#define	TYPE_CACHE	3		/* lkb_cid is the bufctl's cache */
#define	TYPE_UMEM	4		/* lkb_cid is the bufctl's cache */

#define	LKM_CTL_BUFCTL	0	/* normal allocation, PTR is bufctl */
#define	LKM_CTL_VMSEG	1	/* oversize allocation, PTR is vmem_seg_t */
#define	LKM_CTL_MEMORY	2	/* non-umem mmap or brk, PTR is region start */
#define	LKM_CTL_CACHE	3	/* normal alloc, non-debug, PTR is cache */
#define	LKM_CTL_MASK	3L

/*
 * create a lkm_bufctl from a pointer and a type
 */
#define	LKM_CTL(ptr, type)	(LKM_CTLPTR(ptr) | (type))
#define	LKM_CTLPTR(ctl)		((uintptr_t)(ctl) & ~(LKM_CTL_MASK))
#define	LKM_CTLTYPE(ctl)	((uintptr_t)(ctl) &  (LKM_CTL_MASK))

static uintptr_t leak_brkbase;
static uintptr_t leak_brksize;

#define	LEAKY_INBRK(ptr) \
	(((uintptr_t)(ptr) - leak_brkbase) < leak_brksize)

typedef struct leaky_seg_info {
	uintptr_t ls_start;
	uintptr_t ls_end;
} leaky_seg_info_t;

typedef struct leaky_maps {
	leaky_seg_info_t	*lm_segs;
	uintptr_t		lm_seg_count;
	uintptr_t		lm_seg_max;

	pstatus_t		*lm_pstatus;

	leak_mtab_t		**lm_lmp;
} leaky_maps_t;

/*ARGSUSED*/
static int
leaky_mtab(uintptr_t addr, const umem_bufctl_audit_t *bcp, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = (*lmp)++;

	lm->lkm_base = (uintptr_t)bcp->bc_addr;
	lm->lkm_bufctl = LKM_CTL(addr, LKM_CTL_BUFCTL);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_mtab_addr(uintptr_t addr, void *ignored, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = (*lmp)++;

	lm->lkm_base = addr;

	return (WALK_NEXT);
}

static int
leaky_seg(uintptr_t addr, const vmem_seg_t *seg, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = (*lmp)++;

	lm->lkm_base = seg->vs_start;
	lm->lkm_limit = seg->vs_end;
	lm->lkm_bufctl = LKM_CTL(addr, LKM_CTL_VMSEG);
	return (WALK_NEXT);
}

static int
leaky_vmem(uintptr_t addr, const vmem_t *vmem, leak_mtab_t **lmp)
{
	if (strcmp(vmem->vm_name, "umem_oversize") != 0 &&
	    strcmp(vmem->vm_name, "umem_memalign") != 0)
		return (WALK_NEXT);

	if (mdb_pwalk("vmem_alloc", (mdb_walk_cb_t)leaky_seg, lmp, addr) == -1)
		mdb_warn("can't walk vmem_alloc for %s (%p)", vmem->vm_name,
		    addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_estimate_vmem(uintptr_t addr, const vmem_t *vmem, size_t *est)
{
	if (strcmp(vmem->vm_name, "umem_oversize") != 0 &&
	    strcmp(vmem->vm_name, "umem_memalign") != 0)
		return (WALK_NEXT);

	*est += (int)(vmem->vm_kstat.vk_alloc - vmem->vm_kstat.vk_free);

	return (WALK_NEXT);
}

static int
leaky_seg_cmp(const void *l, const void *r)
{
	const leaky_seg_info_t *lhs = (const leaky_seg_info_t *)l;
	const leaky_seg_info_t *rhs = (const leaky_seg_info_t *)r;

	if (lhs->ls_start < rhs->ls_start)
		return (-1);
	if (lhs->ls_start > rhs->ls_start)
		return (1);

	return (0);
}

static ssize_t
leaky_seg_search(uintptr_t addr, leaky_seg_info_t *listp, unsigned count)
{
	ssize_t left = 0, right = count - 1, guess;

	while (right >= left) {
		guess = (right + left) >> 1;

		if (addr < listp[guess].ls_start) {
			right = guess - 1;
			continue;
		}

		if (addr >= listp[guess].ls_end) {
			left = guess + 1;
			continue;
		}

		return (guess);
	}

	return (-1);
}

/*ARGSUSED*/
static int
leaky_count(uintptr_t addr, void *unused, size_t *total)
{
	++*total;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_read_segs(uintptr_t addr, const vmem_seg_t *seg, leaky_maps_t *lmp)
{
	leaky_seg_info_t *my_si = lmp->lm_segs + lmp->lm_seg_count;

	if (seg->vs_start == seg->vs_end && seg->vs_start == 0)
		return (WALK_NEXT);

	if (lmp->lm_seg_count++ >= lmp->lm_seg_max)
		return (WALK_ERR);

	my_si->ls_start = seg->vs_start;
	my_si->ls_end = seg->vs_end;

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
leaky_process_anon_mappings(uintptr_t ignored, const prmap_t *pmp,
    leaky_maps_t *lmp)
{
	uintptr_t start = pmp->pr_vaddr;
	uintptr_t end = pmp->pr_vaddr + pmp->pr_size;

	leak_mtab_t *lm;
	pstatus_t *Psp = lmp->lm_pstatus;

	uintptr_t brk_start = Psp->pr_brkbase;
	uintptr_t brk_end = Psp->pr_brkbase + Psp->pr_brksize;

	int has_brk = 0;
	int in_vmem = 0;

	/*
	 * This checks if there is any overlap between the segment and the brk.
	 */
	if (end > brk_start && start < brk_end)
		has_brk = 1;

	if (leaky_seg_search(start, lmp->lm_segs, lmp->lm_seg_count) != -1)
		in_vmem = 1;

	/*
	 * We only want anonymous, mmaped memory.  That means:
	 *
	 * 1. Must be read-write
	 * 2. Cannot be shared
	 * 3. Cannot have backing
	 * 4. Cannot be in the brk
	 * 5. Cannot be part of the vmem heap.
	 */
	if ((pmp->pr_mflags & (MA_READ | MA_WRITE)) == (MA_READ | MA_WRITE) &&
	    (pmp->pr_mflags & MA_SHARED) == 0 &&
	    (pmp->pr_mapname[0] == 0) &&
	    !has_brk &&
	    !in_vmem) {
		dprintf(("mmaped region: [%p, %p)\n", start, end));
		lm = (*lmp->lm_lmp)++;
		lm->lkm_base = start;
		lm->lkm_limit = end;
		lm->lkm_bufctl = LKM_CTL(pmp->pr_vaddr, LKM_CTL_MEMORY);
	}

	return (WALK_NEXT);
}

static void
leaky_handle_sbrk(leaky_maps_t *lmp)
{
	uintptr_t brkbase = lmp->lm_pstatus->pr_brkbase;
	uintptr_t brkend = brkbase + lmp->lm_pstatus->pr_brksize;

	leak_mtab_t *lm;

	leaky_seg_info_t *segs = lmp->lm_segs;

	int x, first = -1, last = -1;

	dprintf(("brk: [%p, %p)\n", brkbase, brkend));

	for (x = 0; x < lmp->lm_seg_count; x++) {
		if (segs[x].ls_start >= brkbase && segs[x].ls_end <= brkend) {
			if (first == -1)
				first = x;
			last = x;
		}
	}

	if (brkbase == brkend) {
		dprintf(("empty brk -- do nothing\n"));
	} else if (first == -1) {
		dprintf(("adding [%p, %p) whole brk\n", brkbase, brkend));

		lm = (*lmp->lm_lmp)++;
		lm->lkm_base = brkbase;
		lm->lkm_limit = brkend;
		lm->lkm_bufctl = LKM_CTL(brkbase, LKM_CTL_MEMORY);
	} else {
		uintptr_t curbrk = P2ROUNDUP(brkbase, umem_pagesize);

		if (curbrk != segs[first].ls_start) {
			dprintf(("adding [%p, %p) in brk, before first seg\n",
			    brkbase, segs[first].ls_start));

			lm = (*lmp->lm_lmp)++;
			lm->lkm_base = brkbase;
			lm->lkm_limit = segs[first].ls_start;
			lm->lkm_bufctl = LKM_CTL(brkbase, LKM_CTL_MEMORY);

			curbrk = segs[first].ls_start;

		} else if (curbrk != brkbase) {
			dprintf(("ignore [%p, %p) -- realign\n", brkbase,
			    curbrk));
		}

		for (x = first; x <= last; x++) {
			if (curbrk < segs[x].ls_start) {
				dprintf(("adding [%p, %p) in brk\n", curbrk,
				    segs[x].ls_start));

				lm = (*lmp->lm_lmp)++;
				lm->lkm_base = curbrk;
				lm->lkm_limit = segs[x].ls_start;
				lm->lkm_bufctl = LKM_CTL(curbrk,
				    LKM_CTL_MEMORY);
			}
			curbrk = segs[x].ls_end;
		}

		if (curbrk < brkend) {
			dprintf(("adding [%p, %p) in brk, after last seg\n",
			    curbrk, brkend));

			lm = (*lmp->lm_lmp)++;
			lm->lkm_base = curbrk;
			lm->lkm_limit = brkend;
			lm->lkm_bufctl = LKM_CTL(curbrk, LKM_CTL_MEMORY);
		}
	}
}

static int
leaky_handle_anon_mappings(leak_mtab_t **lmp)
{
	leaky_maps_t		lm;

	vmem_t *heap_arena;
	vmem_t *vm_next;
	vmem_t *heap_top;
	vmem_t vmem;

	pstatus_t Ps;

	if (mdb_get_xdata("pstatus", &Ps, sizeof (Ps)) == -1) {
		mdb_warn("couldn't read pstatus xdata");
		return (DCMD_ERR);
	}
	lm.lm_pstatus = &Ps;

	leak_brkbase = Ps.pr_brkbase;
	leak_brksize = Ps.pr_brksize;

	if (umem_readvar(&heap_arena, "heap_arena") == -1) {
		mdb_warn("couldn't read heap_arena");
		return (DCMD_ERR);
	}

	if (heap_arena == NULL) {
		mdb_warn("heap_arena is NULL.\n");
		return (DCMD_ERR);
	}

	for (vm_next = heap_arena; vm_next != NULL; vm_next = vmem.vm_source) {
		if (mdb_vread(&vmem, sizeof (vmem), (uintptr_t)vm_next) == -1) {
			mdb_warn("couldn't read vmem at %p", vm_next);
			return (DCMD_ERR);
		}
		heap_top = vm_next;
	}

	lm.lm_seg_count = 0;
	lm.lm_seg_max = 0;

	if (mdb_pwalk("vmem_span", (mdb_walk_cb_t)leaky_count,
	    &lm.lm_seg_max, (uintptr_t)heap_top) == -1) {
		mdb_warn("couldn't walk vmem_span for vmem %p", heap_top);
		return (DCMD_ERR);
	}
	lm.lm_segs = mdb_alloc(lm.lm_seg_max * sizeof (*lm.lm_segs),
	    UM_SLEEP | UM_GC);

	if (mdb_pwalk("vmem_span", (mdb_walk_cb_t)leaky_read_segs, &lm,
	    (uintptr_t)heap_top) == -1) {
		mdb_warn("couldn't walk vmem_span for vmem %p",
		    heap_top);
		return (DCMD_ERR);
	}

	if (lm.lm_seg_count > lm.lm_seg_max) {
		mdb_warn("segment list for vmem %p grew\n", heap_top);
		return (DCMD_ERR);
	}

	qsort(lm.lm_segs, lm.lm_seg_count, sizeof (*lm.lm_segs), leaky_seg_cmp);

	lm.lm_lmp = lmp;

	prockludge_add_walkers();

	if (mdb_walk(KLUDGE_MAPWALK_NAME,
	    (mdb_walk_cb_t)leaky_process_anon_mappings, &lm) == -1) {
		mdb_warn("Couldn't walk "KLUDGE_MAPWALK_NAME);
		prockludge_remove_walkers();
		return (DCMD_ERR);
	}

	prockludge_remove_walkers();
	leaky_handle_sbrk(&lm);

	return (DCMD_OK);
}

static int
leaky_interested(const umem_cache_t *c)
{
	vmem_t vmem;

	if (mdb_vread(&vmem, sizeof (vmem), (uintptr_t)c->cache_arena) == -1) {
		mdb_warn("cannot read arena %p for cache '%s'",
		    (uintptr_t)c->cache_arena, c->cache_name);
		return (0);
	}

	/*
	 * If this cache isn't allocating from either the umem_default or
	 * umem_firewall vmem arena, we're not interested.
	 */
	if (strcmp(vmem.vm_name, "umem_default") != 0 &&
	    strcmp(vmem.vm_name, "umem_firewall") != 0) {
		dprintf(("Skipping cache '%s' with arena '%s'\n",
		    c->cache_name, vmem.vm_name));
		return (0);
	}

	return (1);
}

/*ARGSUSED*/
static int
leaky_estimate(uintptr_t addr, const umem_cache_t *c, size_t *est)
{
	if (!leaky_interested(c))
		return (WALK_NEXT);

	*est += umem_estimate_allocated(addr, c);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_cache(uintptr_t addr, const umem_cache_t *c, leak_mtab_t **lmp)
{
	leak_mtab_t *lm = *lmp;
	mdb_walk_cb_t cb;
	const char *walk;
	int audit = (c->cache_flags & UMF_AUDIT);

	if (!leaky_interested(c))
		return (WALK_NEXT);

	if (audit) {
		walk = "bufctl";
		cb = (mdb_walk_cb_t)leaky_mtab;
	} else {
		walk = "umem";
		cb = (mdb_walk_cb_t)leaky_mtab_addr;
	}
	if (mdb_pwalk(walk, cb, lmp, addr) == -1) {
		mdb_warn("can't walk umem for cache %p (%s)", addr,
		    c->cache_name);
		return (WALK_DONE);
	}

	for (; lm < *lmp; lm++) {
		lm->lkm_limit = lm->lkm_base + c->cache_bufsize;
		if (!audit)
			lm->lkm_bufctl = LKM_CTL(addr, LKM_CTL_CACHE);
	}
	return (WALK_NEXT);
}

static char *map_head = "%-?s  %?s  %-10s used reason\n";
static char *map_fmt  = "[%?p,%?p) %-10s ";
#define	BACKING_LEN 10 /* must match the third field's width in map_fmt */

static void
leaky_mappings_header(void)
{
	dprintf((map_head, "mapping", "", "backing"));
}

/* ARGSUSED */
static int
leaky_grep_mappings(uintptr_t ignored, const prmap_t *pmp,
    const pstatus_t *Psp)
{
	const char *map_libname_ptr;
	char db_mp_name[BACKING_LEN+1];

	map_libname_ptr = strrchr(pmp->pr_mapname, '/');
	if (map_libname_ptr != NULL)
		map_libname_ptr++;
	else
		map_libname_ptr = pmp->pr_mapname;

	strlcpy(db_mp_name, map_libname_ptr, sizeof (db_mp_name));

	dprintf((map_fmt, pmp->pr_vaddr, (char *)pmp->pr_vaddr + pmp->pr_size,
	    db_mp_name));

#define	USE(rsn)	dprintf_cont(("yes  %s\n", (rsn)))
#define	IGNORE(rsn)	dprintf_cont(("no   %s\n", (rsn)))

	if (!(pmp->pr_mflags & MA_WRITE) || !(pmp->pr_mflags & MA_READ)) {
		IGNORE("read-only");
	} else if (pmp->pr_vaddr <= Psp->pr_brkbase &&
	    pmp->pr_vaddr + pmp->pr_size > Psp->pr_brkbase) {
		USE("bss");			/* grab up to brkbase */
		leaky_grep(pmp->pr_vaddr, Psp->pr_brkbase - pmp->pr_vaddr);
	} else if (pmp->pr_vaddr >= Psp->pr_brkbase &&
	    pmp->pr_vaddr < Psp->pr_brkbase + Psp->pr_brksize) {
		IGNORE("in brk");
	} else if (pmp->pr_vaddr == Psp->pr_stkbase &&
	    pmp->pr_size == Psp->pr_stksize) {
		IGNORE("stack");
	} else if (0 == strcmp(map_libname_ptr, "a.out")) {
		USE("a.out data");
		leaky_grep(pmp->pr_vaddr, pmp->pr_size);
	} else if (0 == strncmp(map_libname_ptr, "libumem.so", 10)) {
		IGNORE("part of umem");
	} else if (pmp->pr_mapname[0] != 0) {
		USE("lib data");		/* library data/bss */
		leaky_grep(pmp->pr_vaddr, pmp->pr_size);
	} else if ((pmp->pr_mflags & MA_ANON) && pmp->pr_mapname[0] == 0) {
		IGNORE("anon");
	} else {
		IGNORE("");		/* default to ignoring */
	}

#undef	USE
#undef	IGNORE

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
leaky_mark_lwp(void *ignored, const lwpstatus_t *lwp)
{
	leaky_mark_ptr(lwp->pr_reg[R_SP] + STACK_BIAS);
	return (0);
}

/*ARGSUSED*/
static int
leaky_process_lwp(void *ignored, const lwpstatus_t *lwp)
{
	const uintptr_t *regs = (const uintptr_t *)&lwp->pr_reg;
	int i;
	uintptr_t sp;
	uintptr_t addr;
	size_t size;

	for (i = 0; i < R_SP; i++)
		leaky_grep_ptr(regs[i]);

	sp = regs[i++] + STACK_BIAS;
	if (leaky_lookup_marked(sp, &addr, &size))
		leaky_grep(sp, size - (sp - addr));

	for (; i < NPRGREG; i++)
		leaky_grep_ptr(regs[i]);

	return (0);
}

/*
 * Handles processing various proc-related things:
 * 1. calls leaky_process_lwp on each the LWP
 * 2. leaky_greps the bss/data of libraries and a.out, and the a.out stack.
 */
static int
leaky_process_proc(void)
{
	pstatus_t Ps;
	struct ps_prochandle *Pr;

	if (mdb_get_xdata("pstatus", &Ps, sizeof (Ps)) == -1) {
		mdb_warn("couldn't read pstatus xdata");
		return (DCMD_ERR);
	}

	dprintf(("pstatus says:\n"));
	dprintf(("\tbrk: base %p size %p\n",
	    Ps.pr_brkbase, Ps.pr_brksize));
	dprintf(("\tstk: base %p size %p\n",
	    Ps.pr_stkbase, Ps.pr_stksize));

	if (mdb_get_xdata("pshandle", &Pr, sizeof (Pr)) == -1) {
		mdb_warn("couldn't read pshandle xdata");
		return (DCMD_ERR);
	}

	if (Plwp_iter(Pr, leaky_mark_lwp, NULL) != 0) {
		mdb_warn("findleaks: Failed to iterate lwps\n");
		return (DCMD_ERR);
	}

	if (Plwp_iter(Pr, leaky_process_lwp, NULL) != 0) {
		mdb_warn("findleaks: Failed to iterate lwps\n");
		return (DCMD_ERR);
	}

	prockludge_add_walkers();

	leaky_mappings_header();

	if (mdb_walk(KLUDGE_MAPWALK_NAME, (mdb_walk_cb_t)leaky_grep_mappings,
	    &Ps) == -1) {
		mdb_warn("Couldn't walk "KLUDGE_MAPWALK_NAME);
		prockludge_remove_walkers();
		return (-1);
	}

	prockludge_remove_walkers();

	return (0);
}

static void
leaky_subr_caller(const uintptr_t *stack, uint_t depth, char *buf,
    uintptr_t *pcp)
{
	int i;
	GElf_Sym sym;
	uintptr_t pc = 0;

	buf[0] = 0;

	for (i = 0; i < depth; i++) {
		pc = stack[i];

		if (mdb_lookup_by_addr(pc,
		    MDB_SYM_FUZZY, buf, MDB_SYM_NAMLEN, &sym) == -1)
			continue;
		if (strncmp(buf, "libumem.so", 10) == 0)
			continue;

		*pcp = pc;
		return;
	}

	/*
	 * We're only here if the entire call chain is in libumem.so;
	 * this shouldn't happen, but we'll just use the last caller.
	 */
	*pcp = pc;
}

int
leaky_subr_bufctl_cmp(const leak_bufctl_t *lhs, const leak_bufctl_t *rhs)
{
	char lbuf[MDB_SYM_NAMLEN], rbuf[MDB_SYM_NAMLEN];
	uintptr_t lcaller, rcaller;
	int rval;

	leaky_subr_caller(lhs->lkb_stack, lhs->lkb_depth, lbuf, &lcaller);
	leaky_subr_caller(rhs->lkb_stack, lhs->lkb_depth, rbuf, &rcaller);

	if (rval = strcmp(lbuf, rbuf))
		return (rval);

	if (lcaller < rcaller)
		return (-1);

	if (lcaller > rcaller)
		return (1);

	if (lhs->lkb_data < rhs->lkb_data)
		return (-1);

	if (lhs->lkb_data > rhs->lkb_data)
		return (1);

	return (0);
}

/*ARGSUSED*/
int
leaky_subr_estimate(size_t *estp)
{
	if (umem_ready == 0) {
		mdb_warn(
		    "findleaks: umem is not loaded in the address space\n");
		return (DCMD_ERR);
	}

	if (umem_ready == UMEM_READY_INIT_FAILED) {
		mdb_warn("findleaks: umem initialization failed -- no "
		    "possible leaks.\n");
		return (DCMD_ERR);
	}

	if (umem_ready != UMEM_READY) {
		mdb_warn("findleaks: No allocations have occured -- no "
		    "possible leaks.\n");
		return (DCMD_ERR);
	}

	if (mdb_walk("umem_cache", (mdb_walk_cb_t)leaky_estimate, estp) == -1) {
		mdb_warn("couldn't walk 'umem_cache'");
		return (DCMD_ERR);
	}

	if (mdb_walk("vmem", (mdb_walk_cb_t)leaky_estimate_vmem, estp) == -1) {
		mdb_warn("couldn't walk 'vmem'");
		return (DCMD_ERR);
	}

	if (*estp == 0) {
		mdb_warn("findleaks: No allocated buffers found.\n");
		return (DCMD_ERR);
	}

	prockludge_add_walkers();

	if (mdb_walk(KLUDGE_MAPWALK_NAME, (mdb_walk_cb_t)leaky_count,
	    estp) == -1) {
		mdb_warn("Couldn't walk "KLUDGE_MAPWALK_NAME);
		prockludge_remove_walkers();
		return (DCMD_ERR);
	}

	prockludge_remove_walkers();

	return (DCMD_OK);
}

int
leaky_subr_fill(leak_mtab_t **lmpp)
{
	if (leaky_handle_anon_mappings(lmpp) != DCMD_OK) {
		mdb_warn("unable to process mappings\n");
		return (DCMD_ERR);
	}

	if (mdb_walk("vmem", (mdb_walk_cb_t)leaky_vmem, lmpp) == -1) {
		mdb_warn("couldn't walk 'vmem'");
		return (DCMD_ERR);
	}

	if (mdb_walk("umem_cache", (mdb_walk_cb_t)leaky_cache, lmpp) == -1) {
		mdb_warn("couldn't walk 'umem_cache'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
leaky_subr_run(void)
{
	if (leaky_process_proc() == DCMD_ERR) {
		mdb_warn("failed to process proc");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

void
leaky_subr_add_leak(leak_mtab_t *lmp)
{
	uintptr_t addr = LKM_CTLPTR(lmp->lkm_bufctl);
	uint_t depth;

	vmem_seg_t vs;
	umem_bufctl_audit_t *bcp;
	UMEM_LOCAL_BUFCTL_AUDIT(&bcp);

	switch (LKM_CTLTYPE(lmp->lkm_bufctl)) {
	case LKM_CTL_BUFCTL:
		if (mdb_vread(bcp, UMEM_BUFCTL_AUDIT_SIZE, addr) == -1) {
			mdb_warn("couldn't read leaked bufctl at addr %p",
			    addr);
			return;
		}

		depth = MIN(bcp->bc_depth, umem_stack_depth);

		/*
		 * The top of the stack will be in umem_cache_alloc().
		 * Since the offset in umem_cache_alloc() isn't interesting
		 * we skip that frame for the purposes of uniquifying stacks.
		 *
		 * Also, we use the cache pointer as the leaks's cid, to
		 * prevent the coalescing of leaks from different caches.
		 */
		if (depth > 0)
			depth--;
		leaky_add_leak(TYPE_UMEM, addr, (uintptr_t)bcp->bc_addr,
		    bcp->bc_timestamp, bcp->bc_stack + 1, depth,
		    (uintptr_t)bcp->bc_cache, (uintptr_t)bcp->bc_cache);
		break;
	case LKM_CTL_VMSEG:
		if (mdb_vread(&vs, sizeof (vs), addr) == -1) {
			mdb_warn("couldn't read leaked vmem_seg at addr %p",
			    addr);
			return;
		}
		depth = MIN(vs.vs_depth, VMEM_STACK_DEPTH);

		leaky_add_leak(TYPE_VMEM, addr, vs.vs_start, vs.vs_timestamp,
		    vs.vs_stack, depth, 0, (vs.vs_end - vs.vs_start));
		break;
	case LKM_CTL_MEMORY:
		if (LEAKY_INBRK(addr))
			leaky_add_leak(TYPE_SBRK, addr, addr, 0, NULL, 0, 0,
			    lmp->lkm_limit - addr);
		else
			leaky_add_leak(TYPE_MMAP, addr, addr, 0, NULL, 0, 0,
			    lmp->lkm_limit - addr);
		break;
	case LKM_CTL_CACHE:
		leaky_add_leak(TYPE_CACHE, lmp->lkm_base, lmp->lkm_base, 0,
		    NULL, 0, addr, addr);
		break;
	default:
		mdb_warn("internal error:  invalid leak_bufctl_t\n");
		break;
	}
}

static int lk_vmem_seen;
static int lk_cache_seen;
static int lk_umem_seen;
static size_t lk_ttl;
static size_t lk_bytes;

void
leaky_subr_dump_start(int type)
{
	switch (type) {
	case TYPE_MMAP:
		lk_vmem_seen = 0;
		break;

	case TYPE_SBRK:
	case TYPE_VMEM:
		return;			/* don't zero counts */

	case TYPE_CACHE:
		lk_cache_seen = 0;
		break;

	case TYPE_UMEM:
		lk_umem_seen = 0;
		break;

	default:
		break;
	}

	lk_ttl = 0;
	lk_bytes = 0;
}

void
leaky_subr_dump(const leak_bufctl_t *lkb, int verbose)
{
	const leak_bufctl_t *cur;
	umem_cache_t cache;
	size_t min, max, size;
	char sz[30];
	char c[MDB_SYM_NAMLEN];
	uintptr_t caller;
	const char *nm, *nm_lc;
	uint8_t type = lkb->lkb_type;

	if (verbose) {
		lk_ttl = 0;
		lk_bytes = 0;
	} else if (!lk_vmem_seen && (type == TYPE_VMEM || type == TYPE_MMAP ||
	    type == TYPE_SBRK)) {
		lk_vmem_seen = 1;
		mdb_printf("%-16s %7s %?s %s\n",
		    "BYTES", "LEAKED", "VMEM_SEG", "CALLER");
	}

	switch (lkb->lkb_type) {
	case TYPE_MMAP:
	case TYPE_SBRK:
		nm = (lkb->lkb_type == TYPE_MMAP) ? "MMAP" : "SBRK";
		nm_lc = (lkb->lkb_type == TYPE_MMAP) ? "mmap(2)" : "sbrk(2)";

		for (; lkb != NULL; lkb = lkb->lkb_next) {
			if (!verbose)
				mdb_printf("%-16d %7d %?p %s\n", lkb->lkb_data,
				    lkb->lkb_dups + 1, lkb->lkb_addr, nm);
			else
				mdb_printf("%s leak: [%p, %p), %ld bytes\n",
				    nm_lc, lkb->lkb_addr,
				    lkb->lkb_addr + lkb->lkb_data,
				    lkb->lkb_data);
			lk_ttl++;
			lk_bytes += lkb->lkb_data;
		}
		return;

	case TYPE_VMEM:
		min = max = lkb->lkb_data;

		for (cur = lkb; cur != NULL; cur = cur->lkb_next) {
			size = cur->lkb_data;

			if (size < min)
				min = size;
			if (size > max)
				max = size;

			lk_ttl++;
			lk_bytes += size;
		}

		if (min == max)
			(void) mdb_snprintf(sz, sizeof (sz), "%ld", min);
		else
			(void) mdb_snprintf(sz, sizeof (sz), "%ld-%ld",
			    min, max);

		if (!verbose) {
			leaky_subr_caller(lkb->lkb_stack, lkb->lkb_depth,
			    c, &caller);

			mdb_printf("%-16s %7d %?p %a\n", sz, lkb->lkb_dups + 1,
			    lkb->lkb_addr, caller);
		} else {
			mdb_arg_t v;

			if (lk_ttl == 1)
				mdb_printf("umem_oversize leak: 1 vmem_seg, "
				    "%ld bytes\n", lk_bytes);
			else
				mdb_printf("umem_oversize leak: %d vmem_segs, "
				    "%s bytes each, %ld bytes total\n",
				    lk_ttl, sz, lk_bytes);

			v.a_type = MDB_TYPE_STRING;
			v.a_un.a_str = "-v";

			if (mdb_call_dcmd("vmem_seg", lkb->lkb_addr,
			    DCMD_ADDRSPEC, 1, &v) == -1) {
				mdb_warn("'%p::vmem_seg -v' failed",
				    lkb->lkb_addr);
			}
		}
		return;

	case TYPE_CACHE:
		if (!lk_cache_seen) {
			lk_cache_seen = 1;
			if (lk_vmem_seen)
				mdb_printf("\n");
			mdb_printf("%-?s %7s %?s %s\n",
			    "CACHE", "LEAKED", "BUFFER", "CALLER");
		}

		if (mdb_vread(&cache, sizeof (cache), lkb->lkb_data) == -1) {
			/*
			 * This _really_ shouldn't happen; we shouldn't
			 * have been able to get this far if this
			 * cache wasn't readable.
			 */
			mdb_warn("can't read cache %p for leaked "
			    "buffer %p", lkb->lkb_data, lkb->lkb_addr);
			return;
		}

		lk_ttl += lkb->lkb_dups + 1;
		lk_bytes += (lkb->lkb_dups + 1) * cache.cache_bufsize;

		caller = (lkb->lkb_depth == 0) ? 0 : lkb->lkb_stack[0];
		if (caller != 0) {
			(void) mdb_snprintf(c, sizeof (c), "%a", caller);
		} else {
			(void) mdb_snprintf(c, sizeof (c), "%s",
			    (verbose) ? "" : "?");
		}

		if (!verbose) {
			mdb_printf("%0?p %7d %0?p %s\n", lkb->lkb_cid,
			    lkb->lkb_dups + 1, lkb->lkb_addr, c);
		} else {
			if (lk_ttl == 1)
				mdb_printf("%s leak: 1 buffer, %ld bytes,\n",
				    cache.cache_name, lk_bytes);
			else
				mdb_printf("%s leak: %d buffers, "
				    "%ld bytes each, %ld bytes total,\n",
				    cache.cache_name, lk_ttl,
				    cache.cache_bufsize, lk_bytes);
			mdb_printf("    %s%s%ssample addr %p\n",
			    (caller == 0) ? "" : "caller ", c,
			    (caller == 0) ? "" : ", ", lkb->lkb_addr);
		}
		return;

	case TYPE_UMEM:
		if (!lk_umem_seen) {
			lk_umem_seen = 1;
			if (lk_vmem_seen || lk_cache_seen)
				mdb_printf("\n");
			mdb_printf("%-?s %7s %?s %s\n",
			    "CACHE", "LEAKED", "BUFCTL", "CALLER");
		}
		if (mdb_vread(&cache, sizeof (cache), lkb->lkb_data) == -1) {
			/*
			 * This _really_ shouldn't happen; we shouldn't
			 * have been able to get this far if this
			 * cache wasn't readable.
			 */
			mdb_warn("can't read cache %p for leaked "
			    "bufctl %p", lkb->lkb_data, lkb->lkb_addr);
			return;
		}

		lk_ttl += lkb->lkb_dups + 1;
		lk_bytes += (lkb->lkb_dups + 1) * cache.cache_bufsize;

		if (!verbose) {
			leaky_subr_caller(lkb->lkb_stack, lkb->lkb_depth, c,
			    &caller);

			mdb_printf("%0?p %7d %0?p %a\n", lkb->lkb_data,
			    lkb->lkb_dups + 1, lkb->lkb_addr, caller);
		} else {
			mdb_arg_t v;

			if (lk_ttl == 1)
				mdb_printf("%s leak: 1 buffer, %ld bytes\n",
				    cache.cache_name, lk_bytes);
			else
				mdb_printf("%s leak: %d buffers, "
				    "%ld bytes each, %ld bytes total\n",
				    cache.cache_name, lk_ttl,
				    cache.cache_bufsize, lk_bytes);

			v.a_type = MDB_TYPE_STRING;
			v.a_un.a_str = "-v";

			if (mdb_call_dcmd("bufctl", lkb->lkb_addr,
			    DCMD_ADDRSPEC, 1, &v) == -1) {
				mdb_warn("'%p::bufctl -v' failed",
				    lkb->lkb_addr);
			}
		}
		return;

	default:
		return;
	}
}

void
leaky_subr_dump_end(int type)
{
	int i;
	int width;
	const char *leak;

	switch (type) {
	case TYPE_VMEM:
		if (!lk_vmem_seen)
			return;

		width = 16;
		leak = "oversized leak";
		break;

	case TYPE_CACHE:
		if (!lk_cache_seen)
			return;

		width = sizeof (uintptr_t) * 2;
		leak = "buffer";
		break;

	case TYPE_UMEM:
		if (!lk_umem_seen)
			return;

		width = sizeof (uintptr_t) * 2;
		leak = "buffer";
		break;

	default:
		return;
	}

	for (i = 0; i < 72; i++)
		mdb_printf("-");
	mdb_printf("\n%*s %7ld %s%s, %ld byte%s\n",
	    width, "Total", lk_ttl, leak, (lk_ttl == 1) ? "" : "s",
	    lk_bytes, (lk_bytes == 1) ? "" : "s");
}

int
leaky_subr_invoke_callback(const leak_bufctl_t *lkb, mdb_walk_cb_t cb,
    void *cbdata)
{
	vmem_seg_t vs;
	umem_bufctl_audit_t *bcp;
	UMEM_LOCAL_BUFCTL_AUDIT(&bcp);

	switch (lkb->lkb_type) {
	case TYPE_VMEM:
		if (mdb_vread(&vs, sizeof (vs), lkb->lkb_addr) == -1) {
			mdb_warn("unable to read vmem_seg at %p",
			    lkb->lkb_addr);
			return (WALK_NEXT);
		}
		return (cb(lkb->lkb_addr, &vs, cbdata));

	case TYPE_UMEM:
		if (mdb_vread(bcp, UMEM_BUFCTL_AUDIT_SIZE,
		    lkb->lkb_addr) == -1) {
			mdb_warn("unable to read bufctl at %p",
			    lkb->lkb_addr);
			return (WALK_NEXT);
		}
		return (cb(lkb->lkb_addr, bcp, cbdata));

	default:
		return (cb(lkb->lkb_addr, NULL, cbdata));
	}
}
