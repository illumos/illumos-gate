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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * UNIX machine dependent virtual memory support.
 */

#include <sys/vm.h>
#include <sys/exec.h>

#include <sys/exechdr.h>
#include <vm/seg_kmem.h>
#include <sys/atomic.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/kdi.h>
#include <sys/cpu_module.h>

#include <vm/hat_sfmmu.h>

#include <sys/memnode.h>

#include <sys/mem_config.h>
#include <sys/mem_cage.h>
#include <vm/vm_dep.h>
#include <sys/platform_module.h>

/*
 * These variables are set by module specific config routines.
 * They are only set by modules which will use physical cache page coloring
 * and/or virtual cache page coloring.
 */
int do_pg_coloring = 0;
int do_virtual_coloring = 0;

/*
 * These variables can be conveniently patched at kernel load time to
 * prevent do_pg_coloring or do_virtual_coloring from being enabled by
 * module specific config routines.
 */

int use_page_coloring = 1;
int use_virtual_coloring = 1;

/*
 * initialized by page_coloring_init()
 */
extern uint_t page_colors;
extern uint_t page_colors_mask;
extern uint_t page_coloring_shift;
int cpu_page_colors;
uint_t vac_colors = 0;
uint_t vac_colors_mask = 0;

/*
 * get the ecache setsize for the current cpu.
 */
#define	CPUSETSIZE()	(cpunodes[CPU->cpu_id].ecache_setsize)

plcnt_t		plcnt;		/* page list count */

/*
 * This variable is set by the cpu module to contain the lowest
 * address not affected by the SF_ERRATA_57 workaround.  It should
 * remain 0 if the workaround is not needed.
 */
#if defined(SF_ERRATA_57)
caddr_t errata57_limit;
#endif

extern int disable_auto_large_pages;	/* used by map_pgsz*() routines */

extern void page_relocate_hash(page_t *, page_t *);

/*
 * these must be defined in platform specific areas
 */
extern void map_addr_proc(caddr_t *, size_t, offset_t, int, caddr_t,
	struct proc *, uint_t);
extern page_t *page_get_freelist(struct vnode *, u_offset_t, struct seg *,
	caddr_t, size_t, uint_t, struct lgrp *);
/*
 * Convert page frame number to an OBMEM page frame number
 * (i.e. put in the type bits -- zero for this implementation)
 */
pfn_t
impl_obmem_pfnum(pfn_t pf)
{
	return (pf);
}

/*
 * Use physmax to determine the highest physical page of DRAM memory
 * It is assumed that any physical addresses above physmax is in IO space.
 * We don't bother checking the low end because we assume that memory space
 * begins at physical page frame 0.
 *
 * Return 1 if the page frame is onboard DRAM memory, else 0.
 * Returns 0 for nvram so it won't be cached.
 */
int
pf_is_memory(pfn_t pf)
{
	/* We must be IO space */
	if (pf > physmax)
		return (0);

	/* We must be memory space */
	return (1);
}

/*
 * Handle a pagefault.
 */
faultcode_t
pagefault(caddr_t addr, enum fault_type type, enum seg_rw rw, int iskernel)
{
	struct as *as;
	struct proc *p;
	faultcode_t res;
	caddr_t base;
	size_t len;
	int err;

	if (INVALID_VADDR(addr))
		return (FC_NOMAP);

	if (iskernel) {
		as = &kas;
	} else {
		p = curproc;
		as = p->p_as;
#if defined(SF_ERRATA_57)
		/*
		 * Prevent infinite loops due to a segment driver
		 * setting the execute permissions and the sfmmu hat
		 * silently ignoring them.
		 */
		if (rw == S_EXEC && AS_TYPE_64BIT(as) &&
		    addr < errata57_limit) {
			res = FC_NOMAP;
			goto out;
		}
#endif
	}

	/*
	 * Dispatch pagefault.
	 */
	res = as_fault(as->a_hat, as, addr, 1, type, rw);

	/*
	 * If this isn't a potential unmapped hole in the user's
	 * UNIX data or stack segments, just return status info.
	 */
	if (!(res == FC_NOMAP && iskernel == 0))
		goto out;

	/*
	 * Check to see if we happened to faulted on a currently unmapped
	 * part of the UNIX data or stack segments.  If so, create a zfod
	 * mapping there and then try calling the fault routine again.
	 */
	base = p->p_brkbase;
	len = p->p_brksize;

	if (addr < base || addr >= base + len) {		/* data seg? */
		base = (caddr_t)(p->p_usrstack - p->p_stksize);
		len = p->p_stksize;
		if (addr < base || addr >= p->p_usrstack) {	/* stack seg? */
			/* not in either UNIX data or stack segments */
			res = FC_NOMAP;
			goto out;
		}
	}

	/* the rest of this function implements a 3.X 4.X 5.X compatibility */
	/* This code is probably not needed anymore */

	/* expand the gap to the page boundaries on each side */
	len = (((uintptr_t)base + len + PAGEOFFSET) & PAGEMASK) -
	    ((uintptr_t)base & PAGEMASK);
	base = (caddr_t)((uintptr_t)base & PAGEMASK);

	as_rangelock(as);
	as_purge(as);
	if (as_gap(as, PAGESIZE, &base, &len, AH_CONTAIN, addr) == 0) {
		err = as_map(as, base, len, segvn_create, zfod_argsp);
		as_rangeunlock(as);
		if (err) {
			res = FC_MAKE_ERR(err);
			goto out;
		}
	} else {
		/*
		 * This page is already mapped by another thread after we
		 * returned from as_fault() above.  We just fallthrough
		 * as_fault() below.
		 */
		as_rangeunlock(as);
	}

	res = as_fault(as->a_hat, as, addr, 1, F_INVAL, rw);

out:

	return (res);
}

/*
 * This is the routine which defines the address limit implied
 * by the flag '_MAP_LOW32'.  USERLIMIT32 matches the highest
 * mappable address in a 32-bit process on this platform (though
 * perhaps we should make it be UINT32_MAX here?)
 */
void
map_addr(caddr_t *addrp, size_t len, offset_t off, int vacalign, uint_t flags)
{
	struct proc *p = curproc;
	caddr_t userlimit = flags & _MAP_LOW32 ?
		(caddr_t)USERLIMIT32 : p->p_as->a_userlimit;
	map_addr_proc(addrp, len, off, vacalign, userlimit, p, flags);
}

/*
 * Some V9 CPUs have holes in the middle of the 64-bit virtual address range.
 */
caddr_t	hole_start, hole_end;

/*
 * kpm mapping window
 */
caddr_t kpm_vbase;
size_t  kpm_size;
uchar_t kpm_size_shift;

/*
 * Determine whether [base, base+len] contains a mapable range of
 * addresses at least minlen long. base and len are adjusted if
 * required to provide a mapable range.
 */
/* ARGSUSED */
int
valid_va_range(caddr_t *basep, size_t *lenp, size_t minlen, int dir)
{
	caddr_t hi, lo;

	lo = *basep;
	hi = lo + *lenp;

	/*
	 * If hi rolled over the top, try cutting back.
	 */
	if (hi < lo) {
		size_t newlen = 0 - (uintptr_t)lo - 1l;

		if (newlen + (uintptr_t)hi < minlen)
			return (0);
		if (newlen < minlen)
			return (0);
		*lenp = newlen;
	} else if (hi - lo < minlen)
		return (0);

	/*
	 * Deal with a possible hole in the address range between
	 * hole_start and hole_end that should never be mapped by the MMU.
	 */
	hi = lo + *lenp;

	if (lo < hole_start) {
		if (hi > hole_start)
			if (hi < hole_end)
				hi = hole_start;
			else
				/* lo < hole_start && hi >= hole_end */
				if (dir == AH_LO) {
					/*
					 * prefer lowest range
					 */
					if (hole_start - lo >= minlen)
						hi = hole_start;
					else if (hi - hole_end >= minlen)
						lo = hole_end;
					else
						return (0);
				} else {
					/*
					 * prefer highest range
					 */
					if (hi - hole_end >= minlen)
						lo = hole_end;
					else if (hole_start - lo >= minlen)
						hi = hole_start;
					else
						return (0);
				}
	} else {
		/* lo >= hole_start */
		if (hi < hole_end)
			return (0);
		if (lo < hole_end)
			lo = hole_end;
	}

	if (hi - lo < minlen)
		return (0);

	*basep = lo;
	*lenp = hi - lo;

	return (1);
}

/*
 * Determine whether [addr, addr+len] with protections `prot' are valid
 * for a user address space.
 */
/*ARGSUSED*/
int
valid_usr_range(caddr_t addr, size_t len, uint_t prot, struct as *as,
    caddr_t userlimit)
{
	caddr_t eaddr = addr + len;

	if (eaddr <= addr || addr >= userlimit || eaddr > userlimit)
		return (RANGE_BADADDR);

	/*
	 * Determine if the address range falls within an illegal
	 * range of the MMU.
	 */
	if (eaddr > hole_start && addr < hole_end)
		return (RANGE_BADADDR);

#if defined(SF_ERRATA_57)
	/*
	 * Make sure USERLIMIT isn't raised too high
	 */
	ASSERT64(addr <= (caddr_t)0xffffffff80000000ul ||
	    errata57_limit == 0);

	if (AS_TYPE_64BIT(as) &&
	    (addr < errata57_limit) &&
	    (prot & PROT_EXEC))
		return (RANGE_BADPROT);
#endif /* SF_ERRATA57 */
	return (RANGE_OKAY);
}

/*
 * Routine used to check to see if an a.out can be executed
 * by the current machine/architecture.
 */
int
chkaout(struct exdata *exp)
{
	if (exp->ux_mach == M_SPARC)
		return (0);
	else
		return (ENOEXEC);
}

/*
 * The following functions return information about an a.out
 * which is used when a program is executed.
 */

/*
 * Return the load memory address for the data segment.
 */
caddr_t
getdmem(struct exec *exp)
{
	/*
	 * XXX - Sparc Reference Hack approaching
	 * Remember that we are loading
	 * 8k executables into a 4k machine
	 * DATA_ALIGN == 2 * PAGESIZE
	 */
	if (exp->a_text)
		return ((caddr_t)(roundup(USRTEXT + exp->a_text, DATA_ALIGN)));
	else
		return ((caddr_t)USRTEXT);
}

/*
 * Return the starting disk address for the data segment.
 */
ulong_t
getdfile(struct exec *exp)
{
	if (exp->a_magic == ZMAGIC)
		return (exp->a_text);
	else
		return (sizeof (struct exec) + exp->a_text);
}

/*
 * Return the load memory address for the text segment.
 */

/*ARGSUSED*/
caddr_t
gettmem(struct exec *exp)
{
	return ((caddr_t)USRTEXT);
}

/*
 * Return the file byte offset for the text segment.
 */
uint_t
gettfile(struct exec *exp)
{
	if (exp->a_magic == ZMAGIC)
		return (0);
	else
		return (sizeof (struct exec));
}

void
getexinfo(
	struct exdata *edp_in,
	struct exdata *edp_out,
	int *pagetext,
	int *pagedata)
{
	*edp_out = *edp_in;	/* structure copy */

	if ((edp_in->ux_mag == ZMAGIC) &&
	    ((edp_in->vp->v_flag & VNOMAP) == 0)) {
		*pagetext = 1;
		*pagedata = 1;
	} else {
		*pagetext = 0;
		*pagedata = 0;
	}
}

#define	MAP_PGSZ_COMMON(pgsz, n, upper, lower, len)	\
	for ((n) = (upper); (n) > (lower); (n)--) {		\
		if (disable_auto_large_pages & (1 << (n)))		\
			continue;				\
		if (hw_page_array[(n)].hp_size <= (len)) {	\
			(pgsz) = hw_page_array[(n)].hp_size;	\
			break;					\
		}						\
	}


/*ARGSUSED*/
size_t
map_pgszva(struct proc *p, caddr_t addr, size_t len)
{
	size_t		pgsz = MMU_PAGESIZE;
	int		n, upper;

	/*
	 * Select the best fit page size within the constraints of
	 * auto_lpg_{min,max}szc.
	 *
	 * Note that we also take the heap size into account when
	 * deciding if we've crossed the threshold at which we should
	 * increase the page size.  This isn't perfect since the heap
	 * may not have reached its full size yet, but it's better than
	 * not considering it at all.
	 */
	len += p->p_brksize;
	if (ptob(auto_lpg_tlb_threshold) <= len) {

		upper = MIN(mmu_page_sizes - 1, auto_lpg_maxszc);

		/*
		 * Use auto_lpg_minszc - 1 as the limit so we never drop
		 * below auto_lpg_minszc.  We don't have a size code to refer
		 * to like we have for bss and stack, so we assume 0.
		 * auto_lpg_minszc should always be >= 0.  Using
		 * auto_lpg_minszc cuts off the loop.
		 */
		MAP_PGSZ_COMMON(pgsz, n, upper, auto_lpg_minszc - 1, len);
	}

	return (pgsz);
}

size_t
map_pgszheap(struct proc *p, caddr_t addr, size_t len)
{
	size_t		pgsz;
	int		n, upper, lower;

	/*
	 * If len is zero, retrieve from proc and don't demote the page size.
	 */
	if (len == 0) {
		len = p->p_brksize;
	}

	/*
	 * Still zero?  Then we don't have a heap yet, so pick the default
	 * heap size.
	 */
	if (len == 0) {
		pgsz = auto_lpg_heap_default;
	} else {
		pgsz = hw_page_array[p->p_brkpageszc].hp_size;
	}

	if ((pgsz * auto_lpg_tlb_threshold) <= len) {
		/*
		 * We're past the threshold, so select the best fit
		 * page size within the constraints of
		 * auto_lpg_{min,max}szc and the minimum required
		 * alignment.
		 */
		upper = MIN(mmu_page_sizes - 1, auto_lpg_maxszc);
		lower = MAX(auto_lpg_minszc - 1, p->p_brkpageszc);
		MAP_PGSZ_COMMON(pgsz, n, upper, lower, len);
	}

	/*
	 * If addr == 0 we were called by memcntl() or exec_args() when the
	 * size code is 0.  Don't set pgsz less than current size.
	 */
	if (addr == 0 && (pgsz < hw_page_array[p->p_brkpageszc].hp_size)) {
		pgsz = hw_page_array[p->p_brkpageszc].hp_size;
	}

	return (pgsz);
}

size_t
map_pgszstk(struct proc *p, caddr_t addr, size_t len)
{
	size_t		pgsz;
	int		n, upper, lower;

	/*
	 * If len is zero, retrieve from proc and don't demote the page size.
	 */
	if (len == 0) {
		len = p->p_stksize;
	}

	/*
	 * Still zero?  Then we don't have a heap yet, so pick the default
	 * stack size.
	 */
	if (len == 0) {
		pgsz = auto_lpg_stack_default;
	} else {
		pgsz = hw_page_array[p->p_stkpageszc].hp_size;
	}

	if ((pgsz * auto_lpg_tlb_threshold) <= len) {
		/*
		 * We're past the threshold, so select the best fit
		 * page size within the constraints of
		 * auto_lpg_{min,max}szc and the minimum required
		 * alignment.
		 */
		upper = MIN(mmu_page_sizes - 1, auto_lpg_maxszc);
		lower = MAX(auto_lpg_minszc - 1, p->p_brkpageszc);
		MAP_PGSZ_COMMON(pgsz, n, upper, lower, len);
	}

	/*
	 * If addr == 0 we were called by memcntl() or exec_args() when the
	 * size code is 0.  Don't set pgsz less than current size.
	 */
	if (addr == 0 && (pgsz < hw_page_array[p->p_stkpageszc].hp_size)) {
		pgsz = hw_page_array[p->p_stkpageszc].hp_size;
	}

	return (pgsz);
}


/*
 * Return non 0 value if the address may cause a VAC alias with KPM mappings.
 * KPM selects an address such that it's equal offset modulo shm_alignment and
 * assumes it can't be in VAC conflict with any larger than PAGESIZE mapping.
 */
int
map_addr_vacalign_check(caddr_t addr, u_offset_t off)
{
	if (vac) {
		return (((uintptr_t)addr ^ off) & shm_alignment - 1);
	} else {
		return (0);
	}
}

/*
 * use_text_pgsz64k, use_initdata_pgsz64k and use_text_pgsz4m
 * can be set in platform or CPU specific code but user can change the
 * default values via /etc/system.
 *
 * Initial values are defined in architecture specific mach_vm_dep.c file.
 */
extern int use_text_pgsz64k;
extern int use_text_pgsz4m;
extern int use_initdata_pgsz64k;

/*
 * disable_text_largepages and disable_initdata_largepages bitmaks are set in
 * platform or CPU specific code to disable page sizes that should not be
 * used. These variables normally shouldn't be changed via /etc/system. A
 * particular page size for text or inititialized data will be used by default
 * if both one of use_* variables is set to 1 AND this page size is not
 * disabled in the corresponding disable_* bitmask variable.
 *
 * Initial values are defined in architecture specific mach_vm_dep.c file.
 */
extern int disable_text_largepages;
extern int disable_initdata_largepages;

/*
 * Minimum segment size tunables before 64K or 4M large pages
 * should be used to map it.
 *
 * Initial values are defined in architecture specific mach_vm_dep.c file.
 */
extern size_t text_pgsz64k_minsize;
extern size_t text_pgsz4m_minsize;
extern size_t initdata_pgsz64k_minsize;

/*
 * Sanity control. Don't use large pages regardless of user
 * settings if there's less than execseg_lpg_min_physmem memory installed.
 * The units for this variable is 8K pages.
 */
pgcnt_t execseg_lpg_min_physmem = 131072;		/* 1GB */


/* assumes TTE8K...TTE4M == szc */

static uint_t
map_text_pgsz4m(caddr_t addr, size_t len)
{
	caddr_t a;

	if (len < text_pgsz4m_minsize) {
		return (0);
	}

	a = (caddr_t)P2ROUNDUP_TYPED(addr, MMU_PAGESIZE4M, uintptr_t);
	if (a < addr || a >= addr + len) {
		return (0);
	}
	len -= (a - addr);
	if (len < MMU_PAGESIZE4M) {
		return (0);
	}

	return (1 << TTE4M);
}

static uint_t
map_text_pgsz64k(caddr_t addr, size_t len)
{
	caddr_t a;
	size_t svlen = len;

	if (len < text_pgsz64k_minsize) {
		return (0);
	}

	a = (caddr_t)P2ROUNDUP_TYPED(addr, MMU_PAGESIZE64K, uintptr_t);
	if (a < addr || a >= addr + len) {
		return (0);
	}
	len -= (a - addr);
	if (len < MMU_PAGESIZE64K) {
		return (0);
	}
	if (!use_text_pgsz4m ||
	    disable_text_largepages & (1 << TTE4M)) {
		return (1 << TTE64K);
	}
	if (svlen < text_pgsz4m_minsize) {
		return (1 << TTE64K);
	}
	addr = a;
	a = (caddr_t)P2ROUNDUP_TYPED(addr, MMU_PAGESIZE4M, uintptr_t);
	if (a < addr || a >= addr + len) {
		return (1 << TTE64K);
	}
	len -= (a - addr);
	if (len < MMU_PAGESIZE4M) {
		return (1 << TTE64K);
	}
	return ((1 << TTE4M) | (1 << TTE64K));
}

static uint_t
map_initdata_pgsz64k(caddr_t addr, size_t len)
{
	caddr_t a;

	if (len < initdata_pgsz64k_minsize) {
		return (0);
	}

	a = (caddr_t)P2ROUNDUP_TYPED(addr, MMU_PAGESIZE64K, uintptr_t);
	if (a < addr || a >= addr + len) {
		return (0);
	}
	len -= (a - addr);
	if (len < MMU_PAGESIZE64K) {
		return (0);
	}
	return (1 << TTE64K);
}

/*
 * Return a bit vector of large page size codes that
 * can be used to map [addr, addr + len) region.
 */
uint_t
map_execseg_pgszcvec(int text, caddr_t addr, size_t len)
{
	uint_t ret = 0;

	if (physmem < execseg_lpg_min_physmem) {
		return (0);
	}

	if (text) {
		if (use_text_pgsz64k &&
		    !(disable_text_largepages & (1 << TTE64K))) {
			ret = map_text_pgsz64k(addr, len);
		} else if (use_text_pgsz4m &&
		    !(disable_text_largepages & (1 << TTE4M))) {
			ret = map_text_pgsz4m(addr, len);
		}
	} else if (use_initdata_pgsz64k &&
	    !(disable_initdata_largepages & (1 << TTE64K))) {
		ret = map_initdata_pgsz64k(addr, len);
	}

	return (ret);
}

#define	PNUM_SIZE(size_code)						\
	(hw_page_array[size_code].hp_size >> hw_page_array[0].hp_shift)

/*
 * Anchored in the table below are counters used to keep track
 * of free contiguous physical memory. Each element of the table contains
 * the array of counters, the size of array which is allocated during
 * startup based on physmax and a shift value used to convert a pagenum
 * into a counter array index or vice versa. The table has page size
 * for rows and region size for columns:
 *
 *	page_counters[page_size][region_size]
 *
 *	page_size: 	TTE size code of pages on page_size freelist.
 *
 *	region_size:	TTE size code of a candidate larger page made up
 *			made up of contiguous free page_size pages.
 *
 * As you go across a page_size row increasing region_size each
 * element keeps track of how many (region_size - 1) size groups
 * made up of page_size free pages can be coalesced into a
 * regsion_size page. Yuck! Lets try an example:
 *
 * 	page_counters[1][3] is the table element used for identifying
 *	candidate 4M pages from contiguous pages off the 64K free list.
 *	Each index in the page_counters[1][3].array spans 4M. Its the
 *	number of free 512K size (regsion_size - 1) groups of contiguous
 *	64K free pages.	So when page_counters[1][3].counters[n] == 8
 *	we know we have a candidate 4M page made up of 512K size groups
 *	of 64K free pages.
 */

/*
 * Per page size free lists. 3rd (max_mem_nodes) and 4th (page coloring bins)
 * dimensions are allocated dynamically.
 */
page_t ***page_freelists[MMU_PAGE_SIZES][MAX_MEM_TYPES];

/*
 * For now there is only a single size cache list.
 * Allocated dynamically.
 */
page_t ***page_cachelists[MAX_MEM_TYPES];

kmutex_t *fpc_mutex[NPC_MUTEX];
kmutex_t *cpc_mutex[NPC_MUTEX];

caddr_t
alloc_page_freelists(int mnode, caddr_t alloc_base, int alloc_align)
{
	int	mtype;
	uint_t	szc;

	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, alloc_align);

	/*
	 * We only support small pages in the cachelist.
	 */
	for (mtype = 0; mtype < MAX_MEM_TYPES; mtype++) {
		page_cachelists[mtype][mnode] = (page_t **)alloc_base;
		alloc_base += (sizeof (page_t *) * page_colors);
		/*
		 * Allocate freelists bins for all
		 * supported page sizes.
		 */
		for (szc = 0; szc < mmu_page_sizes; szc++) {
			page_freelists[szc][mtype][mnode] =
			    (page_t **)alloc_base;
			alloc_base += ((sizeof (page_t *) *
			    page_get_pagecolors(szc)));
		}
	}

	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, alloc_align);

	return (alloc_base);
}

/*
 * Allocate page_freelists bin headers for a memnode from the
 * nucleus data area. This is the first time that mmu_page_sizes is
 * used during sun4u bootup, so check mmu_page_sizes initialization.
 */
int
ndata_alloc_page_freelists(struct memlist *ndata, int mnode)
{
	size_t alloc_sz;
	caddr_t alloc_base;
	caddr_t end;
	int	mtype;
	uint_t	szc;
	int32_t allp = 0;

	if (&mmu_init_mmu_page_sizes) {
		if (!mmu_init_mmu_page_sizes(allp)) {
			cmn_err(CE_PANIC, "mmu_page_sizes %d not initialized",
			    mmu_page_sizes);
		}
	}
	ASSERT(mmu_page_sizes >= DEFAULT_MMU_PAGE_SIZES);

	/* first time called - allocate max_mem_nodes dimension */
	if (mnode == 0) {
		int	i;

		/* page_cachelists */
		alloc_sz = MAX_MEM_TYPES * max_mem_nodes *
		    sizeof (page_t **);

		/* page_freelists */
		alloc_sz += MAX_MEM_TYPES * mmu_page_sizes * max_mem_nodes *
		    sizeof (page_t **);

		/* fpc_mutex and cpc_mutex */
		alloc_sz += 2 * NPC_MUTEX * max_mem_nodes * sizeof (kmutex_t);

		alloc_base = ndata_alloc(ndata, alloc_sz, ecache_alignsize);
		if (alloc_base == NULL)
			return (-1);

		ASSERT(((uintptr_t)alloc_base & (ecache_alignsize - 1)) == 0);

		for (mtype = 0; mtype < MAX_MEM_TYPES; mtype++) {
			page_cachelists[mtype] = (page_t ***)alloc_base;
			alloc_base += (max_mem_nodes * sizeof (page_t **));
			for (szc = 0; szc < mmu_page_sizes; szc++) {
				page_freelists[szc][mtype] =
				    (page_t ***)alloc_base;
				alloc_base += (max_mem_nodes *
				    sizeof (page_t **));
			}
		}
		for (i = 0; i < NPC_MUTEX; i++) {
			fpc_mutex[i] = (kmutex_t *)alloc_base;
			alloc_base += (sizeof (kmutex_t) * max_mem_nodes);
			cpc_mutex[i] = (kmutex_t *)alloc_base;
			alloc_base += (sizeof (kmutex_t) * max_mem_nodes);
		}
		alloc_sz = 0;
	}

	/*
	 * Calculate the size needed by alloc_page_freelists().
	 */
	for (mtype = 0; mtype < MAX_MEM_TYPES; mtype++) {
		alloc_sz += sizeof (page_t *) * page_colors;

		for (szc = 0; szc < mmu_page_sizes; szc++)
			alloc_sz += sizeof (page_t *) *
			    page_get_pagecolors(szc);
	}

	alloc_base = ndata_alloc(ndata, alloc_sz, ecache_alignsize);
	if (alloc_base == NULL)
		return (-1);

	end = alloc_page_freelists(mnode, alloc_base, ecache_alignsize);
	ASSERT((uintptr_t)end == roundup((uintptr_t)alloc_base + alloc_sz,
	    ecache_alignsize));

	return (0);
}

/*
 * To select our starting bin, we stride through the bins with a stride
 * of 337.  Why 337?  It's prime, it's largeish, and it performs well both
 * in simulation and practice for different workloads on varying cache sizes.
 */
uint32_t color_start_current = 0;
uint32_t color_start_stride = 337;
int color_start_random = 0;

/* ARGSUSED */
uint_t
get_color_start(struct as *as)
{
	uint32_t old, new;

	if (consistent_coloring == 2 || color_start_random) {
		return ((uint_t)(((gettick()) << (vac_shift - MMU_PAGESHIFT)) &
		    page_colors_mask));
	}

	do {
		old = color_start_current;
		new = old + (color_start_stride << (vac_shift - MMU_PAGESHIFT));
	} while (cas32(&color_start_current, old, new) != old);

	return ((uint_t)(new));
}

/*
 * Called once at startup from kphysm_init() -- before memialloc()
 * is invoked to do the 1st page_free()/page_freelist_add().
 *
 * initializes page_colors and page_colors_mask based on ecache_setsize.
 *
 * Also initializes the counter locks.
 */
void
page_coloring_init()
{
	int	a;

	if (do_pg_coloring == 0) {
		page_colors = 1;
		return;
	}

	/*
	 * Calculate page_colors from ecache_setsize. ecache_setsize contains
	 * the max ecache setsize of all cpus configured in the system or, for
	 * cheetah+ systems, the max possible ecache setsize for all possible
	 * cheetah+ cpus.
	 */
	page_colors = ecache_setsize / MMU_PAGESIZE;
	page_colors_mask = page_colors - 1;

	/*
	 * initialize cpu_page_colors if ecache setsizes are homogenous.
	 * cpu_page_colors set to -1 during DR operation or during startup
	 * if setsizes are heterogenous.
	 *
	 * The value of cpu_page_colors determines if additional color bins
	 * need to be checked for a particular color in the page_get routines.
	 */
	if ((cpu_page_colors == 0) && (cpu_setsize < ecache_setsize))
		cpu_page_colors = cpu_setsize / MMU_PAGESIZE;

	vac_colors = vac_size / MMU_PAGESIZE;
	vac_colors_mask = vac_colors -1;

	page_coloring_shift = 0;
	a = ecache_setsize;
	while (a >>= 1) {
		page_coloring_shift++;
	}
}

int
bp_color(struct buf *bp)
{
	int color = -1;

	if (vac) {
		if ((bp->b_flags & B_PAGEIO) != 0) {
			color = sfmmu_get_ppvcolor(bp->b_pages);
		} else if (bp->b_un.b_addr != NULL) {
			color = sfmmu_get_addrvcolor(bp->b_un.b_addr);
		}
	}
	return (color < 0 ? 0 : ptob(color));
}

/*
 * Create & Initialise pageout scanner thread. The thread has to
 * start at procedure with process pp and priority pri.
 */
void
pageout_init(void (*procedure)(), proc_t *pp, pri_t pri)
{
	(void) thread_create(NULL, 0, procedure, NULL, 0, pp, TS_RUN, pri);
}

/*
 * Function for flushing D-cache when performing module relocations
 * to an alternate mapping.  Stubbed out on all platforms except sun4u,
 * at least for now.
 */
void
dcache_flushall()
{
	sfmmu_cache_flushall();
}

static int
kdi_range_overlap(uintptr_t va1, size_t sz1, uintptr_t va2, size_t sz2)
{
	if (va1 < va2 && va1 + sz1 <= va2)
		return (0);

	if (va2 < va1 && va2 + sz2 <= va1)
		return (0);

	return (1);
}

/*
 * Return the number of bytes, relative to the beginning of a given range, that
 * are non-toxic (can be read from and written to with relative impunity).
 */
size_t
kdi_range_is_nontoxic(uintptr_t va, size_t sz, int write)
{
	/* OBP reads are harmless, but we don't want people writing there */
	if (write && kdi_range_overlap(va, sz, OFW_START_ADDR, OFW_END_ADDR -
	    OFW_START_ADDR + 1))
		return (va < OFW_START_ADDR ? OFW_START_ADDR - va : 0);

	if (kdi_range_overlap(va, sz, PIOMAPBASE, PIOMAPSIZE))
		return (va < PIOMAPBASE ? PIOMAPBASE - va : 0);

	return (sz); /* no overlap */
}

/*
 * Minimum physmem required for enabling large pages for kernel heap
 * Currently we do not enable lp for kmem on systems with less
 * than 1GB of memory. This value can be changed via /etc/system
 */
size_t segkmem_lpminphysmem = 0x40000000;	/* 1GB */

/*
 * this function chooses large page size for kernel heap
 */
size_t
get_segkmem_lpsize(size_t lpsize)
{
	size_t memtotal = physmem * PAGESIZE;

	if (memtotal < segkmem_lpminphysmem)
		return (PAGESIZE);

	if (plat_lpkmem_is_supported != NULL &&
	    plat_lpkmem_is_supported() == 0)
		return (PAGESIZE);

	return (mmu_get_kernel_lpsize(lpsize));
}
