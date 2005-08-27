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
 * UNIX machine dependent virtual memory support.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/buf.h>
#include <sys/cpuvar.h>
#include <sys/lgrp.h>
#include <sys/disp.h>
#include <sys/vm.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/exec.h>
#include <sys/exechdr.h>
#include <sys/debug.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kp.h>
#include <vm/seg_vn.h>
#include <vm/page.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/vm_dep.h>

#include <sys/cpu.h>
#include <sys/vm_machparam.h>
#include <sys/memlist.h>
#include <sys/bootconf.h> /* XXX the memlist stuff belongs in memlist_plat.h */
#include <vm/hat_i86.h>
#include <sys/x86_archext.h>
#include <sys/elf_386.h>
#include <sys/cmn_err.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>

#include <sys/vtrace.h>
#include <sys/ddidmareq.h>
#include <sys/promif.h>
#include <sys/memnode.h>
#include <sys/stack.h>

uint_t vac_colors = 0;

int largepagesupport = 0;
extern uint_t page_create_new;
extern uint_t page_create_exists;
extern uint_t page_create_putbacks;
extern uint_t page_create_putbacks;
extern uintptr_t eprom_kernelbase;
extern int use_sse_pagecopy, use_sse_pagezero;	/* in ml/float.s */

/* 4g memory management */
pgcnt_t		maxmem4g;
pgcnt_t		freemem4g;
int		physmax4g;
int		desfree4gshift = 4;	/* maxmem4g shift to derive DESFREE4G */
int		lotsfree4gshift = 3;

#ifdef VM_STATS
struct {
	ulong_t	pga_alloc;
	ulong_t	pga_notfullrange;
	ulong_t	pga_nulldmaattr;
	ulong_t	pga_allocok;
	ulong_t	pga_allocfailed;
	ulong_t	pgma_alloc;
	ulong_t	pgma_allocok;
	ulong_t	pgma_allocfailed;
	ulong_t	pgma_allocempty;
} pga_vmstats;
#endif

uint_t mmu_page_sizes;

/* How many page sizes the users can see */
uint_t mmu_exported_page_sizes;

size_t auto_lpg_va_default = MMU_PAGESIZE; /* used by zmap() */
/*
 * Number of pages in 1 GB.  Don't enable automatic large pages if we have
 * fewer than this many pages.
 */
pgcnt_t auto_lpg_min_physmem = 1 << (30 - MMU_PAGESHIFT);

/*
 * Return the optimum page size for a given mapping
 */
/*ARGSUSED*/
size_t
map_pgsz(int maptype, struct proc *p, caddr_t addr, size_t len, int *remap)
{
	level_t l;

	if (remap)
		*remap = 0;

	switch (maptype) {

	case MAPPGSZ_STK:
	case MAPPGSZ_HEAP:
	case MAPPGSZ_VA:
		/*
		 * use the pages size that best fits len
		 */
		for (l = mmu.max_page_level; l > 0; --l) {
			if (len < LEVEL_SIZE(l))
				continue;
			break;
		}
		return (LEVEL_SIZE(l));

	/*
	 * for ISM use the 1st large page size.
	 */
	case MAPPGSZ_ISM:
		if (mmu.max_page_level == 0)
			return (MMU_PAGESIZE);
		return (LEVEL_SIZE(1));
	}
	return (0);
}

/*
 * This can be patched via /etc/system to allow large pages
 * to be used for mapping application and libraries text segments.
 */
int	use_text_largepages = 0;

/*
 * Return a bit vector of large page size codes that
 * can be used to map [addr, addr + len) region.
 */

/*ARGSUSED*/
uint_t
map_execseg_pgszcvec(int text, caddr_t addr, size_t len)
{
	size_t	pgsz;
	caddr_t a;

	if (!text || !use_text_largepages ||
	    mmu.max_page_level == 0)
		return (0);

	pgsz = LEVEL_SIZE(1);
	a = (caddr_t)P2ROUNDUP((uintptr_t)addr, pgsz);
	if (a < addr || a >= addr + len) {
		return (0);
	}
	len -= (a - addr);
	if (len < pgsz) {
		return (0);
	}
	return (1 << 1);
}

/*
 * Handle a pagefault.
 */
faultcode_t
pagefault(
	caddr_t addr,
	enum fault_type type,
	enum seg_rw rw,
	int iskernel)
{
	struct as *as;
	struct hat *hat;
	struct proc *p;
	kthread_t *t;
	faultcode_t res;
	caddr_t base;
	size_t len;
	int err;
	int mapped_red;
	uintptr_t ea;

	ASSERT_STACK_ALIGNED();

	if (INVALID_VADDR(addr))
		return (FC_NOMAP);

	mapped_red = segkp_map_red();

	if (iskernel) {
		as = &kas;
		hat = as->a_hat;
	} else {
		t = curthread;
		p = ttoproc(t);
		as = p->p_as;
		hat = as->a_hat;
	}

	/*
	 * Dispatch pagefault.
	 */
	res = as_fault(hat, as, addr, 1, type, rw);

	/*
	 * If this isn't a potential unmapped hole in the user's
	 * UNIX data or stack segments, just return status info.
	 */
	if (res != FC_NOMAP || iskernel)
		goto out;

	/*
	 * Check to see if we happened to faulted on a currently unmapped
	 * part of the UNIX data or stack segments.  If so, create a zfod
	 * mapping there and then try calling the fault routine again.
	 */
	base = p->p_brkbase;
	len = p->p_brksize;

	if (addr < base || addr >= base + len) {		/* data seg? */
		base = (caddr_t)p->p_usrstack - p->p_stksize;
		len = p->p_stksize;
		if (addr < base || addr >= p->p_usrstack) {	/* stack seg? */
			/* not in either UNIX data or stack segments */
			res = FC_NOMAP;
			goto out;
		}
	}

	/*
	 * the rest of this function implements a 3.X 4.X 5.X compatibility
	 * This code is probably not needed anymore
	 */
	if (p->p_model == DATAMODEL_ILP32) {

		/* expand the gap to the page boundaries on each side */
		ea = P2ROUNDUP((uintptr_t)base + len, MMU_PAGESIZE);
		base = (caddr_t)P2ALIGN((uintptr_t)base, MMU_PAGESIZE);
		len = ea - (uintptr_t)base;

		as_rangelock(as);
		if (as_gap(as, MMU_PAGESIZE, &base, &len, AH_CONTAIN, addr) ==
		    0) {
			err = as_map(as, base, len, segvn_create, zfod_argsp);
			as_rangeunlock(as);
			if (err) {
				res = FC_MAKE_ERR(err);
				goto out;
			}
		} else {
			/*
			 * This page is already mapped by another thread after
			 * we returned from as_fault() above.  We just fall
			 * through as_fault() below.
			 */
			as_rangeunlock(as);
		}

		res = as_fault(hat, as, addr, 1, F_INVAL, rw);
	}

out:
	if (mapped_red)
		segkp_unmap_red();

	return (res);
}

void
map_addr(caddr_t *addrp, size_t len, offset_t off, int vacalign, uint_t flags)
{
	struct proc *p = curproc;
	caddr_t userlimit = (flags & _MAP_LOW32) ?
	    (caddr_t)_userlimit32 : p->p_as->a_userlimit;

	map_addr_proc(addrp, len, off, vacalign, userlimit, curproc, flags);
}

/*ARGSUSED*/
int
map_addr_vacalign_check(caddr_t addr, u_offset_t off)
{
	return (0);
}

/*
 * map_addr_proc() is the routine called when the system is to
 * choose an address for the user.  We will pick an address
 * range which is the highest available below kernelbase.
 *
 * addrp is a value/result parameter.
 *	On input it is a hint from the user to be used in a completely
 *	machine dependent fashion.  We decide to completely ignore this hint.
 *
 *	On output it is NULL if no address can be found in the current
 *	processes address space or else an address that is currently
 *	not mapped for len bytes with a page of red zone on either side.
 *
 *	align is not needed on x86 (it's for viturally addressed caches)
 */
/*ARGSUSED*/
void
map_addr_proc(
	caddr_t *addrp,
	size_t len,
	offset_t off,
	int vacalign,
	caddr_t userlimit,
	struct proc *p,
	uint_t flags)
{
	struct as *as = p->p_as;
	caddr_t addr;
	caddr_t base;
	size_t slen;
	size_t align_amount;

	ASSERT32(userlimit == as->a_userlimit);

	base = p->p_brkbase;
#if defined(__amd64)
	/*
	 * XX64 Yes, this needs more work.
	 */
	if (p->p_model == DATAMODEL_NATIVE) {
		if (userlimit < as->a_userlimit) {
			/*
			 * This happens when a program wants to map
			 * something in a range that's accessible to a
			 * program in a smaller address space.  For example,
			 * a 64-bit program calling mmap32(2) to guarantee
			 * that the returned address is below 4Gbytes.
			 */
			ASSERT((uintptr_t)userlimit < ADDRESS_C(0xffffffff));

			if (userlimit > base)
				slen = userlimit - base;
			else {
				*addrp = NULL;
				return;
			}
		} else {
			/*
			 * XX64 This layout is probably wrong .. but in
			 * the event we make the amd64 address space look
			 * like sparcv9 i.e. with the stack -above- the
			 * heap, this bit of code might even be correct.
			 */
			slen = p->p_usrstack - base -
			    (((size_t)rctl_enforced_value(
			    rctlproc_legacy[RLIMIT_STACK],
			    p->p_rctls, p) + PAGEOFFSET) & PAGEMASK);
		}
	} else
#endif
		slen = userlimit - base;

	len = (len + PAGEOFFSET) & PAGEMASK;

	/*
	 * Redzone for each side of the request. This is done to leave
	 * one page unmapped between segments. This is not required, but
	 * it's useful for the user because if their program strays across
	 * a segment boundary, it will catch a fault immediately making
	 * debugging a little easier.
	 */
	len += 2 * MMU_PAGESIZE;

	/*
	 * figure out what the alignment should be
	 *
	 * XX64 -- is there an ELF_AMD64_MAXPGSZ or is it the same????
	 */
	if (len <= ELF_386_MAXPGSZ) {
		/*
		 * Align virtual addresses to ensure that ELF shared libraries
		 * are mapped with the appropriate alignment constraints by
		 * the run-time linker.
		 */
		align_amount = ELF_386_MAXPGSZ;
	} else {
		int l = mmu.max_page_level;

		while (l && len < LEVEL_SIZE(l))
			--l;

		align_amount = LEVEL_SIZE(l);
	}

	if ((flags & MAP_ALIGN) && ((uintptr_t)*addrp > align_amount))
		align_amount = (uintptr_t)*addrp;

	len += align_amount;

	/*
	 * Look for a large enough hole starting below userlimit.
	 * After finding it, use the upper part.  Addition of PAGESIZE
	 * is for the redzone as described above.
	 */
	if (as_gap(as, len, &base, &slen, AH_HI, NULL) == 0) {
		caddr_t as_addr;

		addr = base + slen - len + MMU_PAGESIZE;
		as_addr = addr;
		/*
		 * Round address DOWN to the alignment amount,
		 * add the offset, and if this address is less
		 * than the original address, add alignment amount.
		 */
		addr = (caddr_t)((uintptr_t)addr & (~(align_amount - 1)));
		addr += (uintptr_t)(off & (align_amount - 1));
		if (addr < as_addr)
			addr += align_amount;

		ASSERT(addr <= (as_addr + align_amount));
		ASSERT(((uintptr_t)addr & (align_amount - 1)) ==
		    ((uintptr_t)(off & (align_amount - 1))));
		*addrp = addr;
	} else {
		*addrp = NULL;	/* no more virtual space */
	}
}

/*
 * Determine whether [base, base+len] contains a valid range of
 * addresses at least minlen long. base and len are adjusted if
 * required to provide a valid range.
 */
/*ARGSUSED3*/
int
valid_va_range(caddr_t *basep, size_t *lenp, size_t minlen, int dir)
{
	uintptr_t hi, lo;

	lo = (uintptr_t)*basep;
	hi = lo + *lenp;

	/*
	 * If hi rolled over the top, try cutting back.
	 */
	if (hi < lo) {
		if (0 - lo + hi < minlen)
			return (0);
		if (0 - lo < minlen)
			return (0);
		*lenp = 0 - lo;
	} else if (hi - lo < minlen) {
		return (0);
	}
#if defined(__amd64)
	/*
	 * Deal with a possible hole in the address range between
	 * hole_start and hole_end that should never be mapped.
	 */
	if (lo < hole_start) {
		if (hi > hole_start) {
			if (hi < hole_end) {
				hi = hole_start;
			} else {
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
			}
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

	*basep = (caddr_t)lo;
	*lenp = hi - lo;
#endif
	return (1);
}

/*
 * Determine whether [addr, addr+len] are valid user addresses.
 */
/*ARGSUSED*/
int
valid_usr_range(caddr_t addr, size_t len, uint_t prot, struct as *as,
    caddr_t userlimit)
{
	caddr_t eaddr = addr + len;

	if (eaddr <= addr || addr >= userlimit || eaddr > userlimit)
		return (RANGE_BADADDR);

#if defined(__amd64)
	/*
	 * Check for the VA hole
	 */
	if (eaddr > (caddr_t)hole_start && addr < (caddr_t)hole_end)
		return (RANGE_BADADDR);
#endif

	return (RANGE_OKAY);
}

/*
 * Return 1 if the page frame is onboard memory, else 0.
 */
int
pf_is_memory(pfn_t pf)
{
	return (address_in_memlist(phys_install, mmu_ptob((uint64_t)pf), 1));
}


/*
 * initialized by page_coloring_init().
 */
uint_t	page_colors;
uint_t	page_colors_mask;
uint_t	page_coloring_shift;
int	cpu_page_colors;
static uint_t	l2_colors;

/*
 * Page freelists and cachelists are dynamically allocated once mnoderangecnt
 * and page_colors are calculated from the l2 cache n-way set size.  Within a
 * mnode range, the page freelist and cachelist are hashed into bins based on
 * color. This makes it easier to search for a page within a specific memory
 * range.
 */
#define	PAGE_COLORS_MIN	16

page_t ****page_freelists;
page_t ***page_cachelists;

/*
 * As the PC architecture evolved memory up was clumped into several
 * ranges for various historical I/O devices to do DMA.
 * < 16Meg - ISA bus
 * < 2Gig - ???
 * < 4Gig - PCI bus or drivers that don't understand PAE mode
 */
static pfn_t arch_memranges[NUM_MEM_RANGES] = {
    0x100000,	/* pfn range for 4G and above */
    0x80000,	/* pfn range for 2G-4G */
    0x01000,	/* pfn range for 16M-2G */
    0x00000,	/* pfn range for 0-16M */
};

/*
 * These are changed during startup if the machine has limited memory.
 */
pfn_t *memranges = &arch_memranges[0];
int nranges = NUM_MEM_RANGES;

/*
 * Used by page layer to know about page sizes
 */
hw_pagesize_t hw_page_array[MAX_NUM_LEVEL + 1];

/*
 * This can be patched via /etc/system to allow old non-PAE aware device
 * drivers to use kmem_alloc'd memory on 32 bit systems with > 4Gig RAM.
 */
#if defined(__i386)
int restricted_kmemalloc = 1;	/* XX64 re-examine with PSARC 2004/405 */
#elif defined(__amd64)
int restricted_kmemalloc = 0;
#endif

kmutex_t	*fpc_mutex[NPC_MUTEX];
kmutex_t	*cpc_mutex[NPC_MUTEX];


/*
 * return the memrange containing pfn
 */
int
memrange_num(pfn_t pfn)
{
	int n;

	for (n = 0; n < nranges - 1; ++n) {
		if (pfn >= memranges[n])
			break;
	}
	return (n);
}

/*
 * return the mnoderange containing pfn
 */
int
pfn_2_mtype(pfn_t pfn)
{
	int	n;

	for (n = mnoderangecnt - 1; n >= 0; n--) {
		if (pfn >= mnoderanges[n].mnr_pfnlo) {
			break;
		}
	}
	return (n);
}

/*
 * is_contigpage_free:
 *	returns a page list of contiguous pages. It minimally has to return
 *	minctg pages. Caller determines minctg based on the scatter-gather
 *	list length.
 *
 *	pfnp is set to the next page frame to search on return.
 */
static page_t *
is_contigpage_free(
	pfn_t *pfnp,
	pgcnt_t *pgcnt,
	pgcnt_t minctg,
	uint64_t pfnseg,
	int iolock)
{
	int	i = 0;
	pfn_t	pfn = *pfnp;
	page_t	*pp;
	page_t	*plist = NULL;

	/*
	 * fail if pfn + minctg crosses a segment boundary.
	 * Adjust for next starting pfn to begin at segment boundary.
	 */

	if (((*pfnp + minctg - 1) & pfnseg) < (*pfnp & pfnseg)) {
		*pfnp = roundup(*pfnp, pfnseg + 1);
		return (NULL);
	}

	do {
retry:
		pp = page_numtopp_nolock(pfn + i);
		if ((pp == NULL) ||
		    (page_trylock(pp, SE_EXCL) == 0)) {
			(*pfnp)++;
			break;
		}
		if (page_pptonum(pp) != pfn + i) {
			page_unlock(pp);
			goto retry;
		}

		if (!(PP_ISFREE(pp))) {
			page_unlock(pp);
			(*pfnp)++;
			break;
		}

		if (!PP_ISAGED(pp)) {
			page_list_sub(pp, PG_CACHE_LIST);
			page_hashout(pp, (kmutex_t *)NULL);
		} else {
			page_list_sub(pp, PG_FREE_LIST);
		}

		if (iolock)
			page_io_lock(pp);
		page_list_concat(&plist, &pp);

		/*
		 * exit loop when pgcnt satisfied or segment boundary reached.
		 */

	} while ((++i < *pgcnt) && ((pfn + i) & pfnseg));

	*pfnp += i;		/* set to next pfn to search */

	if (i >= minctg) {
		*pgcnt -= i;
		return (plist);
	}

	/*
	 * failure: minctg not satisfied.
	 *
	 * if next request crosses segment boundary, set next pfn
	 * to search from the segment boundary.
	 */
	if (((*pfnp + minctg - 1) & pfnseg) < (*pfnp & pfnseg))
		*pfnp = roundup(*pfnp, pfnseg + 1);

	/* clean up any pages already allocated */

	while (plist) {
		pp = plist;
		page_sub(&plist, pp);
		page_list_add(pp, PG_FREE_LIST | PG_LIST_TAIL);
		if (iolock)
			page_io_unlock(pp);
		page_unlock(pp);
	}

	return (NULL);
}

/*
 * verify that pages being returned from allocator have correct DMA attribute
 */
#ifndef DEBUG
#define	check_dma(a, b, c) (0)
#else
static void
check_dma(ddi_dma_attr_t *dma_attr, page_t *pp, int cnt)
{
	if (dma_attr == NULL)
		return;

	while (cnt-- > 0) {
		if (mmu_ptob((uint64_t)pp->p_pagenum) <
		    dma_attr->dma_attr_addr_lo)
			panic("PFN (pp=%p) below dma_attr_addr_lo", pp);
		if (mmu_ptob((uint64_t)pp->p_pagenum) >=
		    dma_attr->dma_attr_addr_hi)
			panic("PFN (pp=%p) above dma_attr_addr_hi", pp);
		pp = pp->p_next;
	}
}
#endif

static kmutex_t	contig_lock;

#define	CONTIG_LOCK()	mutex_enter(&contig_lock);
#define	CONTIG_UNLOCK()	mutex_exit(&contig_lock);

#define	PFN_16M		(mmu_btop((uint64_t)0x1000000))

static page_t *
page_get_contigpage(pgcnt_t *pgcnt, ddi_dma_attr_t *mattr, int iolock)
{
	pfn_t		pfn;
	int		sgllen;
	uint64_t	pfnseg;
	pgcnt_t		minctg;
	page_t		*pplist = NULL, *plist;
	uint64_t	lo, hi;
	pgcnt_t		pfnalign = 0;
	static pfn_t	startpfn;
	static pgcnt_t	lastctgcnt;
	uintptr_t	align;

	CONTIG_LOCK();

	if (mattr) {
		lo = mmu_btop((mattr->dma_attr_addr_lo + MMU_PAGEOFFSET));
		hi = mmu_btop(mattr->dma_attr_addr_hi);
		if (hi >= physmax)
			hi = physmax - 1;
		sgllen = mattr->dma_attr_sgllen;
		pfnseg = mmu_btop(mattr->dma_attr_seg);

		align = maxbit(mattr->dma_attr_align, mattr->dma_attr_minxfer);
		if (align > MMU_PAGESIZE)
			pfnalign = mmu_btop(align);

		/*
		 * in order to satisfy the request, must minimally
		 * acquire minctg contiguous pages
		 */
		minctg = howmany(*pgcnt, sgllen);

		ASSERT(hi >= lo);

		/*
		 * start from where last searched if the minctg >= lastctgcnt
		 */
		if (minctg < lastctgcnt || startpfn < lo || startpfn > hi)
			startpfn = lo;
	} else {
		hi = physmax - 1;
		lo = 0;
		sgllen = 1;
		pfnseg = mmu.highest_pfn;
		minctg = *pgcnt;

		if (minctg < lastctgcnt)
			startpfn = lo;
	}
	lastctgcnt = minctg;

	ASSERT(pfnseg + 1 >= (uint64_t)minctg);

	/* conserve 16m memory - start search above 16m when possible */
	if (hi > PFN_16M && startpfn < PFN_16M)
		startpfn = PFN_16M;

	pfn = startpfn;
	if (pfnalign)
		pfn = P2ROUNDUP(pfn, pfnalign);

	while (pfn + minctg - 1 <= hi) {

		plist = is_contigpage_free(&pfn, pgcnt, minctg, pfnseg, iolock);
		if (plist) {
			page_list_concat(&pplist, &plist);
			sgllen--;
			/*
			 * return when contig pages no longer needed
			 */
			if (!*pgcnt || ((*pgcnt <= sgllen) && !pfnalign)) {
				startpfn = pfn;
				CONTIG_UNLOCK();
				check_dma(mattr, pplist, *pgcnt);
				return (pplist);
			}
			minctg = howmany(*pgcnt, sgllen);
		}
		if (pfnalign)
			pfn = P2ROUNDUP(pfn, pfnalign);
	}

	/* cannot find contig pages in specified range */
	if (startpfn == lo) {
		CONTIG_UNLOCK();
		return (NULL);
	}

	/* did not start with lo previously */
	pfn = lo;
	if (pfnalign)
		pfn = P2ROUNDUP(pfn, pfnalign);

	/* allow search to go above startpfn */
	while (pfn < startpfn) {

		plist = is_contigpage_free(&pfn, pgcnt, minctg, pfnseg, iolock);
		if (plist != NULL) {

			page_list_concat(&pplist, &plist);
			sgllen--;

			/*
			 * return when contig pages no longer needed
			 */
			if (!*pgcnt || ((*pgcnt <= sgllen) && !pfnalign)) {
				startpfn = pfn;
				CONTIG_UNLOCK();
				check_dma(mattr, pplist, *pgcnt);
				return (pplist);
			}
			minctg = howmany(*pgcnt, sgllen);
		}
		if (pfnalign)
			pfn = P2ROUNDUP(pfn, pfnalign);
	}
	CONTIG_UNLOCK();
	return (NULL);
}

/*
 * combine mem_node_config and memrange memory ranges into one data
 * structure to be used for page list management.
 *
 * mnode_range_cnt() calculates the number of memory ranges for mnode and
 * memranges[]. Used to determine the size of page lists and mnoderanges.
 *
 * mnode_range_setup() initializes mnoderanges.
 */
mnoderange_t	*mnoderanges;
int		mnoderangecnt;
int		mtype4g;

int
mnode_range_cnt()
{
	int	mri;
	int	mnrcnt = 0;
	int	mnode;

	for (mnode = 0; mnode < max_mem_nodes; mnode++) {
		if (mem_node_config[mnode].exists == 0)
			continue;

		mri = nranges - 1;

		/* find the memranges index below contained in mnode range */

		while (MEMRANGEHI(mri) < mem_node_config[mnode].physbase)
			mri--;

		/*
		 * increment mnode range counter when memranges or mnode
		 * boundary is reached.
		 */
		while (mri >= 0 &&
		    mem_node_config[mnode].physmax >= MEMRANGELO(mri)) {
			mnrcnt++;
			if (mem_node_config[mnode].physmax > MEMRANGEHI(mri))
				mri--;
			else
				break;
		}
	}
	return (mnrcnt);
}

void
mnode_range_setup(mnoderange_t *mnoderanges)
{
	int	mnode, mri;

	for (mnode = 0; mnode < max_mem_nodes; mnode++) {
		if (mem_node_config[mnode].exists == 0)
			continue;

		mri = nranges - 1;

		while (MEMRANGEHI(mri) < mem_node_config[mnode].physbase)
			mri--;

		while (mri >= 0 && mem_node_config[mnode].physmax >=
		    MEMRANGELO(mri)) {
			mnoderanges->mnr_pfnlo =
			    MAX(MEMRANGELO(mri),
				mem_node_config[mnode].physbase);
			mnoderanges->mnr_pfnhi =
			    MIN(MEMRANGEHI(mri),
				mem_node_config[mnode].physmax);
			mnoderanges->mnr_mnode = mnode;
			mnoderanges->mnr_memrange = mri;
			mnoderanges++;
			if (mem_node_config[mnode].physmax > MEMRANGEHI(mri))
				mri--;
			else
				break;
		}
	}
}

/*
 * Determine if the mnode range specified in mtype contains memory belonging
 * to memory node mnode.  If flags & PGI_MT_RANGE is set then mtype contains
 * the range of indices to 0 or 4g.
 *
 * Return first mnode range type index found otherwise return -1 if none found.
 */
int
mtype_func(int mnode, int mtype, uint_t flags)
{
	if (flags & PGI_MT_RANGE) {
		int	mtlim = 0;	/* default to PGI_MT_RANGEO */

		if (flags & PGI_MT_NEXT)
			mtype--;
		if (flags & PGI_MT_RANGE4G)
			mtlim = mtype4g + 1;
		while (mtype >= mtlim) {
			if (mnoderanges[mtype].mnr_mnode == mnode)
				return (mtype);
			mtype--;
		}
	} else {
		if (mnoderanges[mtype].mnr_mnode == mnode)
			return (mtype);
	}
	return (-1);
}

/*
 * Returns the free page count for mnode
 */
int
mnode_pgcnt(int mnode)
{
	int	mtype = mnoderangecnt - 1;
	int	flags = PGI_MT_RANGE0;
	pgcnt_t	pgcnt = 0;

	mtype = mtype_func(mnode, mtype, flags);

	while (mtype != -1) {
		pgcnt += (mnoderanges[mtype].mnr_mt_flpgcnt +
		    mnoderanges[mtype].mnr_mt_lgpgcnt +
		    mnoderanges[mtype].mnr_mt_clpgcnt);
		mtype = mtype_func(mnode, mtype, flags | PGI_MT_NEXT);
	}
	return (pgcnt);
}

/*
 * Initialize page coloring variables based on the l2 cache parameters.
 * Calculate and return memory needed for page coloring data structures.
 */
size_t
page_coloring_init(uint_t l2_sz, int l2_linesz, int l2_assoc)
{
	size_t	colorsz = 0;
	int	i;
	int	colors;

	/*
	 * Reduce the memory ranges lists if we don't have large amounts
	 * of memory. This avoids searching known empty free lists.
	 */
	i = memrange_num(physmax);
	memranges += i;
	nranges -= i;
#if defined(__i386)
	if (i > 0)
		restricted_kmemalloc = 0;
#endif
	/* physmax greater than 4g */
	if (i == 0)
		physmax4g = 1;

	/*
	 * setup pagesize for generic page layer
	 */
	for (i = 0; i <= mmu.max_page_level; ++i) {
		hw_page_array[i].hp_size = LEVEL_SIZE(i);
		hw_page_array[i].hp_shift = LEVEL_SHIFT(i);
		hw_page_array[i].hp_pgcnt = LEVEL_SIZE(i) >> LEVEL_SHIFT(0);
	}

	ASSERT(ISP2(l2_sz));
	ASSERT(ISP2(l2_linesz));
	ASSERT(l2_sz > MMU_PAGESIZE);

	/* l2_assoc is 0 for fully associative l2 cache */
	if (l2_assoc)
		l2_colors = MAX(1, l2_sz / (l2_assoc * MMU_PAGESIZE));
	else
		l2_colors = 1;

	/* for scalability, configure at least PAGE_COLORS_MIN color bins */
	page_colors = MAX(l2_colors, PAGE_COLORS_MIN);

	/*
	 * cpu_page_colors is non-zero when a page color may be spread across
	 * multiple bins.
	 */
	if (l2_colors < page_colors)
		cpu_page_colors = l2_colors;

	ASSERT(ISP2(page_colors));

	page_colors_mask = page_colors - 1;

	ASSERT(ISP2(CPUSETSIZE()));
	page_coloring_shift = lowbit(CPUSETSIZE());

	/* size for mnoderanges */
	mnoderangecnt = mnode_range_cnt();
	colorsz = mnoderangecnt * sizeof (mnoderange_t);

	/* size for fpc_mutex and cpc_mutex */
	colorsz += (2 * max_mem_nodes * sizeof (kmutex_t) * NPC_MUTEX);

	/* size of page_freelists */
	colorsz += mnoderangecnt * sizeof (page_t ***);
	colorsz += mnoderangecnt * mmu_page_sizes * sizeof (page_t **);

	for (i = 0; i < mmu_page_sizes; i++) {
		colors = page_get_pagecolors(i);
		colorsz += mnoderangecnt * colors * sizeof (page_t *);
	}

	/* size of page_cachelists */
	colorsz += mnoderangecnt * sizeof (page_t **);
	colorsz += mnoderangecnt * page_colors * sizeof (page_t *);

	return (colorsz);
}

/*
 * Called once at startup to configure page_coloring data structures and
 * does the 1st page_free()/page_freelist_add().
 */
void
page_coloring_setup(caddr_t pcmemaddr)
{
	int	i;
	int	j;
	int	k;
	caddr_t	addr;
	int	colors;

	/*
	 * do page coloring setup
	 */
	addr = pcmemaddr;

	mnoderanges = (mnoderange_t *)addr;
	addr += (mnoderangecnt * sizeof (mnoderange_t));

	mnode_range_setup(mnoderanges);

	if (physmax4g)
		mtype4g = pfn_2_mtype(0xfffff);

	for (k = 0; k < NPC_MUTEX; k++) {
		fpc_mutex[k] = (kmutex_t *)addr;
		addr += (max_mem_nodes * sizeof (kmutex_t));
	}
	for (k = 0; k < NPC_MUTEX; k++) {
		cpc_mutex[k] = (kmutex_t *)addr;
		addr += (max_mem_nodes * sizeof (kmutex_t));
	}
	page_freelists = (page_t ****)addr;
	addr += (mnoderangecnt * sizeof (page_t ***));

	page_cachelists = (page_t ***)addr;
	addr += (mnoderangecnt * sizeof (page_t **));

	for (i = 0; i < mnoderangecnt; i++) {
		page_freelists[i] = (page_t ***)addr;
		addr += (mmu_page_sizes * sizeof (page_t **));

		for (j = 0; j < mmu_page_sizes; j++) {
			colors = page_get_pagecolors(j);
			page_freelists[i][j] = (page_t **)addr;
			addr += (colors * sizeof (page_t *));
		}
		page_cachelists[i] = (page_t **)addr;
		addr += (page_colors * sizeof (page_t *));
	}
}

/*ARGSUSED*/
int
bp_color(struct buf *bp)
{
	return (0);
}

/*
 * get a page from any list with the given mnode
 */
page_t *
page_get_mnode_anylist(ulong_t origbin, uchar_t szc, uint_t flags,
    int mnode, int mtype, ddi_dma_attr_t *dma_attr)
{
	kmutex_t	*pcm;
	int		i;
	page_t		*pp;
	page_t		*first_pp;
	uint64_t	pgaddr;
	ulong_t		bin;
	int		mtypestart;

	VM_STAT_ADD(pga_vmstats.pgma_alloc);

	ASSERT((flags & PG_MATCH_COLOR) == 0);
	ASSERT(szc == 0);
	ASSERT(dma_attr != NULL);


	MTYPE_START(mnode, mtype, flags);
	if (mtype < 0) {
		VM_STAT_ADD(pga_vmstats.pgma_allocempty);
		return (NULL);
	}

	mtypestart = mtype;

	bin = origbin;

	/*
	 * check up to page_colors + 1 bins - origbin may be checked twice
	 * because of BIN_STEP skip
	 */
	do {
		i = 0;
		while (i <= page_colors) {
			if (PAGE_FREELISTS(mnode, szc, bin, mtype) == NULL)
				goto nextfreebin;

			pcm = PC_BIN_MUTEX(mnode, bin, PG_FREE_LIST);
			mutex_enter(pcm);
			pp = PAGE_FREELISTS(mnode, szc, bin, mtype);
			first_pp = pp;
			while (pp != NULL) {
				if (page_trylock(pp, SE_EXCL) == 0) {
					pp = pp->p_next;
					if (pp == first_pp) {
						pp = NULL;
					}
					continue;
				}

				ASSERT(PP_ISFREE(pp));
				ASSERT(PP_ISAGED(pp));
				ASSERT(pp->p_vnode == NULL);
				ASSERT(pp->p_hash == NULL);
				ASSERT(pp->p_offset == (u_offset_t)-1);
				ASSERT(pp->p_szc == szc);
				ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) == mnode);
				/* check if page within DMA attributes */
				pgaddr = mmu_ptob((uint64_t)(pp->p_pagenum));

				if ((pgaddr >= dma_attr->dma_attr_addr_lo) &&
				    (pgaddr + MMU_PAGESIZE - 1 <=
				    dma_attr->dma_attr_addr_hi)) {
					break;
				}

				/* continue looking */
				page_unlock(pp);
				pp = pp->p_next;
				if (pp == first_pp)
					pp = NULL;

			}
			if (pp != NULL) {
				ASSERT(mtype == PP_2_MTYPE(pp));
				ASSERT(pp->p_szc == 0);

				/* found a page with specified DMA attributes */
				page_sub(&PAGE_FREELISTS(mnode, szc, bin,
				    mtype), pp);
				page_ctr_sub(mnode, mtype, pp, PG_FREE_LIST);

				if ((PP_ISFREE(pp) == 0) ||
				    (PP_ISAGED(pp) == 0)) {
					cmn_err(CE_PANIC, "page %p is not free",
					    (void *)pp);
				}

				mutex_exit(pcm);
				check_dma(dma_attr, pp, 1);
				VM_STAT_ADD(pga_vmstats.pgma_allocok);
				return (pp);
			}
			mutex_exit(pcm);
nextfreebin:
			pp = page_freelist_fill(szc, bin, mnode, mtype,
			    mmu_btop(dma_attr->dma_attr_addr_hi + 1));
			if (pp)
				return (pp);

			/* try next bin */
			bin += (i == 0) ? BIN_STEP : 1;
			bin &= page_colors_mask;
			i++;
		}
		MTYPE_NEXT(mnode, mtype, flags);
	} while (mtype >= 0);

	/* failed to find a page in the freelist; try it in the cachelist */

	/* reset mtype start for cachelist search */
	mtype = mtypestart;
	ASSERT(mtype >= 0);

	/* start with the bin of matching color */
	bin = origbin;

	do {
		for (i = 0; i <= page_colors; i++) {
			if (PAGE_CACHELISTS(mnode, bin, mtype) == NULL)
				goto nextcachebin;
			pcm = PC_BIN_MUTEX(mnode, bin, PG_CACHE_LIST);
			mutex_enter(pcm);
			pp = PAGE_CACHELISTS(mnode, bin, mtype);
			first_pp = pp;
			while (pp != NULL) {
				if (page_trylock(pp, SE_EXCL) == 0) {
					pp = pp->p_next;
					if (pp == first_pp)
						break;
					continue;
				}
				ASSERT(pp->p_vnode);
				ASSERT(PP_ISAGED(pp) == 0);
				ASSERT(pp->p_szc == 0);
				ASSERT(PFN_2_MEM_NODE(pp->p_pagenum) == mnode);

				/* check if page within DMA attributes */

				pgaddr = ptob((uint64_t)(pp->p_pagenum));

				if ((pgaddr >= dma_attr->dma_attr_addr_lo) &&
				    (pgaddr + MMU_PAGESIZE - 1 <=
				    dma_attr->dma_attr_addr_hi)) {
					break;
				}

				/* continue looking */
				page_unlock(pp);
				pp = pp->p_next;
				if (pp == first_pp)
					pp = NULL;
			}

			if (pp != NULL) {
				ASSERT(mtype == PP_2_MTYPE(pp));
				ASSERT(pp->p_szc == 0);

				/* found a page with specified DMA attributes */
				page_sub(&PAGE_CACHELISTS(mnode, bin,
				    mtype), pp);
				page_ctr_sub(mnode, mtype, pp, PG_CACHE_LIST);

				mutex_exit(pcm);
				ASSERT(pp->p_vnode);
				ASSERT(PP_ISAGED(pp) == 0);
				check_dma(dma_attr, pp, 1);
				VM_STAT_ADD(pga_vmstats.pgma_allocok);
				return (pp);
			}
			mutex_exit(pcm);
nextcachebin:
			bin += (i == 0) ? BIN_STEP : 1;
			bin &= page_colors_mask;
		}
		MTYPE_NEXT(mnode, mtype, flags);
	} while (mtype >= 0);

	VM_STAT_ADD(pga_vmstats.pgma_allocfailed);
	return (NULL);
}

/*
 * This function is similar to page_get_freelist()/page_get_cachelist()
 * but it searches both the lists to find a page with the specified
 * color (or no color) and DMA attributes. The search is done in the
 * freelist first and then in the cache list within the highest memory
 * range (based on DMA attributes) before searching in the lower
 * memory ranges.
 *
 * Note: This function is called only by page_create_io().
 */
/*ARGSUSED*/
page_t *
page_get_anylist(struct vnode *vp, u_offset_t off, struct as *as, caddr_t vaddr,
    size_t size, uint_t flags, ddi_dma_attr_t *dma_attr, lgrp_t	*lgrp)
{
	uint_t		bin;
	int		mtype;
	page_t		*pp;
	int		n;
	int		m;
	int		szc;
	int		fullrange;
	int		mnode;
	int		local_failed_stat = 0;
	lgrp_mnode_cookie_t	lgrp_cookie;

	VM_STAT_ADD(pga_vmstats.pga_alloc);

	/* only base pagesize currently supported */
	if (size != MMU_PAGESIZE)
		return (NULL);

	/*
	 * If we're passed a specific lgroup, we use it.  Otherwise,
	 * assume first-touch placement is desired.
	 */
	if (!LGRP_EXISTS(lgrp))
		lgrp = lgrp_home_lgrp();

	/* LINTED */
	AS_2_BIN(as, seg, vp, vaddr, bin);

	/*
	 * Only hold one freelist or cachelist lock at a time, that way we
	 * can start anywhere and not have to worry about lock
	 * ordering.
	 */
	if (dma_attr == NULL) {
		n = 0;
		m = mnoderangecnt - 1;
		fullrange = 1;
		VM_STAT_ADD(pga_vmstats.pga_nulldmaattr);
	} else {
		pfn_t pfnlo = mmu_btop(dma_attr->dma_attr_addr_lo);
		pfn_t pfnhi = mmu_btop(dma_attr->dma_attr_addr_hi);

		/*
		 * We can guarantee alignment only for page boundary.
		 */
		if (dma_attr->dma_attr_align > MMU_PAGESIZE)
			return (NULL);

		n = pfn_2_mtype(pfnlo);
		m = pfn_2_mtype(pfnhi);

		fullrange = ((pfnlo == mnoderanges[n].mnr_pfnlo) &&
		    (pfnhi >= mnoderanges[m].mnr_pfnhi));
	}
	VM_STAT_COND_ADD(fullrange == 0, pga_vmstats.pga_notfullrange);

	if (n > m)
		return (NULL);

	szc = 0;

	/* cylcing thru mtype handled by RANGE0 if n == 0 */
	if (n == 0) {
		flags |= PGI_MT_RANGE0;
		n = m;
	}

	/*
	 * Try local memory node first, but try remote if we can't
	 * get a page of the right color.
	 */
	LGRP_MNODE_COOKIE_INIT(lgrp_cookie, lgrp, LGRP_SRCH_HIER);
	while ((mnode = lgrp_memnode_choose(&lgrp_cookie)) >= 0) {
		/*
		 * allocate pages from high pfn to low.
		 */
		for (mtype = m; mtype >= n; mtype--) {
			if (fullrange != 0) {
				pp = page_get_mnode_freelist(mnode,
				    bin, mtype, szc, flags);
				if (pp == NULL) {
					pp = page_get_mnode_cachelist(
						bin, flags, mnode, mtype);
				}
			} else {
				pp = page_get_mnode_anylist(bin, szc,
				    flags, mnode, mtype, dma_attr);
			}
			if (pp != NULL) {
				VM_STAT_ADD(pga_vmstats.pga_allocok);
				check_dma(dma_attr, pp, 1);
				return (pp);
			}
		}
		if (!local_failed_stat) {
			lgrp_stat_add(lgrp->lgrp_id, LGRP_NUM_ALLOC_FAIL, 1);
			local_failed_stat = 1;
		}
	}
	VM_STAT_ADD(pga_vmstats.pga_allocfailed);

	return (NULL);
}

/*
 * page_create_io()
 *
 * This function is a copy of page_create_va() with an additional
 * argument 'mattr' that specifies DMA memory requirements to
 * the page list functions. This function is used by the segkmem
 * allocator so it is only to create new pages (i.e PG_EXCL is
 * set).
 *
 * Note: This interface is currently used by x86 PSM only and is
 *	 not fully specified so the commitment level is only for
 *	 private interface specific to x86. This interface uses PSM
 *	 specific page_get_anylist() interface.
 */

#define	PAGE_HASH_SEARCH(index, pp, vp, off) { \
	for ((pp) = page_hash[(index)]; (pp); (pp) = (pp)->p_hash) { \
		if ((pp)->p_vnode == (vp) && (pp)->p_offset == (off)) \
			break; \
	} \
}


page_t *
page_create_io(
	struct vnode	*vp,
	u_offset_t	off,
	uint_t		bytes,
	uint_t		flags,
	struct as	*as,
	caddr_t		vaddr,
	ddi_dma_attr_t	*mattr)	/* DMA memory attributes if any */
{
	page_t		*plist = NULL;
	uint_t		plist_len = 0;
	pgcnt_t		npages;
	page_t		*npp = NULL;
	uint_t		pages_req;
	page_t		*pp;
	kmutex_t	*phm = NULL;
	uint_t		index;

	TRACE_4(TR_FAC_VM, TR_PAGE_CREATE_START,
		"page_create_start:vp %p off %llx bytes %u flags %x",
		vp, off, bytes, flags);

	ASSERT((flags & ~(PG_EXCL | PG_WAIT | PG_PHYSCONTIG)) == 0);

	pages_req = npages = mmu_btopr(bytes);

	/*
	 * Do the freemem and pcf accounting.
	 */
	if (!page_create_wait(npages, flags)) {
		return (NULL);
	}

	TRACE_2(TR_FAC_VM, TR_PAGE_CREATE_SUCCESS,
		"page_create_success:vp %p off %llx",
		vp, off);

	/*
	 * If satisfying this request has left us with too little
	 * memory, start the wheels turning to get some back.  The
	 * first clause of the test prevents waking up the pageout
	 * daemon in situations where it would decide that there's
	 * nothing to do.
	 */
	if (nscan < desscan && freemem < minfree) {
		TRACE_1(TR_FAC_VM, TR_PAGEOUT_CV_SIGNAL,
			"pageout_cv_signal:freemem %ld", freemem);
		cv_signal(&proc_pageout->p_cv);
	}

	if (flags & PG_PHYSCONTIG) {

		plist = page_get_contigpage(&npages, mattr, 1);
		if (plist == NULL) {
			page_create_putback(npages);
			return (NULL);
		}

		pp = plist;

		do {
			if (!page_hashin(pp, vp, off, NULL)) {
				panic("pg_creat_io: hashin failed %p %p %llx",
				    (void *)pp, (void *)vp, off);
			}
			VM_STAT_ADD(page_create_new);
			off += MMU_PAGESIZE;
			PP_CLRFREE(pp);
			PP_CLRAGED(pp);
			page_set_props(pp, P_REF);
			pp = pp->p_next;
		} while (pp != plist);

		if (!npages) {
			check_dma(mattr, plist, pages_req);
			return (plist);
		} else {
			vaddr += (pages_req - npages) << MMU_PAGESHIFT;
		}

		/*
		 * fall-thru:
		 *
		 * page_get_contigpage returns when npages <= sgllen.
		 * Grab the rest of the non-contig pages below from anylist.
		 */
	}

	/*
	 * Loop around collecting the requested number of pages.
	 * Most of the time, we have to `create' a new page. With
	 * this in mind, pull the page off the free list before
	 * getting the hash lock.  This will minimize the hash
	 * lock hold time, nesting, and the like.  If it turns
	 * out we don't need the page, we put it back at the end.
	 */
	while (npages--) {
		phm = NULL;

		index = PAGE_HASH_FUNC(vp, off);
top:
		ASSERT(phm == NULL);
		ASSERT(index == PAGE_HASH_FUNC(vp, off));
		ASSERT(MUTEX_NOT_HELD(page_vnode_mutex(vp)));

		if (npp == NULL) {
			/*
			 * Try to get the page of any color either from
			 * the freelist or from the cache list.
			 */
			npp = page_get_anylist(vp, off, as, vaddr, MMU_PAGESIZE,
			    flags & ~PG_MATCH_COLOR, mattr, NULL);
			if (npp == NULL) {
				if (mattr == NULL) {
					/*
					 * Not looking for a special page;
					 * panic!
					 */
					panic("no page found %d", (int)npages);
				}
				/*
				 * No page found! This can happen
				 * if we are looking for a page
				 * within a specific memory range
				 * for DMA purposes. If PG_WAIT is
				 * specified then we wait for a
				 * while and then try again. The
				 * wait could be forever if we
				 * don't get the page(s) we need.
				 *
				 * Note: XXX We really need a mechanism
				 * to wait for pages in the desired
				 * range. For now, we wait for any
				 * pages and see if we can use it.
				 */

				if ((mattr != NULL) && (flags & PG_WAIT)) {
					delay(10);
					goto top;
				}

				goto fail; /* undo accounting stuff */
			}

			if (PP_ISAGED(npp) == 0) {
				/*
				 * Since this page came from the
				 * cachelist, we must destroy the
				 * old vnode association.
				 */
				page_hashout(npp, (kmutex_t *)NULL);
			}
		}

		/*
		 * We own this page!
		 */
		ASSERT(PAGE_EXCL(npp));
		ASSERT(npp->p_vnode == NULL);
		ASSERT(!hat_page_is_mapped(npp));
		PP_CLRFREE(npp);
		PP_CLRAGED(npp);

		/*
		 * Here we have a page in our hot little mits and are
		 * just waiting to stuff it on the appropriate lists.
		 * Get the mutex and check to see if it really does
		 * not exist.
		 */
		phm = PAGE_HASH_MUTEX(index);
		mutex_enter(phm);
		PAGE_HASH_SEARCH(index, pp, vp, off);
		if (pp == NULL) {
			VM_STAT_ADD(page_create_new);
			pp = npp;
			npp = NULL;
			if (!page_hashin(pp, vp, off, phm)) {
				/*
				 * Since we hold the page hash mutex and
				 * just searched for this page, page_hashin
				 * had better not fail.  If it does, that
				 * means somethread did not follow the
				 * page hash mutex rules.  Panic now and
				 * get it over with.  As usual, go down
				 * holding all the locks.
				 */
				ASSERT(MUTEX_HELD(phm));
				panic("page_create: hashin fail %p %p %llx %p",
				    (void *)pp, (void *)vp, off, (void *)phm);

			}
			ASSERT(MUTEX_HELD(phm));
			mutex_exit(phm);
			phm = NULL;

			/*
			 * Hat layer locking need not be done to set
			 * the following bits since the page is not hashed
			 * and was on the free list (i.e., had no mappings).
			 *
			 * Set the reference bit to protect
			 * against immediate pageout
			 *
			 * XXXmh modify freelist code to set reference
			 * bit so we don't have to do it here.
			 */
			page_set_props(pp, P_REF);
		} else {
			ASSERT(MUTEX_HELD(phm));
			mutex_exit(phm);
			phm = NULL;
			/*
			 * NOTE: This should not happen for pages associated
			 *	 with kernel vnode 'kvp'.
			 */
			/* XX64 - to debug why this happens! */
			ASSERT(vp != &kvp);
			if (vp == &kvp)
				cmn_err(CE_NOTE,
				    "page_create: page not expected "
				    "in hash list for kernel vnode - pp 0x%p",
				    (void *)pp);
			VM_STAT_ADD(page_create_exists);
			goto fail;
		}

		/*
		 * Got a page!  It is locked.  Acquire the i/o
		 * lock since we are going to use the p_next and
		 * p_prev fields to link the requested pages together.
		 */
		page_io_lock(pp);
		page_add(&plist, pp);
		plist = plist->p_next;
		off += MMU_PAGESIZE;
		vaddr += MMU_PAGESIZE;
	}

	check_dma(mattr, plist, pages_req);
	return (plist);

fail:
	if (npp != NULL) {
		/*
		 * Did not need this page after all.
		 * Put it back on the free list.
		 */
		VM_STAT_ADD(page_create_putbacks);
		PP_SETFREE(npp);
		PP_SETAGED(npp);
		npp->p_offset = (u_offset_t)-1;
		page_list_add(npp, PG_FREE_LIST | PG_LIST_TAIL);
		page_unlock(npp);
	}

	/*
	 * Give up the pages we already got.
	 */
	while (plist != NULL) {
		pp = plist;
		page_sub(&plist, pp);
		page_io_unlock(pp);
		plist_len++;
		/*LINTED: constant in conditional ctx*/
		VN_DISPOSE(pp, B_INVAL, 0, kcred);
	}

	/*
	 * VN_DISPOSE does freemem accounting for the pages in plist
	 * by calling page_free. So, we need to undo the pcf accounting
	 * for only the remaining pages.
	 */
	VM_STAT_ADD(page_create_putbacks);
	page_create_putback(pages_req - plist_len);

	return (NULL);
}


/*
 * Copy the data from the physical page represented by "frompp" to
 * that represented by "topp". ppcopy uses CPU->cpu_caddr1 and
 * CPU->cpu_caddr2.  It assumes that no one uses either map at interrupt
 * level and no one sleeps with an active mapping there.
 *
 * Note that the ref/mod bits in the page_t's are not affected by
 * this operation, hence it is up to the caller to update them appropriately.
 */
void
ppcopy(page_t *frompp, page_t *topp)
{
	caddr_t		pp_addr1;
	caddr_t		pp_addr2;
	void		*pte1;
	void		*pte2;
	kmutex_t	*ppaddr_mutex;

	ASSERT_STACK_ALIGNED();
	ASSERT(PAGE_LOCKED(frompp));
	ASSERT(PAGE_LOCKED(topp));

	if (kpm_enable) {
		pp_addr1 = hat_kpm_page2va(frompp, 0);
		pp_addr2 = hat_kpm_page2va(topp, 0);
		kpreempt_disable();
	} else {
		/*
		 * disable pre-emption so that CPU can't change
		 */
		kpreempt_disable();

		pp_addr1 = CPU->cpu_caddr1;
		pp_addr2 = CPU->cpu_caddr2;
		pte1 = (void *)CPU->cpu_caddr1pte;
		pte2 = (void *)CPU->cpu_caddr2pte;

		ppaddr_mutex = &CPU->cpu_ppaddr_mutex;
		mutex_enter(ppaddr_mutex);

		hat_mempte_remap(page_pptonum(frompp), pp_addr1, pte1,
		    PROT_READ | HAT_STORECACHING_OK, HAT_LOAD_NOCONSIST);
		hat_mempte_remap(page_pptonum(topp), pp_addr2, pte2,
		    PROT_READ | PROT_WRITE | HAT_STORECACHING_OK,
		    HAT_LOAD_NOCONSIST);
	}

	if (use_sse_pagecopy)
		hwblkpagecopy(pp_addr1, pp_addr2);
	else
		bcopy(pp_addr1, pp_addr2, PAGESIZE);

	if (!kpm_enable)
		mutex_exit(ppaddr_mutex);
	kpreempt_enable();
}

/*
 * Zero the physical page from off to off + len given by `pp'
 * without changing the reference and modified bits of page.
 *
 * We use this using CPU private page address #2, see ppcopy() for more info.
 * pagezero() must not be called at interrupt level.
 */
void
pagezero(page_t *pp, uint_t off, uint_t len)
{
	caddr_t		pp_addr2;
	void		*pte2;
	kmutex_t	*ppaddr_mutex;

	ASSERT_STACK_ALIGNED();
	ASSERT(len <= MMU_PAGESIZE);
	ASSERT(off <= MMU_PAGESIZE);
	ASSERT(off + len <= MMU_PAGESIZE);
	ASSERT(PAGE_LOCKED(pp));

	if (kpm_enable) {
		pp_addr2 = hat_kpm_page2va(pp, 0);
		kpreempt_disable();
	} else {
		kpreempt_disable();

		pp_addr2 = CPU->cpu_caddr2;
		pte2 = (void *)CPU->cpu_caddr2pte;

		ppaddr_mutex = &CPU->cpu_ppaddr_mutex;
		mutex_enter(ppaddr_mutex);

		hat_mempte_remap(page_pptonum(pp), pp_addr2, pte2,
		    PROT_READ | PROT_WRITE | HAT_STORECACHING_OK,
		    HAT_LOAD_NOCONSIST);
	}

	if (use_sse_pagezero)
		hwblkclr(pp_addr2 + off, len);
	else
		bzero(pp_addr2 + off, len);

	if (!kpm_enable)
		mutex_exit(ppaddr_mutex);
	kpreempt_enable();
}

/*
 * Platform-dependent page scrub call.
 */
void
pagescrub(page_t *pp, uint_t off, uint_t len)
{
	/*
	 * For now, we rely on the fact that pagezero() will
	 * always clear UEs.
	 */
	pagezero(pp, off, len);
}

/*
 * set up two private addresses for use on a given CPU for use in ppcopy()
 */
void
setup_vaddr_for_ppcopy(struct cpu *cpup)
{
	void *addr;
	void *pte;

	addr = vmem_alloc(heap_arena, mmu_ptob(1), VM_SLEEP);
	pte = hat_mempte_setup(addr);
	cpup->cpu_caddr1 = addr;
	cpup->cpu_caddr1pte = (pteptr_t)pte;

	addr = vmem_alloc(heap_arena, mmu_ptob(1), VM_SLEEP);
	pte = hat_mempte_setup(addr);
	cpup->cpu_caddr2 = addr;
	cpup->cpu_caddr2pte = (pteptr_t)pte;

	mutex_init(&cpup->cpu_ppaddr_mutex, NULL, MUTEX_DEFAULT, NULL);
}


/*
 * Create the pageout scanner thread. The thread has to
 * start at procedure with process pp and priority pri.
 */
void
pageout_init(void (*procedure)(), proc_t *pp, pri_t pri)
{
	(void) thread_create(NULL, 0, procedure, NULL, 0, pp, TS_RUN, pri);
}

/*
 * Function for flushing D-cache when performing module relocations
 * to an alternate mapping.  Unnecessary on Intel / AMD platforms.
 */
void
dcache_flushall()
{}
