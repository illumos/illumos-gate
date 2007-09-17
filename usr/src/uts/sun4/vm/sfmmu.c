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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <vm/hat.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <sys/pte.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/machparam.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/mmu.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/lgrp.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/bitmap.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <vm/seg_kpm.h>
#include <vm/rm.h>
#include <vm/vm_dep.h>
#include <sys/t_lock.h>
#include <sys/vm_machparam.h>
#include <sys/promif.h>
#include <sys/prom_isa.h>
#include <sys/prom_plat.h>
#include <sys/prom_debug.h>
#include <sys/privregs.h>
#include <sys/bootconf.h>
#include <sys/memlist.h>
#include <sys/memlist_plat.h>
#include <sys/cpu_module.h>
#include <sys/reboot.h>
#include <sys/kdi.h>

/*
 * Static routines
 */
static void	sfmmu_map_prom_mappings(struct translation *, size_t);
static struct translation *read_prom_mappings(size_t *);
static void	sfmmu_reloc_trap_handler(void *, void *, size_t);

/*
 * External routines
 */
extern void sfmmu_remap_kernel(void);
extern void sfmmu_patch_utsb(void);

/*
 * Global Data:
 */
extern caddr_t	textva, datava;
extern tte_t	ktext_tte, kdata_tte;	/* ttes for kernel text and data */
extern int	enable_bigktsb;

uint64_t memsegspa = (uintptr_t)MSEG_NULLPTR_PA; /* memsegs physical linkage */
uint64_t memseg_phash[N_MEM_SLOTS];	/* use physical memseg addresses */

int	sfmmu_kern_mapped = 0;

/*
 * DMMU primary context register for the kernel context. Machine specific code
 * inserts correct page size codes when necessary
 */
uint64_t kcontextreg = KCONTEXT;

#ifdef DEBUG
static int ndata_middle_hole_detected = 0;
#endif

/* Extern Global Data */

extern int page_relocate_ready;

/*
 * Controls the logic which enables the use of the
 * QUAD_LDD_PHYS ASI for TSB accesses.
 */
extern int	ktsb_phys;

/*
 * Global Routines called from within:
 *	usr/src/uts/sun4u
 *	usr/src/uts/sfmmu
 *	usr/src/uts/sun
 */

pfn_t
va_to_pfn(void *vaddr)
{
	u_longlong_t physaddr;
	int mode, valid;

	if (tba_taken_over)
		return (hat_getpfnum(kas.a_hat, (caddr_t)vaddr));

#if !defined(C_OBP)
	if ((caddr_t)vaddr >= kmem64_base && (caddr_t)vaddr < kmem64_end) {
		if (kmem64_pabase == (uint64_t)-1)
			prom_panic("va_to_pfn: kmem64_pabase not init");
		physaddr = kmem64_pabase + ((caddr_t)vaddr - kmem64_base);
		return ((pfn_t)physaddr >> MMU_PAGESHIFT);
	}
#endif	/* !C_OBP */

	if ((prom_translate_virt(vaddr, &valid, &physaddr, &mode) != -1) &&
	    (valid == -1)) {
		return ((pfn_t)(physaddr >> MMU_PAGESHIFT));
	}
	return (PFN_INVALID);
}

uint64_t
va_to_pa(void *vaddr)
{
	pfn_t pfn;

	if ((pfn = va_to_pfn(vaddr)) == PFN_INVALID)
		return ((uint64_t)-1);
	return (((uint64_t)pfn << MMU_PAGESHIFT) |
	    ((uint64_t)vaddr & MMU_PAGEOFFSET));
}

void
hat_kern_setup(void)
{
	struct translation *trans_root;
	size_t ntrans_root;
	extern void startup_fixup_physavail(void);

	/*
	 * These are the steps we take to take over the mmu from the prom.
	 *
	 * (1)	Read the prom's mappings through the translation property.
	 * (2)	Remap the kernel text and kernel data with 2 locked 4MB ttes.
	 *	Create the the hmeblks for these 2 ttes at this time.
	 * (3)	Create hat structures for all other prom mappings.  Since the
	 *	kernel text and data hme_blks have already been created we
	 *	skip the equivalent prom's mappings.
	 * (4)	Initialize the tsb and its corresponding hardware regs.
	 * (5)	Take over the trap table (currently in startup).
	 * (6)	Up to this point it is possible the prom required some of its
	 *	locked tte's.  Now that we own the trap table we remove them.
	 */

	ktsb_pbase = va_to_pa(ktsb_base);
	ktsb4m_pbase = va_to_pa(ktsb4m_base);
	PRM_DEBUG(ktsb_pbase);
	PRM_DEBUG(ktsb4m_pbase);

	sfmmu_patch_ktsb();
	sfmmu_patch_utsb();
	sfmmu_patch_mmu_asi(ktsb_phys);

	sfmmu_init_tsbs();

	if (kpm_enable) {
		sfmmu_kpm_patch_tlbm();
		if (kpm_smallpages == 0) {
			sfmmu_kpm_patch_tsbm();
		}
	}

	if (!shctx_on) {
		sfmmu_patch_shctx();
	}

	/*
	 * The 8K-indexed kernel TSB space is used to hold
	 * translations below...
	 */
	trans_root = read_prom_mappings(&ntrans_root);
	sfmmu_remap_kernel();
	startup_fixup_physavail();
	mmu_init_kernel_pgsz(kas.a_hat);
	sfmmu_map_prom_mappings(trans_root, ntrans_root);

	/*
	 * We invalidate 8K kernel TSB because we used it in
	 * sfmmu_map_prom_mappings()
	 */
	sfmmu_inv_tsb(ktsb_base, ktsb_sz);
	sfmmu_inv_tsb(ktsb4m_base, ktsb4m_sz);

	sfmmu_init_ktsbinfo();


	sfmmu_kern_mapped = 1;

	/*
	 * hments have been created for mapped pages, and thus we're ready
	 * for kmdb to start using its own trap table.  It walks the hments
	 * to resolve TLB misses, and can't be used until they're ready.
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_vmready();
}

/*
 * Macro used below to convert the prom's 32-bit high and low fields into
 * a value appropriate for the 64-bit kernel.
 */

#define	COMBINE(hi, lo) (((uint64_t)(uint32_t)(hi) << 32) | (uint32_t)(lo))

/*
 * Track larges pages used.
 * Provides observability for this feature on non-debug kernels.
 */
ulong_t map_prom_lpcount[MMU_PAGE_SIZES];

/*
 * This function traverses the prom mapping list and creates equivalent
 * mappings in the sfmmu mapping hash.
 */
static void
sfmmu_map_prom_mappings(struct translation *trans_root, size_t ntrans_root)
{
	struct translation *promt;
	tte_t	tte, oldtte, *ttep;
	pfn_t	pfn, oldpfn, basepfn;
	caddr_t vaddr;
	size_t	size, offset;
	unsigned long i;
	uint_t	attr;
	page_t *pp;
	extern struct memlist *virt_avail;
	char buf[256];

	ttep = &tte;
	for (i = 0, promt = trans_root; i < ntrans_root; i++, promt++) {
		ASSERT(promt->tte_hi != 0);
		ASSERT32(promt->virt_hi == 0 && promt->size_hi == 0);

		vaddr = (caddr_t)COMBINE(promt->virt_hi, promt->virt_lo);

		/*
		 * hack until we get rid of map-for-unix
		 */
		if (vaddr < (caddr_t)KERNELBASE)
			continue;

		ttep->tte_inthi = promt->tte_hi;
		ttep->tte_intlo = promt->tte_lo;
		attr = PROC_DATA | HAT_NOSYNC;
#if defined(TTE_IS_GLOBAL)
		if (TTE_IS_GLOBAL(ttep)) {
			/*
			 * The prom better not use global translations
			 * because a user process might use the same
			 * virtual addresses
			 */
			prom_panic("sfmmu_map_prom_mappings: global"
			    " translation");
			TTE_SET_LOFLAGS(ttep, TTE_GLB_INT, 0);
		}
#endif
		if (TTE_IS_LOCKED(ttep)) {
			/* clear the lock bits */
			TTE_CLR_LOCKED(ttep);
		}
		attr |= (TTE_IS_VCACHEABLE(ttep)) ? 0 : SFMMU_UNCACHEVTTE;
		attr |= (TTE_IS_PCACHEABLE(ttep)) ? 0 : SFMMU_UNCACHEPTTE;
		attr |= (TTE_IS_SIDEFFECT(ttep)) ? SFMMU_SIDEFFECT : 0;
		attr |= (TTE_IS_IE(ttep)) ? HAT_STRUCTURE_LE : 0;

		size = COMBINE(promt->size_hi, promt->size_lo);
		offset = 0;
		basepfn = TTE_TO_PFN((caddr_t)COMBINE(promt->virt_hi,
		    promt->virt_lo), ttep);
		while (size) {
			vaddr = (caddr_t)(COMBINE(promt->virt_hi,
			    promt->virt_lo) + offset);

			/*
			 * make sure address is not in virt-avail list
			 */
			if (address_in_memlist(virt_avail, (uint64_t)vaddr,
			    size)) {
				prom_panic("sfmmu_map_prom_mappings:"
				    " inconsistent translation/avail lists");
			}

			pfn = basepfn + mmu_btop(offset);
			if (pf_is_memory(pfn)) {
				if (attr & SFMMU_UNCACHEPTTE) {
					prom_panic("sfmmu_map_prom_mappings:"
					    " uncached prom memory page");
				}
			} else {
				if (!(attr & SFMMU_SIDEFFECT)) {
					prom_panic("sfmmu_map_prom_mappings:"
					    " prom i/o page without"
					    " side-effect");
				}
			}

			/*
			 * skip kmem64 area
			 */
			if (vaddr >= kmem64_base &&
			    vaddr < kmem64_aligned_end) {
#if !defined(C_OBP)
				prom_panic("sfmmu_map_prom_mappings:"
				    " unexpected kmem64 prom mapping");
#else	/* !C_OBP */
				size_t mapsz;

				if (ptob(pfn) !=
				    kmem64_pabase + (vaddr - kmem64_base)) {
					prom_panic("sfmmu_map_prom_mappings:"
					    " unexpected kmem64 prom mapping");
				}

				mapsz = kmem64_aligned_end - vaddr;
				if (mapsz >= size) {
					break;
				}
				size -= mapsz;
				offset += mapsz;
				continue;
#endif	/* !C_OBP */
			}

			oldpfn = sfmmu_vatopfn(vaddr, KHATID, &oldtte);
			ASSERT(oldpfn != PFN_SUSPENDED);
			ASSERT(page_relocate_ready == 0);

			if (oldpfn != PFN_INVALID) {
				/*
				 * mapping already exists.
				 * Verify they are equal
				 */
				if (pfn != oldpfn) {
					(void) snprintf(buf, sizeof (buf),
					"sfmmu_map_prom_mappings: mapping"
					" conflict (va = 0x%p, pfn = 0x%p,"
					" oldpfn = 0x%p)", (void *)vaddr,
					    (void *)pfn, (void *)oldpfn);
					prom_panic(buf);
				}
				size -= MMU_PAGESIZE;
				offset += MMU_PAGESIZE;
				continue;
			}

			pp = page_numtopp_nolock(pfn);
			if ((pp != NULL) && PP_ISFREE((page_t *)pp)) {
				(void) snprintf(buf, sizeof (buf),
				"sfmmu_map_prom_mappings: prom-mapped"
				" page (va = 0x%p, pfn = 0x%p) on free list",
				    (void *)vaddr, (void *)pfn);
				prom_panic(buf);
			}

			sfmmu_memtte(ttep, pfn, attr, TTE8K);
			sfmmu_tteload(kas.a_hat, ttep, vaddr, pp,
			    HAT_LOAD_LOCK | SFMMU_NO_TSBLOAD);
			size -= MMU_PAGESIZE;
			offset += MMU_PAGESIZE;
		}
	}

	/*
	 * We claimed kmem64 from prom, so now we need to load tte.
	 */
	if (kmem64_base != NULL) {
		pgcnt_t pages;
		size_t psize;
		int pszc;

		pszc = kmem64_szc;
#ifdef sun4u
		if (pszc > TTE8K) {
			pszc = segkmem_lpszc;
		}
#endif	/* sun4u */
		psize = TTEBYTES(pszc);
		pages = btop(psize);
		basepfn = kmem64_pabase >> MMU_PAGESHIFT;
		vaddr = kmem64_base;
		while (vaddr < kmem64_end) {
			sfmmu_memtte(ttep, basepfn,
			    PROC_DATA | HAT_NOSYNC, pszc);
			sfmmu_tteload(kas.a_hat, ttep, vaddr, NULL,
			    HAT_LOAD_LOCK | SFMMU_NO_TSBLOAD);
			vaddr += psize;
			basepfn += pages;
		}
		map_prom_lpcount[pszc] =
		    ((caddr_t)P2ROUNDUP((uintptr_t)kmem64_end, psize) -
		    kmem64_base) >> TTE_PAGE_SHIFT(pszc);
	}
}

#undef COMBINE	/* local to previous routine */

/*
 * This routine reads in the "translations" property in to a buffer and
 * returns a pointer to this buffer and the number of translations.
 */
static struct translation *
read_prom_mappings(size_t *ntransrootp)
{
	char *prop = "translations";
	size_t translen;
	pnode_t node;
	struct translation *transroot;

	/*
	 * the "translations" property is associated with the mmu node
	 */
	node = (pnode_t)prom_getphandle(prom_mmu_ihandle());

	/*
	 * We use the TSB space to read in the prom mappings.  This space
	 * is currently not being used because we haven't taken over the
	 * trap table yet.  It should be big enough to hold the mappings.
	 */
	if ((translen = prom_getproplen(node, prop)) == -1)
		cmn_err(CE_PANIC, "no translations property");
	*ntransrootp = translen / sizeof (*transroot);
	translen = roundup(translen, MMU_PAGESIZE);
	PRM_DEBUG(translen);
	if (translen > TSB_BYTES(ktsb_szcode))
		cmn_err(CE_PANIC, "not enough space for translations");

	transroot = (struct translation *)ktsb_base;
	ASSERT(transroot);
	if (prom_getprop(node, prop, (caddr_t)transroot) == -1) {
		cmn_err(CE_PANIC, "translations getprop failed");
	}
	return (transroot);
}

/*
 * Init routine of the nucleus data memory allocator.
 *
 * The nucleus data memory allocator is organized in ecache_alignsize'd
 * memory chunks. Memory allocated by ndata_alloc() will never be freed.
 *
 * The ndata argument is used as header of the ndata freelist.
 * Other freelist nodes are placed in the nucleus memory itself
 * at the beginning of a free memory chunk. Therefore a freelist
 * node (struct memlist) must fit into the smallest allocatable
 * memory chunk (ecache_alignsize bytes).
 *
 * The memory interval [base, end] passed to ndata_alloc_init() must be
 * bzero'd to allow the allocator to return bzero'd memory easily.
 */
void
ndata_alloc_init(struct memlist *ndata, uintptr_t base, uintptr_t end)
{
	ASSERT(sizeof (struct memlist) <= ecache_alignsize);

	base = roundup(base, ecache_alignsize);
	end = end - end % ecache_alignsize;

	ASSERT(base < end);

	ndata->address = base;
	ndata->size = end - base;
	ndata->next = NULL;
	ndata->prev = NULL;
}

/*
 * Deliver the size of the largest free memory chunk.
 */
size_t
ndata_maxsize(struct memlist *ndata)
{
	size_t chunksize = ndata->size;

	while ((ndata = ndata->next) != NULL) {
		if (chunksize < ndata->size)
			chunksize = ndata->size;
	}

	return (chunksize);
}

/*
 * This is a special function to figure out if the memory chunk needed
 * for the page structs can fit in the nucleus or not. If it fits the
 * function calculates and returns the possible remaining ndata size
 * in the last element if the size needed for page structs would be
 * allocated from the nucleus.
 */
size_t
ndata_spare(struct memlist *ndata, size_t wanted, size_t alignment)
{
	struct memlist *frlist;
	uintptr_t base;
	uintptr_t end;

	for (frlist = ndata; frlist != NULL; frlist = frlist->next) {
		base = roundup(frlist->address, alignment);
		end = roundup(base + wanted, ecache_alignsize);

		if (end <= frlist->address + frlist->size) {
			if (frlist->next == NULL)
				return (frlist->address + frlist->size - end);

			while (frlist->next != NULL)
				frlist = frlist->next;

			return (frlist->size);
		}
	}

	return (0);
}

/*
 * Allocate the last properly aligned memory chunk.
 * This function is called when no more large nucleus memory chunks
 * will be allocated.  The remaining free nucleus memory at the end
 * of the nucleus can be added to the phys_avail list.
 */
void *
ndata_extra_base(struct memlist *ndata, size_t alignment, caddr_t endaddr)
{
	uintptr_t base;
	size_t wasteage = 0;
#ifdef	DEBUG
	static int called = 0;

	if (called++ > 0)
		cmn_err(CE_PANIC, "ndata_extra_base() called more than once");
#endif /* DEBUG */

	/*
	 * The alignment needs to be a multiple of ecache_alignsize.
	 */
	ASSERT((alignment % ecache_alignsize) ==  0);

	while (ndata->next != NULL) {
		wasteage += ndata->size;
		ndata = ndata->next;
	}

	base = roundup(ndata->address, alignment);

	if (base >= ndata->address + ndata->size)
		return (NULL);

	if ((caddr_t)(ndata->address + ndata->size) != endaddr) {
#ifdef DEBUG
		ndata_middle_hole_detected = 1;	/* see if we hit this again */
#endif
		return (NULL);
	}

	if (base == ndata->address) {
		if (ndata->prev != NULL)
			ndata->prev->next = NULL;
		else
			ndata->size = 0;

		bzero((void *)base, sizeof (struct memlist));

	} else {
		ndata->size = base - ndata->address;
		wasteage += ndata->size;
	}
	PRM_DEBUG(wasteage);

	return ((void *)base);
}

/*
 * Select the best matching buffer, avoid memory fragmentation.
 */
static struct memlist *
ndata_select_chunk(struct memlist *ndata, size_t wanted, size_t alignment)
{
	struct memlist *fnd_below = NULL;
	struct memlist *fnd_above = NULL;
	struct memlist *fnd_unused = NULL;
	struct memlist *frlist;
	uintptr_t base;
	uintptr_t end;
	size_t below;
	size_t above;
	size_t unused;
	size_t best_below = ULONG_MAX;
	size_t best_above = ULONG_MAX;
	size_t best_unused = ULONG_MAX;

	ASSERT(ndata != NULL);

	/*
	 * Look for the best matching buffer, avoid memory fragmentation.
	 * The following strategy is used, try to find
	 *   1. an exact fitting buffer
	 *   2. avoid wasting any space below the buffer, take first
	 *	fitting buffer
	 *   3. avoid wasting any space above the buffer, take first
	 *	fitting buffer
	 *   4. avoid wasting space, take first fitting buffer
	 *   5. take the last buffer in chain
	 */
	for (frlist = ndata; frlist != NULL; frlist = frlist->next) {
		base = roundup(frlist->address, alignment);
		end = roundup(base + wanted, ecache_alignsize);

		if (end > frlist->address + frlist->size)
			continue;

		below = (base - frlist->address) / ecache_alignsize;
		above = (frlist->address + frlist->size - end) /
		    ecache_alignsize;
		unused = below + above;

		if (unused == 0)
			return (frlist);

		if (frlist->next == NULL)
			break;

		if (below < best_below) {
			best_below = below;
			fnd_below = frlist;
		}

		if (above < best_above) {
			best_above = above;
			fnd_above = frlist;
		}

		if (unused < best_unused) {
			best_unused = unused;
			fnd_unused = frlist;
		}
	}

	if (best_below == 0)
		return (fnd_below);
	if (best_above == 0)
		return (fnd_above);
	if (best_unused < ULONG_MAX)
		return (fnd_unused);

	return (frlist);
}

/*
 * Nucleus data memory allocator.
 * The granularity of the allocator is ecache_alignsize.
 * See also comment for ndata_alloc_init().
 */
void *
ndata_alloc(struct memlist *ndata, size_t wanted, size_t alignment)
{
	struct memlist *found;
	struct memlist *fnd_above;
	uintptr_t base;
	uintptr_t end;
	size_t below;
	size_t above;

	/*
	 * Look for the best matching buffer, avoid memory fragmentation.
	 */
	if ((found = ndata_select_chunk(ndata, wanted, alignment)) == NULL)
		return (NULL);

	/*
	 * Allocate the nucleus data buffer.
	 */
	base = roundup(found->address, alignment);
	end = roundup(base + wanted, ecache_alignsize);
	ASSERT(end <= found->address + found->size);

	below = base - found->address;
	above = found->address + found->size - end;
	ASSERT(above == 0 || (above % ecache_alignsize) == 0);

	if (below >= ecache_alignsize) {
		/*
		 * There is free memory below the allocated memory chunk.
		 */
		found->size = below - below % ecache_alignsize;

		if (above) {
			fnd_above = (struct memlist *)end;
			fnd_above->address = end;
			fnd_above->size = above;

			if ((fnd_above->next = found->next) != NULL)
				found->next->prev = fnd_above;
			fnd_above->prev = found;
			found->next = fnd_above;
		}

		return ((void *)base);
	}

	if (found->prev == NULL) {
		/*
		 * The first chunk (ndata) is selected.
		 */
		ASSERT(found == ndata);
		if (above) {
			found->address = end;
			found->size = above;
		} else if (found->next != NULL) {
			found->address = found->next->address;
			found->size = found->next->size;
			if ((found->next = found->next->next) != NULL)
				found->next->prev = found;

			bzero((void *)found->address, sizeof (struct memlist));
		} else {
			found->address = end;
			found->size = 0;
		}

		return ((void *)base);
	}

	/*
	 * Not the first chunk.
	 */
	if (above) {
		fnd_above = (struct memlist *)end;
		fnd_above->address = end;
		fnd_above->size = above;

		if ((fnd_above->next = found->next) != NULL)
			fnd_above->next->prev = fnd_above;
		fnd_above->prev = found->prev;
		found->prev->next = fnd_above;

	} else {
		if ((found->prev->next = found->next) != NULL)
			found->next->prev = found->prev;
	}

	bzero((void *)found->address, sizeof (struct memlist));

	return ((void *)base);
}

/*
 * Size the kernel TSBs based upon the amount of physical
 * memory in the system.
 */
static void
calc_tsb_sizes(pgcnt_t npages)
{
	PRM_DEBUG(npages);

	if (npages <= TSB_FREEMEM_MIN) {
		ktsb_szcode = TSB_128K_SZCODE;
		enable_bigktsb = 0;
	} else if (npages <= TSB_FREEMEM_LARGE / 2) {
		ktsb_szcode = TSB_256K_SZCODE;
		enable_bigktsb = 0;
	} else if (npages <= TSB_FREEMEM_LARGE) {
		ktsb_szcode = TSB_512K_SZCODE;
		enable_bigktsb = 0;
	} else if (npages <= TSB_FREEMEM_LARGE * 2 ||
	    enable_bigktsb == 0) {
		ktsb_szcode = TSB_1M_SZCODE;
		enable_bigktsb = 0;
	} else {
		ktsb_szcode = highbit(npages - 1);
		ktsb_szcode -= TSB_START_SIZE;
		ktsb_szcode = MAX(ktsb_szcode, MIN_BIGKTSB_SZCODE);
		ktsb_szcode = MIN(ktsb_szcode, MAX_BIGKTSB_SZCODE);
	}

	/*
	 * We choose the TSB to hold kernel 4M mappings to have twice
	 * the reach as the primary kernel TSB since this TSB will
	 * potentially (currently) be shared by both mappings to all of
	 * physical memory plus user TSBs. If this TSB has to be in nucleus
	 * (only for Spitfire and Cheetah) limit its size to 64K.
	 */
	ktsb4m_szcode = highbit((2 * npages) / TTEPAGES(TTE4M) - 1);
	ktsb4m_szcode -= TSB_START_SIZE;
	ktsb4m_szcode = MAX(ktsb4m_szcode, TSB_MIN_SZCODE);
	ktsb4m_szcode = MIN(ktsb4m_szcode, TSB_SOFTSZ_MASK);
	if ((enable_bigktsb == 0 || ktsb_phys == 0) && ktsb4m_szcode >
	    TSB_64K_SZCODE) {
		ktsb4m_szcode = TSB_64K_SZCODE;
		max_bootlp_tteszc = TTE8K;
	}

	ktsb_sz = TSB_BYTES(ktsb_szcode);	/* kernel 8K tsb size */
	ktsb4m_sz = TSB_BYTES(ktsb4m_szcode);	/* kernel 4M tsb size */
}

/*
 * Allocate kernel TSBs from nucleus data memory.
 * The function return 0 on success and -1 on failure.
 */
int
ndata_alloc_tsbs(struct memlist *ndata, pgcnt_t npages)
{
	/*
	 * Set ktsb_phys to 1 if the processor supports ASI_QUAD_LDD_PHYS.
	 */
	sfmmu_setup_4lp();

	/*
	 * Size the kernel TSBs based upon the amount of physical
	 * memory in the system.
	 */
	calc_tsb_sizes(npages);

	/*
	 * Allocate the 8K kernel TSB if it belongs inside the nucleus.
	 */
	if (enable_bigktsb == 0) {
		if ((ktsb_base = ndata_alloc(ndata, ktsb_sz, ktsb_sz)) == NULL)
			return (-1);
		ASSERT(!((uintptr_t)ktsb_base & (ktsb_sz - 1)));

		PRM_DEBUG(ktsb_base);
		PRM_DEBUG(ktsb_sz);
		PRM_DEBUG(ktsb_szcode);
	}

	/*
	 * Next, allocate 4M kernel TSB from the nucleus since it's small.
	 */
	if (ktsb4m_szcode <= TSB_64K_SZCODE) {

		ktsb4m_base = ndata_alloc(ndata, ktsb4m_sz, ktsb4m_sz);
		if (ktsb4m_base == NULL)
			return (-1);
		ASSERT(!((uintptr_t)ktsb4m_base & (ktsb4m_sz - 1)));

		PRM_DEBUG(ktsb4m_base);
		PRM_DEBUG(ktsb4m_sz);
		PRM_DEBUG(ktsb4m_szcode);
	}

	return (0);
}

/*
 * Allocate hat structs from the nucleus data memory.
 */
int
ndata_alloc_hat(struct memlist *ndata, pgcnt_t npages, pgcnt_t kpm_npages)
{
	size_t	mml_alloc_sz;
	size_t	cb_alloc_sz;
	int	max_nucuhme_buckets = MAX_NUCUHME_BUCKETS;
	int	max_nuckhme_buckets = MAX_NUCKHME_BUCKETS;
	ulong_t hme_buckets;

	if (enable_bigktsb) {
		ASSERT((max_nucuhme_buckets + max_nuckhme_buckets) *
		    sizeof (struct hmehash_bucket) <=
		    TSB_BYTES(TSB_1M_SZCODE));

		max_nucuhme_buckets *= 2;
		max_nuckhme_buckets *= 2;
	}

	/*
	 * The number of buckets in the hme hash tables
	 * is a power of 2 such that the average hash chain length is
	 * HMENT_HASHAVELEN.  The number of buckets for the user hash is
	 * a function of physical memory and a predefined overmapping factor.
	 * The number of buckets for the kernel hash is a function of
	 * physical memory only.
	 */
	hme_buckets = (npages * HMEHASH_FACTOR) /
	    (HMENT_HASHAVELEN * (HMEBLK_SPAN(TTE8K) >> MMU_PAGESHIFT));

	uhmehash_num = (int)MIN(hme_buckets, MAX_UHME_BUCKETS);

	if (uhmehash_num > USER_BUCKETS_THRESHOLD) {
		/*
		 * if uhmehash_num is not power of 2 round it down to the
		 *  next power of 2.
		 */
		uint_t align = 1 << (highbit(uhmehash_num - 1) - 1);
		uhmehash_num = P2ALIGN(uhmehash_num, align);
	} else
		uhmehash_num = 1 << highbit(uhmehash_num - 1);

	hme_buckets = npages / (HMEBLK_SPAN(TTE8K) >> MMU_PAGESHIFT);
	khmehash_num = (int)MIN(hme_buckets, MAX_KHME_BUCKETS);
	khmehash_num = 1 << highbit(khmehash_num - 1);
	khmehash_num = MAX(khmehash_num, MIN_KHME_BUCKETS);

	if ((khmehash_num > max_nuckhme_buckets) ||
	    (uhmehash_num > max_nucuhme_buckets)) {
		khme_hash = NULL;
		uhme_hash = NULL;
	} else {
		size_t hmehash_sz = (uhmehash_num + khmehash_num) *
		    sizeof (struct hmehash_bucket);

		if ((khme_hash = ndata_alloc(ndata, hmehash_sz,
		    ecache_alignsize)) != NULL)
			uhme_hash = &khme_hash[khmehash_num];
		else
			uhme_hash = NULL;

		PRM_DEBUG(hmehash_sz);
	}

	PRM_DEBUG(khme_hash);
	PRM_DEBUG(khmehash_num);
	PRM_DEBUG(uhme_hash);
	PRM_DEBUG(uhmehash_num);

	/*
	 * For the page mapping list mutex array we allocate one mutex
	 * for every 128 pages (1 MB) with a minimum of 64 entries and
	 * a maximum of 8K entries. For the initial computation npages
	 * is rounded up (ie. 1 << highbit(npages * 1.5 / 128))
	 *
	 * mml_shift is roughly log2(mml_table_sz) + 3 for MLIST_HASH
	 *
	 * It is not required that this be allocated from the nucleus,
	 * but it is desirable.  So we first allocate from the nucleus
	 * everything that must be there.  Having done so, if mml_table
	 * will fit within what remains of the nucleus then it will be
	 * allocated here.  If not, set mml_table to NULL, which will cause
	 * startup_memlist() to BOP_ALLOC() space for it after our return...
	 */
	mml_table_sz = 1 << highbit((npages * 3) / 256);
	if (mml_table_sz < 64)
		mml_table_sz = 64;
	else if (mml_table_sz > 8192)
		mml_table_sz = 8192;
	mml_shift = highbit(mml_table_sz) + 3;

	PRM_DEBUG(mml_table_sz);
	PRM_DEBUG(mml_shift);

	mml_alloc_sz = mml_table_sz * sizeof (kmutex_t);

	mml_table = ndata_alloc(ndata, mml_alloc_sz, ecache_alignsize);

	PRM_DEBUG(mml_table);

	cb_alloc_sz = sfmmu_max_cb_id * sizeof (struct sfmmu_callback);
	PRM_DEBUG(cb_alloc_sz);
	sfmmu_cb_table = ndata_alloc(ndata, cb_alloc_sz, ecache_alignsize);
	PRM_DEBUG(sfmmu_cb_table);

	/*
	 * For the kpm_page mutex array we allocate one mutex every 16
	 * kpm pages (64MB). In smallpage mode we allocate one mutex
	 * every 8K pages. The minimum is set to 64 entries and the
	 * maximum to 8K entries.
	 *
	 * It is not required that this be allocated from the nucleus,
	 * but it is desirable.  So we first allocate from the nucleus
	 * everything that must be there.  Having done so, if kpmp_table
	 * or kpmp_stable will fit within what remains of the nucleus
	 * then it will be allocated here.  If not, startup_memlist()
	 * will use BOP_ALLOC() space for it after our return...
	 */
	if (kpm_enable) {
		size_t	kpmp_alloc_sz;

		if (kpm_smallpages == 0) {
			kpmp_shift = highbit(sizeof (kpm_page_t)) - 1;
			kpmp_table_sz = 1 << highbit(kpm_npages / 16);
			kpmp_table_sz = (kpmp_table_sz < 64) ? 64 :
			    ((kpmp_table_sz > 8192) ? 8192 : kpmp_table_sz);
			kpmp_alloc_sz = kpmp_table_sz * sizeof (kpm_hlk_t);

			kpmp_table = ndata_alloc(ndata, kpmp_alloc_sz,
			    ecache_alignsize);

			PRM_DEBUG(kpmp_table);
			PRM_DEBUG(kpmp_table_sz);

			kpmp_stable_sz = 0;
			kpmp_stable = NULL;
		} else {
			ASSERT(kpm_pgsz == PAGESIZE);
			kpmp_shift = highbit(sizeof (kpm_shlk_t)) + 1;
			kpmp_stable_sz = 1 << highbit(kpm_npages / 8192);
			kpmp_stable_sz = (kpmp_stable_sz < 64) ? 64 :
			    ((kpmp_stable_sz > 8192) ? 8192 : kpmp_stable_sz);
			kpmp_alloc_sz = kpmp_stable_sz * sizeof (kpm_shlk_t);

			kpmp_stable = ndata_alloc(ndata, kpmp_alloc_sz,
			    ecache_alignsize);

			PRM_DEBUG(kpmp_stable);
			PRM_DEBUG(kpmp_stable_sz);

			kpmp_table_sz = 0;
			kpmp_table = NULL;
		}
		PRM_DEBUG(kpmp_shift);
	}

	return (0);
}

/*
 * Allocate virtual addresses at base with given alignment.
 * Note that there is no physical memory behind the address yet.
 */
caddr_t
alloc_hme_buckets(caddr_t base, int alignsize)
{
	size_t hmehash_sz = (uhmehash_num + khmehash_num) *
	    sizeof (struct hmehash_bucket);

	ASSERT(khme_hash == NULL);
	ASSERT(uhme_hash == NULL);

	base = (caddr_t)roundup((uintptr_t)base, alignsize);
	hmehash_sz = roundup(hmehash_sz, alignsize);

	khme_hash = (struct hmehash_bucket *)base;
	uhme_hash = (struct hmehash_bucket *)((caddr_t)khme_hash +
	    khmehash_num * sizeof (struct hmehash_bucket));
	base += hmehash_sz;
	return (base);
}

/*
 * This function bop allocs kernel TSBs.
 */
caddr_t
sfmmu_ktsb_alloc(caddr_t tsbbase)
{
	caddr_t vaddr;

	if (enable_bigktsb) {
		ktsb_base = (caddr_t)roundup((uintptr_t)tsbbase, ktsb_sz);
		vaddr = (caddr_t)BOP_ALLOC(bootops, ktsb_base, ktsb_sz,
		    ktsb_sz);
		if (vaddr != ktsb_base)
			cmn_err(CE_PANIC, "sfmmu_ktsb_alloc: can't alloc"
			    " 8K bigktsb");
		ktsb_base = vaddr;
		tsbbase = ktsb_base + ktsb_sz;
		PRM_DEBUG(ktsb_base);
		PRM_DEBUG(tsbbase);
	}

	if (ktsb4m_szcode > TSB_64K_SZCODE) {
		ASSERT(ktsb_phys && enable_bigktsb);
		ktsb4m_base = (caddr_t)roundup((uintptr_t)tsbbase, ktsb4m_sz);
		vaddr = (caddr_t)BOP_ALLOC(bootops, ktsb4m_base, ktsb4m_sz,
		    ktsb4m_sz);
		if (vaddr != ktsb4m_base)
			cmn_err(CE_PANIC, "sfmmu_ktsb_alloc: can't alloc"
			    " 4M bigktsb");
		ktsb4m_base = vaddr;
		tsbbase = ktsb4m_base + ktsb4m_sz;
		PRM_DEBUG(ktsb4m_base);
		PRM_DEBUG(tsbbase);
	}
	return (tsbbase);
}

/*
 * Moves code assembled outside of the trap table into the trap
 * table taking care to relocate relative branches to code outside
 * of the trap handler.
 */
static void
sfmmu_reloc_trap_handler(void *tablep, void *start, size_t count)
{
	size_t i;
	uint32_t *src;
	uint32_t *dst;
	uint32_t inst;
	int op, op2;
	int32_t offset;
	int disp;

	src = start;
	dst = tablep;
	offset = src - dst;
	for (src = start, i = 0; i < count; i++, src++, dst++) {
		inst = *dst = *src;
		op = (inst >> 30) & 0x2;
		if (op == 1) {
			/* call */
			disp = ((int32_t)inst << 2) >> 2; /* sign-extend */
			if (disp + i >= 0 && disp + i < count)
				continue;
			disp += offset;
			inst = 0x40000000u | (disp & 0x3fffffffu);
			*dst = inst;
		} else if (op == 0) {
			/* branch or sethi */
			op2 = (inst >> 22) & 0x7;

			switch (op2) {
			case 0x3: /* BPr */
				disp = (((inst >> 20) & 0x3) << 14) |
				    (inst & 0x3fff);
				disp = (disp << 16) >> 16; /* sign-extend */
				if (disp + i >= 0 && disp + i < count)
					continue;
				disp += offset;
				if (((disp << 16) >> 16) != disp)
					cmn_err(CE_PANIC, "bad reloc");
				inst &= ~0x303fff;
				inst |= (disp & 0x3fff);
				inst |= (disp & 0xc000) << 6;
				break;

			case 0x2: /* Bicc */
				disp = ((int32_t)inst << 10) >> 10;
				if (disp + i >= 0 && disp + i < count)
					continue;
				disp += offset;
				if (((disp << 10) >> 10) != disp)
					cmn_err(CE_PANIC, "bad reloc");
				inst &= ~0x3fffff;
				inst |= (disp & 0x3fffff);
				break;

			case 0x1: /* Bpcc */
				disp = ((int32_t)inst << 13) >> 13;
				if (disp + i >= 0 && disp + i < count)
					continue;
				disp += offset;
				if (((disp << 13) >> 13) != disp)
					cmn_err(CE_PANIC, "bad reloc");
				inst &= ~0x7ffff;
				inst |= (disp & 0x7ffffu);
				break;
			}
			*dst = inst;
		}
	}
	flush_instr_mem(tablep, count * sizeof (uint32_t));
}

/*
 * Routine to allocate a large page to use in the TSB caches.
 */
/*ARGSUSED*/
static page_t *
sfmmu_tsb_page_create(void *addr, size_t size, int vmflag, void *arg)
{
	int pgflags;

	pgflags = PG_EXCL;
	if ((vmflag & VM_NOSLEEP) == 0)
		pgflags |= PG_WAIT;
	if (vmflag & VM_PANIC)
		pgflags |= PG_PANIC;
	if (vmflag & VM_PUSHPAGE)
		pgflags |= PG_PUSHPAGE;

	return (page_create_va_large(&kvp, (u_offset_t)(uintptr_t)addr, size,
	    pgflags, &kvseg, addr, arg));
}

/*
 * Allocate a large page to back the virtual address range
 * [addr, addr + size).  If addr is NULL, allocate the virtual address
 * space as well.
 */
static void *
sfmmu_tsb_xalloc(vmem_t *vmp, void *inaddr, size_t size, int vmflag,
    uint_t attr, page_t *(*page_create_func)(void *, size_t, int, void *),
    void *pcarg)
{
	page_t *ppl;
	page_t *rootpp;
	caddr_t addr = inaddr;
	pgcnt_t npages = btopr(size);
	page_t **ppa;
	int i = 0;

	/*
	 * Assuming that only TSBs will call this with size > PAGESIZE
	 * There is no reason why this couldn't be expanded to 8k pages as
	 * well, or other page sizes in the future .... but for now, we
	 * only support fixed sized page requests.
	 */
	if ((inaddr == NULL) && ((addr = vmem_xalloc(vmp, size, size, 0, 0,
	    NULL, NULL, vmflag)) == NULL))
		return (NULL);

	if (page_resv(npages, vmflag & VM_KMFLAGS) == 0) {
		if (inaddr == NULL)
			vmem_xfree(vmp, addr, size);
		return (NULL);
	}

	ppl = page_create_func(addr, size, vmflag, pcarg);
	if (ppl == NULL) {
		if (inaddr == NULL)
			vmem_xfree(vmp, addr, size);
		page_unresv(npages);
		return (NULL);
	}

	rootpp = ppl;
	ppa = kmem_zalloc(npages * sizeof (page_t *), KM_SLEEP);
	while (ppl != NULL) {
		page_t *pp = ppl;
		ppa[i++] = pp;
		page_sub(&ppl, pp);
		ASSERT(page_iolock_assert(pp));
		page_io_unlock(pp);
	}

	/*
	 * Load the locked entry.  It's OK to preload the entry into
	 * the TSB since we now support large mappings in the kernel TSB.
	 */
	hat_memload_array(kas.a_hat, (caddr_t)rootpp->p_offset, size,
	    ppa, (PROT_ALL & ~PROT_USER) | HAT_NOSYNC | attr, HAT_LOAD_LOCK);

	for (--i; i >= 0; --i) {
		(void) page_pp_lock(ppa[i], 0, 1);
		page_unlock(ppa[i]);
	}

	kmem_free(ppa, npages * sizeof (page_t *));
	return (addr);
}

/* Called to import new spans into the TSB vmem arenas */
void *
sfmmu_tsb_segkmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	lgrp_id_t lgrpid = LGRP_NONE;

	if (tsb_lgrp_affinity) {
		/*
		 * Search for the vmp->lgrpid mapping by brute force;
		 * some day vmp will have an lgrp, until then we have
		 * to do this the hard way.
		 */
		for (lgrpid = 0; lgrpid < NLGRPS_MAX &&
		    vmp != kmem_tsb_default_arena[lgrpid]; lgrpid++);
		if (lgrpid == NLGRPS_MAX)
			lgrpid = LGRP_NONE;
	}

	return (sfmmu_tsb_xalloc(vmp, NULL, size, vmflag, 0,
	    sfmmu_tsb_page_create, lgrpid != LGRP_NONE? &lgrpid : NULL));
}

/* Called to free spans from the TSB vmem arenas */
void
sfmmu_tsb_segkmem_free(vmem_t *vmp, void *inaddr, size_t size)
{
	page_t *pp;
	caddr_t addr = inaddr;
	caddr_t eaddr;
	pgcnt_t npages = btopr(size);
	pgcnt_t pgs_left = npages;
	page_t *rootpp = NULL;

	hat_unload(kas.a_hat, addr, size, HAT_UNLOAD_UNLOCK);

	for (eaddr = addr + size; addr < eaddr; addr += PAGESIZE) {
		pp = page_lookup(&kvp, (u_offset_t)(uintptr_t)addr, SE_EXCL);
		if (pp == NULL)
			panic("sfmmu_tsb_segkmem_free: page not found");

		ASSERT(PAGE_EXCL(pp));
		page_pp_unlock(pp, 0, 1);

		if (rootpp == NULL)
			rootpp = pp;
		if (--pgs_left == 0) {
			/*
			 * similar logic to segspt_free_pages, but we know we
			 * have one large page.
			 */
			page_destroy_pages(rootpp);
		}
	}
	page_unresv(npages);

	if (vmp != NULL)
		vmem_xfree(vmp, inaddr, size);
}
