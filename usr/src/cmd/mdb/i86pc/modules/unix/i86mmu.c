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
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * This part of the file contains the mdb support for dcmds:
 *	::memseg_list
 * and walkers for:
 *	memseg - a memseg list walker for ::memseg_list
 *
 */

#include <sys/types.h>
#include <sys/machparam.h>
#include <sys/controlregs.h>
#include <sys/mach_mmu.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif
#include <vm/as.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target.h>

#include <vm/page.h>
#include <vm/hat_i86.h>

#define	VA_SIGN_BIT (1UL << 47)
#define	VA_SIGN_EXTEND(va) (((va) ^ VA_SIGN_BIT) - VA_SIGN_BIT)

struct pfn2pp {
	pfn_t pfn;
	page_t *pp;
};

static int do_va2pa(uintptr_t, struct as *, int, physaddr_t *, pfn_t *);
static void init_mmu(void);

int
platform_vtop(uintptr_t addr, struct as *asp, physaddr_t *pap)
{
	if (asp == NULL)
		return (DCMD_ERR);

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	return (do_va2pa(addr, asp, 0, pap, NULL));
}

/*
 * ::memseg_list dcmd and walker to implement it.
 */
/*ARGSUSED*/
int
memseg_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct memseg ms;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_pwalk_dcmd("memseg", "memseg_list",
		    0, NULL, 0) == -1) {
			mdb_warn("can't walk memseg");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %?s %?s %?s %?s%</u>\n", "ADDR",
		    "PAGES", "EPAGES", "BASE", "END");

	if (mdb_vread(&ms, sizeof (struct memseg), addr) == -1) {
		mdb_warn("can't read memseg at %#lx", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?lx %0?lx %0?lx %0?lx %0?lx\n", addr,
	    ms.pages, ms.epages, ms.pages_base, ms.pages_end);

	return (DCMD_OK);
}

/*
 * walk the memseg structures
 */
int
memseg_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != NULL) {
		mdb_warn("memseg only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&wsp->walk_addr, "memsegs") == -1) {
		mdb_warn("symbol 'memsegs' not found");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (struct memseg), UM_SLEEP);
	return (WALK_NEXT);

}

int
memseg_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (struct memseg),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct memseg at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((struct memseg *)wsp->walk_data)->next);

	return (status);
}

void
memseg_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct memseg));
}

/*
 * Now HAT related dcmds.
 */

static struct hat *khat;		/* value of kas.a_hat */
struct hat_mmu_info mmu;
uintptr_t kernelbase;

/*
 * stuff for i86xpv images
 */
static int is_xpv;
static uintptr_t mfn_list_addr; /* kernel MFN list address */
uintptr_t xen_virt_start; /* address of mfn_to_pfn[] table */
ulong_t mfn_count;	/* number of pfn's in the MFN list */
pfn_t *mfn_list;	/* local MFN list copy */

/*
 * read mmu parameters from kernel
 */
static void
init_mmu(void)
{
	struct as kas;

	if (mmu.num_level != 0)
		return;

	if (mdb_readsym(&mmu, sizeof (mmu), "mmu") == -1)
		mdb_warn("Can't use HAT information before mmu_init()\n");
	if (mdb_readsym(&kas, sizeof (kas), "kas") == -1)
		mdb_warn("Couldn't find kas - kernel's struct as\n");
	if (mdb_readsym(&kernelbase, sizeof (kernelbase), "kernelbase") == -1)
		mdb_warn("Couldn't find kernelbase\n");
	khat = kas.a_hat;

	/*
	 * Is this a paravirtualized domain image?
	 */
	if (mdb_readsym(&mfn_list_addr, sizeof (mfn_list_addr),
	    "mfn_list") == -1 ||
	    mdb_readsym(&xen_virt_start, sizeof (xen_virt_start),
	    "xen_virt_start") == -1 ||
	    mdb_readsym(&mfn_count, sizeof (mfn_count), "mfn_count") == -1) {
		mfn_list_addr = NULL;
	}

	is_xpv = mfn_list_addr != NULL;

#ifndef _KMDB
	/*
	 * recreate the local mfn_list
	 */
	if (is_xpv) {
		size_t sz = mfn_count * sizeof (pfn_t);
		mfn_list = mdb_zalloc(sz, UM_SLEEP);

		if (mdb_vread(mfn_list, sz, (uintptr_t)mfn_list_addr) == -1) {
			mdb_warn("Failed to read MFN list\n");
			mdb_free(mfn_list, sz);
			mfn_list = NULL;
		}
	}
#endif
}

void
free_mmu(void)
{
#ifdef __xpv
	if (mfn_list != NULL)
		mdb_free(mfn_list, mfn_count * sizeof (mfn_t));
#endif
}

#ifdef __xpv

#ifdef _KMDB

/*
 * Convert between MFNs and PFNs.  Since we're in kmdb we can go directly
 * through the machine to phys mapping and the MFN list.
 */

pfn_t
mdb_mfn_to_pfn(mfn_t mfn)
{
	pfn_t pfn;
	mfn_t tmp;
	pfn_t *pfn_list;

	if (mfn_list_addr == NULL)
		return (-(pfn_t)1);

	pfn_list = (pfn_t *)xen_virt_start;
	if (mdb_vread(&pfn, sizeof (pfn), (uintptr_t)(pfn_list + mfn)) == -1)
		return (-(pfn_t)1);

	if (mdb_vread(&tmp, sizeof (tmp),
	    (uintptr_t)(mfn_list_addr + (pfn * sizeof (mfn_t)))) == -1)
		return (-(pfn_t)1);

	if (pfn >= mfn_count || tmp != mfn)
		return (-(pfn_t)1);

	return (pfn);
}

mfn_t
mdb_pfn_to_mfn(pfn_t pfn)
{
	mfn_t mfn;

	init_mmu();

	if (mfn_list_addr == NULL || pfn >= mfn_count)
		return (-(mfn_t)1);

	if (mdb_vread(&mfn, sizeof (mfn),
	    (uintptr_t)(mfn_list_addr + (pfn * sizeof (mfn_t)))) == -1)
		return (-(mfn_t)1);

	return (mfn);
}

#else /* _KMDB */

/*
 * Convert between MFNs and PFNs.  Since a crash dump doesn't include the
 * MFN->PFN translation table (it's part of the hypervisor, not our image)
 * we do the MFN->PFN translation by searching the PFN->MFN (mfn_list)
 * table, if it's there.
 */

pfn_t
mdb_mfn_to_pfn(mfn_t mfn)
{
	pfn_t pfn;

	init_mmu();

	if (mfn_list == NULL)
		return (-(pfn_t)1);

	for (pfn = 0; pfn < mfn_count; ++pfn) {
		if (mfn_list[pfn] != mfn)
			continue;
		return (pfn);
	}

	return (-(pfn_t)1);
}

mfn_t
mdb_pfn_to_mfn(pfn_t pfn)
{
	init_mmu();

	if (mfn_list == NULL || pfn >= mfn_count)
		return (-(mfn_t)1);

	return (mfn_list[pfn]);
}

#endif /* _KMDB */

static paddr_t
mdb_ma_to_pa(uint64_t ma)
{
	pfn_t pfn = mdb_mfn_to_pfn(mmu_btop(ma));
	if (pfn == -(pfn_t)1)
		return (-(paddr_t)1);

	return (mmu_ptob((paddr_t)pfn) | (ma & (MMU_PAGESIZE - 1)));
}

#else /* __xpv */

#define	mdb_ma_to_pa(ma) (ma)
#define	mdb_mfn_to_pfn(mfn) (mfn)
#define	mdb_pfn_to_mfn(pfn) (pfn)

#endif /* __xpv */

/*
 * ::mfntopfn dcmd translates hypervisor machine page number
 * to physical page number
 */
/*ARGSUSED*/
int
mfntopfn_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pfn_t pfn;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("MFN missing\n");
		return (DCMD_USAGE);
	}

	if ((pfn = mdb_mfn_to_pfn((pfn_t)addr)) == -(pfn_t)1) {
		mdb_warn("Invalid mfn %lr\n", (pfn_t)addr);
		return (DCMD_ERR);
	}

	mdb_printf("%lr\n", pfn);

	return (DCMD_OK);
}

/*
 * ::pfntomfn dcmd translates physical page number to
 * hypervisor machine page number
 */
/*ARGSUSED*/
int
pfntomfn_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pfn_t mfn;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("PFN missing\n");
		return (DCMD_USAGE);
	}

	if ((mfn = mdb_pfn_to_mfn((pfn_t)addr)) == -(pfn_t)1) {
		mdb_warn("Invalid pfn %lr\n", (pfn_t)addr);
		return (DCMD_ABORT);
	}

	mdb_printf("%lr\n", mfn);

	if (flags & DCMD_LOOP)
		mdb_set_dot(addr + 1);
	return (DCMD_OK);
}

static pfn_t
pte2mfn(x86pte_t pte, uint_t level)
{
	pfn_t mfn;
	if (level > 0 && (pte & PT_PAGESIZE))
		mfn = mmu_btop(pte & PT_PADDR_LGPG);
	else
		mfn = mmu_btop(pte & PT_PADDR);
	return (mfn);
}

static int
do_pte_dcmd(int level, uint64_t pte)
{
	static char *attr[] = {
	    "wrback", "wrthru", "uncached", "uncached",
	    "wrback", "wrthru", "wrcombine", "uncached"};
	int pat_index = 0;
	pfn_t mfn;

	mdb_printf("pte=0x%llr: ", pte);

	mfn = pte2mfn(pte, level);
	mdb_printf("%s=0x%lr ", is_xpv ? "mfn" : "pfn", mfn);

	if (PTE_GET(pte, mmu.pt_nx))
		mdb_printf("noexec ");

	if (PTE_GET(pte, PT_NOCONSIST))
		mdb_printf("noconsist ");

	if (PTE_GET(pte, PT_NOSYNC))
		mdb_printf("nosync ");

	if (PTE_GET(pte, mmu.pt_global))
		mdb_printf("global ");

	if (level > 0 && PTE_GET(pte, PT_PAGESIZE))
		mdb_printf("largepage ");

	if (level > 0 && PTE_GET(pte, PT_MOD))
		mdb_printf("mod ");

	if (level > 0 && PTE_GET(pte, PT_REF))
		mdb_printf("ref ");

	if (PTE_GET(pte, PT_USER))
		mdb_printf("user ");

	if (PTE_GET(pte, PT_WRITABLE))
		mdb_printf("write ");

	/*
	 * Report non-standard cacheability
	 */
	pat_index = 0;
	if (level > 0) {
		if (PTE_GET(pte, PT_PAGESIZE) && PTE_GET(pte, PT_PAT_LARGE))
			pat_index += 4;
	} else {
		if (PTE_GET(pte, PT_PAT_4K))
			pat_index += 4;
	}

	if (PTE_GET(pte, PT_NOCACHE))
		pat_index += 2;

	if (PTE_GET(pte, PT_WRITETHRU))
		pat_index += 1;

	if (pat_index != 0)
		mdb_printf("%s", attr[pat_index]);

	if (PTE_GET(pte, PT_VALID) == 0)
		mdb_printf(" !VALID ");

	mdb_printf("\n");
	return (DCMD_OK);
}

/*
 * Print a PTE in more human friendly way. The PTE is assumed to be in
 * a level 0 page table, unless -l specifies another level.
 */
/*ARGSUSED*/
int
pte_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t level = 0;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'l', MDB_OPT_UINT64, &level) != argc)
		return (DCMD_USAGE);

	if (level > mmu.max_level) {
		mdb_warn("invalid level %lu\n", level);
		return (DCMD_ERR);
	}

	if (addr == 0)
		return (DCMD_OK);

	return (do_pte_dcmd((int)level, addr));
}

static size_t
va2entry(htable_t *htable, uintptr_t addr)
{
	size_t entry = (addr - htable->ht_vaddr);

	entry >>= mmu.level_shift[htable->ht_level];
	return (entry & HTABLE_NUM_PTES(htable) - 1);
}

static x86pte_t
get_pte(hat_t *hat, htable_t *htable, uintptr_t addr)
{
	x86pte_t buf;

	if (htable->ht_flags & HTABLE_COPIED) {
		uintptr_t ptr = (uintptr_t)hat->hat_copied_ptes;
		ptr += va2entry(htable, addr) << mmu.pte_size_shift;
		return (*(x86pte_t *)ptr);
	}

	paddr_t paddr = mmu_ptob((paddr_t)htable->ht_pfn);
	paddr += va2entry(htable, addr) << mmu.pte_size_shift;

	if ((mdb_pread(&buf, mmu.pte_size, paddr)) == mmu.pte_size)
		return (buf);

	return (0);
}

static int
do_va2pa(uintptr_t addr, struct as *asp, int print_level, physaddr_t *pap,
    pfn_t *mfnp)
{
	struct as as;
	struct hat *hatp;
	struct hat hat;
	htable_t *ht;
	htable_t htable;
	uintptr_t base;
	int h;
	int level;
	int found = 0;
	x86pte_t pte;
	physaddr_t paddr;

	if (asp != NULL) {
		if (mdb_vread(&as, sizeof (as), (uintptr_t)asp) == -1) {
			mdb_warn("Couldn't read struct as\n");
			return (DCMD_ERR);
		}
		hatp = as.a_hat;
	} else {
		hatp = khat;
	}

	/*
	 * read the hat and its hash table
	 */
	if (mdb_vread(&hat, sizeof (hat), (uintptr_t)hatp) == -1) {
		mdb_warn("Couldn't read struct hat\n");
		return (DCMD_ERR);
	}

	/*
	 * read the htable hashtable
	 */
	for (level = 0; level <= mmu.max_level; ++level) {
		if (level == TOP_LEVEL(&hat))
			base = 0;
		else
			base = addr & mmu.level_mask[level + 1];

		for (h = 0; h < hat.hat_num_hash; ++h) {
			if (mdb_vread(&ht, sizeof (htable_t *),
			    (uintptr_t)(hat.hat_ht_hash + h)) == -1) {
				mdb_warn("Couldn't read htable\n");
				return (DCMD_ERR);
			}
			for (; ht != NULL; ht = htable.ht_next) {
				if (mdb_vread(&htable, sizeof (htable_t),
				    (uintptr_t)ht) == -1) {
					mdb_warn("Couldn't read htable\n");
					return (DCMD_ERR);
				}

				if (htable.ht_vaddr != base ||
				    htable.ht_level != level)
					continue;

				pte = get_pte(&hat, &htable, addr);

				if (print_level) {
					mdb_printf("\tlevel=%d htable=0x%p "
					    "pte=0x%llr\n", level, ht, pte);
				}

				if (!PTE_ISVALID(pte)) {
					mdb_printf("Address %p is unmapped.\n",
					    addr);
					return (DCMD_ERR);
				}

				if (found)
					continue;

				if (PTE_IS_LGPG(pte, level))
					paddr = mdb_ma_to_pa(pte &
					    PT_PADDR_LGPG);
				else
					paddr = mdb_ma_to_pa(pte & PT_PADDR);
				paddr += addr & mmu.level_offset[level];
				if (pap != NULL)
					*pap = paddr;
				if (mfnp != NULL)
					*mfnp = pte2mfn(pte, level);
				found = 1;
			}
		}
	}

done:
	if (!found)
		return (DCMD_ERR);
	return (DCMD_OK);
}

int
va2pfn_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t addrspace;
	char *addrspace_str = NULL;
	int piped = flags & DCMD_PIPE_OUT;
	pfn_t pfn;
	pfn_t mfn;
	int rc;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_STR, &addrspace_str) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	/*
	 * parse the address space
	 */
	if (addrspace_str != NULL)
		addrspace = mdb_strtoull(addrspace_str);
	else
		addrspace = 0;

	rc = do_va2pa(addr, (struct as *)addrspace, !piped, NULL, &mfn);

	if (rc != DCMD_OK)
		return (rc);

	if ((pfn = mdb_mfn_to_pfn(mfn)) == -(pfn_t)1) {
		mdb_warn("Invalid mfn %lr\n", mfn);
		return (DCMD_ERR);
	}

	if (piped) {
		mdb_printf("0x%lr\n", pfn);
		return (DCMD_OK);
	}

	mdb_printf("Virtual address 0x%p maps pfn 0x%lr", addr, pfn);

	if (is_xpv)
		mdb_printf(" (mfn 0x%lr)", mfn);

	mdb_printf("\n");

	return (DCMD_OK);
}

/*
 * Report all hat's that either use PFN as a page table or that map the page.
 */
static int
do_report_maps(pfn_t pfn)
{
	struct hat *hatp;
	struct hat hat;
	htable_t *ht;
	htable_t htable;
	uintptr_t base;
	int h;
	int level;
	int entry;
	x86pte_t pte;
	physaddr_t paddr;
	size_t len;

	/*
	 * The hats are kept in a list with khat at the head.
	 */
	for (hatp = khat; hatp != NULL; hatp = hat.hat_next) {
		/*
		 * read the hat and its hash table
		 */
		if (mdb_vread(&hat, sizeof (hat), (uintptr_t)hatp) == -1) {
			mdb_warn("Couldn't read struct hat\n");
			return (DCMD_ERR);
		}

		/*
		 * read the htable hashtable
		 */
		paddr = 0;
		for (h = 0; h < hat.hat_num_hash; ++h) {
			if (mdb_vread(&ht, sizeof (htable_t *),
			    (uintptr_t)(hat.hat_ht_hash + h)) == -1) {
				mdb_warn("Couldn't read htable\n");
				return (DCMD_ERR);
			}
			for (; ht != NULL; ht = htable.ht_next) {
				if (mdb_vread(&htable, sizeof (htable_t),
				    (uintptr_t)ht) == -1) {
					mdb_warn("Couldn't read htable\n");
					return (DCMD_ERR);
				}

				/*
				 * only report kernel addresses once
				 */
				if (hatp != khat &&
				    htable.ht_vaddr >= kernelbase)
					continue;

				/*
				 * Is the PFN a pagetable itself?
				 */
				if (htable.ht_pfn == pfn) {
					mdb_printf("Pagetable for "
					    "hat=%p htable=%p\n", hatp, ht);
					continue;
				}

				/*
				 * otherwise, examine page mappings
				 */
				level = htable.ht_level;
				if (level > mmu.max_page_level)
					continue;
				paddr = mmu_ptob((physaddr_t)htable.ht_pfn);
				for (entry = 0;
				    entry < HTABLE_NUM_PTES(&htable);
				    ++entry) {

					base = htable.ht_vaddr + entry *
					    mmu.level_size[level];

					/*
					 * only report kernel addresses once
					 */
					if (hatp != khat &&
					    base >= kernelbase)
						continue;

					len = mdb_pread(&pte, mmu.pte_size,
					    paddr + entry * mmu.pte_size);
					if (len != mmu.pte_size)
						return (DCMD_ERR);

					if ((pte & PT_VALID) == 0)
						continue;
					if (level == 0 || !(pte & PT_PAGESIZE))
						pte &= PT_PADDR;
					else
						pte &= PT_PADDR_LGPG;
					if (mmu_btop(mdb_ma_to_pa(pte)) != pfn)
						continue;
					mdb_printf("hat=%p maps addr=%p\n",
					    hatp, (caddr_t)base);
				}
			}
		}
	}

done:
	return (DCMD_OK);
}

/*
 * given a PFN as its address argument, prints out the uses of it
 */
/*ARGSUSED*/
int
report_maps_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pfn_t pfn;
	uint_t mflag = 0;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'm', MDB_OPT_SETBITS, TRUE, &mflag, NULL) != argc)
		return (DCMD_USAGE);

	pfn = (pfn_t)addr;
	if (mflag)
		pfn = mdb_mfn_to_pfn(pfn);

	return (do_report_maps(pfn));
}

static int
do_ptable_dcmd(pfn_t pfn, uint64_t level)
{
	struct hat *hatp;
	struct hat hat;
	htable_t *ht;
	htable_t htable;
	uintptr_t base;
	int h;
	int entry;
	uintptr_t pagesize;
	x86pte_t pte;
	x86pte_t buf;
	physaddr_t paddr;
	size_t len;

	/*
	 * The hats are kept in a list with khat at the head.
	 */
	for (hatp = khat; hatp != NULL; hatp = hat.hat_next) {
		/*
		 * read the hat and its hash table
		 */
		if (mdb_vread(&hat, sizeof (hat), (uintptr_t)hatp) == -1) {
			mdb_warn("Couldn't read struct hat\n");
			return (DCMD_ERR);
		}

		/*
		 * read the htable hashtable
		 */
		paddr = 0;
		for (h = 0; h < hat.hat_num_hash; ++h) {
			if (mdb_vread(&ht, sizeof (htable_t *),
			    (uintptr_t)(hat.hat_ht_hash + h)) == -1) {
				mdb_warn("Couldn't read htable\n");
				return (DCMD_ERR);
			}
			for (; ht != NULL; ht = htable.ht_next) {
				if (mdb_vread(&htable, sizeof (htable_t),
				    (uintptr_t)ht) == -1) {
					mdb_warn("Couldn't read htable\n");
					return (DCMD_ERR);
				}

				/*
				 * Is this the PFN for this htable
				 */
				if (htable.ht_pfn == pfn)
					goto found_it;
			}
		}
	}

found_it:
	if (htable.ht_pfn == pfn) {
		mdb_printf("htable=%p\n", ht);
		if (level == (uint64_t)-1) {
			level = htable.ht_level;
		} else if (htable.ht_level != level) {
			mdb_warn("htable has level %d but forcing level %lu\n",
			    htable.ht_level, level);
		}
		base = htable.ht_vaddr;
		pagesize = mmu.level_size[level];
	} else {
		if (level == (uint64_t)-1)
			level = 0;
		mdb_warn("couldn't find matching htable, using level=%lu, "
		    "base address=0x0\n", level);
		base = 0;
		pagesize = mmu.level_size[level];
	}

	paddr = mmu_ptob((physaddr_t)pfn);
	for (entry = 0; entry < mmu.ptes_per_table; ++entry) {
		len = mdb_pread(&buf, mmu.pte_size,
		    paddr + entry * mmu.pte_size);
		if (len != mmu.pte_size)
			return (DCMD_ERR);
			pte = buf;

		if (pte == 0)
			continue;

		mdb_printf("[%3d] va=0x%p ", entry,
		    VA_SIGN_EXTEND(base + entry * pagesize));
		do_pte_dcmd(level, pte);
	}

done:
	return (DCMD_OK);
}

/*
 * Dump the page table at the given PFN
 */
/*ARGSUSED*/
int
ptable_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pfn_t pfn;
	uint_t mflag = 0;
	uint64_t level = (uint64_t)-1;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'm', MDB_OPT_SETBITS, TRUE, &mflag,
	    'l', MDB_OPT_UINT64, &level, NULL) != argc)
		return (DCMD_USAGE);

	if (level != (uint64_t)-1 && level > mmu.max_level) {
		mdb_warn("invalid level %lu\n", level);
		return (DCMD_ERR);
	}

	pfn = (pfn_t)addr;
	if (mflag)
		pfn = mdb_mfn_to_pfn(pfn);

	return (do_ptable_dcmd(pfn, level));
}

static int
do_htables_dcmd(hat_t *hatp)
{
	struct hat hat;
	htable_t *ht;
	htable_t htable;
	int h;

	/*
	 * read the hat and its hash table
	 */
	if (mdb_vread(&hat, sizeof (hat), (uintptr_t)hatp) == -1) {
		mdb_warn("Couldn't read struct hat\n");
		return (DCMD_ERR);
	}

	/*
	 * read the htable hashtable
	 */
	for (h = 0; h < hat.hat_num_hash; ++h) {
		if (mdb_vread(&ht, sizeof (htable_t *),
		    (uintptr_t)(hat.hat_ht_hash + h)) == -1) {
			mdb_warn("Couldn't read htable ptr\\n");
			return (DCMD_ERR);
		}
		for (; ht != NULL; ht = htable.ht_next) {
			mdb_printf("%p\n", ht);
			if (mdb_vread(&htable, sizeof (htable_t),
			    (uintptr_t)ht) == -1) {
				mdb_warn("Couldn't read htable\n");
				return (DCMD_ERR);
			}
		}
	}
	return (DCMD_OK);
}

/*
 * Dump the htables for the given hat
 */
/*ARGSUSED*/
int
htables_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	hat_t *hat;

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	hat = (hat_t *)addr;

	return (do_htables_dcmd(hat));
}

static uintptr_t
entry2va(size_t *entries)
{
	uintptr_t va = 0;

	for (level_t l = mmu.max_level; l >= 0; l--)
		va += entries[l] << mmu.level_shift[l];

	return (VA_SIGN_EXTEND(va));
}

static void
ptmap_report(size_t *entries, uintptr_t start,
    boolean_t user, boolean_t writable, boolean_t wflag)
{
	uint64_t curva = entry2va(entries);

	mdb_printf("mapped %s,%s range of %lu bytes: %a-%a\n",
	    user ? "user" : "kernel", writable ? "writable" : "read-only",
	    curva - start, start, curva - 1);
	if (wflag && start >= kernelbase)
		(void) mdb_call_dcmd("whatis", start, DCMD_ADDRSPEC, 0, NULL);
}

int
ptmap_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	physaddr_t paddrs[MAX_NUM_LEVEL] = { 0, };
	size_t entry[MAX_NUM_LEVEL] = { 0, };
	uintptr_t start = (uintptr_t)-1;
	boolean_t writable = B_FALSE;
	boolean_t user = B_FALSE;
	boolean_t wflag = B_FALSE;
	level_t curlevel;

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'w', MDB_OPT_SETBITS, TRUE, &wflag, NULL) != argc)
		return (DCMD_USAGE);

	init_mmu();

	if (mmu.num_level == 0)
		return (DCMD_ERR);

	curlevel = mmu.max_level;

	paddrs[curlevel] = addr & MMU_PAGEMASK;

	for (;;) {
		physaddr_t pte_addr;
		x86pte_t pte;

		pte_addr = paddrs[curlevel] +
		    (entry[curlevel] << mmu.pte_size_shift);

		if (mdb_pread(&pte, sizeof (pte), pte_addr) != sizeof (pte)) {
			mdb_warn("couldn't read pte at %p", pte_addr);
			return (DCMD_ERR);
		}

		if (PTE_GET(pte, PT_VALID) == 0) {
			if (start != (uintptr_t)-1) {
				ptmap_report(entry, start,
				    user, writable, wflag);
				start = (uintptr_t)-1;
			}
		} else if (curlevel == 0 || PTE_GET(pte, PT_PAGESIZE)) {
			if (start == (uintptr_t)-1) {
				start = entry2va(entry);
				user = PTE_GET(pte, PT_USER);
				writable = PTE_GET(pte, PT_WRITABLE);
			} else if (user != PTE_GET(pte, PT_USER) ||
			    writable != PTE_GET(pte, PT_WRITABLE)) {
				ptmap_report(entry, start,
				    user, writable, wflag);
				start = entry2va(entry);
				user = PTE_GET(pte, PT_USER);
				writable = PTE_GET(pte, PT_WRITABLE);
			}
		} else {
			/* Descend a level. */
			physaddr_t pa = mmu_ptob(pte2mfn(pte, curlevel));
			paddrs[--curlevel] = pa;
			entry[curlevel] = 0;
			continue;
		}

		while (++entry[curlevel] == mmu.ptes_per_table) {
			/* Ascend back up. */
			entry[curlevel] = 0;
			if (curlevel == mmu.max_level) {
				if (start != (uintptr_t)-1) {
					ptmap_report(entry, start,
					    user, writable, wflag);
				}
				goto out;
			}

			curlevel++;
		}
	}

out:
	return (DCMD_OK);
}
