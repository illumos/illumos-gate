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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 */

#ifndef	_VM_HAT_I86_H
#define	_VM_HAT_I86_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VM - Hardware Address Translation management.
 *
 * This file describes the contents of the x86_64 HAT data structures.
 */
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <sys/vmparam.h>
#include <sys/vm_machparam.h>
#include <sys/promif.h>
#include <vm/hat_pte.h>
#include <vm/htable.h>
#include <vm/hment.h>

/*
 * The essential data types involved:
 *
 * htable_t	- There is one of these for each page table and it is used
 *		by the HAT to manage the page table.
 *
 * hment_t	- Links together multiple PTEs to a single page.
 */

/*
 * VLP processes have a 32 bit address range, so their top level is 2 and
 * with only 4 PTEs in that table.
 */
#define	VLP_LEVEL	(2)
#define	VLP_NUM_PTES	(4)
#define	VLP_SIZE	(VLP_NUM_PTES * sizeof (x86pte_t))
#define	TOP_LEVEL(h)	(((h)->hat_flags & HAT_VLP) ? VLP_LEVEL : mmu.max_level)
#define	VLP_COPY(fromptep, toptep) { \
	toptep[0] = fromptep[0]; \
	toptep[1] = fromptep[1]; \
	toptep[2] = fromptep[2]; \
	toptep[3] = fromptep[3]; \
}

/*
 * The hat struct exists for each address space.
 */
struct hat {
	kmutex_t	hat_mutex;
	struct as	*hat_as;
	uint_t		hat_stats;
	pgcnt_t		hat_pages_mapped[MAX_PAGE_LEVEL + 1];
	pgcnt_t		hat_ism_pgcnt;
	cpuset_t	hat_cpus;
	uint16_t	hat_flags;
	htable_t	*hat_htable;	/* top level htable */
	struct hat	*hat_next;
	struct hat	*hat_prev;
	uint_t		hat_num_hash;	/* number of htable hash buckets */
	htable_t	**hat_ht_hash;	/* htable hash buckets */
	htable_t	*hat_ht_cached;	/* cached free htables */
	x86pte_t	hat_vlp_ptes[VLP_NUM_PTES];
#if defined(__amd64) && defined(__xpv)
	pfn_t		hat_user_ptable; /* alt top ptable for user mode */
#endif
};
typedef struct hat hat_t;

#define	PGCNT_INC(hat, level)	\
	atomic_inc_ulong(&(hat)->hat_pages_mapped[level]);
#define	PGCNT_DEC(hat, level)	\
	atomic_dec_ulong(&(hat)->hat_pages_mapped[level]);

/*
 * Flags for the hat_flags field
 *
 * HAT_FREEING - set when HAT is being destroyed - mostly used to detect that
 *	demap()s can be avoided.
 *
 * HAT_VLP - indicates a 32 bit process has a virtual address range less than
 *	the hardware's physical address range. (VLP->Virtual Less-than Physical)
 *	Note - never used on the hypervisor.
 *
 * HAT_VICTIM - This is set while a hat is being examined for page table
 *	stealing and prevents it from being freed.
 *
 * HAT_SHARED - The hat has exported it's page tables via hat_share()
 *
 * HAT_PINNED - On the hypervisor, indicates the top page table has been pinned.
 */
#define	HAT_FREEING	(0x0001)
#define	HAT_VLP		(0x0002)
#define	HAT_VICTIM	(0x0004)
#define	HAT_SHARED	(0x0008)
#define	HAT_PINNED	(0x0010)

/*
 * Additional platform attribute for hat_devload() to force no caching.
 */
#define	HAT_PLAT_NOCACHE	(0x100000)

/*
 * Simple statistics for the HAT. These are just counters that are
 * atomically incremented. They can be reset directly from the kernel
 * debugger.
 */
struct hatstats {
	ulong_t	hs_reap_attempts;
	ulong_t	hs_reaped;
	ulong_t	hs_steals;
	ulong_t	hs_ptable_allocs;
	ulong_t	hs_ptable_frees;
	ulong_t	hs_htable_rgets;	/* allocs from reserve */
	ulong_t	hs_htable_rputs;	/* putbacks to reserve */
	ulong_t	hs_htable_shared;	/* number of htables shared */
	ulong_t	hs_htable_unshared;	/* number of htables unshared */
	ulong_t	hs_hm_alloc;
	ulong_t	hs_hm_free;
	ulong_t	hs_hm_put_reserve;
	ulong_t	hs_hm_get_reserve;
	ulong_t	hs_hm_steals;
	ulong_t	hs_hm_steal_exam;
	ulong_t hs_tlb_inval_delayed;
};
extern struct hatstats hatstat;
#ifdef DEBUG
#define	HATSTAT_INC(x)	(++hatstat.x)
#else
#define	HATSTAT_INC(x)	(0)
#endif

#if defined(_KERNEL)

/*
 * Useful macro to align hat_XXX() address arguments to a page boundary
 */
#define	ALIGN2PAGE(a)		((uintptr_t)(a) & MMU_PAGEMASK)
#define	IS_PAGEALIGNED(a)	(((uintptr_t)(a) & MMU_PAGEOFFSET) == 0)

extern uint_t	khat_running;	/* set at end of hat_kern_setup() */
extern cpuset_t khat_cpuset;	/* cpuset for kernal address demap Xcalls */
extern kmutex_t hat_list_lock;
extern kcondvar_t hat_list_cv;



/*
 * Interfaces to setup a cpu private mapping (ie. preemption disabled).
 * The attr and flags arguments are the same as for hat_devload().
 * setup() must be called once, then any number of calls to remap(),
 * followed by a final call to release()
 *
 * Used by ppcopy(), page_zero(), the memscrubber, and the kernel debugger.
 */
typedef paddr_t hat_mempte_t;				/* phys addr of PTE */
extern hat_mempte_t hat_mempte_setup(caddr_t addr);
extern void hat_mempte_remap(pfn_t, caddr_t, hat_mempte_t,
	uint_t attr, uint_t flags);
extern void hat_mempte_release(caddr_t addr, hat_mempte_t);

/*
 * Interfaces to manage which thread has access to htable and hment reserves.
 * The USE_HAT_RESERVES macro should always be recomputed in full. Its value
 * (due to curthread) can change after any call into kmem/vmem.
 */
extern uint_t can_steal_post_boot;
extern uint_t use_boot_reserve;
#define	USE_HAT_RESERVES()					\
	(use_boot_reserve || curthread->t_hatdepth > 1 ||	\
	panicstr != NULL || vmem_is_populator())

/*
 * initialization stuff needed by by startup, mp_startup...
 */
extern void hat_cpu_online(struct cpu *);
extern void hat_cpu_offline(struct cpu *);
extern void setup_vaddr_for_ppcopy(struct cpu *);
extern void teardown_vaddr_for_ppcopy(struct cpu *);
extern void clear_boot_mappings(uintptr_t, uintptr_t);

/*
 * magic value to indicate that all TLB entries should be demapped.
 */
#define	DEMAP_ALL_ADDR	(~(uintptr_t)0)

/*
 * not in any include file???
 */
extern void halt(char *fmt);

/*
 * x86 specific routines for use online in setup or i86pc/vm files
 */
extern void hat_kern_alloc(caddr_t segmap_base, size_t segmap_size,
	caddr_t ekernelheap);
extern void hat_kern_setup(void);
extern void hat_tlb_inval(struct hat *hat, uintptr_t va);
extern void hat_pte_unmap(htable_t *ht, uint_t entry, uint_t flags,
	x86pte_t old_pte, void *pte_ptr, boolean_t tlb);
extern void hat_init_finish(void);
extern caddr_t hat_kpm_pfn2va(pfn_t pfn);
extern pfn_t hat_kpm_va2pfn(caddr_t);
extern page_t *hat_kpm_vaddr2page(caddr_t);
extern uintptr_t hat_kernelbase(uintptr_t);
extern void hat_kmap_init(uintptr_t base, size_t len);

extern hment_t *hati_page_unmap(page_t *pp, htable_t *ht, uint_t entry);

#if !defined(__xpv)
/*
 * routines to deal with delayed TLB invalidations for idle CPUs
 */
extern void tlb_going_idle(void);
extern void tlb_service(void);
#endif

/*
 * Hat switch function invoked to load a new context into %cr3
 */
extern void hat_switch(struct hat *hat);

#ifdef __xpv
/*
 * Interfaces to use around code that maps/unmaps grant table references.
 */
extern void hat_prepare_mapping(hat_t *, caddr_t, uint64_t *);
extern void hat_release_mapping(hat_t *, caddr_t);

#define	XPV_DISALLOW_MIGRATE()	xen_block_migrate()
#define	XPV_ALLOW_MIGRATE()	xen_allow_migrate()

#else

#define	XPV_DISALLOW_MIGRATE()	/* nothing */
#define	XPV_ALLOW_MIGRATE()	/* nothing */

#define	pfn_is_foreign(pfn)	__lintzero

#endif


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_I86_H */
