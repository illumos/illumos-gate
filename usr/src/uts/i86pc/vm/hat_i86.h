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

#ifndef	_VM_HAT_I86_H
#define	_VM_HAT_I86_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	kmutex_t	hat_switch_mutex;
	struct as	*hat_as;
	uint_t		hat_stats;
	pgcnt_t		hat_pages_mapped[MAX_PAGE_LEVEL + 1];
	cpuset_t	hat_cpus;
	uint16_t	hat_flags;
	htable_t	*hat_htable;	/* top level htable */
	struct hat	*hat_next;
	struct hat	*hat_prev;
	uint_t		hat_num_hash;	/* number of htable hash buckets */
	htable_t	**hat_ht_hash;	/* htable hash buckets */
	htable_t	*hat_ht_cached;	/* cached free htables */
	x86pte_t	hat_vlp_ptes[VLP_NUM_PTES];
};
typedef struct hat hat_t;

#define	PGCNT_INC(hat, level) \
	atomic_add_long(&(hat)->hat_pages_mapped[level], 1);
#define	PGCNT_DEC(hat, level) \
	atomic_add_long(&(hat)->hat_pages_mapped[level], -1);

/*
 * Flags for the hat_flags field
 *
 * HAT_FREEING - set when HAT is being destroyed - mostly used to detect that
 *	demap()s can be avoided.
 *
 * HAT_VLP - indicates a 32 bit process has a virtual address range less than
 *	the hardware's physical address range. (VLP->Virtual Less-than Physical)
 *
 * HAT_VICTIM - This is set while a hat is being examined for page table
 *	stealing and prevents it from being freed.
 *
 * HAT_SHARED - The hat has exported it's page tables via hat_share()
 */
#define	HAT_FREEING	(0x0001)
#define	HAT_VLP		(0x0002)
#define	HAT_VICTIM	(0x0004)
#define	HAT_SHARED	(0x0008)

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
	uint64_t	hs_reap_attempts;
	uint64_t	hs_reaped;
	uint64_t	hs_steals;
	uint64_t	hs_ptable_allocs;
	uint64_t	hs_ptable_frees;
	uint64_t	hs_htable_rgets;	/* allocs from reserve */
	uint64_t	hs_htable_rputs;	/* putbacks to reserve */
	uint64_t	hs_htable_shared;	/* number of htables shared */
	uint64_t	hs_htable_unshared;	/* number of htables unshared */
	uint64_t	hs_hm_alloc;
	uint64_t	hs_hm_free;
	uint64_t	hs_hm_put_reserve;
	uint64_t	hs_hm_get_reserve;
	uint64_t	hs_hm_steals;
	uint64_t	hs_hm_steal_exam;
};
extern struct hatstats hatstat;
#define	HATSTAT_INC(x)	(atomic_add_64(&hatstat.x, 1))

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
extern void *hat_mempte_kern_setup(caddr_t addr, void *);
extern void *hat_mempte_setup(caddr_t addr);
extern void hat_mempte_remap(pfn_t, caddr_t, void *, uint_t attr, uint_t flags);
extern void hat_mempte_release(caddr_t addr, void *);

/*
 * interfaces to manage which thread has access to htable and hment reserves
 */
extern uint_t can_steal_post_boot;
extern uint_t use_boot_reserve;
extern kthread_t *hat_reserves_thread;

/*
 * initialization stuff needed by by startup, mp_startup...
 */
extern void hat_cpu_online(struct cpu *);
extern void setup_vaddr_for_ppcopy(struct cpu *);
extern void clear_boot_mappings(uintptr_t, uintptr_t);
extern int hat_boot_probe(uintptr_t *va, size_t *len, pfn_t *pfn, uint_t *prot);

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
extern void hat_kern_alloc(void);
extern void hati_kern_setup_load(uintptr_t, size_t, pfn_t, pgcnt_t, uint_t);
extern void hat_demap(struct hat *hat, uintptr_t va);
extern void hat_pte_unmap(htable_t *ht, uint_t entry, uint_t flags,
	x86pte_t old_pte, void *pte_ptr);
extern void hat_init_finish(void);
extern void hat_kmap_init(uintptr_t base, size_t len);
extern caddr_t hat_kpm_pfn2va(pfn_t pfn);
extern pfn_t hat_kpm_va2pfn(caddr_t);
extern page_t *hat_kpm_vaddr2page(caddr_t);
extern uintptr_t hat_kernelbase(uintptr_t);

extern pfn_t hat_boot_remap(uintptr_t, pfn_t);
extern void hat_boot_demap(uintptr_t);
extern hment_t *hati_page_unmap(page_t *pp, htable_t *ht, uint_t entry);
/*
 * Hat switch function invoked to load a new context into %cr3
 */
extern void hat_switch(struct hat *hat);


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_I86_H */
