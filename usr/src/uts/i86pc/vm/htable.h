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
/*
 * Copyright (c) 2014 by Delphix. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_VM_HTABLE_H
#define	_VM_HTABLE_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && defined(_ASM_INLINES) && defined(_KERNEL)
#include <asm/htable.h>
#endif

extern void atomic_andb(uint8_t *addr, uint8_t value);
extern void atomic_orb(uint8_t *addr, uint8_t value);
extern void atomic_inc16(uint16_t *addr);
extern void atomic_dec16(uint16_t *addr);

/*
 * Each hardware page table has an htable_t describing it.
 *
 * We use a reference counter mechanism to detect when we can free an htable.
 * In the implmentation the reference count is split into 2 separate counters:
 *
 *	ht_busy is a traditional reference count of uses of the htable pointer
 *
 *	ht_valid_cnt is a count of how references are implied by valid PTE/PTP
 *	         entries in the pagetable
 *
 * ht_busy is only incremented by htable_lookup() or htable_create()
 * while holding the appropriate hash_table mutex. While installing a new
 * valid PTE or PTP, in order to increment ht_valid_cnt a thread must have
 * done an htable_lookup() or htable_create() but not the htable_release yet.
 *
 * htable_release(), while holding the mutex, can know that if
 * busy == 1 and valid_cnt == 0, the htable can be free'd.
 *
 * The fields have been ordered to make htable_lookup() fast. Hence,
 * ht_hat, ht_vaddr, ht_level and ht_next need to be clustered together.
 */
struct htable {
	struct htable	*ht_next;	/* forward link for hash table */
	struct hat	*ht_hat;	/* hat this mapping comes from */
	uintptr_t	ht_vaddr;	/* virt addr at start of this table */
	int8_t		ht_level;	/* page table level: 0=4K, 1=2M, ... */
	uint8_t		ht_flags;	/* see below */
	int16_t		ht_busy;	/* implements locking protocol */
	int16_t		ht_valid_cnt;	/* # of valid entries in this table */
	uint32_t	ht_lock_cnt;	/* # of locked entries in this table */
					/* never used for kernel hat */
	pfn_t		ht_pfn;		/* pfn of page of the pagetable */
	struct htable	*ht_prev;	/* backward link for hash table */
	struct htable	*ht_parent;	/* htable that points to this htable */
	struct htable	*ht_shares;	/* for HTABLE_SHARED_PFN only */
};
typedef struct htable htable_t;

/*
 * Flags values for htable ht_flags field:
 *
 * HTABLE_COPIED - This is the top level htable of a HAT being used with per-CPU
 * 	pagetables.
 *
 * HTABLE_SHARED_PFN - this htable had its PFN assigned from sharing another
 * 	htable. Used by hat_share() for ISM.
 */
#define	HTABLE_COPIED		(0x01)
#define	HTABLE_SHARED_PFN	(0x02)

/*
 * The htable hash table hashing function.  The 28 is so that high
 * order bits are include in the hash index to skew the wrap
 * around of addresses. Even though the hash buckets are stored per
 * hat we include the value of hat pointer in the hash function so
 * that the secondary hash for the htable mutex winds up begin different in
 * every address space.
 */
#define	HTABLE_HASH(hat, va, lvl)					\
	((((va) >> LEVEL_SHIFT(1)) + ((va) >> 28) + (lvl) +		\
	((uintptr_t)(hat) >> 4)) & ((hat)->hat_num_hash - 1))

/*
 * Each CPU gets a unique hat_cpu_info structure in cpu_hat_info. For more
 * information on its use and members, see uts/i86pc/vm/hat_i86.c.
 */
struct hat_cpu_info {
	kmutex_t hci_mutex;		/* mutex to ensure sequential usage */
#if defined(__amd64)
	pfn_t	hci_pcp_l3pfn;		/* pfn of hci_pcp_l3ptes */
	pfn_t	hci_pcp_l2pfn;		/* pfn of hci_pcp_l2ptes */
	x86pte_t *hci_pcp_l3ptes;	/* PCP Level==3 pagetable (top) */
	x86pte_t *hci_pcp_l2ptes;	/* PCP Level==2 pagetable */
	struct hat *hci_user_hat;	/* CPU specific HAT */
	pfn_t	hci_user_l3pfn;		/* pfn of hci_user_l3ptes */
	x86pte_t *hci_user_l3ptes;	/* PCP User L3 pagetable */
#endif	/* __amd64 */
};


/*
 * Compute the last page aligned VA mapped by an htable.
 *
 * Given a va and a level, compute the virtual address of the start of the
 * next page at that level.
 *
 * XX64 - The check for the VA hole needs to be better generalized.
 */
#if defined(__amd64)
#define	HTABLE_NUM_PTES(ht)	(((ht)->ht_flags & HTABLE_COPIED) ? \
	(((ht)->ht_level == mmu.max_level) ? 512 : 4) : 512)

#define	HTABLE_LAST_PAGE(ht)						\
	((ht)->ht_level == mmu.max_level ? ((uintptr_t)0UL - MMU_PAGESIZE) :\
	((ht)->ht_vaddr - MMU_PAGESIZE +				\
	((uintptr_t)HTABLE_NUM_PTES(ht) << LEVEL_SHIFT((ht)->ht_level))))

#define	NEXT_ENTRY_VA(va, l)	\
	((va & LEVEL_MASK(l)) + LEVEL_SIZE(l) == mmu.hole_start ?	\
	mmu.hole_end : (va & LEVEL_MASK(l)) + LEVEL_SIZE(l))

#elif defined(__i386)

#define	HTABLE_NUM_PTES(ht)	\
	(!mmu.pae_hat ? 1024 : ((ht)->ht_level == 2 ? 4 : 512))

#define	HTABLE_LAST_PAGE(ht)	((ht)->ht_vaddr - MMU_PAGESIZE + \
	((uintptr_t)HTABLE_NUM_PTES(ht) << LEVEL_SHIFT((ht)->ht_level)))

#define	NEXT_ENTRY_VA(va, l) ((va & LEVEL_MASK(l)) + LEVEL_SIZE(l))

#endif

#if defined(_KERNEL)

/*
 * initialization function called from hat_init()
 */
extern void htable_init(void);

/*
 * Functions to lookup, or "lookup and create", the htable corresponding
 * to the virtual address "vaddr"  in the "hat" at the given "level" of
 * page tables. htable_lookup() may return NULL if no such entry exists.
 *
 * On return the given htable is marked busy (a shared lock) - this prevents
 * the htable from being stolen or freed) until htable_release() is called.
 *
 * If kalloc_flag is set on an htable_create() we can't call kmem allocation
 * routines for this htable, since it's for the kernel hat itself.
 *
 * htable_acquire() is used when an htable pointer has been extracted from
 * an hment and we need to get a reference to the htable.
 */
extern htable_t *htable_lookup(struct hat *hat, uintptr_t vaddr, level_t level);
extern htable_t *htable_create(struct hat *hat, uintptr_t vaddr, level_t level,
	htable_t *shared);
extern void htable_acquire(htable_t *);

extern void htable_release(htable_t *ht);
extern void htable_destroy(htable_t *ht);

/*
 * Code to free all remaining htables for a hat. Called after the hat is no
 * longer in use by any thread.
 */
extern void htable_purge_hat(struct hat *hat);

/*
 * Find the htable, page table entry index, and PTE of the given virtual
 * address.  If not found returns NULL. When found, returns the htable_t *,
 * sets entry, and has a hold on the htable.
 */
extern htable_t *htable_getpte(struct hat *, uintptr_t, uint_t *, x86pte_t *,
	level_t);

/*
 * Similar to hat_getpte(), except that this only succeeds if a valid
 * page mapping is present.
 */
extern htable_t *htable_getpage(struct hat *hat, uintptr_t va, uint_t *entry);

/*
 * Called to allocate initial/additional htables for reserve.
 */
extern void htable_initial_reserve(uint_t);
extern void htable_reserve(uint_t);

/*
 * Used to readjust the htable reserve after the reserve list has been used.
 * Also called after boot to release left over boot reserves.
 */
extern void htable_adjust_reserve(void);

/*
 * return number of bytes mapped by all the htables in a given hat
 */
extern size_t htable_mapped(struct hat *);


/*
 * Attach initial pagetables as htables
 */
extern void htable_attach(struct hat *, uintptr_t, level_t, struct htable *,
    pfn_t);

/*
 * Routine to find the next populated htable at or above a given virtual
 * address. Can specify an upper limit, or HTABLE_WALK_TO_END to indicate
 * that it should search the entire address space.  Similar to
 * hat_getpte(), but used for walking through address ranges. It can be
 * used like this:
 *
 *	va = ...
 *	ht = NULL;
 *	while (va < end_va) {
 *		pte = htable_walk(hat, &ht, &va, end_va);
 *		if (!pte)
 *			break;
 *
 *		... code to operate on page at va ...
 *
 *		va += LEVEL_SIZE(ht->ht_level);
 *	}
 *	if (ht)
 *		htable_release(ht);
 *
 */
extern x86pte_t htable_walk(struct hat *hat, htable_t **ht, uintptr_t *va,
	uintptr_t eaddr);

#define	HTABLE_WALK_TO_END ((uintptr_t)-1)

/*
 * Utilities convert between virtual addresses and page table entry indeces.
 */
extern uint_t htable_va2entry(uintptr_t va, htable_t *ht);
extern uintptr_t htable_e2va(htable_t *ht, uint_t entry);

/*
 * Interfaces that provide access to page table entries via the htable.
 *
 * Note that all accesses except x86pte_copy() and x86pte_zero() are atomic.
 */
extern void	x86pte_cpu_init(cpu_t *);
extern void	x86pte_cpu_fini(cpu_t *);

extern x86pte_t	x86pte_get(htable_t *, uint_t entry);

/*
 * x86pte_set returns LPAGE_ERROR if it's asked to overwrite a page table
 * link with a large page mapping.
 */
#define	LPAGE_ERROR (-(x86pte_t)1)
extern x86pte_t	x86pte_set(htable_t *, uint_t entry, x86pte_t new, void *);

extern x86pte_t x86pte_inval(htable_t *ht, uint_t entry,
	x86pte_t old, x86pte_t *ptr, boolean_t tlb);

extern x86pte_t x86pte_update(htable_t *ht, uint_t entry,
	x86pte_t old, x86pte_t new);

extern void	x86pte_copy(htable_t *src, htable_t *dest, uint_t entry,
	uint_t cnt);

/*
 * access to a pagetable knowing only the pfn
 */
extern x86pte_t *x86pte_mapin(pfn_t, uint_t, htable_t *);
extern void x86pte_mapout(void);

/*
 * these are actually inlines for "lock; incw", "lock; decw", etc. instructions.
 */
#define	HTABLE_INC(x)	atomic_inc16((uint16_t *)&x)
#define	HTABLE_DEC(x)	atomic_dec16((uint16_t *)&x)
#define	HTABLE_LOCK_INC(ht)	atomic_inc_32(&(ht)->ht_lock_cnt)
#define	HTABLE_LOCK_DEC(ht)	atomic_dec_32(&(ht)->ht_lock_cnt)

#ifdef __xpv
extern void xen_flush_va(caddr_t va);
extern void xen_gflush_va(caddr_t va, cpuset_t);
extern void xen_flush_tlb(void);
extern void xen_gflush_tlb(cpuset_t);
extern void xen_pin(pfn_t, level_t);
extern void xen_unpin(pfn_t);
extern int xen_kpm_page(pfn_t, uint_t);

/*
 * The hypervisor maps all page tables into our address space read-only.
 * Under normal circumstances, the hypervisor then handles all updates to
 * the page tables underneath the covers for us.  However, when we are
 * trying to dump core after a hypervisor panic, the hypervisor is no
 * longer available to do these updates.  To work around the protection
 * problem, we simply disable write-protect checking for the duration of a
 * pagetable update operation.
 */
#define	XPV_ALLOW_PAGETABLE_UPDATES()					\
	{								\
		if (IN_XPV_PANIC())					\
			setcr0((getcr0() & ~CR0_WP) & 0xffffffff); 	\
	}
#define	XPV_DISALLOW_PAGETABLE_UPDATES()				\
	{								\
		if (IN_XPV_PANIC() > 0)					\
			setcr0((getcr0() | CR0_WP) & 0xffffffff);	\
	}

#else /* __xpv */

#define	XPV_ALLOW_PAGETABLE_UPDATES()
#define	XPV_DISALLOW_PAGETABLE_UPDATES()

#endif

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HTABLE_H */
