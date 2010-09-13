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
 */

#ifndef _SYS_XEN_MMU_H
#define	_SYS_XEN_MMU_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Platform-dependent MMU routines and types for the hypervisor.
 *
 * WARNING: this header file is used by both dboot and i86pc, so don't go using
 * normal kernel headers.
 */

#if (defined(_BOOT) && defined(_BOOT_TARGET_amd64)) || \
	(!defined(_BOOT) && defined(__amd64))
#define	__target_amd64
#endif

typedef uint64_t maddr_t;
#define	mfn_to_ma(mfn)	((maddr_t)(mfn) << MMU_PAGESHIFT)

#ifdef __xpv

#ifdef __target_amd64

#define	IN_HYPERVISOR_VA(va) \
	((va) >= HYPERVISOR_VIRT_START && (va) < HYPERVISOR_VIRT_END)

#else /* __target_amd64 */

#define	IN_HYPERVISOR_VA(va) ((va) >= xen_virt_start)

/*
 * Do this to help catch any uses.
 */
#undef	HYPERVISOR_VIRT_START
#undef	machine_to_phys_mapping

#endif /* __target_amd64 */

#undef __target_amd64

paddr_t ma_to_pa(maddr_t);
maddr_t pa_to_ma(paddr_t);
#endif /* __xpv */

extern uintptr_t xen_virt_start;
extern pfn_t *mfn_to_pfn_mapping;

#ifndef _BOOT

/*
 * On the hypervisor we need:
 * - a way to map a machine address (ie, not pseudo-physical).
 * - to relocate initial hypervisor data structures into kernel VA range.
 * - a way to translate between physical addresses and machine addresses.
 * - a way to change the machine address behind a physical address.
 */
typedef ulong_t mfn_t;
extern mfn_t *mfn_list;
extern mfn_t *mfn_list_pages;
extern mfn_t *mfn_list_pages_page;
extern ulong_t mfn_count;
extern mfn_t cached_max_mfn;

/*
 * locks for mfn_list[] and machine_to_phys_mapping[] when migration / suspend
 * events happen
 */
extern void xen_block_migrate(void);
extern void xen_allow_migrate(void);
extern void xen_start_migrate(void);
extern void xen_end_migrate(void);

/*
 * Conversion between machine (hardware) addresses and pseudo-physical
 * addresses.
 */
#ifdef __xpv
pfn_t mfn_to_pfn(mfn_t);
mfn_t pfn_to_mfn(pfn_t);
#endif

struct page;

void xen_relocate_start_info(void);

/*
 * interfaces to create/destroy pfn_t values for devices or foreign memory
 *
 * xen_assign_pfn() creates (or looks up) a local pfn value to use for things
 * like a foreign domain memory mfn or a device mfn.
 *
 * xen_release_pfn() destroys the association between a pfn and foreign mfn.
 */
pfn_t xen_assign_pfn(mfn_t mfn);
void xen_release_pfn(pfn_t);
uint_t pfn_is_foreign(pfn_t);
void reassign_pfn(pfn_t pfn, mfn_t mfn);

#define	MFN_INVALID	(-(mfn_t)1)

#endif /* !_BOOT */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XEN_MMU_H */
