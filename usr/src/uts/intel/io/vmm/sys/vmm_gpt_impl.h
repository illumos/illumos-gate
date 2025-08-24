/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _VMM_GPT_IMPL_H
#define	_VMM_GPT_IMPL_H

#include <sys/types.h>
#include <sys/mach_mmu.h>
#include <sys/mman.h>
#include <sys/x86_archext.h>
#include <vm/hat_pte.h>

/*
 * Implementation specific functions and attributes for nested page tables on a
 * given hardware platform (VMX or SVM).
 */
typedef struct vmm_pte_impl vmm_pte_impl_t;
struct vmm_pte_impl {
	/* Create a PTE which maps the next level of paging table */
	uint64_t	(*vpi_map_table)(pfn_t);
	/* Create a PTE which maps a PFN with the provided protection/attrs */
	uint64_t	(*vpi_map_page)(pfn_t, uint_t, uint8_t);
	/*
	 * Parse PTE, returning PFN and protection if it is mapped.
	 * Returns false if PTE does not indicated a mapped page.
	 */
	bool		(*vpi_pte_parse)(uint64_t, pfn_t *, uint_t *);
	/* Bit in PTEs which indicates that they have been accessed */
	uint64_t	vpi_bit_accessed;
	/* Bit in PTEs which indicates that they have been dirtied */
	uint64_t	vpi_bit_dirty;
	/*
	 * Generate PML4 for page tables, given PFN of root and if
	 * accessed/dirty page tracking should be enabled
	 */
	uint64_t	(*vpi_get_pmtp)(pfn_t, bool);
	/* Does this platform support access/dirty page tracking */
	bool		(*vpi_hw_ad_supported)(void);

};

#endif /* _VMM_GPT_IMPL_H */
