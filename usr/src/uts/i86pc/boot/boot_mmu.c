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
 * WARNING: This file is used by both dboot and the kernel.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/machparam.h>
#include <sys/mach_mmu.h>
#ifdef __xpv
#include <sys/hypervisor.h>
#endif

#ifdef _BOOT
#include <dboot/dboot_printf.h>
#define	bop_panic dboot_panic
#else
#include <sys/bootconf.h>
#endif

uint_t shift_amt_nopae[] = {12, 22};
uint_t shift_amt_pae[] = {12, 21, 30, 39};
uint_t *shift_amt;
uint_t ptes_per_table;
uint_t pte_size;
uint32_t lpagesize;
paddr_t top_page_table;
uint_t top_level;

/*
 * Return the index corresponding to a virt address at a given page table level.
 */
static uint_t
vatoindex(uint64_t va, uint_t level)
{
	return ((va >> shift_amt[level]) & (ptes_per_table - 1));
}

/*
 * Return a pointer to the page table entry that maps a virtual address.
 * If there is no page table and probe_only is not set, one is created.
 */
x86pte_t *
find_pte(uint64_t va, paddr_t *pa, uint_t level, uint_t probe_only)
{
	uint_t l;
	uint_t index;
	paddr_t table;

	if (pa)
		*pa = 0;

#ifndef _BOOT
	if (IN_HYPERVISOR_VA(va))
		return (NULL);
#endif

	/*
	 * Walk down the page tables creating any needed intermediate tables.
	 */
	table = top_page_table;
	for (l = top_level; l != level; --l) {
		uint64_t pteval;
		paddr_t new_table;

		index = vatoindex(va, l);
		pteval = get_pteval(table, index);

		/*
		 * Life is easy if we find the pagetable.  We just use it.
		 */
		if (pteval & PT_VALID) {
			table = ma_to_pa(pteval & MMU_PAGEMASK);
			if (table == -1) {
				if (probe_only)
					return (NULL);
				bop_panic("find_pte(): phys not found!");
			}
			continue;
		}

		if (probe_only)
			return (NULL);

		new_table = make_ptable(&pteval, l);
		set_pteval(table, index, l, pteval);

		table = new_table;
	}

	/*
	 * Return a pointer into the current pagetable.
	 */
	index = vatoindex(va, l);
	if (pa)
		*pa = table + index * pte_size;
	return (map_pte(table, index));
}
