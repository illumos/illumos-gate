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

#ifndef _SYS_MACH_MMU_H
#define	_SYS_MACH_MMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/types.h>
#include <sys/systm.h>

/*
 * Platform-dependent MMU routines and types.
 *
 * WARNING: this header file is used by both dboot and i86pc, so don't go using
 * normal kernel headers.
 */

#define	TWO_MEG		(2 * 1024 * 1024)

/*
 * This is:
 *	The kernel nucleus pagesizes, ie: bi->bi_kseg_size
 *	The grub 64 bit file load address (see multiboot header in dboot_grub.s)
 *	The grub 32 bit and hypervisor physical load addresses of
 *	    the kernel text/data (see Mapfile.unix)
 */
#define	FOUR_MEG	(4 * 1024 * 1024)

#define	ONE_GIG		(1024 * 1024 * 1024)
#define	FOUR_GIG	((uint64_t)4 * ONE_GIG)

#define	MMU_STD_PAGESIZE	4096
#ifdef __amd64
#define	MMU_STD_PAGEMASK	0xFFFFFFFFFFFFF000ULL
#else
#define	MMU_STD_PAGEMASK	0xFFFFF000UL
#endif

/*
 * Defines for the bits in X86 and AMD64 Page Tables
 *
 * Notes:
 *
 * Largepages and PAT bits:
 *
 * bit 7 at level 0 is the PAT bit
 * bit 7 above level 0 is the Pagesize bit (set for large page)
 * bit 12 (when a large page) is the PAT bit
 *
 * In Solaris the PAT/PWT/PCD values are set up so that:
 *
 * PAT & PWT -> Write Protected
 * PAT & PCD -> Write Combining
 * PAT by itself (PWT == 0 && PCD == 0) yields uncacheable (same as PCD == 1)
 *
 *
 * Permission bits:
 *
 * - PT_USER must be set in all levels for user pages
 * - PT_WRITE must be set in all levels for user writable pages
 * - PT_NX applies if set at any level
 *
 * For these, we use the "allow" settings in all tables above level 0 and only
 * ever disable things in PTEs.
 *
 * The use of PT_GLOBAL and PT_NX depend on being enabled in processor
 * control registers. Hence, we use a variable to reference these bit
 * masks. During hat_kern_setup() if the feature isn't enabled we
 * clear out the variables.
 */
#define	PT_VALID	(0x001)	/* a valid translation is present */
#define	PT_WRITABLE	(0x002)	/* the page is writable */
#define	PT_USER		(0x004)	/* the page is accessible by user mode */
#define	PT_WRITETHRU	(0x008)	/* write back caching is disabled (non-PAT) */
#define	PT_NOCACHE	(0x010)	/* page is not cacheable (non-PAT) */
#define	PT_REF		(0x020)	/* page was referenced */
#define	PT_MOD		(0x040)	/* page was modified */
#define	PT_PAGESIZE	(0x080)	/* above level 0, indicates a large page */
#define	PT_PAT_4K	(0x080) /* at level 0, used for write combining */
#define	PT_GLOBAL	(0x100)	/* the mapping is global */
#define	PT_SOFTWARE	(0xe00)	/* software bits */

#define	PT_PAT_LARGE	(0x1000)	/* PAT bit for large pages */

#define	PT_PTPBITS	(PT_VALID | PT_USER | PT_WRITABLE | PT_REF)
#define	PT_FLAGBITS	(0xfff)	/* for masking off flag bits */

/*
 * The software bits are used by the HAT to track attributes.
 * Note that the attributes are inclusive as the values increase.
 *
 * PT_NOSYNC - The PT_REF/PT_MOD bits are not sync'd to page_t.
 *             The hat will install them as always set.
 *
 * PT_NOCONSIST - There is no hment entry for this mapping.
 *
 * PT_FOREIGN - used for the hypervisor, check via
 *		(pte & PT_SOFTWARE) >= PT_FOREIGN
 *		as it might set	0x800 for foreign grant table mappings.
 */
#define	PT_NOSYNC	(0x200)	/* PTE was created with HAT_NOSYNC */
#define	PT_NOCONSIST	(0x400)	/* PTE was created with HAT_LOAD_NOCONSIST */
#define	PT_FOREIGN	(0x600)	/* MFN mapped on the hypervisor has no PFN */

#ifdef __xpv
#include <sys/xen_mmu.h>
#else
#include <sys/pc_mmu.h>
#endif

/*
 * The software extraction for a single Page Table Entry will always
 * be a 64 bit unsigned int. If running a non-PAE hat, the page table
 * access routines know to extend/shorten it to 32 bits.
 */
typedef uint64_t x86pte_t;
typedef uint32_t x86pte32_t;

x86pte_t get_pteval(paddr_t, uint_t);
void set_pteval(paddr_t, uint_t, uint_t, x86pte_t);
paddr_t make_ptable(x86pte_t *, uint_t);
x86pte_t *find_pte(uint64_t, paddr_t *, uint_t, uint_t);
x86pte_t *map_pte(paddr_t, uint_t);

#ifndef _BOOT
ulong_t getcr3();
#endif

extern uint_t *shift_amt;
extern uint_t ptes_per_table;
extern paddr_t top_page_table;
extern uint_t top_level;
extern uint_t pte_size;
extern uint_t shift_amt_nopae[];
extern uint_t shift_amt_pae[];
extern uint32_t lpagesize;

#ifdef __cplusplus
}
#endif

#endif /* _ASM */

#endif	/* _SYS_MACH_MMU_H */
