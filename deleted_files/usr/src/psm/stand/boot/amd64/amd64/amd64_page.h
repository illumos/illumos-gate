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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AMD64_AMD64_PAGE_H
#define	_AMD64_AMD64_PAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AMD64_PAGESIZE		4096
#define	AMD64_PAGESIZE2M	(2*1024*1024)
#define	AMD64_PAGESIZE4M	(4*1024*1024)

#define	AMD64_PAGEOFFSET(pagesize)	((uint64_t)((pagesize) - 1))
#define	AMD64_PAGEMASK(pagesize)	(~(AMD64_PAGEOFFSET(pagesize)))

#define	AMD64_PAGEALIGNED(va, pagesize)	\
	(!((uint64_t)(va) & AMD64_PAGEOFFSET(pagesize)))

#define	AMD64_PAGESIZE_OFFSET_NBITS	11

#define	BIT_GLOBAL	8
#define	BIT_PS		7	/* PDE only */
#define	BIT_US		2
#define	BIT_RW		1
#define	BIT_VALID	0

#define	TBL_GLOBAL	(1 << BIT_GLOBAL)
#define	TBL_US		(1 << BIT_US)
#define	TBL_RW		(1 << BIT_RW)
#define	TBL_VALID	(1 << BIT_VALID)

#define	PDE_PS		(1 << BIT_PS)

#define	IS_PDE(level, amd64_mmu_mode)	\
	((level) == (mmus[(amd64_mmu_mode)].map_level - 1))

#define	IS_PTE(level, amd64_mmu_mode)	\
	((level) == mmus[(amd64_mmu_mode)].map_level)

#define	IS_LARGEMAP(entry)	((entry) & PDE_PS)
#define	ENTRY_VALID(entry)	((entry) & TBL_VALID)

#define	PA_MODBITS_MASK		0x1eULL
#define	PA_MODBITS(entry)	(((uint64_t)(entry)) & PA_MODBITS_MASK)

#define	AMD64_MODE_LEGACY	0
#define	AMD64_MODE_LONG64	1

typedef struct amd64_mmumode {
	uint8_t	shift_base;	/* shift to start of page tables */
	uint8_t	level_shift;	/* shift between page table levels */
	uint8_t	map_level;	/* mapping level for AMD64_PAGESIZE pages */
	uint16_t tbl_entries;	/* number of entries per table level */
} amd64_mmumode_t;

/*
 * This macro is needed because of a difference of opinion between compilers
 * that can result in inadvertent sign extension when converting from 32-bit
 * to 64-bit values.
 *
 * For example, given the code:
 *
 *    long *i = (long *)0xf0000000;
 *    unsigned long long l;
 *
 *    l = (unsigned long long)i;
 *
 * GCC will currently sign extend "i" before converting it to unsigned long
 * long, resulting in the value 0xfffffffff0000000 being stored in l.
 *
 * On the other hand, Forte compilers will not do the extension, resulting in
 * l receiving the value 0xf0000000.
 *
 * The only way to assure sane results regardless of compiler is to use this
 * macro whenever converting any value to an unsigned 64-bit value.
 */
#define	UINT64_FROMPTR32(val32)	((uint64_t)(uintptr_t)(val32))

#define	TBL_ENTRY_DEFAULT(pa)	(UINT64_FROMPTR32(pa) | TBL_RW | TBL_VALID)
#define	TBL_PTR(table)		((uint64_t *)(&table))

#define	TBL_INDEX(va, shift, mask)	(((va) >> (shift)) & mask)

#define	TBL_ENTRY32(amd64_mmu_mode, tbl_base, va, shift, mask)		\
	(((amd64_mmu_mode) == AMD64_MODE_LEGACY) ?			\
	    (*(((uint32_t *)(tbl_base)) +				\
	    TBL_INDEX((va), (shift), (mask)))) :			\
	    ((uint32_t)*(((uint64_t *)(tbl_base)) +			\
	    TBL_INDEX((va), (shift), (mask)))))

#define	TBL_ENTRY64(amd64_mmu_mode, tbl_base, va, shift, mask)		\
	(((amd64_mmu_mode) == AMD64_MODE_LEGACY) ?			\
	    ((uint64_t)(*(((uint32_t *)(tbl_base)) +			\
	    TBL_INDEX((va), (shift), (mask))))) :			\
	    (*(((uint64_t *)(tbl_base)) + TBL_INDEX((va), (shift), (mask)))))

#define	SET_TABLEVAL(amd64_mmu_mode, tbl_base, va, shift, mask, val)	\
	(((amd64_mmu_mode) == AMD64_MODE_LEGACY) ?			\
	    (*(((uint32_t *)(tbl_base)) +				\
	    TBL_INDEX((va), (shift), (mask))) = (uint32_t)val) :	\
	    (*(((uint64_t *)(tbl_base)) + TBL_INDEX((va), (shift),	\
	    (mask))) = val))

#define	VA64_OFFSET	(0xffffffff00000000ULL)

#define	ADDR_TRUNC(a)	((void *)((uintptr_t)(a)))
#define	ADDR_XTND(a)	(((uintptr_t)(a)) == 0 ? 0ULL :	\
			    ((UINT64_FROMPTR32(a)) | VA64_OFFSET))

extern void amd64_map_mem(uint64_t, uint64_t, uint32_t, uint8_t, uint32_t,
    uint16_t);

extern uint16_t amd64_modbits(uint64_t);

extern uint64_t amd64_legacy_physaddr(uint32_t);
extern uint64_t amd64_long_physaddr(uint64_t);
extern uint64_t amd64_physaddr(uint64_t, uint8_t);

extern uint64_t amd64_long_lookup(uint64_t, uint32_t *, uint32_t);
extern uint32_t amd64_legacy_lookup(uint64_t, uint32_t *, uint32_t);
extern uint64_t amd64_legacy_lookup_physaddr(uint64_t, uint32_t);

extern uint64_t amd64_init_longpt(uint32_t);

extern void amd64_xlate_legacy_va(uint32_t, uint32_t, uint32_t, uint32_t);
extern void amd64_xlate_long_va(uint64_t, uint32_t, uint32_t, uint32_t);

extern void amd64_xlate_boot_tables(uint32_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_AMD64_PAGE_H */
