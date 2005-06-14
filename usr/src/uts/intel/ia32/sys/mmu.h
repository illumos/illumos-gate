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

#ifndef	_IA32_SYS_MMU_H
#define	_IA32_SYS_MMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <sys/pte.h>
#if defined(__GNUC__) && defined(_ASM_INLINES) && defined(_KERNEL)
#include <asm/mmu.h>
#endif
#endif

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Definitions for the Intel 80x86 MMU
 */

/*
 * Page fault error code, pushed onto stack on page fault exception
 */
#define	MMU_PFEC_P		0x1	/* Page present */
#define	MMU_PFEC_WRITE		0x2	/* Write access */
#define	MMU_PFEC_USER		0x4	/* User mode access */

/* Access types based on above error codes */
#define	MMU_PFEC_AT_MASK	(MMU_PFEC_USER|MMU_PFEC_WRITE)
#define	MMU_PFEC_AT_UREAD	MMU_PFEC_USER
#define	MMU_PFEC_AT_UWRITE	(MMU_PFEC_USER|MMU_PFEC_WRITE)
#define	MMU_PFEC_AT_SREAD	0
#define	MMU_PFEC_AT_SWRITE	MMU_PFEC_WRITE

#if defined(_KERNEL) && !defined(_ASM)

extern int valid_va_range(caddr_t *, size_t *, size_t, int);

#endif /* defined(_KERNEL) && !defined(_ASM) */

/*
 * Page directory and physical page parameters
 */
#ifndef MMU_PAGESIZE
#define	MMU_PAGESIZE	4096
#endif



#define	MMU_STD_PAGESIZE	MMU_PAGESIZE
#ifdef __amd64
#define	MMU_STD_PAGEMASK	0xFFFFFFFFFFFFF000ULL
#else
#define	MMU_STD_PAGEMASK	0xFFFFF000UL
#endif
#define	MMU_STD_PAGESHIFT	12



/* ### also in pte.h */

#define	TWOMB_PAGESIZE		0x200000
#define	TWOMB_PAGEOFFSET	(TWOMB_PAGESIZE - 1)
#define	TWOMB_PAGESHIFT		21
#define	FOURMB_PAGESIZE		0x400000
#define	FOURMB_PAGEOFFSET	(FOURMB_PAGESIZE - 1)
#define	FOURMB_PAGESHIFT	22
#define	FOURMB_PAGEMASK		(~FOURMB_PAGEOFFSET)

#define	HAT_INVLDPFNUM		0xffffffff

#define	IN_SAME_4MB_PAGE(a, b)	(MMU_L1_INDEX(a)  ==  MMU_L1_INDEX(b))
#define	FOURMB_PDE(a, g,  b, c) \
	((((uint32_t)((uint_t)(a))) << MMU_STD_PAGESHIFT) |\
	((g) << 8) | PTE_LARGEPAGE |(((b) & 0x03) << 1) | (c))

#ifndef _ASM
#define	mmu_tlbflush_all()	reload_cr3()

/* Low-level functions */
extern void mmu_tlbflush_entry(caddr_t);
extern ulong_t getcr3(void);
extern void reload_cr3(void);
extern void setcr3(ulong_t);
#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _IA32_SYS_MMU_H */
