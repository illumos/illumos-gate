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

#ifndef	_SUN4_MMU_H
#define	_SUN4_MMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sun-4 memory management unit.
 * All sun-4 implementations use 32 bits of address.
 * A particular implementation may implement a smaller MMU.
 * If so, the missing addresses are in the "middle" of the
 * 32 bit address space. All accesses in this range behave
 * as if there was an invalid page map entry correspronding
 * to the address.
 *
 * There are two types of MMUs a 2 level MMU and a 3 level MMU.
 * Three level MMUs do not have holes.
 */

/*
 * Hardware context and segment information
 * Mnemonic decoding:
 *	PMENT - Page Map ENTry
 *	PMGRP - Group of PMENTs (aka "segment")
 *	SMENT - Segment Map ENTry - 3 level MMU only
 *	SMGRP - Group of SMENTs (aka "region") - 3 level MMU only
 */
/* fixed SUN4 constants */
#define	NPMENTPERPMGRP		32
#define	NPMENTPERPMGRPSHIFT	5	/* log2(NPMENTPERPMGRP) */
#define	PMGRPSIZE	(NPMENTPERPMGRP * PAGESIZE)
#define	PMGRPOFFSET	(PMGRPSIZE - 1)
#define	PMGRPSHIFT	(PAGESHIFT + NPMENTPERPMGRPSHIFT)
#define	PMGRPMASK	(~PMGRPOFFSET)

#define	NSMENTPERSMGRP		64
#define	NSMENTPERSMGRPSHIFT	6	/* log2(NSMENTPERSMGRP) */
#define	SMGRPSIZE	(NSMENTPERSMGRP * PMGRPSIZE)
#define	SMGRPOFFSET	(SMGRPSIZE - 1)
#define	SMGRPSHIFT	(PMGRPSHIFT + NSMENTPERSMGRPSHIFT)
#define	SMGRPMASK	(~SMGRPOFFSET)

#define	NSMGRPPERCTX		256

/*
 * Useful defines for hat constants,
 * Every implementation seems to have its own set
 * they are set at boot time by setcputype()
 */
#define	NCTXS		nctxs
#define	NPMGRPS		npmgrps
#define	NSMGRPS		nsmgrps

/*
 * Variables set at boot time to reflect cpu type.
 */
#ifndef LOCORE
#include <sys/types.h>

extern uint_t nctxs;		/* number of implemented contexts */
extern uint_t npmgrps;		/* number of pmgrps in page map */
#ifdef	MMU_3LEVEL
extern uint_t nsmgrps;		/* number of smgrps in segment map (3 level) */
#endif	/* MMU_3LEVEL */
extern uint_t segmask;		/* mask for segment number */
extern addr_t hole_start;	/* addr of start of MMU "hole" */
extern addr_t hole_end;		/* addr of end of MMU "hole" */
extern uint_t shm_alignment;	/* VAC address consistency modulus */

#ifdef MMU_3LEVEL
extern int mmu_3level;		/* indicates 3 level MMU can exist */
#endif /* MMU_3LEVEL */

#define	PMGRP_INVALID (NPMGRPS - 1)
#define	SMGRP_INVALID (NSMGRPS - 1)

/*
 * Macro to determine whether an address is within the range of the MMU.
 */
#ifdef MMU_3LEVEL
#define	good_addr(a) \
	(mmu_3level || (addr_t)(a) < hole_start || (addr_t)(a) >= hole_end)
#else
#define	good_addr(a) \
	((addr_t)(a) < hole_start || (addr_t)(a) >= hole_end)
#endif /* MMU_3LEVEL */
#endif /* !LOCORE */

/*
 * Address space identifiers.
 */
#define	ASI_CTL	0x2		/* control space */
#define	ASI_SM	0x3		/* segment map */
#define	ASI_PM	0x4		/* page map */
#define	ASI_BC	0x5		/* block copy */
#define	ASI_RM	0x6		/* region map */
#define	ASI_FCR	0x7		/* flush cache region */
#define	ASI_UP	0x8		/* user program */
#define	ASI_SP	0x9		/* supervisor program */
#define	ASI_UD	0xA		/* user data */
#define	ASI_SD	0xB		/* supervisor data */
#define	ASI_FCS	0xC		/* flush cache segment */
#define	ASI_FCP	0xD		/* flush cache page */
#define	ASI_FCC	0xE		/* flush cache context */
#define	ASI_FCU 0xF		/* flush cache user, sunray */

#define	ASI_CD	0xF		/* cache data, sunrise */

/*
 * ASI_CTL addresses
 */
#define	ID_PROM		0x00000000
#define	CONTEXT_REG	0x30000000
#define	SYSTEM_ENABLE	0x40000000
#define	BUS_ERROR_REG	0x60000000
#define	DIAGNOSTIC_REG	0x70000000
#define	CACHE_TAGS	0x80000000
#define	CACHE_DATA	0x90000000	/* cache data, sunray */
#define	VME_INT_VEC	0xE0000000
#define	UART_BYPASS	0xF0000000

#define	IDPROMSIZE	0x20		/* size of id prom in bytes */

/*
 * Constants for cache operations.
 * XXX - should be deleted but the standalones (boot) use them.
 */
#define	VAC_SIZE		0x20000		/* 128K */
#define	VAC_LINESIZE_SUNRISE	16		/* 16 bytes per line */
#define	VAC_LINESIZE_SUNRAY	32		/* 32 bytes per line */
#define	NPMGRPPERCTX_110	4096
#define	NPMGRPPERCTX_260	4096
#define	NPMGRPPERCTX_330	4096
#define	NPMGRPS_110		256
#define	NPMGRPS_260		512
#define	NPMGRPS_330		256
#define	NPMGRPS_470		1024

/*
 * Various I/O space related constants
 */
#define	VME16_BASE	0xFFFF0000
#define	VME16_SIZE	(1<<16)
#define	VME16_MASK	(VME16_SIZE-1)

#define	VME24_BASE	0xFF000000
#define	VME24_SIZE	(1<<24)
#define	VME24_MASK	(VME24_SIZE-1)

/*
 * Virtual address where dvma starts.
 */
#define	DVMABASE	(0-(1024*1024))

/*
 * Context for kernel. On a Sun-4 the kernel is in every address space,
 * but KCONTEXT is magic in that there is never any user context there.
 */
#define	KCONTEXT	0

/*
 * MDEVBASE is a virtual segment reserved for mapping misc. obio devices.
 * The base address and the number of devices mapped should not cause the
 * device mappings to cross a segment boundary.  We use the segment
 * immediately before SYSBASE
 */
#define	MDEVBASE	(SYSBASE - PMGRPSIZE)

/*
 * SEGTEMP & SEGTEMP2 are virtual segments reserved for temporary operations.
 * We use the segments immediately before the start of debugger area.
 */
#define	SEGTEMP		((addr_t)(DEBUGSTART - (2 * PMGRPSIZE)))
#define	SEGTEMP2	((addr_t)(DEBUGSTART - PMGRPSIZE))

/*
 * REGTEMP is only during intialization, we use the
 * REGION immediately before KERNELBASE, it is invalidated
 * after use
 */
#define	REGTEMP		((KERNELBASE-SMGRPSIZE)&SMGRPMASK)

#if defined(KERNEL) && !defined(LOCORE)

#ifdef VAC
void vac_dontcache();
/*
 * cache related constants set at boot time
 */
extern int vac_size;			/* size of cache in bytes */
extern int vac_linesize;		/* cache linesize */
extern int vac_nlines;			/* number of lines in cache */
extern int vac_pglines;			/* number of cache lines in a page */
#endif /* VAC */

/*
 * Low level mmu-specific functions
 */
struct	ctx *mmu_getctx();
void	mmu_setctx(/* ctx */);
void	mmu_setpmg(/* base, pmg */);
void	mmu_settpmg(/* base, pmg */);
struct	pmgrp *mmu_getpmg(/* base */);
void	mmu_setpte(/* base, pte */);
void	mmu_getpte(/* base, ppte */);
void	mmu_getkpte(/* base, ppte */);
void	mmu_pmginval(/* pmg */);
#ifdef MMU_3LEVEL
struct	smgrp *mmu_getsmg(/* base */);
void	mmu_setsmg(/* base, smg */);
void	mmu_settsmg(/* base, smg */);
void	mmu_smginval(/* smg */);
#endif /* MMU_3LEVEL */

/*
 * Cache specific routines - ifdef'ed out if there is no chance
 * of running on a machine with a virtual address cache.
 */
#ifdef VAC
void	vac_init();
void	vac_tagsinit();
void	vac_flushall();
void	vac_ctxflush();
#ifdef MMU_3LEVEL
void	vac_usrflush();
void	vac_rgnflush(/* base */);
#endif /* MMU_3LEVEL */
void	vac_segflush(/* base */);
void	vac_pageflush(/* base */);
void	vac_flush(/* base, len */);
int	bp_alloc(/* map, bp, size */);
#else /* VAC */
#define	vac_init()
#define	vac_tagsinit()
#define	vac_flushall()
#define	vac_usrflush()
#define	vac_ctxflush()
#define	vac_rgnflush(base)
#define	vac_segflush(base)
#define	vac_pageflush(base)
#define	vac_flush(base, len)
#define	bp_alloc(map, bp, size)		(int)rmalloc((map), (long)(size))
#endif /* VAC */

int	valid_va_range(/* basep, lenp, minlen, dir */);

#endif /* defined(KERNEL) && !defined(LOCORE) */

#ifdef	__cplusplus
}
#endif

#endif /* !_SUN4_MMU_H */
