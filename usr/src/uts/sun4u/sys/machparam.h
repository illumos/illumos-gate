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
 * Copyright 2019 Peter Tribble.
 */
/*
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#define	ADDRESS_C(c)    c ## ul
#else   /* _ASM */
#define	ADDRESS_C(c)    (c)
#endif	/* _ASM */

/*
 * Machine dependent parameters and limits - sun4u version.
 */

/*
 * Define the VAC symbol (etc.) if we could run on a machine
 * which has a Virtual Address Cache
 *
 * This stuff gotta go.
 */
#define	VAC			/* support virtual addressed caches */

/*
 * The maximum possible number of UPA devices in a system.
 * MAX_UPA maybe defined in a platform's makefile.
 */
#ifndef MAX_UPA
#define	MAX_UPA			32
#endif

/*
 * Maximum cpuid value that we support.  NCPU can be defined in a platform's
 * makefile.
 */
#ifndef NCPU
#define	NCPU	32
#endif

#if	(NCPU <= 1)
#define	NCPU_LOG2	0
#elif	(NCPU <= 2)
#define	NCPU_LOG2	1
#elif	(NCPU <= 4)
#define	NCPU_LOG2	2
#elif	(NCPU <= 8)
#define	NCPU_LOG2	3
#elif	(NCPU <= 16)
#define	NCPU_LOG2	4
#elif	(NCPU <= 32)
#define	NCPU_LOG2	5
#elif	(NCPU <= 64)
#define	NCPU_LOG2	6
#elif	(NCPU <= 128)
#define	NCPU_LOG2	7
#elif	(NCPU <= 256)
#define	NCPU_LOG2	8
#elif	(NCPU <= 512)
#define	NCPU_LOG2	9
#elif	(NCPU <= 1024)
#define	NCPU_LOG2	10
#else
#error	"add test for larger NCPU"
#endif

/* NCPU_P2 is NCPU rounded to a power of 2 */
#define	NCPU_P2	(1 << NCPU_LOG2)

/*
 * Maximum number of processors that we support.  With CMP processors, the
 * portid may not be equal to cpuid.  MAX_CPU_CHIPID can be defined in a
 * platform's makefile.
 */
#ifndef	MAX_CPU_CHIPID
#define	MAX_CPU_CHIPID	NCPU
#endif

/*
 * Define the FPU symbol if we could run on a machine with an external
 * FPU (i.e. not integrated with the normal machine state like the vax).
 *
 * The fpu is defined in the architecture manual, and the kernel hides
 * its absence if it is not present, that's pretty integrated, no?
 */

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 */
#define	MMU_PAGE_SIZES		6	/* max sun4u mmu-supported page sizes */
#define	DEFAULT_MMU_PAGE_SIZES	4	/* default sun4u supported page sizes */

/*
 * XXX make sure the MMU_PAGESHIFT definition here is
 * consistent with the one in param.h
 */
#define	MMU_PAGESHIFT		13
#define	MMU_PAGESIZE		(1<<MMU_PAGESHIFT)
#define	MMU_PAGEOFFSET		(MMU_PAGESIZE - 1)
#define	MMU_PAGEMASK		(~MMU_PAGEOFFSET)

#define	MMU_PAGESHIFT64K	16
#define	MMU_PAGESIZE64K		(1 << MMU_PAGESHIFT64K)
#define	MMU_PAGEOFFSET64K	(MMU_PAGESIZE64K - 1)
#define	MMU_PAGEMASK64K		(~MMU_PAGEOFFSET64K)

#define	MMU_PAGESHIFT512K	19
#define	MMU_PAGESIZE512K	(1 << MMU_PAGESHIFT512K)
#define	MMU_PAGEOFFSET512K	(MMU_PAGESIZE512K - 1)
#define	MMU_PAGEMASK512K	(~MMU_PAGEOFFSET512K)

#define	MMU_PAGESHIFT4M		22
#define	MMU_PAGESIZE4M		(1 << MMU_PAGESHIFT4M)
#define	MMU_PAGEOFFSET4M	(MMU_PAGESIZE4M - 1)
#define	MMU_PAGEMASK4M		(~MMU_PAGEOFFSET4M)

#define	MMU_PAGESHIFT32M	25
#define	MMU_PAGESIZE32M		(1 << MMU_PAGESHIFT32M)
#define	MMU_PAGEOFFSET32M	(MMU_PAGESIZE32M - 1)
#define	MMU_PAGEMASK32M		(~MMU_PAGEOFFSET32M)

#define	MMU_PAGESHIFT256M	28
#define	MMU_PAGESIZE256M	(1 << MMU_PAGESHIFT256M)
#define	MMU_PAGEOFFSET256M	(MMU_PAGESIZE256M - 1)
#define	MMU_PAGEMASK256M	(~MMU_PAGEOFFSET256M)

#define	PAGESHIFT	13
#define	PAGESIZE	(1<<PAGESHIFT)
#define	PAGEOFFSET	(PAGESIZE - 1)
#define	PAGEMASK	(~PAGEOFFSET)

/*
 * DATA_ALIGN is used to define the alignment of the Unix data segment.
 */
#define	DATA_ALIGN	ADDRESS_C(0x2000)

/*
 * DEFAULT KERNEL THREAD stack size.
 */

#define	DEFAULTSTKSZ	(3*PAGESIZE)

/*
 * DEFAULT initial thread stack size.
 */
#define	T0STKSZ		(2 * DEFAULTSTKSZ)

/*
 * KERNELBASE is the virtual address which
 * the kernel text/data mapping starts in all contexts.
 */
#define	KERNELBASE	ADDRESS_C(0x01000000)

/*
 * Virtual address range available to the debugger
 */
#define	SEGDEBUGBASE	ADDRESS_C(0xedd00000)
#define	SEGDEBUGSIZE	(ADDRESS_C(0xf0000000) - SEGDEBUGBASE)

/*
 * Define the userlimits
 */

#define	USERLIMIT	ADDRESS_C(0xFFFFFFFF80000000)
#define	USERLIMIT32	ADDRESS_C(0xFFC00000)

/*
 * Define SEGKPBASE, start of the segkp segment.
 */

#define	SEGKPBASE	ADDRESS_C(0x2a100000000)

/*
 * Define SEGMAPBASE, start of the segmap segment.
 */

#define	SEGMAPBASE	ADDRESS_C(0x2a750000000)

/*
 * SYSBASE is the virtual address which the kernel allocated memory
 * mapping starts in all contexts.  SYSLIMIT is the end of the Sysbase segment.
 */

#define	SYSBASE		ADDRESS_C(0x30000000000)
#define	SYSLIMIT	ADDRESS_C(0x70000000000)
#define	SYSBASE32	ADDRESS_C(0x70000000)
#define	SYSLIMIT32	ADDRESS_C(0x80000000)

/*
 * BOOTTMPBASE is the base of a space that can be reclaimed
 * after the kernel takes over the machine.  It contains the
 * boot archive and memory allocated by krtld before kmem_alloc
 * is brought online.
 */
#define	BOOTTMPBASE	ADDRESS_C(0x4C000000)

/*
 * MEMSCRUBBASE is the base virtual address for the memory scrubber
 * to read large pages.  It MUST be 4MB page aligned.
 */

#define	MEMSCRUBBASE	0x2a000000000

/*
 * Define the kernel address space range allocated to Open Firmware
 */
#define	OFW_START_ADDR	0xf0000000
#define	OFW_END_ADDR	0xffffffff

/*
 * ARGSBASE is the base virtual address of the range which
 * the kernel uses to map the arguments for exec.
 */
#define	ARGSBASE	(MEMSCRUBBASE - NCARGS)

/*
 * PPMAPBASE is the base virtual address of the range which
 * the kernel uses to quickly map pages for operations such
 * as ppcopy, pagecopy, pagezero, and pagesum.
 */
#define	PPMAPSIZE	(512 * 1024)
#define	PPMAPBASE	(ARGSBASE - PPMAPSIZE)

#define	MAXPP_SLOTS	ADDRESS_C(16)
#define	PPMAP_FAST_SIZE	(MAXPP_SLOTS * PAGESIZE * NCPU)
#define	PPMAP_FAST_BASE	(PPMAPBASE - PPMAP_FAST_SIZE)

/*
 * PIOMAPBASE is the base virtual address at which programmable I/O registers
 * are mapped.  This allows such memory -- which may induce side effects when
 * read -- to be cordoned off from the system at-large.
 */
#define	PIOMAPSIZE	(1024 * 1024 * 1024 * (uintptr_t)5)
#define	PIOMAPBASE	(PPMAP_FAST_BASE - PIOMAPSIZE)

/*
 * Allocate space for kernel modules on nucleus pages
 */
#define	MODDATA	1024 * 512

/*
 * The heap has a region allocated from it specifically for module text that
 * cannot fit on the nucleus page.  This region -- which starts at address
 * HEAPTEXT_BASE and runs for HEAPTEXT_SIZE bytes -- has virtual holes
 * punched in it: for every HEAPTEXT_MAPPED bytes of available virtual, there
 * is a virtual hole of size HEAPTEXT_UNMAPPED bytes sitting beneath it.  This
 * assures that any text address is within HEAPTEXT_MAPPED of an unmapped
 * region.  The unmapped regions themselves are managed with the routines
 * kobj_texthole_alloc() and kobj_texthole_free().
 */
#define	HEAPTEXT_SIZE		(128 * 1024 * 1024)	/* bytes */
#define	HEAPTEXT_OVERSIZE	(64 * 1024 * 1024)	/* bytes */
#define	HEAPTEXT_BASE		(SYSLIMIT32 - HEAPTEXT_SIZE)
#define	HEAPTEXT_MAPPED		(2 * 1024 * 1024)
#define	HEAPTEXT_UNMAPPED	(2 * 1024 * 1024)

#define	HEAPTEXT_NARENAS	\
	(HEAPTEXT_SIZE / (HEAPTEXT_MAPPED + HEAPTEXT_UNMAPPED) + 2)

/*
 * Preallocate an area for setting up the user stack during
 * the exec(). This way we have a faster allocator and also
 * make sure the stack is always VAC aligned correctly. see
 * get_arg_base() in startup.c.
 */
#define	ARG_SLOT_SIZE	(0x8000)
#define	ARG_SLOT_SHIFT	(15)
#define	N_ARG_SLOT	(0x80)

#define	NARG_BASE	(PIOMAPBASE - (ARG_SLOT_SIZE * N_ARG_SLOT))

/*
 * ktextseg+kvalloc should not use space beyond KERNEL_LIMIT32.
 */

/*
 * For 64-bit kernels, rename KERNEL_LIMIT to KERNEL_LIMIT32 to more accurately
 * reflect the fact that it's actually the limit for 32-bit kernel virtual
 * addresses.
 */
#define	KERNEL_LIMIT32	BOOTTMPBASE

#define	PFN_TO_BUSTYPE(pfn)	(((pfn) >> 19) & 0x1FF)
#define	IO_BUSTYPE(pfn)	((PFN_TO_BUSTYPE(pfn) & 0x100) >> 8)

#define	PFN_TO_UPAID(pfn)	(((pfn) >> 20) & 0x1F)

/*
 * Defines used for the ptl1_panic parameter, which is passed to the
 * ptl1_panic assembly routine in %g1.  These #defines have string
 * names defined in sun4u/os/mach_cpu_states.c which should be kept up to
 * date if new #defines are added.
 */
#define	PTL1_BAD_DEBUG		0
#define	PTL1_BAD_WTRAP		1
#define	PTL1_BAD_KMISS		2
#define	PTL1_BAD_KPROT_FAULT	3
#define	PTL1_BAD_ISM		4
#define	PTL1_BAD_MMUTRAP	5
#define	PTL1_BAD_TRAP		6
#define	PTL1_BAD_FPTRAP		7
#define	PTL1_BAD_INTR_VEC	8
#define	PTL1_BAD_TRACE_PTR	9
#define	PTL1_BAD_STACK		10
#define	PTL1_BAD_DTRACE_FLAGS	11
#define	PTL1_BAD_CTX_STEAL	12
#define	PTL1_BAD_ECC		13
#define	PTL1_BAD_CTX		14
#define	PTL1_BAD_RAISE_TSBEXCP	20
#define	PTL1_NO_SCDTSB8K	21

/*
 * Defines used for ptl1 related data structs.
 */
#define	PTL1_MAXTL		4
#define	PTL1_DEBUG_TRAP		0x7C
#define	PTL1_SSIZE		1024	/* minimum stack size */
#define	CPU_ALLOC_SIZE		MMU_PAGESIZE

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHPARAM_H */
