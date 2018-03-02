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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#ifndef _ASM

#include <sys/types.h>

#if defined(__xpv)
#include <sys/xpv_impl.h>
#endif

#endif /* !_ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#define	ADDRESS_C(c)    c ## ul
#else   /* _ASM */
#define	ADDRESS_C(c)    (c)
#endif  /* _ASM */

/*
 * Machine dependent parameters and limits.
 */

/*
 * If NCPU grows beyond 256, sizing for the x86 comm page will require
 * adjustment.
 */
#define	NCPU	256
#define	NCPU_LOG2	8

/* NCPU_P2 is NCPU rounded to a power of 2 */
#define	NCPU_P2	(1 << NCPU_LOG2)

/*
 * The value defined below could grow to 16. hat structure and
 * page_t have room for 16 nodes.
 */
#define	MAXNODES 	4
#define	NUMA_NODEMASK	0x0f

/*
 * Define the FPU symbol if we could run on a machine with an external
 * FPU (i.e. not integrated with the normal machine state like the vax).
 *
 * The fpu is defined in the architecture manual, and the kernel hides
 * its absence if it is not present, that's pretty integrated, no?
 */

/* supported page sizes */
#define	MMU_PAGE_SIZES	3

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 */

#define	MMU_PAGESIZE	0x1000		/* 4096 bytes */
#define	MMU_PAGESHIFT	12		/* log2(MMU_PAGESIZE) */

#if !defined(_ASM)
#define	MMU_PAGEOFFSET	(MMU_PAGESIZE-1) /* Mask of address bits in page */
#else	/* _ASM */
#define	MMU_PAGEOFFSET	_CONST(MMU_PAGESIZE-1)	/* assembler lameness */
#endif	/* _ASM */

#define	MMU_PAGEMASK	(~MMU_PAGEOFFSET)

#define	PAGESIZE	0x1000		/* All of the above, for logical */
#define	PAGESHIFT	12
#define	PAGEOFFSET	(PAGESIZE - 1)
#define	PAGEMASK	(~PAGEOFFSET)

/*
 * DATA_ALIGN is used to define the alignment of the Unix data segment.
 */
#define	DATA_ALIGN	PAGESIZE

/*
 * DEFAULT KERNEL THREAD stack size (in pages).
 */
#define	DEFAULTSTKSZ_NPGS	5

#if !defined(_ASM)
#define	DEFAULTSTKSZ	(DEFAULTSTKSZ_NPGS * PAGESIZE)
#else	/* !_ASM */
#define	DEFAULTSTKSZ	_MUL(DEFAULTSTKSZ_NPGS, PAGESIZE) /* as(1) lameness */
#endif	/* !_ASM */

/*
 * During intial boot we limit heap to the top 4Gig.
 */
#define	BOOT_KERNELHEAP_BASE	ADDRESS_C(0xffffffff00000000)

/*
 * VMWare works best if we don't use the top 64Meg of memory for amd64.
 * Set KERNEL_TEXT to top_o_memory - 64Meg - 8 Meg for 8Meg of nucleus pages.
 */
#define	PROMSTART	ADDRESS_C(0xffc00000)

/*
 * Virtual address range available to the debugger
 */
#define	SEGDEBUGBASE	ADDRESS_C(0xffffffffff800000)
#define	SEGDEBUGSIZE	ADDRESS_C(0x400000)

#define	KERNEL_TEXT	UINT64_C(0xfffffffffb800000)

/*
 * Reserve pages just below KERNEL_TEXT for the GDT, IDT, LDT, TSS and debug
 * info.
 *
 * For now, DEBUG_INFO_VA must be first in this list for "xm" initiated dumps
 * of solaris domUs to be usable with mdb. Relying on a fixed VA is not viable
 * long term, but it's the best we've got for now.
 */
#if !defined(_ASM)
#define	DEBUG_INFO_VA	(KERNEL_TEXT - MMU_PAGESIZE)
#define	GDT_VA		(DEBUG_INFO_VA - MMU_PAGESIZE)
#define	IDT_VA		(GDT_VA - MMU_PAGESIZE)
#define	LDT_VA		(IDT_VA - (16 * MMU_PAGESIZE))
#define	KTSS_VA		(IDT_VA - MMU_PAGESIZE)
#define	DFTSS_VA	(KTSS_VA - MMU_PAGESIZE)
#define	MISC_VA_BASE	(DFTSS_VA)
#define	MISC_VA_SIZE	(KERNEL_TEXT - MISC_VA_BASE)
#endif /* !_ASM */

/*
 * Base of 'core' heap area, which is used for kernel and module text/data
 * that must be within a 2GB range to allow for rip-relative addressing.
 */
#define	COREHEAP_BASE	ADDRESS_C(0xffffffffc0000000)

/*
 * This is valloc_base, above seg_kpm, but below everything else.
 * A lower value than this may be used if SEGKPM_BASE is adjusted.
 * See i86pc/os/startup.c
 */
#define	VALLOC_BASE	ADDRESS_C(0xfffffe0000000000)

#define	SEGZIOMINSIZE	(400L * 1024 * 1024L)			/* 400M */
#define	SEGVMMMINSIZE	(4096L * 1024 * 1024L)			/* 4G */

#define	SEGKPDEFSIZE	(2L * 1024L * 1024L * 1024L)		/*   2G */
#define	SEGKPMAXSIZE	(8L * 1024L * 1024L * 1024L)		/*   8G */
#define	SEGKPMINSIZE	(200L * 1024 * 1024L)			/* 200M */

#define	SEGKPM_BASE	ADDRESS_C(0xfffffd0000000000)

/*
 * KERNELBASE is the virtual address at which the kernel segments start in
 * all contexts.
 *
 * KERNELBASE is not fixed.  The value of KERNELBASE can change with
 * installed memory size.
 *
 * common/conf/param.c requires a compile time defined value for KERNELBASE.
 * This value is save in the variable _kernelbase.  _kernelbase may then be
 * modified with to a different value in i86pc/os/startup.c.
 *
 * Most code should be using kernelbase, which resolves to a reference to
 * _kernelbase.
 */
#define	KERNELBASE	ADDRESS_C(0xfffffc8000000000)

/*
 * Size of the unmapped "red zone" at the very bottom of the kernel's
 * address space.  Corresponds to 1 slot in the toplevel pagetable.
 */
#define	KERNEL_REDZONE_SIZE   ((uintptr_t)1 << 39)

/*
 * Define upper limit on user address space
 *
 * The upper limit on a 64-bit user address space is 1 large page
 * (2MB) below kernelbase.  The upper limit for a 32-bit user address space
 * is 1 small page (4KB) below the top of the 32-bit range.  The 64-bit
 * limit give dtrace the red zone it needs below kernelbase.  The 32-bit
 * limit gives us a small red zone to detect address-space overruns in a
 * user program.
 *
 * On the hypervisor, we limit the user to memory below the VA hole.
 * Subtract 1 large page for a red zone.
 */
#if defined(__xpv)
#define	USERLIMIT	ADDRESS_C(0x00007fffffe00000)
#else
#define	USERLIMIT	ADDRESS_C(0xfffffc7fffe00000)
#endif

#ifdef bug_5074717_is_fixed
#define	USERLIMIT32	ADDRESS_C(0xfffff000)
#else
#define	USERLIMIT32	ADDRESS_C(0xfefff000)
#endif

#if !defined(_ASM) && !defined(_KMDB)
extern uintptr_t kernelbase, segmap_start, segmapsize;
#endif

/*
 * ARGSBASE is the base virtual address of the range which
 * the kernel uses to map the arguments for exec.
 */
#define	ARGSBASE	PROMSTART

/*
 * reserve space for modules
 */
#define	MODTEXT	(1024 * 1024 * 2)
#define	MODDATA	(1024 * 300)

/*
 * The heap has a region allocated from it of HEAPTEXT_SIZE bytes specifically
 * for module text.
 */
#define	HEAPTEXT_SIZE		(64 * 1024 * 1024)	/* bytes */

/*
 * Size of a kernel threads stack.  It must be a whole number of pages
 * since the segment it comes from will only allocate space in pages.
 */
#define	T_STACKSZ	2*PAGESIZE

/*
 * Size of a cpu startup thread stack.  (It must be a whole number of pages
 * since the containing segment only allocates space in pages.)
 */

#define	STARTUP_STKSZ	3*PAGESIZE

/*
 * Bus types
 */
#define	BTISA		1
#define	BTEISA		2
#define	BTMCA		3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHPARAM_H */
