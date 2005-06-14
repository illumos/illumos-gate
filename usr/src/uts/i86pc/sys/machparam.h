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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#define	ADDRESS_C(c)    c ## ul
#else   /* _ASM */
#define	ADDRESS_C(c)    (c)
#endif  /* _ASM */

/*
 * Machine dependent parameters and limits - PC version.
 */
#define	NCPU 	21

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
#define	MMU_PAGE_SIZES	2

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 */

#define	MMU_PAGESIZE	0x1000		/* 4096 bytes */
#define	MMU_PAGESHIFT	12		/* log2(MMU_PAGESIZE) */
#define	MMU_PAGEOFFSET	(MMU_PAGESIZE-1) /* Mask of address bits in page */
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
 * DEFAULT KERNEL THREAD stack size.
 */
#if defined(__amd64)
#define	DEFAULTSTKSZ	(5 * PAGESIZE)
#elif defined(__i386)
#define	DEFAULTSTKSZ	(2 * PAGESIZE)
#endif

/*
 * KERNELBASE is the virtual address at which the kernel segments start in
 * all contexts.
 *
 * KERNELBASE is not fixed on 32-bit systems.  The value of KERNELBASE can
 * change with installed memory and the eprom variable 'eprom_kernelbase'.
 * This value is fixed on 64-bit systems.
 *
 * common/conf/param.c requires a compile time defined value for KERNELBASE
 * which it saves in the variable _kernelbase.  If kernelbase is modifed on
 * a 32-bit system, _kernelbase will be updated with the new value in
 * i86pc/os/startup.c.
 *
 * i86 and i86pc files use kernelbase instead of KERNELBASE, which is
 * initialized in i86pc/os/startup.c.
 */

#if defined(__amd64)

#define	KERNELBASE	ADDRESS_C(0xfffffd8000000000)

/*
 * Size of the unmapped "red zone" at the very bottom of the kernel's
 * address space.  Corresponds to 1 slot in the toplevel pagetable.
 */
#define	KERNEL_REDZONE_SIZE   ((uintptr_t)1 << 39)

/*
 * Base of 'core' heap area, which is used for kernel and module text/data
 * that must be within a 2GB range to allow for rip-relative addressing.
 *
 * XX64: because vmx and boot cannot be trusted to stay in a 1GB playpen at
 * the bottom of the upper 4GB range, we need to restrict the core heap to
 * the top 1GB for now.
 */
#define	COREHEAP_BASE	ADDRESS_C(0xffffffffc0000000)

/*
 * Beginning of the segkpm window
 */
#define	SEGKPM_BASE	ADDRESS_C(0xfffffe0000000000)

/*
 * default and boundary sizes for segkp
 */
#define	SEGKPDEFSIZE	(2L * 1024L * 1024L * 1024L)		/*   2G */
#define	SEGKPMAXSIZE	(8L * 1024L * 1024L * 1024L)		/*   8G */
#define	SEGKPMINSIZE	(200L * 1024 * 1024L)			/* 200M */

/*
 * Boot (or, more precisely, vmx) maps most pages twice - once in the
 * bottom 2GB of memory and once in the bottom 2GB of the topmost 4GB.
 * When boot is unmapped this range is available to the kernel, but until
 * then we have to leave it untouched.
 */
#define	BOOT_DOUBLEMAP_BASE	ADDRESS_C(0xffffffff00000000)
#define	BOOT_DOUBLEMAP_SIZE	ADDRESS_C(0x80000000)

/*
 * VMWare works best if we don't use the top 64Meg of memory for amd64.
 * Set KERNEL_TEXT to top_o_memory - 64Meg - 8 Meg for 8Meg of nucleus pages.
 */
#define	PROMSTART	ADDRESS_C(0xffc00000)
#define	KERNEL_TEXT	ADDRESS_C(0xfffffffffb800000)

/*
 * Define upper limit on user address space
 *
 * In amd64, the upper limit on a 64-bit user address space is 1 large page
 * (2MB) below kernelbase.  The upper limit for a 32-bit user address space
 * is 1 small page (4KB) below the top of the 32-bit range.  The 64-bit
 * limit give dtrace the red zone it needs below kernelbase.  The 32-bit
 * limit gives us a small red zone to detect address-space overruns in a
 * user program.
 */
#define	USERLIMIT	ADDRESS_C(0xfffffd7fffe00000)
#ifdef bug_5074717_is_fixed
#define	USERLIMIT32	ADDRESS_C(0xfffff000)
#else
#define	USERLIMIT32	ADDRESS_C(0xfefff000)
#endif

#elif defined(__i386)

#ifdef DEBUG
#define	KERNELBASE	ADDRESS_C(0xc8000000)
#else
#define	KERNELBASE	ADDRESS_C(0xd4000000)
#endif

#define	KERNELBASE_MAX	ADDRESS_C(0xe0000000)

/*
 * The i386 ABI requires that the user address space be at least 3Gb
 * in size.  KERNELBASE_ABI_MIN is used as the default KERNELBASE for
 * physical memory configurations > 4gb.
 */
#define	KERNELBASE_ABI_MIN	ADDRESS_C(0xc0000000)

/*
 * Size of the unmapped "red zone" at the very bottom of the kernel's
 * address space.  Since segmap start immediately above the red zone, this
 * needs to be MAXBSIZE aligned.
 */
#define	KERNEL_REDZONE_SIZE   MAXBSIZE

/*
 * This is the last 4MB of the 4G address space. Some psm modules
 * need this region of virtual address space mapped 1-1
 */
#define	PROMSTART	ADDRESS_C(0xffc00000)
#define	KERNEL_TEXT	ADDRESS_C(0xfe800000)

/*
 * Define upper limit on user address space
 */
#define	USERLIMIT	KERNELBASE
#define	USERLIMIT32	USERLIMIT

#endif	/* __i386 */

#if	!defined(_KADB)
extern uintptr_t kernelbase, segkmap_start, segmapsize;
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
