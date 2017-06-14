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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VM_MACHPARAM_H
#define	_SYS_VM_MACHPARAM_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Machine dependent constants for PC.
 */

/*
 * USRTEXT is the start of the user text/data space.
 */
#define	USRTEXT		USRSTACK

/*
 * Virtual memory related constants for UNIX resource control, all in bytes.
 * The default stack size (initial stack size limit) keeps the stack from
 * taking more than 2 page directory entries in addition to the part of
 * the page directory entry which also maps the initial text and data,
 * and makes the default slightly bigger than the 8MB on SPARC.
 */
#ifdef __amd64
/*
 * On amd64, the stack grows down from just below KERNELBASE (see the
 * definition of USERLIMIT in i86pc/sys/machparam.h). Theoretically,
 * it could grow down to the top of the VA hole (0xffff800000000000),
 * giving it a possible maximum of about 125T. For an amd64 xpv
 * kernel, all user VA space is below the VA hole. The theoretical
 * maximum for the stack is about the same, although it can't grow
 * to quite that size, since it would clash with the heap.
 *
 * Pick an upper limit that will work in both cases: 32T.
 *
 * For 32bit processes, the stack is below the text segment.
 */
#define	MAXSSIZ		(32ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL)
#else
#define	MAXSSIZ		(USRSTACK - 1024*1024)
#endif /* __amd64 */
#define	DFLSSIZ		(8*1024*1024 + ((USRSTACK) & 0x3FFFFF))

/*
 * Size of the kernel segkmem system pte table.  This virtual
 * space is controlled by the resource map "kernelmap".
 */
#define	SYSPTSIZE	((61*1024*1024) / MMU_PAGESIZE)

/*
 * Size of the ethernet addressable kernel segkmem system pte table.
 * This virtual space is controlled by the resource map "ekernelmap".
 * The ethernet interfaces in some sun machines can address only
 * the upper 16 Megabytes of memory.  Since the ethernet
 * driver kmem_allocs its memory, we bias all kmem_allocs
 * to try ekernelmap first and if it fails try kernelmap.
 * Folks that allocate directly out of kernelmap, above,
 * get memory that is non-ethernet addressable.
 */
#define	E_SYSPTSIZE	(0x2000000 / MMU_PAGESIZE)

/*
 * The virtual address space to be used by the seg_map segment
 * driver for fast kernel mappings.
 */
#if defined(__i386)
#define	SEGMAPDEFAULT	(16 * 1024 * 1024)
#define	SEGMAPMAX	(128 * 1024 * 1024)
#else
#define	SEGMAPDEFAULT	(64 * 1024 * 1024)
#endif

/*
 * The time for a process to be blocked before being very swappable.
 * This is a number of seconds which the system takes as being a non-trivial
 * amount of real time. You probably shouldn't change this;
 * it is used in subtle ways (fractions and multiples of it are, that is, like
 * half of a ``long time'', almost a long time, etc.)
 * It is related to human patience and other factors which don't really
 * change over time.
 */
#define	MAXSLP 		20

/*
 * A swapped in process is given a small amount of core without being bothered
 * by the page replacement algorithm. Basically this says that if you are
 * swapped in you deserve some resources. We protect the last SAFERSS
 * pages against paging and will just swap you out rather than paging you.
 * Note that each process has at least UPAGES pages which are not
 * paged anyways so this number just means a swapped in process is
 * given around 32k bytes.
 */
/*
 * nominal ``small'' resident set size
 * protected against replacement
 */
#define	SAFERSS		3

/*
 * DISKRPM is used to estimate the number of paging i/o operations
 * which one can expect from a single disk controller.
 *
 * XXX - The system doesn't account for multiple swap devices.
 */
#define	DISKRPM		60

/*
 * The maximum value for handspreadpages which is the the distance
 * between the two clock hands in pages.
 */
#define	MAXHANDSPREADPAGES	((64 * 1024 * 1024) / PAGESIZE)

/*
 * Paged text files that are less than PGTHRESH bytes
 * may be "prefaulted in" instead of demand paged.
 */
#define	PGTHRESH	(280 * 1024)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VM_MACHPARAM_H */
