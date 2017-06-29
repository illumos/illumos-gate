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
 * Machine dependent constants for sun4u.
 */

/*
 * USRTEXT is the start of the user text/data space.
 */
#define	USRTEXT		0x2000

/*
 * Virtual memory related constants for UNIX resource control, all in bytes
 * The default stack size of 8M allows an optimization of mmu mapping
 * resources so that in normal use a single mmu region map entry (smeg)
 * can be used to map both the stack and shared libraries
 */
#define	MAXSSIZ		(0x7ffff000)	/* max stack size limit */
#define	DFLSSIZ		(8*1024*1024)	/* initial stack size limit */

/*
 * Minimum allowable virtual address space to be used
 * by the seg_map segment driver for fast kernel mappings.
 */
#define	MINMAPSIZE	0x200000

/*
 * The virtual address space to be used by the seg_map segment
 * driver for fast kernel mappings.
 *
 * Size is 1/8th of physmem at boot.
 */

#ifdef	_LP64
#define	SEGMAPSIZE	(256L * 1024L * 1024L * 1024L)	/* 256G */
#else
#define	SEGMAPSIZE	(256 * 1024 * 1024)		/* 256M */
#endif	/* _LP64 */

/*
 * Define the default virtual size and valid size range for the segkp segment.
 */
#ifdef	_LP64
#define	SEGKPDEFSIZE	(2L * 1024L * 1024L * 1024L)		/*   2G */
#define	SEGKPMAXSIZE	(24L * 1024L * 1024L * 1024L)		/*  24G */
#define	SEGKPMINSIZE	(512L * 1024 * 1024L)			/* 512M */
#else
#define	SEGKPDEFSIZE	(512 * 1024 * 1024)
#define	SEGKPMAXSIZE	(512 * 1024 * 1024)
#define	SEGKPMINSIZE	(512 * 1024 * 1024)
#endif	/* _LP64 */

/*
 * Define minimum size for zio segment
 */
#define	SEGZIOMINSIZE	(512L * 1024L * 1024L)			/* 512M */
#define	SEGZIOMAXSIZE	(512L * 1024L * 1024L * 1024L)		/* 512G */

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

/*
 * Cacheable bit for 64 bit MXCC Stream Source registers
 */
#define	BC_CACHE_SHIFT	36

/*
 * set type for 64 bit phys addr variables.  Needed at least for interface
 * with MXCC.
 */

#ifndef _ASM
typedef unsigned long long pa_t;
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VM_MACHPARAM_H */
