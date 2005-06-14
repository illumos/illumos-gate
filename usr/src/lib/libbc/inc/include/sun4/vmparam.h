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
 * Copyright (c) 1987-1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SUN4_VMPARAM_H
#define	_SUN4_VMPARAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sun4/param.h>

/*
 * Machine dependent constants for Sun-4
 */

/*
 * USRTEXT is the start of the user text/data space, while USRSTACK
 * is the top (end) of the user stack.
 */
#define	USRTEXT		0x2000
#define	USRSTACK	KERNELBASE

/*
 * Virtual memory related constants for UNIX resource control, all in bytes
 * The default stack size of 8M allows an optimization of mmu mapping
 * resources so that in normal use a single mmu region map entry (smeg)
 * can be used to map both the stack and shared libraries
 */
#define	DFLSSIZ		(8*1024*1024)		/* initial stack size limit */

#define	DFLDSIZ_260	((512*1024*1024)-USRTEXT) /* initial data size limit */
#define	MAXDSIZ_260	((512*1024*1024)-USRTEXT) /* max data size limit */
#define	MAXSSIZ_260	((512*1024*1024)-KERNELSIZE) /* max stack size limit */

#define	DFLDSIZ_470	((2048*1024*1024)-USRTEXT) /* initial data size limit */
#define	MAXDSIZ_470	((2048*1024*1024)-USRTEXT) /* max data size limit */
#define	MAXSSIZ_470	((2048*1024*1024)-KERNELSIZE) /* max stack size limit */

#define	DFLDSIZ		dfldsiz
#define	MAXDSIZ		maxdsiz
#define	MAXSSIZ		maxssiz

#ifndef LOCORE
extern unsigned int	dfldsiz;
extern unsigned int 	maxdsiz;
extern unsigned int	maxssiz;
#endif /* !LOCORE */

#define	SSIZE		1			/* initial stack size */
#define	SINCR		1			/* increment of stack */

/*
 * Size of the kernel segkmem system pte table.  This virtual
 * space is controlled by the resource map "kernelmap".
 */
#define	SYSPTSIZE	(0x640000 / MMU_PAGESIZE)

/*
 * Minimum allowable virtual address space to be used
 * by the seg_map segment driver for fast kernel mappings.
 */
#define	MINMAPSIZE	0x200000

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
#define	SAFERSS		3

/*
 * DISKRPM is used to estimate the number of paging i/o operations
 * which one can expect from a single disk controller.
 */
#define	DISKRPM		60

/*
 * Paging thresholds (see vm_pageout.c).
 * Strategy of 3/17/83:
 *	lotsfree is 256k bytes, but at most 1/8 of memory
 *	desfree is 100k bytes, but at most 1/16 of memory
 *	minfree is 32k bytes, but at most 1/2 of desfree
 */
#define	LOTSFREE	(256 * 1024)
#define	LOTSFREEFRACT	8
#define	DESFREE		(100 * 1024)
#define	DESFREEFRACT	16
#define	MINFREE		(32 * 1024)
#define	MINFREEFRACT	2

/*
 * There are two clock hands, initially separated by HANDSPREAD bytes
 * (but at most all of user memory).  The amount of time to reclaim
 * a page once the pageout process examines it increases with this
 * distance and decreases as the scan rate rises.
 */
#define	HANDSPREAD	(2 * 1024 * 1024)

/*
 * Paged text files that are less than PGTHRESH bytes
 * may be "prefaulted in" instead of demand paged.
 */
#define	PGTHRESH	(280 * 1024)

#ifdef __cplusplus
}
#endif

#endif /* !_SUN4_VMPARAM_H */
