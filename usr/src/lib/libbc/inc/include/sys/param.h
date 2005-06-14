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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__sys_param_h
#define	__sys_param_h

/*
 * Machine type dependent parameters.
 */
#include <machine/param.h>

#define	NPTEPG		(NBPG/(sizeof (struct pte)))

/*
 * Machine-independent constants
 */
#define	NMOUNT	40		/* est. of # mountable fs for quota calc */
#define	MSWAPX	15		/* pseudo mount table index for swapdev */
#define	MAXUPRC	25		/* max processes per user */
#define	NOFILE	256		/* max open files per process */
#define	MAXPID	30000		/* max process id */
#define	MAXUID	0xfffd		/* max user id (from 60000)  */
#define	MAXLINK	32767		/* max links */
#define	CANBSIZ	256		/* max size of typewriter line */
#define	VDISABLE 0		/* use this to turn off c_cc[i] */
#define	PIPE_BUF 4096		/* pipe buffer size */
#ifndef	KERNEL
/*
 * HZ defines the ticks/second for system calls, eg, times(), which
 * return values just in ticks; but not for getrusage(), which returns
 * values in ticks*pages.  HZ *must* be 60 for compatibility reasons.
 */
#define	HZ	60
#endif
#define	NCARGS	0x100000	/* (absolute) max # characters in exec arglist */
/* If NGROUPS changes, change <sys/limits.h> NGROUPS_MAX at the same time. */
#define	NGROUPS	16		/* max number groups */

#define	NOGROUP	-1		/* marker for empty group set member */

#ifdef	KERNEL
/*
 * Priorities
 */
#define	PMASK	0177
#define	PCATCH	0400		/* return if sleep interrupted, don't longjmp */
#define	PSWP	0
#define	PINOD	10
#define	PAMAP	10
#define	PRIBIO	20
#define	PRIUBA	24
#define	PZERO	25
#define	PPIPE	26
#define	PVFS	27
#define	PWAIT	30
#define	PLOCK	35
#define	PSLEP	40

#ifdef	VPIX
#define	PV86	41
#endif

#define	PFLCK	42	/* File/Record lock */

#define	PUSER	50

#define	NZERO	20
#endif	/* KERNEL */

/*
 * Signals
 */
#include <sys/signal.h>

#define	ISSIG(p, flag) \
	((p)->p_sig && ((p)->p_flag&STRC || \
	 ((p)->p_sig &~ ((p)->p_sigignore | (p)->p_sigmask))) && issig(flag))

#define	NBPW	sizeof (int)	/* number of bytes in an integer */

#ifndef	NULL
#define	NULL	0
#endif
#define	CMASK	0		/* default mask for file creation */
#define	NODEV	(dev_t)(-1)

#ifndef	INTRLVE
/* macros replacing interleaving functions */
#define	dkblock(bp)	((bp)->b_blkno)
#define	dkunit(bp)	(minor((bp)->b_dev) >> 3)
#endif

#define	CBSIZE	28		/* number of chars in a clist block */
#define	CROUND	0x1F		/* clist rounding; sizeof (int *) + CBSIZE-1 */

#if	!defined(LOCORE) || !defined(KERNEL)
#include <sys/types.h>
#endif

/*
 * File system parameters and macros.
 *
 * The file system is made out of blocks of at most MAXBSIZE units,
 * with smaller units (fragments) only in the last direct block.
 * MAXBSIZE primarily determines the size of buffers in the buffer
 * pool. It may be made larger without any effect on existing
 * file systems; however making it smaller make make some file
 * systems unmountable.
 *
 * Note that the blocked devices are assumed to have DEV_BSIZE
 * "sectors" and that fragments must be some multiple of this size.
 */
#define	MAXBSIZE	8192
#define	DEV_BSIZE	512
#define	DEV_BSHIFT	9		/* log2(DEV_BSIZE) */
#define	MAXFRAG 	8

#define	btodb(bytes)			/* calculates (bytes / DEV_BSIZE) */ \
	((unsigned)(bytes) >> DEV_BSHIFT)
#define	dbtob(db)			/* calculates (db * DEV_BSIZE) */ \
	((unsigned)(db) << DEV_BSHIFT)

/*
 * Map a ``block device block'' to a file system block.
 * XXX - this is currently only being used for tape drives.
 */
#define	BLKDEV_IOSIZE	2048
#define	bdbtofsb(bn)	((bn) / (BLKDEV_IOSIZE/DEV_BSIZE))

/*
 * MAXPATHLEN defines the longest permissable path length,
 * including the terminating null, after expanding symbolic links.
 * MAXSYMLINKS defines the maximum number of symbolic links
 * that may be expanded in a path name. It should be set high
 * enough to allow all legitimate uses, but halt infinite loops
 * reasonably quickly.
 */
#define	MAXPATHLEN	1024
#define	MAXSYMLINKS	20

/*
 * bit map related macros
 */
#define	setbit(a,i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a,i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a,i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a,i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

/*
 * Macros for fast min/max.
 */
#ifndef	MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef	MAX
#define	MAX(a,b) (((a)>(b))?(a):(b))
#endif

/*
 * Macros for counting and rounding.
 */
#ifdef	sun386
#define	howmany(x, y)   ((((u_int)(x))+(((u_int)(y))-1))/((u_int)(y)))
#define	roundup(x, y)   ((((u_int)(x)+((u_int)(y)-1))/(u_int)(y))*(u_int)(y))
#else
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#endif

/*
 * Scale factor for scaled integers used to count
 * %cpu time and load averages.
 */
#define	FSHIFT	8		/* bits to right of fixed binary point */
#define	FSCALE	(1<<FSHIFT)

/*
 * Maximum size of hostname recognized and stored in the kernel.
 */
#define	MAXHOSTNAMELEN  64

#endif	/* !__sys_param_h */
