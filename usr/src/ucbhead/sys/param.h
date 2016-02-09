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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_PARAM_H
#define	_SYS_PARAM_H


/*
 * Fundamental variables; don't change too often.
 *
 * This file is included here for compatibility with
 * SunOS, but it does *not* include all the values
 * define in the SunOS version of this file.
 */

#include <sys/isa_defs.h>
#include <limits.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	MAX_INPUT
#define	MAX_INPUT	512	/* Maximum bytes stored in the input queue */
#endif

#ifndef	MAX_CANON
#define	MAX_CANON	256	/* Maximum bytes for canoical processing */
#endif

#define	UID_NOBODY	60001
#define	GID_NOBODY	60001

#define	UID_NOACCESS	60002	/* user ID no access */

#define	MAXPID	((pid_t)sysconf(_SC_MAXPID))	/* max process id */
#define	MAXUID	2147483647	/* max user id */
#define	MAXLINK	32767		/* max links */

#define	NMOUNT		40	/* est. of # mountable fs for quota calc */

/* The values below are defined in limits.h */
#define	NOFILE	OPEN_MAX	/* max open files per process */

#define	CANBSIZ	256		/* max size of typewriter line	*/
#define	HZ	((int)sysconf(_SC_CLK_TCK))  /* ticks/second of the clock */
#define	TICK	(1000000000/((int)sysconf(_SC_CLK_TCK)))

#define	NCARGS	0x100000	/* # characters in exec arglist */
				/*   must be multiple of NBPW.  */
/*
 * These define the maximum and minimum allowable values of the
 * configurable parameter NGROUPS_MAX.
 */
#define	NGROUPS_UMAX	32
#define	NGROUPS_UMIN	8

#define	NGROUPS		NGROUPS_MAX	/* max number groups, from limits.h */
#define	NOGROUP		-1	/* marker for empty group set member */

/*
 * Priorities.  Should not be altered too much.
 */

#define	PMASK	0177
#define	PCATCH	0400
#define	PNOSTOP	01000
#define	PSWP	0
#define	PINOD	10
#define	PSNDD	PINOD
#define	PAMAP	PINOD
#define	PPMAP	PINOD
#define	PRIBIO	20
#define	PZERO	25
#define	PMEM	0
#define	NZERO	20
#define	PPIPE	26
#define	PVFS	27
#define	PWAIT	30
#define	PLOCK	35
#define	PSLEP	39
#define	PUSER	60
#define	PIDLE	127

/*
 * Fundamental constants of the implementation--cannot be changed easily.
 */

#define	NBPS	0x20000		/* Number of bytes per segment */
#define	NBPW	sizeof (int)	/* number of bytes in an integer */

#define	CMASK	0		/* default mask for file creation */
#define	CDLIMIT	(1L<<11)	/* default max write address */
#define	NODEV	(dev_t)(-1)
#define	NBPSCTR		512	/* Bytes per disk sector.	*/
#define	UBSIZE		512	/* unix block size.		*/
#define	SCTRSHFT	9	/* Shift for BPSECT.		*/

#define	lobyte(X)	(((unsigned char *)&(X))[1])
#define	hibyte(X)	(((unsigned char *)&(X))[0])
#define	loword(X)	(((ushort_t *)&(X))[1])
#define	hiword(X)	(((ushort_t *)&(X))[0])

/* REMOTE -- whether machine is primary, secondary, or regular */
#define	SYSNAME 9		/* # chars in system name */
#define	PREMOTE 39

/*
 * MAXPATHLEN defines the longest permissible path length,
 * including the terminating null, after expanding symbolic links.
 * MAXSYMLINKS defines the maximum number of symbolic links
 * that may be expanded in a path name. It should be set high
 * enough to allow all legitimate uses, but halt infinite loops
 * reasonably quickly.
 * MAXNAMELEN is the length (including the terminating null) of
 * the longest permissible file (component) name.
 */
#define	MAXPATHLEN	1024
#define	MAXSYMLINKS	20
#define	MAXNAMELEN	256

#ifndef	NADDR
#define	NADDR 13
#endif

/*
 * The following are defined to be the same as
 * defined in /usr/include/limits.h.  They are
 * needed for pipe and FIFO compatibility.
 */
#ifndef	PIPE_BUF	/* max # bytes atomic in write to a pipe */
#define	PIPE_BUF	5120
#endif	/* PIPE_BUF */

#ifndef	PIPE_MAX	/* max # bytes written to a pipe in a write */
#define	PIPE_MAX	5120
#endif	/* PIPE_MAX */

#define	PIPEBUF PIPE_BUF	/* pipe buffer size */

#ifndef	NBBY
#define	NBBY	8			/* number of bits per byte */
#endif

/* macros replacing interleaving functions */
#define	dkblock(bp)	((bp)->b_blkno)
#define	dkunit(bp)	(minor((bp)->b_dev) >> 3)

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

#ifdef  _LP64
#define	MAXOFF_T	0x7fffffffffffffffl
#define	MAXOFFSET_T	0x7fffffffffffffffll
#else
#define	MAXOFF_T	0x7fffffff
#ifndef _LONGLONG_TYPE
#define	MAXOFFSET_T	0x7fffffff
#else
#define	MAXOFFSET_T	0x7fffffffffffffffLL
#endif
#endif  /* _LP64 */

#define	btodb(bytes)			/* calculates (bytes / DEV_BSIZE) */ \
	((unsigned)(bytes) >> DEV_BSHIFT)
#define	dbtob(db)			/* calculates (db * DEV_BSIZE) */ \
	((unsigned)(db) << DEV_BSHIFT)

/*
 * PAGES* describes the logical page size used by the system.
 */

#define	PAGESIZE	(sysconf(_SC_PAGESIZE))	/* All the above, for logical */
#define	PAGEOFFSET	(PAGESIZE - 1)
#define	PAGEMASK	(~PAGEOFFSET)

/*
 * Some random macros for units conversion.
 */

/*
 * pages to bytes, and back (with and without rounding)
 */
#define	ptob(x)		((x) * PAGESIZE)
#define	btop(x)		(((unsigned)(x)) / PAGESIZE)
#define	btopr(x)	((((unsigned)(x) + PAGEOFFSET) / PAGESIZE))

/*
 * Signals
 */

#include <sys/signal.h>
#include <sys/types.h>

/*
 * bit map related macros
 */
#define	setbit(a, i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a, i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a, i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a, i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

/*
 * Macros for fast min/max.
 */
#ifndef	MIN
#define	MIN(a, b)	(((a) < (b))?(a):(b))
#endif
#ifndef	MAX
#define	MAX(a, b)	(((a) > (b))?(a):(b))
#endif

#define	howmany(x, y)	(((x)+((y)-1))/(y))
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))

/*
 * Scale factor for scaled integers used to count
 * %cpu time and load averages.
 */
#define	FSHIFT	8		/* bits to right of fixed binary point */
#define	FSCALE	(1<<FSHIFT)

/*
 * Maximum size of hostname recognized and stored in the kernel.
 * Same as in /usr/include/netdb.h
 */
#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	256
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_PARAM_H */
