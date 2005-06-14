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
 * Copyright (c) 1997,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FS_UFS_BIO_H
#define	_SYS_FS_UFS_BIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/t_lock.h>
#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Statistics on ufs buffer cache
 * Not protected by locks
 */
struct ufsbiostats {
	kstat_named_t ub_breads;	/* ufs_bread */
	kstat_named_t ub_bwrites;	/* ufs_bwrite and ufs_bwrite2 */
	kstat_named_t ub_fbiwrites;	/* ufs_fbiwrite */
	kstat_named_t ub_getpages;	/* ufs_getpage_miss */
	kstat_named_t ub_getras;	/* ufs_getpage_ra */
	kstat_named_t ub_putsyncs;	/* ufs_putapage (B_SYNC) */
	kstat_named_t ub_putasyncs;	/* ufs_putapage (B_ASYNC) */
	kstat_named_t ub_pageios;	/* ufs_pageios (swap) */
};

extern struct ufsbiostats ub;

#if defined(_KERNEL)

/*
 * let's define macros for the ufs_bio calls (as they were originally
 * defined name-wise).  using these macros to access the appropriate
 * *_common routines to minimize subroutine calls.
 */
extern struct buf *bread_common(void *arg, dev_t dev,
					daddr_t blkno, long bsize);
extern void bwrite_common(void *arg, struct buf *bp, int force_wait,
					int do_relse, int clear_flags);
extern struct buf *getblk_common(void * arg, dev_t dev,
					daddr_t blkno, long bsize, int flag);

#define	UFS_BREAD(ufsvfsp, dev, blkno, bsize)	\
	bread_common(ufsvfsp, dev, blkno, bsize)
#define	UFS_BWRITE(ufsvfsp, bp)	\
	bwrite_common(ufsvfsp, bp, /* force_wait */ 0, /* do_relse */ 1, \
	/* clear_flags */ (B_READ | B_DONE | B_ERROR | B_DELWRI))
#define	UFS_BRWRITE(ufsvfsp, bp)	\
	(bp)->b_flags |= B_RETRYWRI; \
	bwrite_common(ufsvfsp, bp, /* force_wait */ 0, /* do_relse */ 1, \
	/* clear_flags */ (B_READ | B_DONE | B_ERROR | B_DELWRI))
#define	UFS_BWRITE2(ufsvfsp, bp) \
	bwrite_common(ufsvfsp, bp, /* force_wait */ 1, /* do_relse */ 0, \
	/* clear_flags */ (B_READ | B_DONE | B_ERROR | B_DELWRI))
#define	UFS_GETBLK(ufsvfsp, dev, blkno, bsize)	\
	getblk_common(ufsvfsp, dev, blkno, bsize, /* errflg */ 0)

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_UFS_BIO_H */
