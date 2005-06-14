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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_SYS_FS_SWAPNODE_H
#define	_SYS_FS_SWAPNODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * pointer to swapfs global data structures
 */
extern pgcnt_t swapfs_minfree;		/* amount of availrmem (in pages) */
					/* that is unavailable to swapfs */
extern pgcnt_t swapfs_desfree;

extern pgcnt_t swapfs_reserve;		/* amount of availrmem (in pages) */
					/* that is unavailable for swap */
					/* reservation to non-priv processes */

extern struct vnodeops *swap_vnodeops;
extern struct vnode *swapfs_getvp(ulong_t);

#ifdef SWAPFS_DEBUG
extern int swapfs_debug;
#define	SWAPFS_PRINT(X, S, Y1, Y2, Y3, Y4, Y5)	\
	if (swapfs_debug & (X)) 		\
		printf(S, Y1, Y2, Y3, Y4, Y5);
#define	SWAP_SUBR	0x01
#define	SWAP_VOPS	0x02
#define	SWAP_VFSOPS	0x04
#define	SWAP_PGC		0x08
#define	SWAP_PUTP	0x10
#else	/* SWAPFS_DEBUG */
#define	SWAPFS_PRINT(X, S, Y1, Y2, Y3, Y4, Y5)
#endif	/* SWAPFS_DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_SWAPNODE_H */
