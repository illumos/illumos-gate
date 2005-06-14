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
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _THR_INT_H
#define	_THR_INT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Thread/Libc/rtld Interface
 *
 * This file should be deleted since nothing in libc uses it.
 * However, ld.so.1 is coded to be compatible with all things past
 * and it imports this file for the benefit of _ld_concurrency().
 * Nothing calls _ld_concurrency() in Solaris 10, but the current
 * code for ld.so.1 might be copied back to a patch workspace
 * and _ld_concurrency() is called in Solaris 9 and prior releases.
 *
 * All definitions previously in this file have been deleted
 * except for just those definitions used by ld.so.1, below.
 */

#define	TI_LRW_WRLOCK	4	/* _llrw_wrlock() address */
#define	TI_LRW_UNLOCK	5	/* _llrw_unlock() address */
#define	TI_BIND_GUARD	6	/* _bind_guard() address */
#define	TI_BIND_CLEAR	7	/* _bind_clear() address */
#define	TI_LATFORK	8	/* _lpthread_atfork() */
#define	TI_THRSELF	9	/* _thr_self() address */
#define	TI_VERSION	10	/* current version of ti_interface */

/*
 * Threads Interface communication structure for old threads libraries
 */
typedef struct {
	int	ti_tag;
	union {
		int (*	ti_func)();
		long	ti_val;
	} ti_un;
} Thr_interface;

#ifdef	__cplusplus
}
#endif

#endif /* _THR_INT_H */
