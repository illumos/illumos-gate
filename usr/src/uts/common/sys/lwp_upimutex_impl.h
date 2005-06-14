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

#ifndef _SYS_LWP_UPIMUTEX_IMPL_H
#define	_SYS_LWP_UPIMUTEX_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/thread.h>
#include <sys/lwp.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct upimutex upimutex_t;
typedef struct upib upib_t;

struct upib {
	kmutex_t upib_lock;
	upimutex_t *upib_first;
};

struct upimutex {
	struct _kthread *upi_owner;  /* owner */
	int	upi_waiter; /* wait bit */
	upib_t *upi_upibp; /* point back to upib bucket in hash chain */
	lwp_mutex_t *upi_vaddr;   /* virtual address, i.e. user lock ptr */
	lwpchan_t  upi_lwpchan;  /* lwpchan of virtual address */
	upimutex_t *upi_nextchain; /* next in hash chain */
	upimutex_t *upi_nextowned; /* list of mutexes owned by lwp */
};

#define	UPILWPCHAN_BITS		9
#define	UPILWPCHAN_TABSIZ	(1 << UPILWPCHAN_BITS)
#define	UPIMUTEX_TABSIZE	UPILWPCHAN_TABSIZ
#define	UPILWPCHAN_HASH(lwpchan)	\
	(((uintptr_t)((lwpchan).lc_wchan0)^(uintptr_t)((lwpchan).lc_wchan)) ^ \
	(((uintptr_t)((lwpchan).lc_wchan0)^(uintptr_t)((lwpchan).lc_wchan)) >> \
	UPILWPCHAN_BITS)) & (UPIMUTEX_TABSIZE - 1)
#define	UPI_CHAIN(lwpchan)	upimutextab[UPILWPCHAN_HASH((lwpchan))]

#define	UPIMUTEX_TRY	1
#define	UPIMUTEX_BLOCK	0

#ifdef _KERNEL
extern void upimutex_cleanup();
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LWP_UPIMUTEX_IMPL_H */
