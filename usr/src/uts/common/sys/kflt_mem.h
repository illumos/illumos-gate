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
/*
 * Copyright (c) 2010, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_KFLT_MEM_H
#define	_KFLT_MEM_H

#include <sys/types.h>
#include <sys/memlist.h>

/*
 * Kernel memory freelist interfaces.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	KFT_FAILURE	0
#define	KFT_CRIT	1
#define	KFT_NONCRIT	2

#define	KFLT_EXPAND_RETRIES 10
#define	KFLT_PAGESIZE	1

extern pgcnt_t kflt_freemem;
extern pgcnt_t kflt_desfree;
extern pgcnt_t kflt_minfree;
extern pgcnt_t kflt_lotsfree;
extern pgcnt_t kflt_needfree;
extern pgcnt_t kflt_user_alloc;
extern pgcnt_t kflt_user_threshhold;
extern pgcnt_t kflt_throttlefree;
extern pgcnt_t kflt_reserve;
extern kthread_id_t kflt_evict_thread;
extern int kflt_on;

extern void kflt_evict_wakeup(void);
extern void kflt_freemem_add(pgcnt_t);
extern void kflt_freemem_sub(pgcnt_t);
extern int kflt_create_throttle(pgcnt_t, int);
extern void kflt_expand(void);
extern void kflt_init(void);
extern void kflt_tick(void);
#pragma weak kflt_expand

#if defined(__amd64) && !defined(__xpv)
/* Macros to throttle memory allocations from the kernel page freelist. */

#define	KERNEL_THROTTLE_NONCRIT(npages, flags)			\
	(kflt_create_throttle(npages, flags) == KFT_NONCRIT)

#define	KERNEL_THROTTLE(npages, flags)				\
	if (((flags) & PG_KFLT) &&					\
	    (kflt_freemem < (kflt_throttlefree + (npages)))) {        	\
		(void) kflt_create_throttle(npages, flags);		\
	}

#define	KERNEL_THROTTLE_PGCREATE(npages, flags, cond)		\
	((((flags) & (PG_KFLT|(cond)) ==  (PG_KFLT|(cond))) &&		\
	    (kflt_freemem < (kflt_throttlefree + (npages))) &&		\
	    (kflt_create_throttle(npages, flags) == KFT_FAILURE)) ?	\
	    1 : 0)

#define	KERNEL_NOT_THROTTLED(flags) (!kflt_on || !(flags & PG_KFLT))

#elif !defined(__sparc)

#define	KERNEL_THROTTLE_NONCRIT(npages, flags)	0

#define	KERNEL_THROTTLE(npages, flags)

#define	KERNEL_THROTTLE_PGCREATE(npages, flags, cond) 0

#define	KERNEL_NOT_THROTTLED(flags) 1

#endif

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _KFLT_MEM_H */
