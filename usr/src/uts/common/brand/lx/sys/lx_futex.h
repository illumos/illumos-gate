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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2016, Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LX_FUTEX_H
#define	_SYS_LX_FUTEX_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	FUTEX_WAIT		0
#define	FUTEX_WAKE		1
#define	FUTEX_FD		2
#define	FUTEX_REQUEUE		3
#define	FUTEX_CMP_REQUEUE	4
#define	FUTEX_WAKE_OP		5
#define	FUTEX_LOCK_PI		6
#define	FUTEX_UNLOCK_PI		7
#define	FUTEX_TRYLOCK_PI	8
#define	FUTEX_WAIT_BITSET	9
#define	FUTEX_WAKE_BITSET	10
#define	FUTEX_WAIT_REQUEUE_PI	11
#define	FUTEX_CMP_REQUEUE_PI	12
#define	FUTEX_MAX_CMD		FUTEX_CMP_REQUEUE_PI

/*
 * Flags that can be OR'd into a futex operation.
 */
#define	FUTEX_CMD_MASK		0x007f
#define	FUTEX_PRIVATE_FLAG	0x0080
#define	FUTEX_CLOCK_REALTIME	0x0100

#define	FUTEX_BITSET_MATCH_ANY	0xffffffff
/*
 * FUTEX_WAKE_OP operations
 */
#define	FUTEX_OP_SET		0	/* *(int *)UADDR2 = OPARG; */
#define	FUTEX_OP_ADD		1	/* *(int *)UADDR2 += OPARG; */
#define	FUTEX_OP_OR		2	/* *(int *)UADDR2 |= OPARG; */
#define	FUTEX_OP_ANDN		3	/* *(int *)UADDR2 &= ~OPARG; */
#define	FUTEX_OP_XOR		4	/* *(int *)UADDR2 ^= OPARG; */

/*
 * FUTEX_WAKE_OP comparison operations
 */
#define	FUTEX_OP_CMP_EQ		0	/* if (oldval == CMPARG) wake */
#define	FUTEX_OP_CMP_NE		1	/* if (oldval != CMPARG) wake */
#define	FUTEX_OP_CMP_LT		2	/* if (oldval < CMPARG) wake */
#define	FUTEX_OP_CMP_LE		3	/* if (oldval <= CMPARG) wake */
#define	FUTEX_OP_CMP_GT		4	/* if (oldval > CMPARG) wake */
#define	FUTEX_OP_CMP_GE		5	/* if (oldval >= CMPARG) wake */

/*
 * The encoding of the FUTEX_WAKE_OP operation in 32 bits:
 *
 *	+--+-- - --+-- - --+-- - --+-- - --+
 *	|S |OP     |CMP    |OPARG  |CMPARG |
 *	+--+-- - --+-- - --+-- - --+-- - --+
 *	|31|30 - 28|27 - 24|23 - 12|11 -  0|
 *
 * The S bit denotes that the OPARG should be (1 << OPARG) instead of OPARG.
 * (Yes, this whole thing is entirely absurd -- see the block comment in
 * lx_futex.c for an explanation of this nonsense.)  Macros to extract the
 * various components from the operation, given the above encoding:
 */
#define	FUTEX_OP_OP(x)		(((x) >> 28) & 7)
#define	FUTEX_OP_CMP(x)		(((x) >> 24) & 15)
#define	FUTEX_OP_OPARG(x)	(((x) >> 31) ? (1 << (((x) << 8) >> 20)) : \
				((((x) << 8) >> 20)))
#define	FUTEX_OP_CMPARG(x)	(((x) << 20) >> 20)

#ifdef _KERNEL

/*
 * This structure is used to track all the threads currently waiting on a
 * futex.  There is one fwaiter_t for each blocked thread.  We store all
 * fwaiter_t's in a hash structure, indexed by the memid_t of the integer
 * containing the futex's value.
 *
 * At the moment, all fwaiter_t's for a single futex are simply dumped into
 * the hash bucket.  If futex contention ever becomes a hot path, we can
 * chain a single futex's waiters together.
 */
typedef struct fwaiter {
	memid_t		fw_memid;	/* memid of the user-space futex */
	kcondvar_t	fw_cv;		/* cond var */
	struct fwaiter	*fw_next;	/* hash queue */
	struct fwaiter	*fw_prev;	/* hash queue */
	uint32_t	fw_bits;	/* bits waiting on */
	volatile int	fw_woken;
} fwaiter_t;

#define	FUTEX_WAITERS			0x80000000
#define	FUTEX_OWNER_DIED		0x40000000
#define	FUTEX_TID_MASK			0x3fffffff

#define	FUTEX_ROBUST_LOCK_PI		1
#define	FUTEX_ROBUST_LIST_LIMIT		2048

extern long lx_futex(uintptr_t addr, int cmd, int val, uintptr_t lx_timeout,
    uintptr_t addr2, int val2);
extern void lx_futex_init(void);
extern int lx_futex_fini(void);
extern long lx_set_robust_list(void *listp, size_t len);
extern long lx_get_robust_list(pid_t pid, void **listp, size_t *lenp);
extern void lx_futex_robust_exit(uintptr_t addr, uint32_t tid);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_FUTEX_H */
