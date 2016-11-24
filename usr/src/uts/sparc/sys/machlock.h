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

#ifndef _SYS_MACHLOCK_H
#define	_SYS_MACHLOCK_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/types.h>

#ifdef _KERNEL

extern void	lock_set(lock_t *lp);
extern int	lock_try(lock_t *lp);
extern int	lock_spin_try(lock_t *lp);
extern int	ulock_try(lock_t *lp);
extern void	ulock_clear(lock_t *lp);
extern void	lock_clear(lock_t *lp);
extern void	lock_set_spl(lock_t *lp, int new_pil, ushort_t *old_pil);
extern void	lock_clear_splx(lock_t *lp, int s);

#endif	/* _KERNEL */

#define	LOCK_HELD_VALUE		0xff
#define	LOCK_INIT_CLEAR(lp)	(*(lp) = 0)
#define	LOCK_INIT_HELD(lp)	(*(lp) = LOCK_HELD_VALUE)
#define	LOCK_HELD(lp)		(*(volatile lock_t *)(lp) != 0)

typedef	lock_t	disp_lock_t;		/* dispatcher lock type */

/*
 * SPIN_LOCK() macro indicates whether lock is implemented as a spin lock or
 * an adaptive mutex, depending on what interrupt levels use it.
 */
#define	SPIN_LOCK(pl)	((pl) > ipltospl(LOCK_LEVEL))

/*
 * Macro to control loops which spin on a lock and then check state
 * periodically.  Its passed an integer, and returns a boolean value
 * that if true indicates its a good time to get the scheduler lock and
 * check the state of the current owner of the lock.
 */
#define	LOCK_SAMPLE_INTERVAL(i)	(((i) & 0xff) == 0)

/*
 * Extern for CLOCK_LOCK.
 */
extern	volatile int	hres_lock;

#endif	/* _ASM */

/*
 * The definitions of the symbolic interrupt levels:
 *
 *   CLOCK_LEVEL =>  The level at which one must be to block the clock.
 *
 *   LOCK_LEVEL  =>  The highest level at which one may block (and thus the
 *                   highest level at which one may acquire adaptive locks)
 *                   Also the highest level at which one may be preempted.
 *
 *   DISP_LEVEL  =>  The level at which one must be to perform dispatcher
 *                   operations.
 *
 * The constraints on the platform:
 *
 *  - CLOCK_LEVEL must be less than or equal to LOCK_LEVEL
 *  - LOCK_LEVEL must be less than DISP_LEVEL
 *  - DISP_LEVEL should be as close to LOCK_LEVEL as possible
 *
 * Note that LOCK_LEVEL and CLOCK_LEVEL have historically always been equal;
 * changing this relationship is probably possible but not advised.
 *
 */
#define	CLOCK_LEVEL	10
#define	LOCK_LEVEL	10
#define	DISP_LEVEL	(LOCK_LEVEL + 1)

#define	HIGH_LEVELS	(PIL_MAX - LOCK_LEVEL)

#define	PIL_MAX		15

/*
 * The mutex and semaphore code depends on being able to represent a lock
 * plus owner in a single 32-bit word.  Thus the owner must contain at most
 * 24 significant bits.  At present only threads, mutexes and semaphores
 * must be aware of this vile constraint.  Different ISAs may handle this
 * differently depending on their capabilities (e.g. compare-and-swap)
 * and limitations (e.g. constraints on alignment and/or KERNELBASE).
 */
#define	PTR24_LSB	5			/* lower bits all zero */
#define	PTR24_MSB	(PTR24_LSB + 24)	/* upper bits all one */
#define	PTR24_ALIGN	32		/* minimum alignment (1 << lsb) */
#define	PTR24_BASE	0xe0000000	/* minimum ptr value (-1 >> (32-msb)) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHLOCK_H */
