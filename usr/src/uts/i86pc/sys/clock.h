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

#ifndef _SYS_CLOCK_H
#define	_SYS_CLOCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#ifndef	_ASM

#include <sys/psw.h>
#include <sys/time.h>
#include <sys/processor.h>
#if defined(__GNUC__) && defined(_ASM_INLINES)
#include <asm/clock.h>
#endif
#include <sys/machclock.h>

extern time_t ggmtl(void);
extern void sgmtl(time_t);
extern void rtcsync(void);

extern void unlock_hres_lock(void);
extern void hres_tick(void);
extern void (*hrtime_tick)(void);

#ifndef __xpv
extern void tsc_hrtimeinit(uint64_t cpu_freq_hz);
extern void tsc_sync_master(processorid_t);
extern void tsc_sync_slave(void);
#endif

/*
 * Careful: this can always return zero on some systems.  Use the system hrtime
 * routines if you want a meaningful time.
 */
extern hrtime_t tsc_read(void);

extern hrtime_t __rdtsc_insn(void);

extern int tsc_gethrtime_enable;

#define	ADJ_SHIFT 4		/* used in get_hrestime */

#define	YRBASE		00	/* 1900 - what year 0 in chip represents */

#endif	/* !_ASM */

#define	CBE_HIGH_PIL	14
#define	CBE_LOCK_PIL	LOCK_LEVEL
#define	CBE_LOW_PIL	2

/*
 * CLOCK_LOCK() sets the LSB (bit 0) of the hres_lock. The rest of the
 * 31bits are used as the counter. This lock is acquired
 * around "hrestime" and "timedelta". This lock is acquired to make
 * sure that level-14 accounts for changes to this variable in that
 * interrupt itself. The level-14 interrupt code also acquires this
 * lock.
 * (Note: It is assumed that the lock_set_spl() uses only bit 0 of the lock.)
 *
 * CLOCK_UNLOCK() increments the lower bytes straight, thus clearing the
 * lock and also incrementing the counter. This way gethrtime()
 * can figure out if the value in the lock got changed or not.
 */
#define	HRES_LOCK_OFFSET 0	/* byte 0 has the lock bit(bit 0 in the byte) */

#define	CLOCK_LOCK(oldsplp)	\
	lock_set_spl((lock_t *)&hres_lock + HRES_LOCK_OFFSET, 	\
		ipltospl(XC_HI_PIL), oldsplp)

#define	CLOCK_UNLOCK(spl)		\
	unlock_hres_lock();		\
	splx(spl);			\
	LOCKSTAT_RECORD0(LS_CLOCK_UNLOCK_RELEASE,	\
		(lock_t *)&hres_lock + HRES_LOCK_OFFSET);

#endif	/* KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CLOCK_H */
