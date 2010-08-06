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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_APIC_TIMER_H
#define	_SYS_APIC_TIMER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/time.h>

#define	IA32_DEADLINE_TSC_MSR	0x6E0

/* Timer Vector Table register	*/
#define	APIC_LOCAL_TIMER	0xc8

/* timer vector table		*/
#define	AV_PERIODIC	0x20000 /* Set timer mode to periodic */
#define	AV_DEADLINE	0x40000 /* Set timer mode to deadline */

#define	APIC_TIMER_MODE_ONESHOT		0x0
#define	APIC_TIMER_MODE_PERIODIC	0x1
#define	APIC_TIMER_MODE_DEADLINE	0x2	/* TSC-Deadline timer mode */

extern int	apic_oneshot;
extern uint_t	apic_nsec_per_intr;
extern uint_t	apic_hertz_count;
extern uint64_t apic_ticks_per_SFnsecs;

/*
 * Use scaled-fixed-point arithmetic to calculate apic ticks.
 * Round when dividing (by adding half of divisor to dividend)
 * for one extra bit of precision.
 */

#define	SF	(1ULL<<20)		/* Scaling Factor: scale by 2^20 */
#define	APIC_TICKS_TO_NSECS(ticks)	((((int64_t)(ticks) * SF) + \
					apic_ticks_per_SFnsecs / 2) / \
					apic_ticks_per_SFnsecs);
#define	APIC_NSECS_TO_TICKS(nsecs)	(((int64_t)(nsecs) * \
					apic_ticks_per_SFnsecs + (SF/2)) / SF)

extern int	apic_timer_init(int);
extern void	apic_timer_reprogram(hrtime_t);
extern void	apic_timer_enable(void);
extern void	apic_timer_disable(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_APIC_TIMER_H */
