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

#ifndef _SYS_AVINTR_H
#define	_SYS_AVINTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dditypes.h>

/*
 * Period of autovector structures (add this in to get the next level).
 */
#define	MAXIPL	16

/*
 * These are only used by sun4m and later OBP versions
 */
#define	INTLEVEL_ONBOARD	0x20
#define	INTLEVEL_SBUS		0x30

#define	INT_LEVEL(lvl)	((lvl) & ~(MAXIPL-1))
#define	INT_IPL(lvl)	((lvl) & (MAXIPL-1))

/*
 * maximum number of autovectored interrupts at a given priority
 * XXX: This is temporary until we come up with dynamic additions..
 */

#define	NVECT	17	/* 16 shared per level, +1 to end the list */
#define	AV_INT_SPURIOUS	-1

#ifdef	__STDC__
typedef uint_t (*avfunc)(caddr_t, caddr_t);
#else
typedef uint_t (*avfunc)();
#endif	/* __STDC__ */


struct autovec {

	/*
	 * Interrupt handler and argument to pass to it.
	 */

	avfunc	av_vector;
	caddr_t	av_intarg;

	/*
	 * Device that requested the interrupt, used as an id in case
	 * we have to remove it later.
	 */
	dev_info_t *av_devi;

	/*
	 *
	 * If this flag is true, then this is a 'fast' interrupt reservation.
	 * Fast interrupts go directly out of the
	 * trap table for speed and do not go through the normal autovector
	 * interrupt setup code. There can be only one 'fast' interrupt
	 * per autovector level.
	 */
	uint_t	av_fast;
};

#ifdef _KERNEL

extern const uint_t maxautovec;
extern struct autovec * const vectorlist[];

extern int add_avintr(dev_info_t *, int, avfunc, caddr_t);
extern void rem_avintr(dev_info_t *, int, avfunc);
extern int settrap(dev_info_t *, int, avfunc);
extern int not_serviced(int *, int, char *);

extern void wait_till_seen(int);

extern kmutex_t av_lock;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_AVINTR_H */
