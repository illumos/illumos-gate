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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_INTR_H
#define	_SYS_INTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Each cpu allocates two arrays, intr_head[] and intr_tail[], with the
 * size of PIL_LEVELS each. The entry 0 of these arrays are reserved.
 *
 * The entries 1-15 of the arrays are the head and the tail of interrupt
 * level 1-15 request queues.
 */
#define	PIL_LEVELS	16	/* 0	: reserved */
				/* 1-15 : for the pil level 1-15 */

#define	PIL_1	1
#define	PIL_2	2
#define	PIL_3	3
#define	PIL_4	4
#define	PIL_5	5
#define	PIL_6	6
#define	PIL_7	7
#define	PIL_8	8
#define	PIL_9	9
#define	PIL_10	10
#define	PIL_11	11
#define	PIL_12	12
#define	PIL_13	13
#define	PIL_14	14
#define	PIL_15	15

#ifndef _ASM
extern uint64_t poke_cpu_inum;
extern void intr_init(struct cpu *);
#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_INTR_H */
