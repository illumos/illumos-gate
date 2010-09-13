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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DMV_H
#define	_SYS_DMV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#include <sys/inttypes.h>
#endif


/*
 * Definitions for databearing mondo vector facility.  See PSARC 1998/222 for
 * more details.
 */

/*
 * DMV layout.
 *
 *		  +--+----------------+----------+---------------------------+
 *		  |63|62            61|60      48|47                        0|
 *		  +--+----------------+----------+---------------------------+
 *	Word 0:   | 1| reserved (MBZ) | dmv_inum | device private data       |
 *		  +--+----------+----------------+---------------------------+
 *	Word 1-7: | device private data                                      |
 *		  +----------------------------------------------------------+
 */

#define	DMV_INUM_SHIFT		48
#define	DMV_INUM_MASK		0x1FFF
#define	DMV_PRIVATE_MASK	0xFFFFFFFFFFFF

/*
 * The following macro is designed to allow the construction of the first
 * word of a DMV in software, for instance for testing purposes.
 */
#define	DMV_MAKE_DMV(dmv_inum, dev_private) \
	((UINT64_C(1) << 63) | \
	    ((((uint64_t)(dmv_inum)) & UINT64_C(DMV_INUM_MASK)) <<  \
	    DMV_INUM_SHIFT) | \
	    (((uint64_t)(dev_private)) & UINT64_C(DMV_PRIVATE_MASK)))

#define	DMV_IS_DMV(irdr0)	(((uint64_t)(irdr0)) >> 63)


/*
 * Version control for the dmv interfaces.
 */

#define	DMV_INTERFACE_MAJOR_VERSION	1
#define	DMV_INTERFACE_MINOR_VERSION	1

#ifndef _ASM

extern int dmv_interface_major_version;
extern int dmv_interface_minor_version;

int dmv_add_intr(int dmv_inum, void (*routine)(), void *arg);
int dmv_add_softintr(void (*routine)(void), void *arg);
int dmv_rem_intr(int dmv_inum);

/*
 * The following macros are for use with the intr_add_cpu and
 * intr_rem_cpu functions.  These functions allow a driver to choose
 * a CPU to be targeted by a device's interrupts, and also allow
 * interrupt retargeting when a CPU is taken offline.  The macros
 * convert a databearing inum to (and from) a value which will not
 * clash with an ordinary inum, thus allowing both values to coexist
 * in the same linked list.
 *
 * If a driver registers at least one soft interrupt handler for each
 * databearing mondo is uses, and keeps track of the correspondence
 * between them, it could also use the soft interrupt inum as input to
 * intr_add_cpu.
 */

#define	DMV_INUM_2_INUM(i)	(((i) | 0x8000) << 16)
#define	INUM_2_DMV_INUM(i)	(((i) >> 16) & 0x1FFF)

/*
 * DMV dispatch table entry.
 *
 * Note on consistency: we want to ensure that if dmv_func is valid, then
 * dmv_arg is as well.  We don't want to have to do any locking in the
 * interrupt handler, so instead we do the following:
 *
 * 1. When we initialize an entry, we set dmv_arg first, then do a membar #sync,
 *    then set dmv_func.
 *
 * 2. When we clear an entry, we only clear dmv_func.
 *
 * 3. When the interrupt handler uses an entry, it uses either an ldx (in
 *    the 32-bit kernel) or an atomic quad load (in the 64-bit kernel) to
 *    get a matching func/arg pair.  If func is zero, there is no handler and
 *    we discard the interrupt.
 */

struct dmv_disp {
	void (*dmv_func)(void);
	void *dmv_arg;
};

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DMV_H */
