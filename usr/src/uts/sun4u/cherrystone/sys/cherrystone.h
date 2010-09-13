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

#ifndef	_CHERRYSTONE_H
#define	_CHERRYSTONE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cherrystone.h - Cherrystone common header file
 *
 * This header file contains the common definitions and macros for the
 * Cherrystone platform. We define them all here to avoid them being redefined
 * in numerous different drivers and daemons.
 */
#define	CHERRYSTONE_SBD_SLOTS		2
#define	CHERRYSTONE_CPUS_PER_BOARD	2
#define	CHERRYSTONE_MAX_CPUS		(CHERRYSTONE_SBD_SLOTS * \
						CHERRYSTONE_CPUS_PER_BOARD)
#define	CHERRYSTONE_BANKS_PER_MC	4
#define	CHERRYSTONE_MAX_SLICE		(CHERRYSTONE_MAX_CPUS * \
						CHERRYSTONE_BANKS_PER_MC)

/*
 *   Slot SlotID   Agent ID
 *   ---- ------  --------
 *    0     0  <==>  0
 *    0     1  <==>  2
 *    1     0  <==>  1
 *    1     1  <==>  3
 *    4[*]  -  <==>  8 (Schizo0)
 *    5[*]  -  <==>  9 (Schizo1)
 *
 *    [*] Fake slot numbers used for prtdiag bookkeeping
 */
#define	CHERRYSTONE_GETSLOT(AID)	(((AID&0xc)>>1)|(AID&1))
#define	CHERRYSTONE_GETSLOT_LABEL(AID)	('A' + CHERRYSTONE_GETSLOT(AID))
#define	CHERRYSTONE_GETSID(AID)		((AID&2)>>1)
#define	CHERRYSTONE_GETAID(SLOT, SID)	(((SLOT&2)<<1)|(SLOT&1)|((SID)<<1))

/*
 * These values are taken from Appendices R and U of the UltraSPARC-III
 * JPS1 Implementation Supplement.
 */
#define	MC_VALID_SHIFT		63
#define	MC_UK_SHIFT		41
#define	MC_UM_SHIFT		20
#define	MC_LK_SHIFT		14
#define	MC_LM_SHIFT		8
#define	PHYS2UM_SHIFT		26
#define	MC_UK(memdec)		(((memdec) >> MC_UK_SHIFT) & 0xfffu)
#define	MC_LK(memdec)		(((memdec) >> MC_LK_SHIFT)& 0x3fu)
#define	MC_INTLV(memdec)	((~(MC_LK(memdec)) & 0xfu) + 1)
#define	MC_UK2SPAN(memdec)	((MC_UK(memdec) + 1) << PHYS2UM_SHIFT)
#define	MC_SPANMB(memdec)	(MC_UK2SPAN(memdec) >> 20)
#define	MC_UM(memdec)		(((memdec) >> MC_UM_SHIFT) & 0x1fffffu)
#define	MC_LM(memdec)		(((memdec) >> MC_LM_SHIFT) & 0x3f)
#define	MC_BASE(memdec)		(MC_UM(memdec) & ~(MC_UK(memdec)))
#define	MC_BASE2UM(base)	(((base) & 0x1fffffu) << MC_UM_SHIFT)
#define	SAF_MASK		0x000007ffff800000ull
#define	MC_OFFSET_MASK		0xffu

/*
 * Cherrystone slices are defined by bits 36..39 of the physical address space
 */

#define	PA_SLICE_SHIFT		(36)
#define	PFN_SLICE_SHIFT		(PA_SLICE_SHIFT - MMU_PAGESHIFT)
#define	PA_2_SLICE(pa)		(((pa) >> PA_SLICE_SHIFT) & \
					CHERRYSTONE_SLICE_MASK)
#define	PFN_2_SLICE(pfn)	(((pfn) >> PFN_SLICE_SHIFT) & \
					CHERRYSTONE_SLICE_MASK)

/* Define the number of possible slices for the span of slice bits */
#define	CHERRYSTONE_SLICE_MASK		(0xf)

extern uint64_t lddsafaddr(uint64_t physaddr);
extern uint64_t lddmcdecode(uint64_t physaddr);

#ifdef	__cplusplus
}
#endif

#endif /* _CHERRYSTONE_H */
