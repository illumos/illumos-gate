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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIMM_PHYS_H
#define	_DIMM_PHYS_H

#ifdef __cplusplus
extern "C" {
#endif

#define	OFFSET_ROW_BANK_COL	0x8000000000000000ULL
#define	OFFSET_RANK_SHIFT	52
#define	OFFSET_RAS_SHIFT	32
#define	OFFSET_BANK_SHIFT	24
#define	TCODE_OFFSET(rank, bank, ras, cas) (OFFSET_ROW_BANK_COL | \
	((uint64_t)(rank) << OFFSET_RANK_SHIFT) | \
	((uint64_t)(ras) << OFFSET_RAS_SHIFT) | \
	((uint64_t)(bank) << OFFSET_BANK_SHIFT) | (cas))

#define	TCODE_OFFSET_RANK(tcode) (((tcode) >> OFFSET_RANK_SHIFT) & RANK_MASK)
#define	TCODE_OFFSET_RAS(tcode) (((tcode) >> OFFSET_RAS_SHIFT) & RAS_MASK)
#define	TCODE_OFFSET_BANK(tcode) (((tcode) >> OFFSET_BANK_SHIFT) & BANK_MASK)
#define	TCODE_OFFSET_CAS(tcode) ((tcode) & CAS_MASK)

extern void dimm_init(void);
extern void dimm_fini(void);
extern void dimm_add_rank(int, int, int, int, uint64_t, uint32_t, uint32_t,
    int, uint64_t);
extern void dimm_add_geometry(int, int, int, int, int, int);

extern uint64_t dimm_getoffset(int, int, int, int, int);
extern uint64_t dimm_getphys(int, int, int, int, int);

#ifdef __cplusplus
}
#endif

#endif /* _DIMM_PHYS_H */
