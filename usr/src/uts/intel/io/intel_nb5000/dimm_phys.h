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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIMM_PHYS_H
#define	_DIMM_PHYS_H

#ifdef __cplusplus
extern "C" {
#endif

#define	MAXPHYS_ADDR		0xffffffff00000000ULL

extern void dimm_init(void);
extern void dimm_fini(void);
extern void dimm_add_rank(int, int, int, int, uint64_t, uint32_t, uint32_t,
    int, uint64_t);

extern uint64_t dimm_getoffset(int, int, int, int, int);
extern uint64_t dimm_getphys(uint16_t, uint16_t, uint64_t, uint64_t, uint64_t);

#pragma weak dimm_getoffset
#pragma weak dimm_getphys

#ifdef __cplusplus
}
#endif

#endif /* _DIMM_PHYS_H */
