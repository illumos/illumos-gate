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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PMUBUS_H
#define	_SYS_PMUBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * definition of pmubus reg spec entry:
 */
typedef struct {
	uint32_t reg_addr_hi;
	uint32_t reg_addr_lo;
	uint32_t reg_size;
} pmubus_obpregspec_t;

typedef struct {
	uint64_t reg_addr;
	uint32_t reg_size;
} pmubus_regspec_t;


typedef struct {
	uint64_t rng_child;
	uint32_t rng_parent_hi;
	uint32_t rng_parent_mid;
	uint32_t rng_parent_low;
	uint32_t rng_size;
} pmu_rangespec_t;


/*
 * driver soft state structure:
 */
typedef struct {
	dev_info_t *pmubus_dip;
	pci_regspec_t *pmubus_regp;
	int pmubus_reglen;
	ddi_acc_handle_t pmubus_reghdl;
	pmu_rangespec_t *pmubus_rangep;
	int pmubus_rnglen;
	int pmubus_nranges;
	kmutex_t pmubus_reg_access_lock;
} pmubus_devstate_t;

/* Flags for specifying the type of register space. */
#define	MAPREQ_SHARED_REG	0x1
#define	MAPREQ_SHARED_BITS	0x2

#define	MAPPING_SHARED_BITS_MASK	0x8000000000000000ull

#define	PMUBUS_REGOFFSET	0xff

typedef struct {
	pmubus_devstate_t *mapreq_softsp;
	unsigned long mapreq_flags;
	uint64_t mapreq_addr;
	size_t mapreq_size;
	uint64_t mapreq_mask;
} pmubus_mapreq_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PMUBUS_H */
