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

#ifndef	_SYS_PCMU_TYPES_H
#define	_SYS_PCMU_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct pcicmu pcmu_t;
typedef struct pcmu_cb pcmu_cb_t;
typedef struct pcmu_ib pcmu_ib_t;
typedef struct pcmu_pbm pcmu_pbm_t;
typedef uint16_t pcmu_ign_t;
typedef struct pcmu_errstate pcmu_errstate_t;
typedef struct pcmu_ecc_errstate pcmu_ecc_errstate_t;
typedef struct pcmu_pbm_errstate pcmu_pbm_errstate_t;
typedef struct pcmu_cb_errstate pcmu_cb_errstate_t;
typedef struct pcmu_bus_range pcmu_bus_range_t;
typedef struct pcmu_ranges  pcmu_ranges_t;
typedef enum pcmu_cb_nintr_index pcmu_cb_nintr_index_t;
typedef struct pcmu_ecc pcmu_ecc_t;
typedef struct pcmu_ecc_intr_info pcmu_ecc_intr_info_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_TYPES_H */
