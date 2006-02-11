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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GCPU_H
#define	_GCPU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cpu_module.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gcpu_mca_bank {
	uint_t bank_ctl;		/* MCi_CTL MSR */
	uint_t bank_status;		/* MCi_STATUS MSR */
	uint_t bank_addr;		/* MCi_ADDR MSR */
	uint_t bank_misc;		/* MCi_MISC MSR */
} gcpu_mca_bank_t;

typedef struct gcpu_mca_data {
	uint64_t bank_status_data;	/* MCi_STATUS value from exception */
	uint64_t bank_addr_data;	/* MCi_ADDR value from exception */
	uint64_t bank_misc_data;	/* MCi_MISC value from exception */
} gcpu_mca_data_t;

typedef struct gcpu_mca {
	const gcpu_mca_bank_t *gcpu_mca_banks;
	gcpu_mca_data_t *gcpu_mca_data;
	uint_t gcpu_mca_nbanks;
} gcpu_mca_t;

typedef struct gcpu_data {
	gcpu_mca_t gcpu_mca;
} gcpu_data_t;

struct regs;

extern void gcpu_mca_init(void *);
extern int gcpu_mca_trap(void *, struct regs *);

#ifdef __cplusplus
}
#endif

#endif /* _GCPU_H */
