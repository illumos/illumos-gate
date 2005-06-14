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

#ifndef	_SYS_NEXUSINTR_IMPL_H
#define	_SYS_NEXUSINTR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dditypes.h>

/* This is a sun4 specific interrupt specification structure (ispec) */
typedef struct ddi_ispec {
	uint32_t	*is_intr;	/* Interrupt spec at a given bus node */
	int32_t 	is_intr_sz;	/* Size in bytes of interrupt spec */
	uint32_t 	is_pil;	/* Hint of the PIL for this interrupt spec */
} ddi_ispec_t;

/* This is a soft interrupt specification */
typedef struct ddi_softispec {
	dev_info_t *sis_rdip;	 /* Interrupt requestors dip */
	uint32_t sis_softint_id; /* Soft interrupt id */
	uint32_t sis_pil;	 /* Hint of the PIL for this interrupt spec */
} ddi_softispec_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NEXUSINTR_IMPL_H */
