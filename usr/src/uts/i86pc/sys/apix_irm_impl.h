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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_APIX_IRM_IMPL_H
#define	_APIX_IRM_IMPL_H

#include <sys/types.h>
#include <sys/ddi_intr_impl.h>
#include <sys/psm_types.h>
#include <sys/apix.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	APIX_IRM_DEBUG(args)	DDI_INTR_IRMDBG(args)

typedef struct apix_irm_info {
	int	apix_ncpus;		/* # of available CPUs (boot time) */
	int	apix_per_cpu_vectors;	/* # of available vectors per CPU */
	int	apix_ioapic_max_vectors; /* max # of vectors used by IOAPICs */
	int	apix_vectors_allocated; /* # of vectors (pre) allocated */
} apix_irm_info_t;

extern apix_irm_info_t apix_irminfo;
extern int apix_system_max_vectors;
extern int apix_irm_cpu_factor;
extern ddi_irm_pool_t *apix_irm_pool_p;

#ifdef	__cplusplus
}
#endif

#endif	/* _APIX_IRM_IMPL_H */
