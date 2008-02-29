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

#ifndef _OPL_CMA_H
#define	_OPL_CMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_api.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	FM_FMRI_HC_CPUIDS	"hc-xscf-cpuids"

extern int cma_cpu_hc_retire(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *);
extern int cpu_offline(fmd_hdl_t *, uint_t, int);

#ifdef __cplusplus
}
#endif

#endif /* _OPL_CMA_H */
