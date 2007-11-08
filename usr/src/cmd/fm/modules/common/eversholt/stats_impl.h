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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EFT_STATS_IMPL_H
#define	_EFT_STATS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "fme.h"

struct stats {
	fmd_stat_t fmd_stats;
	enum stats_type {
		STATS_COUNTER = 3000,
		STATS_ELAPSE,
		STATS_STRING
	} t;

	/* used for STATS_ELAPSE */
	hrtime_t start;
	hrtime_t stop;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _EFT_STATS_IMPL_H */
