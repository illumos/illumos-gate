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

#ifndef	_STATISTICS_H
#define	_STATISTICS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <string.h>

#include "types.h"

extern void stats_init(sort_statistics_t *);
extern void stats_display();

extern void stats_incr_convert_reallocs();
extern void stats_incr_fetches();
extern void stats_incr_input_files();
extern void stats_incr_insert_filled_downward();
extern void stats_incr_insert_filled_input();
extern void stats_incr_insert_filled_upward();
extern void stats_incr_line_conversions();
extern void stats_incr_merge_files();
extern void stats_incr_not_unique();
extern void stats_incr_put_unique();
extern void stats_incr_puts();
extern void stats_incr_shelves();
extern void stats_incr_subfiles();
extern void stats_incr_swaps();
extern void stats_incr_tqs_calls();

extern void stats_set_available_memory(uint64_t);
extern void stats_set_input_files(uint_t);
extern void stats_set_merge_files(uint_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _STATISTICS_H */
