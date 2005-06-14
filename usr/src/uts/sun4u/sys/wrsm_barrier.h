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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSM_BARRIER_H
#define	_WRSM_BARRIER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmpi.h>

/*
 * Span of time barriers
 */
int wrsm_open_barrier_ctrl(rsm_controller_handle_t, rsm_barrier_t *);
int wrsm_open_barrier_node(rsm_controller_handle_t, rsm_addr_t,
    rsm_barrier_t *);
int wrsm_open_barrier_region(rsm_memseg_import_handle_t, rsm_barrier_t *);
int wrsm_open_barrier_regions(rsm_memseg_import_handle_t *, uint_t num_regions,
    rsm_barrier_t *);

/*
 * Thread of code barriers
 */
int wrsm_open_barrier_ctrl_thr(rsm_controller_handle_t, rsm_barrier_t *);
int wrsm_open_barrier_node_thr(rsm_controller_handle_t, rsm_addr_t,
    rsm_barrier_t *);
int wrsm_open_barrier_region_thr(rsm_memseg_import_handle_t, rsm_barrier_t *);
int wrsm_open_barrier_regions_thr(rsm_memseg_import_handle_t *,
    uint_t num_regions, rsm_barrier_t *);

/*
 * Barrier close/reopen/ordering
 */
int wrsm_close_barrier(rsm_barrier_t *);
int wrsm_reopen_barrier(rsm_barrier_t *);
int wrsm_order_barrier(rsm_barrier_t *);

/*
 * Thread of code init/fini.
 */
int wrsm_thread_init(rsm_controller_handle_t);
int wrsm_thread_fini(rsm_controller_handle_t);

/*
 * Memseg barrier mode control.
 */
int wrsm_get_barrier_mode(rsm_memseg_import_handle_t, rsm_barrier_mode_t *);
int wrsm_set_barrier_mode(rsm_memseg_import_handle_t, rsm_barrier_mode_t);

/*
 * Debug functions.
 */
#ifdef DEBUG
void wrsm_print_barrier(rsm_barrier_t *);
#endif /* DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_BARRIER_H */
