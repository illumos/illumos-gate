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

#ifndef _SYS_WRSM_RSMPI_H
#define	_SYS_WRSM_RSMPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/wrsm_common.h>


#ifdef __cplusplus
extern "C" {
#endif

int wrsmrsm_get_controller_handler(const char *name, uint32_t number,
    rsm_controller_object_t *controller, uint32_t version);

int wrsmrsm_release_controller_handler(const char *name, uint32_t number,
    rsm_controller_object_t *controller);

void wrsm_rsm_setup_controller_attr(wrsm_network_t *network);
#ifdef __cplusplus
}
#endif

#endif /* _SYS_WRSM_RSMPI_H */
