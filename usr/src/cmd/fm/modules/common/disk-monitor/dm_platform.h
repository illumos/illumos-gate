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

#ifndef	_DM_PLATFORM_H
#define	_DM_PLATFORM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dm_types.h"

#ifdef	__cplusplus
extern "C" {
#endif

int dm_platform_update_fru(const char *action, dm_fru_t *fru);
int dm_platform_indicator_execute(const char *action);
int dm_platform_resync(void);

int dm_platform_init(void);
void dm_platform_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _DM_PLATFORM_H */
