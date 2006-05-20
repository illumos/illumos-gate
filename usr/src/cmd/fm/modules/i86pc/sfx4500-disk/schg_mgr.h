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

#ifndef _SCHG_MGR_H
#define	_SCHG_MGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * State Change Manager declarations
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include "dm_types.h"

#define	DISK_STATE(d)	((d) & (~HPS_FAULTED))
#define	DISK_FAULTED(d)	((d) & HPS_FAULTED)

extern int init_state_change_manager(cfgdata_t *cfgdatap);
extern void cleanup_state_change_manager(cfgdata_t *cfgdatap);
extern void dm_state_change(diskmon_t *diskp, hotplug_state_t newstate);
extern void dm_fault_indicator_set(diskmon_t *diskp, ind_state_t istate);
extern void block_state_change_events(void);
extern void unblock_state_change_events(void);

#ifdef	__cplusplus
}
#endif

#endif /* _SCHG_MGR_H */
