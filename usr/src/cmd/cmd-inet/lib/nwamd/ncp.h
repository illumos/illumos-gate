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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NCP_H
#define	_NCP_H

#include <inetcfg.h>
#include <libdladm.h>
#include <libdlpi.h>
#include <libdlwlan.h>
#include <libnwam.h>
#include <libuutil.h>
#include <pthread.h>

/* Time between NCU checks */
#define	NCU_WAIT_TIME_DEFAULT		120

/* Value of priority-group at start and reset */
#define	INVALID_PRIORITY_GROUP		-1LL

extern char active_ncp[];
extern nwam_ncp_handle_t active_ncph;
extern int64_t current_ncu_priority_group;
extern uint64_t ncu_wait_time;

boolean_t nwamd_ncp_find_next_priority_group(int64_t, int64_t *);
void nwamd_ncp_activate_priority_group(int64_t);
void nwamd_ncp_deactivate_priority_group(int64_t);
void nwamd_ncp_deactivate_priority_group_all(int64_t);
boolean_t nwamd_ncp_check_priority_group(int64_t *);
void nwamd_ncp_activate_manual_ncus(void);

/* Create ncu check event */
void nwamd_create_ncu_check_event(uint64_t);

#endif /* _NCP_H */
