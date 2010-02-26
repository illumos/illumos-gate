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

#ifndef _CONDITIONS_H
#define	_CONDITIONS_H

#include <libnwam.h>

#define	CONDITION_CHECK_INTERVAL_DEFAULT	120
#define	CONDITION_CHECK_INTERVAL_MIN		30

extern uint64_t condition_check_interval;

/* Common condition check function */
extern boolean_t nwamd_check_conditions(nwam_activation_mode_t, char **,
    uint_t);
/* Rate condition (used to pick best location condition) */
extern uint64_t nwamd_rate_conditions(nwam_activation_mode_t, char **,
    uint_t);

/* Check activation conditions */
extern void nwamd_set_timed_check_all_conditions(void);
extern void nwamd_check_all_conditions(void);

/* Create condition check events */
extern void nwamd_create_timed_condition_check_event(void);
extern void nwamd_create_triggered_condition_check_event(uint32_t);

#endif /* _CONDITIONS_H */
