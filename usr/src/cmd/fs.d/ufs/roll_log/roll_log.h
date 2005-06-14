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
 * Copyright (c) 1996,1997,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_ROLL_LOG_H
#define	_ROLL_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fs/ufs_fs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains definitions for the module that rolls the Unix File
 * System log.
 */

/*
 * rl_result_t defines the type of the value that is returned by all roll
 * log functions.
 */

typedef enum rl_result {
	/*
	 * Choose values so that all passing returns are >= 0, and all
	 * failing returns are < 0.
	 */

	RL_CORRUPT = -4,		/* Corrupted on disk structure. */
	RL_FAIL = -3,			/* Generic failure. */
	RL_SYSERR = -2,			/* Failing system call. */
	RL_FALSE = -1,
	RL_SUCCESS = 0,
	RL_TRUE = 1
} rl_result_t;

/* Functions defined in roll_log.c */

extern rl_result_t	rl_roll_log(char *dev);
extern rl_result_t	rl_log_control(char *dev, int request);

#ifdef	__cplusplus
}
#endif

#endif	/* _ROLL_LOG_H */
