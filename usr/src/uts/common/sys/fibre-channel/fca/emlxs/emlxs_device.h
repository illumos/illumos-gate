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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_DEVICE_H
#define	_EMLXS_DEVICE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This is the global device driver control structure
 */

#ifndef EMLXS_HBA_T
typedef struct emlxs_hba emlxs_hba_t;
#endif

/* This structure must match the one in ./mdb/msgblib.c */
typedef struct emlxs_device {
	uint32_t hba_count;
	emlxs_hba_t *hba[MAX_FC_BRDS];
	kmutex_t lock;

	time_t drv_timestamp;
	clock_t log_timestamp;	/* Common base timestamp for all log entries */
	emlxs_msg_log_t *log[MAX_FC_BRDS];   /* Message log pointers for mdb */

} emlxs_device_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_DEVICE_H */
