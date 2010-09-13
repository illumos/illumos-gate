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

#ifndef	_TSALARM_H
#define	_TSALARM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* alarm_action */
#define	TSALARM_ENABLE		1
#define	TSALARM_DISABLE		2
#define	TSALARM_STATUS		3

/* alarm_id */
#define	TSALARM_CRITICAL	0
#define	TSALARM_MAJOR		1
#define	TSALARM_MINOR		2
#define	TSALARM_USER		3

/* alarm_state */
#define	TSALARM_STATE_ON	1
#define	TSALARM_STATE_OFF	2
#define	TSALARM_STATE_UNKNOWN	3

/* Status Types */
#define	TSALARM_OK		1
#define	TSALARM_ERROR		2

/* Error codes */
#define	TSALARM_SUCCESS			0
#define	TSALARM_CHANNEL_INIT_FAILURE	-1
#define	TSALARM_NULL_REQ_DATA		-2
#define	TSALARM_COMM_FAILURE		-3
#define	TSALARM_UNBOUND_PACKET_RECVD	-4
#define	TSALARM_GET_ERROR		-5
#define	TSALARM_SET_ERROR		-6

/*
 * alarm set/get request message
 */
typedef struct tsalarm_req {
	uint32_t	alarm_id;
	uint32_t	alarm_action;
} tsalarm_req_t;

/*
 * alarm set/get response message
 */
typedef struct tsalarm_resp {
	uint32_t	status;
	uint32_t	alarm_id;
	uint32_t	alarm_state;
} tsalarm_resp_t;

int tsalarm_get(uint32_t alarm_type, uint32_t *alarm_state);
int tsalarm_set(uint32_t alarm_type, uint32_t alarm_state);

#ifdef	__cplusplus
}
#endif

#endif /* _TSALARM_H */
