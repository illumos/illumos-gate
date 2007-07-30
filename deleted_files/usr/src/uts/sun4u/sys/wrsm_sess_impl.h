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

#ifndef _WRSM_SESS_IMPL_H
#define	_WRSM_SESS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/wrsm_common.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_transport.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SESS_SUCCESS	0
#define	SESS_TIMEOUT	1000000 /* in usec */

/*
 * Type declarations
 */

/*
 * Session state to a remote cnode
 * Note: there is an array of session statea strings used for debugging
 * purposes that must be kept in sync with this enum.
 */
typedef enum {
	SESS_STATE_UNREACH,	/* newcnode not reachable */
	SESS_STATE_DOWN,	/* No valid session */
	SESS_STATE_ESTAB,	/* Waiting for reply to sess_start message */
	SESS_STATE_UP		/* A valid session exists */
} sess_state;

/* Per-remote-cnode state structure */
typedef struct wrsm_node_session {
	cnodeid_t cnodeid;
	kmutex_t mutex;
	kcondvar_t cv_session_up;
	boolean_t enabled;
	sess_state state;
	boolean_t state_changing;
	boolean_t event_queued;
	kcondvar_t cv_state_changing;
	wrsm_sessionid_t session_id;
	wrsm_sessionid_t last_session_id;
	caddr_t barrier_page;
	caddr_t barrier_mem;
	wrsm_cmmu_tuple_t *barrier_tuple;
	wrsm_cmmu_tuple_t remote_tuple;
	uint_t dereferences_needed;
	kcondvar_t cv_await_dereferences;
} wrsm_node_session_t;

/* Session state structure */
#define	MAX_CLIENTS	10
struct wrsm_session {
	wrsm_network_t *network;
	wrsm_sess_func_t cb[MAX_CLIENTS];
	wrsm_node_session_t node[WRSM_MAX_CNODES];
};

/* Message formats */
typedef struct {
	wrsm_message_header_t header;
	wrsm_sessionid_t session_id;
	ncslice_t barrier_ncslice;
	wrsm_cmmu_offset_t barrier_offset;
} msg_session_start_t;

typedef struct {
	wrsm_message_header_t header;
	wrsm_sessionid_t session_id;
	ncslice_t barrier_ncslice;
	off_t barrier_offset;
	int result;
} msg_session_start_rsp_t;

typedef struct {
	wrsm_message_header_t header;
	wrsm_sessionid_t session_id;
} msg_session_end_t;

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_SESS_IMPL_H */
