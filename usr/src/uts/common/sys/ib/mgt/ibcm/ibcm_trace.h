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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IBCM_IBCM_TRACE_H
#define	_SYS_IB_MGT_IBCM_IBCM_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ibcm_trace.h
 *
 * This file contains all of the internal data structures and
 * definitions for IBCM Trace implementation
 */

/* Defines event qualifiers for detailed traces per RC connection. */
typedef enum ibcm_state_rc_trace_qualifier_e {

	/* Initial headers */
	IBCM_DISPLAY_SID		= 1,
	IBCM_DISPLAY_CHAN,
	IBCM_DISPLAY_LCID,
	IBCM_DISPLAY_LQPN,
	IBCM_DISPLAY_RCID,
	IBCM_DISPLAY_RQPN,
	IBCM_DISPLAY_TM,

	/* List possible Incoming MADs */
	IBCM_TRACE_INCOMING_REQ,
	IBCM_TRACE_INCOMING_REP,
	IBCM_TRACE_INCOMING_RTU,
	IBCM_TRACE_INCOMING_COMEST,
	IBCM_TRACE_INCOMING_MRA,
	IBCM_TRACE_INCOMING_REJ,
	IBCM_TRACE_INCOMING_LAP,
	IBCM_TRACE_INCOMING_APR,
	IBCM_TRACE_INCOMING_DREQ,
	IBCM_TRACE_INCOMING_DREP,

	/* List possible outgoing MADs */
	IBCM_TRACE_OUTGOING_REQ,
	IBCM_TRACE_OUTGOING_REP,
	IBCM_TRACE_OUTGOING_RTU,
	IBCM_TRACE_OUTGOING_LAP,
	IBCM_TRACE_OUTGOING_APR,
	IBCM_TRACE_OUTGOING_MRA,
	IBCM_TRACE_OUTGOING_REJ,
	IBCM_TRACE_OUTGOING_DREQ,
	IBCM_TRACE_OUTGOING_DREP,

	/* List of ibmf send completions */
	IBCM_TRACE_REQ_POST_COMPLETE,
	IBCM_TRACE_REP_POST_COMPLETE,
	IBCM_TRACE_RTU_POST_COMPLETE,
	IBCM_TRACE_MRA_POST_COMPLETE,
	IBCM_TRACE_REJ_POST_COMPLETE,
	IBCM_TRACE_LAP_POST_COMPLETE,
	IBCM_TRACE_APR_POST_COMPLETE,
	IBCM_TRACE_DREQ_POST_COMPLETE,
	IBCM_TRACE_DREP_POST_COMPLETE,

	/* List possible timeouts. Other timeouts always re-post MADs */
	IBCM_TRACE_TIMEOUT_REP,

	/* client handler related */
	IBCM_TRACE_CALLED_REQ_RCVD_EVENT,
	IBCM_TRACE_RET_REQ_RCVD_EVENT,

	IBCM_TRACE_CALLED_REP_RCVD_EVENT,
	IBCM_TRACE_RET_REP_RCVD_EVENT,

	/* client handler related */
	IBCM_TRACE_CALLED_CONN_EST_EVENT,
	IBCM_TRACE_RET_CONN_EST_EVENT,

	IBCM_TRACE_CALLED_CONN_FAIL_EVENT,
	IBCM_TRACE_RET_CONN_FAIL_EVENT,

	IBCM_TRACE_CALLED_CONN_CLOSE_EVENT,
	IBCM_TRACE_RET_CONN_CLOSE_EVENT,

	/* RC QP state change related */
	IBCM_TRACE_INIT_INIT,
	IBCM_TRACE_INIT_INIT_FAIL,
	IBCM_TRACE_INIT_RTR,
	IBCM_TRACE_INIT_RTR_FAIL,
	IBCM_TRACE_RTR_RTS,
	IBCM_TRACE_RTR_RTS_FAIL,
	IBCM_TRACE_RTS_RTS,
	IBCM_TRACE_RTS_RTS_FAIL,
	IBCM_TRACE_ERROR,
	IBCM_TRACE_ERROR_FAIL,
	IBCM_TRACE_SET_ALT,
	IBCM_TRACE_SET_ALT_FAIL,

	/* special event related */
	IBCM_TRACE_STALE_DETECT,

	IBCM_TRACE_OUT_REQ_RETRY,
	IBCM_TRACE_OUT_REP_RETRY,
	IBCM_TRACE_OUT_LAP_RETRY,
	IBCM_TRACE_OUT_MRA_RETRY,
	IBCM_TRACE_OUT_DREQ_RETRY,

	/* End Marker */
	IBCM_TRACE_END_MARKER

} ibcm_state_rc_trace_qualifier_t;

/* Number of traces per connection chunk */
#define		IBCM_MAX_CONN_TRCNT		40
#define		IBCM_DEBUG_BUF_SIZE		4096

/* If the trace time diff type is changed in the future, modify below */
#define		TM_DIFF_MAX			UINT32_MAX
typedef		uint32_t			tm_diff_type;

/*
 * The following structure stores the trace data per connection, and
 * defined as a field in ibcm_state_data_t.
 *
 * conn_trace_options:
 *	Stores various active trace options, like whether time stamp stored,
 *	detailed trace data stored, etc.,
 * conn_qpn:
 *	QPN of channel used for connection
 * conn_chan:
 *	Channel used for connection
 * conn_base_tm:
 *	Base time stamp in usec, when the first trace for this connection has
 *	been recorded. Gethrtime is used to record the base time stamp.
 * conn_trace_events:
 *	Trace events recorded for the connection
 * conn_trace_event_times:
 *	Trace event times recorded for the connection
 * conn_trace_ind:
 *	Index into trace_events, where the next trace event shall be stored
 * conn_allocated_trcnt:
 *	Allocated number of trace entries
 */
typedef struct ibcm_conn_trace_s {
	hrtime_t		conn_base_tm;
	uint8_t			*conn_trace_events;
	tm_diff_type		*conn_trace_event_times;
	uint8_t			conn_trace_ind;
	uint16_t		conn_allocated_trcnt;
} ibcm_conn_trace_t;

/* function that inserts a new trace into ibcm_conn_trace_t */
void	ibcm_insert_trace(void *statep,
	    ibcm_state_rc_trace_qualifier_t event_qualifier);

/* dumps the connection trace into ibtf_debug_buf */
void	ibcm_dump_conn_trace(void *statep);

extern char	ibcm_debug_buf[];

extern kmutex_t	ibcm_trace_mutex;
extern kmutex_t	ibcm_trace_print_mutex;
extern int	ibcm_conn_max_trcnt;

/*
 *	ibcm_enable_trace has the following flag bits:
 *
 *		0	No tracing performed.
 *		1	Tracing without timing.
 *		2	Trace failed connections.
 *		4	Trace all connections.
 */
extern int	ibcm_enable_trace;

extern char	*event_str[];

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBCM_IBCM_TRACE_H */
