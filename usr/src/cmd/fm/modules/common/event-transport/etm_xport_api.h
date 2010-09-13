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

/*
 * FMA ETM-to-Transport API header
 *
 * const/type defns for transporting data between an Event Transport
 * Module (ETM) and its associated Transport Layer within a fault domain.
 */

#ifndef _ETM_XPORT_API_H
#define	_ETM_XPORT_API_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <fm/fmd_api.h>

typedef void* etm_xport_hdl_t;	/* transport instance handle */
typedef void* etm_xport_conn_t;	/* transport connection handle */

typedef enum etm_callback_flag {
	ETM_CBFLAG_REINIT,	/* reinitialize connection */
	ETM_CBFLAG_RECV		/* receive message */
} etm_cb_flag_t;

/*
 * Connection Management
 */

/*
 * Initialize/setup transport instance before any connections are opened.
 * Return transport instance handle if successful, or NULL for failure.
 */
etm_xport_hdl_t
etm_xport_init(fmd_hdl_t *hdl, char *endpoint_id,
    int (*cb_func)(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_cb_flag_t flag,
    void *arg), void *cb_func_arg);

/*
 * Callback function provided to etm_xport_init().
 * This function is called by the transport layer to notify the common layer
 * that action is required (receive a message, reinitialize a connection, etc.).
 * Return zero for success.
 * For any non-zero return value, the connection should be closed.
 */
int
etm_xport_cb_func(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_cb_flag_t flag,
    void *arg);

/*
 * Finish/teardown any transport infrastructure.
 * Return zero if successful, or nonzero for failure.
 */
int
etm_xport_fini(fmd_hdl_t *hdl, etm_xport_hdl_t tlhdl);

/*
 * Open a connection with the given endpoint.
 * Return the transport connection handle if successful, or NULL for failure.
 */
etm_xport_conn_t
etm_xport_open(fmd_hdl_t *hdl, etm_xport_hdl_t tlhdl);

/*
 * Close a connection.
 * Return zero if successful, or nonzero for failure.
 */
int
etm_xport_close(fmd_hdl_t *hdl, etm_xport_conn_t conn);

/*
 * Input/Output
 */

/*
 * Try to read byte_cnt bytes from the connection into the given buffer.
 * Return number of bytes successfully read, or a value < 0 for failure.
 */
ssize_t
etm_xport_read(fmd_hdl_t *hdl, etm_xport_conn_t conn, hrtime_t timeout,
    void *buf, size_t byte_cnt);

/*
 * Try to write byte_cnt bytes to the connection from the given buffer.
 * Return number of bytes successfully written, or a value < 0 for failure.
 */
ssize_t
etm_xport_write(fmd_hdl_t *hdl, etm_xport_conn_t conn, hrtime_t timeout,
    void *buf, size_t byte_cnt);

/*
 * Filter
 */

#define	ETM_XPORT_FILTER_OK (1)		/* OK to send/post event */
#define	ETM_XPORT_FILTER_DROP (0)	/* Do not send/post event */
#define	ETM_XPORT_FILTER_ERROR (-1)	/* Error */

/*
 * Make a decision whether or not to send an event to a remote endpoint.
 * Return ETM_XPORT_FILTER_OK, ETM_XPORT_FILTER_DROP, or ETM_XPORT_FILTER_ERROR
 * and set errno for failure.
 */
int
etm_xport_send_filter(fmd_hdl_t *hdl, nvlist_t *event, const char *dest);

/*
 * Make a decision whether or not to post an event to FMD.
 * Return ETM_XPORT_FILTER_OK, ETM_XPORT_FILTER_DROP, or ETM_XPORT_FILTER_ERROR
 * and set errno for failure.
 */
int
etm_xport_post_filter(fmd_hdl_t *hdl, nvlist_t *event, const char *src);

#ifdef __cplusplus
}
#endif

#endif /* _ETM_XPORT_API_H */
