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

#ifndef _KMDB_WR_IMPL_H
#define	_KMDB_WR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmdb/kmdb_wr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	WNTASK_DMOD_LOAD	0x0001		/* Load a specific dmod */
#define	WNTASK_DMOD_LOAD_ALL	0x0002		/* Load all dmods for kmods */
#define	WNTASK_DMOD_UNLOAD	0x0004		/* Unload a specific dmod */
#define	WNTASK_DMOD_PATH_CHANGE	0x0008		/* Change dmod search path */

#define	WNFLAGS_NOFREE		0x0001		/* Don't free this wr on ack */

#define	WNTASK_ACK		0x8000		/* Acknowledgement of req */

#define	WR_ISACK(wr)		((((kmdb_wr_t *)(wr))->wn_task) & WNTASK_ACK)
#define	WR_ACK(wr)		(((kmdb_wr_t *)(wr))->wn_task) |= WNTASK_ACK
#define	WR_TASK(wr)		((((kmdb_wr_t *)(wr))->wn_task) & ~WNTASK_ACK)

struct kmdb_wr {
	struct kmdb_wr		*wn_next;	/* List of work requests */
	struct kmdb_wr		*wn_prev;	/* List of work requests */
	ushort_t		wn_task;	/* Task to be performed */
	ushort_t		wn_flags;	/* Flags for this request */
	uint_t			wn_errno;	/* Status for completed reqs */
};

/*
 * Debugger-initiated loads: Debugger creates, passes to driver, driver loads
 * the module, returns the request as an ack.  Driver-initiated loads: driver
 * creates, loads module, passes to debugger as announcement, debugger returns
 * as an ack.
 */
typedef struct kmdb_wr_load {
	kmdb_wr_t		dlr_node;

	/* Supplied by requestor */
	char			*dlr_fname;

	/* Filled in by driver upon successful completion */
	struct modctl		*dlr_modctl;

	/*
	 * Used by the driver to track outstanding driver-initiated
	 * notifications for leak prevention.
	 */
	struct kmdb_wr_load	*dlr_next;
	struct kmdb_wr_load	*dlr_prev;
} kmdb_wr_load_t;

#define	dlr_errno	dlr_node.wn_errno

/*
 * The debugger creates a request for a module to be unloaded, and passes it
 * to the driver.  The driver unloads the module, and returns the message to
 * the debugger as an ack.
 */
typedef struct kmdb_wr_unload {
	kmdb_wr_t		dur_node;

	/* Supplied by requestor */
	char			*dur_modname;
	struct modctl		*dur_modctl;
} kmdb_wr_unload_t;

#define	dur_errno	dur_node.wn_errno

/*
 * The debugger creates a new path-change "request" when the dmod search path
 * changes, and sends it to the driver.  The driver hangs onto the request
 * until either the path changes again or the debugger is unloaded.  Either way,
 * the state change request is passed back at that time as an ack.
 */
typedef struct kmdb_wr_path {
	kmdb_wr_t		dpth_node;

	/* Supplied by requestor */
	const char		**dpth_path;
	size_t			dpth_pathlen;
} kmdb_wr_path_t;

#define	dpth_errno	dpth_node.wn_errno

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_WR_IMPL_H */
