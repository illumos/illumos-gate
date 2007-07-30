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

#ifndef _WRSM_SESS_H
#define	_WRSM_SESS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/wrsm_transport.h>

/*
 * Type Declarations
 */

typedef enum {
	SESSION_UP,
	SESSION_DOWN
} wrsm_sess_state;


/*
 * Definition of the user's callback function.
 *
 * The boolean return value should be set to true if teardown is complete,
 * or false if there are still references to this node from this subsystem.
 * If false was returned, the client should eventually call
 * wrsm_sess_unreferenced() to indicate when teardown is finally complete.
 */
typedef boolean_t (*wrsm_sess_func_t)(wrsm_network_t *, cnodeid_t,
    wrsm_sess_state);


/*
 * Config functions, should be called by transport.
 */

/* Init function. */
void wrsm_sess_init(wrsm_network_t *);

/* Fini function. */
void wrsm_sess_fini(wrsm_network_t *);

/* Informs session that a new cnode is reachable */
void wrsm_sess_reachable(wrsm_network_t *, cnodeid_t);

/* Informs session that a cnode is no longer reachable */
void wrsm_sess_unreachable(wrsm_network_t *, cnodeid_t);

/* Establishes a session with a remote cnode, if enabled. */
wrsm_sessionid_t wrsm_sess_establish(wrsm_network_t *, cnodeid_t);

/* Asynchronously tears down a session to a cnode. */
void wrsm_sess_teardown(wrsm_network_t *, cnodeid_t);

/* Returns the current session. */
wrsm_sessionid_t wrsm_sess_get(wrsm_network_t *, cnodeid_t);

/*
 * Functions for client use.
 */

/* Allows user to register for callbacks. */
void wrsm_sess_register(wrsm_network_t *, wrsm_sess_func_t);

/* Removes a user callback registration. */
void wrsm_sess_unregister(wrsm_network_t *, wrsm_sess_func_t);

/*
 * Notify session layer of final dereference of node,
 * completing earlier session down callback.
 */
void wrsm_sess_unreferenced(wrsm_network_t *net, cnodeid_t cnode);

/*
 * Functions for use by some topology management entitiy.
 */

/* Enables communication with a cnode. */
void wrsm_sess_enable(wrsm_network_t *, cnodeid_t);

/* Disables communication with a cnode. May cause a teardown. */
int wrsm_sess_disable(wrsm_network_t *, cnodeid_t);

/* Returns a cnode bitmask indicating which cnodes have valid sessions */
void wrsm_sess_get_cnodes(wrsm_network_t *, cnode_bitmask_t *);

/*
 * call to initiate an immediate session establish/teardown
 */
void wrsm_sess_establish_immediate(wrsm_network_t *net, cnodeid_t cnodeid);
void wrsm_sess_teardown_immediate(wrsm_network_t *net, cnodeid_t cnodeid);

/* Does write/read to remote node */
int wrsm_sess_touch_node(wrsm_network_t *net, cnodeid_t cnodeid,
    uint32_t stripes);

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_SESS_H */
