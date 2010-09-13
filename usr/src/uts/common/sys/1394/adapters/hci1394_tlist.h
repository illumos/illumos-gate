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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_TLIST_H
#define	_SYS_1394_ADAPTERS_HCI1394_TLIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_tlist.h
 *   This implements a timed double linked list.
 *   This list supports:
 *	- addition of node to the end of the list
 *	- atomic deletion of node anywhere in list
 *	- get and remove node from head of list
 *	- enable/disable of timeout feature
 *	- timeout feature, if enabled, will remove each node on the list which
 *	  has been on the list for > timeout.  The callback provided will be
 *	  called for each node removed. The worst case time is around
 *	  timer_resolution after the timeout has occurred (i.e. if you set the
 *	  timer resolution to 50uS and the timeout to 100uS, you could get the
 *	  callback anywhere from 100uS to 150uS from when you added the node to
 *	  the list.  This is a general statement and ignores things like
 *	  interrupt latency, context switching, etc.  So if you see a time
 *	  around 155uS, don't complain :-)
 *	- The timer is only used when something is on the list
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/note.h>

/*
 * Node Information
 *   This structure is used to track the information for a given node in the
 *   linked list.  The node is added to the end of the linked list be calling
 *   tlist_add().
 */
typedef struct hci1394_tlist_node_s {
	/*
	 * Public Members
	 *  addr
	 *    generic address pointer.  This should be set to point to
	 *    whatever information you are using this node to track.
	 */
	void	*tln_addr;

	/*
	 * Private Members
	 *   These are private.  They are only to be used in the tlist
	 *   implementation.  They are included in the header file so that we
	 *   do not have to alloc/free memory when something is added/deleted
	 *   from the tlist.
	 */
	boolean_t			tln_on_list;
	hrtime_t			tln_expire_time;
	struct hci1394_tlist_node_s	*tln_prev;
	struct hci1394_tlist_node_s	*tln_next;
} hci1394_tlist_node_t;


/*
 * callback used in hci1394_tlist_timer_t.  This will be called when a node on
 * the list expires.
 */
typedef
    void (*hci1394_tlist_callback_t)(hci1394_tlist_node_t *node, void *arg);


/*
 * This structure is used if you are using the timeout feature of the linked
 * list.
 *   timeout
 *	time in nS when a node should be considered to haved timed out.
 *
 *   timer_resolution
 *	time in nS when the list should be checked for timeouts. It can be
 *      varied from timeout to reduce the jitter in the callback.
 *
 *   callback
 *	function to call on timeout.
 *
 *   callback_arg
 *	user specified argument passed in callback
 *
 */
typedef struct hci1394_tlist_timer_s {
	hrtime_t			tlt_timeout;
	hrtime_t			tlt_timer_resolution;
	hci1394_tlist_callback_t	tlt_callback;
	void				*tlt_callback_arg;
} hci1394_tlist_timer_t;


/* State to determine if timeout is scheduled or not */
typedef enum {
	HCI1394_TLIST_TIMEOUT_OFF,
	HCI1394_TLIST_TIMEOUT_ON
} hci1394_tlist_timeout_state_t;


/* private structure used to keep track of the tlist */
typedef struct hci1394_tlist_s {
	/* head and tail of linked list */
	hci1394_tlist_node_t		*tl_head;
	hci1394_tlist_node_t		*tl_tail;

	/* are we using timeout feature */
	boolean_t			tl_timer_enabled;

	/* has timeout() been called */
	hci1394_tlist_timeout_state_t	tl_state;

	/* id returned from timeout() */
	timeout_id_t			tl_timeout_id;

	/* local copy of timer_info */
	hci1394_tlist_timer_t		tl_timer_info;

	hci1394_drvinfo_t		*tl_drvinfo;
	kmutex_t			tl_mutex;
} hci1394_tlist_t;

_NOTE(SCHEME_PROTECTS_DATA("Single thread modifies", \
	hci1394_tlist_s::tl_state \
	hci1394_tlist_s::tl_timeout_id \
	hci1394_tlist_s::tl_timer_info.tlt_timeout))

/* handle passed back from init() and used for rest of functions */
typedef	struct hci1394_tlist_s	*hci1394_tlist_handle_t;



void hci1394_tlist_init(hci1394_drvinfo_t *drvinfo,
    hci1394_tlist_timer_t *timer, hci1394_tlist_handle_t *tlist_handle);
void hci1394_tlist_fini(hci1394_tlist_handle_t *tlist_handle);


void hci1394_tlist_add(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t *node);
int hci1394_tlist_delete(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t *node);
void hci1394_tlist_get(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t **node);
void hci1394_tlist_peek(hci1394_tlist_handle_t tlist_handle,
    hci1394_tlist_node_t **node);

void hci1394_tlist_timeout_update(hci1394_tlist_handle_t tlist_handle,
    hrtime_t timeout);
void hci1394_tlist_timeout_cancel(hci1394_tlist_handle_t tlist_handle);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_TLIST_H */
