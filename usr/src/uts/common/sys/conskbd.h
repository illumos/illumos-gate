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

#ifndef	_SYS_CONSKBD_H
#define	_SYS_CONSKBD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/consdev.h>
#include <sys/kbd.h>
#include <sys/kbtrans.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Lower Queue State:
 *
 * Every physical keyboard has a corresponding STREAMS queue. We call this
 * queue lower queue. To describe this kind of queue, we define a structure
 * (refer conskbd_lower_queue_t). Every lower queue has a state, transform
 * of the state describes the process from a keyborad attached to system to
 * the keyboard is plumbed into conskbd or rejected.
 *  Rule:
 *
 * 1) LQS_UNINITIALIZED 	--->	LQS_KIOCTYPE_ACK_PENDING;
 * 	send a KIOCTYPE to lower queue, and then wait response;
 *
 * 2) LQS_KIOCTYPE_ACK_PENDING	--->	LQS_INITIALIZED_LEGACY;
 * 	receive nak to KIOCTYPE, the corresponding keyboard can not
 * 	multiplexed with other keyboards. so the conskbd is bypassed,
 * 	only one keyboard is supported.
 *
 * 3) LQS_KIOCTYPE_ACK_PENDING	--->	LQS_KIOCTRANS_ACK_PENDING;
 *	receive ack to KIOCTYPE, and send KIOCTRANS to lower queue,
 *
 * 4) LQS_KIOCTRANS_ACK_PENDING	--->	LQS_KIOCLAYOUT_ACK_PENDING;
 * 	receive ack to KIOCTRANS, and send KIOCLAYOUT to lower queue
 *
 * 5) LQS_KIOCTRANS_ACK_PENDING --->	Destroy
 * 	receive nak to KIOCTRANS, it is a fatal error so that this
 * 	keyboard is not avilable. destroy the lower queue struct.
 *
 * 6) LQS_KIOCLAYOUT_ACK_PENDING --->	LQS_KIOCSLED_ACK_PENDING;
 * 	receive ack/nak to KIOCLAYOUT, and send KIOCSLED/KIOCGLED to
 *	lower queue.
 *
 * 7) LQS_KIOCSLED_ACK_PENDING	--->	LQS_INITIALIZED
 * 	receive ack/nak, the keyboard is linked under conskbd, multiplexed
 * 	with other keyboards.
 *
 * 8) when lower queue is in the state of LQS_INITIALIZED_LEGACY or
 *    LQS_INITIALIZED, no state transform occures unless the lower
 *    queue is destroyed.
 */
enum conskbd_lqs_state {
	LQS_UNINITIALIZED = 0,
	LQS_KIOCTYPE_ACK_PENDING = 1,	/* waiting ACK for KIOCTYPE */
	LQS_KIOCTRANS_ACK_PENDING = 2, /* waiting ACK for KIOCTRANS */
	LQS_KIOCLAYOUT_ACK_PENDING = 3, /* waiting ACK for KIOCLAYOUT */
	LQS_KIOCSLED_ACK_PENDING = 4, /* waiting ACK for KIOCSLED/KIOCGLED */
	LQS_INITIALIZED_LEGACY = 5, /* only one lower legacy keyboard */
	LQS_INITIALIZED = 6 /* virtual keyboard initialized */
};

struct conskbd_state;
struct conskbd_lower_queue;

/*
 * state of lower queue.
 */
typedef struct conskbd_lower_queue	conskbd_lower_queue_t;
struct conskbd_lower_queue {

	conskbd_lower_queue_t	*lqs_next;

	queue_t		*lqs_queue; /* streams queue of lower driver */

	queue_t		*lqs_pending_queue; /* queue of pending message from */
	mblk_t		*lqs_pending_plink; /* pending I_PLINK message */

	/* state of lower queue */
	enum conskbd_lqs_state		lqs_state;

	/* polled I/O interface structure of lower keyboard driver */
	struct cons_polledio	*lqs_polledio;

	/* key status (key-down/key-up) of each key */
	enum keystate	lqs_key_state[KBTRANS_KEYNUMS_MAX];
};

/*
 * Pending message structure.
 *
 * Note:
 *     When conskbd receives message from its upper module, it has to
 * clone the message and send a copy to each of its lower queues. The
 * conskbd_pending_msg structure is used to track the process of handling
 * this kind of messages.
 */
typedef struct conskbd_pending_msg	conskbd_pending_msg_t;
struct conskbd_pending_msg {

	conskbd_pending_msg_t	*kpm_next;

	/* the upper queue from which request message is sent out */
	queue_t	*kpm_upper_queue;

	mblk_t	*kpm_req_msg;	/* the message block from upper */

	/* message ID and Command Code of the message pointed by kpm_req_msg */
	uint_t	kpm_req_id;
	int	kpm_req_cmd;

	/* number of request message's copies sent down to lower queues */
	int	kpm_req_nums;

	/* number of responses to request message received from lower queues */
	int	kpm_resp_nums;

	mblk_t	*kpm_resp_list;	/* chain of responses from lower */

	kmutex_t kpm_lock;	/* lock for this structure */
};

/*
 * software state structure for virtual keyboard
 */
struct conskbd_state {

	/* kbtrans of virtual keyboard */
	struct kbtrans		*conskbd_kbtrans;

	/* polled I/O interface structure of virutal keyboard */
	struct cons_polledio	conskbd_polledio;

	/* chain of lower physical keyboard queues */
	conskbd_lower_queue_t	*conskbd_lqueue_list;

	/* the number of lower physical keyboard queues */
	int	conskbd_lqueue_nums;

	int	conskbd_layout;	 /* layout of virtual keyboard */
	int	conskbd_led_state; /* LED state of virtual keyboard */

	boolean_t	conskbd_directio; /* upstream directory */
	boolean_t	conskbd_bypassed; /* is virtual keyboard disabled ? */
};
typedef struct conskbd_state	conskbd_state_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONSKBD_H */
