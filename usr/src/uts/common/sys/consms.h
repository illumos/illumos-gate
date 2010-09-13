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

#ifndef	_SYS_CONSMS_H
#define	_SYS_CONSMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Those default values are taken from lower mice drivers.
 */
#define	CONSMS_SR_DEFAULT_HEIGHT	768
#define	CONSMS_SR_DEFAULT_WIDTH		1024

#define	CONSMS_PARMS_DEFAULT_JITTER	0
#define	CONSMS_PARMS_DEFAULT_SPEED_LAW	0
#define	CONSMS_PARMS_DEFAULT_SPEED_LIMIT	48

#define	CONSMS_MAX(x, y)	((x) > (y) ? (x) : (y))

/*
 * These states are only used when an underlying mouse
 * is being linked under the virtual mouse (/dev/mouse),
 * in order to set some cached state variables. And these
 * states go in a sequential way.
 */
typedef enum {
	LQS_START = 0,				/* begin of initializing */
	LQS_BUTTON_COUNT_PENDING = 1,		/* wait for button count ACK */
	LQS_WHEEL_COUNT_PENDING = 2,		/* wait for wheel count ACK */
	LQS_SET_VUID_FORMAT_PENDING = 3,	/* wait for set format ACK */
	LQS_SET_WHEEL_STATE_PENDING = 4,	/* wait for wheel state ACK */
	LQS_SET_PARMS_PENDING = 5,		/* wait for parameters ACK */
	LQS_SET_RESOLUTION_PENDING = 6,		/* wait for resolution ACK */
	LQS_DONE = 7				/* mark end of initialization */
} consms_lq_state_t;

struct consms_lq;
typedef void (*ioc_reply_func_t)(struct consms_lq *, mblk_t *);

/*
 * This structure contains information
 * for each underlying physical mouse
 * (lower queue).
 */
typedef struct consms_lq {
	struct consms_lq	*lq_next;	/* next lower queue */

	consms_lq_state_t	lq_state;	/* used during initializing */
	queue_t			*lq_queue;	/* lower write q */

	ioc_reply_func_t	lq_ioc_reply_func; /* reply function */
	mblk_t			*lq_pending_plink; /* pending msg */
	queue_t			*lq_pending_queue; /* upper write q */

	int			lq_num_buttons; /* number of buttons */
	int			lq_num_wheels;	/* number of wheels */
	ushort_t		lq_wheel_state_bf; /* enabled/disabled */
} consms_lq_t;

/*
 * This structure is used to remember the
 * COPYIN and COPYOUT request mp from lower
 * queue during transparent ioctl.
 */
typedef struct consms_response {
	struct consms_response	*rsp_next;
	mblk_t  *rsp_mp;	/* response mp (M_COPYIN or M_COPYOUT) */
	queue_t	*rsp_queue;	/* lower read q giving this response */
} consms_response_t;

/*
 * This structure contains information for
 * each ioctl message from upper layer
 * (usually, X server).
 */
typedef struct consms_msg {
	struct consms_msg *msg_next;

	uint_t	msg_id;			/* taken from request message */
	int	msg_num_requests;	/* # of lower queues dispatched */
	int	msg_num_responses;	/* # of responses from lower queues */
	mblk_t	*msg_request;		/* pending request message from upper */
	queue_t *msg_queue;		/* upper write q used for qrely() */

	/*
	 * ack_mp is just used for IOCACK
	 * and rsp_list is only used for COPYIN
	 * or COPYOUT responses from lowers
	 */
	mblk_t			*msg_ack_mp;	/* IOCACK from lower */
	consms_response_t	*msg_rsp_list;	/* responses from lower */
} consms_msg_t;

/*
 * This structure contains information
 * about virtual mouse (lower queue list,
 * and virtual mouse state variables).
 */
typedef struct consms_state {
	consms_lq_t	*consms_lqs;		/* lower queues */
	int		consms_num_lqs;		/* # of lower queues */

	/* virtual mouse state variables */
	int		consms_vuid_format;	/* NATIVE or VUID_FIRM */
	int		consms_num_buttons;	/* max number of buttons */
	int		consms_num_wheels;	/* max number of wheels */
	ushort_t	consms_wheel_state_bf;	/* wheel enabled or disabled */
	Ms_parms	consms_ms_parms;	/* parameters for usb mouse */
	Ms_screen_resolution	consms_ms_sr; 	/* for absolute mouse */
} consms_state_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONSMS_H */
