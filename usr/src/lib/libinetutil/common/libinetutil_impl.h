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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBINETUTIL_IMPL_H
#define	_LIBINETUTIL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains implementation-specific definitions for libinetutil.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/inetutil.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/poll.h>
#include <signal.h>
#include <limits.h>

/*
 * timer queue implementation-specific artifacts which may change.  A
 * `iu_tq_t' is an incomplete type as far as the consumer of timer queues
 * is concerned.
 */

typedef struct iu_timer_node {

	struct iu_timer_node		*iutn_prev;
	struct iu_timer_node		*iutn_next;
	struct iu_timer_node		*iutn_expire_next;
	hrtime_t			iutn_abs_timeout;
	iu_timer_id_t			iutn_timer_id;
	iu_tq_callback_t		*iutn_callback;
	void				*iutn_arg;
	int				iutn_pending_delete;

} iu_timer_node_t;

struct iu_timer_queue {
	iu_timer_id_t	iutq_next_timer_id;
	iu_timer_node_t	*iutq_head;		/* in order of time-to-fire */
	int		iutq_in_expire;	/* nonzero if in the expire function */
	uchar_t		iutq_timer_id_map[(IU_TIMER_ID_MAX + CHAR_BIT) /
				CHAR_BIT];
};

/*
 * event handler implementation-specific artifacts which may change.  An
 * `iu_eh_t' is an incomplete type as far as the consumer of event handlers is
 * concerned.
 */

typedef struct iu_event_node {

	iu_eh_callback_t	*iuen_callback;	/* callback to call */

	void			*iuen_arg;	/* argument to pass to the */
						/* callback */
} iu_event_node_t;

typedef struct iu_eh_sig_info  {

	boolean_t		iues_pending;	/* signal is currently */
						/* pending */

	iu_eh_sighandler_t	*iues_handler;	/* handler for a given signal */

	void			*iues_data; 	/* data to pass back to the */
						/* handler */
} iu_eh_sig_info_t;

struct iu_event_handler {

	struct pollfd		*iueh_pollfds;	/* array of pollfds */

	iu_event_node_t		*iueh_events;	/* corresponding pollfd info */

	unsigned int		iueh_num_fds;	/* number of pollfds/events */

	boolean_t		iueh_stop;	/* true when done */

	unsigned int		iueh_reason;	/* if stop is true, reason */

	sigset_t		iueh_sig_regset;	/* registered signal */
							/* set */

	iu_eh_sig_info_t	iueh_sig_info[NSIG];	/* signal handler */
							/* information */

	iu_eh_shutdown_t	*iueh_shutdown;	/* shutdown callback */

	void			*iueh_shutdown_arg;	/* data for shutdown */
							/* callback */
};

#ifdef	__cplusplus
}
#endif

#endif	/* !_LIBINETUTIL_IMPL_H */
