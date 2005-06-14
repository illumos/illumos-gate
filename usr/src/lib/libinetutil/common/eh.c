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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stropts.h>	/* INFTIM */

#include <libinetutil.h>
#include "libinetutil_impl.h"

static int	grow_fds(iu_eh_t *, int);

/*
 * signal_to_eh[] is pretty much useless, since the event handler is
 * really a singleton (we pass iu_eh_t *'s around to maintain an
 * abstraction, not to allow multiple event handlers to exist).  we
 * need some way to get back our event handler in post_signal(),
 * and since the signal model is too lame to provide opaque pointers,
 * we have to resort to global variables.
 */

static iu_eh_t *signal_to_eh[NSIG];

/*
 * iu_eh_create(): creates, initializes, and returns an event handler for use
 *
 *   input: void
 *  output: iu_eh_t *: the new event handler
 */

iu_eh_t *
iu_eh_create(void)
{
	iu_eh_t	*eh = malloc(sizeof (iu_eh_t));
	int	sig;

	if (eh == NULL)
		return (NULL);

	eh->iueh_pollfds	= NULL;
	eh->iueh_events		= NULL;
	eh->iueh_shutdown	= NULL;
	eh->iueh_num_fds	= 0;
	eh->iueh_stop		= B_FALSE;
	eh->iueh_reason		= 0;
	eh->iueh_shutdown_arg	= NULL;

	(void) sigemptyset(&eh->iueh_sig_regset);
	for (sig = 0; sig < NSIG; sig++) {
		eh->iueh_sig_info[sig].iues_pending = B_FALSE;
		eh->iueh_sig_info[sig].iues_handler = NULL;
		eh->iueh_sig_info[sig].iues_data = NULL;
	}

	return (eh);
}

/*
 * iu_eh_destroy(): destroys an existing event handler
 *
 *   input: iu_eh_t *: the event handler to destroy
 *  output: void
 *   notes: it is assumed all events related to this eh have been unregistered
 *          prior to calling iu_eh_destroy()
 */

void
iu_eh_destroy(iu_eh_t *eh)
{
	int	sig;

	for (sig = 0; sig < NSIG; sig++)
		if (signal_to_eh[sig] == eh)
			(void) iu_eh_unregister_signal(eh, sig, NULL);

	free(eh->iueh_pollfds);
	free(eh->iueh_events);
	free(eh);
}

/*
 * iu_stop_handling_events(): informs the event handler to stop handling events
 *
 *   input: iu_eh_t *: the event handler to stop.
 *	    unsigned int: the (user-defined) reason why
 *          iu_eh_shutdown_t *: the shutdown callback. if it is NULL,
 *				the event handler will stop right away;
 *				otherwise, the event handler will not
 *				stop until the callback returns B_TRUE
 *	    void *: data for the shutdown callback. it may be NULL
 *  output: void
 *   notes: the event handler in question must be in iu_handle_events()
 */

void
iu_stop_handling_events(iu_eh_t *eh, unsigned int reason,
    iu_eh_shutdown_t *shutdown, void *arg)
{
	eh->iueh_stop   = B_TRUE;
	eh->iueh_reason = reason;
	eh->iueh_shutdown = shutdown;
	eh->iueh_shutdown_arg = arg;
}

/*
 * grow_fds(): grows the internal file descriptor set used by the event
 *		  handler
 *
 *   input: iu_eh_t *: the event handler whose descriptor set needs to be grown
 *          int: the new total number of descriptors needed in the set
 *  output: int: zero on failure, success otherwise
 */

static int
grow_fds(iu_eh_t *eh, int total_fds)
{
	unsigned int	i;
	struct pollfd	*new_pollfds;
	iu_event_node_t	*new_events;

	if (total_fds <= eh->iueh_num_fds)
		return (1);

	new_pollfds = realloc(eh->iueh_pollfds,
	    total_fds * sizeof (struct pollfd));
	if (new_pollfds == NULL)
		return (0);

	eh->iueh_pollfds = new_pollfds;

	new_events = realloc(eh->iueh_events,
	    total_fds * sizeof (iu_event_node_t));
	if (new_events == NULL) {

		/*
		 * yow.  one realloc failed, but the other succeeded.
		 * we will just leave the descriptor size at the
		 * original size.  if the caller tries again, then the
		 * first realloc() will do nothing since the requested
		 * number of descriptors is already allocated.
		 */

		return (0);
	}

	for (i = eh->iueh_num_fds; i < total_fds; i++)
		eh->iueh_pollfds[i].fd = -1;

	eh->iueh_events  = new_events;
	eh->iueh_num_fds = total_fds;
	return (1);
}

/*
 * when increasing the file descriptor set size, how much to increase by:
 */

#define	EH_FD_SLACK	10

/*
 * iu_register_event(): adds an event to the set managed by an event handler
 *
 *   input: iu_eh_t *: the event handler to add the event to
 *          int: the descriptor on which to listen for events.  must be
 *		 a descriptor which has not yet been registered.
 *          short: the events to listen for on that descriptor
 *          iu_eh_callback_t: the callback to execute when the event happens
 *          void *: the argument to pass to the callback function
 *  output: iu_event_id_t: -1 on failure, the new event id otherwise
 */

iu_event_id_t
iu_register_event(iu_eh_t *eh, int fd, short events, iu_eh_callback_t *callback,
    void *arg)
{
	if (eh->iueh_num_fds <= fd)
		if (grow_fds(eh, fd + EH_FD_SLACK) == 0)
			return (-1);

	/*
	 * the current implementation uses the file descriptor itself
	 * as the iu_event_id_t, since we know the kernel's gonna be
	 * pretty smart about managing file descriptors and we know
	 * that they're per-process unique.  however, it does mean
	 * that the same descriptor cannot be registered multiple
	 * times for different callbacks depending on its events.  if
	 * this behavior is desired, either use dup(2) to get a unique
	 * descriptor, or demultiplex in the callback function based
	 * on `events'.
	 */

	if (eh->iueh_pollfds[fd].fd != -1)
		return (-1);

	eh->iueh_pollfds[fd].fd 		= fd;
	eh->iueh_pollfds[fd].events		= events;
	eh->iueh_events[fd].iuen_callback	= callback;
	eh->iueh_events[fd].iuen_arg		= arg;

	return (fd);
}

/*
 * iu_unregister_event(): removes an event from the set managed by an event
 *			  handler
 *
 *   input: iu_eh_t *: the event handler to remove the event from
 *          iu_event_id_t: the event to remove (from iu_register_event())
 *          void **: if non-NULL, will be set to point to the argument passed
 *                   into iu_register_event()
 *  output: int: zero on failure, success otherwise
 */

int
iu_unregister_event(iu_eh_t *eh, iu_event_id_t event_id, void **arg)
{
	if (event_id < 0 || event_id >= eh->iueh_num_fds ||
	    eh->iueh_pollfds[event_id].fd == -1)
		return (0);

	/*
	 * fringe condition: in case this event was about to be called
	 * back in iu_handle_events(), zero revents to prevent it.
	 * (having an unregistered event get called back could be
	 * disastrous depending on if `arg' is reference counted).
	 */

	eh->iueh_pollfds[event_id].revents = 0;
	eh->iueh_pollfds[event_id].fd = -1;
	if (arg != NULL)
		*arg = eh->iueh_events[event_id].iuen_arg;

	return (1);
}

/*
 * iu_handle_events(): begins handling events on an event handler
 *
 *   input: iu_eh_t *: the event handler to begin event handling on
 *          tq_t *: a timer queue of timers to process while handling events
 *                  (see timer_queue.h for details)
 *  output: int: the reason why we stopped, -1 if due to internal failure
 */

int
iu_handle_events(iu_eh_t *eh, iu_tq_t *tq)
{
	int		n_lit, timeout, sig, saved_errno;
	unsigned int	i;
	sigset_t	oset;

	eh->iueh_stop = B_FALSE;
	do {
		timeout = tq ? iu_earliest_timer(tq) : INFTIM;

		/*
		 * we only unblock registered signals around poll(); this
		 * way other parts of the code don't have to worry about
		 * restarting "non-restartable" system calls and so forth.
		 */

		(void) sigprocmask(SIG_UNBLOCK, &eh->iueh_sig_regset, &oset);
		n_lit = poll(eh->iueh_pollfds, eh->iueh_num_fds, timeout);
		saved_errno = errno;
		(void) sigprocmask(SIG_SETMASK, &oset, NULL);

		switch (n_lit) {

		case -1:
			if (saved_errno != EINTR)
				return (-1);

			for (sig = 0; sig < NSIG; sig++) {
				if (eh->iueh_sig_info[sig].iues_pending) {
					eh->iueh_sig_info[sig].iues_pending =
					    B_FALSE;
					eh->iueh_sig_info[sig].iues_handler(eh,
					    sig,
					    eh->iueh_sig_info[sig].iues_data);
				}
			}

			if (eh->iueh_shutdown != NULL)
				break;

			continue;

		case  0:
			/*
			 * timeout occurred.  we must have a valid tq pointer
			 * since that's the only way a timeout can happen.
			 */

			(void) iu_expire_timers(tq);
			continue;

		default:
			break;
		}

		/* file descriptors are lit; call 'em back */

		for (i = 0; i < eh->iueh_num_fds && n_lit > 0; i++) {

			if (eh->iueh_pollfds[i].revents == 0)
				continue;

			n_lit--;

			/*
			 * turn off any descriptors that have gone
			 * bad.  shouldn't happen, but...
			 */

			if (eh->iueh_pollfds[i].revents & (POLLNVAL|POLLERR)) {
				/* TODO: issue a warning here - but how? */
				(void) iu_unregister_event(eh, i, NULL);
				continue;
			}

			eh->iueh_events[i].iuen_callback(eh, i,
			    eh->iueh_pollfds[i].revents, i,
			    eh->iueh_events[i].iuen_arg);
		}

	} while (eh->iueh_stop == B_FALSE || (eh->iueh_shutdown != NULL &&
	    eh->iueh_shutdown(eh, eh->iueh_shutdown_arg) == B_FALSE));

	return (eh->iueh_reason);
}

/*
 * post_signal(): posts a signal for later consumption in iu_handle_events()
 *
 *   input: int: the signal that's been received
 *  output: void
 */

static void
post_signal(int sig)
{
	if (signal_to_eh[sig] != NULL)
		signal_to_eh[sig]->iueh_sig_info[sig].iues_pending = B_TRUE;
}

/*
 * iu_eh_register_signal(): registers a signal handler with an event handler
 *
 *   input: iu_eh_t *: the event handler to register the signal handler with
 *	    int: the signal to register
 *	    iu_eh_sighandler_t *: the signal handler to call back
 *	    void *: the argument to pass to the signal handler function
 *   output: int: zero on failure, success otherwise
 */

int
iu_eh_register_signal(iu_eh_t *eh, int sig, iu_eh_sighandler_t *handler,
    void *data)
{
	struct sigaction	act;

	if (sig < 0 || sig >= NSIG || signal_to_eh[sig] != NULL)
		return (0);

	act.sa_flags = 0;
	act.sa_handler = &post_signal;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaddset(&act.sa_mask, sig); /* used for sigprocmask() */

	if (sigaction(sig, &act, NULL) == -1)
		return (0);

	(void) sigprocmask(SIG_BLOCK, &act.sa_mask, NULL);

	eh->iueh_sig_info[sig].iues_data = data;
	eh->iueh_sig_info[sig].iues_handler = handler;
	signal_to_eh[sig] = eh;

	(void) sigaddset(&eh->iueh_sig_regset, sig);
	return (0);
}

/*
 * iu_eh_unregister_signal(): unregisters a signal handler from an event handler
 *
 *   input: iu_eh_t *: the event handler to unregister the signal handler from
 *	    int: the signal to unregister
 *	    void **: if non-NULL, will be set to point to the argument passed
 *		     into iu_eh_register_signal()
 *  output: int: zero on failure, success otherwise
 */

int
iu_eh_unregister_signal(iu_eh_t *eh, int sig, void **datap)
{
	sigset_t	set;

	if (sig < 0 || sig >= NSIG || signal_to_eh[sig] != eh)
		return (0);

	if (signal(sig, SIG_DFL) == SIG_ERR)
		return (0);

	if (datap != NULL)
		*datap = eh->iueh_sig_info[sig].iues_data;

	(void) sigemptyset(&set);
	(void) sigaddset(&set, sig);
	(void) sigprocmask(SIG_UNBLOCK, &set, NULL);

	eh->iueh_sig_info[sig].iues_data = NULL;
	eh->iueh_sig_info[sig].iues_handler = NULL;
	eh->iueh_sig_info[sig].iues_pending = B_FALSE;
	signal_to_eh[sig] = NULL;

	(void) sigdelset(&eh->iueh_sig_regset, sig);
	return (1);
}
