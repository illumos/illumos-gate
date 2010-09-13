/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>

#include "eloop.h"

static struct eloop_data eloop;
/*
 * Initialize global event loop data - must be called before any other eloop_*
 * function. user_data is a pointer to global data structure and will be passed
 * as eloop_ctx to signal handlers.
 */
void
eloop_init(void *user_data)
{
	(void) memset(&eloop, 0, sizeof (eloop));
	eloop.user_data = user_data;
}

/*
 * Register handler for read event
 */
int
eloop_register_read_sock(int sock,
    void (*handler)(int sock, void *eloop_ctx,
    void *sock_ctx), void *eloop_data, void *user_data)
{
	struct eloop_sock *tmp;

	tmp = (struct eloop_sock *)realloc(eloop.readers,
	    (eloop.reader_count + 1) * sizeof (struct eloop_sock));
	if (tmp == NULL)
		return (-1);

	tmp[eloop.reader_count].sock = sock;
	tmp[eloop.reader_count].eloop_data = eloop_data;
	tmp[eloop.reader_count].user_data = user_data;
	tmp[eloop.reader_count].handler = handler;
	eloop.reader_count++;
	eloop.readers = tmp;
	if (sock > eloop.max_sock)
		eloop.max_sock = sock;

	return (0);
}

void
eloop_unregister_read_sock(int sock)
{
	int i;

	if (eloop.readers == NULL || eloop.reader_count == 0)
		return;

	for (i = 0; i < eloop.reader_count; i++) {
		if (eloop.readers[i].sock == sock)
			break;
	}
	if (i == eloop.reader_count)
		return;
	if (i != eloop.reader_count - 1) {
		(void) memmove(&eloop.readers[i], &eloop.readers[i + 1],
		    (eloop.reader_count - i - 1) *
		    sizeof (struct eloop_sock));
	}
	eloop.reader_count--;
}

/*
 * Register timeout routines
 */
int
eloop_register_timeout(unsigned int secs, unsigned int usecs,
    void (*handler)(void *eloop_ctx, void *timeout_ctx),
    void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp, *prev;

	timeout = (struct eloop_timeout *)malloc(sizeof (*timeout));
	if (timeout == NULL)
		return (-1);
	(void) gettimeofday(&timeout->time, NULL);
	timeout->time.tv_sec += secs;
	timeout->time.tv_usec += usecs;
	while (timeout->time.tv_usec >= 1000000) {
		timeout->time.tv_sec++;
		timeout->time.tv_usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	timeout->next = NULL;

	if (eloop.timeout == NULL) {
		eloop.timeout = timeout;
		return (0);
	}

	prev = NULL;
	tmp = eloop.timeout;
	while (tmp != NULL) {
		if (timercmp(&timeout->time, &tmp->time, < /* */))
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if (prev == NULL) {
		timeout->next = eloop.timeout;
		eloop.timeout = timeout;
	} else {
		timeout->next = prev->next;
		prev->next = timeout;
	}

	return (0);
}

/*
 * Cancel timeouts matching <handler,eloop_data,user_data>.
 * ELOOP_ALL_CTX can be used as a wildcard for cancelling all timeouts
 * regardless of eloop_data/user_data.
 */
void
eloop_cancel_timeout(void (*handler)(void *eloop_ctx, void *sock_ctx),
    void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev, *next;

	prev = NULL;
	timeout = eloop.timeout;
	while (timeout != NULL) {
		next = timeout->next;

		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		    eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		    user_data == ELOOP_ALL_CTX)) {
			if (prev == NULL)
				eloop.timeout = next;
			else
				prev->next = next;
			free(timeout);
		} else
			prev = timeout;

		timeout = next;
	}
}

static void eloop_handle_signal(int sig)
{
	int i;

	eloop.signaled++;
	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].sig == sig) {
			eloop.signals[i].signaled++;
			break;
		}
	}
}

static void eloop_process_pending_signals(void)
{
	int i;

	if (eloop.signaled == 0)
		return;
	eloop.signaled = 0;

	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].signaled) {
			eloop.signals[i].signaled = 0;
			eloop.signals[i].handler(eloop.signals[i].sig,
			    eloop.user_data, eloop.signals[i].user_data);
		}
	}
}

/*
 * Register handler for signal.
 * Note: signals are 'global' events and there is no local eloop_data pointer
 * like with other handlers. The (global) pointer given to eloop_init() will be
 * used as eloop_ctx for signal handlers.
 */
int
eloop_register_signal(int sig,
    void (*handler)(int sig, void *eloop_ctx, void *signal_ctx),
    void *user_data)
{
	struct eloop_signal *tmp;

	tmp = (struct eloop_signal *)
	    realloc(eloop.signals,
	    (eloop.signal_count + 1) *
	    sizeof (struct eloop_signal));
	if (tmp == NULL)
		return (-1);

	tmp[eloop.signal_count].sig = sig;
	tmp[eloop.signal_count].user_data = user_data;
	tmp[eloop.signal_count].handler = handler;
	tmp[eloop.signal_count].signaled = 0;
	eloop.signal_count++;
	eloop.signals = tmp;
	(void) signal(sig, eloop_handle_signal);

	return (0);
}

/*
 * Start event loop and continue running as long as there are any registered
 * event handlers.
 */
void
eloop_run(void)
{
	struct pollfd pfds[MAX_POLLFDS];	/* array of polled fd */
	int i, res;
	int default_t, t;
	struct timeval tv, now;

	default_t = 5 * 1000;	/* 5 seconds */
	while (!eloop.terminate &&
	    (eloop.timeout || eloop.reader_count > 0)) {
		if (eloop.timeout) {
			(void) gettimeofday(&now, NULL);
			if (timercmp(&now, &eloop.timeout->time, < /* */))
				timersub(&eloop.timeout->time, &now, &tv);
			else
				tv.tv_sec = tv.tv_usec = 0;
		}

		t = (eloop.timeout == NULL ?
		    default_t : (tv.tv_sec * 1000 + tv.tv_usec / 1000));
		for (i = 0; i < eloop.reader_count; i++) {
			pfds[i].fd = eloop.readers[i].sock;
			pfds[i].events = POLLIN | POLLPRI;
		}
		res = poll(pfds, eloop.reader_count, t);
		if (res < 0 && errno != EINTR)
			return;

		eloop_process_pending_signals();

		/* check if some registered timeouts have occurred */
		if (eloop.timeout) {
			struct eloop_timeout *tmp;

			(void) gettimeofday(&now, NULL);
			if (!timercmp(&now, &eloop.timeout->time, < /* */)) {
				tmp = eloop.timeout;
				eloop.timeout = eloop.timeout->next;
				tmp->handler(tmp->eloop_data, tmp->user_data);
				free(tmp);
			}

		}

		if (res <= 0)
			continue;

		for (i = 0; i < eloop.reader_count; i++) {
			if (pfds[i].revents) {
				eloop.readers[i].handler(
				    eloop.readers[i].sock,
				    eloop.readers[i].eloop_data,
				    eloop.readers[i].user_data);
			}
		}
	}
}

/*
 * Terminate event loop even if there are registered events.
 */
void
eloop_terminate(void)
{
	eloop.terminate = 1;
}


/*
 * Free any reserved resources. After calling eloop_destoy(), other eloop_*
 * functions must not be called before re-running eloop_init().
 */
void
eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;

	timeout = eloop.timeout;
	while (timeout != NULL) {
		prev = timeout;
		timeout = timeout->next;
		free(prev);
	}
	free(eloop.readers);
	free(eloop.signals);
}
