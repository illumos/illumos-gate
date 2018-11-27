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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <limits.h>
#include <thread.h>
#include <wait.h>
#include <synch.h>
#include <errno.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>

#include <libsysevent.h>

#include "message_reg_mod.h"

/*
 * SLM for sysevent event subscribers
 */

extern char	*root_dir;
extern void	syseventd_print(int level, char *format, ...);
extern void	syseventd_err_print(char *format, ...);

sysevent_handle_t *sysevent_hp;

typedef struct ev_queue {
	struct ev_queue *evq_next;
	sysevent_t	*evq_ev;
} ev_queue_t;

static mutex_t	evq_lock;
static cond_t evq_cv;
static ev_queue_t *event_q = NULL;
static int cleanup;
static thread_t deliver_thr_id;

static int
init_channel()
{
	/*
	 * This functionality is not supported in the mini-root
	 * environment, ie install.  If root_dir is set, implying
	 * install, we quietly fail.
	 */
	if (strcmp(root_dir, "") != 0) {
		return (EACCES);
	}

	/*
	 * Initialize the private sysevent handle
	 */
	sysevent_hp = sysevent_open_channel(SYSEVENTD_CHAN);
	if (sysevent_hp == NULL) {
		if (errno == EACCES) {
			syseventd_print(3, "sysevent_reg_mod: "
			    "sysevent_open_channel failed with %s init "
			    "deferred\n", strerror(errno));
			return (errno);
		} else {
			syseventd_err_print(INIT_SUB_OPEN_CHAN_ERR,
			    strerror(errno));
			return (errno);
		}
	}

	if (sysevent_bind_publisher(sysevent_hp) != 0) {
		/*
		 * Only one publisher allowed on the syseventd channel,
		 * cleanup previously allocated syseventd channel publishers
		 */
		if (errno == EBUSY) {
			sysevent_cleanup_publishers(sysevent_hp);
			if (sysevent_bind_publisher(sysevent_hp) == 0)
				return (0);
		}

		syseventd_err_print(INIT_SUB_BIND_PUB_ERR,
		    strerror(errno));
		sysevent_close_channel(sysevent_hp);
		sysevent_hp = NULL;
		return (errno);
	}

	return (0);
}

static int
deliver_event(sysevent_t *ev, int flag)
{
	int ret, ev_size;
	ev_queue_t *new_evq, *tmp_evq;

	/* Not initialized */
	if (sysevent_hp == NULL) {

		ret = init_channel();
		if (ret != 0) {
			if (ret == EBUSY && flag != SE_NO_RETRY) {
				return (EAGAIN);
			} else if (ret == EACCES) {
				return (0);
			} else {
				syseventd_err_print(INIT_SUB_OPEN_CHAN_ERR,
				    strerror(ret));
				return (0);
			}
		}
		/* Check for stale syseventd subscribers */
		sysevent_cleanup_subscribers(sysevent_hp);
		syseventd_print(3, "sysevent_reg_mod: init successful");
	}

	/* Queue event for delivery to all subscribers */
	new_evq = (ev_queue_t *)calloc(1, sizeof (ev_queue_t));
	if (new_evq == NULL) {
		return (EAGAIN);
	}
	ev_size = sysevent_get_size(ev);
	new_evq->evq_ev = (sysevent_t *)malloc(ev_size);
	if (new_evq->evq_ev == NULL) {
		free(new_evq);
		return (EAGAIN);
	}
	bcopy(ev, new_evq->evq_ev, ev_size);

	(void) mutex_lock(&evq_lock);
	if (event_q == NULL) {
		event_q = new_evq;
	} else {
		tmp_evq = event_q;
		while (tmp_evq->evq_next != NULL)
			tmp_evq = tmp_evq->evq_next;
		tmp_evq->evq_next = new_evq;
	}
	syseventd_print(3, "sysevent_reg_mod: queue event 0X%llx\n",
	    sysevent_get_seq(ev));

	(void) cond_signal(&evq_cv);
	(void) mutex_unlock(&evq_lock);

	return (0);
}

void *
subscriber_deliver_thr(void *arg __unused)
{
	ev_queue_t *evqp;

	(void) mutex_lock(&evq_lock);
	for (;;) {
		while (event_q == NULL && cleanup == 0) {
			(void) cond_wait(&evq_cv, &evq_lock);
		}

		/* Send events on to all current subscribers */
		evqp = event_q;
		while (evqp) {
			(void) mutex_unlock(&evq_lock);
			syseventd_print(3, "sysevent_reg_mod: sending event "
			    "0X%llx\n", sysevent_get_seq(evqp->evq_ev));
			if (sysevent_send_event(sysevent_hp,
			    evqp->evq_ev) != 0) {
				syseventd_print(3, "sysevent_reg_mod: "
				    "failed to send event\n");
			}
			syseventd_print(3, "sysevent_reg_mod: event sent "
			    "0X%llx\n", sysevent_get_seq(evqp->evq_ev));
			(void) mutex_lock(&evq_lock);
			event_q = evqp->evq_next;
			free(evqp->evq_ev);
			free(evqp);
			evqp = event_q;
		}
		if (cleanup) {
			syseventd_print(3, "sysevent_reg_mod: deliver "
			    "thread exiting\n");
			(void) mutex_unlock(&evq_lock);
			(void) thr_exit(NULL);
			/* NOTREACHED */
		}
	}

	/* NOTREACHED */
}

static struct slm_mod_ops sysevent_reg_mod_ops = {
	SE_MAJOR_VERSION, SE_MINOR_VERSION, SE_MAX_RETRY_LIMIT, deliver_event};

struct slm_mod_ops *
slm_init()
{
	cleanup = 0;
	sysevent_hp = NULL;

	(void) init_channel();

	(void) mutex_init(&evq_lock, USYNC_THREAD, NULL);
	(void) cond_init(&evq_cv, USYNC_THREAD, NULL);

	if (thr_create(NULL, 0, (void *(*)(void *))subscriber_deliver_thr,
	    NULL, 0, &deliver_thr_id) != 0) {
		syseventd_err_print(INIT_SUB_THR_CREATE_ERR, strerror(errno));
		return (NULL);
	}

	return (&sysevent_reg_mod_ops);
}

void
slm_fini()
{
	(void) mutex_lock(&evq_lock);
	cleanup = 1;
	(void) cond_signal(&evq_cv);
	(void) mutex_unlock(&evq_lock);

	/* Wait for delivery threads to exit */
	(void) thr_join(deliver_thr_id, NULL, NULL);

	(void) mutex_destroy(&evq_lock);
	(void) cond_destroy(&evq_cv);

	sysevent_close_channel(sysevent_hp);
	sysevent_hp = NULL;
}
