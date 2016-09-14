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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Nexenta Systems, Inc.
 */

/*
 * datalink syseventd module.
 *
 * The purpose of this module is to identify all datalink related events,
 * and react accordingly.
 */

#include <errno.h>
#include <sys/sysevent/eventdefs.h>
#include <string.h>
#include <libnvpair.h>
#include <librcm.h>
#include <libsysevent.h>
#include "sysevent_signal.h"

extern void syseventd_err_print(char *, ...);

struct event_list {
	nvlist_t *ev;
	struct event_list *next;
};

static rcm_handle_t *rcm_hdl = NULL;
static boolean_t dl_exiting;
static thread_t dl_notify_tid;
static mutex_t dl_mx;
static cond_t dl_cv;
static struct event_list *dl_events;

/* ARGSUSED */
static void *
datalink_notify_thread(void *arg)
{
	struct event_list *tmp_events, *ep;

	(void) mutex_lock(&dl_mx);

	while (! dl_exiting || dl_events != NULL) {
		if (dl_events == NULL) {
			(void) cond_wait(&dl_cv, &dl_mx);
			continue;
		}

		tmp_events = dl_events;
		dl_events = NULL;

		(void) mutex_unlock(&dl_mx);

		while (tmp_events != NULL) {
			struct sigaction cbuf, dfl;

			/*
			 * Ignore SIGCLD for the
			 * duration of the rcm_notify_event call.
			 */
			(void) memset(&dfl, 0, sizeof (dfl));
			dfl.sa_handler = SIG_IGN;
			(void) sigaction(SIGCHLD, &dfl, &cbuf);

			/*
			 * Send the PHYSLINK_NEW event to network_rcm to update
			 * the network devices cache accordingly.
			 */
			if (rcm_notify_event(rcm_hdl, RCM_RESOURCE_PHYSLINK_NEW,
			    0, tmp_events->ev, NULL) != RCM_SUCCESS)
				syseventd_err_print("datalink_mod: Can not "
				    "notify event: %s\n", strerror(errno));

			(void) sigaction(SIGCHLD, &cbuf, NULL);
			ep = tmp_events;
			tmp_events = tmp_events->next;
			nvlist_free(ep->ev);
			free(ep);
		}

		(void) mutex_lock(&dl_mx);
	}

	(void) mutex_unlock(&dl_mx);

	return (NULL);
}

/*ARGSUSED*/
static int
datalink_deliver_event(sysevent_t *ev, int unused)
{
	const char *class = sysevent_get_class_name(ev);
	const char *subclass = sysevent_get_subclass_name(ev);
	nvlist_t *nvl;
	struct event_list *newp, **elpp;

	if (strcmp(class, EC_DATALINK) != 0 ||
	    strcmp(subclass, ESC_DATALINK_PHYS_ADD) != 0) {
		return (0);
	}

	if (sysevent_get_attr_list(ev, &nvl) != 0)
		return (EINVAL);

	/*
	 * rcm_notify_event() needs to be called asynchronously otherwise when
	 * sysevent queue is full, deadlock will happen.
	 */
	if ((newp = malloc(sizeof (struct event_list))) == NULL)
		return (ENOMEM);

	newp->ev = nvl;
	newp->next = NULL;

	/*
	 * queue up at the end of the event list and signal notify_thread to
	 * process it.
	 */
	(void) mutex_lock(&dl_mx);
	elpp = &dl_events;
	while (*elpp !=  NULL)
		elpp = &(*elpp)->next;
	*elpp = newp;
	(void) cond_signal(&dl_cv);
	(void) mutex_unlock(&dl_mx);

	return (0);
}

static struct slm_mod_ops datalink_mod_ops = {
	SE_MAJOR_VERSION,
	SE_MINOR_VERSION,
	SE_MAX_RETRY_LIMIT,
	datalink_deliver_event
};

struct slm_mod_ops *
slm_init()
{
	dl_events = NULL;
	dl_exiting = B_FALSE;

	if (rcm_alloc_handle(NULL, 0, NULL, &rcm_hdl) != RCM_SUCCESS)
		return (NULL);

	(void) mutex_init(&dl_mx, USYNC_THREAD, NULL);
	(void) cond_init(&dl_cv, USYNC_THREAD, NULL);

	if (thr_create(NULL, 0,  datalink_notify_thread, NULL, 0,
	    &dl_notify_tid) != 0) {
		(void) rcm_free_handle(rcm_hdl);
		(void) mutex_destroy(&dl_mx);
		(void) cond_destroy(&dl_cv);
		return (NULL);
	}

	return (&datalink_mod_ops);
}

void
slm_fini()
{
	(void) mutex_lock(&dl_mx);
	dl_exiting = B_TRUE;
	(void) cond_signal(&dl_cv);
	(void) mutex_unlock(&dl_mx);
	(void) thr_join(dl_notify_tid, NULL, NULL);

	(void) mutex_destroy(&dl_mx);
	(void) cond_destroy(&dl_cv);
	(void) rcm_free_handle(rcm_hdl);
	rcm_hdl = NULL;
}
