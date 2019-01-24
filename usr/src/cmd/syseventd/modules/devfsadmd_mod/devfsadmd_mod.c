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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <thread.h>
#include <wait.h>
#include <synch.h>
#include <syslog.h>
#include <libintl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>

#include <libsysevent.h>

#include "sysevent_signal.h"
#include "../devfsadm/devfsadm.h"

/*
 * SLM for devfsadmd device configuration daemon
 */

extern char *root_dir;
extern void syseventd_print();

sysevent_handle_t *sysevent_hp;

/* Alternate root declarations during install */
static int use_alt_root = 0;

static int devfsadmdeliver_event(sysevent_t *ev, int flag);

static struct slm_mod_ops devfsadm_mod_ops = {
	SE_MAJOR_VERSION, SE_MINOR_VERSION, 10, devfsadmdeliver_event};

typedef struct ev_queue {
	struct ev_queue *evq_next;
	sysevent_t	*evq_ev;
} ev_queue_t;

static mutex_t evq_lock;
static cond_t evq_cv;
static ev_queue_t *eventq_head;
static ev_queue_t *eventq_tail;

#define	DELIVERY_FAILED	\
	gettext("devfsadmd not responding, /dev may not be current")

#define	DELIVERY_RESUMED \
	gettext("devfsadmd now responding again")

/*
 * Retry error recovery when attempting to send an event to devfsadmd
 */
#define	RETRY_DAEMON_RESTART	0
#define	RETRY_MSG_THRESHOLD	60
#define	RETRY_DAEMON_INTERVAL	60

static int
system1(const char *s_path, const char *s)
{
	struct sigaction cbuf, ibuf, qbuf, ignore, dfl;
	sigset_t mask, savemask;
	struct stat st;
	pid_t pid;
	int status, w;

	/* Check the requested command */
	if (s == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* Check the ability to execute devfsadmd from this process */
	if (stat(s_path, &st) < 0) {
		return (-1);
	}
	if (((geteuid() == st.st_uid) && ((st.st_mode & S_IXUSR) == 0)) ||
	    ((getegid() == st.st_gid) && ((st.st_mode & S_IXGRP) == 0)) ||
	    ((st.st_mode & S_IXOTH) == 0)) {
		errno = EPERM;
		return (-1);
	}

	/*
	 * Block SIGCHLD and set up a default handler for the duration of the
	 * system1 call.
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGCHLD);
	(void) sigprocmask(SIG_BLOCK, &mask, &savemask);
	(void) memset(&dfl, 0, sizeof (dfl));
	dfl.sa_handler = SIG_DFL;
	(void) sigaction(SIGCHLD, &dfl, &cbuf);

	/* Fork off the child process (using fork1(), because it's MT-safe) */
	switch (pid = fork1()) {
		case -1:
			/* Error */
			(void) sigaction(SIGCHLD, &cbuf, NULL);
			(void) sigprocmask(SIG_SETMASK, &savemask, NULL);
			return (-1);
		case 0:
			/* Set-up an initial signal mask for the child */
			(void) sigemptyset(&mask);
			(void) sigprocmask(SIG_SETMASK, &mask, NULL);
			closefrom(3);
			(void) execl(s_path, s, (char *)0);
			_exit(-1);
			break;
		default:
			/* Parent */
			break;
	}

	(void) memset(&ignore, 0, sizeof (ignore));
	ignore.sa_handler = SIG_IGN;
	(void) sigaction(SIGINT, &ignore, &ibuf);
	(void) sigaction(SIGQUIT, &ignore, &qbuf);

	do {
		w = waitpid(pid, &status, 0);
	} while (w == -1 && errno == EINTR);

	(void) sigaction(SIGINT, &ibuf, NULL);
	(void) sigaction(SIGQUIT, &qbuf, NULL);
	(void) sigaction(SIGCHLD, &cbuf, NULL);
	(void) sigprocmask(SIG_SETMASK, &savemask, NULL);

	return ((w == -1)? w: status);
}

/*
 * devfsadmdeliver_event - called by syseventd to deliver an event buffer.
 *			The event buffer is subsequently delivered to
 *			devfsadmd.  If devfsadmd, is not responding to the
 *			delivery attempt, we will try to startup the
 *			daemon.  MT protection is provided by syseventd
 *			and the client lock.  This insures sequential
 *			event delivery and protection from re-entrance.
 */
/*ARGSUSED*/
static int
devfsadmdeliver_event(sysevent_t *ev, int flag)
{
	int ev_size;
	ev_queue_t *new_evq;

	/* Not initialized */
	if (sysevent_hp == NULL) {
		return (0);
	}

	/* Quick return for uninteresting events */
	if (strcmp(sysevent_get_class_name(ev), EC_DEVFS) != 0) {
		return (0);
	}

	/* Queue event for delivery to devfsadmd */
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
	if (eventq_head == NULL) {
		eventq_head = new_evq;
	} else {
		eventq_tail->evq_next = new_evq;
	}
	eventq_tail = new_evq;

	(void) cond_signal(&evq_cv);
	(void) mutex_unlock(&evq_lock);

	return (0);
}

static int cleanup;
thread_t deliver_thr_id;

void
devfsadmd_deliver_thr()
{
	int retry = 0;
	int msg_emitted = 0;
	ev_queue_t *evqp;

	(void) mutex_lock(&evq_lock);
	for (;;) {
		while (eventq_head == NULL) {
			(void) cond_wait(&evq_cv, &evq_lock);
			if (cleanup && eventq_head == NULL) {
				(void) cond_signal(&evq_cv);
				(void) mutex_unlock(&evq_lock);
				return;
			}
		}

		/* Send events on to devfsadmd */
		evqp = eventq_head;
		while (evqp) {
			(void) mutex_unlock(&evq_lock);
			retry = 0;
			while (sysevent_send_event(sysevent_hp,
			    evqp->evq_ev) != 0) {
				/*
				 * Invoke devfsadm to handle node creation
				 * but not for an alternate root.
				 */
				if (use_alt_root != 0)
					break;
				/*
				 * daemon unresponsive -
				 * restart daemon and retry once more
				 */
				if ((errno == EBADF || errno == ENOENT) &&
				    (retry == RETRY_DAEMON_RESTART) ||
				    ((retry % RETRY_DAEMON_INTERVAL) == 0)) {
					(void) system1(
					    DEVFSADMD_START_PATH,
					    DEVFSADMD_START);
				}
				if (retry == RETRY_MSG_THRESHOLD) {
					syslog(LOG_ERR, DELIVERY_FAILED);
					msg_emitted = 1;
				}
				(void) sleep(1);
				++retry;
				continue;
			}

			/*
			 * Event delivered: remove from queue
			 * and reset delivery retry state.
			 */
			if (msg_emitted) {
				syslog(LOG_ERR, DELIVERY_RESUMED);
				msg_emitted = 0;
			}
			retry = 0;
			(void) mutex_lock(&evq_lock);
			if (eventq_head != NULL) {
				eventq_head = eventq_head->evq_next;
				if (eventq_head == NULL)
					eventq_tail = NULL;
			}
			free(evqp->evq_ev);
			free(evqp);
			evqp = eventq_head;
		}
		if (cleanup) {
			(void) cond_signal(&evq_cv);
			(void) mutex_unlock(&evq_lock);
			return;
		}
	}

	/* NOTREACHED */
}

struct slm_mod_ops *
slm_init()
{
	char alt_door[MAXPATHLEN];

	if (strcmp(root_dir, "") == 0) {
		/* Initialize the private sysevent handle */
		sysevent_hp = sysevent_open_channel_alt(DEVFSADM_SERVICE_DOOR);
	} else {

		/* Try alternate door during install time */
		if (snprintf(alt_door, MAXPATHLEN, "%s%s", "/tmp",
		    DEVFSADM_SERVICE_DOOR) >= MAXPATHLEN)
			return (NULL);

		sysevent_hp = sysevent_open_channel_alt(alt_door);
		use_alt_root = 1;
	}
	if (sysevent_hp == NULL) {
		syseventd_print(0, "Unable to allocate sysevent handle"
		    " for devfsadm module\n");
		return (NULL);
	}

	if (sysevent_bind_publisher(sysevent_hp) != 0) {
		if (errno == EBUSY) {
			sysevent_cleanup_publishers(sysevent_hp);
			if (sysevent_bind_publisher(sysevent_hp) != 0) {
				(void) sysevent_close_channel(sysevent_hp);
				return (NULL);
			}
		}
	}

	sysevent_cleanup_subscribers(sysevent_hp);
	cleanup = 0;
	eventq_head = NULL;
	eventq_tail = NULL;

	(void) mutex_init(&evq_lock, USYNC_THREAD, NULL);
	(void) cond_init(&evq_cv, USYNC_THREAD, NULL);

	if (thr_create(NULL, 0, (void *(*)(void *))devfsadmd_deliver_thr,
	    NULL, THR_BOUND, &deliver_thr_id) != 0) {
		(void) mutex_destroy(&evq_lock);
		(void) cond_destroy(&evq_cv);
		sysevent_close_channel(sysevent_hp);
		return (NULL);
	}

	return (&devfsadm_mod_ops);
}

void
slm_fini()
{
	/* Wait for all events to be flushed out to devfsadmd */
	(void) mutex_lock(&evq_lock);
	cleanup = 1;
	(void) cond_signal(&evq_cv);
	(void) cond_wait(&evq_cv, &evq_lock);
	(void) mutex_unlock(&evq_lock);

	/* Wait for delivery thread to exit */
	(void) thr_join(deliver_thr_id, NULL, NULL);

	(void) mutex_destroy(&evq_lock);
	(void) cond_destroy(&evq_cv);

	sysevent_close_channel(sysevent_hp);
	sysevent_hp = NULL;
}
