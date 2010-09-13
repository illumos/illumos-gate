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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <syslog.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Implementation of event notification mechanism used by the GUI and
 * nwamadm.  Clients register for events via nwam_events_init() and
 * unregister via nwam_events_fini().  nwamd sends events via nwam_event_send()
 * and applications block waiting for a new event to be delivered in
 * nwam_event_wait().  Events are implemented as System V message queues,
 * one per event client.  The event mechanism has to be resilient to
 * nwamd restarts so that clients do not lose the event connection.
 */

#define	NWAM_EVENT_MSG_DIR		"/etc/svc/volatile/nwam/"
#define	NWAM_EVENT_MSG_FILE		"nwam_event_msgs"
#define	NWAM_EVENT_MSG_FILE_PREFIX	NWAM_EVENT_MSG_DIR NWAM_EVENT_MSG_FILE
#define	NWAM_EVENT_MAX_SIZE		(sizeof (struct nwam_event) + \
	(NWAMD_MAX_NUM_WLANS * sizeof (nwam_wlan_t)))
#define	NWAM_EVENT_WAIT_TIME		10
#define	NWAM_EVENT_MAX_NUM_PENDING	25

/*
 * This is protecting simultaneous access to the msqid and its configuration.
 */
static pthread_mutex_t event_mutex = PTHREAD_MUTEX_INITIALIZER;
static int event_msqid = -1;

static nwam_error_t
nwam_event_alloc(nwam_event_t *eventp)
{
	assert(eventp != NULL);

	*eventp = calloc(1, NWAM_EVENT_MAX_SIZE);
	if (*eventp == NULL)
		return (NWAM_NO_MEMORY);
	return (NWAM_SUCCESS);
}

void
nwam_event_free(nwam_event_t event)
{
	if (event != NULL)
		free(event);
}

/*
 * Get next event in queue.
 */
nwam_error_t
nwam_event_wait(nwam_event_t *eventp)
{
	nwam_error_t err;
	nwam_event_t event;

	assert(eventp != NULL);

	if ((err = nwam_event_alloc(&event)) != NWAM_SUCCESS)
		return (err);
	while (msgrcv(event_msqid, (struct msgbuf *)event, NWAM_EVENT_MAX_SIZE,
	    0, 0) == -1) {
		switch (errno) {
			case EAGAIN:
			case EBUSY:
				/*
				 * We see this errno eventhough it isn't
				 * documented.  Try again.  If this causes
				 * a busy loop then grab a trace otherwise
				 * it's a brace 'til we can figure out why it
				 * happens.
				 */
				continue;

			default:
				nwam_event_free(event);
				return (nwam_errno_to_nwam_error(errno));
		}
	}

	/* Resize event down from maximum size */
	if ((*eventp = realloc(event, event->nwe_size)) == NULL)
		return (NWAM_NO_MEMORY);

	return (NWAM_SUCCESS);
}

/*
 * Register for receipt of events from nwamd.  Event delivery is
 * done via a System V message queue.
 */
nwam_error_t
nwam_events_init(void)
{
	char eventmsgfile[MAXPATHLEN];
	nwam_error_t err;
	nwam_error_t rc = NWAM_SUCCESS;
	key_t key;

	(void) snprintf(eventmsgfile, sizeof (eventmsgfile), "%s.%d",
	    NWAM_EVENT_MSG_FILE_PREFIX, getpid());

	(void) pthread_mutex_lock(&event_mutex);

	if (event_msqid != -1) {
		rc = NWAM_ENTITY_IN_USE;
		goto exit;
	}

	if ((err = nwam_request_register_unregister
	    (NWAM_REQUEST_TYPE_EVENT_REGISTER, eventmsgfile)) != NWAM_SUCCESS) {
		rc = err;
		goto exit;
	}

	if ((key = ftok(eventmsgfile, 0)) == -1) {
		rc = nwam_errno_to_nwam_error(errno);
		goto exit;
	}

	/* Get system-wide message queue ID */
	if ((event_msqid = msgget(key, 0444)) == -1) {
		rc = nwam_errno_to_nwam_error(errno);
		goto exit;
	}

exit:
	(void) pthread_mutex_unlock(&event_mutex);

	return (rc);
}

/*
 * Un-register for receipt of events from nwamd.  Make a request to nwamd
 * to destroy the message queue.
 */
void
nwam_events_fini(void)
{
	char eventmsgfile[MAXPATHLEN];

	(void) snprintf(eventmsgfile, sizeof (eventmsgfile), "%s.%d",
	    NWAM_EVENT_MSG_FILE_PREFIX, getpid());

	(void) pthread_mutex_lock(&event_mutex);

	(void) nwam_request_register_unregister
	    (NWAM_REQUEST_TYPE_EVENT_UNREGISTER, eventmsgfile);

	event_msqid = -1;

	(void) pthread_mutex_unlock(&event_mutex);
}

/*
 * Create an event queue.  Called by nwamd to create System V message queues
 * for clients to listen for events.
 */
nwam_error_t
nwam_event_queue_init(const char *eventmsgfile)
{
	int fd;
	key_t key;

	if ((fd = open(eventmsgfile, O_RDWR | O_CREAT | O_TRUNC, 0644)) == -1)
		return (nwam_errno_to_nwam_error(errno));
	(void) close(fd);

	if ((key = ftok(eventmsgfile, 0)) == -1)
		return (nwam_errno_to_nwam_error(errno));

	if (msgget(key, 0644 | IPC_CREAT) == -1)
		return (nwam_errno_to_nwam_error(errno));

	return (NWAM_SUCCESS);
}

/*
 * Send event to registered listeners via the set of registered System V
 * message queues.
 */
nwam_error_t
nwam_event_send(nwam_event_t event)
{
	DIR *dirp;
	struct dirent *dp;
	struct msqid_ds buf;
	key_t key;
	int msqid;
	char eventmsgfile[MAXPATHLEN];
	nwam_error_t err = NWAM_SUCCESS;

	if ((dirp = opendir(NWAM_EVENT_MSG_DIR)) == NULL) {
		return (nwam_errno_to_nwam_error(errno));
	}

	/*
	 * For each file matching our event message queue file prefix,
	 * check the queue is still being read, and if so send the message.
	 */
	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp(dp->d_name, NWAM_EVENT_MSG_FILE,
		    strlen(NWAM_EVENT_MSG_FILE)) != 0)
			continue;

		(void) snprintf(eventmsgfile, sizeof (eventmsgfile), "%s/%s",
		    NWAM_EVENT_MSG_DIR, dp->d_name);

		if ((key = ftok(eventmsgfile, 0)) == -1) {
			int errno_save = errno;
			syslog(LOG_INFO, "nwam_event_send: ftok: %s",
			    strerror(errno_save));
			err = nwam_errno_to_nwam_error(errno_save);
			continue;
		}

		if ((msqid = msgget(key, 0644)) == -1) {
			int errno_save = errno;
			syslog(LOG_INFO, "nwam_event_send: msgget: %s",
			    strerror(errno_save));
			err = nwam_errno_to_nwam_error(errno_save);
			continue;
		}

		/* Retrieve stats to analyse queue activity */
		if (msgctl(msqid, IPC_STAT, &buf) == -1) {
			int errno_save = errno;
			syslog(LOG_INFO, "nwam_event_send: msgctl: %s",
			    strerror(errno_save));
			err = nwam_errno_to_nwam_error(errno_save);
			continue;
		}
		/*
		 * If buf.msg_qnum > NWAM_EVENT_MAX_NUM_PENDING
		 * _and_ msg_stime is more than 10s after msg_rtime -
		 * indicating message(s) have been hanging around unclaimed -
		 * we destroy the queue as the client has most likely gone
		 * away. This can happen if a registered client hits Ctrl^C.
		 */
		if (buf.msg_qnum > NWAM_EVENT_MAX_NUM_PENDING &&
		    ((buf.msg_stime + NWAM_EVENT_WAIT_TIME) > buf.msg_rtime)) {
			nwam_event_queue_fini(eventmsgfile);
			continue;
		}

		/*
		 * This shouldn't ever block.  If it does then log an error and
		 * clean up the queue.
		 */
		if (msgsnd(msqid, (struct msgbuf *)event, event->nwe_size,
		    IPC_NOWAIT) == -1) {
			int errno_save = errno;
			syslog(LOG_ERR, "nwam_event_send: msgsnd: %s, "
			    "destroying message queue %s", strerror(errno_save),
			    eventmsgfile);
			nwam_event_queue_fini(eventmsgfile);
			err = nwam_errno_to_nwam_error(errno_save);
			continue;
		}

	}
	(void) closedir(dirp);

	return (err);
}

/*
 * Destroy an event queue.  Called by nwamd to destroy the associated message
 * queue.
 */
void
nwam_event_queue_fini(const char *eventmsgfile)
{
	key_t key;
	int msqid;

	if ((key = ftok(eventmsgfile, 0)) != -1 &&
	    (msqid = msgget(key, 0644)) != -1 &&
	    msgctl(msqid, IPC_RMID, NULL) != -1)
		(void) unlink(eventmsgfile);
}

/*
 * Stop sending events.  Called by nwamd to destroy each System V message queue
 * registered.
 */
void
nwam_event_send_fini(void)
{
	DIR *dirp;
	struct dirent *dp;
	char eventmsgfile[MAXPATHLEN];

	(void) pthread_mutex_lock(&event_mutex);

	if ((dirp = opendir(NWAM_EVENT_MSG_DIR)) == NULL) {
		(void) pthread_mutex_unlock(&event_mutex);
		return;
	}

	/*
	 * For each file matching our event message queue file prefix,
	 * destroy the queue and message file.
	 */
	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp(dp->d_name, NWAM_EVENT_MSG_FILE,
		    strlen(NWAM_EVENT_MSG_FILE)) != 0)
			continue;

		(void) snprintf(eventmsgfile, sizeof (eventmsgfile), "%s/%s",
		    NWAM_EVENT_MSG_DIR, dp->d_name);

		nwam_event_queue_fini(eventmsgfile);
	}
	(void) pthread_mutex_unlock(&event_mutex);
}
