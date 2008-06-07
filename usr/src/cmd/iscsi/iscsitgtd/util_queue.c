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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <syslog.h>
#include <synch.h>
#include <time.h>
#include <umem.h>

#include "queue.h"
#include "iscsi_conn.h"
#include "utility.h"
#include "target.h"
#include "t10.h"

/*
 * Constants
 */
static const timespec_t usec = {0, 1000};

FILE *qlog = NULL;
int qlog_lvl = 0;

pthread_mutex_t q_mutex;
int queue_num;

void
queue_init()
{
	(void) pthread_mutex_init(&q_mutex, NULL);
	queue_log(True);
}

target_queue_t *
queue_alloc()
{
	target_queue_t	*q =
	    (target_queue_t *)calloc(1, sizeof (target_queue_t));

	if (q == NULL)
		return (NULL);

	(void) pthread_mutex_lock(&q_mutex);
	q->q_num = queue_num++;
	(void) pthread_mutex_unlock(&q_mutex);

	(void) sema_init(&q->q_sema, 0, USYNC_THREAD, NULL);
	(void) pthread_mutex_init(&q->q_mutex, NULL);

	return (q);
}

void
queue_log(Boolean_t on)
{
	(void) pthread_mutex_lock(&q_mutex);
	if ((on == True) && (qlog == NULL) && (qlog_lvl != 0)) {
		qlog = fopen(target_log, "ab");
	} else if ((on == False) && (qlog != NULL)) {
		(void) fclose(qlog);
		qlog = NULL;
	}
	(void) pthread_mutex_unlock(&q_mutex);
}

/*
 * []----
 * | queue_message_set -- add a given message to the queue.
 * []----
 */
void
queue_message_set(target_queue_t *q, uint32_t lvl, msg_type_t type,
    void *data)
{
	msg_t	*msg;

	if ((msg = umem_cache_alloc(queue_cache, 0)) == NULL)
		return;

	bzero(msg, sizeof (*msg));
	msg->msg_pri_level	= lvl;
	msg->msg_type		= type;
	msg->msg_data		= data;

	(void) pthread_mutex_lock(&q->q_mutex);

	if (q->q_head == NULL) {
		q->q_head = msg;
		assert(q->q_tail == NULL);
		q->q_tail = msg;
	} else if (lvl & Q_HIGH) {
		msg->msg_next = q->q_head;
		q->q_head->msg_prev = msg;
		q->q_head = msg;
	} else {
		q->q_tail->msg_next = msg;
		msg->msg_prev = q->q_tail;
		q->q_tail = msg;
	}

	(void) pthread_mutex_unlock(&q->q_mutex);

	(void) sema_post(&q->q_sema);
}

/*
 * []----
 * | queue_message_get -- retrieve the first message in the queue
 * []----
 */
msg_t *
queue_message_get(target_queue_t *q)
{
	msg_t *m;

	while (sema_wait(&q->q_sema) == -1)
		(void) nanosleep(&usec, 0);
	(void) pthread_mutex_lock(&q->q_mutex);
	m = q->q_head;
	if (m == NULL) {
		assert(q->q_tail == NULL);
		(void) pthread_mutex_unlock(&q->q_mutex);
		return (NULL);
	}
	q->q_head = m->msg_next;
	if (q->q_head == NULL)
		q->q_tail = NULL;
	(void) pthread_mutex_unlock(&q->q_mutex);

	return (m);
}

/*
 * []----
 * | queue_message_try_get -- see if there's a message available
 * []----
 */
msg_t *
queue_message_try_get(target_queue_t *q)
{
	msg_t	*m;

	if (sema_trywait(&q->q_sema) != 0)
		return (NULL);
	(void) pthread_mutex_lock(&q->q_mutex);
	m = q->q_head;
	q->q_head = m->msg_next;
	if (q->q_head == NULL)
		q->q_tail = NULL;
	(void) pthread_mutex_unlock(&q->q_mutex);

	return (m);
}

/*
 * []----
 * | queue_walker_free -- Run through a queue and free certain messages.
 * |
 * | Users of the queues should not walk the queue structure themselves
 * | unless they also need to grab the lock. To prevent that level of
 * | knowledge of the queue structures this method is provided to enable
 * | other subsystems to walk the queue looking for messages which need
 * | to be deleted.
 * []----
 */
void
queue_walker_free(target_queue_t *q, Boolean_t (*func)(msg_t *m, void *v),
    void *v1)
{
	msg_t	*m;		/* current working message */
	msg_t	*n;		/* next message */

	(void) pthread_mutex_lock(&q->q_mutex);
	m = q->q_head;
	while (m) {
		if ((*func)(m, v1) == True) {
			if (m == q->q_head) {
				q->q_head = m->msg_next;
				if (m->msg_next == NULL)
					q->q_tail = NULL;
				else
					m->msg_next->msg_prev = NULL;
			} else {
				m->msg_prev->msg_next = m->msg_next;
				if (m->msg_next == NULL)
					q->q_tail = m->msg_prev;
				else
					m->msg_next->msg_prev = m->msg_prev;
			}
			n = m->msg_next;
			queue_message_free(m);
			m = n;
		} else {
			m = m->msg_next;
		}
	}
	(void) pthread_mutex_unlock(&q->q_mutex);
}

/*
 * []----
 * | queue_reset -- Flush a queue of all command messages messages.
 * []----
 */
void
queue_reset(target_queue_t *q)
{
	msg_t	*m;
	msg_t	*n;

	(void) pthread_mutex_lock(&q->q_mutex);
	m = q->q_head;
	while (m != NULL) {

		switch (m->msg_type) {
		case msg_cmd_data_out:
		case msg_cmd_send:
			if (m == q->q_head) {
				q->q_head = m->msg_next;
				if (m->msg_next == NULL)
					q->q_tail = NULL;
				else
					m->msg_next->msg_prev = NULL;
			} else {
				assert(m->msg_prev != NULL);
				m->msg_prev->msg_next = m->msg_next;
				if (m->msg_next == NULL)
					q->q_tail = m->msg_prev;
				else
					m->msg_next->msg_prev = m->msg_prev;
			}
			n = m->msg_next;
			queue_message_free(m);
			m = n;
			(void) sema_wait(&q->q_sema);
			break;

		case msg_reset_lu:
		case msg_shutdown:
		case msg_lu_add:
		case msg_lu_remove:
		case msg_lu_online:
		case msg_thick_provo:
			/*
			 * Don't flush the control messages
			 */
			m = m->msg_next;
			break;

		default:
			queue_prt(mgmtq, Q_STE_ERRS,
			    "---- Unexpected msg type %d ----", m->msg_type);
			m = m->msg_next;
			break;
		}
	}

	(void) pthread_mutex_unlock(&q->q_mutex);
}

void
queue_message_free(msg_t *m)
{
	umem_cache_free(queue_cache, m);
}

/*
 * []----
 * | queue_free -- free resources used by queue structure
 * []----
 */
void
queue_free(target_queue_t *q, void (*free_func)(msg_t *))
{
	msg_t	*m;
	msg_t	*n;

	(void) pthread_mutex_lock(&q->q_mutex);
	m = q->q_head;
	while (m != NULL) {
		if (free_func != NULL)
			(*free_func)(m);
		n = m->msg_next;
		queue_message_free(m);
		m = n;
	}
	(void) pthread_mutex_unlock(&q->q_mutex);

	(void) pthread_mutex_destroy(&q->q_mutex);
	(void) sema_destroy(&q->q_sema);
	free(q);
}

void
queue_prt(target_queue_t *q, int type, char *fmt, ...)
{
	va_list		ap;
	char		buf[80];

	va_start(ap, fmt);
	/* LINTED variable format specifier */
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	queue_str(q, type, msg_log, buf);
	va_end(ap);
}

/*
 * []----
 * | queue_str -- helper function which sends a string to the queue
 * []----
 */
void
queue_str(target_queue_t *q, uint32_t lvl, msg_type_t type, char *fmt)
{
	int		len;
	char		*m;
	hrtime_t	h	= gethrtime();
	hrtime_t	delta;
	static hrtime_t	last_h	= 0;
	time_t		tval = time((time_t *)0);
	char		debug[80];

	(void) pthread_mutex_lock(&q_mutex);
	if ((qlog) && (qlog_lvl & lvl)) {
		(void) ctime_r(&tval, debug, sizeof (debug));
		(void) fprintf(qlog, "%s %s", debug, fmt);
		(void) fflush(qlog);
	}
	(void) pthread_mutex_unlock(&q_mutex);

	if ((dbg_timestamps == True) && (lvl != 0) && ((lvl & Q_HIGH) == 0)) {
		len	= strlen(fmt) + 12;
		m	= malloc(len);
		delta	= h - last_h;
		last_h	= h;
		(void) snprintf(m, len, "%9.3f %s",
		    (double)delta / (double)1000000.0, fmt);
		queue_message_set(q, lvl, type, (void *)m);
	} else {
		len	= strlen(fmt) + 1;
		m	= malloc(len);
		(void) strncpy(m, fmt, len);
		queue_message_set(q, lvl, type, (void *)m);
	}
}

/*
 * []------------------------------------------------------------------[]
 * | Specialized free routines for queue data.				|
 * | It is possible for a shutdown to start because the STE thread	|
 * | receives an error while reading from the socket. If at the same	|
 * | time the connection poll thread is processing a PDU it could place	|
 * | a msg_ste_datain package on the STE queue. When the STE hits the	|
 * | shutdown message first it will exit and we need to clean up	|
 * | anything on that queue which means freeing memory in the		|
 * | appropriate manner. This is just one example and there are several	|
 * | others. Another method to deal with this would be to have a closed	|
 * | flag such that any futher calls to queue_message_set would return	|
 * | an error. This would require any calls to queue_message_set() deal	|
 * | with this condition. The approach used here seems cleaner.		|
 * | The drawback to this approach is that if any new messages are	|
 * | added then the developer had better add it to these routines as	|
 * | appropriate.							|
 * []------------------------------------------------------------------[]
 */

/*
 * []----
 * | sess_queue_data_remove -- free any message data left on the sess queue
 * |
 * | XXX This should be recoded so that we're doing the cleanup within
 * | the session code. Peal off any messages and deal with them there.
 * []----
 */
void
sess_queue_data_remove(msg_t *m)
{
	mgmt_request_t	*mq;
	char		**buf;

	syslog(LOG_ERR, "sess_queue_data: type %d", m->msg_type);
	switch (m->msg_type) {
	default:
		syslog(LOG_ERR, "Unknown session type data being free'd, %d",
		    m->msg_type);
		free(m->msg_data);
		break;

	case msg_shutdown:
	case msg_shutdown_rsp:
	case msg_ste_media_error:
		syslog(LOG_ERR, "Impossible message left in session queue"
		    " of type %d", m->msg_type);
		break;

	case msg_cmd_data_out:
		break;

	case msg_initiator_name:
	case msg_initiator_alias:
	case msg_target_name:
		free(((name_request_t *)m->msg_data)->nr_name);
		break;

	case msg_mgmt_rqst:
		mq = (mgmt_request_t *)m->msg_data;
		(void) pthread_mutex_lock(&mq->m_resp_mutex);
		tgt_buf_add(mq->m_u.m_resp, "queue_freed", NULL);
		(void) pthread_mutex_unlock(&mq->m_resp_mutex);
		queue_message_set(mq->m_q, 0, msg_mgmt_rply, 0);
		break;

	case msg_mgmt_rply:
		mq	= (mgmt_request_t *)m->msg_data;
		buf	= mq->m_u.m_resp;
		tgt_buf_add_tag(buf, XML_ELEMENT_STATS, Tag_End);
		tgt_buf_add_tag(buf, XML_ELEMENT_CONN, Tag_End);

		(void) pthread_mutex_unlock(&mq->m_resp_mutex);
		queue_message_set(mq->m_q, 0, msg_mgmt_rply, 0);
		break;

	case msg_reset_targ:
	case msg_reset_lu:
		/* ---- these are safe to ignore, no data to free ---- */
		break;
	}
}

/*
 * []----
 * | conn_queue_data_remove -- free any message data left on the conn queue
 * []----
 */
void
conn_queue_data_remove(msg_t *m)
{
	mgmt_request_t	*mq;

	syslog(LOG_ERR, "conn_queue_data: type %d", m->msg_type);
	switch (m->msg_type) {
	case msg_cmd_data_rqst:
	case msg_cmd_data_out:
	case msg_cmd_cmplt:
		syslog(LOG_ERR, "Free'ing data which should already be gone");
		free(m->msg_data);
		break;

	case msg_mgmt_rqst:
		mq = (mgmt_request_t *)m->msg_data;
		(void) pthread_mutex_lock(&mq->m_resp_mutex);
		if (mq->m_u.m_resp != NULL)
			tgt_buf_add(mq->m_u.m_resp, "queue_freed", NULL);
		(void) pthread_mutex_unlock(&mq->m_resp_mutex);
		queue_message_set(mq->m_q, 0, msg_mgmt_rply, 0);
		break;

	default:
		syslog(LOG_ERR, "Unknown connection message being free'd: %d",
		    m->msg_type);
		free(m->msg_data);
		break;
	}
}
