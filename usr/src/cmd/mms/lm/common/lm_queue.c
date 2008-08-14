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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <pthread.h>
#include <time.h>
#include "lm.h"
#include <lm_proto.h>

static void *lm_q_worker(void *arg);

static	char	*_SrcFile = __FILE__;

/*
 *
 * lm_queue_init()
 *
 * Parameters:
 *	- cq		Ptr to main work queue structure used for processing
 *			the LMPM commands.
 *	- threads:	The number of worker threads that can be started
 *	- worker:	The routine that is to be used to process items
 *			on the work queue. In LM that is lm_cmd_handler
 *
 * Globals:
 *	None
 *
 * Initialize a work queue objects that are going to be used by LM to process
 * commands sent to it by the MM.
 *
 * Return Values:
 *	LM_OK:		If function compelete cleanly
 *	LM_ERROR:	If an error was encountered during the queue init.
 *
 */

int
lm_queue_init(lm_queue_t *cq, int threads, void (*worker)(void *arg))
{

	if (pthread_attr_init(&cq->lmq_attr) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_init: attr_init failed, errno - "
		    "%s", strerror(errno));
		return (LM_ERROR);
	}
	if (pthread_attr_setdetachstate(&cq->lmq_attr,
	    PTHREAD_CREATE_DETACHED) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_init: setdetachstate failed, "
		    "errno - %s", strerror(errno));
		(void) pthread_attr_destroy(&cq->lmq_attr);
		return (LM_ERROR);
	}

	if (pthread_mutex_init(&cq->lmq_mutex, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_init: mutex_init failed, errno - "
		    "%s", strerror(errno));
		(void) pthread_attr_destroy(&cq->lmq_attr);
		return (LM_ERROR);
	}

	if (pthread_cond_init(&cq->lmq_cv, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_init: cond_init failed, errno - "
		    "%s", strerror(errno));
		(void) pthread_mutex_destroy(&cq->lmq_mutex);
		(void) pthread_attr_destroy(&cq->lmq_attr);
		return (LM_ERROR);
	}

	cq->lmq_quit = 0;
	cq->lmq_first = cq->lmq_last = NULL;
	cq->lmq_parallel = threads;
	cq->lmq_counter = cq->lmq_idle = 0;
	cq->lmq_worker = worker;
	return (LM_OK);
}

/*
 *
 * lm_queue_clean()
 *
 * Parameters:
 *
 * Globals:
 *
 * This function will go through the work queue and delete all commands
 * that are pending. It will send a error final response for the commands
 * with an error code of abort. This function is used when LM is told to
 * disable, reset, or exit.
 *
 * Return Values:
 *
 */
void
lm_queue_clean()
{
	char	msg_str[256];
	char	rsp_str[512];

	lm_queue_ele_t	*ce;
	lm_queue_t	*cq = &lm_cmdq;

	mms_trace(MMS_DEVP, "Entering lm_queue_clean");

	if (pthread_mutex_lock(&cq->lmq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_clean: mutex_lock failed, errno - "
		    "%s", strerror(errno));
		return;
	}

	while (cq->lmq_first != NULL) {
		ce = cq->lmq_first;
		cq->lmq_first = ce->lmqe_next;
		if (cq->lmq_last == ce)
			cq->lmq_last = NULL;
			/* Events and internal commands do not get final */
			/* response sent to MM, just skip and ignore */
		if (ce->lmqe_cindex == LM_C_EVENT ||
		    ce->lmqe_cindex == LM_C_INTERNAL) {
			mms_trace(MMS_DEBUG,
			    "lm_queue_clean: %s command does not "
			    "need to be aborted",
			    lm_cmdData[ce->lmqe_cindex].cmd);
			mms_pn_destroy(ce->lmqe_cmd_tree);
			free(ce);
			continue;
		}
		mms_trace(MMS_DEBUG, "lm_queue_clean: Aborting %s command",
		    lm_cmdData[ce->lmqe_cindex].cmd);
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7027_MSG,
		    lm_cmdData[ce->lmqe_cindex].cmd,
		    lm_cmdData[ce->lmqe_cindex].cmd);
		(void) snprintf(rsp_str, sizeof (rsp_str),
		    LM_ERR_FINAL, ce->lmqe_tid,
		    mms_sym_code_to_str(MMS_INTERNAL),
		    mms_sym_code_to_str(MMS_LM_E_DEVCMDABORT), msg_str);
		mms_trace(MMS_OPER,
		    "lm_queue_clean: %s command was aborted, final "
		    "response:\n%s", lm_cmdData[ce->lmqe_cindex].cmd, rsp_str);
		if (lm_write_msg(rsp_str, &lm.lm_mms_conn, lm_write_mutex)) {
			lm_serr(MMS_CRIT, "lm_queue_clean: Sending final "
			    "response for %s command failed",
			    lm_cmdData[ce->lmqe_cindex].cmd);
			return;
		}
		mms_pn_destroy(ce->lmqe_cmd_tree);
		free(ce);
	}

	if (pthread_mutex_unlock(&cq->lmq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_clean: mutex_unlock "
		    "failed, errno - %s", strerror(errno));
	}

	mms_trace(MMS_DEVP, "Exiting lm_queue_clean");
}

/*
 *
 * lm_queue_add()
 *
 * Parameters:
 *	cq	Ptr to main work queue structure used for processing the
 *		LMPM commands.
 *	cmd	Pointer to parse tree of the LMPM command that is to be
 *		processed by one of the worker threads.
 *	tid	The task id of the LMPM command being added to work queue.
 *	index	The index into the lm_cmdData[] of the LMPM command
 *
 * Globals:
 *	None
 *
 * This functions adds the cmd to the work queue. It also determines if
 * a worker thread is available to processes the cmd. If no worker threads
 * can process the cmd and another worker thread can be started, the
 * function will start another worker thread.
 *
 * Return Values:
 *	LM_OK:		If function compelete cleanly
 *	LM_ERROR:	If an error was encountered during adding the cmd
 *			to the work queue.
 *
 */

int
lm_queue_add(lm_queue_t *cq, void *cmd, char **tid, int index)
{

	lm_queue_ele_t *item;
	pthread_t id;

	if ((item = (lm_queue_ele_t *)malloc(sizeof (lm_queue_ele_t)))
	    == NULL) {
		lm_serr(MMS_CRIT, "lm_queue_add: malloc failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

	item->lmqe_cindex = index;
	if (*tid == NULL)
		item->lmqe_tid = NULL;
	else
		item->lmqe_tid = *tid;
	item->lmqe_cmd_tree = cmd;
	item->lmqe_next = NULL;
	if (pthread_mutex_init(&item->lmqe_mutex, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_add: mutex_init failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}
	if (pthread_cond_init(&item->lmqe_rv, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_add: cond_init failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}
	if (pthread_mutex_lock(&cq->lmq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_add: mutex_lock failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

	/*
	 * Add the command to the end of the queue
	 */
	if (cq->lmq_first == NULL)
		cq->lmq_first = item;
	else
		cq->lmq_last->lmqe_next = item;
	cq->lmq_last = item;

	/* If any threads are idle, wake them up, or if allowed start a */
	/* new worker thread */

	if (cq->lmq_idle > 0) {
			/* A thread is idle, wake it up to handle cmd */
		mms_trace(MMS_DEBUG, "lm_queue_add: Waking up idle thread to "
		    "handle new command");
		if (pthread_cond_signal(&cq->lmq_cv) != 0) {
			lm_serr(MMS_CRIT, "lm_queue_add: cond_signal failed "
			    "errno - %s", strerror(errno));
			(void) pthread_mutex_unlock(&cq->lmq_mutex);
			return (LM_ERROR);
		}
	} else if (cq->lmq_counter < cq->lmq_parallel) {
			/* Create new thread to handle cmd */
		mms_trace(MMS_DEBUG,
		    "lm_queue_add: Creating new command processing "
		    "thread");
		if (pthread_create(&id, &cq->lmq_attr, lm_q_worker,
		    (void *)cq) != 0) {
			lm_serr(MMS_CRIT, "lm_queue_add: thread_create failed, "
			    "errno - %s", strerror(errno));
			(void) pthread_mutex_unlock(&cq->lmq_mutex);
			return (LM_ERROR);
		}
		cq->lmq_counter++;
	}
	if (pthread_mutex_unlock(&cq->lmq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_queue_add: mutex_unlock failed, errno - "
		    "%s", strerror(errno));
		return (LM_ERROR);
	}

	return (LM_OK);
}

/*
 *
 * lm_q_worker()
 *
 * Parameters:
 *	- arg		Ptr to main work queue structure used for processing
 *			the LMPM commands.
 *
 * Globals:
 *	None
 *
 * This function is the wrapper that pulls the command off the work queue
 * and then calls the actual function lm_cmd_handler() to process the command.
 * This routine takes care of the thread processing part of the command
 * processing so that the actual command processor does not need to worry
 * about how it got the command.
 *
 * Return Values:
 *	NULL:		If function compelete cleanly
 *	NULL:		If an error was encountered during processing.
 *
 */

static void *
lm_q_worker(void *arg)
{

	int rc;
	int timedout;

	struct timespec timeout;

	lm_queue_t *cq = (lm_queue_t *)arg;
	lm_queue_ele_t *ce;

	mms_trace(MMS_DEVP, "lm_q_worker: New worker thread starting");

	if (pthread_mutex_lock(&cq->lmq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_q_worker: mutex_lock failed, errno - "
		    "%s", strerror(errno));
		return ((void *)NULL);
	}

	/* LINTED constant in conditional context */
	while (1) {
		timedout = 0;
		mms_trace(MMS_DEBUG,
		    "lm_q_worker: Worker thread looking for work");
		(void) clock_gettime(CLOCK_REALTIME, &timeout);
		timeout.tv_sec += 5;

		while (cq->lmq_first == NULL && !cq->lmq_quit) {
			mms_trace(MMS_DEBUG,
			    "lm_q_worker: Worker thread waiting on "
			    "work");
			cq->lmq_idle++;
			rc = pthread_cond_timedwait(&cq->lmq_cv,
			    &cq->lmq_mutex, &timeout);
			cq->lmq_idle--;
			if (rc == ETIMEDOUT) {
				mms_trace(MMS_DEBUG,
				    "lm_q_worker: Worker thread "
				    "waiting for work timed out");
				timedout = 1;
				break;
			} else if (rc != 0) {
				mms_trace(MMS_ERR, "lm_q_worker: Worker thread "
				    "failed, %d", rc);
				cq->lmq_counter--;
				if ((pthread_mutex_unlock(&cq->lmq_mutex))
				    != 0)
					lm_serr(MMS_CRIT, "lm_q_worker: "
					    "unlock failed, errno - %s",
					    strerror(errno));
				return ((void *)NULL);
			} else {
				mms_trace(MMS_DEBUG,
				    "lm_q_worker: Worker thread "
				    "woke up to handle work");
			}
		}

		mms_trace(MMS_DEBUG, "lm_q_worker: Queue: %#lx, quit: %d",
		    cq->lmq_first, cq->lmq_quit);
		ce = cq->lmq_first;
		if (ce != NULL) {
			cq->lmq_first = ce->lmqe_next;
			if (cq->lmq_last == ce)
				cq->lmq_last = NULL;
			if (pthread_mutex_unlock(&cq->lmq_mutex) != 0) {
				lm_serr(MMS_CRIT, "lm_q_worker: mutex_unlock "
				    "failed, errno - %s", strerror(errno));
				return ((void *)NULL);
			}
			mms_trace(MMS_DEBUG,
			    "lm_q_worker: Worker thread calling "
			    "cmd processing routine");
			cq->lmq_worker(ce);
			free(ce);
			if (pthread_mutex_lock(&cq->lmq_mutex) != 0) {
				lm_serr(MMS_CRIT, "lm_q_worker: mutex_lock "
				    "failed, errno - %s",
				    strerror(errno));
				return ((void *)NULL);
			}
		}

		if (cq->lmq_first == NULL && cq->lmq_quit) {
			mms_trace(MMS_DEBUG,
			    "lm_q_worker: Worker thread shutting "
			    "down");
			cq->lmq_counter--;
			if (cq->lmq_counter == 0)
				if (pthread_cond_broadcast(&cq->lmq_cv)
				    != 0)
					lm_serr(MMS_CRIT, "lm_q_worker: "
					    "cond_broadcast failed, "
					    "errno - %s", strerror(errno));
			if (pthread_mutex_unlock(&cq->lmq_mutex) != 0)
				lm_serr(MMS_CRIT, "lm_q_worker: mutex_unlock "
				    "failed, errno - %s", strerror(errno));
			return ((void *)NULL);
		}

		if (cq->lmq_first == NULL && timedout) {
			mms_trace(MMS_DEBUG, "lm_q_worker: Worker thread "
			    "terminating due to timeout being reached");
			cq->lmq_counter--;
			break;
		}
	}

	if (pthread_mutex_unlock(&cq->lmq_mutex) != 0)
		lm_serr(MMS_CRIT,
		    "lm_q_worker: mutex_unlock failed, errno - %s",
		    strerror(errno));

	mms_trace(MMS_DEVP, "lm_q_worker: Worker thread exiting");
	return ((void *)NULL);
}
