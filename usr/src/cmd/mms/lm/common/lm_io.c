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


#include "lm.h"
#include <lm_proto.h>

static char	*_SrcFile = __FILE__;

/*
 * lm_remove_lmpl_cmd
 *
 * Parameters:
 *	tid	The index into the response queue for the command being
 *		removed. A -1 value means that only the memory of ele is
 *		to be freed.
 *	ele	The structure which contains the information about the lmpl
 *		command being removed.
 *
 * Gloabals:
 *	None
 *
 * This functions cleans up the response queue which handles responses for
 * lmpl commands. Once the lmpl command has received its finial response
 * this functions is called to free up the memory associated with ele and
 * to open the index in the response queue associated with the task id of
 * the lmpl command. There is no lock around the updates, since we are
 * only removing an elements memory and setting the lm_rspq.rspq_cmd[tid]
 * to NULL.
 *
 * Return Values:
 *	None
 */
void
/* LINTED tid in lm_remove_lmpl_cmd (E_FUNC_ARG_UNUSED) */
lm_remove_lmpl_cmd(int tid, lmpl_rsp_ele_t *ele)
{
	lmpl_rsp_node_t	*node;
	lmpl_rsp_node_t	*next;

	if (ele == NULL) {
		return;
	}

	if (pthread_cond_destroy(&ele->lmpl_rsp_cv) != 0) {
		lm_serr(MMS_CRIT, "lm_remove_lmpl_cmd: Unable to free lmpl "
		    "command element's condition variable");
	}

	if (pthread_mutex_destroy(&ele->lmpl_rsp_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_remove_lmpl_cmd: Unable to free lmpl "
		    "command element's mutex");
	}

	if (ele->lmpl_acc_tree != NULL)
		mms_pn_destroy(ele->lmpl_acc_tree);

	mms_list_foreach_safe(&ele->lmpl_rsp_list, node, next) {
		mms_list_remove(&ele->lmpl_rsp_list, node);

		if (node->lmpl_rsp_tree != NULL)
			mms_pn_destroy(node->lmpl_rsp_tree);
		free(node);
	}
	free(ele);
}

/*
 * lm_obtain_task_id()
 *
 * Parameters:
 *	tid	Next available task id for a LMPL command.
 *	rele	Will be updated with the location of new element created for
 *		the lmpl command.
 *
 * This function obtains the necessary taskid for the cmd that is to
 * be generated. It sets up a ptr to the lm_queue_ele in the lm_rspq
 * based on the taskid as an index into lm_rspq.rspq_cmd array.
 *
 * Return Values:
 *   LM_OK	If it was able to obtain a taskid and lock the necessary
 *		mutexes.
 *   LM_ERROR	If it encountered an error while processing. All errors
 *		generate an internal processing error that are not
 *		currently recoverable from. Thus, any error encountered will
 *		set the global lm_internal_error indicating to LM that
 *		it should abort processing as quick as possible.
 *
 */
int
lm_obtain_task_id(int *tid, lmpl_rsp_ele_t **rele)
{

	lmpl_rsp_ele_t	*ele;

	if ((ele = (lmpl_rsp_ele_t *)malloc(sizeof (lmpl_rsp_ele_t)))
	    == NULL) {
		lm_serr(MMS_CRIT, "lm_obtain_task_id: Unable to malloc space "
		    "for a new lmpl command element, errno - %s",
		    strerror(errno));
		*rele = NULL;
		return (LM_ERROR);
	}

	if (pthread_mutex_init(&ele->lmpl_rsp_mutex, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_obtain_task_id: Unable to initialize new "
		    "lmpl command element's mutex, errno - %s",
		    strerror(errno));
		free(ele);
		*rele = NULL;
		return (LM_ERROR);
	}

	if (pthread_cond_init(&ele->lmpl_rsp_cv, NULL) != 0) {
		lm_serr(MMS_CRIT, "lm_obtain_task_id: Unable to initialize new "
		    "lmpl command element's condition variable, "
		    "errno - %s", strerror(errno));
		free(ele);
		*rele = NULL;
		if (pthread_mutex_destroy(&ele->lmpl_rsp_mutex) != 0) {
			mms_trace(MMS_CRIT,
			    "lm_obtain_task_id: Unable to free lmpl "
			    "command element's mutex, errno - %s",
			    strerror(errno));
		}
		return (LM_ERROR);
	}

	mms_list_create(&ele->lmpl_rsp_list, sizeof (lmpl_rsp_node_t),
	    offsetof(lmpl_rsp_node_t, lmpl_rsp_next));

	ele->lmpl_acc_tree = NULL;
	ele->lmpl_rsp_final = LMPL_WAITING;

		/* Lock the accept/unaccept mutex so that if any */
		/* any other cmd processing threads want to send */
		/* a cmd to MM they will block here until the last */
		/* thread that generated a cmd gets it's accept */
		/* unaccept response. */
	if (pthread_mutex_lock(&lm_acc_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_obtain_task_id: Lock of accept/unaccept "
		    "mutex failed with errno - %s", strerror(errno));
		lm_remove_lmpl_cmd(-1, ele);
		*rele = NULL;
		return (LM_ERROR);
	}

			/* Lock the response queue so that there is not */
			/* more than one thread updating information in the */
			/* queue at one time */

	if (pthread_mutex_lock(&lm_rspq.rspq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_obtain_task_id: Lock of response queue's "
		    "mutex failed with errno - %s", strerror(errno));
		if (pthread_mutex_unlock(&lm_acc_mutex) != 0)
			mms_trace(MMS_CRIT, "lm_obtain_task_id: Unlock of "
			    "accept/unaccept mutex failed with errno - "
			    "%s", strerror(errno));
		lm_remove_lmpl_cmd(-1, ele);
		*rele = NULL;
		return (LM_ERROR);
	}

			/* Update the response queue task id to the next */
			/* available one */
	if (++lm_rspq.rspq_tid == SIZE_RSP_ARRAY)
		lm_rspq.rspq_tid = 0;

			/* This is not an infinite loop because the */
			/* lm_remove_lmpl_cmd does not need the resp queue */
			/* mutex to free an element. Also, the number */
			/* of outstanding LMPL commands is equal to the */
			/* number of command processing threads, thus the */
			/* most outstanding is equal to the number of */
			/* processing threads and therefore there should */
			/* always be an available taskid */
	while (lm_rspq.rspq_cmd[lm_rspq.rspq_tid] != NULL) {
		if (lm_rspq.rspq_tid == SIZE_RSP_ARRAY)
			lm_rspq.rspq_tid = 0;
		else
			lm_rspq.rspq_tid++;
	}

	*tid = lm_rspq.rspq_tid;
	lm_rspq.rspq_cmd[lm_rspq.rspq_tid] = ele;

	*rele = ele;

	if (pthread_mutex_unlock(&lm_rspq.rspq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_obtain_task_id: Unlock of response "
		    "queue's mutex failed with errno - %s",
		    strerror(errno));
		if (pthread_mutex_unlock(&lm_acc_mutex) != 0)
			mms_trace(MMS_CRIT, "lm_obtain_task_id: Unlock of "
			    "accept/unaccept mutex failed with errno - "
			    "%s", strerror(errno));
		lm_remove_lmpl_cmd(lm_rspq.rspq_tid, ele);
		*rele = NULL;
		return (LM_ERROR);
	}

	return (LM_OK);
}

/*
 * lm_gen_lmpl_cmd
 *
 * Parameters:
 *	cmd_str	The LMPL command to send to MM.
 *	ele	The structure which contains the information about the lmpl
 *		command being being sent to MM.
 *	wait	Indicates if the LMPL command should only take this many
 *		seconds to process. If it takes longer than this many
 *		seconds, LM will send a LMPL cancel command to MM to
 *		try to cancel the original LMPL command.
 *
 * Gloabals:
 *	None
 *
 * This functions sends the LMPL command to MM and waits for an accept
 * response, and the final response to the command. Once the final
 * response is received, it returns the lmpl response in ele.
 *
 * Return Values:
 *	MMS_OK		If command was sent successfully and a valid response
 *			was received.
 *	MMS_ERROR	If an error was encountered while sending the command
 *			or receiving the response.
 */
int
lm_gen_lmpl_cmd(char *cmd_str, lmpl_rsp_ele_t *ele, int wait)
{
	int		rc;
	int		len;
	int		taskid;

	timespec_t 	tv;
	timespec_t 	*tvp;
	mms_par_node_t	*acc;

	taskid = lm_rspq.rspq_tid;
	len = strlen(cmd_str);

			/* Lock mutex to protect that only one thread is */
			/* sending information over the socket to MM at */
			/* one time */
	if ((rc = pthread_mutex_lock(&lm_write_mutex)) != 0) {
		lm_serr(MMS_CRIT,
		    "lm_gen_lmpl_cmd: Lock on write mutex failed, "
		    "errno - %s", strerror(errno));
		return (LM_ERROR);
	}
			/* Write out cmd to MM */
	mms_trace(MMS_DEVP,
	    "send to MM: \n%s",
	    cmd_str);
	if ((rc = mms_writer(&lm.lm_mms_conn, cmd_str)) != len) {
		lm_serr(MMS_CRIT, "lm_gen_lmpl_cmd: mms_writer failed, "
		    "errno - %s", strerror(errno));
		(void) pthread_mutex_unlock(&lm_write_mutex);
		return (LM_ERROR);
	}
			/* Unlock write mutex */
	if ((rc = pthread_mutex_unlock(&lm_write_mutex)) != 0) {
		lm_serr(MMS_CRIT, "lm_gen_lmpl_cmd: Unlock write mutex failed, "
		    "errno - %s", strerror(errno));
		return (LM_ERROR);
	}

			/* Go to sleep until accept or unaccept is returned */
	if ((rc = pthread_mutex_lock(&ele->lmpl_rsp_mutex)) != 0) {
		lm_serr(MMS_CRIT, "lm_gen_lmpl_cmd: Unable to lock element "
		    "mutex, errno - %s", strerror(errno));
		return (LM_ERROR);
	}

	while (ele->lmpl_acc_tree == NULL) {
		timespec_t tv;
		timespec_t *tvp;

		mms_trace_flush(); /* flush mms_trace buffer */
		tv.tv_sec = time(NULL) + LM_THREAD_WAIT;
		tv.tv_nsec = 0;
		tvp = &tv;

		rc = pthread_cond_timedwait(&ele->lmpl_rsp_cv,
		    &ele->lmpl_rsp_mutex, tvp);
		if (rc == ETIMEDOUT) {
			if (!lm_internal_error)
				continue;
			else {
				mms_trace(MMS_ERR, "lm_gen_lmpl_cmd: While "
				    "waiting on an accept response, LM "
				    "encountered an internal processing error");
				(void) pthread_mutex_unlock(&ele->
				    lmpl_rsp_mutex);
				return (LM_ERROR);
			}
		} else if (rc != 0) {
			lm_serr(MMS_CRIT, "lm_gen_lmpl_cmd: Unable to wait on "
			    "element cond var, errno - %s",
			    strerror(errno));
			(void) pthread_mutex_unlock(&ele->lmpl_rsp_mutex);
			return (LM_ERROR);
		}
		mms_trace(MMS_DEBUG,
		    "lm_gen_lmpl_cmd: Went to sleep waiting for "
		    "accept");
	}

	mms_trace(MMS_DEBUG, "lm_gen_lmpl_cmd: Handling accept response");

	if ((acc = ele->lmpl_acc_tree) == NULL) {
		lm_serr(MMS_ERR, "lm_gen_lmpl_cmd: Woken up while waiting on "
		    "an accept response, but accept response is still set "
		    "to NULL");
		(void) pthread_mutex_unlock(&ele->lmpl_rsp_mutex);
		return (LM_ERROR);
	}

	if (mms_pn_lookup(acc, "unacceptable", MMS_PN_KEYWORD,
	    NULL) != NULL) {
		mms_trace(MMS_ERR, "lm_gen_lmpl_cmd: Received an unacceptable "
		    "response for LMPL command:\n%s", cmd_str);
		(void) pthread_mutex_unlock(&ele->lmpl_rsp_mutex);
		(void) pthread_mutex_unlock(&lm_acc_mutex);
		ele->lmpl_rsp_final = LMPL_UNACCEPTABLE;
		return (LMPL_UNACCEPTABLE);
	}

	mms_trace(MMS_DEBUG, "Free up accept mutex");
	if ((rc = pthread_mutex_unlock(&lm_acc_mutex)) != 0) {
		lm_serr(MMS_CRIT, "lm_gen_lmpl_cmd: Unable to unlock acc/unacc "
		    "mutex, errno - %s", strerror(errno));
		(void) pthread_mutex_unlock(&ele->lmpl_rsp_mutex);
		return (LM_ERROR);
	}

	while (ele->lmpl_rsp_final == LMPL_WAITING) {
		mms_trace(MMS_DEBUG,
		    "lm_gen_lmpl_cmd: Going to sleep waiting for "
		    "final response");
			/* If the LMPL command that is being sent does not */
			/* complete in the alotted time, then LM will */
			/* send a LMPL cancel command to MM to cancel the */
			/* original LMPL command */
		if (wait) {
			tv.tv_sec = time(NULL) + wait;
			tv.tv_nsec = 0;
			tvp = &tv;
			if ((rc = pthread_cond_timedwait(&ele->lmpl_rsp_cv,
			    &ele->lmpl_rsp_mutex, tvp)) == ETIMEDOUT) {
				mms_trace(MMS_DEBUG,
				    "lm_gen_lmpl_cmd: 2 Timeout "
				    "hit, send LMPL cancel command for command"
				    ":\n%s", cmd_str);
				lm_send_cancel(taskid);
				wait = 0;
				continue;
			} else if (rc != 0) {
				lm_serr(MMS_CRIT,
				    "lm_gen_lmpl_cmd: 2 Unable to "
				    "wait on element cond var, errno - %s",
				    strerror(errno));
				(void) pthread_mutex_unlock(&ele->
				    lmpl_rsp_mutex);
				return (LM_ERROR);
			}
		} else {
			tv.tv_sec = time(NULL) + LM_THREAD_WAIT;
			tv.tv_nsec = 0;
			tvp = &tv;
			if ((rc = pthread_cond_timedwait(&ele->lmpl_rsp_cv,
			    &ele->lmpl_rsp_mutex, tvp)) == ETIMEDOUT) {
				if (!lm_internal_error)
					continue;
				mms_trace(MMS_ERR,
				    "lm_gen_lmpl_cmd: 2 Detected "
				    "an internal processing error");
				(void) pthread_mutex_unlock(&ele->
				    lmpl_rsp_mutex);
				return (LM_ERROR);
			} else if (rc != 0) {
				lm_serr(MMS_CRIT,
				    "lm_gen_lmpl_cmd: 2 Unable to "
				    "wait on element cond var, errno - %s",
				    strerror(errno));
				(void) pthread_mutex_unlock(&ele->
				    lmpl_rsp_mutex);
				return (LM_ERROR);
			}
		}
		mms_trace(MMS_DEBUG,
		    "lm_gen_lmpl_cmd: Woke up while waiting for "
		    "final reponse");
	}

	(void) pthread_mutex_unlock(&ele->lmpl_rsp_mutex);

	mms_trace(MMS_DEVP, "lm_gen_lmpl_cmd: return to command routine");

	return (ele->lmpl_rsp_final);
}

/*
 *
 * lm_handle_event()
 *
 * Parameters:
 *	- cmd		Ptr to parse tree of event command.
 *
 * This function will do any preprocessing of an event notification
 * command. It currently only checks to see if the state of the LM is
 * valid to process an event.
 * NOTE: Currently LM does not register for any events.
 *
 * Return Values:
 *	LM_OK		If it was able to process the event correctly
 *	LM_ERROR	If routine encountered an internal error while
 *			processing event
 *
 */
int
lm_handle_event(mms_par_node_t *cmd)
{
	char	*tid = NULL;

			/* If LM is not active ignore event commands */
	if (!(lm_state & LM_MASK2)) {
		mms_trace(MMS_OPER,
		    "lm_handle_event: LM is not in a valid state "
		    "to process event command, state - 0x%x", lm_state);
		mms_pn_destroy(cmd);
		return (LM_OK);
	}

	if (lm_queue_add(&lm_cmdq, (void *)cmd, &tid, LM_C_EVENT) != 0) {
		lm_serr(MMS_ERR, "lm_handle_event: adding %s command "
		    "to work queue failed", mms_pn_token(cmd));
		mms_pn_destroy(cmd);
		return (LM_ERROR);
	}
	return (LM_OK);
}

/*
 *
 * lm_handle_response()
 *
 * Parameters:
 *	- cmd		Ptr to parse tree of response cmd.
 *
 * This function will indicate to the correct thread waiting for a response
 * from the MM that it has received it and wake it up. It is the cmd
 * processing thread that will interrept the response based on its expectations
 * This function's job is only to save the parsed cmd in the queue's element
 * location and wake the cmd thread up.
 *
 * Return Values:
 *	LM_OK		If it was able to process the response correctly
 *	LM_ERROR	If routine encountered an internal error while
 *			processing response
 *
 */

int
lm_handle_response(mms_par_node_t *cmd)
{
	int	found = LMPL_FINAL_INVALID;
	int	task_id;

	lmpl_rsp_ele_t	*ele;
	lmpl_rsp_node_t	*node;

	mms_par_node_t	*clause;
	mms_par_node_t 	*tid;

	if (pthread_mutex_lock(&lm_rspq.rspq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_handle_response: unable to lock "
		    "response queue mutex, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

	if (mms_pn_lookup(cmd, "accepted", MMS_PN_KEYWORD, NULL)
	    != NULL) {
		mms_trace(MMS_DEBUG,
		    "lm_handle_response: handle accept response "
		    "for tid - %d", lm_rspq.rspq_tid);
		found = LMPL_ACCEPT;

	} else if (mms_pn_lookup(cmd, "unacceptable", MMS_PN_KEYWORD,
	    NULL) != NULL) {
		mms_trace(MMS_DEBUG,
		    "lm_handle_response: handle unaccept response "
		    "for tid - %d", lm_rspq.rspq_tid);
		found = LMPL_UNACCEPTABLE;

	} else if (mms_pn_lookup(cmd, "success", MMS_PN_KEYWORD,
	    NULL) != NULL) {
		mms_trace(MMS_DEBUG, "lm_handle_response: Found a success "
		    "response");
		found = LMPL_FINAL_OK;

	} else if (mms_pn_lookup(cmd, "intermediate", MMS_PN_KEYWORD,
	    NULL) != NULL) {
		mms_trace(MMS_DEBUG, "lm_handle_response: Found a intermediate "
		    "response");
		found = LMPL_FINAL_INTER;

	} else if (mms_pn_lookup(cmd, "error", MMS_PN_CLAUSE,
	    NULL) != NULL) {
		mms_trace(MMS_DEBUG, "lm_handle_response: Found a error "
		    "response");
		found = LMPL_FINAL_ERROR;

	} else if (mms_pn_lookup(cmd, "cancelled", MMS_PN_KEYWORD,
	    NULL) != NULL) {
		mms_trace(MMS_DEBUG, "lm_handle_response: Found a cancelled "
		    "response");
		found = LMPL_FINAL_CANCEL;

	} else {
		lm_serr(MMS_CRIT, "lm_handle_response: Did not find "
		    "accept, unacceptable, success, error, or cancelled in "
		    "response:\n%s", mms_pn_build_cmd_text(cmd));
		(void) pthread_mutex_unlock(&lm_rspq.rspq_mutex);
		return (LM_ERROR);
	}

	if (found == LMPL_ACCEPT || found == LMPL_UNACCEPTABLE) {
		ele = lm_rspq.rspq_cmd[lm_rspq.rspq_tid];
		task_id = lm_rspq.rspq_tid;
		if (ele == NULL) {
			lm_serr(MMS_CRIT, "lm_handle_response: Trying to "
			    "handle a accept/unaccept response for tid - %d, "
			    "but element is null", lm_rspq.rspq_tid);
			(void) pthread_mutex_unlock(&lm_rspq.rspq_mutex);
			return (LM_ERROR);
		}
		ele->lmpl_acc_tree = cmd;
	} else {
		if ((clause = mms_pn_lookup(cmd, "task", MMS_PN_CLAUSE,
		    NULL)) == NULL) {
			lm_serr(MMS_CRIT, "lm_handle_response: Did not find "
			    "task clause in response:\n%s",
			    mms_pn_build_cmd_text(cmd));
			(void) pthread_mutex_unlock(&lm_rspq.rspq_mutex);
			return (LM_ERROR);
		}

		if ((tid = mms_pn_lookup(clause, NULL, MMS_PN_STRING, NULL))
		    == NULL) {
			lm_serr(MMS_CRIT, "lm_handle_response: Did not find "
			    "task value in response:\n%s",
			    mms_pn_build_cmd_text(cmd));
			(void) pthread_mutex_unlock(&lm_rspq.rspq_mutex);
			return (LM_ERROR);
		}
		mms_trace(MMS_DEVP, "lm_handle_response: Response task id "
		    "- %s", mms_pn_token(tid));

		task_id = atoi(mms_pn_token(tid));
		mms_trace(MMS_DEBUG, "lm_handle_response: Response task id "
		    "- %d", task_id);

		if (task_id < 0 || task_id > SIZE_RSP_ARRAY) {
			lm_serr(MMS_CRIT, "lm_handle_response: Task id %d in "
			    "response is not in the range of possible "
			    "LMPL task ids, range: %d - %d", task_id, 0,
			    SIZE_RSP_ARRAY);
			(void) pthread_mutex_unlock(&lm_rspq.rspq_mutex);
			return (LM_ERROR);
		}

		ele = lm_rspq.rspq_cmd[task_id];
		if (ele == NULL) {
			lm_serr(MMS_CRIT, "lm_handle_response: Trying to "
			    "handle a response for tid - %d, but response "
			    "element is NULL", task_id);
			(void) pthread_mutex_unlock(&lm_rspq.rspq_mutex);
			return (LM_ERROR);
		}
		if ((node = (lmpl_rsp_node_t *)malloc(sizeof (lmpl_rsp_node_t)))
		    == NULL) {
			lm_serr(MMS_CRIT, "lm_obtain_task_id: Unable to malloc "
			    "space for a new lmpl node element, errno - %s",
			    strerror(errno));
			return (LM_ERROR);
		}
		node->lmpl_rsp_tree = cmd;
		node->lmpl_rsp_type = found;

		mms_list_insert_tail(&ele->lmpl_rsp_list, node);

		if (found == LMPL_FINAL_INTER) {
			mms_trace(MMS_DEBUG, "lm_handle_response: Recevied a "
			    "intermediate response for task id - %d", task_id);
			return (LM_OK);
		}
		ele->lmpl_rsp_final = found;

			/* clear entry in response array so that another */
			/* LMPL command can use it */
		lm_rspq.rspq_cmd[task_id] = NULL;
	}

	if (pthread_cond_signal(&ele->lmpl_rsp_cv) != 0) {
		lm_serr(MMS_CRIT, "lm_handle_response: Cond_signal failed "
		    "trying to signal thread waiting on wakeup call, "
		    "errno - %s", strerror(errno));
		(void) pthread_mutex_unlock(&ele->lmpl_rsp_mutex);
		return (LM_ERROR);
	}
	mms_trace(MMS_DEBUG, "lm_handle_response: Signaled thread waiting on "
	    "condition mutex - %d", task_id);

	if (pthread_mutex_unlock(&lm_rspq.rspq_mutex) != 0) {
		lm_serr(MMS_CRIT, "lm_handle_response: Failure trying to "
		    "unlock lm_rspq.rspq_mutex mutex, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

	return (LM_OK);
}

/*
 * lm_handle_parser_error()
 *
 * Parameters:
 *	- cmd		Parse tree of input generated by mms_lmpm_parse
 *	- err_list	List of errors found by mms_lmpm_parse
 *
 * Globals:
 *
 * This function handle the case where mms_lmpm_parse detected a error. This
 * routine tries to look at the errors that were detected and decide
 * what should be done.
 *
 * NOTE: The input could be one of the following. This routine tries to
 * look at the output from the parser and handle each case:
 *	- A new LMPM cmd sent to LM by MM.
 *	- A final response to a LMPL cmd that LM sent to MM.
 *	- A accept/unaccept response to a LMPL cmd that LM sent to MM.
 *
 * Return Values:
 *	MMS_OK:	If error was a syntax error on a new command from MM. We send
 *		a unaccept response back to MM in this case.
 *	NOMEM:	Have the parser retry parsing the cmd since memory may be freed
 *		since the first try.
 *	MMS_ERROR:  This routine encountered an error that should not of occured
 *		and it could not recover.
 *
 */

int
lm_handle_parser_error(mms_par_node_t *cmd, mms_list_t *err_list)
{
	char		rsp_str[256];	/* Contains negative resp BNF string */
					/* msg part of rsp_str */
	char		msg_str[256];

	mms_par_err_t	*err;		/* Used to step through error list */
	mms_par_node_t	*root;		/* Ptr to cmd node of parse tree */

					/* Determine type of errors detected */
	mms_list_foreach(err_list, err) {
		mms_trace(MMS_ERR, "lm_handle_parser_error: lmp_parse error, \
		    line %d, col %d, near token \"%s\", err code %d, %s",
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code,
		    err->pe_msg);

		switch (err->pe_code) {
			case MMS_PE_NOMEM:
				mms_trace(MMS_ERR, "lm_handle_parser_error: "
				    "Parser error indicates that no memory "
				    "is available to create parse tree, try "
				    "parsing again");
				return (LM_NOMEM);
			case MMS_PE_SYNTAX:
				break;
			case MMS_PE_MAX_LEVEL:
				lm_serr(MMS_CRIT, "lm_handle_parser_error: "
				    "Parser error indicates that the max level "
				    "was reached");
				return (LM_ERROR);
			default:
					/* Only above three possible error */
					/* conditions exist, thus if this */
					/* condition is ever hit, things */
					/* are really messed up, system error */
				lm_serr(MMS_CRIT, "lm_handle_parser_error: "
				    "Encountered a unknown parser error - %d",
				    err->pe_code);
				return (LM_ERROR);
		}
	}

	root = mms_pn_lookup(cmd, NULL, MMS_PN_CMD, NULL);
	if (root == NULL) {
			/* Unable to tell what the input was at all, in this */
			/* case we generate a system error and will exit */
		lm_serr(MMS_CRIT, "lm_handle_parser_error: Parser error is a "
		    "syntax error, but unable to determine if error is on a "
		    "new LMPM command or a LMPL response");
		return (LM_SYNTAX_ERR);
	}

	if (strcmp("response", mms_pn_token(root)) == 0) {
		lm_serr(MMS_CRIT, "lm_handle_parser_error: Parser syntax error "
		    "on LMPL response from MM");
		return (LM_SYNTAX_RSP);
	}

	/* ASSUME THAT THE MM SENT US A CMD. NEED TO SEND AN UNACCEPT, SINCE */
	/* WE ARE USING LMPM_PARSE, WE KNOW IT IS A LMPM COMMAND, JUST NOT */
	/* VALID LMPM COMMAND */

	lm_serr(MMS_CRIT, "lm_handle_parser_error: Parser syntax error "
	    "on LMPM %s command from MM", mms_pn_token(root));

	(void) snprintf(msg_str, sizeof (msg_str),
	    LM_7005_MSG, mms_pn_token(root),
	    mms_pn_token(root));
	(void) snprintf(rsp_str, sizeof (rsp_str),
	    LM_UNACC_RESP, msg_str);
	if (lm_write_msg(rsp_str, &lm.lm_mms_conn, lm_write_mutex)) {
		lm_serr(MMS_CRIT,
		    "lm_handle_parser_error: Sending unacceptable "
		    "response on invalid LMPM command failed");
	}
	return (LM_SYNTAX_CMD);
}

/*
 *
 * lm_write_msg()
 *
 * Parameters:
 *	- msg		The message that is to be sent to the MM. It is in BNF
 *			form defined in the IEEE spec for MMS.
 *	- conn		The connection structure
 *	- mutex		The mutex which allows only one thread of the LM to
 *			write to the MM at a time.
 *
 * This function sends a message from the LM to the MM over the socket that
 * connects the LM and MM. Locks the mutex around output, and sends the message.
 * This routine is not to be used to send a LMPL command to MM. Use
 * lm_gen_lmpl_cmd() to do this. This routine is used to send messages where
 * no response is expected.
 *
 * Return Values:
 *	- MMS_OK		If the message was sent without errors.
 *	- MMS_ERROR		If a error occurred while sending the message.
 *
 * NOTE: The calling routine should call lm_serr if LM_ERROR is returned.
 * This routine only sends a mms_trace message indicating the write error.
 *
 */

int
lm_write_msg(char *msg, mms_t *conn, pthread_mutex_t mutex)
{

	int		len;		/* length of xmlcmd string */
	int		rc;		/* return code */

	len = strlen(msg);

	if ((rc = pthread_mutex_lock(&mutex)) != 0) {
		lm_serr(MMS_CRIT, "lm_write_msg: Unable to lock mutex for "
		    "writing command to MM, errno - %s", strerror(errno));
		return (LM_ERROR);
	}

	if ((rc = mms_writer(conn, msg)) != len) {
		mms_trace(MMS_CRIT, "lm_write_msg: mms_writer failed to write "
		    "to MM, error - %d", rc);
		mms_trace(MMS_CRIT, "lm_write_msg: Command/Response:\n%s", msg);
		(void) pthread_mutex_unlock(&mutex);
		return (LM_ERROR);
	}

	if ((rc = pthread_mutex_unlock(&mutex)) != 0) {
		lm_serr(MMS_CRIT, "lm_write_msg: Unable to unlock mutex "
		    "for writing to MM, errno - %s", strerror(errno));
		return (LM_ERROR);
	}

	return (LM_OK);
}
