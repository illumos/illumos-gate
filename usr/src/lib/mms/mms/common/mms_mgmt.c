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


/*
 *   mms_mgmt.c
 *
 *   Define functions used to manage API lists.
 */

#include <mms.h>
#include <mgmt_mms.h>

static char	*_SrcFile = __FILE__;

/*
 *   mms_acc_insert
 *
 *   Add a response to the accept pointer.
 */
void
mms_acc_insert(mms_session_t *sp, mms_rsp_ele_t *rsp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_acc_insert: Lock of MMS accept mutex "
		    "failed with errno - %s", strerror(rc));
	}

	sp->mms_acc_rsp = rsp;

	/*
	 *    Wake up any thread waiting on an accept/unaccept response.
	 */
	if ((rc = pthread_cond_broadcast(&sp->mms_acc_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_acc_insert: Broadcast on accept "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_acc_insert: Unlock of MMS accept "
		    "mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_acc_wakeup
 *
 *   Wake-up threads waiting for the an accept response.
 */
void
mms_acc_wakeup(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_reperr: Lock of MMS accept mutex "
		    "failed with errno - %s", strerror(rc));
	}

	/*
	 *    Wake up any thread waiting on an accept/unaccept response.
	 */
	if ((rc = pthread_cond_broadcast(&sp->mms_acc_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_reperr: Broadcast on accept "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_reperr: Unlock of MMS accept mutex "
		    "failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_be_wait
 *
 *   Wait for a pending begin-end sequence to complete.
 */
void
mms_be_wait(mms_session_t *sp, boolean_t be_start)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_be_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_be_wait: Lock of MMS begin-end "
		    "mutex failed with error - %s", strerror(rc));
	}

	while (sp->mms_be_pending) {
		if ((rc = pthread_cond_wait(&sp->mms_be_cv,
		    &sp->mms_be_mutex)) != 0) {
			mms_serr(MMS_CRIT, "mms_be_wait: Unable to wait "
			    "on begin-end condition variable, error "
			    "- %s", strerror(rc));
		}
	}

	if (be_start)
		sp->mms_be_pending = B_TRUE;

	if ((rc = pthread_mutex_unlock(&sp->mms_be_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_be_wait: Unlock of MMS begin-end "
		    "mutex failed with error - %s", strerror(rc));
	}
}


/*
 *   mms_be_wakeup
 *
 *   Wake-up threads waiting for a begin-end sequence to complete.
 */
void
mms_be_wakeup(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_be_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_be_wakeup: Lock of MMS begin-end "
		    "mutex failed with error - %s", strerror(rc));
	}

	sp->mms_be_pending = B_FALSE;

	if ((rc = pthread_cond_broadcast(&sp->mms_be_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_be_wakeup: Broadcast on begin-end "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_be_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_be_wakeup: Unlock of MMS begin-end "
		    "mutex failed with error - %s", strerror(rc));
	}

	mms_trace(MMS_DEBUG, "mms_be_wakeup: Wakeup pending begin-end "
	    "sequences");
}


/*
 *   mms_cmd_create
 *
 *   Create an element to manage asynchronous requests.
 */
void
mms_cmd_create(mms_session_t *sp, char *tid, char *mms_cmd, int cmd_type,
    void (*callbk)(void *arg, void *arg1), void *callbk_param)
{
	mms_cmd_ele_t	*cmd;

	cmd = (mms_cmd_ele_t *)malloc(sizeof (mms_cmd_ele_t));
	if (cmd == NULL) {
		mms_serr(MMS_CRIT, "mms_cmd_create: Unable to allocate memory "
		    "for a command list element (errno = %s)", strerror(errno));
	}

	cmd->mms_cmd_type = cmd_type;
	cmd->mms_cmd_tid = strdup(tid);
	cmd->mms_cmd_cmd = strdup(mms_cmd);
	cmd->mms_cmd_callbk = callbk;
	cmd->mms_cmd_callbk_param = callbk_param;

	mms_cmd_insert(sp, cmd);
}


/*
 *   mms_cmd_extract
 *
 *   Parse a command, extracting the command type and task id.
 */
int
mms_cmd_extract(char *cmd, char **tid, mms_cmd_name_t *cmdtype)
{
	mms_par_node_t	*root;
	mms_list_t		err_list;
	int		rc;

	*cmdtype = MMS_CMD_OTHER;

	rc = mms_mmp_parse(&root, &err_list, cmd);
	if (rc) {
		mms_pe_destroy(&err_list);
		return (rc);
	}

	mms_pe_destroy(&err_list);

	*tid = mms_cmd_get_task(root);
	if (*tid == NULL) {
		return (MMS_INVALID_REQ);
	}

	if (strcmp(mms_pn_token(root), "begin") == 0) {
		*cmdtype = MMS_CMD_BEGIN;

	} else if (strcmp(mms_pn_token(root), "end") == 0) {
		*cmdtype = MMS_CMD_END;
	}

	mms_pn_destroy(root);
	return (MMS_API_OK);
}


/*
 *   mms_cmd_flush
 *
 *   Flush all entries from the command queue.
 */
void
mms_cmd_flush(mms_session_t *sp, char *msg)
{
	mms_rsp_ele_t	*err_rsp;
	mms_cmd_ele_t	*cmd;
	int		rc;

	if ((rc = pthread_mutex_lock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_reperr: Lock of MMS command list "
		    "mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Send error final response for all outstanding commands.
	 */
	while (! mms_list_empty(&sp->mms_cmd_list)) {

		cmd = mms_list_head(&sp->mms_cmd_list);
		mms_list_remove(&sp->mms_cmd_list, cmd);

		/*
		 *  If the command was sent asynchronously, then execute the
		 *  callback function, sending a generated error response.
		 *  For commands sent over a synchronous connection,
		 *  mms_obtain_response will return the error response.
		 */
		if (msg && cmd->mms_cmd_type == MMS_API_ASYNC) {
			err_rsp = mms_gen_err_rsp(cmd->mms_cmd_tid,
			    sp->mms_api_errcode, msg);
			if (err_rsp) {
				cmd->mms_cmd_callbk(
				    cmd->mms_cmd_callbk_param, err_rsp);
			}
		}
		mms_cmd_free(cmd);
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_reperr: Unlock of MMS command list"
		    " mutex failed with errno - %s", strerror(rc));
	}
}


/*
 * mms_cmd_free
 *
 * This function frees memory associated with a command list element.
 */
void
mms_cmd_free(mms_cmd_ele_t *cmd)
{
	if (cmd == NULL)
		return;

	free(cmd->mms_cmd_tid);
	free(cmd->mms_cmd_cmd);
	free(cmd);

	mms_trace(MMS_DEBUG, "mms_cmd_free: Completed free of command "
	    "list element memory");
}


/*
 *   mms_cmd_get_task
 *
 *   Extract the task id from the command.
 */
char *
mms_cmd_get_task(mms_par_node_t *root)
{
	mms_par_node_t	*node;
	mms_par_node_t	*tasknode;
	char		*task;

	node = mms_pn_lookup(root, "task", MMS_PN_CLAUSE, NULL);
	if (node == NULL) {
		mms_trace(MMS_DEBUG,
		    "mms_cmd_get_task: Couldn't find a task clause");
		return (NULL);
	}

	tasknode = mms_pn_lookup(node, NULL, MMS_PN_STRING, NULL);
	if (tasknode == NULL) {
		mms_trace(MMS_DEBUG,
		    "mms_cmd_get_task: Couldn't find the task string");
		return (NULL);
	}
	if (mms_pn_token(tasknode) == NULL) {
		mms_trace(MMS_DEBUG,
		    "mms_cmd_get_task: Task string is null");
		return (NULL);
	}

	task = strdup(mms_pn_token(tasknode));
	return (task);
}


/*
 *   mms_cmd_insert
 *
 *   Add an element to the command list.
 */
void
mms_cmd_insert(mms_session_t *sp, mms_cmd_ele_t *cmd)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_cmd_insert: Lock of MMS command list "
		    "mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *  Add cmd element to outstanding command list so that reader
	 *  thread knows what to do with the response, either add to
	 *  response list or do a callback.
	 */
	mms_list_insert_tail(&sp->mms_cmd_list, cmd);

	if ((rc = pthread_mutex_unlock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_cmd_insert: Unlock of MMS command "
		    "list mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_cmd_remove
 *
 *   Return the command list element for task 'tid'.
 */
mms_cmd_ele_t *
mms_cmd_remove(mms_session_t *sp, char *tid)
{
	mms_cmd_ele_t	*cmd_ele;
	mms_cmd_ele_t	*next;
	int		rc;

	/*
	 *    Obtain the command structure that is associated with the
	 *    taskid of the last command sent to MMS.
	 */
	if ((rc = pthread_mutex_lock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_cmd_remove: Lock of command "
		    "mutex failed with errno - %s", strerror(rc));
	}

	mms_list_foreach_safe(&sp->mms_cmd_list, cmd_ele, next) {
		if ((strcmp(cmd_ele->mms_cmd_tid, tid)) == 0) {
			mms_trace(MMS_DEBUG,
			    "mms_cmd_remove: Entry in command list"
			    " found for final response for taskid %s", tid);
			mms_list_remove(&sp->mms_cmd_list, cmd_ele);
			break;
		}
	}

	if (cmd_ele == NULL) {
		mms_trace(MMS_ERR,
		    "mms_cmd_remove, Did not find final response "
		    "entry in command list for command with taskid %s", tid);
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_cmd_remove: Unlock of command"
		    "list mutex failed with errno - %s", strerror(rc));
	}

	return (cmd_ele);
}


/*
 *   mms_ev_insert
 *
 *   Insert response in the event list and wakeup any threads reading
 *   events.
 */
void
mms_ev_insert(mms_session_t *sp, mms_rsp_ele_t *rsp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_ev_mutex)) != 0) {
		mms_send_errmsg(sp, MMS_API_3002_MSG, 4, "mms_ev_mutex",
		    strerror(rc), "mms_ev_mutex", strerror(rc));
		mms_serr(MMS_CRIT, "mms_ev_insert: Lock of MMS event"
		    "mutex failed with errno - %s\n", strerror(rc));
	}

	mms_list_insert_tail(&sp->mms_ev_list, rsp);

	if ((rc = pthread_cond_broadcast(&sp->mms_ev_cv)) != 0) {
		mms_send_errmsg(sp, MMS_API_3003_MSG, 4, "mms_ev_cv",
		    strerror(rc), "mms_ev_cv", strerror(rc));
		mms_serr(MMS_CRIT, "mms_ev_insert: Broadcast on "
		    "event list condition variable failed with errno -"
		    " %s", strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_ev_mutex)) != 0) {
		mms_send_errmsg(sp, MMS_API_3003_MSG, 4, "mms_ev_mutex",
		    strerror(rc), "mms_ev_mutex", strerror(rc));
		mms_serr(MMS_CRIT, "mms_ev_insert: Unlock of MMS event "
		    "list mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_rsp_create
 *
 *   Create an MMS response.
 */
mms_rsp_ele_t *
mms_rsp_create(char *input, mms_par_node_t *cmd, int resp_type, char *tid)
{
	mms_rsp_ele_t	*rsp;

	rsp = (mms_rsp_ele_t *)malloc(sizeof (mms_rsp_ele_t));
	if (rsp == NULL) {
		mms_serr(MMS_CRIT, "mms_rsp_create: Malloc of space for new "
		    "response list element failed with errno - %s",
		    strerror(errno));
	}

	rsp->mms_rsp_str = input;
	rsp->mms_rsp_cmd = cmd;
	rsp->mms_rsp_type = resp_type;
	rsp->mms_rsp_tid = tid;

	return (rsp);
}


/*
 *   mms_rsp_find
 *
 *   Find the response, with the specified id, in the response list.
 */
mms_rsp_ele_t *
mms_rsp_find(mms_session_t *sp, char *tid)
{
	mms_rsp_ele_t	*ele;
	mms_rsp_ele_t	*next;

	mms_list_foreach_safe(&sp->mms_rsp_list, ele, next) {
		if ((strcmp(ele->mms_rsp_tid, tid)) == 0) {
			mms_trace(MMS_DEBUG, "mms_rsp_find: Found final "
			    "response for command with taskid %s", tid);
			mms_list_remove(&sp->mms_rsp_list, ele);
			break;
		}
	}

	return (ele);
}


/*
 *   mms_rsp_insert
 *
 *   Add a response to the response list.
 */
void
mms_rsp_insert(mms_session_t *sp, mms_rsp_ele_t *rsp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_rsp_insert: Unlock of MMS "
		    "response list mutex failed with errno - %s", strerror(rc));
	}

	mms_list_insert_tail(&sp->mms_rsp_list, rsp);

	if ((rc = pthread_cond_broadcast(&sp->mms_rsp_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_rsp_insert: Broadcast on "
		    "response list condition variable failed with errno - %s",
		    strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_rsp_insert: Unlock of MMS "
		    "response list mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_rsp_wakeup
 *
 *   Wakeup threads waiting for a final response.
 */
void
mms_rsp_wakeup(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_rsp_wakeup: Lock of MMS response list"
		    " mutex failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_cond_broadcast(&sp->mms_rsp_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_rsp_wakeup: Broadcast on response list"
		    " condition variable failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_rsp_wakeup: Unlock of MMS response"
		    " list mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_start_notify
 *
 *   Notify anyone waiting for the asynchronous interface to start
 *   processing requests.
 */
void
mms_start_notify(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_start_notify: Lock of MMS reader "
		    " start mutex failed with errno - %s", strerror(rc));
	}

	sp->mms_api_rstarted = MMS_API_YES;

	if ((rc = pthread_cond_broadcast(&sp->mms_acc_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_start_notify: Broadcast on MMS "
		    "reader start condition variable failed with errno - %s",
		    strerror(rc));
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_start_notify: Unlock of MMS reader "
		    "start mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_thread_exit
 *
 *   Decrement the thread count.
 */
void
mms_thread_exit(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_cnt_mutex)) != 0) {
		sp->mms_thrd_cnt--;
		mms_serr(MMS_CRIT, "mms_thread_exit: Lock of MMS thread "
		    "count mutex failed with errno - %s", strerror(rc));
	}

	if (--sp->mms_thrd_cnt == 0 &&
	    sp->mms_api_state == MMS_API_SHUTDOWN) {
		mms_trace(MMS_DEBUG,
		    "mms_thread_exit: Last client thread to exit, "
		    "send broadcast to wake up goodbye");
		if ((rc = pthread_cond_broadcast(&sp->mms_cnt_cv)) != 0) {
			mms_serr(MMS_CRIT, "mms_thread_exit: Broadcast on "
			    "thrd cnt variable failed with errno - %s",
			    strerror(rc));
		}
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_cnt_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_thread_exit: Unlock of MMS thread "
		    "count mutex failed with errno - %s", strerror(rc));
	}
}


/*
 *   mms_thread_start
 *
 *   Start MMS API processing for a thread.
 */
void
mms_thread_start(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_mutex_lock(&sp->mms_cnt_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_thread_start: Lock of MMS thread "
		    "count mutex failed with errno - %s", strerror(rc));
	}

	sp->mms_thrd_cnt++;

	if ((rc = pthread_mutex_unlock(&sp->mms_cnt_mutex)) != 0) {
		sp->mms_thrd_cnt--;
		mms_serr(MMS_CRIT, "mms_thread_start: Unlock of MMS thread "
		    "count mutex failed with errno - %s", strerror(rc));
	}
}
