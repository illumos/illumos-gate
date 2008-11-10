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


#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <stdarg.h>
#include <ctype.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <libgen.h>
#include <time.h>
#include <sys/varargs.h>
#include <pthread.h>
#include <sys/mkdev.h>
#include <sys/varargs.h>
#include <errno.h>
#include <sys/siginfo.h>
#include <sys/scsi/impl/uscsi.h>
#include <dlfcn.h>
#include <mms_network.h>
#include <mms_trace.h>
#include <mms_sym.h>
#include <dm_impl.h>
#include <mms_dmd.h>
#include <dm_msg.h>
#include <dm_proto.h>
#include <mms_strapp.h>
#include <mms_cat.h>

static	char *_SrcFile = __FILE__;

/*
 * Function name
 *	dm_bld_task(char *cmd)
 *
 * Parameters:
 *	cmd	command name pointer
 *
 * Description:
 *	create a task id for use with a DMP command
 *
 * Return code:
 *	pointer to the task id. Caller must free after its use
 *
 * Note:
 *
 *
 */

char	*
dm_bld_task(char *cmd)
{
	char		*task;

	task = mms_strnew("%s:%s:%s:%s:%ld-%d", wka->dm_local_hostname,
	    DMNAME, DRVNAME, cmd, (long)wka->dm_pid, wka->dm_counter++);
	return (task);
}

/*
 * Function name
 *	dm_parse_err(mms_par_node_t *root, mms_list_t *err_list)
 *
 * Parameters:
 *	root	root of parse tree
 *	err_list	list of errors
 *
 * Description:
 *	trace parser error
 *	put the first error in the parse tree in the response
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_parse_err(mms_par_node_t *root, mms_list_t *err_list)
{
	mms_par_node_t	*node;
	mms_par_err_t	*err;

	if (root == NULL) {
		node = NULL;
	} else {
		node = mms_pn_lookup(root, NULL, MMS_PN_CMD, NULL);
	}
	mms_list_foreach(err_list, err) {
		TRACE((MMS_ERR, "Parse error: %s command, line %d, col %d, "
		    "near token \"%s\", err code %d, %s",
		    node == NULL ? "Unknown" : mms_pn_token(node),
		    err->pe_line,
		    err->pe_col,
		    err->pe_token,
		    err->pe_code, err->pe_msg));
	}

	/*
	 * Return the first error message
	 */
	err = (mms_par_err_t *)mms_list_head(err_list);
	DM_MSG_ADD((MMS_INVALID, MMS_E_SYNTAX_ERR,
	    "command %s, "
	    "line %d, "
	    "col %d, "
	    "token %s, "
	    "code %d, "
	    "%s",
	    node == NULL ? "unknown" : mms_pn_token(node),
	    err->pe_line,
	    err->pe_col,
	    err->pe_token, err->pe_code, err->pe_msg));

	dm_resp_unacceptable(6500, NULL);
}


/*
 * Function name
 *	dm_reader(char **cmdbuf)
 *
 * Parameters:
 *	cmdbuf	pointer to the buffer address
 *
 * Description:
 *	read a message from the socket connection to MM
 *
 * Return code:
 *	> 0	number of bytes of message
 *	0	EOF
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_reader(char **cmdbuf)
{
	int		rc;
	int		err;

	pthread_mutex_lock(&wka->dm_io_mutex);
	rc = mms_reader(&wka->dm_mms_conn, cmdbuf);
	err = errno;
	pthread_mutex_unlock(&wka->dm_io_mutex);
	if (rc == 0) {
		TRACE((MMS_INFO, "Socket EOF"));
	} else if (rc > 0) {
		TRACE((MMS_INFO, "input read: %s", *cmdbuf));
	} else {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_IO,
		    "Read error: %s", strerror(err)));
	}
	return (rc);
}

/*
 * Function name
 *	dm_writer_accept(char *cmdbuf)
 *
 * Parameters:
 *	cmdbuf	command buffer
 *
 * Description:
 *	send accepted and unacceptable command
 *
 * Return code:
 *	0	success
 *	-1	Error
 *	-2	incomplete write, write interrupted
 *
 * Note:
 *
 *
 */

int
dm_writer_accept(char *cmdbuf)
{
	return (dm_writer_aux(cmdbuf, DM_WRITE_ACCEPT));
}

/*
 * Function name
 *	dm_writer(char *cmdbuf)
 *
 * Parameters:
 *	cmdbuf	command buffer
 *
 * Description:
 *	send a command
 *
 * Return code:
 *	0	success
 *	-1	Error
 *	-2	incomplete write, write interrupted
 *
 * Note:
 *
 *
 */

int
dm_writer(char *cmdbuf)
{
	return (dm_writer_aux(cmdbuf, ~DM_WRITE_ACCEPT));
}

/*
 * Function name
 *	dm_writer_aux(char *cmdbuf)
 *
 * Parameters:
 *	cmdbuf	command buffer
 *
 * Description:
 *	send a command
 *	wait until no outstanding accept before sending a command
 *
 * Return code:
 *	0	success
 *	-1	Error
 *	-2	incomplete write, write interrupted
 *
 * Note:
 *
 *
 */

int
dm_writer_aux(char *cmdbuf, int accept)
{
	int		rc;

	TRACE((MMS_INFO, "Sending cmd: %s", cmdbuf));

	if (accept == DM_WRITE_ACCEPT) {
		/* write accept, just write it */
		pthread_mutex_lock(&wka->dm_io_mutex);
	} else {
		/* Wait for all accept is done */
		mms_trace_flush();		/* flush mms_trace buffer */
		pthread_mutex_lock(&wka->dm_queue_mutex);
		while (!mms_list_empty(&wka->dm_pend_ack_queue)) {
			pthread_cond_wait(&wka->dm_accept_cv,
			    &wka->dm_queue_mutex);
		}
		/* accept is sent */
		pthread_mutex_unlock(&wka->dm_queue_mutex);
		pthread_mutex_lock(&wka->dm_io_mutex);
	}

	rc = mms_writer(&wka->dm_mms_conn, cmdbuf);
	pthread_mutex_unlock(&wka->dm_io_mutex);
	if (rc > 0) {
		if (rc == strlen(cmdbuf)) {
			/* success */
			rc = 0;
		} else {
			/* partial write */
			rc = -2;
		}
	} else {
		/* error */
		rc = -1;
	}
	return (rc);
}


/*
 * Function name
 *	dm_get_task(mms_par_node_t *root)
 *
 * Parameters:
 *	root	root of parse tree
 *
 * Description:
 *	return the task id of a command from the parse tree
 *
 * Return code:
 *	task id string
 *
 * Note:
 *
 *
 */

char	*
dm_get_task(mms_par_node_t *root)
{
	mms_par_node_t	*node;
	mms_par_node_t	*tasknode;
	char		*task;

	if (root == NULL) {
		return (NULL);		/* no tree to lookup */
	}

	node = mms_pn_lookup(root, "task", MMS_PN_CLAUSE, NULL);
	if (node == NULL) {
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_INTERNAL,
		    "No task clause"));
		return (NULL);
	}
	tasknode = mms_pn_lookup(node, NULL, MMS_PN_STRING, NULL);
	if (tasknode == NULL) {
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_INTERNAL, "No task id"));
		return (NULL);
	}
	task = strdup(mms_pn_token(tasknode));
	return (task);
}

/*
 * Function name
 *	dm_get_hostpath
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Get the host specific library path if it is set.
 *
 * Return code:
 *	0 - good
 *	-1 - error
 *
 * Note:
 *
 *
 */

int
dm_get_hostpath(void)
{
	char		*show_cmd;
	char		*val;
	char		*task;
	dm_command_t	*cmd;
	mms_par_node_t	*root;

	if (drv->drv_disk_libpath) {
		free(drv->drv_disk_libpath);
		drv->drv_disk_libpath = NULL;
	}

	task = dm_bld_task("show-hostpath");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ and( streq(DM.'DMName' '%s') "
	    "streq(LIBRARYACCESS.'HostName' '%s')) ] "
	    "report[ LIBRARYACCESS.'LibraryPath' ] "
	    ";",
	    task, drv->drv_dmname, wka->dm_local_hostname);

	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send show hostpath error"));
		goto error;
	}

	root = cmd->cmd_root;
	val = dm_get_attr_value(root, "LIBRARYACCESS", "LibraryPath");
	if (val != NULL) {
		drv->drv_disk_libpath = strdup(val);
	}

	dm_destroy_cmd(cmd);
	return (0);

error:
	if (cmd != NULL) {
		dm_destroy_cmd(cmd);
	}
	return (-1);
}

/*
 * Function name
 *	dm_get_default_lib_path
 *
 * Parameters:
 *	none
 *
 * Description:
 *	Get the default library path from the LIBRARY object the
 *	DM belongs to.
 *
 * Return code:
 *	0 - OK
 *	-1 - error
 *
 * Note:
 *
 *
 */

int
dm_get_default_lib_path(void)
{
	char		*show_cmd;
	char		*val;
	char		*task;
	dm_command_t	*cmd;
	mms_par_node_t	*root;
	int		err;

	if (drv->drv_disk_libpath) {
		free(drv->drv_disk_libpath);
		drv->drv_disk_libpath = NULL;
	}

	task = dm_bld_task("show-default_lib_path");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ streq(DM.'DMName' '%s') ] "
	    "report[ LIBRARY.'DefaultLibraryPath' ] "
	    ";",
	    task, drv->drv_dmname);

	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send show default lib path error"));
		goto error;
	}

	root = cmd->cmd_root;
	val = dm_get_attr_value(root, "LIBRARY", "DefaultLibraryPath");
	if (val == NULL || val[0] == '\0') {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "no library path specified"));
		goto error;
	}
	if (mkdirp(val, 0755) == 0) {
		TRACE((MMS_DEBUG, "Created DISK lib %s", val));
	} else if (errno != EEXIST) {
		err = errno;
		/* Unable to create it */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to access library path %s: %s",
		    val, strerror(err)));
		goto error;
	}
	drv->drv_disk_libpath = strdup(val);		/* save lib path */

	dm_destroy_cmd(cmd);
	return (0);

error:
	if (cmd != NULL) {
		dm_destroy_cmd(cmd);
	}
	return (-1);
}

/*
 * Function name
 *	dm_get_cmd_by_task(char *task)
 *
 * Parameters:
 *	task	task id
 *
 * Description:
 *	return the dm_command_t that has the task id
 *
 * Return code:
 *	dm_command_t pointer
 *	NULL	can't find a command with matching task id
 *
 * Note:
 *
 *
 */

dm_command_t	*
dm_get_cmd_by_task(char *task)
{
	dm_command_t	*cmd;

	pthread_mutex_lock(&wka->dm_queue_mutex);
	mms_list_foreach(&wka->dm_cmd_queue, cmd) {
		if (strcmp(task, cmd->cmd_task) == 0) {
			/* found cmd with matching task */
			pthread_mutex_unlock(&wka->dm_queue_mutex);
			return (cmd);
		}
	}
	/* Not found */
	DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
	    "No command for task %s", task));
	pthread_mutex_unlock(&wka->dm_queue_mutex);
	return (NULL);
}

/*
 * Function name
 *	dm_read_input(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	read commands from the connection socket.
 *	If a command from MM is read, put it in a dm_command_t and
 *	put it in the command list.
 *	If a response to a command sent to MM is read, then set the
 *	command dispatchable.
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

/*
 * dm_read_input
 *	Read input command from MM and put it on input list
 */
void
dm_read_input(void)
{
	char		*buf = NULL;
	int		rc;
	dm_command_t	*cmd;
	mms_par_node_t	*root;
	mms_par_node_t	*node;
	mms_list_t	err_list;
	char		*task;

	rc = dm_reader(&buf);
	if (rc > 0) {
		/*
		 * Read a command
		 */
		rc = mms_dmpm_parse(&root, &err_list, buf);
		if (rc == 1) {
			dm_parse_err(root, &err_list);
			mms_pe_destroy(&err_list);
			mms_pn_destroy(root);
			TRACE((MMS_ERR, "Command in error: %s", buf));
			free(buf);
			return;
		}
		node = mms_pn_lookup(root, NULL, MMS_PN_CMD, NULL);
		task = dm_get_task(node);
		if (strcmp(mms_pn_token(node), "response") == 0) {
			/*
			 * MM responded to a command sent by DM
			 */
			if (task != NULL) {
				TRACE((MMS_DEBUG, "Get cmd by task %s", task));
				mms_trace_flush();
				cmd = dm_get_cmd_by_task(task);
				free(task);
				task = NULL;
			} else {
				/* Must be response unacceptable */
				TRACE((MMS_DEBUG, "Got unacceptable response"));
				DM_EXIT(DM_RESTART);
			}
			mms_trace_flush();
			if (cmd == NULL) {
				DM_MSG_SEND((DM_ADM_ERR, DM_6505_MSG, NULL));
				mms_pn_destroy(root);
				free(buf);
				return;
			}
			cmd->cmd_root = root;
			TRACE((MMS_DEBUG, "Calling cmd function"));
			mms_trace_flush();
			rc = (*cmd->cmd_func) (cmd);
			TRACE((MMS_DEBUG, "Back from cmd function"));
			mms_trace_flush();
			if (rc == DM_COMPLETE) {
				/*
				 * Command completed
				 */
				pthread_mutex_lock(&cmd->cmd_done_mutex);
				cmd->cmd_flags |= CMD_COMPLETE;
				pthread_cond_broadcast(&cmd->cmd_done_cv);
				pthread_mutex_unlock(&cmd->cmd_done_mutex);
			} else {
				/*
				 * Command not complete, free the parse tree
				 */
				mms_pn_destroy(root);
			}
		} else {
			/*
			 * A new command from MM
			 */
			cmd = (dm_command_t *)malloc(sizeof (dm_command_t));
			if (cmd == NULL) {
				DM_MSG_ADD((MMS_INTERNAL,
				    MMS_DM_E_INTERNAL, "Out of memory"));
				dm_resp_unacceptable(6506, NULL);
				mms_pn_destroy(root);
				free(buf);
				return;
			}

			memset(cmd, 0, sizeof (dm_command_t));
			cmd->cmd_flags |= CMD_INCOMING;
			cmd->cmd_root = root;
			cmd->cmd_task = task;
			if (dm_setup_incoming_cmd(cmd) != 0) {	/* setup cmd */
				/* Failed */
				dm_resp_unacceptable(6506, NULL);
				dm_destroy_cmd(cmd);
				free(buf);
				return;
			} else {
				pthread_mutex_lock(&wka->dm_queue_mutex);
				mms_list_insert_tail(&wka->dm_pend_ack_queue,
				    cmd);
				pthread_mutex_unlock(&wka->dm_queue_mutex);
			}
		}
	} else if (rc == 0) {
		/*
		 * Hit end of file or connection closed by MM
		 */
		TRACE((MMS_WARN, "dm_read_input: mms_reader error: hit EOF",
		    strerror(errno)));
		if (buf != NULL) {
			TRACE((MMS_INFO, "cmd = %s", buf));
		}

		/*
		 * Close current connection
		 */
		mms_close(&wka->dm_mms_conn);
		wka->dm_mms_conn.mms_fd = -1;
		wka->dm_flags &= ~DM_HAVE_SESSION;
		TRACE((MMS_OPER, "Exiting DM"));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Lost connection to MM"));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	} else {
		/*
		 * Got an error
		 */
		TRACE((MMS_CRIT, "dm_read_input: mms_reader error: %s",
		    strerror(errno)));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "mms_reader error: %s", strerror(errno)));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	}
	free(buf);
}

/*
 * Function name
 *	dm_responded_with(dm_command_t *cmd, char *keyword)
 *
 * Parameters:
 *	cmd	dm_command_t with the command
 *	keyword	keyword of response type
 *
 * Description:
 *	Check to see if the response matches the input keyword
 *
 * Return code:
 *	1	type matched
 *	0	type not matched
 *
 * Note:
 *
 *
 */

int
dm_responded_with(dm_command_t *cmd, char *keyword)
{
	if (mms_pn_lookup(cmd->cmd_root, keyword, MMS_PN_KEYWORD, NULL) ||
	    mms_pn_lookup(cmd->cmd_root, keyword, MMS_PN_CLAUSE, NULL)) {
		/* Found respond with keyword */
		return (1);
	} else {
		return (0);
	}
}

/*
 * Function name
 *	dm_accept_cmds(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	send accepted commands to all commands that have not been accepted
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_accept_cmds(void)
{
	dm_command_t	*cmd;
	dm_command_t	*next;
	int		rc;

	pthread_mutex_lock(&wka->dm_queue_mutex);
	mms_list_foreach_safe(&wka->dm_pend_ack_queue, cmd, next) {
		pthread_mutex_unlock(&wka->dm_queue_mutex);
		rc = dm_accept_cmd_aux(cmd);
		pthread_mutex_lock(&wka->dm_queue_mutex);
		next = mms_list_next(&wka->dm_pend_ack_queue, cmd);
		if (rc == 0) {
			/* Accept sent, move cmd to dispatch list */
			mms_list_remove(&wka->dm_pend_ack_queue, cmd);
			/* no error */
			mms_list_insert_tail(&wka->dm_cmd_queue, cmd);
			pthread_mutex_lock(&wka->dm_worker_mutex);
			/* wakeup worker thread to do work */
			cmd->cmd_flags |= CMD_DISPATCHABLE;
			wka->dm_cmd_dispatchable = 1;
			wka->dm_work_todo = 1;
			pthread_cond_broadcast(&wka->dm_work_cv);
			pthread_mutex_unlock(&wka->dm_worker_mutex);
		}
	}
	if (mms_list_empty(&wka->dm_pend_ack_queue)) {
		/* all commands accepted. enable writing commands */
		pthread_cond_broadcast(&wka->dm_accept_cv);
	}
	pthread_mutex_unlock(&wka->dm_queue_mutex);
}

/*
 * Function name
 *	dm_accept_cmd_aux(dm_command_t *cmd)
 *
 * Parameters:
 *	cmd	dm_command_t pointer
 *
 * Description:
 *	construct an accepted command and send it
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_accept_cmd_aux(dm_command_t *cmd)
{
	char		*accept;
	int		rc;
	int		err;

	if (cmd->cmd_task == NULL) {
		cmd->cmd_task = dm_get_task(cmd->cmd_root);
	}

	accept = mms_strnew("response task [ '%s' ] accepted;", cmd->cmd_task);
	rc = dm_writer_accept(accept);
	err = errno;
	if (rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to send accept to task %s: %s",
		    cmd->cmd_task, strerror(err)));
		dm_resp_unacceptable(6507, NULL);
		free(accept);
		return (-1);
	}
	free(accept);
	return (0);
}

/*
 * Function name
 *	dm_resp_unacceptable(int msgid, ...)
 *
 * Parameters:
 *	msgid	message id
 *	...	argument list, terminated by NULL.
 *
 * Description:
 *	send response unacceptable command
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_resp_unacceptable(int msgid, ...)
{
	char		*msgcl;
	char		*unacc;
	int		rc;
	va_list		args;

	/*
	 * Build a message clause
	 */
	va_start(args, msgid);
	msgcl = mms_bld_msgcl(msgid, args);
	va_end(args);

	unacc = mms_strnew("response unacceptable %s ;", msgcl);
	free(msgcl);

	rc = dm_writer_accept(unacc);
	if (rc == DM_ERROR) {
		TRACE((MMS_ERR, "dm_accept_cmd: mms_writer error: %s",
		    strerror(errno)));
	} else if (rc == DM_PARTIAL_WRITE) {
		TRACE((MMS_ERR, "dm_accept_cmd: mms_writer error: %s",
		    strerror(errno)));
	}
	free(unacc);
}

/*
 * Function name
 *	dm_resp_error(int msgid, ...)
 *
 * Parameters:
 *	msgid	message id
 *	...	argument list, terminated by NULL.
 *
 * Description:
 *	send response error command
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_resp_error(char *task, int msgid, ...)
{
	char		*rep;
	char		*msgcl;
	va_list		args;
	int		rc;

	/*
	 * Build a message clause
	 */
	va_start(args, msgid);
	msgcl = mms_bld_msgcl(msgid, args);
	va_end(args);

	rep = mms_strnew("response task [ '%s' ] "
	    "error [ '%s' '%s' ] %s ;",
	    task,
	    mms_sym_code_to_str(dm_msg_class()),
	    mms_sym_code_to_str(dm_msg_code()),
	    msgcl);
	free(msgcl);
	rc = dm_writer(rep);
	free(rep);
	if (rc == DM_ERROR) {
		TRACE((MMS_ERR, "dm_resp_error: mms_writer error: %s",
		    strerror(errno)));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "mms_writer error: %s", strerror(errno)));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	} else if (rc == DM_PARTIAL_WRITE) {
		TRACE((MMS_ERR, "dm_resp_error: mms_writer error: %s",
		    strerror(errno)));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "mms_writer error: %s", strerror(errno)));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	}
}


/*
 * Function name
 *	dm_resp_success(char *task, char *text)
 *
 * Parameters:
 *	task	task id
 *	text	content of text clause
 *
 * Description:
 *	send response success command
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_resp_success(char *task, char *text)
{
	char		*rep;
	char		*textcl = NULL;
	int		rc;

	if (text != NULL && text[0] != '\0') {
		textcl = mms_strnew("text [ '%s' ] ", text);
	}
	rep = mms_strnew("response task [ '%s' ] success %s;",
	    task, textcl == NULL ? "" : textcl);
	rc = dm_writer(rep);
	free(rep);
	free(textcl);
	if (rc == DM_ERROR) {
		TRACE((MMS_ERR, "dm_resp_success: mms_writer error: %s",
		    strerror(errno)));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "mms_writer error: %s", strerror(errno)));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	} else if (rc == DM_PARTIAL_WRITE) {
		TRACE((MMS_DEBUG, "dm_resp_success: mms_writer error: %s",
		    strerror(errno)));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "mms_writer error: %s", strerror(errno)));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	}
}

/*
 * Function name
 *	dm_send_message(char *who, char *severity, int msgid, ...)
 *
 * Parameters:
 *	who	who to send message to
 *	severity	severity of message
 *	msgid	message id
 *	...	variable list of arguments of the message ending with NULL
 *
 * Description:
 *	send a message to the administrator
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

void
dm_send_message(char *who, char *severity, int msgid, ...)
{
	char		*msg_cmd;
	char		*task;
	dm_command_t	*cmd;
	char		*msgcl;
	va_list		ap;

	task = dm_bld_task("message");
	va_start(ap, msgid);
	msgcl = mms_bld_msgcl(msgid, ap);
	va_end(ap);
	msg_cmd = mms_strnew("message task [ '%s' ] who [ %s ] "
	    "severity [ %s ] %s ;", task, who, severity, msgcl);
	cmd = dm_send_cmd(msg_cmd, dm_cmd_response, task);
	free(task);
	free(msgcl);
	free(msg_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		TRACE((MMS_ERR, "Unable to send message command"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return;
	}
	dm_destroy_cmd(cmd);
	dm_msg_destroy();			/* clean up message queue */
}

/*
 * Function name
 *	dm_send_ready(int msgid, ...)
 *
 * Parameters:
 *	msgid	message id
 *	...	variable list of arguments ending with NULL
 *
 * Description:
 *	send a ready command
 *
 * Return code:
 *
 *
 * Note:
 *
 *
 */

int
dm_send_ready(int msgid, ...)
{
	va_list		ap;
	int		rc;

	va_start(ap, msgid);
	rc = dm_send_ready_aux(NULL, msgid, ap);
	va_end(ap);
	return (rc);
}

/*
 * Function name
 *	dm_send_ready_broken(int msgid, ...)
 *
 * Parameters:
 *	msgid	message id
 *	...	arguments for message ending with NULL
 *
 * Description:
 *	send ready broken message
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_send_ready_broken(int msgid, ...)
{
	va_list		ap;
	int		rc;

	va_start(ap, msgid);
	rc = dm_send_ready_aux("broken", msgid, ap);
	va_end(ap);
	return (rc);
}

/*
 * Function name
 *	dm_send_ready_disconnected(int msgid, ...)
 *
 * Parameters:
 *	msgid	message id
 *	...	arguments for message ending with NULL
 *
 * Description:
 *	send ready disconnected message
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_send_ready_disconnected(int msgid, ...)
{
	va_list		ap;
	int		rc;

	va_start(ap, msgid);
	rc = dm_send_ready_aux("disconnected", msgid, ap);
	va_end(ap);
	return (rc);
}

/*
 * Function name
 *	dm_send_ready_not(int msgid, ...)
 *
 * Parameters:
 *	msgid	message id
 *	...	arguments for message ending with NULL
 *
 * Description:
 *	send ready not message
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_send_ready_not(int msgid, ...)
{
	va_list		ap;
	int		rc;

	va_start(ap, msgid);
	rc = dm_send_ready_aux("not", msgid, ap);
	va_end(ap);
	return (rc);
}

/*
 * Function name
 *	dm_send_ready_aux(char *spec, int msgid, va_list args)
 *
 * Parameters:
 *	spec	specific ready type
 *	msgid	message id
 *	args	variable length arg list terminated by NULL
 *
 * Description:
 *	construct a ready message and send it
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_send_ready_aux(char *spec, int msgid, va_list args)
{
	dm_command_t	*cmd;
	char		*ready_cmd;
	char		*task;
	char		*msgcl;

	/*
	 * Build a message clause
	 */
	msgcl = mms_bld_msgcl(msgid, args);

	task = dm_bld_task("ready");
	if (spec == NULL) {
		spec = "";
	}
	ready_cmd = mms_strnew("ready task['%s'] %s %s;", task, spec, msgcl);
	cmd = dm_send_cmd(ready_cmd, dm_cmd_response, task);
	free(task);
	free(msgcl);
	free(ready_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send ready command error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

/*
 * Function name
 *	dm_update_capacity(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	get capacity of cartridge and update the partition size in
 *	the PARTITION object.
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_update_capacity(void)
{
	int		rc = 0;

	if (drv->drv_flags & DRV_LOADED) {
		/*
		 * Read capacity from tape
		 */
		if (DRV_CALL(drv_get_capacity, (&drv->drv_cap)) == 0) {
			/* update capacity */
			if (dm_send_capacity(&drv->drv_cap) != 0) {
				DM_MSG_ADD((MMS_INTERNAL,
				    MMS_DM_E_INTERNAL,
				    "update capacity error"));
				rc = -1;
			}
		} else {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "cannot get cartridge capacity"));
		}
	}
	return (rc);
}

/*
 * Function name
 *	dm_send_capacity(mms_capacity_t *cap)
 *
 * Parameters:
 *	cap	addr of mms_capacity_t
 *
 * Description:
 *	send capacity to MM to update capacity
 *
 * Return code:
 *	o	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_send_capacity(mms_capacity_t *cap)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("send-capacity");
	attr_cmd = mms_strnew("attribute task['%s'] "
	    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(PARTITION.'PartitionName' '%s') "
	    "streq(DRIVE.'DriveName' '%s'))]"
	    "set[PARTITION.'PartitionSize' '%lld'] "
	    "set[PARTITION.'PartitionAvailable' '%lld'] "
	    "set[PARTITION.'PartitionPercentAvailable' '%d'] "
	    "set[CARTRIDGETYPE.'CartridgeTypeMediaLength' '%lld'] "
	    ";",
	    task, dca->dca_pcl, dca->dca_part_name, drv->drv_drvname,
	    cap->mms_max, cap->mms_avail, cap->mms_pc_avail, cap->mms_max);

	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(task);
	free(attr_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "update capacity error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

/*
 * Function name
 *	dm_send_loaded(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	update DriveStateHard to loaded
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_send_loaded(void)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	task = dm_bld_task("send-loaded");
	attr_cmd = mms_strnew("attribute task['%s'] "
	    "match[ streq(DRIVE.'DriveName' '%s') ] "
	    "set[DRIVE.'DriveStateHard' 'loaded'] "
	    "set[DRIVE.'DMName' '%s'] ;", task, DRVNAME, DMNAME);

	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(task);
	free(attr_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send loaded error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

/*
 * Function name
 *	dm_get_capacity(mms_par_node_t *root)
 *
 * Parameters:
 *	root	pointer to the parse tree
 *
 * Description:
 *	get capacity from the response of a show command and save it
 *	in drv->drv_avail.
 *
 * Return code:
 *	0	success
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_get_capacity(mms_par_node_t *root)
{
	char		*val;

	/*
	 * Save tape capacity
	 */
	val = dm_get_attr_value(root, "PARTITION", "PartitionSize");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get partition size"));
		return (-1);
	}

	sscanf(val, "%lld", (int64_t *)&drv->drv_capacity);

	val = dm_get_attr_value(root, "PARTITION", "PartitionAvailable");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get partition available"));
		return (-1);
	}

	sscanf(val, "%lld", (int64_t *)&drv->drv_avail);

	val = dm_get_attr_value(root, "PARTITION", "PartitionPercentAvailable");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get partition % available"));
		return (-1);
	}

	sscanf(val, "%d", (int32_t *)&drv->drv_pc_avail);
	return (0);
}

/*
 * Function name
 *	dm_show_mount_point(mms_par_node_t **typeroot)
 *
 * Parameters:
 *	typeroot	addr of pointer to root of response parse tree
 *
 * Description:
 *	Show mount points of all cartridges that can be mounted on
 *	the drive controlled by this DM.
 *
 * Return code:
 *	0	success - root of parse tree returned in typeroot.
 *	-1	error
 *
 * Note:
 *
 *
 */

int
dm_show_mount_point(mms_par_node_t **typeroot)
{
	char		*show_cmd;
	char		*task;
	dm_command_t	*cmd;

	/*
	 * Show mount points of all cartridges that can be mounted on
	 * the drive controlled by this DM.
	 */
	task = dm_bld_task("show-mount-point");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue unique] "
	    "match[and(streq(DM.'DMName' '%s') "
	    "streq(CARTRIDGETYPE.'CartridgeShapeName' 'DISK'))] "
	    "report[CARTRIDGE.'CartridgeMountPoint'] "
	    ";", task, drv->drv_dmname);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "show mount point error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	*typeroot = cmd->cmd_root;
	cmd->cmd_root = NULL;
	dm_destroy_cmd(cmd);
	return (0);
}

/*
 * Function name
 *	dm_show_virt_cart_path(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	show the path to a DISK cartridge
 *
 * Return code:
 *	pointer to path string. Caller must free after use.
 *	NULL	can't get path
 *
 * Note:
 *
 *
 */

char *
dm_show_virt_cart_path(void)
{
	char		*show_cmd;
	char		*task;
	mms_par_node_t	*root;
	dm_command_t	*cmd;
	char		*mp;
	char		*fn;
	char		*path;
	int		len;

	task = dm_bld_task("show-virt-cart-type");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[streq(CARTRIDGE.'CartridgePCL' '%s') ] "
	    "report[CARTRIDGE.'CartridgeMountPoint' CARTRIDGE.'CartridgePath' ]"
	    ";", task, mnt->mnt_pcl);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "show virt cart type error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (NULL);
	}
	root = cmd->cmd_root;
	mp = dm_get_attr_value(root, "CARTRIDGE", "CartridgeMountPoint");
	len = strlen(mp);
	if (mp[len - 1] == '/') {
		mp[len - 1] = '\0';
	}
	fn = dm_get_attr_value(root, "CARTRIDGE", "CartridgePath");

	path = mms_strnew("%s/%s", mp, fn);
	dm_destroy_cmd(cmd);
	return (path);
}

int
dm_show_eof_pos(void)
{
	char		*show_cmd;
	char		*task;
	mms_par_node_t	*root;
	dm_command_t	*cmd;
	char		*val;
	int		eof;
	int		pmode;

	task = dm_bld_task("show-eof-pos");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(SIDE.'SideName' '%s') "
	    "streq(PARTITION.'PartitionName' '%s') "
	    "streq(DRIVE.'DriveName' '%s'))]"
	    "report[ PARTITION.'PartitionEOFPos' ]"
	    ";",
	    task, dca->dca_pcl, dca->dca_side_name, dca->dca_part_name,
	    drv->drv_drvname);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "show eof position error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	root = cmd->cmd_root;

	/*
	 * Save EOF position
	 */
	val = dm_get_attr_value(root, "PARTITION", "PartitionEOFPos");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get EOF position"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	drv->drv_flags &= ~DRV_VALID_EOF_POS;		/* assume no eof pos */
	if (strcmp(val, "none") != 0) {
		/* EOF position is valid */
		if (sscanf(val, "%lld %d %d %d %d %d",
		    (int64_t *)&drv->drv_eof_pos.lgclblkno,
		    &drv->drv_eof_pos.fileno,
		    &drv->drv_eof_pos.blkno,
		    &drv->drv_eof_pos.partition,
		    &eof, &pmode) == 6) {
			drv->drv_eof_pos.eof = eof;
			drv->drv_eof_pos.pmode = pmode;

			drv->drv_flags |= DRV_VALID_EOF_POS;
		}
	}

	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_send_eof_pos(void)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("update-eof-pos");
	if (drv->drv_flags & DRV_VALID_EOF_POS) {
		attr_cmd = mms_strnew("attribute task['%s'] "
		    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
		    "streq(SIDE.'SideName' '%s') "
		    "streq(PARTITION.'PartitionName' '%s') "
		    "streq(DRIVE.'DriveName' '%s'))]"
		    "set[PARTITION.'PartitionEOFPos' '%lld %d %d %d %d %d '] "
		    ";",
		    task, dca->dca_pcl, dca->dca_side_name, dca->dca_part_name,
		    drv->drv_drvname,
		    drv->drv_eof_pos.lgclblkno,
		    drv->drv_eof_pos.fileno,
		    drv->drv_eof_pos.blkno,
		    drv->drv_eof_pos.partition,
		    drv->drv_eof_pos.eof,
		    drv->drv_eof_pos.pmode);
	} else {
		attr_cmd = mms_strnew("attribute task['%s'] "
		    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
		    "streq(SIDE.'SideName' '%s') "
		    "streq(PARTITION.'PartitionName' '%s') "
		    "streq(DRIVE.'DriveName' '%s'))]"
		    "unset[PARTITION.'PartitionEOFPos'] "
		    ";",
		    task, dca->dca_pcl, dca->dca_side_name, dca->dca_part_name,
		    drv->drv_drvname);
	}
	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(task);
	free(attr_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send eof position error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_send_write_protect(int wp)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("update-write-protect");
	attr_cmd = mms_strnew("attribute task['%s'] "
	    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(SIDE.'SideName' '%s') "
	    "streq(PARTITION.'PartitionName' '%s') "
	    "streq(DRIVE.'DriveName' '%s'))]"
	    "set[CARTRIDGE.'CartridgeWriteProtected' '%s'] "
	    ";",
	    task, dca->dca_pcl, dca->dca_side_name, dca->dca_part_name,
	    drv->drv_drvname,
	    wp ? "yes" : "no");
	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(task);
	free(attr_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send write protect error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_show_dca_info(mms_par_node_t **rt)
{
	char		*show_cmd;
	char		*val;
	char		*task;
	dm_command_t	*cmd;
	mms_par_node_t	*root;

	memset(dca, 0, sizeof (drv_cart_access_t));
	task = dm_bld_task("show-dca-info");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ and( streq(DRIVE.'DriveName' '%s') "
	    "streq(VOLUME.'VolumeName' '%s')) ] "
	    "report[ "
	    "DRIVE.'DriveTimeMountedLast' "
	    "DRIVE.'DriveShapeName' "
	    "CARTRIDGETYPE.'CartridgeShapeName' "
	    "CARTRIDGETYPE.'CartridgeTypeMediaType' "
	    "CARTRIDGE.'CartridgeNumberMounts' "
	    "PARTITION.'SideName' "
	    "PARTITION.'PartitionName' "
	    "PARTITION.'CartridgeID' "
	    "PARTITION.'PartitionRWMode' "
	    "PARTITION.'PartitionSize' "
	    "PARTITION.'PartitionAvailable' "
	    "PARTITION.'PartitionPercentAvailable' "
	    "PARTITION.'PartitionEOFPos' "
	    "] ;", task, DRVNAME, mnt->mnt_volumename);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send show dca info error"));
		goto error;
	}

	root = cmd->cmd_root;
	val = dm_get_attr_value(root, "PARTITION", "SideName");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get side name"));
		goto error;
	}
	dca->dca_side_name = strdup(val);

	val = dm_get_attr_value(root, "PARTITION", "PartitionName");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get partition name"));
		goto error;
	}
	dca->dca_part_name = strdup(val);

	val = dm_get_attr_value(root, "CARTRIDGE", "CartridgeID");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get cartridge ID"));
		goto error;
	}
	dca->dca_cart_id = strdup(val);

	val = dm_get_attr_value(root, "DRIVE", "DriveTimeMountedLast");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get DriveTimeMountedLast"));
		goto error;
	}
	dm_mms_to_db_time(val);
	dca->dca_mounted_last = strdup(val);

	val = dm_get_attr_value(root, "CARTRIDGETYPE", "CartridgeShapeName");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get CartridgeShapeName"));
		goto error;
	}
	dca->dca_cart_shape_name = strdup(val);

	val = dm_get_attr_value(root, "DRIVE", "DriveShapeName");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get DriveShapeName"));
		goto error;
	}
	dca->dca_drv_shape_name = strdup(val);

	dca->dca_pcl = strdup(mnt->mnt_pcl);

	dca->dca_flags |= DRV_DCA_VALID;
	*rt = cmd->cmd_root;
	cmd->cmd_root = NULL;
	dm_destroy_cmd(cmd);
	return (0);

error:
	dm_destroy_dca();
	if (cmd != NULL) {
		dm_destroy_cmd(cmd);
	}
	return (-1);
}

int
dm_show_application(mms_par_node_t **rt)
{
	char		*show_cmd;
	char		*task;
	dm_command_t	*cmd;

	task = dm_bld_task("show-application");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ streq(VOLUME.'VolumeName' '%s') ] "
	    "report[ "
	    "APPLICATION "
	    "] ;", task, mnt->mnt_volumename);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(task);
	free(show_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send show application error"));
		goto error;
	}

	*rt = cmd->cmd_root;
	cmd->cmd_root = NULL;
	dm_destroy_cmd(cmd);
	return (0);

error:
	if (cmd != NULL) {
		dm_destroy_cmd(cmd);
	}
	return (-1);
}

int
dm_send_error(void)
{
	char		*create_cmd;
	char		*ts;
	char		sense[200];
	char		cdb[64];
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	/*
	 * Create DRIVECARTRIDGEERROR
	 */
	task = dm_bld_task("create-drive-cart-error");
	ts = dm_timestamp();
	create_cmd = mms_strnew("create task['%s'] "
	    "type [ DRIVECARTRIDGEERROR ] "
	    "set[DRIVECARTRIDGEERROR.'DriveName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'DMName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'CartridgeID' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'SideName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'PartitionName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'ApplicationName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'CartridgePCL' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'DriveSerialNum' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'CartridgeShapeName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'DriveShapeName' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'SCSICommand' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'TimeStamp' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'CDB' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'IOStatus' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'SenseKey' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'AdditionalSenseCode' '%2.2x' ] "
	    "set[DRIVECARTRIDGEERROR.'AdditionalSenseCodeQualifier' '%2.2x' ] "
	    "set[DRIVECARTRIDGEERROR.'SenseBytes' '%s' ] "
	    "set[DRIVECARTRIDGEERROR.'ErrorText' '%s' ] "
	    ";",
	    task, DRVNAME, DMNAME,
	    dca->dca_cart_id == NULL ? "None" : dca->dca_cart_id,
	    dca->dca_side_name == NULL ? "None" : dca->dca_side_name,
	    dca->dca_part_name == NULL ? "None" : dca->dca_part_name,
	    dca->dca_app_name == NULL ? "None" : dca->dca_app_name,
	    dca->dca_pcl == NULL ? "None" : dca->dca_pcl,
	    drv->drv_serial_num == NULL ? "None" : drv->drv_serial_num,
	    dca->dca_cart_shape_name ==
	    NULL ? "None" : dca->dca_cart_shape_name,
	    dca->dca_drv_shape_name == NULL ? "None" : dca->dca_drv_shape_name,
	    mms_scsi_cmd(serr->se_cdb[0]),
	    ts,
	    dm_char_to_hex(serr->se_cdb, serr->se_cdblen, cdb, sizeof (cdb)),
	    mms_scsi_status(serr->se_status),
	    mms_scsi_sensekey(serr->se_senkey),
	    serr->se_asc,
	    serr->se_ascq,
	    serr->se_senkey == KEY_NO_SENSE ? "No sense" :
	    dm_char_to_hex(serr->se_sense, serr->se_senlen,
	    sense, sizeof (sense)),
	    (serr->se_err_text == NULL) ? "unknown error" : serr->se_err_text);
	free(ts);
	cmd = dm_send_cmd(create_cmd, dm_cmd_response, task);
	free(task);
	free(create_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send drive cartridge error error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_send_clean_request(void)
{
	char		*clean_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("cleaning-request");
	clean_cmd = mms_strnew("private task['%s'] "
	    "set[DRIVE.'DriveNeedsCleaning' 'true'] "
	    ";", task);

	cmd = dm_send_cmd(clean_cmd, dm_cmd_response, task);
	free(task);
	free(clean_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send drive needs cleaning error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_send_statistics(void)
{
	char		*create_cmd;
	char		*unmnttime;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	/*
	 * Create DRIVECARTRIDGEACCESS
	 */
	task = dm_bld_task("create-drive-cart-access");
	unmnttime = dm_timestamp();
	create_cmd = mms_strnew("create task['%s'] "
	    "type [ DRIVECARTRIDGEACCESS ] "
	    "set[DRIVECARTRIDGEACCESS.'DriveName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'DMName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'CartridgeID' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'SideName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'PartitionName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'ApplicationName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'CartridgePCL' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'DriveSerialNum' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'CartridgeShapeName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'DriveShapeName' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS.'DriveCartridgeAccessTimeMount' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessTimeUnmount' '%s' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessByteReadCount' '%lld' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessMediumByteReadCount' '%lld' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessByteWriteCount' '%lld' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessMediumByteWriteCount' '%lld' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessHardReadErrorCount' '%d' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessSoftReadErrorCount' '%d' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessHardWriteErrorCount' '%d' ] "
	    "set[DRIVECARTRIDGEACCESS."
	    "'DriveCartridgeAccessSoftWriteErrorCount' '%d' ] "
	    ";", task, DRVNAME, DMNAME,
	    dca->dca_cart_id == NULL ? "None" : dca->dca_cart_id,
	    dca->dca_side_name == NULL ? "None" : dca->dca_side_name,
	    dca->dca_part_name == NULL ? "None" : dca->dca_part_name,
	    dca->dca_app_name == NULL ? "None" : dca->dca_app_name,
	    dca->dca_pcl == NULL ? "None" : dca->dca_pcl,
	    drv->drv_serial_num == NULL ? "None" : drv->drv_serial_num,
	    dca->dca_cart_shape_name ==
	    NULL ? "None" : dca->dca_cart_shape_name,
	    dca->dca_drv_shape_name == NULL ? "None" : dca->dca_drv_shape_name,
	    dca->dca_mounted_last,
	    unmnttime,
	    dca->dca_bytes_read,
	    dca->dca_bytes_read_med,
	    dca->dca_bytes_written,
	    dca->dca_bytes_written_med,
	    dca->dca_read_err,
	    dca->dca_rcvd_read_err,
	    dca->dca_write_err,
	    dca->dca_rcvd_write_err);
	free(unmnttime);
	cmd = dm_send_cmd(create_cmd, dm_cmd_response, task);
	free(task);
	free(create_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send drive cartridge access error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	dm_destroy_dca();
	dm_destroy_cmd(cmd);
	return (0);
}

void
dm_destroy_dca(void)
{
	if (dca->dca_side_name)
		free(dca->dca_side_name);
	if (dca->dca_part_name)
		free(dca->dca_part_name);
	if (dca->dca_app_name)
		free(dca->dca_app_name);
	if (dca->dca_cart_id)
		free(dca->dca_cart_id);
	if (dca->dca_mounted_last)
		free(dca->dca_mounted_last);
	if (dca->dca_cart_shape_name)
		free(dca->dca_cart_shape_name);
	if (dca->dca_drv_shape_name)
		free(dca->dca_drv_shape_name);
	if (dca->dca_pcl)
		free(dca->dca_pcl);
	memset(dca, 0, sizeof (drv_cart_access_t));
}

char *
dm_timestamp(void)
{
	struct	timeval	tv;
	struct	tm	*cl;
	char	*buf;

	gettimeofday(&tv, NULL);
	time(&tv.tv_sec);
	cl = localtime(&tv.tv_sec);
	buf = mms_strnew("%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d.%3.3d",
	    cl->tm_year + 1900,
	    cl->tm_mon + 1,
	    cl->tm_mday,
	    cl->tm_hour,
	    cl->tm_min,
	    cl->tm_sec,
	    (int32_t)tv.tv_usec / 1000);
	return (buf);
}

void
dm_mms_to_db_time(char *db)
{
	db[4] = '-';
	db[7] = '-';
	db[13] = ':';
	db[16] = ':';
	db[19] = '.';
}

int
dm_send_drive_broken(void)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("set-drive-broken");
	attr_cmd = mms_strnew("attribute task['%s'] "
	    "match[ streq(DRIVE.'DriveName' '%s') ] "
	    "set[DRIVE.'DriveBroken' '%s'] "
	    ";", task, DRVNAME, "true");
	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(attr_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send drive broken error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_send_cartridge_media_error(void)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("set-cart-media-error");
	attr_cmd = mms_strnew("attribute task['%s'] "
	    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(SIDE.'SideName' '%s') "
	    "streq(PARTITION.'PartitionName' '%s') "
	    "streq(DRIVE.'DriveName' '%s'))]"
	    "set[CARTRIDGE.'CartridgeMediaError' '%s'] "
	    ";",
	    task, dca->dca_pcl, dca->dca_side_name, dca->dca_part_name,
	    drv->drv_drvname,
	    "yes");
	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(attr_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send cartridge media error error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_show_drive_dmname(char **dmname)
{
	char		*show_cmd;
	char		*task;
	mms_par_node_t	*root;
	dm_command_t	*cmd;
	char		*val;

	*dmname = NULL;
	task = dm_bld_task("drive-dmname");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ streq(DRIVE.'DriveName' '%s') ] "
	    "report[DRIVE.'DMName'] ;", task, DRVNAME);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(show_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send show command error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	root = cmd->cmd_root;

	/*
	 * Save drive dmname
	 */
	val = dm_get_attr_value(root, "DRIVE", "DMName");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get drive DMName"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	*dmname = strdup(val);

	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_show_system(mms_par_node_t ** root)
{
	char		*show_cmd;
	char		*task;
	dm_command_t	*cmd;

	task = dm_bld_task("show-system");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "report[SYSTEM] ;", task);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(show_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to send show SYSTEM command"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	*root = cmd->cmd_root;
	cmd->cmd_root = NULL;
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_show_drive(mms_par_node_t ** root)
{
	char		*show_cmd;
	char		*task;
	dm_command_t	*cmd;

	task = dm_bld_task("show-drive");
	show_cmd = mms_strnew("show task['%s'] reportmode[namevalue] "
	    "match[ streq(DRIVE.'DriveName' '%s') ] "
	    "report[DRIVE] ;",
	    task, DRVNAME);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(show_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send show drive error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	*root = cmd->cmd_root;
	cmd->cmd_root = NULL;
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_cmd_response(dm_command_t *cmd)
{
	mms_par_node_t	*root;
	mms_par_node_t	*id = NULL;
	mms_par_node_t	*man = NULL;
	mms_par_node_t	*mod = NULL;
	mms_par_node_t	*msgid = NULL;
	mms_par_node_t	*work = NULL;

	root = mms_pn_lookup(cmd->cmd_root, NULL, MMS_PN_CMD, NULL);
	switch (cmd->cmd_state) {
	case 0:
		/*
		 * check for accept
		 */
		if (dm_responded_with(cmd, "accepted")) {
			TRACE((MMS_INFO, "Command %s accepted",
			    mms_pn_token(root)));
			cmd->cmd_state++;
			return (DM_CONTINUE);
		} else if (dm_responded_with(cmd, "unacceptable")) {
			id = mms_pn_lookup(root, "id", MMS_PN_CLAUSE,
			    NULL);
			if (id != NULL) {
				work = NULL;
				man = mms_pn_lookup(id, NULL,
				    MMS_PN_STRING, &work);
				mod = mms_pn_lookup(id, NULL,
				    MMS_PN_STRING, &work);
				msgid = mms_pn_lookup(id, NULL,
				    MMS_PN_STRING, &work);
			}
			TRACE((MMS_ERR, "Command %s unacceptable, "
			    "manufacturer '%s', model '%s', msgid '%s'",
			    mms_pn_token(root),
			    man == NULL ? "[none]" : mms_pn_token(man),
			    mod == NULL ? "[none]" : mms_pn_token(mod),
			    msgid == NULL ? "[none]" : mms_pn_token(msgid)));
			cmd->cmd_rc = -1;
		} else if (dm_responded_with(cmd, "cancelled")) {
			id = mms_pn_lookup(root, "id", MMS_PN_CLAUSE,
			    NULL);
			if (id != NULL) {
				work = NULL;
				man = mms_pn_lookup(id, NULL,
				    MMS_PN_STRING, &work);
				mod = mms_pn_lookup(id, NULL,
				    MMS_PN_STRING, &work);
				msgid = mms_pn_lookup(id, NULL,
				    MMS_PN_STRING, &work);
			}
			TRACE((MMS_ERR, "Command %s cancelled, "
			    "manufacturer '%s', model '%s', msgid '%s'",
			    mms_pn_token(root),
			    man == NULL ? "[none]" : mms_pn_token(man),
			    mod == NULL ? "[none]" : mms_pn_token(mod),
			    msgid == NULL ? "[none]" :
			    mms_pn_token(msgid)));
			cmd->cmd_rc = -1;
		}
		return (DM_COMPLETE);

	case 1:
		/*
		 * check for success
		 */
		if (dm_responded_with(cmd, "success")) {
			return (DM_COMPLETE);
		} else if (dm_responded_with(cmd, "cancelled")) {
			TRACE((MMS_CRIT, "Unable to config DM, "
			    "command cancelled"));
			cmd->cmd_rc = -1;
			return (DM_COMPLETE);
		} else if (dm_responded_with(cmd, "error")) {
			TRACE((MMS_CRIT, "Unable to config DM, "
			    "command had error"));
			cmd->cmd_rc = -1;
			return (DM_COMPLETE);
		} else {
			TRACE((MMS_CRIT, "Unexpected response from MM"));
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "Unexpected response from MM"));
			DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
			DM_EXIT(DM_NO_RESTART);
		}
default:
		/*
		 * Should not happen
		 */
		TRACE((MMS_CRIT, "Unexpected cmd state: %d", cmd->cmd_state));
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Unexpected cmd state: %d", cmd->cmd_state));
		DM_MSG_SEND((DM_ADM_ERR, DM_6526_MSG, NULL));
		DM_EXIT(DM_RESTART);
	}

	return (DM_COMPLETE);
}

void
dm_dispatch_cmds(void)
{
	dm_command_t	*cmd;
	dm_command_t	*next;
	int		rc = DM_NOT_COMPLETE;	/* not complete yet */

	pthread_mutex_lock(&wka->dm_worker_mutex);
	while (wka->dm_cmd_dispatchable) {
		wka->dm_cmd_dispatchable = 0;
		pthread_mutex_unlock(&wka->dm_worker_mutex);
		/* Dispatch commands */
		pthread_mutex_lock(&wka->dm_queue_mutex);
		mms_list_foreach_safe(&wka->dm_cmd_queue, cmd, next) {
			if (cmd->cmd_flags & CMD_DISPATCHABLE) {
				cmd->cmd_flags &= ~CMD_DISPATCHABLE;
				/*
				 * dispatch the command
				 */
				dm_msg_destroy();	/* clean up messages */
				if (cmd->cmd_func != NULL) {
					pthread_mutex_unlock(&wka->
					    dm_queue_mutex);
					rc = (cmd->cmd_func) (cmd);
					pthread_mutex_lock(&wka->
					    dm_queue_mutex);
					next = mms_list_next(&wka->dm_cmd_queue,
					    cmd);
				}
				if (rc == DM_COMPLETE) {
					if (cmd->cmd_flags & CMD_INCOMING) {
						/* Incoming command completes */
						mms_list_remove(&wka->
						    dm_cmd_queue, cmd);
						dm_destroy_cmd(cmd);
					}
				}
				dm_msg_destroy();	/* clean up messages */
			}
		}
		pthread_mutex_unlock(&wka->dm_queue_mutex);
		pthread_mutex_lock(&wka->dm_worker_mutex);
	}
	pthread_mutex_unlock(&wka->dm_worker_mutex);
}

void
dm_destroy_cmd(dm_command_t *cmd)
{
	if (cmd->cmd_root) {
		mms_pn_destroy(cmd->cmd_root);
	}
	if (cmd->cmd_task) {
		free(cmd->cmd_task);
	}
	if (cmd->cmd_textcmd) {
		free(cmd->cmd_textcmd);
	}
	free(cmd);
}

dm_command_t *
dm_send_cmd(char *cmdbuf, int (*cmd_func) (dm_command_t *), char *task)
{
	dm_command_t	*cmd;

	/* Build dm_command_t */
	cmd = (dm_command_t *)malloc(sizeof (dm_command_t));
	if (cmd == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send command error: out of memory"));
		return (NULL);
	}
	memset(cmd, 0, sizeof (dm_command_t));
	cmd->cmd_textcmd = strdup(cmdbuf);
	cmd->cmd_func = cmd_func;
	cmd->cmd_task = strdup(task);
	pthread_cond_init(&cmd->cmd_done_cv, NULL);
	pthread_mutex_init(&cmd->cmd_done_mutex, NULL);

	/* Put command in cmd_queue */
	pthread_mutex_lock(&wka->dm_queue_mutex);
	mms_list_insert_tail(&wka->dm_cmd_queue, cmd);
	pthread_mutex_unlock(&wka->dm_queue_mutex);
	/* send cmd */
	if (dm_writer(cmdbuf) != 0) {
		pthread_mutex_lock(&wka->dm_queue_mutex);
		mms_list_remove(&wka->dm_cmd_queue, cmd);
		TRACE((MMS_DEBUG, "send cmd %p removed from dm_cmd_queue",
		    cmd));
		pthread_mutex_unlock(&wka->dm_queue_mutex);
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_COMMUNICATION,
		    "unable to send command to MM: socket write error"));
		dm_destroy_cmd(cmd);
		return (NULL);
	}

	/*
	 * Wait for command to complete
	 */
	mms_trace_flush();
	pthread_mutex_lock(&cmd->cmd_done_mutex);
	while ((cmd->cmd_flags & CMD_COMPLETE) == 0) {
		pthread_cond_wait(&cmd->cmd_done_cv, &cmd->cmd_done_mutex);
	}
	pthread_mutex_unlock(&cmd->cmd_done_mutex);

	pthread_mutex_lock(&wka->dm_queue_mutex);
	mms_list_remove(&wka->dm_cmd_queue, cmd);
	pthread_mutex_unlock(&wka->dm_queue_mutex);

	pthread_cond_destroy(&cmd->cmd_done_cv);
	pthread_mutex_destroy(&cmd->cmd_done_mutex);

	return (cmd);
}

int
dm_setup_incoming_cmd(dm_command_t *cmd)
{
	mms_par_node_t	*root;

	mms_trace_flush();
	root = mms_pn_lookup(cmd->cmd_root, NULL, MMS_PN_CMD, NULL);
	if (strcmp(mms_pn_token(root), "activate") == 0) {
		cmd->cmd_func = dm_activate_cmd;
	} else if (strcmp(mms_pn_token(root), "attach") == 0) {
		cmd->cmd_func = dm_attach_cmd;
	} else if (strcmp(mms_pn_token(root), "private") == 0) {
		cmd->cmd_func = dm_dmpm_private_cmd;
	} else if (strcmp(mms_pn_token(root), "load") == 0) {
		cmd->cmd_func = dm_load_cmd;
	} else if (strcmp(mms_pn_token(root), "identify") == 0) {
		cmd->cmd_func = dm_identify_cmd;
	} else if (strcmp(mms_pn_token(root), "detach") == 0) {
		cmd->cmd_func = dm_detach_cmd;
	} else if (strcmp(mms_pn_token(root), "unload") == 0) {
		cmd->cmd_func = dm_unload_cmd;
	} else if (strcmp(mms_pn_token(root), "reset") == 0) {
		cmd->cmd_func = (int (*)(dm_command_t *))dm_reset_cmd;
	} else if (strcmp(mms_pn_token(root), "exit") == 0) {
		cmd->cmd_func = (int (*)(dm_command_t *))dm_exit_cmd;
	} else {
		/* Unknown command */
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_UNSUPPORTED,
		    "Unsupported command %s", mms_pn_token(root)));
		return (-1);
	}
	return (0);
}

int
dm_send_config(void)
{
	char		*cfg_cmd;
	char		*task;
	dm_command_t	*cmd;

	task = dm_bld_task("config");
	cfg_cmd = dm_bld_config_cmd(task);
	if (cfg_cmd == NULL) {
		free(task);
		return (-1);
	}
	cmd = dm_send_cmd(cfg_cmd, dm_cmd_response, task);
	free(task);
	free(cfg_cmd);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "send config command error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_activate_cmd(dm_command_t *cmd)
{
	mms_par_node_t	*node;
	int		rc;

	node = mms_pn_lookup(cmd->cmd_root, NULL, MMS_PN_KEYWORD, NULL);
	if (strcmp(mms_pn_token(node), "enable") == 0) {
		/* Enable DM */
		rc = dm_activate_enable(cmd);
	} else if (strcmp(mms_pn_token(node), "disable") == 0) {
		/* Disable DM */
		rc = dm_activate_disable(cmd);
	} else if (strcmp(mms_pn_token(node), "reserve") == 0) {
		/* Reserve Drive */
		rc = dm_activate_reserve(cmd);
	} else if (strcmp(mms_pn_token(node), "release") == 0) {
		/* Release Drive */
		rc = dm_activate_release(cmd);
	}

	return (rc);
}

/*
 * Activate DM
 * - send contact drive and send config
 */
int
dm_activate_enable(dm_command_t *cmd)
{
	if (drv->drv_flags & DRV_ENABLED) {
		/* Already enabled */
		DM_MSG_ADD((MMS_STATE, MMS_DM_E_ENABLED,
		    "already enabled"));
		goto error;
	}

	/*
	 * Have to re-open the DM device to unbind the target device
	 * so that we may probe all the devices to find the one with
	 * the matching serial number.
	 */
	if (dm_open_dm_device() != 0) {
		DM_MSG_ADD((MMS_STATE, MMS_DM_E_INTERNAL,
		    "reopen DM device error"));
		goto error;
	}

	/*
	 * default size of sense data
	 */
	drv->drv_mtee_stat_len = sizeof (struct scsi_extended_sense);

	/*
	 * Close all the device dynamic libraries
	 */
	if (wka->dm_default_lib_hdl) {
		dlclose(wka->dm_default_lib_hdl);
	}
	if (wka->dm_dev_lib_hdl) {
		dlclose(wka->dm_dev_lib_hdl);
	}

	/*
	 * Load default device library
	 */
	if (dm_load_default_lib() != 0) {
		goto error1;
	}

	/*
	 * Get system options
	 */
	if (dm_get_system_options() != 0) {
		goto error1;
	}

	/*
	 * Get DM target path
	 */
	if (dm_get_target_base() != 0 ||
	    wka->dm_target_base == NULL) {
		goto error1;
	}

	/*
	 * configure device
	 */
	if (dm_stat_targ_base() != 0) {
		goto error1;
	}

	/*
	 * Connect to target drive
	 */
	if (dm_bind_target() != 0) {
		goto error1;
	}
	/*
	 * Load the device dependent library
	 */
	if (dm_load_devlib() != 0) {
		goto error1;
	}

	if (DRV_CALL(drv_rebind_target, ()) != 0) {
		goto error1;
	}

	if (DRV_CALL(drv_init_dev, ())) {
		goto error1;
	}

	/*
	 * Get sense data size
	 */
	dm_init_sense_buf();

	if (dm_update_drivetype() != 0) {
		goto error1;
	}

	/*
	 * Make prsv key and set it in dmd.
	 */
	DRV_CALL(drv_mk_prsv_key, ());

	/*
	 * Set up disallowed USCSI commands and ioctl
	 */
	DRV_CALL(drv_disallowed, ());

	/*
	 * Tell driver we are ready
	 */
	ioctl(wka->dm_drm_fd, DRM_DM_READY, 1);
	TRACE((MMS_DEVP, "main: DM is ready"));

	/*
	 * Send config to MM
	 */
	if (dm_send_config() != 0) {
		goto error1;
	}

	drv->drv_flags |= DRV_ENABLED;
	dm_resp_success(cmd->cmd_task, NULL);

	return (DM_COMPLETE);

error1:
	(void) dm_send_ready_disconnected(DM_6501_MSG, "type", "enable", NULL);
error:
	dm_resp_error(cmd->cmd_task, DM_6501_MSG, "type", "enable", NULL);
	return (DM_COMPLETE);
}

/*
 * Activate DM
 * - reserve the drive
 */
int
dm_activate_reserve(dm_command_t *cmd)
{
	/*
	 * Start timing mount time
	 */
	gettimeofday(&wka->dm_mnt_start, NULL);

	/*
	 * Get system options. Use what we know if error.
	 */
	if (dm_get_system_options() != 0) {
		goto error;
	}

	/*
	 * Check if reserve drive
	 */
	if ((wka->dm_flags & DM_RESERVE_DRIVE) == 0) {
		/* Don't reserve drive */
		goto success;
	}

	/*
	 * Reserve target
	 */
	if (dm_reserve_target() != 0) {
		goto error;
	}
success:
	dm_resp_success(cmd->cmd_task, NULL);
	return (DM_COMPLETE);

error:
	dm_resp_error(cmd->cmd_task, DM_6501_MSG, "type", "reserve", NULL);
	return (DM_COMPLETE);
}

int
dm_activate_release(dm_command_t *cmd)
{
	if ((wka->dm_flags & DM_RESERVE_DRIVE) == 0) {
		/* Didn't reserve drive */
		dm_resp_success(cmd->cmd_task, NULL);
		return (DM_COMPLETE);
	}

	if (drv->drv_flags & DRV_RESERVED) {
		/*
		 * Release is always successful.
		 * If there is any problem, let
		 * activate reserve take care of it.
		 */
		if (wka->dm_flags & DM_USE_PRSV) {
			/* Do persistent release */
			if (DRV_CALL(drv_prsv_register, ()) ||
			    DRV_CALL(drv_prsv_release, ())) {
				goto error;
			}
		/* Do SCSI release */
		} else if (DRV_CALL(drv_release, ()) != 0) {
			goto error;
		}
	}
	dm_resp_success(cmd->cmd_task, NULL);
	return (DM_COMPLETE);

error:
	dm_resp_error(cmd->cmd_task, DM_6501_MSG, "type", "release", NULL);
	return (DM_COMPLETE);
}

int
dm_activate_disable(dm_command_t *cmd)
{
	/* success */
	drv->drv_flags &= ~DRV_ENABLED;
	dm_resp_success(cmd->cmd_task, NULL);

	return (DM_COMPLETE);
}

int
dm_dmpm_private_cmd(dm_command_t *cmd)
{
	int		len;

	memset(mnt, 0, sizeof (drv_mount_t));
	mnt->mnt_blksize = -1;
	mnt->mnt_fseq = -1;		/* fseq not specified */
	if (dm_get_mount_options(cmd) != 0) {
		/* had error */
		dm_resp_error(cmd->cmd_task, DM_6507_MSG, NULL);
		return (DM_COMPLETE);
	}
	/*
	 * If a private cmd for mounting, check to see if authorized to
	 * use tape
	 */
	if (mnt->mnt_user) {
		if (dm_chk_dev_auth(mnt->mnt_user) != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "User %s is not authorized to use MMS",
			    mnt->mnt_user));
			dm_resp_error(cmd->cmd_task, DM_6527_MSG, NULL);
			return (DM_COMPLETE);
		}
	}

	/*
	 * Set up default options
	 */
	if (mnt->mnt_fseq == -1) {
		mnt->mnt_fseq = 1;
	}
	if (mnt->mnt_vid == NULL && mnt->mnt_pcl != NULL) {
		mnt->mnt_vid = strdup(mnt->mnt_pcl);
	}
	if (mnt->mnt_fname == NULL && mnt->mnt_volumename != NULL) {
		/* Filename defaults to volumename */
		mnt->mnt_fname = malloc(18);
		if (mnt->mnt_fname == NULL) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "out of memory"));
			dm_resp_error(cmd->cmd_task, DM_6506_MSG, NULL);
			return (DM_COMPLETE);
		}
		memset(mnt->mnt_fname, ' ', 17);
		mnt->mnt_fname[17] = '\0';
		len = strlen(mnt->mnt_volumename);
		if (len > 17) {
			strncpy(mnt->mnt_fname,
			    mnt->mnt_volumename + (len - 17), 17);
		} else {
			strncpy(mnt->mnt_fname, mnt->mnt_volumename, len);
		}
	}
	if (mnt->mnt_flags & MNT_MMS) {
		/* In MMS mode */
		if (!(mnt->mnt_flags & (MNT_BSD | MNT_NOBSD | MNT_MMS_TM))) {
			/* set default if no TM processing option */
			mnt->mnt_flags |= MNT_MMS_TM;
		}
	} else {
		/*
		 * Raw mode
		 */
		if (!(mnt->mnt_flags & (MNT_BSD | MNT_NOBSD | MNT_MMS_TM))) {
			/* set default if no TM processing option */
			mnt->mnt_flags |= MNT_NOBSD;
		}
	}

	dm_resp_success(cmd->cmd_task, NULL);

	return (DM_COMPLETE);
}

int
dm_get_mount_options(dm_command_t *cmd)
{
	mms_par_node_t	*name;
	mms_par_node_t	*val;
	mms_par_node_t	*set;
	mms_par_node_t	*work = NULL;
	char		*np;
	char		*vp;
	char		*errtok;
	int		len;
	mms_trace_sev_t	sev;

	/*
	 * Check if mount options
	 */
	for (set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work);
	    set != NULL;
	    set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work)) {
		/* look for set cap. If found then this is mount option */
		if (mms_pn_lookup(set, "cap", MMS_PN_STRING, NULL)) {
			/* Mount options, clean out mnttab */
			dm_destroy_mnt();
		}
	}

	work = NULL;
	for (set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work);
	    set != NULL;
	    set = mms_pn_lookup(cmd->cmd_root, "set",
	    MMS_PN_CLAUSE, &work)) {
		mnt->mnt_flags &= ~MNT_PRIVILEGED;
		mms_list_pair_foreach(&set->pn_arglist, name, val) {
			np = mms_pn_token(name);
			vp = mms_pn_token(val);
			if (strcmp(np, "filename") == 0) {
				dm_trim_tail(vp);
				if (strlen(vp) > DRV_LBN_LEN) {
					vp += (strlen(vp) - DRV_LBN_LEN);
				}
				dm_to_upper(vp);
				mnt->mnt_fname = malloc(18);
				memset(mnt->mnt_fname, ' ', 17);
				mnt->mnt_fname[17] = '\0';
				len = strlen(vp);
				if (len > 17) {
					/* Get last 17 chars from name */
					strncpy(mnt->mnt_fname,
					    vp + (len - 17), 17);
				} else {
					strncpy(mnt->mnt_fname, vp, len);
				}
			} else if (strcmp(np, "volumeid") == 0) {
				/* VID must be in uppercase */
				dm_to_upper(vp);
				mnt->mnt_vid = malloc(7);
				memset(mnt->mnt_vid, ' ', 6);
				mnt->mnt_vid[6] = '\0';
				strncpy(mnt->mnt_vid, vp, strlen(vp));
			} else if (strcmp(np, "CartridgePCL") == 0) {
				dm_to_upper(vp);
				mnt->mnt_pcl = strdup(vp);
			} else if (strcmp(np, "user") == 0) {
				mnt->mnt_user = strdup(vp);
			} else if (strcmp(np, "VolumeName") == 0) {
				mnt->mnt_volumename = strdup(vp);
			} else if (strcmp(np, "blocksize") == 0) {
				sscanf(vp, "%d", &mnt->mnt_blksize);
			} else if (strcmp(np, "defaultblocksize") == 0) {
				sscanf(vp, "%d", &mnt->mnt_dflt_blksize);
			} else if (strcmp(np, "cap") == 0) {
				errtok = dm_get_capabilities(vp);
				if (errtok != NULL) {
					/* Have an invalid capability */
					return (-1);
				}
			} else if (strcmp(np, "DMMessageLevel") == 0) {
				wka->dm_msg_level = mms_msg_get_severity(vp);
			} else if (strcmp(np, "TraceLevel") == 0) {
				(void) mms_trace_str2sev(vp, &sev);
				(void) mms_trace_filter(sev);
			} else if (strcmp(np, "TraceFileSize") == 0) {
				(void) mms_trace_set_fsize(vp);
			} else if (strcmp(np, "privileged") == 0) {
				if (strcmp(vp, "true") == 0) {
					mnt->mnt_flags |= MNT_PRIVILEGED;
				}
			} else if (strcmp(np, "SystemDiskMountTimeout") == 0) {
				sscanf(vp, "%d", &drv->drv_disk_mount_timeout);
			}
			/* Ignore unknown attributes */
		}
	}
	return (0);
}

int
dm_attach_cmd(dm_command_t *cmd)
{
	mms_par_node_t	*approot;
	mms_par_node_t	*root;
	char		*handle;
	struct		passwd pwd;
	struct		passwd *pwent;
	time_t		t;
	int		err;
	int		i;
	char		tbuf[] = "YYYYMMDDhhmmss";
	uint64_t	max_cap;
	int		try = 0;
	char		*val;

	if (drv->drv_flags & DRV_ATTACHED) {
		/* Drive already attached */
		DM_MSG_ADD((MMS_STATE, MMS_DM_E_INTERNAL,
		    "already attached"));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG, NULL);
		/*
		 * Something is very wrong here because MM has not done
		 * a detach. Restart and cleanup.
		 */
		DM_MSG_SEND((DM_ADM_ERR, DM_6524_MSG, NULL));
		DM_EXIT(DM_RESTART);
	}

	/*
	 * Create a handle for application
	 */
	time(&t);
	strftime(tbuf, sizeof (tbuf), "%Y""%m""%d""%H""%M""%S", localtime(&t));
	handle = mms_strnew("%s/%s.%d.%s-%s", MMS_HDL_DIR, wka->dm_hdl_prefix,
	    wka->dm_counter++, tbuf, mnt->mnt_pcl);
	/* Replace blanks in handle with '-' */
	for (i = 0; handle[i] != '\0'; i++) {
		if (handle[i] == ' ') {
			handle[i] = '-';
		}
	}
	wka->dm_targ_hdl = handle;
	wka->dm_hdl_major = wka->dm_drm_major;

	/*
	 * Get a minor dev number for handle which must be > 255.
	 */
	wka->dm_hdl_minor = dm_hdl_minor();
	TRACE((MMS_DEBUG, "Handle: %s (%d,%d)", wka->dm_targ_hdl,
	    wka->dm_hdl_major, wka->dm_hdl_minor));

	if (mknod(wka->dm_targ_hdl, S_IFCHR | S_IRUSR | S_IWUSR,
	    makedev(wka->dm_hdl_major, wka->dm_hdl_minor))) {
		err = errno;
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_MAKEHANDLE,
		    "make handle error: %s: %s",
		    wka->dm_targ_hdl, strerror(err)));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG, NULL);
		free(wka->dm_targ_hdl);
		return (DM_COMPLETE);
	}

	/*
	 * Tell dmd driver about the current minor dev number
	 */
	ioctl(wka->dm_drm_fd, DRM_TARG_MINOR, wka->dm_hdl_minor);

	if (mnt->mnt_user) {
		/* Change owner of handle to user */
		setpwent();		/* to beginning of PW file */
		pwent = getpwnam_r(mnt->mnt_user, &pwd,
		    wka->dm_pwbuf, wka->dm_pwbuf_size);
		endpwent();

		if (pwent == NULL) {
			/*
			 * Can't find user
			 */
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_USER,
			    "no user"));
			dm_resp_error(cmd->cmd_task, DM_6508_MSG, NULL);
			free(wka->dm_targ_hdl);
			return (DM_COMPLETE);
		}

		if (chown(wka->dm_targ_hdl, pwent->pw_uid, pwent->pw_gid)) {
			/* chown error */
			TRACE((MMS_ERR, "Can't chown to user"));
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_USER,
			    "cannot chown handle to user"));
			dm_resp_error(cmd->cmd_task, DM_6508_MSG, NULL);
			free(wka->dm_targ_hdl);
			return (DM_COMPLETE);
		}
	}

	drv->drv_rdbytes = 0;
	drv->drv_wrbytes = 0;


	/*
	 * Get info from databse
	 */
	if (dm_show_application(&approot) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get APPLICATION"));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG,
		    NULL);
		return (DM_COMPLETE);
	}

	dm_destroy_dca();
	while ((dca->dca_flags & DRV_DCA_VALID) == 0 && try < 10) {
		if (dm_show_dca_info(&root) != 0) {
			dm_destroy_dca();
			sleep(1);
			try++;
			continue;
		}
		dca->dca_flags |= DRV_DCA_VALID;
	}

	val = dm_get_attr_value(approot, "APPLICATION", "ApplicationName");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get application name"));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG,
		    NULL);
		mms_pn_destroy(root);
		mms_pn_destroy(approot);
		return (DM_COMPLETE);
	}
	dca->dca_app_name = strdup(val);

	if ((dca->dca_flags & DRV_DCA_VALID) == 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get info for DRIVECARTRIDGEACCESS"));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG,
		    NULL);
		mms_pn_destroy(root);
		mms_pn_destroy(approot);
		return (DM_COMPLETE);
	}

	/*
	 * Get application options
	 */
	if (dm_get_app_options(approot) != 0 ||
	    dm_get_part_rwmode(root) != 0 || dm_update_write_protect() != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get info for application/partition"));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG,
		    NULL);
		mms_pn_destroy(root);
		mms_pn_destroy(approot);
		return (DM_COMPLETE);
	}

	/*
	 * Override options with mount command options
	 */
	if (mnt->mnt_flags & MNT_VALIDATE_VID) {
		drv->drv_flags |= DRV_VALIDATE_VID;
	} else if (mnt->mnt_flags & MNT_NO_VALIDATE_VID) {
		drv->drv_flags &= ~DRV_VALIDATE_VID;
	}

	if (mnt->mnt_flags & MNT_VALIDATE_XDATE) {
		drv->drv_flags |= DRV_VALIDATE_XDATE;
	} else if (mnt->mnt_flags & MNT_NO_VALIDATE_XDATE) {
		drv->drv_flags &= ~DRV_VALIDATE_XDATE;
	}

	if (mnt->mnt_flags & MNT_VALIDATE_FNAME) {
		drv->drv_flags |= DRV_VALIDATE_FNAME;
	} else if (mnt->mnt_flags & MNT_NO_VALIDATE_FNAME) {
		drv->drv_flags &= ~DRV_VALIDATE_FNAME;
	}

	if (mnt->mnt_flags & MNT_PREEMPT_RSV) {
		wka->dm_flags &= ~DM_ASK_PREEMPT_RSV;
		wka->dm_flags |= DM_PREEMPT_RSV;
	} else if (mnt->mnt_flags & MNT_ASK_PREEMPT_RSV) {
		wka->dm_flags &= ~DM_PREEMPT_RSV;
		wka->dm_flags |= DM_ASK_PREEMPT_RSV;
	} else if (mnt->mnt_flags & MNT_NO_PREEMPT_RSV) {
		wka->dm_flags &= ~(DM_PREEMPT_RSV | DM_ASK_PREEMPT_RSV);
	}

	if (mnt->mnt_flags & MNT_SWITCH_LBL) {
		drv->drv_flags &= ~DRV_ASK_SWITCH_LBL;
		drv->drv_flags |= DRV_SWITCH_LBL;
	} else if (mnt->mnt_flags & MNT_ASK_SWITCH_LBL) {
		drv->drv_flags &= ~DRV_SWITCH_LBL;
		drv->drv_flags |= DRV_ASK_SWITCH_LBL;
	} else if (mnt->mnt_flags & MNT_NO_SWITCH_LBL) {
		drv->drv_flags &= ~(DRV_SWITCH_LBL | DRV_ASK_SWITCH_LBL);
	}

	if (mnt->mnt_flags & MNT_WRITEOVER) {
		drv->drv_flags &= ~DRV_ASK_WRITEOVER;
		drv->drv_flags |= DRV_WRITEOVER;
	} else if (mnt->mnt_flags & MNT_ASK_WRITEOVER) {
		drv->drv_flags &= ~DRV_WRITEOVER;
		drv->drv_flags |= DRV_ASK_WRITEOVER;
	} else if (mnt->mnt_flags & MNT_NO_WRITEOVER) {
		drv->drv_flags &= ~(DRV_WRITEOVER | DRV_ASK_WRITEOVER);
	}

	/*
	 * Tell dmd driver the operation mode - raw/mms.
	 */
	ioctl(wka->dm_drm_fd, DRM_MMS_MODE,
	    (mnt->mnt_flags & MNT_MMS) ? 1 : 0);

	TRACE((MMS_DEBUG, "drv_flags %16.16llx, mnt_flags %16.16llx",
	    drv->drv_flags, mnt->mnt_flags));

	/*
	 * get tape capacity from DB
	 */
	if (dm_get_capacity(root) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get info for application/partition"));
		dm_resp_error(cmd->cmd_task, DM_6508_MSG,
		    NULL);
		mms_pn_destroy(root);
		mms_pn_destroy(approot);
		return (DM_COMPLETE);
	}
	max_cap = drv->drv_capacity;

	/*
	 * Update capacity
	 */
	if (drv->drv_capacity != max_cap ||
	    drv->drv_capacity == (uint64_t)(-1LL) ||
	    drv->drv_avail == (uint64_t)(-1LL) ||
	    drv->drv_pc_avail == (uint32_t)(-1)) {
		/* Uninitialized capacity */
		if (dm_update_capacity() != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "unable to update capacity"));
			dm_resp_error(cmd->cmd_task, DM_6508_MSG,
			    NULL);
			mms_pn_destroy(root);
			mms_pn_destroy(approot);
			return (DM_COMPLETE);
		}
	}

	mms_pn_destroy(root);
	mms_pn_destroy(approot);

	/* Success */
	drv->drv_flags |= DRV_ATTACHED;
	dm_resp_success(cmd->cmd_task, wka->dm_targ_hdl);

	return (DM_COMPLETE);
}

int
dm_get_app_options(mms_par_node_t *root)
{
	mms_par_node_t	*attr;
	mms_par_node_t	*name;
	mms_par_node_t	*val;

	attr = mms_pn_lookup(root, "attrlist", MMS_PN_CLAUSE, NULL);
	if (attr == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get attrlist"));
		mms_pn_destroy(root);
		return (-1);
	}

	mms_list_pair_foreach(&attr->pn_arglist, name, val) {
		if (strcmp(mms_pn_token(name), "ValidateFileName") == 0) {
			if (strcmp(mms_pn_token(val), "yes") == 0) {
				drv->drv_flags |= DRV_VALIDATE_FNAME;
			} else {
				drv->drv_flags &= ~DRV_VALIDATE_FNAME;
			}
		} else if (strcmp(mms_pn_token(name),
		    "ValidateVolumeID") == 0) {
			if (strcmp(mms_pn_token(val), "yes") == 0) {
				drv->drv_flags |= DRV_VALIDATE_VID;
			} else {
				drv->drv_flags &= ~DRV_VALIDATE_VID;
			}
		} else if (strcmp(mms_pn_token(name),
		    "ValidateExpirationDate") == 0) {
			if (strcmp(mms_pn_token(val), "yes") == 0) {
				drv->drv_flags |= DRV_VALIDATE_XDATE;
			} else {
				drv->drv_flags &= ~DRV_VALIDATE_XDATE;
			}
		} else if (strcmp(mms_pn_token(name), "SwitchLabel") == 0) {
			drv->drv_flags &=
			    ~(DRV_SWITCH_LBL | DRV_ASK_SWITCH_LBL);
			if (strcmp(mms_pn_token(val), "yes") == 0) {
				drv->drv_flags |= DRV_SWITCH_LBL;
			} else if (strcmp(mms_pn_token(val), "ask") == 0) {
				drv->drv_flags |= DRV_ASK_SWITCH_LBL;
			}
		} else if (strcmp(mms_pn_token(name),
		    "WriteOverExistingData") == 0) {
			drv->drv_flags &=
			    ~(DRV_WRITEOVER | DRV_ASK_WRITEOVER);
			if (strcmp(mms_pn_token(val), "yes") == 0) {
				drv->drv_flags |= DRV_WRITEOVER;
			} else if (strcmp(mms_pn_token(val), "ask") == 0) {
				drv->drv_flags |= DRV_ASK_WRITEOVER;
			}
		} else if (strcmp(mms_pn_token(name), "Retention") == 0) {
			sscanf(mms_pn_token(val), "%d",
			    &drv->drv_retention);
		}
	}

	return (0);
}

int
dm_get_part_rwmode(mms_par_node_t *root)
{
	char		*val;

	val = dm_get_attr_value(root, "PARTITION", "PartitionRWMode");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get partition RW mode, assume readonly"));
		mms_pn_destroy(root);
		return (-1);
	}

	if (strcmp(val, "readonly") == 0) {
		mnt->mnt_flags |= MNT_READONLY;
		mnt->mnt_flags &= ~MNT_READWRITE;
		TRACE((MMS_DEBUG, "Volume is readonly"));
	}

	return (0);
}

int
dm_update_write_protect(void)
{
	int		wp;

	/*
	 * Read mode sense data
	 */
	if (DRV_CALL(drv_get_write_protect, (&wp))) {
		/* Error getting WP flag */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get WP flag"));
		return (-1);
	}
	if (dm_send_write_protect(wp) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "update write protect error"));
		return (-1);
	}


	if (wp == 1) {
		/* Cartridge is write protected */
		drv->drv_flags |= DRV_WRITEPROTECTED;
	}

	return (0);
}

int
dm_update_drivetype(void)
{
	char		*attr_cmd;
	char		*task;
	dm_command_t	*cmd;

	if ((wka->dm_flags & DM_HAVE_SESSION) == 0) {
		TRACE((MMS_ERR, "No connection to MM"));
		return (-1);
	}

	task = dm_bld_task("send-drivetype");
	attr_cmd = mms_strnew("attribute task['%s'] "
	    "match[ streq(DRIVE.'DriveName' '%s') ] "
	    "set[DRIVE.'DriveVendorID' '%s'] "
	    "set[DRIVE.'DriveProductID' '%s'] "
	    "set[DRIVE.'DriveTypeName' '%s'] "
	    "set[DM.'DMTargetPath' '%s'] "
	    ";", task, drv->drv_drvname,
	    drv->drv_vend, drv->drv_prod, drv->drv_typename,
	    wka->dm_target_base);

	cmd = dm_send_cmd(attr_cmd, dm_cmd_response, task);
	free(attr_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "update drivetype error"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_load_cmd(dm_command_t *cmd)
{
	TRACE((MMS_DEBUG, "Loading drive"));

	/*
	 * If the tape is already loaded, check to see if access mode
	 * asks for a load command to be issued.
	 */
	if ((drv->drv_flags & DRV_LOADED) && (drv->drv_flags & DRV_UDATA)) {
		if (mnt->mnt_flags & MNT_NOLOAD) {
			/* Don't issue load command */
			dm_resp_success(cmd->cmd_task, NULL);
			return (DM_COMPLETE);
		}
	}

	/*
	 * Save DRV_ATTACH flag and reserved flag
	 */
	drv->drv_flags &= (DRV_ATTACHED | DRV_RESERVED);

	/* issue a load command */
	if (DRV_CALL(drv_load, ()) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_DRIVE,
		    "load failed, drive not ready"));
		dm_resp_error(cmd->cmd_task, DM_6517_MSG, NULL);
		return (DM_COMPLETE);
	}

	drv->drv_flags |= (DRV_LOADED | DRV_BOM);

	/*
	 * Get rid of any pending attention
	 */
	while (DRV_CALL(drv_tur, ()) != 0) {
		;
	}

	dm_resp_success(cmd->cmd_task, NULL);
	return (DM_COMPLETE);
}


int
dm_identify_cmd(dm_command_t *cmd)
{
	drv_vol1_t	*vol1 = &drv->drv_vol1;
	int		rc;
	char		*resp;

	if ((drv->drv_flags & DRV_LOADED) == 0) {
		DM_MSG_ADD((MMS_STATE, MMS_DM_E_LOAD, "drive not loaded"));
		dm_resp_error(cmd->cmd_task, DM_6510_MSG, NULL);
		return (DM_COMPLETE);
	}

	if ((mnt->mnt_flags & MNT_MMS) == 0) {
		/* No MMS control */
		dm_resp_success(cmd->cmd_task, "No Signature");
		goto done;
	}

	/*
	 * If tape has already been identified, then return VSN.
	 * else rewind the tape and read VOL1.
	 */

	if (drv->drv_flags & DRV_IDENTIFIED) {
		dm_resp_success(cmd->cmd_task, drv->drv_vid);
		goto done;
	}

	/* No VSN, must determine VSN */
	if (DRV_CALL(drv_rewind, ()) != 0) {
		/* I/O error */
		drv->drv_flags |= DRV_LOST_POS;
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_IO, "rewind error"));
		dm_resp_error(cmd->cmd_task, DM_6510_MSG, NULL);
		return (DM_COMPLETE);
	}

	if (dm_set_label_blksize() != 0) {
		/* I/O error */
		TRACE((MMS_DEBUG, "Can't set label blksize"));
		dm_resp_error(cmd->cmd_task, DM_6510_MSG, NULL);
		return (DM_COMPLETE);
	}

	drv->drv_vid[0] = '\0';		/* No VSN yet */

	rc = DRV_CALL(drv_read, ((char *)vol1, 80));
	if (rc != 80) {
		/* Did not read a label */
		drv->drv_lbl_type = DRV_NL;	/* a non labeled tape */
	} else if (strncmp(vol1->vol1_id, VOL1_ID, 4) == 0) {
		drv->drv_lbl_type = DRV_AL;
	} else {
		drv->drv_lbl_type = DRV_NL;
	}
	if (rc > 0 || (drv->drv_flags & DRV_TM)) {
		/*
		 * Read something ot hit a tapemark. Not a blank tape anymore.
		 */
		drv->drv_flags &= ~DRV_BLANK;
	}
	if (drv->drv_flags & DRV_EOM) {
		/* Hit EOM, must be a blank tape */
		drv->drv_flags |= DRV_BLANK;
	}

	if (drv->drv_lbl_type == DRV_NL) {

		if (DRV_CALL(drv_rewind, ()) != 0) {
			/* I/O error */
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_IO,
			    "rewind error"));
			dm_resp_error(cmd->cmd_task, DM_6510_MSG, NULL);
			return (DM_COMPLETE);
		}
		drv->drv_fseq = 1;	/* at file seq 1 */
		drv->drv_flags |= (DRV_BOF | DRV_UDATA);
		if (dm_get_bof_pos() != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "unable to get BOF position"));
			dm_resp_error(cmd->cmd_task, DM_6510_MSG, NULL);
			return (DM_COMPLETE);
		}
		resp = "No Signature";
	} else {

		drv->drv_flags |= DRV_VOL1;	/* has VOL1 lable */
		drv->drv_fseq = 1;	/* at file seq 1 */
		if (strncmp(vol1->vol1_impid, DRV_IMPID, DRV_IMPID_LEN) == 0 ||
		    strncmp(vol1->vol1_impid, DRV_IMPID2, DRV_IMPID_LEN) == 0) {
			/* Created by SUN mms */
			drv->drv_flags |= DRV_MMS_LBL;
		}

		/* Return VSN */
		strncpy(drv->drv_vid, vol1->vol1_vid, 6);
		drv->drv_vid[6] = '\0';

		/*
		 * Verify the mounted cartridge has the requested VSN
		 */
		if (drv->drv_flags & DRV_VALIDATE_VID) {
			if ((mnt->mnt_flags & MNT_NO_VALIDATE_VID) == 0) {
				if (strcmp(drv->drv_vid, mnt->mnt_vid) != 0) {
					/* Wrong cartridge mounted */
					DM_MSG_ADD((MMS_INTERNAL,
					    MMS_DM_E_VOLUME_ID,
					    "incorrect volume id: "
					    "requested %s, mounted %s",
					    mnt->mnt_vid, drv->drv_vid));
					dm_resp_error(cmd->cmd_task,
					    DM_6510_MSG, NULL);
					return (DM_COMPLETE);
				}
			}
		}
		resp = drv->drv_vid[0] == '\0' ? "Null VSN" : drv->drv_vid;
	}
	drv->drv_flags |= DRV_IDENTIFIED;
	dm_resp_success(cmd->cmd_task, resp);
done:
	/*
	 * Calculate mount time
	 */
	gettimeofday(&wka->dm_mnt_done, NULL);
	wka->dm_mnt_time.tv_sec =
	    wka->dm_mnt_done.tv_sec - wka->dm_mnt_start.tv_sec;
	wka->dm_mnt_time.tv_usec =
	    wka->dm_mnt_done.tv_usec - wka->dm_mnt_start.tv_usec;
	if (wka->dm_mnt_time.tv_usec < 0) {
		wka->dm_mnt_time.tv_usec += 1000000;
		wka->dm_mnt_time.tv_sec--;
	}
	TRACE((MMS_OPER, "Mount time = %ld.%l6.6d",
	    wka->dm_mnt_time.tv_sec, wka->dm_mnt_time.tv_usec));

	return (DM_COMPLETE);
}

int
dm_detach_cmd(dm_command_t *cmd)
{
	mms_par_node_t	*handle;
	mms_par_node_t	*stale;

	TRACE((MMS_DEBUG, "Enter dm_detach_cmd"));

	handle =
	    mms_pn_lookup(cmd->cmd_root, "drivehandle", MMS_PN_CLAUSE,
	    NULL);
	handle = mms_pn_lookup(handle, NULL, MMS_PN_STRING, NULL);

	stale =
	    mms_pn_lookup(cmd->cmd_root, "stale", MMS_PN_CLAUSE, NULL);
	stale = mms_pn_lookup(stale, NULL, MMS_PN_KEYWORD, NULL);


	if (wka->dm_targ_hdl == NULL) {
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_NOEXISTHANDLE,
		    "no handle"));
		dm_resp_error(cmd->cmd_task, DM_6511_MSG, NULL);
		return (DM_COMPLETE);
	} else if (strcmp(mms_pn_token(handle), wka->dm_targ_hdl) != 0) {
		/* unknown handle name */
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_BADHANDLE,
		    "unknown handle"));
		dm_resp_error(cmd->cmd_task, DM_6511_MSG, NULL);
		return (DM_COMPLETE);
	} else if (wka->dm_app_pid != 0) {
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_HANDLEINUSE,
		    "handle in use by pid %d", (int)wka->dm_app_pid));
		dm_resp_error(cmd->cmd_task, DM_6511_MSG, NULL);
		return (DM_COMPLETE);
	} else if ((drv->drv_flags & DRV_ATTACHED) == 0) {
		DM_MSG_ADD((MMS_STATE, MMS_DM_E_DEVDET, "not attached"));
		dm_resp_error(cmd->cmd_task, DM_6511_MSG, NULL);
		return (DM_COMPLETE);
	}

	if (strcmp(mms_pn_token(stale), "false") == 0) {
		/*
		 * Not a stale handle. Must be a detach from normal
		 * unmount processing.
		 * Remove the handle.
		 */

		ioctl(wka->dm_drm_fd, DRM_TARG_MINOR, NULL);

		unlink(mms_pn_token(handle));
		if (wka->dm_targ_hdl != NULL) {
			free(wka->dm_targ_hdl);
			wka->dm_targ_hdl = NULL;
		}
		drv->drv_flags &= ~DRV_ATTACHED;

		/*
		 * Clean up mnt table
		 */
		dm_destroy_mnt();
		dm_destroy_dca();
		drv->drv_flags &= ~DRV_VALIDATED_FNAME;

		dm_resp_success(cmd->cmd_task, NULL);
	} else {
		/*
		 * A stale handle
		 */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "stale handle"));
		dm_resp_error(cmd->cmd_task, DM_6511_MSG, NULL);
	}

	return (DM_COMPLETE);
}

int
dm_unload_cmd(dm_command_t *cmd)
{
	int		release = 0;

	if ((wka->dm_flags & (DM_DFLT_LIB_LOADED | DM_DEV_LIB_LOADED)) == 0) {
		/* library not loaded */
		TRACE((MMS_DEBUG,
		    "dm_unload_cmd: device libraries not loaded"));
		dm_resp_success(cmd->cmd_task, NULL);
		return (DM_COMPLETE);
	}

	/*
	 * Update capacity
	 */
	if (wka->dm_flags & DM_SEND_CAPACITY) {
		if (dm_send_capacity(&drv->drv_cap) != 0) {
			TRACE((MMS_ERR, "Can't send capacity"));
		} else {
			wka->dm_flags &= ~DM_SEND_CAPACITY;
		}
	}
	/*
	 * Update EOF pos
	 */
	if (wka->dm_flags & DM_SEND_EOF_POS) {
		if (dm_send_eof_pos()) {
			TRACE((MMS_ERR, "Can't send eof pos"));
		} else {
			wka->dm_flags &= ~DM_SEND_EOF_POS;
		}
	}

	/*
	 * If not reserved, then reserve it to prevent st from reserving it
	 */
	if ((drv->drv_flags & DRV_RESERVED) == 0) {
		if (DRV_CALL(drv_prsv_register, ()) == 0 &&
		    DRV_CALL(drv_prsv_reserve, ()) == 0) {
			release = 1;
		}
	}

	/*
	 * Get drive statistics before unloading
	 */
	if (dca->dca_flags & DRV_DCA_VALID) {
		if (DRV_CALL(drv_get_statistics, ()) == 0) {
			(void) dm_send_statistics();
		}
		dm_destroy_dca();
	}

	/*
	 * Ignore any unload error so MM can unload the tape
	 */
	DRV_CALL(drv_unload, ());
	dm_resp_success(cmd->cmd_task, NULL);

	if (release == 1) {
		DRV_CALL(drv_prsv_register, ());
		DRV_CALL(drv_prsv_release, ());
	}

	/*
	 * Save DRV_ATTACH flag
	 */
	drv->drv_flags &= DRV_ATTACHED;

	return (DM_COMPLETE);
}

void
dm_exit_cmd(dm_command_t *cmd)
{
	dm_resp_success(cmd->cmd_task, NULL);
	dm_exit(DM_NO_RESTART, __FILE__, __LINE__);
}

void
dm_reset_cmd(dm_command_t *cmd)
{
	dm_resp_success(cmd->cmd_task, NULL);
	dm_exit(DM_RESTART, __FILE__, __LINE__);
}

void
dm_destroy_mnt(void)
{
	if (mnt->mnt_volumename) {
		free(mnt->mnt_volumename);
		mnt->mnt_volumename = NULL;
	}
	if (mnt->mnt_vid) {
		free(mnt->mnt_vid);
		mnt->mnt_vid = NULL;
	}
	if (mnt->mnt_pcl) {
		free(mnt->mnt_pcl);
		mnt->mnt_pcl = NULL;
	}
	if (mnt->mnt_fname) {
		free(mnt->mnt_fname);
		mnt->mnt_fname = NULL;
	}
	if (mnt->mnt_user) {
		free(mnt->mnt_user);
		mnt->mnt_user = NULL;
	}
	if (mnt->mnt_dencode) {
		free(mnt->mnt_dencode);
		mnt->mnt_dencode = NULL;
	}
	if (mnt->mnt_shape) {
		free(mnt->mnt_shape);
		mnt->mnt_shape = NULL;
	}
}

char	*
dm_bld_config_cmd(char *task)
{
	int		kwlen;
	int		i;
	char		*conf = NULL;
	char		*fmt = DRV_CONFIG;
	char		**cp;
	drv_shape_density_t	*sd;
	mms_sym_t		*mms_sym;

	/*
	 * Now, substitute values
	 */
	for (i = 0, cp = 0; fmt[i] != '\0'; i += kwlen) {
		kwlen = 0;
		if (strncmp(fmt + i, CONF_TASK,
		    kwlen = strlen(CONF_TASK)) == 0) {
			conf = mms_strapp(conf, "%s", task);
		} else if (strncmp(fmt + i, CONF_DMNAME,
		    kwlen = strlen(CONF_DMNAME)) == 0) {
			conf = mms_strapp(conf, "%s", drv->drv_dmname);
		} else if (strncmp(fmt + i, CONF_DENSITY_RW,
		    kwlen = strlen(CONF_DENSITY_RW)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den != NULL &&
				    strcmp(sd->drv_bit, sd->drv_den) == 0) {
					conf = mms_strapp(conf,
					    "'%s' ", sd->drv_den);
				}
			}
		} else if (strncmp(fmt + i, CONF_DENSITY_RO,
		    kwlen = strlen(CONF_DENSITY_RO)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den == NULL) {
					conf = mms_strapp(conf,
					    "'%s' ", sd->drv_bit);
				}
			}
		} else if (strncmp(fmt + i, CONF_BITFORMAT,
		    kwlen = strlen(CONF_BITFORMAT)) == 0) {
			for (mms_sym = drv->drv_density;
			    mms_sym->sym_token != NULL; mms_sym++) {
				conf = mms_strapp(conf,
				    "'bit_%s' ",
				    mms_sym->sym_token);
			}
		} else if (strncmp(fmt + i, CONF_BITFORMAT_RW,
		    kwlen = strlen(CONF_BITFORMAT_RW)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den != NULL &&
				    strcmp(sd->drv_bit, sd->drv_den) == 0) {
					conf = mms_strapp(conf,
					    "'bit_%s' ",
					    sd->drv_den);
				}
			}
		} else if (strncmp(fmt + i, CONF_BITFORMAT_RO,
		    kwlen = strlen(CONF_BITFORMAT_RO)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den == NULL) {
					conf = mms_strapp(conf,
					    "'bit_%s'",
					    sd->drv_bit);
				}
			}
		} else if (strncmp(fmt + i, CONF_BITFORMAT_WO,
		    kwlen = strlen(CONF_BITFORMAT_WO)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den != NULL &&
				    strcmp(sd->drv_bit, sd->drv_den) != 0) {
					conf = mms_strapp(conf,
					    "'bit_%s'",
					    sd->drv_bit);
				}
			}
		} else if (strncmp(fmt + i, CONF_BIT_CLAUSE,
		    kwlen = strlen(CONF_BIT_CLAUSE)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (dm_duplicate_bit(sd)) {
					continue;
				}
				conf = mms_strapp(conf,
				    "bitformat "
				    "['bitformat_%s' 'bit_%s'] ",
				    sd->drv_bit, sd->drv_bit);
			}
		} else if (strncmp(fmt + i, CONF_SHAPE,
		    kwlen = strlen(CONF_SHAPE)) == 0) {
			for (cp = drv->drv_shape; *cp != NULL; cp++) {
				conf = mms_strapp(conf,
				    "'%s' ", *cp);
			}
		} else if (strncmp(fmt + i, CONF_SHAPE_RW,
		    kwlen = strlen(CONF_SHAPE_RW)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den == NULL ||
				    strcmp(sd->drv_bit, sd->drv_den) != 0 ||
				    dm_duplicate_shape(sd, "rw")) {
					continue;
				}
				conf = mms_strapp(conf,
				    "'%s' ", sd->drv_shape);
			}
		} else if (strncmp(fmt + i, CONF_SHAPE_RO,
		    kwlen = strlen(CONF_SHAPE_RO)) == 0) {
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (sd->drv_den != NULL ||
				    dm_rw_shape(sd->drv_shape) ||
				    dm_duplicate_shape(sd, "ro")) {
					continue;
				}
				conf = mms_strapp(conf,
				    "'%s' ", sd->drv_shape);
			}
		} else if (strncmp(fmt + i, CONF_DRIVE_SPEC,
		    kwlen = strlen(CONF_DRIVE_SPEC)) == 0) {
			conf = mms_strapp(conf,
			    "'%s' '%s' '%s' ", drv->drv_dmname,
			    drv->drv_drvname, wka->dm_target_base);
		} else if (strncmp(fmt + i, CONF_DRIVE_TYPE,
		    kwlen = strlen(CONF_DRIVE_TYPE)) == 0) {
			conf = mms_strapp(conf, "%s", drv->drv_drive_type);
		} else if (strncmp(fmt + i, CONF_CAP_DENSITY_CLAUSE,
		    kwlen = strlen(CONF_CAP_DENSITY_CLAUSE)) == 0) {
			if (dm_cap_clause(&conf) != 0) {
				goto err;
			}
		} else {
			conf = mms_strnapp(conf, 1, fmt + i);
			kwlen = 1;
		}
	}

	return (conf);

err:
	free(conf);
	return (NULL);
}

int
dm_cap_clause(char **pconf)
{
	drv_shape_density_t	*sd;
	char		*readwrite = DRV_CAP_READWRITE;
	char		*writeover = DRV_CAP_WRITEOVER;

	for (sd = drv->drv_shape_den; sd->drv_shape != NULL; sd++) {
		if (sd->drv_den != NULL &&
		    strcmp(sd->drv_bit, sd->drv_den) == 0) {
			/* Readwrite density */
			if (dm_cap_clause_aux(readwrite, pconf, sd) != 0) {
				return (-1);
			}
		} else if (sd->drv_den != NULL) {
			/* Writeover density */
			if (dm_cap_clause_aux(writeover, pconf, sd) != 0) {
				return (-1);
			}
		}
	}
	return (0);
}

int
dm_cap_clause_aux(char *fmt, char **pconf, drv_shape_density_t *sd)
{
	int		i;
	char		*conf = *pconf;
	int		kwlen;
	char		*buf;

	for (i = 0; fmt[i] != '\0'; i += kwlen) {
		if (strncmp(fmt + i, CONF_DRIVE_SPEC,
		    kwlen = strlen(CONF_DRIVE_SPEC)) == 0) {
			conf = mms_strapp(conf,
			    "'%s' '%s' '%s' ", drv->drv_dmname,
			    drv->drv_drvname, wka->dm_target_base);
		} else if (strncmp(fmt + i, CONF_DMNAME,
		    kwlen = strlen(CONF_DMNAME)) == 0) {
			conf = mms_strapp(conf, "%s", drv->drv_dmname);
		} else if (strncmp(fmt + i, CONF_DRIVE_TYPE,
		    kwlen = strlen(CONF_DRIVE_TYPE)) == 0) {
			conf = mms_strapp(conf, "%s", drv->drv_drive_type);
		} else if (strncmp(fmt + i, CUR_DENSITY_RW,
		    kwlen = strlen(CUR_DENSITY_RW)) == 0) {
			conf = mms_strapp(conf, "%s", sd->drv_den);
		} else if (strncmp(fmt + i, CUR_BITFORMAT_RW,
		    kwlen = strlen(CUR_BITFORMAT_RW)) == 0) {
			conf = mms_strapp(conf,
			    "bit_%s", sd->drv_bit);
		} else if (strncmp(fmt + i, CUR_BITFORMAT_WO,
		    kwlen = strlen(CUR_BITFORMAT_WO)) == 0) {
			conf = mms_strapp(conf,
			    "bit_%s", sd->drv_bit);
		} else if (strncmp(fmt + i, CUR_SHAPE_RW,
		    kwlen = strlen(CUR_SHAPE_RW)) == 0) {
			conf = mms_strapp(conf, "%s", sd->drv_shape);
		} else if (fmt[i] == '$') {
			buf = mms_strnew("%-50.50", fmt + i);
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "Unknown keyword %s", buf));
			free(buf);
			goto err;
		} else {
			conf = mms_strnapp(conf, 1, fmt + i);
			kwlen = 1;
		}
	}

	*pconf = conf;
	return (0);
err:
	return (-1);
}

int
dm_rw_shape(char *shape)
{
	drv_shape_density_t	*sd;

	for (sd = drv->drv_shape_den; sd->drv_shape != NULL; sd++) {
		if (strcmp(sd->drv_shape, shape) == 0) {
			if (sd->drv_den != NULL &&
			    strcmp(sd->drv_bit, sd->drv_den) == 0) {
				return (1);
			}
		}
	}
	return (0);
}

int
dm_duplicate_bit(drv_shape_density_t *sd)
{
	drv_shape_density_t	*sd1;

	for (sd1 = drv->drv_shape_den; sd1 < sd; sd1++) {
		if (strcmp(sd1->drv_bit, sd->drv_bit) == 0) {
			return (1);
		}
	}
	return (0);
}

int
dm_duplicate_shape(drv_shape_density_t *sd, char *type)
{
	drv_shape_density_t	*sd1;
	int		rw;

	rw = strcmp(type, "rw") == 0;
	for (sd1 = drv->drv_shape_den; sd1 < sd; sd1++) {
		if (rw) {
			/* Readwrite shape */
			if (sd1->drv_den != NULL &&
			    strcmp(sd1->drv_bit, sd1->drv_den) == 0) {
				if (strcmp(sd1->drv_shape, sd->drv_shape)
				    == 0) {
					return (1);
				}
			}
		} else {
			/* Readonly shape */
			if (sd1->drv_den == NULL) {
				if (strcmp(sd1->drv_shape, sd->drv_shape)
				    == 0) {
					return (1);
				}
			}
		}
	}
	return (0);
}

/*
 * drv_get_capabilities - get capabilities values from string
 * If no error, return NULL, otherwise, return the token in error.
 */

char	*
dm_get_capabilities(char *tokens)
{
	char		*cp;
	char		*tok = tokens;
	mms_sym_t		*mms_sym;
	drv_shape_density_t	*sd;

	mnt->mnt_flags = 0;
	for (cp = strchr(tok, ':');
	    tok[0] != '\0' && cp != NULL;
	    tok = cp + 1, cp = strchr(tok, ':')) {
		cp[0] = '\0';
		if (strcmp(tok, "*load") == 0) {
			mnt->mnt_flags &= ~MNT_NOLOAD;
		} else if (strcmp(tok, "noload") == 0) {
			mnt->mnt_flags |= MNT_NOLOAD;
		} else if (strcmp(tok, "*rewind") == 0) {
			mnt->mnt_flags &= ~MNT_NOREWIND;
		} else if (strcmp(tok, "norewind") == 0) {
			mnt->mnt_flags |= MNT_NOREWIND;
		} else if (strcmp(tok, "fixed") == 0 ||
		    strcmp(tok, "block") == 0) {
			mnt->mnt_flags |= MNT_FIXED;
			mnt->mnt_flags &= ~MNT_VARIABLE;
		} else if (strcmp(tok, "variable") == 0) {
			mnt->mnt_flags |= MNT_VARIABLE;
			mnt->mnt_flags &= ~MNT_FIXED;
		} else if (strcmp(tok, "*dflt_vldt_vid") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_VID |
			    MNT_NO_VALIDATE_VID);
		} else if (strcmp(tok, "validate_vid") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_VID |
			    MNT_NO_VALIDATE_VID);
			mnt->mnt_flags |= MNT_VALIDATE_VID;
		} else if (strcmp(tok, "no_validate_vid") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_VID |
			    MNT_NO_VALIDATE_VID);
			mnt->mnt_flags |= MNT_NO_VALIDATE_VID;
		} else if (strcmp(tok, "*dflt_vldt_xdate") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_XDATE |
			    MNT_NO_VALIDATE_XDATE);
		} else if (strcmp(tok, "validate_xdate") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_XDATE |
			    MNT_NO_VALIDATE_XDATE);
			mnt->mnt_flags |= MNT_VALIDATE_XDATE;
		} else if (strcmp(tok, "no_validate_xdate") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_XDATE |
			    MNT_NO_VALIDATE_XDATE);
			mnt->mnt_flags |= MNT_NO_VALIDATE_XDATE;
		} else if (strcmp(tok, "*dflt_vldt_filename") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_FNAME |
			    MNT_NO_VALIDATE_FNAME);
		} else if (strcmp(tok, "validate_filename") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_FNAME |
			    MNT_NO_VALIDATE_FNAME);
			mnt->mnt_flags |= MNT_VALIDATE_FNAME;
		} else if (strcmp(tok, "no_validate_filename") == 0) {
			mnt->mnt_flags &= ~(MNT_VALIDATE_FNAME |
			    MNT_NO_VALIDATE_FNAME);
			mnt->mnt_flags |= MNT_NO_VALIDATE_FNAME;
		} else if (strcmp(tok, "*dflt_preempt_rsv") == 0) {
			mnt->mnt_flags &= ~(MNT_PREEMPT_RSV |
			    MNT_ASK_PREEMPT_RSV | MNT_NO_PREEMPT_RSV);
		} else if (strcmp(tok, "preempt_rsv") == 0) {
			mnt->mnt_flags &= ~(MNT_PREEMPT_RSV |
			    MNT_ASK_PREEMPT_RSV | MNT_NO_PREEMPT_RSV);
			mnt->mnt_flags |= MNT_PREEMPT_RSV;
		} else if (strcmp(tok, "ask_preempt_rsv") == 0) {
			mnt->mnt_flags &= ~(MNT_PREEMPT_RSV |
			    MNT_ASK_PREEMPT_RSV | MNT_NO_PREEMPT_RSV);
			mnt->mnt_flags |= MNT_ASK_PREEMPT_RSV;
		} else if (strcmp(tok, "nopreempt_rsv") == 0) {
			mnt->mnt_flags &= ~(MNT_PREEMPT_RSV |
			    MNT_ASK_PREEMPT_RSV | MNT_NO_PREEMPT_RSV);
			mnt->mnt_flags |= MNT_NO_PREEMPT_RSV;
		} else if (strcmp(tok, "*dflt_writeover") == 0) {
			mnt->mnt_flags &= ~(MNT_WRITEOVER |
			    MNT_ASK_WRITEOVER | MNT_NO_WRITEOVER);
		} else if (strcmp(tok, "writeover") == 0) {
			mnt->mnt_flags &= ~(MNT_WRITEOVER |
			    MNT_ASK_WRITEOVER | MNT_NO_WRITEOVER);
			mnt->mnt_flags |= MNT_WRITEOVER;
		} else if (strcmp(tok, "ask_writeover") == 0) {
			mnt->mnt_flags &= ~(MNT_WRITEOVER |
			    MNT_ASK_WRITEOVER | MNT_NO_WRITEOVER);
			mnt->mnt_flags |= MNT_ASK_WRITEOVER;
		} else if (strcmp(tok, "no_writeover") == 0) {
			mnt->mnt_flags &= ~(MNT_WRITEOVER |
			    MNT_ASK_WRITEOVER | MNT_NO_WRITEOVER);
			mnt->mnt_flags |= MNT_NO_WRITEOVER;
		} else if (strcmp(tok, "*dflt_switch_lbl") == 0) {
			mnt->mnt_flags &= ~(MNT_SWITCH_LBL |
			    MNT_ASK_SWITCH_LBL | MNT_NO_SWITCH_LBL);
		} else if (strcmp(tok, "switch_lbl") == 0) {
			mnt->mnt_flags &= ~(MNT_SWITCH_LBL |
			    MNT_ASK_SWITCH_LBL | MNT_NO_SWITCH_LBL);
			mnt->mnt_flags |= MNT_SWITCH_LBL;
		} else if (strcmp(tok, "ask_switch_lbl") == 0) {
			mnt->mnt_flags &= ~(MNT_SWITCH_LBL |
			    MNT_ASK_SWITCH_LBL | MNT_NO_SWITCH_LBL);
			mnt->mnt_flags |= MNT_ASK_SWITCH_LBL;
		} else if (strcmp(tok, "no_switch_lbl") == 0) {
			mnt->mnt_flags &= ~(MNT_SWITCH_LBL |
			    MNT_ASK_SWITCH_LBL | MNT_NO_SWITCH_LBL);
			mnt->mnt_flags |= MNT_NO_SWITCH_LBL;
		} else if (strcmp(tok, "mms") == 0) {
			mnt->mnt_flags |= MNT_MMS;
		} else if (strcmp(tok, "raw") == 0) {
			mnt->mnt_flags &= ~MNT_MMS;
		} else if (strcmp(tok, "*nocompression") == 0) {
			mnt->mnt_flags &= ~MNT_COMPRESSION;
		} else if (strcmp(tok, "compression") == 0) {
			mnt->mnt_flags |= MNT_COMPRESSION;
			mnt->mnt_flags &=
			    ~(MNT_LOW | MNT_MEDIUM | MNT_HIGH | MNT_ULTRA);
		} else if (strcmp(tok, "low") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_LOW | MNT_MEDIUM | MNT_HIGH | MNT_ULTRA);
			mnt->mnt_flags |= MNT_LOW;
		} else if (strcmp(tok, "medium") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_LOW | MNT_MEDIUM | MNT_HIGH | MNT_ULTRA);
			mnt->mnt_flags |= MNT_MEDIUM;
		} else if (strcmp(tok, "high") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_LOW | MNT_MEDIUM | MNT_HIGH | MNT_ULTRA);
			mnt->mnt_flags |= MNT_HIGH;
		} else if (strcmp(tok, "ultra") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_LOW | MNT_MEDIUM | MNT_HIGH | MNT_ULTRA);
			mnt->mnt_flags |= MNT_ULTRA;
		} else if (strcmp(tok, "mms_tm") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_BSD | MNT_NOBSD | MNT_MMS_TM);
			mnt->mnt_flags |= MNT_MMS_TM;
		} else if (strcmp(tok, "st_bsd") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_BSD | MNT_NOBSD | MNT_MMS_TM);
			mnt->mnt_flags |= MNT_BSD;
		} else if (strcmp(tok, "st_nobsd") == 0) {
			mnt->mnt_flags &=
			    ~(MNT_BSD | MNT_NOBSD | MNT_MMS_TM);
			mnt->mnt_flags |= MNT_NOBSD;
		} else if (strcmp(tok, "readonly") == 0) {
			mnt->mnt_flags |= MNT_READONLY;
			mnt->mnt_flags &= ~MNT_READWRITE;
		} else if (strcmp(tok, "readwrite") == 0) {
			mnt->mnt_flags &= ~MNT_READONLY;
			mnt->mnt_flags |= MNT_READWRITE;
		} else if (strcmp(tok, "*readwrite") == 0) {
			mnt->mnt_flags &= ~(MNT_READONLY | MNT_READWRITE);
		} else if (strcmp(tok, "al") == 0 ||
		    strcmp(tok, "*default_lbl") == 0) {
			mnt->mnt_lbl_type = DRV_AL;
		} else if (strcmp(tok, "sl") == 0) {
			mnt->mnt_lbl_type = DRV_SL;
		} else if (strcmp(tok, "nl") == 0) {
			mnt->mnt_lbl_type = DRV_NL;
		} else if (strcmp(tok, "blp") == 0) {
			mnt->mnt_lbl_type = DRV_BLP;
		} else if (strcmp(tok, "*oflag") == 0) {
			mnt->mnt_flags &= ~(MNT_CREAT | MNT_OLD);
		} else if (strcmp(tok, "old") == 0) {
			mnt->mnt_flags |= MNT_OLD;
			mnt->mnt_flags &= ~MNT_CREAT;
		} else if (strcmp(tok, "creat") == 0 ||
		    strcmp(tok, "new") == 0) {
			mnt->mnt_flags &= ~MNT_OLD;
			mnt->mnt_flags |= MNT_CREAT;
		} else if (strcmp(tok, "*auto_density") == 0) {
			mnt->mnt_flags |= MNT_AUTO_DEN;
		} else if (strcmp(tok, "*auto_drive") &&
		    strcmp(tok, "*bit_unknown") &&
		    strcmp(tok, DMNAME) &&
		    strcmp(tok, DRVNAME) &&
		    strcmp(tok, "*default_tm") &&
		    strcmp(tok, wka->dm_target_base)) {
			/*
			 * Look for drive type name
			 */
			if (strcmp(tok, drv->drv_drive_type) == 0) {
				/* Matching drive type name */
				continue;
			}
			/*
			 * Look for read/write supported density
			 */
			if (mms_sym = dm_sym_in(drv->drv_density, tok)) {
				for (sd = drv->drv_shape_den;
				    sd->drv_shape != NULL; sd++) {
					if (sd->drv_den != NULL &&
					    strcmp(sd->drv_bit,
					    sd->drv_den) != 0 &&
					    strcmp(sd->drv_den, tok) != 0) {
						break;
					}
				}
				if (sd->drv_shape != NULL) {
					/* Found a matching R/W density */
					mnt->mnt_density = mms_sym;
					continue;
				}
			}
			/*
			 * Look for bitformat
			 */
			/* skip "bit_" to get density */
			if (mms_sym = dm_sym_in(drv->drv_density, tok + 4)) {
				/* Found matching bitformat */
				mnt->mnt_bitformat = mms_sym;
				continue;
			}
			/*
			 * Look for matching shape
			 */
			for (sd = drv->drv_shape_den;
			    sd->drv_shape != NULL; sd++) {
				if (strcmp(sd->drv_shape, tok) == 0) {
					/* found a matching shape */
					break;
				}
			}
			if (sd->drv_shape == NULL) {
				/* Unknown token, error */
				DM_MSG_ADD((MMS_INVALID, MMS_DM_E_BADVAL,
				    "unsupported capability: %s", tok));
				return (tok);
			}
		}
	}

	return (NULL);
}

int
dm_verify_serial_num(void)
{
	char		sernum[MMS_SER_NUM_LEN + 1];

	if (DRV_CALL(drv_get_serial_num, (sernum)) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "read drive serial number error: %s", strerror(errno)));
		return (-1);
	}

	TRACE((MMS_ERR, "Serial number: "
	    "From DRIVE: %s, From device : %s.", drv->drv_sernum, sernum));
	if (strcmp(drv->drv_sernum, sernum) != 0) {
		DM_MSG_ADD((MMS_INVALID, MMS_DM_E_DRIVE_SER_NUM,
		    "mismatched drive serial number, "
		    "from library %s, from drive %s",
		    drv->drv_sernum, sernum));
		return (-1);
	}

	return (0);
}

int
dm_drv_assigned(void)
{
	char		*dmname;

	if (dm_show_drive_dmname(&dmname) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Can't read DRIVE.'DMName'"));
		return (-1);
	}
	if (dmname != NULL && strcmp(dmname, "none") == 0) {
		/* drive not assigned */
		TRACE((MMS_DEBUG, "Drive not assigned"));
		free(dmname);
		return (-1);
	}

	/* Drive assigned */
	TRACE((MMS_DEBUG, "Drive assigned to %s", dmname));
	free(dmname);
	return (0);
}

int
dm_get_system_options(void)
{
	mms_par_node_t	*root;
	char		*val;

	if (dm_show_system(&root) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "cannot get SYSTEM attributes"));
		return (-1);
	}

	/*
	 * Save system options
	 */

	val = dm_get_attr_value(root, "SYSTEM", "PreemptReservation");
	if (val == NULL) {
		mms_pn_destroy(root);
		return (-1);
	}

	wka->dm_flags &= ~(DM_PREEMPT_RSV | DM_ASK_PREEMPT_RSV);
	if (strcmp(val, "yes") == 0) {
		wka->dm_flags |= DM_PREEMPT_RSV;
	} else if (strcmp(val, "ask") == 0) {
		wka->dm_flags &= ~DM_ASK_PREEMPT_RSV;
	}

	val = dm_get_attr_value(root, "SYSTEM", "DefaultBlocksize");
	if (val == NULL) {
		mms_pn_destroy(root);
		return (-1);
	}

	sscanf(val, "%d", &drv->drv_dflt_blksize);
	mms_pn_destroy(root);

	/*
	 * Get attributes from drive
	 */
	if (dm_show_drive(&root) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "cannot get DRIVE attributes"));
		return (-1);
	}

	/*
	 * Save drive options
	 */

	val = dm_get_attr_value(root, "DRIVE", "ReserveDrive");
	if (val == NULL) {
		mms_pn_destroy(root);
		return (-1);
	}
	if (strcmp(val, "yes") == 0) {
		wka->dm_flags |= DM_RESERVE_DRIVE;
	} else {
		wka->dm_flags &= ~DM_RESERVE_DRIVE;
	}

	val = dm_get_attr_value(root, "DRIVE", "DriveSerialNum");
	if (val == NULL) {
		mms_pn_destroy(root);
		return (-1);
	}
	memset(drv->drv_serial_num, 0, sizeof (drv->drv_serial_num));
	strncpy(drv->drv_serial_num, val, sizeof (drv->drv_serial_num) - 1);
	mms_pn_destroy(root);
	return (0);
}

void
dm_send_request(char **reply, int msgid, ...)
{
	char		*req_cmd;
	char		*task;
	mms_par_node_t	*root;
	dm_command_t	*cmd;
	mms_par_node_t	*text;
	mms_par_node_t	*val;
	mms_par_node_t	*work = NULL;
	char		*msgcl;
	va_list		args;

	*reply = NULL;
	task = dm_bld_task("request");
	va_start(args, msgid);
	msgcl = mms_bld_msgcl(msgid, args);
	va_end(args);
	req_cmd = mms_strnew("request task ['%s'] type[DM] "
	    "priority ['1000'] %s ;", task, msgcl);
	cmd = dm_send_cmd(req_cmd, dm_cmd_response, task);
	free(req_cmd);
	free(task);
	free(msgcl);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to send request"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return;
	}
	root = cmd->cmd_root;

	/*
	 * Get reply
	 */
	text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, NULL);
	/* Skip down to the replied value */
	val = mms_pn_lookup(text, NULL, MMS_PN_STRING, &work);
	val = mms_pn_lookup(text, NULL, MMS_PN_STRING, &work);
	val = mms_pn_lookup(text, NULL, MMS_PN_STRING, &work);
	*reply = val->pn_string;
	val->pn_string = NULL;

	dm_destroy_cmd(cmd);
}

char	*
dm_get_attr_value(mms_par_node_t *root, char *obj, char *attr)
{
	mms_par_node_t	*name;
	mms_par_node_t	*val;
	mms_par_node_t	*work = NULL;

	name = mms_pn_lookup(root, attr, MMS_PN_STRING, &work);
	if (name == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "%s.'%s' not found", obj, attr));
		return (NULL);
	}

	val = mms_pn_lookup(root, "", MMS_PN_STRING, &work);
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "%s.'%s' has no value", obj, attr));
		return (NULL);
	}
	TRACE((MMS_DEBUG, "'%s' '%s'", attr, mms_pn_token(val)));
	return (mms_pn_token(val));
}

int
dm_update_bitformat(void)
{
	int		den;
	mms_sym_t		*mms_sym;
	char		*cmdbuf;
	char		*task;
	dm_command_t	*cmd;

	/*
	 * Get current density
	 */
	if (DRV_CALL(drv_get_density, (&den, NULL)) != 0) {
		return (-1);
	}

	/*
	 * If current density matches density of requested bitformat density,
	 * then no need to update.
	 */
	if (mnt->mnt_bitformat != NULL) {
		if (den == (mnt->mnt_bitformat->sym_code & 0xff)) {
			return (0);
		}
	}

	/*
	 * Lookup density name
	 */
	for (mms_sym = drv->drv_density; mms_sym->sym_token != NULL;
	    mms_sym++) {
		if (mms_sym->sym_code == den) {
			break;
		}
	}
	if (mms_sym->sym_token == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_DENSITY,
		    "Unsupported density 0x%x", den));
		return (-1);
	}
	mnt->mnt_bitformat = mms_sym;

	/*
	 * Update bitformat
	 */
	task = dm_bld_task("update-bitformat");
	cmdbuf = mms_strnew("attribute task['%s'] "
	    "match[ and (streq(CARTRIDGE.'CartridgePCL' '%s') "
	    "streq(SIDE.'SideName' '%s') "
	    "streq(PARTITION.'PartitionName' '%s') "
	    "streq(DRIVE.'DriveName' '%s'))]"
	    "set [ PARTITION.'PartitionBitFormat' 'bitformat_%s' ] ;",
	    task, dca->dca_pcl, dca->dca_side_name, dca->dca_part_name,
	    drv->drv_drvname,
	    mms_sym->sym_token);
	cmd = dm_send_cmd(cmdbuf, dm_cmd_response, task);
	free(cmdbuf);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		TRACE((MMS_ERR, "Unable to update bitformat"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}

	dm_destroy_cmd(cmd);
	return (0);
}

mms_sym_t	*
dm_sym_in(mms_sym_t *arr, char *token)
{
	mms_sym_t		*mms_sym;

	for (mms_sym = arr; mms_sym->sym_token != NULL; mms_sym++) {
		if (strcmp(mms_sym->sym_token, token) == 0) {
			/* mms_sym in arr */
			return (mms_sym);
		}
	}
	/*
	 * Symbol not in array
	 */
	return (NULL);
}
