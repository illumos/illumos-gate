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


#include <mms.h>
#include <mgmt_mms.h>

#define	MMS_API_MSG "message task [\"3999\"] who [operator] \
severity [error] %s; "

#if mms_lint
extern int mms_select_large_fdset(int, fd_set *_RESTRICT_KYWD,
    fd_set *_RESTRICT_KYWD, fd_set *_RESTRICT_KYWD,
    struct timeval *_RESTRICT_KYWD);
#define	select mms_select_large_fdset
#endif

static char	*_SrcFile = __FILE__;

/*
 * mms_serr()
 *
 * Parameters:
 *	- severity	The severity of the system error encountered
 *	- file		The name of the file in which the error occurred
 *	- line		The line number in the file where the error occurred
 *	- fmt		The format of the message to be mms_printed.
 *	- ...		The variable number of arguments for the message.
 *
 * This function is used within the MMS API to handle system errors that
 * are not recoverable from. The function outputs the critial message to
 * the mms_trace file and then aborts. This function is used to handle
 * system errors such as thread function errors.
 *
 * Return Values:
 *	None
 *
 */
void
mms_serr(mms_trace_sev_t severity, char *file, int line, const char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	mms_trace_va(severity, file, line, fmt, args);
	va_end(args);

	mms_trace_flush();
	mms_trace_close();
	abort();
}

#define	MMS_API_ERR_FMT 	"response task [\"%s\"] error [%s %s] %s;"
#define	MMS_API_MSG_PAD	30

/*
 * mms_gen_err_rsp()
 *
 * Parameters:
 *	- tid		The task id of the command to receive error response
 *	- code		The code to use in the error response
 *	- err_msg	The error message to use in the error response
 *
 * This function is used within the MMS API to generate an error response.
 * This is only used in the mms_api_reader to send a generated error
 * response to async commands waiting for a response. This is done
 * when the API has an internal processing error that it cannot recover
 * from
 *
 * Return Values:
 *	The generated error response if it could create it or NULL
 *
 */
mms_rsp_ele_t *
mms_gen_err_rsp(char *tid, int code, char *err_msg)
{
	mms_list_t		err_list;
	mms_par_err_t	*err;
	mms_par_node_t	*cmd;
	mms_rsp_ele_t	*rsp;
	char		*err_rsp;
	char		*s_internal;
	char		*s_code;
	int		len = MMS_API_MSG_PAD;

	if ((rsp = (mms_rsp_ele_t *)malloc(sizeof (mms_rsp_ele_t))) == NULL) {
		mms_serr(MMS_CRIT, "mms_gen_err_rsp: Malloc of space for new "
		    "error response failed with errno - %s", strerror(errno));
	}

	rsp->mms_rsp_tid = strdup(tid);
	rsp->mms_rsp_type = MMS_API_RSP_FINAL_ERR;
	rsp->mms_rsp_cmd = NULL;

	s_internal = mms_sym_code_to_str(MMS_INTERNAL);
	s_code = mms_sym_code_to_str(code);
	len += strlen(MMS_API_ERR_FMT) + strlen(tid) + strlen(s_internal) +
	    strlen(s_code);
	if (err_msg)
		len += strlen(err_msg);

	err_rsp = malloc(len);
	if (!err_rsp) {
		mms_serr(MMS_CRIT, "mms_gen_err_rsp: Malloc of space for "
		    "error message failed with errno - %s", strerror(errno));
	}

	(void) snprintf(err_rsp, len,
	    MMS_API_ERR_FMT, tid, s_internal, s_code,
	    err_msg ? err_msg : "API Error");
	rsp->mms_rsp_str = err_rsp;

	if (mms_mmp_parse(&cmd, &err_list, err_rsp)) {
		/* Should never occur unless error response format */
		/* has a syntax error or the parser cannot obtain */
		/* memory for the parse tree */
		mms_trace(MMS_ERR, "mms_gen_err_rsp: parse error detected "
		    "during generation of error response:\n%s", err_rsp);
		mms_list_foreach(&err_list, err) {
			mms_trace(MMS_ERR, "mms_gen_err_rsp: "
			    "mms_mmp_parse, line %d, col %d, "
			    "near token \"%s\", err code %d, %s",
			    err->pe_line, err->pe_col,
			    err->pe_token, err->pe_code,
			    err->pe_msg);
		}
		mms_pe_destroy(&err_list);
		rsp->mms_rsp_cmd = NULL;
		return (rsp);
	}
	mms_pe_destroy(&err_list);
	rsp->mms_rsp_cmd = cmd;
	return (rsp);
}

/*
 * mms_msglen
 *
 * Calculate the message length.
 */
static int
mms_msglen(const char *fmt, int nargs, va_list args)
{
	char	*ap;
	int	len = MMS_API_MSG_PAD;
	int	i;

	len += strlen(fmt);
	for (i = 0; i < nargs; i++) {
		ap = va_arg(args, char *);
		len += strlen(ap);
	}

	return (len);
}

/*
 * mms_crtmsg
 *
 * Create an error response message.
 */
static char *
mms_crtmsg(const char *fmt, int len, va_list args)
{
	char	*msg;

	msg = malloc(len);
	if (msg == NULL)
		return (NULL);

	if (vsnprintf(msg, len, fmt, args) == -1) {
		free(msg);
		return (NULL);
	}

	return (msg);
}

/*
 * mms_errmsg
 *
 * Allocate the memory for and then create and return an
 * error message.
 */
static char *
mms_errmsg(const char *fmt, int nargs, ...)
{
	va_list	arglist;
	char	*message;
	int	len;

	va_start(arglist, nargs);
	len = mms_msglen(fmt, nargs, arglist);
	va_end(arglist);

	/*
	 *   Create the error message.
	 */
	va_start(arglist, nargs);
	message = mms_crtmsg(fmt, len, arglist);
	va_end(arglist);

	return (message);
}


/*
 *   mms_log_error
 *
 *   Output an error message to a log file.
 */
static void
mms_log_error(mms_session_t *sp, char *message)
{
	mms_par_err_t	*err;
	mms_par_node_t	*msg;
	mms_list_t		err_list;
	char		*lmsg;
	char		*err_msg;
	int		len = MMS_API_MSG_PAD;

	if (sp->clog == NULL)
		return;

	if (message == NULL)
		return;

	len += strlen(MMS_API_MSG) + strlen(message);
	err_msg = malloc(len);
	if (!err_msg) {
		free(message);
		return;
	}

	if (snprintf(err_msg, len, MMS_API_MSG, message) == -1) {
		mms_trace(MMS_ERR, "mms_log_error: Unable to create API error "
		    "message:\n%s", message);
		free(err_msg);
		free(message);
	}

	if (mms_mmp_parse(&msg, &err_list, err_msg)) {

		/*
		 *  Should never occur unless message format has a syntax
		 *  error or the parser cannot obtain memory for the parse
		 *  tree.
		 */
		mms_trace(MMS_ERR, "mms_log_error: parse error detected "
		    "during generation of message:\n%s", message);
		mms_list_foreach(&err_list, err) {
			mms_trace(MMS_ERR,
			    "mms_log_error: mms_mmp_parse, line %d, "
			    "col %d, near token \"%s\", err code %d, %s",
			    err->pe_line, err->pe_col,
			    err->pe_token, err->pe_code,
			    err->pe_msg);
		}
		mms_pe_destroy(&err_list);
		mms_trace(MMS_DEBUG, "mms_log_error: Outputing default "
		    "message to clients log");
		sp->clog(sp->cprefix, message);
		free(err_msg);
		free(message);
		return;
	}
	mms_pe_destroy(&err_list);
	if ((lmsg = mms_get_msg(msg)) != NULL) {
		sp->clog(sp->cprefix, lmsg);
	} else {
		mms_trace(MMS_DEBUG, "mms_log_error: Outputing default "
		    "message to client's log");
		sp->clog(sp->cprefix, message);
	}
	mms_pn_destroy(msg);
	free(err_msg);
	free(message);
}

/*
 * mms_send_errmsg()
 *
 * Parameters:
 *	- session	Connection to MMS to use.
 *	- message	The mms api error message to log to client
 *
 * This function will log a error that is internal to MMS into the
 * clients log file if it is enabled. The message is in the mms catalog
 * and thus will be internationalized. If any type of error is encountered,
 * the message itself will be outputed to the log file.
 *
 * Return Values:
 *	- None
 *
 */
void
mms_send_errmsg(mms_session_t *sp, const char *fmt, int nargs, ...)
{
	va_list		arglist;
	char		*message;
	int		len;

	if (sp->clog == NULL)
		return;

	/*
	 *   Calculate the message length.
	 */
	va_start(arglist, nargs);
	len = mms_msglen(fmt, nargs, arglist);
	va_end(arglist);

	va_start(arglist, nargs);
	message = mms_crtmsg(fmt, len, arglist);
	va_end(arglist);
	if (!message)
		return;

	mms_trace(MMS_DEBUG, "mms_send_errmsg: Send message to "
	    "client's log file:\n%s", message);

	mms_log_error(sp, message);
}


/*
 *   mms_rsp_extract
 *
 *   Extract the command, command type, and tag from the response.
 *
 *   Return:
 *	0	Successful
 *	> 0 	API Error
 *	< 0	Response specific error
 */
int
mms_rsp_extract(mms_session_t *sp, char *input, mms_par_node_t **cmdp,
    int *resp_type, char **tid, char **msg)
{
	mms_list_t		err_list;
	mms_par_err_t	*err;
	mms_par_node_t	*cmd;
	mms_par_node_t	*cnode;
	mms_par_node_t	*clause;
	mms_par_node_t	*value;

	*tid = NULL;

	if (mms_mmp_parse(cmdp, &err_list, input)) {
		mms_trace(MMS_ERR, "mms_rsp_extract: parse error "
		    "detected on MMS input:\n%s", input);
		err = mms_list_head(&err_list);
		if (err) {
			mms_trace(MMS_ERR,
			    "mms_rsp_extract: mms_mmp_parse, line "
			    "%d, col %d, near token \"%s\", err code %d, %s",
			    err->pe_line, err->pe_col,
			    err->pe_token, err->pe_code,
			    err->pe_msg);
		}
/* XXX SEE IF LM PARSE MMS_ERROR CODE CAN BE ADAPTED TO WORK HERE AS WELL */
		*msg = mms_errmsg(MMS_API_3017_MSG, 1, (err == NULL) ?
		    "parse error" : err->pe_msg);
		mms_pe_destroy(&err_list);
		return (MMS_E_INVALID_RESPONSE);
	}

	mms_pe_destroy(&err_list);
	cmd = *cmdp;

	cnode = mms_pn_lookup(cmd, NULL, MMS_PN_CMD, NULL);
	if (cnode == NULL) {
		mms_trace(MMS_CRIT, "mms_rsp_extract: No command "
		    "node found in what should be a valid "
		    "response or event from MMS:\n%s", input);
		mms_pn_destroy(cmd);
		*msg = mms_errmsg(MMS_API_3014_MSG, 2, "command node",
		    "command node");
		return (MMS_E_INVALID_RESPONSE);
	}

	/*
	 *   Validate the response.
	 */
	if ((strcmp("response", mms_pn_token(cnode)) != 0) &&
	    (strcmp("event", mms_pn_token(cnode)) != 0)) {
		mms_trace(MMS_ERR, "mms_rsp_extract: Received a non "
		    "response or event input from MMS:\n%s", input);
		mms_pn_destroy(cmd);
		return (-1);
	}

	/*
	 *   Process an event.
	 */
	if (strcmp("event", mms_pn_token(cnode)) == 0) {

		mms_trace(MMS_DEBUG, "mms_rsp_extract: Received an "
		    "event from MMS:\n%s", input);

		clause = mms_pn_lookup(cmd, "tag", MMS_PN_CLAUSE, NULL);
		if (clause == NULL) {
			mms_trace(MMS_ERR, "mms_rsp_extract: No tag "
			    "clause found in event:\n%s", input);
			*msg = mms_errmsg(MMS_API_3013_MSG, 0);
			mms_pn_destroy(cmd);
			return (-1);
		}

		value = mms_pn_lookup(clause, NULL, MMS_PN_STRING, NULL);
		if (value == NULL) {
			mms_trace(MMS_ERR, "mms_rsp_extract: No tag "
			    "string found in event:\n%s", input);
			*msg = mms_errmsg(MMS_API_3013_MSG, 0);
			mms_pn_destroy(cmd);
			return (-1);
		}

		*resp_type = MMS_API_RSP_EVENT;
		*tid = strdup(mms_pn_token(value));

	/*
	 *   Process an unacceptable response.
	 */
	} else if (mms_pn_lookup(cmd, "unacceptable", MMS_PN_KEYWORD,
	    NULL) != NULL) {

		mms_trace(MMS_DEBUG, "mms_rsp_extract: Received an "
		    "unaccept response from MMS");
		*tid = strdup(sp->mms_acc_tid);
		*resp_type = MMS_API_RSP_UNACC;

	/*
	 *   Process all other response types.
	 */
	} else {

		mms_trace(MMS_DEVP, "mms_rsp_extract: Received a response "
		    "from MMS:\n%s", input);

		clause = mms_pn_lookup(cmd, "task", MMS_PN_CLAUSE, NULL);
		if (clause == NULL) {
			mms_trace(MMS_ERR, "mms_rsp_extract: No task "
			    "clause found in response:\n%s", input);
			mms_pn_destroy(cmd);
			*msg = mms_errmsg(MMS_API_3014_MSG, 2,
			    "task id clause", "task id clause");
			return (MMS_MISSING_TASKID);
		}
		value = mms_pn_lookup(clause, NULL, MMS_PN_STRING, NULL);
		if (value == NULL) {
			mms_trace(MMS_ERR, "mms_rsp_extract: No task"
			    "string found in response:\n%s", input);
			mms_pn_destroy(cmd);
			*msg = mms_errmsg(MMS_API_3014_MSG, 2,
			    "task id string", "task id string");
			return (MMS_MISSING_TASKID);
		}

		*tid = strdup(mms_pn_token(value));

		/*
		 *   Determine the response type.
		 */
		if (mms_pn_lookup(cmd, "accepted", MMS_PN_KEYWORD, NULL)
		    != NULL) {
			mms_trace(MMS_DEBUG, "mms_rsp_extract: Received an "
			    "accept response");
			*resp_type = MMS_API_RSP_ACC;

		} else if (mms_pn_lookup(cmd, "success",
		    MMS_PN_KEYWORD, NULL) != NULL) {
			mms_trace(MMS_DEBUG, "mms_rsp_extract: Received a "
			    "success response");
			*resp_type = MMS_API_RSP_FINAL;

		} else if (mms_pn_lookup(cmd, "intermediate",
		    MMS_PN_KEYWORD, NULL) != NULL) {
			mms_trace(MMS_DEBUG, "mms_rsp_extract: Received an "
			    "intermediate response");
			*resp_type = MMS_API_RSP_FINAL_INTR;

		} else if (mms_pn_lookup(cmd, "error",
		    MMS_PN_CLAUSE, NULL) != NULL) {
			mms_trace(MMS_DEBUG, "mms_rsp_extract: Received an "
			    "error response");
			*resp_type = MMS_API_RSP_FINAL_ERR;

		} else if (mms_pn_lookup(cmd, "cancelled",
		    MMS_PN_KEYWORD, NULL) != NULL) {
			mms_trace(MMS_DEBUG, "mms_rsp_extract: Received a "
			    "cancelled response");
			*resp_type = MMS_API_RSP_FINAL_CANC;

		} else {
			mms_trace(MMS_CRIT, "mms_rsp_extract: Recevied an "
			    "unknown type of response:\n%s", input);
			*msg = mms_errmsg(MMS_API_3006_MSG, 2, *tid, *tid);
			mms_pn_destroy(cmd);
			return (MMS_INVALID_RSP);
		}
	}

	return (0);
}


/*
 *   mms_rsp_read
 *
 *   Wait for and read a response from the MM.
 *
 *   Return:
 *	0	Successful
 *	> 0 	API Error
 *	< 0	Response specific error
 */
int
mms_rsp_read(mms_session_t *sp, mms_rsp_ele_t **rsp, char **msg)
{
	fd_set		fdset;
	struct timeval	tv;
	struct timeval	*tvp;
	mms_par_node_t	*cmd;		/* ptr to parsed input string */
	char		*input = NULL;	/* ptr to input string from MM */
	char		*tid = NULL;
	int		resp_type = 0;
	int		rc;

	*rsp = NULL;
	*msg = NULL;

	/* LINTED warning: constant in conditional context */
	while (1) {
		if (sp->mms_api_state == MMS_API_SHUTDOWN) {
			mms_trace(MMS_OPER, "mms_rsp_read: MMS "
			    "API session is being terminated");
			*msg = mms_errmsg(MMS_API_3018_MSG, 0);
			return (MMS_API_SHUTDOWN);
		}

		if (sp->mms_api_state == MMS_API_FAILURE) {
			mms_trace(MMS_ERR, "mms_rsp_read: MMS API is in a state"
			    " of error, returning error response for command");
			*msg = mms_errmsg(MMS_API_3001_MSG, 0);
			return (sp->mms_api_errcode);
		}

		FD_ZERO(&fdset);
		FD_SET(sp->mms_conn.mms_fd, &fdset);

		tv.tv_sec = 10;
		tv.tv_usec = 0;
		tvp = &tv;

		rc = select(sp->mms_conn.mms_fd + 1, &fdset, NULL, NULL, tvp);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EBADF) {
				if (sp->mms_api_state == MMS_API_SHUTDOWN)
					continue;
				mms_trace(MMS_ERR, "mms_rsp_read: "
				    "Socket to MMS is not open");
				*msg = mms_errmsg(MMS_API_3010_MSG, 0);
				return (MMS_E_NET_IO_ERR);
			} else {
				mms_trace(MMS_ERR, "mms_rsp_read: select "
				    "failed with errno - %s", strerror(errno));
				*msg = mms_errmsg(MMS_API_3011_MSG, 2,
				    strerror(errno), strerror(errno));
				return (MMS_SELECT_ERROR);
			}
		} else if (rc == 0) {	/* select timeout hit */
			continue;
		} else { 	/* something to read on socket */
			break;
		}
	}

	/*
	 *   Obtain next response from mm.
	 */
	if ((rc = mms_reader(&sp->mms_conn, &input)) <= 0) {
		if (rc == 0) {
			mms_trace(MMS_ERR, "mms_rsp_read: MMS "
			    "disconnected from client");
		} else {
			mms_trace(MMS_ERR, "mms_rsp_read: Failed "
			    "to read new response, rc - %d", rc);
		}
		*msg = mms_errmsg((rc == 0) ? MMS_API_3012_MSG :
		    MMS_API_3013_MSG, 0);
		return (MMS_E_NET_IO_ERR);
	}

	/*
	 *   Extract the command, type and tag from the data.
	 */
	rc = mms_rsp_extract(sp, input, &cmd, &resp_type, &tid, msg);
	if (rc) {
		free(input);
		return (rc);
	}

	/*
	 *  Create the response structure.
	 */
	*rsp = mms_rsp_create(input, cmd, resp_type, tid);

	return (0);
}


/*
 *   mms_obtain_accept
 *
 *   Wait for and then process an accept response.
 */
int
mms_obtain_accept(mms_session_t *sp, char *tid, mms_rsp_ele_t **ret_rsp)
{
	mms_rsp_ele_t	*rsp;
	int		rc = MMS_API_OK;
	int		c;

	mms_trace(MMS_DEBUG, "mms_obtain_accept: Thread looking for accept "
	    "response, tid - %s", tid);

	if ((c = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_obtain_accept: Lock of MMS "
		    "accept mutex failed with errno - %s", strerror(c));
	}

	*ret_rsp = NULL;

	/* LINTED warning: constant in conditional context */
	while (1) {

		if (sp->mms_api_state == MMS_API_SHUTDOWN) {
			mms_trace(MMS_OPER, "mms_obtain_accept: MMS API "
			    "session is being terminated");
			mms_send_errmsg(sp, MMS_API_3018_MSG, 0);
			rc = MMS_API_SHUTDOWN;
			break;
		}

		/*
		 *  Check to see if MMS API has encountered an
		 *  internal processing error.
		 */
		if (sp->mms_api_state == MMS_API_FAILURE) {
			mms_trace(MMS_ERR, "mms_obtain_accept: MMS API is in "
			    "a state of error, returning an error response "
			    "for command with task id %s", tid);
			mms_send_errmsg(sp, MMS_API_3001_MSG, 0);
			rc = sp->mms_api_errcode;
			break;
		}

		/*
		 *  Process an accept/unaccept if it was received.
		 */
		if ((rsp = sp->mms_acc_rsp) != NULL) {

			sp->mms_acc_rsp = NULL;
			sp->mms_acc_tid = mms_empty_string;

			if (rsp->mms_rsp_type == MMS_API_RSP_ACC &&
			    strcmp(tid, rsp->mms_rsp_tid) != 0) {

				mms_trace(MMS_ERR, "mms_obtain_accept: Task "
				    "id of accept response, %s, and task id of "
				    "last command sent to MMS, %s, do not "
				    "match", rsp->mms_rsp_tid, tid);

				sp->mms_api_errcode = MMS_WRONG_TASKID;
				sp->mms_api_state = MMS_API_FAILURE;
				mms_send_errmsg(sp, MMS_API_3008_MSG, 4, tid,
				    rsp->mms_rsp_tid, tid, rsp->mms_rsp_tid);
				mms_free_rsp(rsp);
				rc = MMS_WRONG_TASKID;
			}
			break;
		}

		/*
		 *   Wait for the accept response, becoming the socket
		 *   reader if no thread is currently reading from socket.
		 */
		if (! pthread_mutex_trylock(&sp->mms_reading)) {

			if ((c = pthread_mutex_unlock(&sp->mms_acc_mutex))
			    != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_accept: "
				    "Unlock of MMS accept mutex failed "
				    "with errno - %s", strerror(c));
			}

			rc = mms_sync_reader(sp, MMS_API_RSP_ACC, tid, &rsp);

			if ((c = pthread_mutex_lock(&sp->mms_acc_mutex))
			    != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_accept: Lock of"
				    " MMS accept mutex failed with errno - %s",
				    strerror(c));
			}

			if (rc != MMS_API_OK)
				break;

		} else {
			if ((c = pthread_cond_wait(&sp->mms_acc_cv,
			    &sp->mms_acc_mutex)) != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_accept: "
				    "Unable to wait on accept condition"
				    " variable, errno - %s", strerror(c));
			}
		}

		mms_trace(MMS_DEBUG, "mms_obtain_accept: Thread woken up "
		    "by broadcast from reader thread to look for a accept "
		    "response, tid - %s", tid);
	}

	if ((c = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_obtain_accept: Unlock of MMS "
		    "accept mutex failed with errno - %s", strerror(c));
	}

	*ret_rsp = rsp;

	return (rc);
}


/*
 * mms_obtain_event()
 *
 * This function obtains an event that has been sent by the MM.
 *
 * Return Values:
 *	MMS_API_OK	If an event was obtained from MMS.
 *	! MMS_API_OK	If an error occurred during processing.
 *
 */
int
mms_obtain_event(mms_session_t *sp, mms_rsp_ele_t **event)
{
	mms_rsp_ele_t	*rsp;
	int		err;
	int		rc;

	mms_trace(MMS_DEBUG, "mms_obtain_event: Obtain the next sync event");

	*event = NULL;
	if (sp == NULL) {
		mms_trace(MMS_ERR,
		    "mms_obtain_event: Session pointer is set to "
		    "NULL, unable to obtain any events at this time");
		mms_send_errmsg(sp, MMS_API_3000_MSG, 0);
		return (MMS_WRONG_API_MODE);
	}

	if ((rc = pthread_mutex_lock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_obtain_event: Lock of MMS event list "
		    "mutex failed with errno - %s", strerror(rc));
	}
	/* LINTED constant in conditional context */
	while (1) {
		if (sp->mms_api_state == MMS_API_SHUTDOWN) {
			mms_trace(MMS_OPER, "mms_obtain_event: MMS API "
			    "session is being terminated");
			rc = MMS_API_SHUTDOWN;
			break;
		}
		if (sp->mms_api_state == MMS_API_FAILURE) {
			mms_trace(MMS_ERR, "mms_obtain_event: MMS API is in a "
			    "state of error, unable to obtain any events "
			    "at this time");
			rc = sp->mms_api_errcode;
			break;
		}

		/*
		 *   Check for a queued event.
		 */
		if ((rsp = mms_list_head(&sp->mms_ev_list)) != NULL) {

			mms_trace(MMS_DEBUG,
			    "mms_obtain_event: Found event with %s"
			    " tag waiting to be processed", rsp->mms_rsp_tid);

			mms_list_remove(&sp->mms_ev_list, rsp);

			rc = MMS_API_OK;
			*event = rsp;
			break;
		}

		/*
		 *   Did not find a event for thread.
		 */
		mms_trace(MMS_DEBUG,
		    "mms_obtain_event: No event waiting, check if "
		    "any thread is reading from socket to MM");

		/*
		 *   If no thread reading from MM, become reader thread.
		 */
		if (! pthread_mutex_trylock(&sp->mms_reading)) {

			if ((rc = pthread_mutex_unlock(&sp->mms_ev_mutex))
			    != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_event: Unlock "
				    "of MMS event list mutex failed with errno"
				    " - %s", strerror(rc));
			}

			rc = mms_sync_reader(sp, MMS_API_RSP_EVENT, "",
			    &rsp);

			*event = rsp;
			return (rc);

		} else {
			mms_trace(MMS_DEBUG, "mms_obtain_event: Reader thread "
			    "already exists, going into wait");

			if ((rc = pthread_cond_wait(&sp->mms_ev_cv,
			    &sp->mms_ev_mutex)) != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_event: Wait on "
				    "MMS event condition variable failed with "
				    "errno - %s", strerror(rc));
			}
		}
		mms_trace(MMS_DEBUG, "mms_obtain_event: Thread woke up "
		    "by broadcast from reader thread");
	}

	if ((err = pthread_mutex_unlock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_obtain_event: Unlock of MMS event "
		    "list mutex failed with errno - %s", strerror(err));
	}

	return (rc);
}


/*
 *   mms_obtain_final
 *
 *   Wait for and then process a final response.
 */
int
mms_obtain_final(mms_session_t *sp, char *tid, mms_rsp_ele_t **final_rsp)
{
	mms_rsp_ele_t	*rsp;
	int		rc;
	int		c;

	mms_trace(MMS_DEBUG, "mms_obtain_final: Thread looking for final "
	    "response, tid - %s", tid);

	if ((c = pthread_mutex_lock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_obtain_final: Lock of MMS "
		    "response mutex failed with errno - %s", strerror(c));
	}

	*final_rsp = NULL;

	/* LINTED warning: constant in conditional context */
	while (1) {

		if (sp->mms_api_state == MMS_API_SHUTDOWN) {
			mms_trace(MMS_OPER, "mms_obtain_final: MMS API "
			    "session is being terminated");
			mms_send_errmsg(sp, MMS_API_3018_MSG, 0);
			rc = MMS_API_SHUTDOWN;
			break;
		}

		/*
		 *  Check to see if MMS API has encountered an
		 *  internal processing error.
		 */
		if (sp->mms_api_state == MMS_API_FAILURE) {
			mms_trace(MMS_ERR, "mms_obtain_final: MMS API is in "
			    "a state of error, returning an error response "
			    "for command with task id %s", tid);
			mms_send_errmsg(sp, MMS_API_3001_MSG, 0);
			rc = sp->mms_api_errcode;
			break;
		}

		/*
		 *  Go through response list to see if a final
		 *  response for the specified command exists.
		 */
		if ((rsp = mms_rsp_find(sp, tid)) != NULL) {
			*final_rsp = rsp;
			rc = MMS_API_OK;
			break;
		}

		/*
		 *   Wait for the final response, becoming the socket
		 *   reader if no thread is currently reading from socket.
		 */
		if (! pthread_mutex_trylock(&sp->mms_reading)) {

			if ((c = pthread_mutex_unlock(&sp->mms_rsp_mutex))
			    != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_final: "
				    "Unlock of MMS wait response mutex failed "
				    "with errno - %s", strerror(c));
			}

			rc = mms_sync_reader(sp, MMS_API_RSP_FINAL, tid,
			    final_rsp);

			if ((c = pthread_mutex_lock(&sp->mms_rsp_mutex))
			    != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_final: "
				    "Lock of MMS wait response mutex failed "
				    "with errno - %s", strerror(c));
			}
			break;

		} else {
			if ((c = pthread_cond_wait(&sp->mms_rsp_cv,
			    &sp->mms_rsp_mutex)) != 0) {
				mms_serr(MMS_CRIT, "mms_obtain_final: "
				    "Unable to wait on accept condition"
				    " variable, errno - %s", strerror(c));
			}
		}

		mms_trace(MMS_DEBUG, "mms_obtain_final: Thread woken up "
		    "by broadcast from reader thread to look for a final "
		    "response, tid - %s", tid);
	}

	if ((c = pthread_mutex_unlock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_obtain_final: Unlock of MMS "
		    "response mutex failed with errno - %s", strerror(c));
	}

	return (rc);
}


/*
 *   mms_send
 *
 *   Send a command and wait for an accept.
 */
int
mms_send(mms_session_t *sp, char *tid, mms_cmd_name_t cmdtype, char *cmd,
    mms_rsp_ele_t **rsp)
{
	mms_rsp_ele_t	*rsp_accept;
	int		cmdlen;
	int		rc;
	int		c;

	/*
	 *   A response is returned on synchronous requests.
	 */
	if (rsp)
		*rsp = NULL;

	/*
	 *   Only one begin-end command sequence may be pending at a time,
	 *   If this is a 'begin' command or a command sent synchronously,
	 *   wait for any pending command sequences to complete before
	 *   allowing this command to be sent.
	 */
	if (cmdtype == MMS_CMD_BEGIN || rsp != NULL) {
		mms_be_wait(sp, cmdtype == MMS_CMD_BEGIN);
	}

	/*
	 *   Stop other clients from sending commands until this
	 *   client receives an accept or unaccept to this command.
	 */
	if ((c = pthread_mutex_lock(&sp->mms_cacc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_send: Lock on MMS command "
		    "accept mutex failed with errno - %s", strerror(c));
	}

	sp->mms_acc_tid = tid;
	sp->mms_acc_rsp = NULL;
	cmdlen = strlen(cmd);

	if ((c = pthread_mutex_lock(&sp->mms_conn_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_send: Lock of MMS connection "
		    "mutex failed with errno - %s", strerror(c));
	}

	/*
	 *   Write the command to the socket.
	 */
	rc = mms_writer(&sp->mms_conn, cmd);

	if ((c = pthread_mutex_unlock(&sp->mms_conn_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_send: Unlock of MMS "
		    "connection mutex failed with errno - %s", strerror(c));
	}

	if (rc != cmdlen) {
		mms_trace(MMS_CRIT, "mms_send: mms_writer failed, "
		    "rc - %d, command being sent:\n%s", rc, cmd);
		if ((c = pthread_mutex_unlock(&sp->mms_cacc_mutex)) != 0) {
			mms_serr(MMS_CRIT, "mms_send: Unlock of MMS "
			    "command accept mutex failed with errno - %s",
			    strerror(c));
		}
		if (cmdtype == MMS_CMD_END || cmdtype == MMS_CMD_BEGIN)
			mms_be_wakeup(sp);
		mms_send_errmsg(sp, MMS_API_3005_MSG, 2, tid, tid);
		sp->mms_api_errcode = MMS_E_NET_IO_ERR;
		sp->mms_api_state = MMS_API_FAILURE;
		return (MMS_E_NET_IO_ERR);
	}

	/*
	 *   Wait for an accept response.
	 */
	rc = mms_obtain_accept(sp, tid, &rsp_accept);

	if (rc == MMS_API_OK) {
		if (rsp && rsp_accept->mms_rsp_type == MMS_API_RSP_UNACC) {
			*rsp = (void *)rsp_accept;
		} else {
			mms_free_rsp(rsp_accept);
		}
	}

	if ((c = pthread_mutex_unlock(&sp->mms_cacc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_send: Unlock of MMS command "
		    "accept mutex failed with errno - %s", strerror(c));
	}

	if (cmdtype == MMS_CMD_END ||
	    ((rc != MMS_API_OK) && (cmdtype == MMS_CMD_BEGIN))) {
		mms_be_wakeup(sp);
	}

	return (rc);
}


/*
 *   mms_sync_reader
 *
 *   Wait for and then process data written to the socket.
 */
int
mms_sync_reader(mms_session_t *sp, int wait_type, char *tid,
    mms_rsp_ele_t **final_rsp)
{
	mms_rsp_ele_t	*rsp;
	char		*msg;
	int		rc;
	int		c;

	*final_rsp = NULL;

	mms_trace(MMS_DEBUG, "mms_sync_reader: Thread becoming reader, tid %s",
	    tid);

	/* LINTED warning: constant in conditional context */
	while (1) {

		/*
		 *   Wait for data to be written to the socket.
		 */
		rc = mms_rsp_read(sp, &rsp, &msg);
		if (rc > 0) {
			break;
		} else if (rc < 0) {
			continue;
		}

		/*
		 *   Process an event response.  Add the event to the
		 *   event list is there is an registration for the event.
		 */
		if (rsp->mms_rsp_type == MMS_API_RSP_EVENT) {

			/*
			 *   If waiting for events, return this event.
			 *   Otherwise, queue the response and signal
			 *   the waiting thread.
			 */
			if (wait_type == MMS_API_RSP_EVENT) {
				break;
			} else {
				mms_ev_insert(sp, rsp);
			}

		/*
		 *   An accept/unaccept response was received.
		 */
		} else if (rsp->mms_rsp_type == MMS_API_RSP_UNACC ||
		    rsp->mms_rsp_type == MMS_API_RSP_ACC) {

			mms_acc_insert(sp, rsp);

			if (wait_type == MMS_API_RSP_ACC)
				break;

		/*
		 *    Process a final response.
		 */
		} else if (rsp->mms_rsp_type >= MMS_API_RSP_FINAL ||
		    rsp->mms_rsp_type <= MMS_API_RSP_FINAL_CANC) {

			if ((wait_type == MMS_API_RSP_FINAL) &&
			    strcmp(rsp->mms_rsp_tid, tid) == 0) {
				mms_trace(MMS_DEBUG, "mms_sync_reader: Found a "
				    "final response for itself, tid %s", tid);
				break;
			}

			mms_rsp_insert(sp, rsp);
		}
	}

	if (rc == MMS_API_OK) {
		*final_rsp = rsp;

	} else {
		mms_log_error(sp, msg);
		sp->mms_api_errcode = rc;
		if (rc == MMS_API_SHUTDOWN)
			sp->mms_api_state = MMS_API_SHUTDOWN;
		else
			sp->mms_api_state = MMS_API_FAILURE;
	}

	/*
	 *   Unlock and wakeup up threads waiting for a response to be
	 *   read. This will allow another thread to become the reader.
	 */
	if ((c = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Lock MMS accept "
		    "mutex failed with errno - %s", strerror(c));
	}
	if ((c = pthread_mutex_lock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Lock MMS response "
		    "mutex failed with errno - %s", strerror(c));
	}
	if ((c = pthread_mutex_lock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Lock MMS event "
		    "mutex failed with errno - %s", strerror(c));
	}

	/*
	 *   Release the reader lock.
	 */
	if ((c = pthread_mutex_unlock(&sp->mms_reading)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Unlock of MMS reading "
		    "mutex failed with errno - %s", strerror(c));
	}

	/*
	 *   Wake-up threads waiting on read. Another thread must
	 *   become the reader if waiting for a response.
	 */
	if ((c = pthread_cond_broadcast(&sp->mms_ev_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Broadcast on MMS event "
		    "response condition variable failed with errno - %s",
		    strerror(c));
	}
	if ((c = pthread_cond_broadcast(&sp->mms_rsp_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Broadcast on MMS "
		    "response condition variable failed with errno - %s",
		    strerror(c));
	}
	if ((c = pthread_cond_broadcast(&sp->mms_acc_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Broadcast on MMS "
		    "accept condition variable failed with errno - %s",
		    strerror(c));
	}

	if ((c = pthread_mutex_unlock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Unlock of MMS event "
		    "mutex failed with errno - %s", strerror(c));
	}
	if ((c = pthread_mutex_unlock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Unlock of MMS response "
		    "mutex failed with errno - %s", strerror(c));
	}
	if ((c = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sync_reader: Unlock of MMS accept "
		    "mutex failed with errno - %s", strerror(c));
	}
	return (rc);
}


/*
 * mms_api_reader()
 *
 * Parameters:
 *	- arg		The structure used to access the session to MMS
 *
 * The mms_async_init() starts this function as a standalone thread.
 * This thread reads input on behalf of a client connect to the MMS
 * through an async connection. It will currently handle accept/unaccept
 * and final command responses as well as unsolictied events that the client
 * has registered for.
 *
 * Return Values:
 *	None
 *
 */
void *
mms_api_reader(void *arg)
{
	mms_session_t	*sp;
	mms_rsp_ele_t	*new_rsp;
	mms_rsp_ele_t	*unacc_rsp;
	mms_cmd_ele_t	*cmd;
	char		*msg;
	char		*tid;
	int		rc;

	mms_trace(MMS_OPER, "mms_api_reader: MMS api reader thread started");

	sp = (mms_session_t *)arg;

	/*
	 *   Lock the reading thread.  The API reader thread should
	 *   always hold this lock.
	 */
	if (pthread_mutex_trylock(&sp->mms_reading)) {
		mms_trace(MMS_ERR, "mms_api_reader: Unable to obtain lock of "
		    "MMS reading mutex, reader thread exiting");
		sp->mms_api_errcode = MMS_ASYNC_API_FAILURE;
		sp->mms_api_state = MMS_API_FAILURE;
		/* log msg, set state, any wakeup */
		return ((void *)NULL);
	}

	/*
	 *   Reader thread ready for requests.
	 */
	mms_start_notify(sp);

	/*
	 *   Update the thread count.
	 */
	mms_thread_start(sp);

	/*
	 *   Wait for input from the MMS socket and process the response.
	 */

	/* LINTED warning: constant in conditional context */
	while (1) {

		/*
		 *   Wait for a response from the MM.
		 */
		rc = mms_rsp_read(sp, &new_rsp, &msg);
		if (rc > 0) {
			break;
		} else if (rc < 0) {
			continue;
		}

		/*
		 *   Process an event response.
		 */
		if (new_rsp->mms_rsp_type == MMS_API_RSP_EVENT) {

			if (sp->mms_ev_callbk != NULL) {
				mms_trace(MMS_DEBUG, "mms_api_reader: return "
				    "event with tag %s", new_rsp->mms_rsp_tid);
				sp->mms_ev_callbk(sp->mms_ev_callbk_param,
				    new_rsp);

			} else {
				mms_ev_insert(sp, new_rsp);
			}

		/*
		 *   Process an accept response.
		 */
		} else if (new_rsp->mms_rsp_type == MMS_API_RSP_ACC) {

			mms_acc_insert(sp, new_rsp);

		/*
		 *   Process an unaccept response.
		 */
		} else if (new_rsp->mms_rsp_type == MMS_API_RSP_UNACC) {

			cmd = mms_cmd_remove(sp, new_rsp->mms_rsp_tid);
			if (cmd == NULL) {
				msg = mms_errmsg(MMS_API_3015_MSG, 4,
				    "command list", new_rsp->mms_rsp_tid,
				    "command list", new_rsp->mms_rsp_tid);
				rc = MMS_API_ERR;
				break;
			}

			if (cmd->mms_cmd_type == MMS_API_ASYNC) {
				unacc_rsp = new_rsp;
				tid = strdup(new_rsp->mms_rsp_tid);
				new_rsp = mms_rsp_create(NULL, NULL,
				    MMS_API_RSP_UNACC, tid);
				cmd->mms_cmd_callbk(cmd->mms_cmd_callbk_param,
				    unacc_rsp);
			}

			mms_cmd_free(cmd);
			mms_acc_insert(sp, new_rsp);

		/*
		 *   Process a final response.
		 */
		} else if (new_rsp->mms_rsp_type >= MMS_API_RSP_FINAL ||
		    new_rsp->mms_rsp_type <= MMS_API_RSP_FINAL_CANC) {

			/*
			 *   Find the command in the command list.
			 */
			cmd = mms_cmd_remove(sp, new_rsp->mms_rsp_tid);
			if (cmd == NULL) {
				msg = mms_errmsg(MMS_API_3015_MSG, 4,
				    "command list", new_rsp->mms_rsp_tid,
				    "command list", new_rsp->mms_rsp_tid);
				mms_free_rsp(new_rsp);
				break;
			}

			mms_trace(MMS_DEBUG,
			    "mms_api_reader: Final response is for"
			    " %s command with task id %s", cmd->mms_cmd_type ==
			    MMS_API_ASYNC ? "asynchronous" : "synchronous",
			    new_rsp->mms_rsp_tid);

			if (cmd->mms_cmd_type == MMS_API_ASYNC) {
				cmd->mms_cmd_callbk(cmd->mms_cmd_callbk_param,
				    new_rsp);
			} else {
				mms_rsp_insert(sp, new_rsp);
			}

			mms_cmd_free(cmd);

		/*
		 *   An invalid response was received.
		 */
		} else {
			msg = mms_errmsg(MMS_API_3006_MSG, 2,
			    new_rsp->mms_rsp_tid, new_rsp->mms_rsp_tid);
			mms_free_rsp(new_rsp);
			break;
		}

	}

	/*
	 *   An unrecoverable error occurred.  Terminate processing
	 *   and wakeup any threads waiting for responses.
	 */
	sp->mms_api_errcode = rc;

	if (sp->mms_api_state != MMS_API_SHUTDOWN) {
		sp->mms_api_state = MMS_API_FAILURE;
		mms_cmd_flush(sp, msg);
		mms_rsp_wakeup(sp);
		mms_acc_wakeup(sp);
	}

	if (sp->mms_async_error != NULL)
		sp->mms_async_error(sp->mms_async_error_param);

	if (msg)
		free(msg);

	mms_thread_exit(sp);

	return (0);
}
