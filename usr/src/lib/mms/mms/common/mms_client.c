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

static char	*_SrcFile = __FILE__;
			/* Only first call to mms_init or mms_ainit */
			/* will create a mms_trace file if called for */

char	mms_empty_string[] = "empty";
char	*mms_empty_message = "No loctext message found\n";

char *mms_api[] = {
	"Unconfigured",
	"Asynchronous",
	"Synchronous",
	NULL};

char *mms_state[] = {
	"Unconfigured",
	"Configured",
	"Failure",
	"Shutdown",
	NULL};

/*
 * mms_free_rsp()
 *
 * Parameters:
 *	- rsp		Pointer to a response returned from one of
 *			routines that return a command response or
 *			the response sent to a callback routine.
 *
 * This function is used by a client to free unneeded responses to commands.
 * list elements.
 *
 * Return Values:
 *	None
 *
 */
void
mms_free_rsp(void *rsp)
{
	mms_rsp_ele_t *ele = (mms_rsp_ele_t *)rsp;

	if (ele != NULL) {
		if (ele->mms_rsp_tid != NULL)
			free(ele->mms_rsp_tid);
		if (ele->mms_rsp_str != NULL)
			free(ele->mms_rsp_str);
		if (ele->mms_rsp_cmd != NULL)
			mms_pn_destroy(ele->mms_rsp_cmd);
		free(ele);
		ele = NULL;
		mms_trace(MMS_DEBUG, "mms_free_rsp: Completed free of response "
		    "list element memory");
	} else {
		mms_trace(MMS_DEBUG, "mms_free_rsp: response list element is "
		    "NULL, no memory to free");
	}
}

/*
 * mms_handle_err_rsp()
 *
 * Parameters:
 *	- response	The error response to process
 *	- class		The class contained in the response
 *	- code		The code contained in the response
 *	- msg		The internationalized version of the error message
 *			This message needs to be freed by the client once
 *			it is done with it.
 *
 * This function takes an error response and processes on behalf of the
 * the client.
 *
 * Return Values:
 *	- MMS_API_NOT_ERR_RSP if response is not an error response
 *	- MMS_API_ERROR if unable to obtain error class and code
 *	- MMS_API_OK if processing completed correctly
 *
 */
int
mms_handle_err_rsp(void *response, int *class, int *code, char **msg)
{
	mms_rsp_ele_t	*rsp = (mms_rsp_ele_t *)response;

	mms_par_node_t	*clause;
	mms_par_node_t	*token;
	mms_par_node_t	*loc = NULL;

	*msg = NULL;

	if (rsp->mms_rsp_type != MMS_API_RSP_FINAL_ERR) {
		mms_trace(MMS_ERR, "mms_handle_err_rsp: Response is "
		    " not a error response:\n%s", rsp->mms_rsp_str);
		return (MMS_API_NOT_ERR_RSP);
	}

	MMS_PN_LOOKUP(clause, rsp->mms_rsp_cmd, "error", MMS_PN_CLAUSE,
	    NULL);
	MMS_PN_LOOKUP(token, clause, NULL, MMS_PN_KEYWORD, &loc);
	*class = mms_sym_str_to_code(mms_pn_token(token));
	MMS_PN_LOOKUP(token, clause, NULL, MMS_PN_KEYWORD, &loc);
	*code = mms_sym_str_to_code(mms_pn_token(token));

	if ((clause = mms_pn_lookup(rsp->mms_rsp_cmd, "message",
	    MMS_PN_CLAUSE, NULL)) != NULL) {
		if ((*msg = mms_get_msg(clause)) == NULL)
			*msg = strdup(rsp->mms_rsp_str);
	}

	return (MMS_API_OK);

not_found:
	mms_trace(MMS_ERR, "mms_handle_err_rsp: Missing class or code in "
	    "error response:\n%s", rsp->mms_rsp_str);
	return (MMS_API_ERROR);
}

/*
 * mms_hello()
 *
 * Parameters:
 *	- session	Session structure to to use to connect to MMS.
 *	- host		The hostname of where MM is running.
 *      - port		The port where MM is running.
 *	- app		Name of client's application name to use in
 *			HELLO command.
 *	- ai		Name of client's application instance to use in
 *			HELLO command.
 *	- tag		This is an optional parameter that a client can
 *			specify that will tag the session with this value.
 *			If no tag is to be used, use NULL.
 *	- cli_pass	Client's password to use in HELLO command.
 *	- mm_pass	Optional, expected password in MMS_WELCOME response,
 *			set to null for no password validation.
 *	- ssl_data	SSL connection data is required for secure MM,
 *			set to null for no SSL connection.
 *
 * This function fills in the network structure with the client's
 * specific information to use in the HELLO command that is to
 * be sent to MMS.
 * If the connection is an async connection, it will start the writer and
 * reader threads after the connection is established.
 *
 * Return Values:
 *	MMS_API_OK	If connection was made successfully.
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_hello(void *session, char *host, char *port, char *app, char *ai, char *tag,
    char *cli_pass, char *mm_pass, void *ssl_data)
{
	mms_network_cfg_t	net;
	int		rc;

	(void) memset(&net, 0, sizeof (mms_network_cfg_t));
	net.cli_host = host;
	net.cli_port = port;
	net.cli_name = app;
	net.cli_inst = ai;
	net.cli_vers = MMS_MMP_VERSION;
	net.cli_lang = MMS_MMP_LANG;
	net.cli_pass = cli_pass;
	net.mm_pass = mm_pass;

	rc = mms_hello_net(session, &net, tag, ssl_data);
	return (rc);
}

/*
 * mms_hello_net()
 *
 * Parameters:
 *	- session	Session structure to to use to connect to MMS.
 *	- net		MMS network configuration where the MMS MM is located.
 *	- tag		This is an optional parameter that a client can
 *			specify that will tag the session with this value.
 *			If no tag is to be used, use NULL.
 *	- ssl_data	SSL connection data is required for secure MM,
 *			set to null for no SSL connection.
 *
 * This function uses the network structure with the client's
 * specific information to use in the HELLO command that is to
 * be sent to MMS.
 * If the connection is an async connection, it will start the writer and
 * reader threads after the connection is established.
 *
 * Return Values:
 *	MMS_API_OK	If connection was made successfully.
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_hello_net(void *session, mms_network_cfg_t *net, char *tag, void *ssl_data)
{
	mms_session_t	*sp = (mms_session_t *)session;
	pthread_t	id;
	int		rc;
	int		err;


	if (mms_mmconnect(net, ssl_data, &sp->mms_conn, &err, tag) != 0) {
		mms_trace(MMS_ERR, "mms_hello: Error returned from "
		    "mms_mmconnect() - %d, %s", err, mms_sym_code_to_str(err));
		mms_send_errmsg(sp, MMS_API_3051_MSG, 2,
		    mms_sym_code_to_str(err), mms_sym_code_to_str(err));
		return (err);
	}

	if (sp->mms_api_mode == MMS_API_ASYNC) {

			/* Start reader thread */
		if ((rc = pthread_create(&id, &sp->mms_reader_attr,
		    mms_api_reader, (void *)sp)) != 0) {
			mms_serr(MMS_CRIT, "mms_hello: Start of MMS reader "
			    "thread failed with errno - %s", strerror(rc));
		}

			/* Wait until reader thread gets starts */
		if ((rc = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
			mms_serr(MMS_CRIT, "mms_hello: Lock of MMS reader "
			    "start mutex failed with errno - %s", strerror(rc));
		}

		while (sp->mms_api_rstarted == MMS_API_NO) {
			if ((rc = pthread_cond_wait(&sp->mms_acc_cv,
			    &sp->mms_acc_mutex)) != 0) {
				mms_serr(MMS_CRIT, "mms_hello: Unable to wait "
				    "on reader start condition variable, errno "
				    "- %s", strerror(rc));
			}
		}

		if ((rc = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
			mms_serr(MMS_CRIT, "mms_hello: Unlock of MMS reader "
			    "start mutex failed with errno - %s", strerror(rc));
		}
	}

	mms_trace(MMS_OPER, "mms_hello: Client connected to MMS");
	return (MMS_API_OK);
}

/*
 *   mms_sess_create
 *
 *   Allocate and initialize a session structure.
 */
mms_session_t *
mms_sess_create()
{
	mms_session_t	*sp;
	int		rc;

	if ((sp = (mms_session_t *)malloc(sizeof (mms_session_t))) == NULL) {
		mms_trace(MMS_CRIT,
		    "mms_sess_create: Malloc of memory for a new "
		    "client session failed with errno - %s", strerror(errno));
		return (NULL);
	}

	(void) memset(sp, 0, sizeof (mms_session_t));

	/*
	 *   Create lists for the command responses, registered events,
	 *   and events received.
	 */
	mms_list_create(&sp->mms_rsp_list, sizeof (mms_rsp_ele_t),
	    offsetof(mms_rsp_ele_t, mms_rsp_next));
	mms_list_create(&sp->mms_ev_list, sizeof (mms_rsp_ele_t),
	    offsetof(mms_rsp_ele_t, mms_rsp_next));
	mms_list_create(&sp->mms_cmd_list, sizeof (mms_cmd_ele_t),
	    offsetof(mms_cmd_ele_t, mms_cmd_next));

	/*
	 *   Initialize a mutex used to track the number of outstanding
	 *   client threads with pending MM requests.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_cnt_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS count "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_init(&sp->mms_cnt_cv, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS count "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	/*
	 *   Initialize a mutex to allow only one command to be
	 *   sent to MMS until a accept response is received.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_cacc_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS command "
		    "accept mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Create mutex and condition variable to coordinate handling of
	 *   accept/unaccept responses between a reader thread and a thread
	 *   waiting on accept response.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_acc_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS accept "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_init(&sp->mms_acc_cv, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS accept "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	/*
	 *   Initialize a mutex used to manage the pending commands.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_cmd_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS command "
		    "list mutex init failed with errno - %s", strerror(rc));
	}

	/*
	 *   Create mutex and condition variable to coordinate handling of
	 *   final responses between a reader thread and a thread waiting on
	 *   final response.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_rsp_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS response "
		    "list mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_init(&sp->mms_rsp_cv, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS response "
		    "list condition variable failed with errno - %s",
		    strerror(rc));
	}

	/*
	 *   Initialize a mutex and condition variable which will be used to
	 *   prevent more than one begin-end sequence being sent to the MM.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_be_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS begin-end "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_init(&sp->mms_be_cv, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS begin-end "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	/*
	 *   Create mutex to allow only one thread to write to the
	 *   socket at a time.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_conn_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS connection "
		    "mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Create mutex to allow only one thread to become the socket reader.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_reading, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS reading "
		    "mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Initialize an event manager mutex and condition variable.
	 */
	if ((rc = pthread_mutex_init(&sp->mms_ev_mutex, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS event list "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_init(&sp->mms_ev_cv, NULL)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS event list "
		    "condition variable failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_attr_init(&sp->mms_reader_attr)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Init of MMS reader's "
		    "attribute failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_attr_setdetachstate(&sp->mms_reader_attr,
	    PTHREAD_CREATE_DETACHED)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_create: Create of MMS reader "
		    "detach state failed with errno - %s", strerror(rc));
	}

	sp->clog = NULL;
	sp->cprefix = NULL;
	sp->mms_thrd_cnt = 0;
	sp->mms_be_pending = B_FALSE;

	return (sp);
}


/*
 *   mms_sess_free
 *
 *   Free all resources used to manage a session.
 */
void
mms_sess_free(mms_session_t *sp)
{
	int	rc;

	if ((rc = pthread_cond_destroy(&sp->mms_cnt_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS count "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_cnt_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS count "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS command "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_destroy(&sp->mms_acc_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS accept "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS accept "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_cacc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS command "
		    "accept mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_destroy(&sp->mms_rsp_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS response "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS response "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_destroy(&sp->mms_be_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS begin-end "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_be_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS begin-end "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_destroy(&sp->mms_ev_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS event "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS event "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_conn_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS connection"
		    " mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_destroy(&sp->mms_reading)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS reading "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_attr_destroy(&sp->mms_reader_attr)) != 0) {
		mms_serr(MMS_CRIT, "mms_sess_free: Destroy of MMS reader "
		    "attribute failed with errno - %s", strerror(rc));
	}

	mms_list_destroy(&sp->mms_ev_list);
	mms_list_destroy(&sp->mms_cmd_list);
	mms_list_destroy(&sp->mms_rsp_list);

	(void) memset(sp, 0, sizeof (mms_session_t));
	free(sp);
}


/*
 *   mms_mm_shutdown
 *
 *   Send a shutdown request to the MM.
 */
void
mms_mm_shutdown(mms_session_t *sp, int force)
{
	void	*rsp;
	char	cmd_str[128];
	int	rc;

	if (force) {
		mms_trace(MMS_OPER, "mms_mm_shutdown: force shutdown, current "
		    "count - %d", sp->mms_thrd_cnt);
		return;
	}

	(void) snprintf(cmd_str, sizeof (cmd_str),
	    "goodbye task[\"api_goodbye\"];");
	mms_trace(MMS_OPER, "mms_mm_shutdown: Send goodbye to MM: %s", cmd_str);

	if ((rc = mms_send_cmd(sp, cmd_str, &rsp)) != MMS_API_OK) {
		mms_trace(MMS_ERR, "mms_mm_shutdown: Sending goodbye to MM "
		    "failed with a %s error", mms_sym_code_to_str(rc));
		mms_send_errmsg(sp, MMS_API_3052_MSG, 0);
		return;
	}

	switch (mms_rsp_type(rsp)) {
	case MMS_API_RSP_UNACC:
		mms_trace(MMS_ERR, "mms_mm_shutdown: Received an unacceptable "
		    "response to goodbye command");
		break;

	case MMS_API_RSP_FINAL:
		mms_trace(MMS_OPER, "mms_mm_shutdown: Received a success "
		    "response to goodbye command");
		break;

	case MMS_API_RSP_FINAL_ERR:
		mms_trace(MMS_ERR, "mms_mm_shutdown: Received an error "
		    "response to goodbye command");
		break;

	case MMS_API_RSP_FINAL_CANC:
		mms_trace(MMS_ERR, "mms_mm_shutdown: Received a cancel "
		    "response to goodbye command");
		break;
	default:
		mms_trace(MMS_ERR, "mms_mm_shutdown: Received an unknown "
		    "response to goodbye command");
		break;
	}

	mms_free_rsp(rsp);
}


/*
 *   mms_shutdown
 *
 *   Shutdown all activity for a session.
 */
void
mms_shutdown(mms_session_t *sp, int force)
{
	timespec_t	tv;
	timespec_t	*tvp;
	mms_rsp_ele_t	*rsp_ele;
	mms_cmd_ele_t	*cmd_ele;
	int		rc;

	/*
	 *   Send a shutdown command to the MM.
	 */
	mms_mm_shutdown(sp, force);

	/*
	 *   Set state of API session to shutdown.
	 */
	sp->mms_api_state = MMS_API_SHUTDOWN;

	/*
	 *   Close socket to MM.
	 */
	mms_close(&sp->mms_conn);

	mms_trace(MMS_OPER, "mms_shutdown: Set shutdown flag and wait for all "
	    "outstanding api threads to shutdown, current count - %d",
	    sp->mms_thrd_cnt);

	/*
	 *   Broadcast to wake any client threads in a condition wait.
	 */
	if ((rc = pthread_mutex_lock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Lock of MMS accept mutex "
		    "failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_broadcast(&sp->mms_acc_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Broadcast on accept "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_acc_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS accept mutex "
		    "failed with errno - %s", strerror(rc));
	}

	if ((rc = pthread_cond_broadcast(&sp->mms_rsp_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Broadcast on response list "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS response list"
		    " mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_broadcast(&sp->mms_ev_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Broadcast on event list "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS event list "
		    "mutex failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_cond_broadcast(&sp->mms_be_cv)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Broadcast on send list "
		    "condition variable failed with errno - %s", strerror(rc));
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_be_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS send list "
		    "mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Check to see if any client threads are still outstanding.
	 */
	if ((rc = pthread_mutex_lock(&sp->mms_cnt_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Lock of MMS thread "
		    "count mutex failed with errno - %s", strerror(rc));
	}

	if (sp->mms_thrd_cnt != 0) {

		tv.tv_sec = time(NULL) + 15;
		tv.tv_nsec = 0;
		tvp = &tv;
		if ((rc = pthread_cond_timedwait(&sp->mms_cnt_cv,
		    &sp->mms_cnt_mutex, tvp)) != 0) {
			if (rc == ETIMEDOUT)
				mms_trace(MMS_ERR, "mms_shutdown: 15 seconds "
				    "wait period expired waiting for all "
				    "client threads to exit, forcing shutdown");
			else
				mms_serr(MMS_CRIT, "mms_shutdown: Unable to "
				    "wait on thread condition variable, "
				    "errno - %s", strerror(rc));
		} else {
			mms_trace(MMS_OPER,
			    "mms_shutdown: all outstanding client "
			    "threads have exited, connection to MM closed");
		}
	} else {
		mms_trace(MMS_OPER,
		    "mms_shutdown: There are no outstanding client "
		    "threads currently running, connection to MM closed");
	}

	if ((rc = pthread_mutex_unlock(&sp->mms_cnt_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS thread "
		    "count mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Clean the event lists.
	 */
	if ((rc = pthread_mutex_lock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Lock of MMS event list "
		    "mutex failed with errno - %s", strerror(rc));
	}
	while (! mms_list_empty(&sp->mms_ev_list)) {
		rsp_ele = mms_list_head(&sp->mms_ev_list);
		mms_list_remove(&sp->mms_ev_list, rsp_ele);
		mms_free_rsp(rsp_ele);
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_ev_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS event list "
		    "mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Clean the response list.
	 */
	if ((rc = pthread_mutex_lock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Lock of MMS response list "
		    "mutex failed with errno - %s", strerror(rc));
	}
	while (! mms_list_empty(&sp->mms_rsp_list)) {
		rsp_ele = mms_list_head(&sp->mms_rsp_list);

		mms_list_remove(&sp->mms_rsp_list, rsp_ele);
		mms_free_rsp(rsp_ele);
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_rsp_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS response "
		    "list mutex failed with errno - %s", strerror(rc));
	}

	/*
	 *   Clean the command list.
	 */
	if ((rc = pthread_mutex_lock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Lock of MMS command list "
		    "mutex failed with errno - %s", strerror(rc));
	}
	while (! mms_list_empty(&sp->mms_cmd_list)) {
		cmd_ele = mms_list_head(&sp->mms_cmd_list);

		mms_list_remove(&sp->mms_cmd_list, cmd_ele);
		mms_cmd_free(cmd_ele);
	}
	if ((rc = pthread_mutex_unlock(&sp->mms_cmd_mutex)) != 0) {
		mms_serr(MMS_CRIT, "mms_shutdown: Unlock of MMS command list"
		    " mutex failed with errno - %s", strerror(rc));
	}
}


/*
 * mms_init()
 *
 * Parameters:
 *	- session	If init is successful, returns the pointer to the new
 *			session structure that the client uses to
 *			communicate with MMS. If an error occurs it is set
 *			to NULL;
 *	- version	Set to the version that the API was built with.
 *			The client will use this to determine if it is
 *			compatible with the MMS API.
 *
 * This function initializes the mutexs, condition variables, lists,
 * necessary for a client to communicate with MMS in a sync mode.
 *
 * Return Values:
 *	MMS_API_OK	If a new sessions was successfully created.
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_init(void **session, int *version)
{
	mms_session_t *sp;

	if (session == NULL || version == NULL) {
		mms_trace(MMS_DEBUG, "mms_init: Null pointer specified for %s",
		    session == NULL ? "session" : "version");
		return (MMS_INVALID_REQ);
	}

	if ((sp = mms_sess_create()) == NULL) {
		*session = NULL;
		return (MMS_MALLOC_ERROR);
	}

	sp->mms_api_state = MMS_API_CONFIG;
	sp->mms_api_mode = MMS_API_SYNC;

	mms_trace(MMS_OPER, "mms_init: Init of client's sync api connection "
	    "to MMS complete");

	*version = MMS_API_VERSION;
	*session = sp;

	return (MMS_API_OK);
}


/*
 * mms_ainit()
 *
 * Parameters:
 *	- session	If init is successful, returns a pointer to the new
 *			session structure that the client uses to
 *			communicate with MMS. If an error occurs it is set
 *			to NULL;
 *	- version	Set to the version the API was built with.
 *			The client will use this to determine if it is
 *			compatible with the MMS API.
 *      - err_callbk    The routine that is to be called when the reader
 *                      detects an internal processing error and is ready to
 *                      exit. This function is called to notify the client
 *                      that a internal processing error has occurred and
 *                      the api is no longer is a stable state. This routine
 *			is also called when reader exits because the api
 *			has been terminated by the client.
 *      - ev_callbk     The routine that is to be called when an event is
 *			received.
 *
 * This function initializes the mutexs, condition variables, lists,
 * necessary for a client to communicate with MMS in a async mode.
 *
 * Return Values:
 *	MMS_API_OK	If a new sessions was successfully created
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_ainit(void **session, int *version, mms_callbk_t *err_callbk,
    mms_rsp_callbk_t *ev_callbk)
{
	mms_session_t	*sp;

	if (session == NULL || version == NULL) {
		mms_trace(MMS_DEBUG, "mms_init: Null pointer specified for %s",
		    session == NULL ? "session" : "version");
		return (MMS_INVALID_REQ);
	}

	if ((sp = mms_sess_create()) == NULL) {
		*session = NULL;
		return (MMS_MALLOC_ERROR);
	}

	sp->mms_api_rstarted = MMS_API_NO;
	sp->mms_api_mode = MMS_API_ASYNC;
	sp->mms_api_state = MMS_API_CONFIG;

	/*
	 *   Set callback function to process events.
	 */
	if (ev_callbk) {
		sp->mms_ev_callbk = ev_callbk->mms_func;
		sp->mms_ev_callbk_param = ev_callbk->mms_param;
	} else {
		sp->mms_ev_callbk = NULL;
		sp->mms_ev_callbk_param = NULL;
	}

	/*
	 *   Set callback function in case reader thread needs to
	 *   shutdown due to internal processing.
	 */
	if (err_callbk) {
		sp->mms_async_error = err_callbk->mms_func;
		sp->mms_async_error_param = err_callbk->mms_param;
	} else {
		sp->mms_async_error = NULL;
		sp->mms_async_error_param = NULL;
	}

	mms_trace(MMS_OPER, "mms_ainit: Init of client's async api "
	    "connection to MMS complete");

	*version = MMS_API_VERSION;
	*session = sp;

	return (MMS_API_OK);
}

/*
 * mms_goodbye()
 *
 * Parameters:
 *	- session	The session that is to be closed
 *	- force		0 - indicates graceful shutdown
 *			1 - indicates an immediate shutdown
 *
 * This function closes a synchronouse session that a client has open with MMS.
 *
 * Return Values:
 *	MMS_API_OK	If session was closed successfully
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_goodbye(void *session, int force)
{
	mms_session_t	*sp = (mms_session_t *)session;

	mms_trace(MMS_DEBUG, "mms_goodbye: Closing session with MMS");

	if (sp == NULL) {
		mms_trace(MMS_ERR, "mms_goodbye: Client session pointer is "
		    "NULL, unable to close session");
		mms_send_errmsg(sp, MMS_API_3000_MSG, 0);
		return (MMS_INVALID_REQ);
	}

	if (sp->mms_api_mode != MMS_API_SYNC) {
		mms_trace(MMS_ERR, "mms_goodbye: Trying to use sync close "
		    "on a session which is not an sync session");
		mms_send_errmsg(sp, MMS_API_3019_MSG, 0);
		return (MMS_WRONG_API_MODE);
	}

	/*
	 *   Shutdown the session.
	 */
	mms_shutdown(sp, force);

	/*
	 *   Free all resources used to manage the session.
	 */
	mms_sess_free(sp);

	return (MMS_API_OK);
}

/*
 * mms_agoodbye()
 *
 * Parameters:
 *	- session	The session that is to be closed
 *	- force		0 - indicates graceful shutdown
 *			1 - indicates an immediate shutdown
 *
 * This function closes a asynchronous session that a client has open with mms
 *
 * Return Values:
 *	MMS_API_OK	If session was closed successfully.
 *	! MMS_API_OK	An error code indicating the error encountered.
 *
 */
int
mms_agoodbye(void *session, int force)
{
	mms_session_t	*sp = (mms_session_t *)session;

	mms_trace(MMS_DEBUG, "mms_agoodbye: Closing session with MMS");

	if (sp == NULL) {
		mms_trace(MMS_ERR, "mms_agoodbye: Client session pointer is "
		    "NULL, unable to close session");
		mms_send_errmsg(sp, MMS_API_3000_MSG, 0);
		return (MMS_INVALID_REQ);
	}

	if (sp->mms_api_mode != MMS_API_ASYNC) {
		mms_trace(MMS_ERR, "mms_agoodbye: Trying to use async close "
		    "on a session which is not an async session");
		mms_send_errmsg(sp, MMS_API_3019_MSG, 0);
		return (MMS_WRONG_API_MODE);
	}

	/*
	 *   Shutdown the session.
	 */
	mms_shutdown(sp, force);

	/*
	 *   Free all resources used to manage the session.
	 */
	mms_sess_free(sp);

	return (MMS_API_OK);
}

/*
 * mms_send_cmd()
 *
 * Parameters:
 *	- session	The structure used to access the socket to MMS.
 *	- cmd		The MMP cmd to be sent to MMS.
 *	- rsp		The response from MMS to the cmd. This is actually a
 *			mms_rsp_ele_t structure. When the client is
 *			done with the response, they need to call
 *			mms_free_rsp() to free up the strucutes memory.
 *
 * This function sends MMP commands to MMS and waits for a response to them.
 * It returns in rsp a MMS response structure. The client will then use
 * other MMS API commands to obtain the information from the response, thus
 * the client does not need to know the actual format of the response
 * actually pull the response apart in order to determine what it needs from
 * structure. If a processing error has occurred within the MMS API, this
 * routine will return a error response and return a value indicating what
 * processing error occurred.
 *
 * Return Values:
 *	MMS_API_OK	If it received a vaild response from MMS
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_send_cmd(void *session, char *cmd, void **rsp)
{
	mms_session_t	*sp = (mms_session_t *)session;
	mms_rsp_ele_t	*new_rsp;
	mms_cmd_name_t	cmdtype;
	char		*tid;
	int		rc;

	if (cmd == NULL) {
		mms_trace(MMS_DEBUG, "mms_send_cmd: Null pointer specified"
		    " for the command");
		return (MMS_INVALID_REQ);
	}

	mms_trace(MMS_OPER, "mms_send_cmd: Command to be sent to MMS:\n%s",
	    cmd);

	if (rsp == NULL) {
		mms_trace(MMS_DEBUG, "mms_send_cmd: Null pointer specified "
		    "for the response");
		return (MMS_INVALID_REQ);
	}

	*rsp = NULL;

	if (sp == NULL) {
		mms_trace(MMS_ERR, "mms_send_cmd: Session pointer is set "
		    "to NULL, unable to send new command:\n%s", cmd);
		return (MMS_INVALID_REQ);
	}

	if (sp->mms_api_state == MMS_API_FAILURE) {
		mms_trace(MMS_ERR, "mms_send_cmd: MMS API is in a state of "
		    "error, unable to send new command:\n%s", cmd);
		mms_send_errmsg(sp, MMS_API_3001_MSG, 0);
		return (sp->mms_api_errcode);
	}

	/*
	 *   Extract the command type and task id from the command.
	 */
	rc = mms_cmd_extract(cmd, &tid, &cmdtype);
	if (rc != MMS_API_OK) {
		return (rc);
	}

	/*
	 *   The begin-end command sequence cannot be issued synchronously.
	 */
	if (cmdtype == MMS_CMD_BEGIN || cmdtype == MMS_CMD_END) {
		free(tid);
		return (MMS_INVALID_REQ);
	}

	/*
	 *   Create and queue a command element to manage the command.
	 */
	if (sp->mms_api_mode == MMS_API_ASYNC) {
		mms_cmd_create(sp, tid, cmd, MMS_API_SYNC, NULL, NULL);
	}

	mms_thread_start(sp);

	/*
	 *   Send the command and wait for the accept.
	 */
	rc = mms_send(sp, tid, cmdtype, cmd, &new_rsp);

	/*
	 *   Return an error if the command could not be sent or
	 *   was not accepted.
	 */
	if (rc != MMS_API_OK) {
		if (sp->mms_api_mode == MMS_API_ASYNC)
			(void) mms_cmd_remove(sp, tid);
		free(tid);
		mms_thread_exit(sp);
		return (rc);
	}
	if (new_rsp != NULL) {
		*rsp = (void *)new_rsp;
		mms_thread_exit(sp);
		free(tid);
		return (rc);
	}

	/*
	 *   Wait for the final response.
	 */
	rc = mms_obtain_final(sp, tid, &new_rsp);

	mms_thread_exit(sp);
	free(tid);

	if (rc != MMS_API_OK) {
		if (rc != MMS_API_SHUTDOWN)
			mms_trace(MMS_ERR, "mms_send_cmd: obtaining a MMS "
			    "response failed %d, %s for command:\n%s", rc,
			    mms_sym_code_to_str(rc), cmd);
		return (rc);
	}

	*rsp = (void *)new_rsp;
	return (MMS_API_OK);
}


/*
 * mms_read_response()
 *
 * Parameters:
 *	- session	The structure used to communicate with MMS.
 *	- tid		The task id for the command that client is waiting
 *			for additional responses for.
 *	- rsp		Will contain the next response for the command with
 *			taskid.
 *
 * This function obtains secondary responses to commands that have been sent
 * to MMS. The function should only be called if the mms_send_cmd()
 * function received a "intermediate" response or a prior call to this
 * function received a "intermediate" response.
 *
 * Return Values:
 *	MMS_API_OK	If a response from MMS was received without any
 *			internal processing errors.
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_read_response(void *session, char *tid, void **rsp)
{
	mms_rsp_ele_t	*new_rsp;
	mms_session_t	*sp = (mms_session_t *)session;
	int		rc;

	if (tid == NULL || rsp == NULL) {
		mms_trace(MMS_DEBUG, "mms_read_response: Null pointer "
		    "specified for %s", tid == NULL ? "task id" :
		    "response");
		return (MMS_INVALID_REQ);
	}

	*rsp = NULL;

	if (sp == NULL) {
		mms_trace(MMS_ERR, "mms_read_response: Session pointer is "
		    "set to NULL, unable to obtain a response for command "
		    "with taskid %s", tid);
		mms_send_errmsg(sp, MMS_API_3000_MSG, 0);
		return (MMS_INVALID_REQ);
	}
	if (sp->mms_api_state == MMS_API_FAILURE) {
		mms_trace(MMS_ERR, "mms_read_response: MMS API is in a "
		    "state of error, unable to obtain a response for command "
		    "with taskid %s", tid);
		mms_send_errmsg(sp, MMS_API_3001_MSG, 0);
		return (sp->mms_api_errcode);
	}

	mms_thread_start(sp);

	rc = mms_obtain_final(sp, tid, &new_rsp);

	mms_thread_exit(sp);

	if (rc != MMS_API_OK) {
		if (rc != MMS_API_SHUTDOWN) {
			mms_trace(MMS_ERR, "mms_read_response: Obtaining a "
			    "response for command with taskid %s from MMS "
			    "failed, rc - %d, %s.", tid, rc,
			    mms_sym_code_to_str(rc));
		}
		return (rc);
	}

	*rsp = (void *)new_rsp;
	return (MMS_API_OK);
}

/*
 * mms_send_acmd()
 *
 * Parameters:
 *	- sp		The structure used to access the socket to MMS.
 *	- tid		The task id of the MMP command to be sent to MMS.
 *	- cmd		The MMP cmd to be sent to MMS.
 *	- callbk	The routine that is to be called when the reader
 *			receives a final response for the command.
 *	- callbk_param	A user specified parameter to send to the callbk
 *			function when the final response is received.
 *
 * This function sends MMP commands to MMS and does not wait for any type
 * of response from MMS before returning to the caller of this function.
 * It just adds the command to the outstanding command list and the send
 * command list and returns.
 *
 * Return Values:
 *	MMS_API_OK	If function completed correctly.
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered. If the client has registered
 *			a logging routine for the API, a message will be
 *			sent to that routine.
 *
 */
int
mms_send_acmd(void *session, char *cmd, void (*callbk)(void *arg, void *arg1),
    void *callbk_param)
{
	mms_session_t	*sp = (mms_session_t *)session;
	char		*tid;
	mms_cmd_name_t	cmdtype;
	int		rc;

	if (cmd == NULL) {
		mms_trace(MMS_DEBUG, "mms_send_acmd: Null pointer "
		    "specified for command");
		return (MMS_INVALID_REQ);
	}

	mms_trace(MMS_OPER, "mms_send_acmd: Command to be sent to MMS:\n%s",
	    cmd);

	if (sp == NULL) {
		mms_trace(MMS_ERR, "mms_send_acmd: Session pointer is set "
		    "to NULL, unable to send new comand:\n%s", cmd);
		return (MMS_INVALID_REQ);
	}

	if (callbk == NULL) {
		mms_trace(MMS_DEBUG, "mms_send_acmd: Null pointer specified "
		    "for callback function");
		return (MMS_INVALID_REQ);
	}

	if (sp->mms_api_state == MMS_API_FAILURE) {
		mms_trace(MMS_ERR, "mms_send_acmd: MMS API is in a state "
		    "of error, unable to send new command:\n%s", cmd);
		mms_send_errmsg(sp, MMS_API_3001_MSG, 0);
		return (sp->mms_api_errcode);
	}

	/*
	 *   MM connection must have been initialized in asynchronous mode.
	 */
	if (sp->mms_api_mode != MMS_API_ASYNC) {
		mms_trace(MMS_ERR, "mms_send_acmd: Trying to use the MMS "
		    "API connection in ASYNC mode, though it is configured for "
		    "%s mode", mms_api[sp->mms_api_mode]);
		mms_send_errmsg(sp, MMS_API_3019_MSG, 0);
		return (MMS_WRONG_API_MODE);
	}

	/*
	 *   Extract the command type and task id from the command.
	 */
	rc = mms_cmd_extract(cmd, &tid, &cmdtype);
	if (rc != MMS_API_OK) {
		return (rc);
	}

	/*
	 *   Create and add the command to the command list for this
	 *   session.
	 */
	mms_cmd_create(sp, tid, cmd, MMS_API_ASYNC, callbk, callbk_param);

	mms_thread_start(sp);

	/*
	 *   Send the command and wait for an accept.
	 */
	rc = mms_send(sp, tid, cmdtype, cmd, NULL);

	mms_thread_exit(sp);

	/*
	 *   Return an error if the command could not be sent or
	 *   was not accepted.
	 */
	if (rc != MMS_API_OK) {
		(void) mms_cmd_remove(sp, tid);
		free(tid);
		return (rc);
	}

	mms_trace(MMS_DEBUG, "mms_send_acmd: Command with taskid "
	    "%s accepted", tid);
	free(tid);

	return (MMS_API_OK);
}

/*
 * mms_read_event()
 *
 * Parameters:
 *	- session	Connection to MMS to use.
 *	- event		The generic response structure used to store the
 *			event to be processed by the client.
 *
 * This function obtains events from MMS.  When MMS has an event to send
 * to a client, it sends it over the session socket. This routine pulls the
 * event off the socket and then returns it to the client. A client needs to
 * call mms_free_rsp() to free the memory associated with the event structure
 * that is returned.
 *
 * Return Values:
 *	MMS_API_OK	If it was able to obtain a event successfully.
 *	! MMS_API_OK	The code relevant to the internal processing error
 *			that was encountered.
 *
 */
int
mms_read_event(void *session, void **event)
{
	int	rc;

	mms_rsp_ele_t	*new_ev;
	mms_session_t	*sp = (mms_session_t *)session;

	if (sp == NULL || event == NULL) {
		mms_trace(MMS_DEBUG, "mms_read_event: Null pointer specified"
		    " for %s", sp == NULL ? "session" : "event");
		return (MMS_INVALID_REQ);
	}

	mms_thread_start(sp);

	/*
	 *   Wait for an event.
	 */
	rc = mms_obtain_event(sp, &new_ev);

	mms_thread_exit(sp);

	if (rc != MMS_API_OK) {
		if (rc != MMS_API_SHUTDOWN) {
			mms_trace(MMS_ERR,
			    "mms_read_event: obtaining new event "
			    "failed, error code - %d, %s", rc,
			    mms_sym_code_to_str(rc));
		}
		*event = (void *)NULL;
		return (rc);
	}

	*event = new_ev;
	return (MMS_API_OK);
}

/*
 * mms_get_attr_aux()
 *
 * Parameters:
 *	- top		The top of the list being searched
 *	- start		The starting point to search from in the list
 *	- str		The string to search for
 *	- type		The type of attribute to search for
 *			receives a final response for the command.
 *	- self		Indicates if start should be searched.
 *
 * This function calls itself recursivily looking for str in the list
 * top starting at the start location.
 *
 * Return Values:
 *	Returns a pointer to the node in the list that matches str and type
 *	or it returns NULL if the list is exhausted without finding str.
 *
 */
static mms_par_node_t *
mms_get_attr_aux(mms_par_node_t *top,
    mms_par_node_t *start, char *str, int type,
		    int self)
{
	mms_par_node_t	*tmp;
	mms_par_node_t	*node;
	mms_par_node_t	*result;
	mms_list_t		*list;

	if (top == NULL || start == NULL) {
		return (NULL);
	}

		/* Start from the start node */
	if (self == 1) {
		if (type & mms_pn_type(start)) {
			if (strcmp(str, mms_pn_token(start)) == 0) {
					/* found a matching node */
				return (start);
			}
		}
			/* Already did self check, don't do it again */
		self = 0;
	}

	list = &top->pn_arglist;
	if (top == start) {
		start = mms_list_head(list);
			/* Have a new start node, do self check on this one */
		self = 1;
	}
	for (node = start; node != NULL; node = mms_list_next(list, node)) {
		result = mms_get_attr_aux(node, node, str, type, self);
		if (result != NULL) {
			/* found a matching node */
			return (result);
		}
			/* skip value of name value pair */
		tmp = mms_list_next(list, node);
		if (tmp != NULL && (type & mms_pn_type(tmp))) {
			node = tmp;
		}
			/* Do self check from now on */
		self = 1;
	}

		/* Can't find a matching node. */
	return (NULL);
}

/*
 * mms_get_attribute()
 *
 * Parameters:
 *	- rsp		The response that is to be processed
 *	- name		The name of the attribute to scan the response for.
 *	- prev		Maintains the location of how far the scan has been
 *			done between calls. The client sets this to NULL
 *			on the initial call to this routine and then the
 *			routine updates it to keep track of where it is in
 *			the response.
 *
 * This function takes a response that has a report in namevalue form
 * and looks through it for the name attribute. It returns the value
 * associated with the name when it finds one.
 *
 * Return Values:
 *	value of name	If a name attribute was found it returns the value
 *			associated with the attribute.
 *	NULL		If no name attribute was found.
 *
 */
char *
mms_get_attribute(void *rsp, char *name, void **prev)
{
	int		self = 1;

	mms_rsp_ele_t	*lrsp = (mms_rsp_ele_t *)rsp;

	mms_par_node_t	*root = lrsp->mms_rsp_cmd;
	mms_par_node_t	*clause_top;
	mms_par_node_t	*start;
	mms_par_node_t	*node = NULL;
	mms_par_node_t	*value = NULL;

	if (name == NULL) {
		mms_trace(MMS_ERR, "mms_get_attribute: Name is set to NULL");
		return (NULL);
	}

	if (prev == NULL || *prev == NULL) {
		if ((clause_top = mms_pn_lookup(root, "text",
		    MMS_PN_CLAUSE, NULL)) == NULL) {
			mms_trace(MMS_DEBUG, "mms_get_attribute: No text found "
			    "found in response %s", lrsp->mms_rsp_str);
			return (NULL);
		}
		start = clause_top;
	} else {
		start = (mms_par_node_t *)(*prev);

		clause_top = start->pn_list;
		self = 0;
	}

	node = mms_get_attr_aux(clause_top, start, name,
	    MMS_PN_STRING, self);

	while (clause_top != NULL && node == NULL) {

		if (strcmp(mms_pn_token(clause_top), "text") == 0) {
			if ((clause_top = mms_pn_lookup(root, "text",
			    MMS_PN_CLAUSE, &clause_top)) == NULL) {
				mms_trace(MMS_DEBUG,
				    "mms_get_attribute: No more "
				    "text clause found");
				continue;
			}
			start = clause_top;
		} else {
			start = clause_top;
			clause_top = clause_top->pn_list;
			node = mms_list_next(&clause_top->pn_arglist, start);
			if (node == NULL)
				continue;
			start = node;
		}

		self = 1;
		node = mms_get_attr_aux(clause_top, start, name,
		    MMS_PN_STRING, self);
		if (node != NULL)
			break;
	}

	if (prev != NULL && node != NULL) {
		value = mms_list_next(&node->pn_list->pn_arglist, node);
		if (value != NULL) {
			mms_trace(MMS_DEBUG,
			    "mms_get_attribute: Next value for "
			    "%s attribute - %s", name, mms_pn_token(value));
			*prev = value;
			return (mms_pn_token(value));
		}
	}

	return (NULL);
}
