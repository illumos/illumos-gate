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


#include <lm.h>
#include <lm_proto.h>
#include <net_cfg_service.h>

/* Globals */
static	char	*_SrcFile = __FILE__;
lm_t	lm;		/* The global library management structure. Only one */
			/* exists per library manager. */
lm_queue_t lm_cmdq;	/* The global work queue for processing LMPM cmds */
lmpl_rsp_t lm_rspq;	/* The global response structure. This keeps track */
			/* of which cmds are waiting on responses from MM */

pthread_mutex_t	lm_acc_mutex;	/* Mutex to protect cmd waiting on a accept */
				/* This mutex allows only one cmd to be sent */
				/* to MM at a time until MM responses with */
				/* a accept or unaccept response */
pthread_mutex_t lm_write_mutex;	/* Mutex to protect from multiple writes */
				/* occuring at one time from different */
				/* threads */
int lm_daemon_mode = 1;		/* Indicates if running in daemon mode */
int lm_message_level = MMS_MSG_SEV_WARN;	/* LM's message level from MM */
int lm_state = LM_NOT_ACTIVE;	/* Global indicator of LM's state */
int exit_code = LM_NORMAL;	/* Global to tell what exit code should */
				/* be used when LM exits */
int lm_internal_error = LM_OK;	/* Indicates that a fatal internal LM system */
				/* error was detected. LM will shutdown */
				/* processing and exit */

			/* Structure that is updated to contain the */
			/* dynamic entry points to the commands that */
			/* interface with a specific library */
lm_cmdData_t lm_cmdData[] = {
	"mount", "lm_mount", NULL,
	"unmount", "lm_unmount", NULL,
	"move", "lm_move", NULL,
	"inject", "lm_inject", NULL,
	"scan", "lm_scan", NULL,
	"activate", "lm_activate", NULL,
	"reset", "lm_reset", NULL,
	"eject", "lm_eject", NULL,
	"barrier", "lm_barrier", NULL,
	"private", "lm_private", NULL,
	"cancel", "lm_cancel", NULL,
	"exit", "lm_exit", NULL,
	"event", "lm_event", NULL,
	NULL, NULL, NULL,
			/* Commands that also need a general */
			/* part as well as a library specific part */
			/* This general part will get called frist */
			/* and then the library specific part will be called */
	"activate", "lm_common_activate", lm_common_activate,
	"private", "lm_common_private", lm_common_private,
	"exit", "lm_common_exit", lm_common_exit,
	"reset", "lm_common_reset", lm_common_reset,
	"event", "lm_common_event", lm_common_event,
	"internal", "lm_common_internal", lm_common_internal,
	NULL, NULL, NULL };

static sigset_t signalSet;

static void lm_cmd_handler(lm_queue_ele_t *);

/*
 * signal_waiter
 *
 * Parameters:
 *	None - arg exists only to match argument in pthread_create
 *
 * This routine is spawned as a separate thread created to wait for masked
 * signals. Any masked signaled will be delivered to this thread.
 *
 * Return Values:
 *	None - Return value exists only to match return value in pthread_create
 */

static void*
/* LINTED arg in signal_waiter (E_FUNC_ARG_UNUSED) */
signal_waiter(void *arg)
{
	int signum;

	mms_trace(MMS_DEVP, "Entering signal_waiter");

	/* LINTED constant in conditional context */
	while (1) {
		signum = sigwait(&signalSet);

		switch (signum) {

		case SIGHUP:
			mms_trace(MMS_OPER, "signal_waiter: Received SIGHUP "
			    "signal, ignoring signal");
			break;
		case SIGINT:
			mms_trace(MMS_OPER, "signal_waiter: Received SIGINT "
			    "signal, restarting LM");
			mms_trace_flush();
			lm_state = LM_STOP;
			exit_code = LM_SIG_RESTART;
			break;
		case SIGPIPE:
			mms_trace(MMS_OPER, "signal_waiter: Received SIGPIPE "
			    "signal, shutting down LM");
			mms_trace_flush();
			lm_internal_error = LM_NO_MM;
			exit_code = LM_SIG_RESTART;
			break;
		case SIGTERM:
			mms_trace(MMS_OPER, "signal_waiter: Received SIGTERM "
			    "signal, shutting down LM");
			mms_trace_flush();
			lm_state = LM_STOP;
			exit_code = LM_SIG_NRESTART;
			break;
		default:
			mms_trace(MMS_ERR,
			    "signal_waiter: Received a signal that "
			    "lm does not handle - %d", signum);
			break;
		}
	}
	/* LINTED Function has no return statement */
}

/*
 * set_signal_handling()
 *
 * Paramters:
 *	None
 *
 * Mask signals to catch.  All threads inherit the signal mask
 * from their creator (this thread).  The semantics of sigwait
 * (see signal_waiter function) requires that all threads have
 * the signal masked.  Otherwise a signal that arrives while the
 * signal_waiter is not blocked in sigwait might be delivered to
 * another thread.
 *
 * Return Values:
 *	None
 *
 */
static void
set_signal_handling()
{
	int rc;
	pthread_t signal_thread_id;

	(void) sigemptyset(&signalSet);
	(void) sigaddset(&signalSet, SIGHUP);
	(void) sigaddset(&signalSet, SIGPIPE);
	(void) sigaddset(&signalSet, SIGTERM);
	(void) sigaddset(&signalSet, SIGINT);

	if ((rc = pthread_sigmask(SIG_BLOCK, &signalSet, NULL)) != 0) {
		lm_log(LOG_ERR, "%s:%d set_signal_handling: pthread_sigmask "
		    "failed, rc - %d\n", MMS_HERE, rc);
		exit(LM_RESTART);
	}

	/*
	 *	Create signal waiter thread.
	 */
	if ((rc = pthread_create(&signal_thread_id, NULL, signal_waiter,
	    NULL)) != 0) {
		lm_log(LOG_ERR, "%s:%d set_signal_handling: pthread_create "
		    "failed to create signal_waiter thread, rc - %d\n",
		    MMS_HERE, rc);
		exit(LM_RESTART);
	}
}


/*
 * lm_initialize()
 *
 * Parameters:
 *	- cfg_name:	Name of network configuration file. This file contains
 *			necessary configuration information to connect to the MM
 *	- lm_daemon_mode:	Indicates if LM should be started in daemon
 *				mode or in a standalone execution mode.
 *				Default is daemon mode.
 *
 * Globals:
 *	- lm:		The global library management structure. Only one exists
 *			per library manager. Using a global verses passing it
 *			into all the different routines that need it.
 *
 * This function will initialize LM.
 *	- Sets up for signal processing.
 *	- Sets up the work queue for processing LMPM cmds.
 *	- Initializes mutexes.
 *	- Establishes the initial connection to MM.
 *	- Sets up the correct set of commands to support the library type.
 *
 * Return Values:
 *	MMS_OK:		Function completed sucessfully.
 *	LM_ERROR:	Function had a non recoverable error.
 *
 *			Errors are logged in the LM's mms_trace log or
 *                      syslog file.
 */
static int
lm_initialize(char *cfg_name, int lm_daemon_mode)
{
	int		err;
	int		rc;				/* return code */
	int		i;
	char		*tag = NULL;
	char		ebuf[MMS_EBUF_LEN];
	char		*hello;
	char		*welcome;
	char		*corename;

	lm_log(LOG_INFO, "%s:%d lm_init: Entering "
	    "lm_initialize, config file - %s\n", MMS_HERE, cfg_name);

			/* Set up signal handling */
	set_signal_handling();

			/* Obtain information from config file in order */
			/* be able to connect to MM */
	if (rc = mms_net_cfg_read(&lm.lm_net_cfg, cfg_name)) {
		lm_log(LOG_ERR, "%s:%d lm_init: Reading LM's config file %s "
		    "failed.\n", MMS_HERE, cfg_name);
		exit(LM_NON_RESTART);
	}
	if (lm.lm_net_cfg.cli_vers) {
		free(lm.lm_net_cfg.cli_vers);
	}
	if (lm.lm_net_cfg.cli_pass) {
		hello = mms_obfpassword(lm.lm_net_cfg.cli_pass, 1);
		free(lm.lm_net_cfg.cli_pass);
		lm.lm_net_cfg.cli_pass = hello;
	}
	if (lm.lm_net_cfg.mm_pass) {
		welcome = mms_obfpassword(lm.lm_net_cfg.mm_pass, 1);
		free(lm.lm_net_cfg.mm_pass);
		lm.lm_net_cfg.mm_pass = welcome;
	}
	if ((lm.lm_net_cfg.cli_vers = strdup(SUPPORT_LMP_VERSION)) == NULL) {
		lm_log(LOG_ERR, "%s:%d lm_init: Setting version", MMS_HERE);
		exit(LM_NON_RESTART);
	}

	lm_log(LOG_INFO, "%s:%d lm_init: Reading LM's config file %s "
	    "completed successfully\n", MMS_HERE, cfg_name);

	if (lm_daemon_mode) {
		lm_log(LOG_INFO, "%s:%d lm_init: Start LM as a daemon.\n",
		    MMS_HERE);

		if (getuid() != 0) {
			lm_log(LOG_ERR, "%s:%d lm_init: LM was started in "
			    "daemon by a process that is not root\n");
			exit(LM_NON_RESTART);
		}

		/* Close all open file descriptors and redirect stdin, */
		/* stdout, and stderr to /dev/null in prepration to */
		/* becoming a standalone daemon */
		for (i = 0; i < OPEN_MAX; i++)
			(void) close(i);

		(void) fopen("/dev/null", "r");
		(void) fopen("/dev/null", "w");
		(void) fopen("/dev/null", "w");

		if (setsid() < 0) {
			lm_log(LOG_ERR, "%s:%d lm_init: LM's setsid failed - "
			    "%s, make sure LM is started by root\n",
			    MMS_HERE, strerror(errno));
			exit(LM_NON_RESTART);
		}

		(void) umask(0);

			/* Move to where core files will be placed */
		if (mms_set_core(MMS_CORES_DIR, lm.lm_net_cfg.cli_inst)) {
			lm_log(LOG_ERR, "%s:%d lm_init: LM's core setup failed "
			    "- %s", MMS_HERE, strerror(errno));
		}

		corename = mms_strapp(NULL, "core.mmslm.%s",
		    lm.lm_net_cfg.cli_inst);
		/* Check to see how many core files exist */
		if (mms_man_cores(MMS_CORES_DIR, corename)) {
			lm_log(LOG_ERR, "%s:%d lm_init: LM's core man failed "
			    "- %s", MMS_HERE, strerror(errno));
		}
		free(corename);

			/* Trace filename should indicate which library */
			/* the mms_trace file is for */
		(void) snprintf(lm.lm_tracefn, sizeof (lm.lm_tracefn),
		    "%s/%s.debug", LM_TRACE_DIR,
		    lm.lm_net_cfg.cli_inst);
		lm_log(LOG_INFO, "%s:%d lm_init: LM's mms_trace file - %s\n",
		    MMS_HERE, lm.lm_tracefn);
		if (mms_trace_open(lm.lm_tracefn, MMS_ID_LM, -1, -1, 1, 1)) {
			lm_log(LOG_ERR, "%s:%d lm_init: Unable to open LM's "
			    "mms_trace file %s, LM is unable to mms_trace "
			    "messages.\n",
			    MMS_HERE, lm.lm_tracefn);
		}
	} else {
		if (mms_trace_open("/dev/null", MMS_ID_ND, -1, -1, 1, 1)) {
			(void) printf("%s:%d lm_init: "
			    "Unable to set mms_trace file to "
			    "stderr for non daemon mode\n", MMS_HERE);
			exit(LM_NON_RESTART);
		}
	}

#ifdef	MMS_OPENSSL
	if (mms_ssl_client(&lm.lm_net_cfg, &lm.lm_ssl_data, &lm.lm_mms_err)) {
		mms_get_error_string(&lm.lm_mms_err, ebuf, MMS_EBUF_LEN);
		mms_trace(MMS_ERR, "ssl init - %s", ebuf);
		exit(LM_NON_RESTART);
	}
#endif	/* MMS_OPENSSL */

				/* set tracing level */
#ifdef MMSDEBUG
#ifdef JDP
	(void) mms_trace_filter(MMS_SEV_DEVP);
#else
	(void) mms_trace_filter(MMS_SEV_DEBUG);
#endif /* JDP */
#else
	(void) mms_trace_filter(MMS_SEV_WARN);
#endif
	mms_trace(MMS_DEVP, "lm_init: through daemon/non-daemon startup");

		/* Initialize  work queue */
	if ((rc = lm_queue_init(&lm_cmdq, LM_NUM_WRK_THRDS, lm_cmd_handler))
	    != 0) {
		mms_trace(MMS_DEBUG, "lm_init: queue_init failed, rc - %d", rc);
		return (LM_ERROR);
	}

		/* Initialize mutex for cmd waiting on an accept response */
	if ((rc = pthread_mutex_init(&lm_acc_mutex, NULL)) != 0) {
		lm_serr(MMS_CRIT, "lm_init: acc_mutex_init failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

		/* Initialize mutex for controling writes over MM socket */
	if ((rc = pthread_mutex_init(&lm_write_mutex, NULL)) != 0) {
		lm_serr(MMS_CRIT,
		    "lm_init: write_mutex_init failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

		/* Initialize mutex for accessing response queue structure */
	if ((rc = pthread_mutex_init(&lm_rspq.rspq_mutex, NULL)) != 0) {
		lm_serr(MMS_CRIT, "lm_init: rsp_mutex_init failed, errno - %s",
		    strerror(errno));
		return (LM_ERROR);
	}

	if (mms_mmconnect(&lm.lm_net_cfg, lm.lm_ssl_data,
	    &lm.lm_mms_conn, &err, tag) < 0) {
		/* XXX STILL NEED RESPONSE TO MMS_ERROR RETURNS AS TO WHICH */
		/* ONES SHOULD CAUSE AN EXIT WITH A RESTART AND WHICH */
		/* ONES SHOULD CAUSE A NON RESTART */
		lm_serr(MMS_CRIT,
		    "lm_init: LM's mms_mmconnect failed, code - %s",
		    mms_sym_code_to_str(err));
		return (LM_ERROR);
	}

	mms_trace(MMS_DEVP, "LM's mms_mmconnect succeeded");

	return (LM_OK);
}

/*
 *
 * lm_cmd_intrp()
 *
 * Parameters:
 *	- cmd		Parse tree of LMPM command sent to LM by MM
 *	- tid		A return ptr to string containing task id from cmd
 *
 * Globals:
 *	- None.
 *
 * This function will determine which LMPM command to process. It pulls
 * the command string from the cmd node of the parse tree.
 *
 * Return Values:
 *	- Enumeration of the command to process.
 *	- MMS_LM_E_DEVCMDILLEGAL	If the cmd string was not a valid
 *					command. This should never occur
 *					unless lmpm_parse_buf() has a
 *					logic error.
 *
 */
static int
lm_cmd_intrp(mms_par_node_t *cmd, char **tid)
{
	int		rc;		/* Return code */

	char 		*cmd_str;	/* cmd to be processed */

	mms_par_node_t	*clause;	/* Ptr to clause node of parse tree */
	mms_par_node_t	*value;		/* Ptr to value node of parse tree */

	/* We know at this point we have a syntaically correct cmd, and */
	/* the cmd points to the cmd portion of the parse tree */

	mms_trace(MMS_DEVP, "Entering lm_cmd_intrp");

	cmd_str = mms_pn_token(cmd);

	if (strcmp("mount", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is mount");
		rc = LM_MOUNT;
	}

	else if (strcmp("unmount", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is unmount");
		rc = LM_UNMOUNT;
	}

	else if (strcmp("move", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is move");
		rc = LM_MOVE;
	}

	else if (strcmp("inject", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is inject");
		rc = LM_INJECT;
	}

	else if (strcmp("eject", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is eject");
		rc = LM_EJECT;
	}

	else if (strcmp("scan", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is scan");
		rc = LM_SCAN;
	}

	else if (strcmp("activate", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is activate");
		rc = LM_C_ACTIVATE;
	}

	else if (strcmp("reset", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is reset");
		rc = LM_C_RESET;
	}

	else if (strcmp("exit", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is exit");
		rc = LM_C_EXIT;
	}

	else if (strcmp("barrier", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is barrier");
		rc = LM_BARRIER;
	}

	else if (strcmp("private", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is private");
		rc = LM_C_PRIVATE;
	}

	else if (strcmp("cancel", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is cancel");
		rc = LM_CANCEL;
	}

	else if (strcmp("event", cmd_str) == 0) {
		mms_trace(MMS_DEBUG, "lm_cmd_intrp: Input is event");
		rc = LM_C_EVENT;
			/* Return here for events, there is no taskid */
			/* in an event */
		return (rc);
	}

	else {
		mms_trace(MMS_ERR,
		    "lm_cmd_intrp: Command %s is not a supported "
		    "LMPM command", cmd_str);
			/* Return unsupported command error response to MM */
		rc = MMS_LM_E_DEVCMDILLEGAL;
	}

	clause = mms_pn_lookup(cmd, "task", MMS_PN_CLAUSE, NULL);
	if (clause == NULL) {
		mms_trace(MMS_ERR, "lm_cmd_intrp: No task id clause found in "
		    "LMPM %s command", cmd_str);
		/* Return an unacceptable to MM for the command */
		return (rc);
	}
	value = mms_pn_lookup(clause, NULL, MMS_PN_STRING, NULL);
	if (value == NULL) {
		mms_trace(MMS_ERR, "lm_cmd_intrp: No task id value found in "
		    "LMPM %s command", cmd_str);
		/* Return an unacceptable to MM for this command */
		return (rc);
	}
	*tid = mms_pn_token(value);

	return (rc);
}

/*
 * lm_input_handler()
 *
 * Parameters:
 *	- None
 *
 * Globals:
 *	lm	The global library management structure. Only one exists
 *		per library manager. Using a global verses passing it
 *		into all the different routines that need it.
 *
 * This function will handle all input for LM from MM.
 *	- Read input from MM.
 *	- Parse input.
 *	- Send accept/unaccept response for command
 *	- Determine if a response cmd. If so give response to the thread that
 *	  is waiting on the response. Response can be a accept or finial.
 *	- If new command place command on work queue for processing threads.
 *
 * Return Values:
 *	NONE:	This routine does not exit unless LM is told to shutdown or
 *		an internal error is detected. The lm_internal_error and
 *		lm_state variables control when this routine will return.
 */
static void
lm_input_handler()
{

	int		rc;		/* return code */
	int		class;
	int		code;

	char		*input = NULL;	/* ptr to xml input string from MM */
	char		*tid;		/* new cmd's task id */
	char		msg_str[256];
	char		rsp_str[512];

	mms_list_t	err_list;	/* error list structure for parser */
	mms_par_node_t	*cmd;		/* ptr to parsed xml input string */
	mms_par_node_t	*node;		/* ptr to cmd node of parsed xml str */

	fd_set		fdset;
	struct timeval	tv;
	struct timeval	*tvp;

	mms_trace(MMS_DEVP, "Entering lm_input_handler");

		/* Continue processing input until we are told by MM through */
		/* an exit command to shutdown. Signals may also shut us down */
		/* but at this point, we don't know which signals we are to */
		/* accept and which ones we are to ignore */
	/* LINTED constant in conditional context */
	while (1) {
		if (getppid() == 1) {
			lm_serr(MMS_CRIT, "lm_input_handler: LM has detected "
			    "that it's parnet process mmswcr has gone away");
			lm_internal_error = LM_NO_WCR;
			return;
		}
				/* Setup a timer on the select so that */
				/* we will kick out periodically to see if */
				/* a signal from the watcher occurred */

		FD_ZERO(&fdset);
		FD_SET(lm.lm_mms_conn.mms_fd, &fdset);

		tv.tv_sec = LM_SELECT_WAIT;
		tv.tv_usec = 0;
		tvp = &tv;

		mms_trace_flush();
		rc = select(lm.lm_mms_conn.mms_fd + 1, &fdset, NULL, NULL,
		    tvp);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EBADF) {
				lm_serr(MMS_CRIT, "lm_input_handler: select() "
				    "has determined that the MM socket is no "
				    "longer open - %s", strerror(errno));
				lm_internal_error = LM_NO_MM;
				return;
			} else {
				lm_serr(MMS_CRIT, "lm_input_handler: select() "
				    "on socket to MM has failed with a "
				    "errno of %s", strerror(errno));
				return;
			}

				/* Timer expired see if a something  occurred */
				/* to cause LM to shutdown */
		} else if (rc == 0) {
				/* Check to see if LM was told to stop */
			if (lm_state == LM_STOP) {
					/* See if LM can exit */
				if (lm_cmdq.lmq_first == NULL &&
				    lm_cmdq.lmq_counter == 0) {
					mms_trace(MMS_DEBUG,
					    "lm_input_handler: "
					    "LM told to exit and there are no "
					    "outstanding LMPM commands left to "
					    "process, shutting down LM");
					return;
				}
			}
				/* Check to see if one of the command */
				/* processing threads encountered an internal */
				/* error */
			if (lm_internal_error) {
				mms_trace(MMS_DEBUG, "lm_input_handler: LM has "
				    "encountered an unrecoverable internal "
				    "error, shutting down LM");
				return;
			}
			continue;
		}

			/* Check to see if one of the command processing */
			/* threads encountered an internal error */
		if (lm_internal_error) {
			mms_trace(MMS_DEBUG,
			    "lm_input_handler: LM has encountered "
			    "an unrecoverable internal error, shutting "
			    "down LM");
			return;
		}

			/* Obtain input from MM */
		if (! FD_ISSET(lm.lm_mms_conn.mms_fd, &fdset)) {
			mms_trace(MMS_ERR, "lm_input_handler: select() "
			    "tripped on a file descriptor, but not the one "
			    "LM has opened with MM");
			continue;
		}

		if ((rc = mms_reader(&lm.lm_mms_conn, &input)) <= 0) {
			if (rc == 0) {
				lm_serr(MMS_CRIT, "lm_input_handler: Reading "
				    "routine mms_reader() has indicated that "
				    "the MM has disconnected");
				lm_internal_error = LM_NO_MM;
			} else
				lm_serr(MMS_CRIT, "lm_input_handler: Reading "
				    "routine mms_reader() failed with a "
				    "return code of %d", rc);
			return;
		}

		if (rc = mms_lmpm_parse(&cmd, &err_list, input)) {
			mms_trace(MMS_ERR, "lm_input_handler: lmpm_parse_buf() "
			    "failed on MM input:\n%s", input);
			if ((rc = lm_handle_parser_error(cmd, &err_list))
			    == LM_NOMEM) {
					/* NOMEM error, retry parsing again */
				mms_pe_destroy(&err_list);
				mms_pn_destroy(cmd);
				if (mms_lmpm_parse(&cmd, &err_list, input)) {
					/* Second attempt at parsing had an */
					/* error, return error */
					lm_serr(MMS_CRIT, "lm_input_handler: "
					    "lmpm_parser() failed on second "
					    "attempt to parse input after a "
					    "first attempt failed due to lack "
					    "of memory");
				} else {
					mms_trace(MMS_OPER, "lm_input_handler: "
					    "Able to obtain memory to parse "
					    "new input on second attempt of "
					    "parse");
					goto parse_ok;
				}
			}

			switch (rc) {
				case LM_NOMEM:
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7025_MSG);
					(void) snprintf(rsp_str,
					    sizeof (rsp_str), LM_MSG_PARSE,
					    msg_str);
					break;
				case LM_SYNTAX_ERR:
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7024_MSG);
					(void) snprintf(rsp_str,
					    sizeof (rsp_str), LM_MSG_PARSE,
					    msg_str);
					break;
				case LM_SYNTAX_RSP:
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7023_MSG);
					(void) snprintf(rsp_str,
					    sizeof (rsp_str), LM_MSG_PARSE,
					    msg_str);
					break;
				case LM_SYNTAX_CMD:
					node = mms_pn_lookup(cmd, NULL,
					    MMS_PN_CMD, NULL);
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7005_MSG,
					    mms_pn_token(node),
					    mms_pn_token(node));
					(void) snprintf(rsp_str,
					    sizeof (rsp_str), LM_MSG_PARSE,
					    msg_str);
					break;
				default:
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7026_MSG);
					(void) snprintf(rsp_str,
					    sizeof (rsp_str), LM_MSG_PARSE,
					    msg_str);
					break;
			}
				/* Send message to MM indicating the type */
				/* of parse error detected. Do no wait for */
				/* a response to the message */
			if (lm_write_msg(rsp_str, &lm.lm_mms_conn,
			    lm_write_mutex))
				lm_serr(MMS_CRIT, "lm_input_handler: Sending "
				    "parser error message failed");
			mms_pe_destroy(&err_list);
			mms_pn_destroy(cmd);
			free(input);
			return;
		}
parse_ok:
		mms_pe_destroy(&err_list);
		node = mms_pn_lookup(cmd, NULL, MMS_PN_CMD, NULL);
			/* This should never occur unless parser generated */
			/* a invalid parse tree or memory corruption */
		if (node == NULL) {
			lm_serr(MMS_CRIT, "lm_input_handler: No command node "
			    "found in MM input:\n%s", input);
			mms_pn_destroy(cmd);
			free(input);
			return;
		}

		if (strcmp("response", node->pn_string) == 0) {
			/* Have received a response for a LMPL command */
			/* that the LM sent to the MM, update the response */
			/* command structure with the necessary response */
			/* and wake up command processing thread waiting on */
			/* the response */
			/* NOTE: We do not destory the node "cmd" here. It is */
			/* the job of function that issued the LMPL command */
			/* to free the cmd memory when it is done processing */
			/* the response */
			mms_trace(MMS_OPER, "lm_input_handler: Received a LMPL "
			    "response:\n%s", input);
			if (lm_handle_response(cmd)) {
				mms_trace(MMS_DEBUG, "lm_input_handler: "
				    "lm_handle_response was not able to "
				    "handle response cleanly");
				mms_pn_destroy(cmd);
				free(input);
				return;
			}
			free(input);
			continue;
		}
		/* At this point we can assume that we have a new LMPM */
		/* command Determine the command to process send an */
		/* accept/unacceptable response and place command onto work */
		/* queue for worker threads */
		/* NOTE: We do not destory the node "cmd" here. It is the job */
		/* of lm_cmd_handler() function to free the cmd memory when */
		/* it is done processing the cmd */

		mms_trace(MMS_OPER,
		    "lm_input_handler: Process LMPM command:\n%s",
		    input);
		tid = NULL;
		rc = lm_cmd_intrp(cmd, &tid);
			/* Check to see if LMPM command is an event */
		if (rc == LM_C_EVENT) {
			if (lm_handle_event(cmd)) {
				mms_trace(MMS_DEBUG, "lm_input_handler: "
				    "handle_event failed with internal "
				    "error");
				return;
			}
			continue;
		}
			/* If lm_cmd_intrp was unable to obtain a valid */
			/* task id for the command we need to send an */
			/* unaccept response for the command. There is */
			/* an issue with lmpm_parse_buf since it did not */
			/* issue an error for the command and yet we could */
			/* not find the task id for the command */
		if (tid == NULL || *tid == '\0') {
			(void) snprintf(msg_str,
			    sizeof (msg_str), LM_7000_MSG, mms_pn_token(cmd),
			    mms_pn_token(cmd));
			(void) snprintf(rsp_str, sizeof (rsp_str),
			    LM_UNACC_RESP, msg_str);
			mms_trace(MMS_OPER,
			    "lm_input_handler: Sending unacceptable "
			    "response for LMPM %s command:\n%s",
			    mms_pn_token(cmd), rsp_str);
			if (lm_write_msg(rsp_str, &lm.lm_mms_conn,
			    lm_write_mutex)) {
				lm_serr(MMS_CRIT, "lm_input_handler: Sending "
				    "unacceptable response failed");
				mms_pn_destroy(cmd);
				free(input);
				return;
			}
				/* Obtain next command */
			continue;
		}

			/* Send accept response for command */
		(void) snprintf(rsp_str, sizeof (rsp_str), LM_ACC_RESP, tid);
		mms_trace(MMS_OPER,
		    "lm_input_handler: Sending accept response:\n%s",
		    rsp_str);
		if (lm_write_msg(rsp_str, &lm.lm_mms_conn, lm_write_mutex)) {
			lm_serr(MMS_CRIT, "lm_input_handler: Sending accept "
			    "response failed");
			mms_pn_destroy(cmd);
			free(input);
			return;
		}

			/* If processing an exit cmd, */
			/* SIGTERM, or SIGINT, the state of lm gets set */
			/* to LM_STOP. Any commands that are received */
			/* after one of the above, will be aborted with an */
			/* error response */
		if (lm_state == LM_STOP) {
			(void) snprintf(msg_str,
			    sizeof (msg_str), LM_7003_MSG, mms_pn_token(cmd),
			    mms_pn_token(cmd));
			mms_pn_destroy(cmd);
			(void) snprintf(rsp_str,
			    sizeof (rsp_str), LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(MMS_INTERNAL),
			    mms_sym_code_to_str(MMS_LM_E_DEVCMDABORT),
			    msg_str);
			mms_trace(MMS_OPER,
			    "lm_input_handler: LM in stop state "
			    "sending error final response for new command:"
			    "\n%s", rsp_str);
			if (lm_write_msg(rsp_str, &lm.lm_mms_conn,
			    lm_write_mutex)) {
				lm_serr(MMS_CRIT, "lm_input_handler: Sending "
				    "error response failed");
				return;
			}
			mms_pn_destroy(cmd);
			free(input);
			continue;
		}

		code = 0;
		class = 0;
		switch (rc) {
				/* Commands that can be executed with LM */
				/* in any state execpt stop. Stop state */
				/* is detected above, thus not in stop state */
			case LM_C_RESET:
			case LM_C_EXIT:
			case LM_C_PRIVATE:
				break;
				/* Commands that can be executed with LM */
				/* in not-ready, broken, or disconnected */
			case LM_BARRIER:
			case LM_CANCEL:
				if (!(lm_state & LM_MASK0)) {
					mms_trace(MMS_ERR,
					    "lm_input_handler: LM "
					    "is not in a valid state to "
					    "process %s command, state "
					    "- 0x%x",
					    lm_cmdData[rc].cmd, lm_state);
					code = MMS_LM_E_READY;
					class = MMS_STATE;
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7001_MSG,
					    lm_cmdData[rc].cmd,
					    lm_cmdData[rc].cmd);
				}
				break;

				/* Commands that can be executed with LM */
				/* only in not-active, disconnected, or */
				/* active states */
			case LM_C_ACTIVATE:
				if (!(lm_state & LM_MASK1)) {
					mms_trace(MMS_ERR,
					    "lm_input_handler: LM "
					    "is not in a valid state to "
					    "process %s command, state "
					    "- 0x%x",
					    lm_cmdData[rc].cmd, lm_state);
					code = MMS_LM_E_READY;
					class = MMS_STATE;
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7001_MSG,
					    lm_cmdData[rc].cmd,
					    lm_cmdData[rc].cmd);
				}
				break;
				/* Commands that can only be executed with */
				/* LM in the active state */
			case LM_MOUNT:
			case LM_UNMOUNT:
			case LM_MOVE:
			case LM_INJECT:
			case LM_SCAN:
			case LM_EJECT:
					/* Make sure LM is active */
				if (!(lm_state & LM_MASK2)) {
					mms_trace(MMS_ERR,
					    "lm_input_handler: LM "
					    "is not in a valid state to "
					    "process %s command, state "
					    "- 0x%x",
					    lm_cmdData[rc].cmd, lm_state);
					code = MMS_LM_E_READY;
					class = MMS_STATE;
					(void) snprintf(msg_str,
					    sizeof (msg_str), LM_7001_MSG,
					    lm_cmdData[rc].cmd,
					    lm_cmdData[rc].cmd);
				}
				break;
			case MMS_LM_E_DEVCMDILLEGAL:
				mms_trace(MMS_DEBUG,
				    "lm_input_handler: cmd_intrp "
				    "returned invalid command found, send "
				    "error final response");
				(void) snprintf(msg_str, sizeof (msg_str),
				    LM_7002_MSG,
				    mms_pn_token(cmd), mms_pn_token(cmd));
				code = rc;
				class = MMS_INTERNAL;
				break;
		}
		if (code) {
			(void) snprintf(rsp_str, sizeof (rsp_str),
			    LM_ERR_FINAL, tid,
			    mms_sym_code_to_str(class),
			    mms_sym_code_to_str(code), msg_str);
			mms_trace(MMS_OPER, "lm_input_handler: Sending error "
			    "final response to LMPM %s command:\n%s",
			    mms_pn_token(cmd), rsp_str);
			if (lm_write_msg(rsp_str, &lm.lm_mms_conn,
			    lm_write_mutex)) {
				lm_serr(MMS_CRIT, "lm_input_handler: Sending "
				    "error final response failed");
				return;
			}
			mms_pn_destroy(cmd);
			free(input);
			continue;
		}
			/* Free command memory */
		free(input);

		mms_trace(MMS_DEBUG, "lm_input_handler: Adding %s command to "
		    "work queue", mms_pn_token(cmd));
		if ((rc = lm_queue_add(&lm_cmdq, (void *)cmd, &tid, rc))
		    != LM_OK) {
			mms_trace(MMS_DEBUG, "lm_input_handler adding %s "
			    "command to LM's work queue failed",
			    mms_pn_token(cmd));
			mms_pn_destroy(cmd);
			return;
		}
	}
}

/*
 *
 * lm_cmd_handler()
 *
 * Parameters:
 *	- ce		Structure to a work queue element. The structure
 *			contains the necessary elements to process a command,
 *			one being the parse tree of the command itself. See
 *			lm.h for a complete description of the elements of
 *			the structure.
 *
 * This function is what process each of the commands issued to LM by
 * MM. This function is actually executed as a spearate thread within LM.
 * The queue_add function called by lm_input_handler() is what starts this
 * function as a thread. The queue_add() function will start up to a
 * max number of these threads to process individual commands. See the
 * the queue functions for a better description of how the work queue is
 * used.
 *
 * The final response is written out when the command processing returns.
 *
 * Return Values:
 *	- None. 	All error encountered need to be handled at a global
 *			level. Errors found in this routine are issues with
 *			system problems and most likely cause the LM to abort
 *			since recovery in most cases cannot be done correctly.
 *			The cmd was successfully parsed and thus should
 *			represent a valid command.
 *
 */

static void
lm_cmd_handler(lm_queue_ele_t *ce)
{
					/* Parse tree of cmd being processed */
	mms_par_node_t	*cmd = ce->lmqe_cmd_tree;
	char		ret_msg[RMBUFSIZE];
	int		rc;

	mms_trace(MMS_DEVP, "Entering lm_cmd_handler");

	mms_trace(MMS_DEBUG, "lm_cmd_handler: Processing LMPM command %s",
	    lm_cmdData[ce->lmqe_cindex].cmd);

					/* Call cmd processing routine */
	rc = (*lm_cmdData[ce->lmqe_cindex].cd_cmdptr)(cmd, ce->lmqe_tid,
	    &ret_msg[0]);

		/* Each command will return either a successful finial */
		/* response or an error finial response message */
	if (rc == LM_ERROR)
		mms_trace(MMS_DEBUG,
		    "lm_cmd_handler: Processing of LMPM %s command "
		    "failed:\n%s", lm_cmdData[ce->lmqe_cindex].cmd,
		    mms_pn_build_cmd_text(cmd));
	else
		mms_trace(MMS_DEVP,
		    "lm_cmd_handler: Processing of LMPM %s command "
		    "succeded", lm_cmdData[ce->lmqe_cindex].cmd);

		/* Free memory of parse tree of LMPM cmd */
	mms_pn_destroy(cmd);

		/* Event or internal commands do not get a acknowledge or */
		/* final response */
	if (ce->lmqe_cindex == LM_C_EVENT || ce->lmqe_cindex == LM_C_INTERNAL)
		return;

			/* write out final response message for LMPM command */
	mms_trace(MMS_OPER, "lm_cmd_handler: %s command's final response - %s",
	    lm_cmdData[ce->lmqe_cindex].cmd, ret_msg);
	if (lm_write_msg(ret_msg, &lm.lm_mms_conn, lm_write_mutex)) {
		lm_serr(MMS_CRIT, "lm_cmd_handler: Sending finial response for "
		    "%s command to MM failed",
		    lm_cmdData[ce->lmqe_cindex].cmd);
	}
}

/*
 *
 * Main routine for Library Manager.
 *
 * Arguments:
 *	Arg 1:	Path to configuration file which this instance of LM is to
 *			use to obtain its configuration information from.
 *	Arg 2:	Indicates if LM should be run in a non daemon mode. If set
 *		then LM can run as a standalone process. If run in daemon
 *		mode (default) LM must be run as root.
 *
 * Description:
 *	Each instance of an LM is used to control an actual physical instance
 *	of a library. Multiple LM instances for a library can exist at the
 *	same time, but only one can be active at a given time.
 */
int
main(int argc, char **argv)
{
	char	msg_str[256];
	char	msg_cmd[512];

			/* If a second parameter is passed then this */
			/* indicates that LM is being run in standalone mode */
	if (argc == 3)
		lm_daemon_mode = 0;

	if (argc == 1) {
		lm_log(LOG_ERR, "%s:%d LM was not given a configuration file. "
		    "Unable to start LM\n.", MMS_HERE);
		exit(LM_RESTART);
	}

	if (lm_initialize(argv[1], lm_daemon_mode) == LM_ERROR) {
		mms_trace(MMS_CRIT,
		    "LM initialization failed, Unable to start LM.");
		mms_trace_flush();
		mms_trace_close();
		exit(LM_RESTART);
	} else
		lm_input_handler();


	if (lm_internal_error == LM_NO_MM) {
		mms_trace(MMS_OPER,
		    "Exiting LM because connection to MM is gone");
		mms_trace_flush();
		mms_trace_close();
		exit(exit_code);
	}
		/* send a message to MM indicating LM is shutting down */
	if (lm_internal_error) {
		if (lm_internal_error == LM_NO_WCR)
			(void) sprintf(msg_str, LM_7021_MSG);
		else
			(void) sprintf(msg_str, LM_7007_MSG);
		(void) snprintf(msg_cmd, sizeof (msg_cmd),
		    LM_MSG_EXIT, msg_str);
		(void) mms_writer(&lm.lm_mms_conn, msg_cmd);
	} else if (exit_code == LM_SIG_NRESTART || exit_code ==
	    LM_SIG_RESTART) {
		(void) snprintf(msg_str, sizeof (msg_str),
		    LM_7006_MSG, exit_code, exit_code);
		(void) snprintf(msg_cmd, sizeof (msg_cmd),
		    LM_MSG_EXIT, msg_str);
		if (lm_write_msg(msg_cmd, &lm.lm_mms_conn, lm_write_mutex))
			mms_trace(MMS_ERR, "Sending exit message failed");
		if (exit_code == LM_SIG_NRESTART)
			exit_code = LM_NON_RESTART;
		else
			exit_code = LM_RESTART;
	}

	mms_trace(MMS_OPER, "Exiting LM with exit code - %d", exit_code);
	mms_trace_flush();
	mms_trace_close();

		/* Need sleep in order for MM to complete processing of */
		/* the LMPL message */
	(void) sleep(5);
	mms_close(&lm.lm_mms_conn);

	return (exit_code);
}
