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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is a module that provides an interface to managing
 * concurrent sessions executed in either a separate thread or a
 * separate process. Threads are used only if the compile time flag
 * DCS_MULTI_THREAD is set. Otherwise, a new process is forked for
 * each session.
 *
 * Multiple processes are used to enable full Internationalization
 * support. This support requires that each session is able to set
 * its own locale for use in reporting errors to the user. Currently,
 * this is not possible using multiple threads because the locale
 * can not be set for an individual thread. For this reason, multiple
 * processes are supported until proper locale support is provided
 * for multiple threads.
 *
 * When Solaris supports a different locale in each thread, all
 * code used to enable using multiple processes should be removed.
 * To simplify this process, all references to DCS_MULTI_THREAD can
 * be found in this file.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <locale.h>
#include <sys/socket.h>

#ifdef DCS_MULTI_THREAD
#include <thread.h>
#include <pthread.h>
#else /* DCS_MULTI_THREAD */
#include <sys/types.h>
#include <sys/wait.h>
#endif /* DCS_MULTI_THREAD */

#include "dcs.h"
#include "rdr_messages.h"
#include "rdr_param_types.h"


#define	DCS_DEFAULT_LOCALE		"C"


/* session allocation/deallocation functions */
static int ses_alloc(void);
static int ses_free(void);

/* handler functions */
static void *ses_handler(void *arg);
#ifndef DCS_MULTI_THREAD
static void exit_handler(int sig, siginfo_t *info, void *context);
#endif /* !DCS_MULTI_THREAD */

/* session accounting functions */
#ifdef DCS_MULTI_THREAD
static void ses_thr_exit(void);
#endif /* DCS_MULTI_THREAD */


/*
 * Global structure that holds all relevant information
 * about the current session. If multiple threads are
 * used, the thread specific data mechanism is used. This
 * requires a data key to access the thread's private
 * session information.
 */
#ifdef DCS_MULTI_THREAD
thread_key_t	ses_key = THR_ONCE_KEY;
#else /* DCS_MULTI_THREAD */
session_t	*ses;
#endif /* DCS_MULTI_THREAD */


/*
 * Information about the current number of active sessions.
 * If multiple threads are used, synchronization objects
 * are required.
 */
static ulong_t sessions = 0;

#ifdef DCS_MULTI_THREAD
static mutex_t	sessions_lock = DEFAULTMUTEX;
static cond_t	sessions_cv   = DEFAULTCV;
#endif /* DCS_MULTI_THREAD */


/*
 * ses_start:
 *
 * Start the session handler. If multiple threads are used, create a new
 * thread that runs the ses_handler() function. If multiple processes
 * are used, fork a new process and call ses_handler().
 */
int
ses_start(int fd)
{
#ifdef DCS_MULTI_THREAD

	int	thr_err;


	mutex_lock(&sessions_lock);
	sessions++;
	mutex_unlock(&sessions_lock);

	thr_err = thr_create(NULL, 0, ses_handler, (void *)fd,
	    THR_DETACHED | THR_NEW_LWP, NULL);

	return ((thr_err) ? -1 : 0);

#else /* DCS_MULTI_THREAD */

	int 	pid;


	pid = fork();

	if (pid == -1) {
		(void) rdr_close(fd);
		return (-1);
	}

	/*
	 * Parent:
	 */
	if (pid) {
		/* close the child's fd */
		(void) close(fd);

		sessions++;

		return (0);
	}

	/*
	 * Child:
	 */
	ses_handler((void *)fd);

	/*
	 * Prevent return to parent's loop
	 */
	exit(0);

	/* NOTREACHED */

#endif /* DCS_MULTI_THREAD */
}


/*
 * ses_close:
 *
 * Initiate the closure of a session by sending an RDR_SES_END message
 * to the client. It does not attempt to close the network connection.
 */
int
ses_close(int err_code)
{
	session_t	*sp;
	cfga_params_t	req_data;
	rdr_msg_hdr_t	req_hdr;
	int		snd_status;
	static char	*op_name = "session close";


	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	/* check if already sent session end */
	if (sp->state == DCS_SES_END) {
		return (0);
	}

	/* prepare header information */
	init_msg(&req_hdr);
	req_hdr.message_opcode = RDR_SES_END;
	req_hdr.data_type = RDR_REQUEST;
	req_hdr.status = err_code;

	/* no operation specific data */
	(void) memset(&req_data, 0, sizeof (req_data));

	PRINT_MSG_DBG(DCS_SEND, &req_hdr);

	/* send the message */
	snd_status = rdr_snd_msg(sp->fd, &req_hdr, &req_data, DCS_SND_TIMEOUT);

	if (snd_status == RDR_ABORTED) {
		abort_handler();
	}

	if (snd_status != RDR_OK) {
		dcs_log_msg(LOG_ERR, DCS_OP_REPLY_ERR, op_name);
	}

	/*
	 * Setting the session state to DCS_SES_END will
	 * cause the session handler to terminate the
	 * network connection. This should happen whether
	 * or not the session end message that was just
	 * sent was received successfully.
	 */
	sp->state = DCS_SES_END;
	return (0);
}


/*
 * ses_abort:
 *
 * Attempt to abort an active session. If multiple threads are used,
 * the parameter represents a thread_t identifier. If multiple
 * processes are used, the parameter represents a pid. In either
 * case, use this identifier to send a SIGINT signal to the approprate
 * session.
 */
int
ses_abort(long ses_id)
{
	DCS_DBG(DBG_SES, "killing session %d", ses_id);

#ifdef DCS_MULTI_THREAD

	if (thr_kill(ses_id, SIGINT) != 0) {
		/*
		 * If the thread cannot be found, we will assume
		 * that the session was able to exit normally. In
		 * this case, there is no error since the desired
		 * result has already been achieved.
		 */
		if (errno == ESRCH) {
			return (0);
		}
		return (-1);
	}

#else /* DCS_MULTI_THREAD */

	if (kill(ses_id, SIGINT) == -1) {
		/*
		 * If the process cannot be found, we will assume
		 * that the session was able to exit normally. In
		 * this case, there is no error since the desired
		 * result has already been achieved.
		 */
		if (errno == ESRCH) {
			return (0);
		}
		return (-1);
	}

#endif /* DCS_MULTI_THREAD */

	return (0);
}


/*
 * ses_abort_enable:
 *
 * Enter a mode where the current session can be aborted. This mode
 * will persist until ses_abort_disable() is called.
 *
 * A signal handler for SIGINT must be installed prior to calling this
 * function. If this is not the case, and multiple threads are used,
 * the default handler for SIGINT will cause the entire process to
 * exit, rather than just the current session. If multiple processes
 * are used, the default handler for SIGINT will not affect the main
 * process, but it will prevent both sides from gracefully closing
 * the session.
 */
void
ses_abort_enable(void)
{
	sigset_t	unblock_set;


	/* unblock SIGINT */
	sigemptyset(&unblock_set);
	sigaddset(&unblock_set, SIGINT);
	(void) sigprocmask(SIG_UNBLOCK, &unblock_set, NULL);
}


/*
 * ses_abort_disable:
 *
 * Exit the mode where the current session can be aborted. This
 * will leave the mode entered by ses_abort_enable().
 */
void
ses_abort_disable(void)
{
	sigset_t	block_set;


	/* block SIGINT */
	sigemptyset(&block_set);
	sigaddset(&block_set, SIGINT);
	(void) sigprocmask(SIG_BLOCK, &block_set, NULL);
}


/*
 * ses_setlocale:
 *
 * Set the locale for the current session. Currently, if multiple threads
 * are used, the 'C' locale is specified for all cases. Once there is support
 * for setting a thread specific locale, the requested locale will be used.
 * If multiple processes are used, an attempt is made to set the locale of
 * the process to the locale passed in as a parameter.
 */
int
ses_setlocale(char *locale)
{
	char	*new_locale;

	/* sanity check */
	if (locale == NULL) {
		locale = DCS_DEFAULT_LOCALE;
	}

#ifdef DCS_MULTI_THREAD

	/*
	 * Reserved for setting the locale on a per thread
	 * basis. Currently there is no Solaris support for
	 * this, so use the default locale.
	 */
	new_locale = setlocale(LC_ALL, DCS_DEFAULT_LOCALE);

#else /* DCS_MULTI_THREAD */

	new_locale = setlocale(LC_ALL, locale);

#endif /* DCS_MULTI_THREAD */

	if ((new_locale == NULL) || (strcmp(new_locale, locale) != 0)) {
		/* silently fall back to C locale */
		new_locale = setlocale(LC_ALL, DCS_DEFAULT_LOCALE);
	}

	DCS_DBG(DBG_SES, "using '%s' locale", new_locale);

	return (0);
}


/*
 * ses_init_signals:
 *
 * Initialize the set of signals to be blocked. It is assumed that the
 * mask parameter initially contains all signals. If multiple threads
 * are used, this is the correct behavior and the mask is not altered.
 * If multiple processes are used, session accounting is performed in
 * a SIGCHLD handler and so SIGCHLD must not be blocked. The action of
 * initializing this handler is also performed in this function.
 */
/* ARGSUSED */
void
ses_init_signals(sigset_t *mask)
{
#ifndef DCS_MULTI_THREAD

	struct sigaction	act;


	/* unblock SIGCHLD */
	(void) sigdelset(mask, SIGCHLD);

	/*
	 * Establish a handler for SIGCHLD
	 */
	(void) memset(&act, 0, sizeof (act));
	act.sa_sigaction = exit_handler;
	act.sa_flags = SA_SIGINFO;

	(void) sigaction(SIGCHLD, &act, NULL);

#endif /* !DCS_MULTI_THREAD */
}


/*
 * ses_sleep:
 *
 * Sleep for a specified amount of time, but don't prevent the
 * session from being aborted.
 */
void
ses_sleep(int sec)
{
	ses_abort_enable();
	sleep(sec);
	ses_abort_disable();
}


/*
 * ses_wait:
 *
 * Wait for the number of active sessions to drop below the maximum
 * allowed number of active sessions. If multiple threads are used,
 * the thread waits on a condition variable until a child thread
 * signals that it is going to exit. If multiple processes are used,
 * the process waits until at least one child process exits.
 */
static void
ses_wait(void)
{
#ifdef DCS_MULTI_THREAD

	mutex_lock(&sessions_lock);

	while (sessions >= max_sessions) {
		cond_wait(&sessions_cv, &sessions_lock);
	}

	mutex_unlock(&sessions_lock);

#else /* DCS_MULTI_THREAD */

	if (sessions >= max_sessions) {
		(void) wait(NULL);
	}

#endif /* DCS_MULTI_THREAD */
}


/*
 * ses_poll:
 *
 * Poll on the file descriptors passed in as a parameter. Before polling,
 * a check is performed to see if the number of active sessions is less
 * than the maximum number of active sessions allowed. If the limit for
 * active sessions is reached, the poll will be delayed until at least
 * one session exits.
 */
int
ses_poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	int	err;


	ses_wait();

	err = poll(fds, nfds, timeout);

	return (err);
}


/*
 * curr_ses:
 *
 * Return a pointer to the global session information. If multiple threads
 * are being used, this will point to a thread specific instance of a
 * session structure.
 */
session_t *
curr_ses(void)
{
#ifdef DCS_MULTI_THREAD

	return (pthread_getspecific(ses_key));

#else /* DCS_MULTI_THREAD */

	return (ses);

#endif /* DCS_MULTI_THREAD */
}


/*
 * curr_ses_id:
 *
 * Return the session identifier. This is either the thread_t identifier
 * of the thread, or the pid of the process.
 */
long
curr_ses_id(void)
{
#ifdef DCS_MULTI_THREAD

	return (thr_self());

#else /* DCS_MULTI_THREAD */

	return (getpid());

#endif /* DCS_MULTI_THREAD */
}


/*
 * ses_handler:
 *
 * Handle initialization and processing of a session. Initializes a session
 * and enters a loop which waits for requests. When a request comes in, it
 * is dispatched. When the session is terminated, the loop exits and the
 * session is cleaned up.
 */
static void *
ses_handler(void *arg)
{
	session_t		*sp;
	rdr_msg_hdr_t		op_hdr;
	cfga_params_t		op_data;
	int			rcv_status;
	sigset_t		block_set;
	struct sigaction	act;

	static char *dcs_state_str[] = {
		"unknown state",
		"DCS_CONNECTED",
		"DCS_SES_REQ",
		"DCS_SES_ESTBL",
		"DCS_CONF_PENDING",
		"DCS_CONF_DONE",
		"DCS_SES_END"
	};


	if (ses_alloc() == -1) {
		(void) rdr_close((int)arg);
		return ((void *)-1);
	}

	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (NULL);
	}

	/* initialize session information */
	memset(sp, 0, sizeof (session_t));
	sp->state = DCS_CONNECTED;
	sp->random_resp = lrand48();
	sp->fd = (int)arg;
	sp->id = curr_ses_id();

	/* initially, block all signals and cancels */
	(void) sigfillset(&block_set);
	(void) sigprocmask(SIG_BLOCK, &block_set, NULL);

	/* set the abort handler for this session */
	(void) memset(&act, 0, sizeof (act));
	act.sa_handler = abort_handler;
	(void) sigaction(SIGINT, &act, NULL);

	DCS_DBG(DBG_SES, "session handler starting...");

	/*
	 * Process all requests in the session until the
	 * session is terminated
	 */
	for (;;) {

		DCS_DBG(DBG_STATE, "session state: %s",
		    dcs_state_str[sp->state]);

		if (sp->state == DCS_SES_END) {
			break;
		}

		(void) memset(&op_hdr, 0, sizeof (op_hdr));
		(void) memset(&op_data, 0, sizeof (op_data));

		rcv_status = rdr_rcv_msg(sp->fd, &op_hdr, &op_data,
		    DCS_RCV_TIMEOUT);

		if (rcv_status != RDR_OK) {

			switch (rcv_status) {

			case RDR_TIMEOUT:
				DCS_DBG(DBG_SES, "receive timed out");
				break;

			case RDR_DISCONNECT:
				dcs_log_msg(LOG_NOTICE, DCS_DISCONNECT);
				break;

			case RDR_ABORTED:
				dcs_log_msg(LOG_INFO, DCS_SES_ABORTED);
				break;

			case RDR_MSG_INVAL:
				/*
				 * Only log invalid messages if a session has
				 * already been established. Logging invalid
				 * session request messages could flood syslog.
				 */
				if (sp->state != DCS_CONNECTED) {
					dcs_log_msg(LOG_WARNING, DCS_MSG_INVAL);
				} else {
					DCS_DBG(DBG_SES, "received an invalid "
					    "message");
				}

				break;

			default:
				dcs_log_msg(LOG_ERR, DCS_RECEIVE_ERR);
				break;
			}

			/*
			 * We encountered an unrecoverable error,
			 * so exit this session handler.
			 */
			break;

		} else {
			/* handle the message */
			dcs_dispatch_message(&op_hdr, &op_data);
			rdr_cleanup_params(op_hdr.message_opcode, &op_data);
		}
	}

	DCS_DBG(DBG_SES, "connection closed");

	/* clean up */
	(void) rdr_close(sp->fd);
	(void) ses_free();

#ifdef DCS_MULTI_THREAD
	ses_thr_exit();
#endif /* DCS_MULTI_THREAD */

	return (0);
}


/*
 * abort_handler:
 *
 * Handle a request to abort a session. This function should be installed
 * as the signal handler for SIGINT. It sends a message to the client
 * indicating that the session was aborted, and that the operation failed
 * as a result. The session then terminates, and the thread or process
 * handling the session exits.
 */
void
abort_handler(void)
{
	session_t	*sp;
	rdr_msg_hdr_t	op_hdr;
	cfga_params_t	op_data;


	/* get the current session information */
	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
#ifdef DCS_MULTI_THREAD
		ses_thr_exit();
		thr_exit(0);
#else /* DCS_MULTI_THREAD */
		exit(0);
#endif /* DCS_MULTI_THREAD */
	}

	DCS_DBG(DBG_MSG, "abort_handler()");

	/* prepare header information */
	init_msg(&op_hdr);
	op_hdr.message_opcode = sp->curr_msg.hdr->message_opcode;
	op_hdr.data_type = RDR_REPLY;
	op_hdr.status = DCS_SES_ABORTED;

	/* no operation specific data */
	(void) memset(&op_data, 0, sizeof (op_data));

	PRINT_MSG_DBG(DCS_SEND, &op_hdr);

	(void) rdr_snd_msg(sp->fd, &op_hdr, &op_data, DCS_SND_TIMEOUT);

	DCS_DBG(DBG_INFO, "abort_handler: connection closed");

	/* clean up */
	rdr_cleanup_params(op_hdr.message_opcode, sp->curr_msg.params);
	(void) rdr_close(sp->fd);
	(void) ses_free();

	dcs_log_msg(LOG_INFO, DCS_SES_ABORTED);

#ifdef DCS_MULTI_THREAD
	ses_thr_exit();
	thr_exit(0);
#else /* DCS_MULTI_THREAD */
	exit(0);
#endif /* DCS_MULTI_THREAD */
}


#ifndef DCS_MULTI_THREAD

/*
 * exit_handler:
 *
 * If multiple processes are used, this function is used to record
 * the fact that a child process has exited. In order to make sure
 * that all zombie processes are released, a waitpid() is performed
 * for the child that has exited.
 */
/* ARGSUSED */
static void
exit_handler(int sig, siginfo_t *info, void *context)
{
	sessions--;

	if (info != NULL) {
		(void) waitpid(info->si_pid, NULL, 0);
	}
}

#endif /* !DCS_MULTI_THREAD */


/*
 * ses_alloc:
 *
 * Allocate the memory required for the global session structure.
 * If multiple threads are used, create a thread specific data
 * key. This will only occur the first time that this function
 * gets called.
 */
static int
ses_alloc(void)
{
	session_t	*sp;

#ifdef DCS_MULTI_THREAD

	int		thr_err;

	thr_err = thr_keycreate_once(&ses_key, NULL);
	if (thr_err)
		return (-1);

#endif /* DCS_MULTI_THREAD */

	DCS_DBG(DBG_SES, "allocating session memory");

	sp = (session_t *)malloc(sizeof (session_t));

	if (!sp) {
		dcs_log_msg(LOG_ERR, DCS_INT_ERR, "malloc", strerror(errno));
		return (-1);
	}

#ifdef DCS_MULTI_THREAD

	thr_err = thr_setspecific(ses_key, sp);

	return ((thr_err) ? -1 : 0);

#else /* DCS_MULTI_THREAD */

	/* make the data global */
	ses = sp;

	return (0);

#endif /* DCS_MULTI_THREAD */
}


/*
 * ses_free:
 *
 * Deallocate the memory associated with the global session structure.
 */
static int
ses_free(void)
{
	session_t	*sp;


	DCS_DBG(DBG_SES, "freeing session memory");

	if ((sp = curr_ses()) == NULL) {
		ses_close(DCS_ERROR);
		return (-1);
	}

	if (sp) {
		(void) free((void *)sp);
	}

	return (0);
}


#ifdef DCS_MULTI_THREAD

/*
 * ses_thr_exit:
 *
 * If multiple threads are used, this function is used to record the
 * fact that a child thread has exited. In addition, the condition
 * variable is signaled so that the main thread can wakeup and begin
 * accepting connections again.
 */
static void
ses_thr_exit()
{
	mutex_lock(&sessions_lock);

	sessions--;

	cond_signal(&sessions_cv);

	mutex_unlock(&sessions_lock);
}

#endif /* DCS_MULTI_THREAD */
