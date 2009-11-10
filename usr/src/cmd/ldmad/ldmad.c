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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Logical Domains (LDoms) Agents Daemon
 *
 * The LDoms agents daemon (ldmad) runs on LDoms domains and provides
 * information to the control domain. It is composed of a set of agents
 * which can send and receive messages to and from the control domain.
 * Each agent is registered as a domain service using the libds library,
 * and is able to handle requests coming from the control domain.
 *
 * The control domain sends requests to an agent as messages on the
 * corresponding domain service (identified by the agent name). All requests
 * are received by the ldmad daemon which dispatches them to the appropriate
 * handler function of the agent depending on the type of the message.
 *
 * After the request has been processed by the handler, the ldmad daemon sent
 * a reply message back to the control domain. The reply is either a result
 * message if the request was successfully completed, or an error message
 * describing the failure.
 */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <libds.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "ldma.h"

#define	LDMA_MODULE	"ldm-agent-daemon"

#define	LDMA_CONTROL_DOMAIN_DHDL	0	/* id of the control domain */
#define	LDMA_DOMAIN_NAME_MAXLEN		MAXNAMELEN

typedef struct ldma_agent {
	ldma_agent_info_t	*info;		/* agent information */
	ds_hdl_t		conn_hdl;	/* connexion handler */
	ds_ver_t		conn_ver;	/* connexion version */
} ldma_agent_t;

/* information about existing agents */
extern ldma_agent_info_t ldma_device_info;
extern ldma_agent_info_t ldma_system_info;

boolean_t ldma_debug = B_FALSE;
boolean_t ldma_daemon = B_FALSE;

static ldma_agent_info_t *ldma_agent_infos[] = {
	&ldma_device_info,
	&ldma_system_info,
	NULL
};

static char *cmdname;
static pid_t daemon_pid = 0;

/*
 * Allocate a new message with the specified message number (msg_num),
 * message type (msg_type) and message data length (msg_dlen). Return
 * NULL if the allocation has failed.
 */
static ldma_message_header_t *
ldma_alloc_msg(uint64_t msg_num, uint32_t msg_type, size_t msg_dlen)
{
	ldma_message_header_t *msg;
	size_t msg_len;

	msg_len = LDMA_MESSAGE_SIZE(msg_dlen);
	msg = malloc(msg_len);
	if (msg == NULL)
		return (NULL);

	msg->msg_num = msg_num;
	msg->msg_type = msg_type;
	msg->msg_info = 0;

	return (msg);
}

/*
 * Allocate a result message (LDMA_MSG_REQ_RESULT) with the specified message
 * data length (msg_dlen). If the request argument is not NULL then the message
 * is created with the same message number as the request, otherwise the message
 * number is set to 0. Return NULL if the allocation has failed.
 */
ldma_message_header_t *
ldma_alloc_result_msg(ldma_message_header_t *request, size_t msg_dlen)
{
	uint64_t msg_num;

	msg_num = (request == NULL)? 0 : request->msg_num;

	return (ldma_alloc_msg(msg_num, LDMA_MSG_RESULT, msg_dlen));
}

/*
 * Agent register callback. This callback is invoked when a client is registered
 * for using the service provided by an agent. An agent will only have one
 * consumer which is coming from the control domain.
 */
static void
ldma_reg_cb(ds_hdl_t hdl, ds_cb_arg_t arg, ds_ver_t *ver,
    ds_domain_hdl_t dhdl)
{
	ldma_agent_t *agent = (ldma_agent_t *)arg;
	char dname[LDMA_DOMAIN_NAME_MAXLEN];

	if (ds_dom_hdl_to_name(dhdl, dname, LDMA_DOMAIN_NAME_MAXLEN) != 0) {
		(void) strcpy(dname, "<unknown>");
	}

	LDMA_DBG("%s: REGISTER hdl=%llx, dhdl=%llx (%s) ver=%hd.%hd",
	    agent->info->name, hdl, dhdl, dname, ver->major, ver->minor);

	/*
	 * Record client information if the connexion is from the control
	 * domain. The domain service framework only allows connexion of a
	 * domain with the control domain. However, if the agent is running
	 * on the control domain then it can see connexions coming from any
	 * domains. That's why we explicitly have to check if the connexion
	 * is effectively with the control domain.
	 */
	if (dhdl == LDMA_CONTROL_DOMAIN_DHDL) {
		agent->conn_hdl = hdl;
		agent->conn_ver.major = ver->major;
		agent->conn_ver.minor = ver->minor;
	} else {
		LDMA_INFO("agent %s will ignore any request from distrusted "
		    "domain %s", agent->info->name, dname);
	}
}

/*
 * Agent unregister callback. This callback is invoked when a client is
 * unregistered and stops using the service provided by an agent.
 */
static void
ldma_unreg_cb(ds_hdl_t hdl, ds_cb_arg_t arg)
{
	ldma_agent_t *agent = (ldma_agent_t *)arg;

	LDMA_DBG("%s: UNREGISTER hdl=%llx", agent->info->name, hdl);

	if (agent->conn_hdl == hdl) {
		agent->conn_hdl = 0;
		agent->conn_ver.major = 0;
		agent->conn_ver.minor = 0;
	} else {
		LDMA_INFO("agent %s has unregistered consumer from "
		    "distrusted domain", agent->info->name);
	}
}

/*
 * Agent data callback. This callback is invoked when an agent receives a new
 * message from a client. Any request from a client which is not the control
 * domain is immediatly rejected. Otherwise the message is forwarded to the
 * appropriate handler function provided by the agent, depending on the message
 * type.
 */
static void
ldma_data_cb(ds_hdl_t hdl, ds_cb_arg_t arg, void *buf, size_t len)
{
	ldma_agent_t *agent = (ldma_agent_t *)arg;
	ldma_msg_handler_t *handler;
	ldma_message_header_t *request = buf;
	ldma_message_header_t *reply = NULL;
	ldma_request_status_t status;
	size_t request_dlen, reply_len, reply_dlen = 0;
	int i;

	/* check the message size */
	if (len < LDMA_MESSAGE_HEADER_SIZE) {
		LDMA_INFO("agent %s has ignored message with an invalid "
		    "size of %d bytes", agent->info->name, len);
		return;
	}

	request_dlen = LDMA_MESSAGE_DLEN(len);

	LDMA_DBG("%s: DATA hdl=%llx, request num=%llu type=0x%x info=0x%x "
	    "dlen=%d", agent->info->name, hdl, request->msg_num,
	    request->msg_type, request->msg_info, request_dlen);

	/* reject any request which is not from the control domain */
	if (hdl != agent->conn_hdl) {
		LDMA_DBG("%s: DATA hdl=%llx, rejecting request from a "
		    "distrusted domain", agent->info->name, hdl);
		status = LDMA_REQ_DENIED;
		goto do_reply;
	}

	handler = NULL;

	for (i = 0; i < agent->info->nhandlers; i++) {
		if (agent->info->handlers[i].msg_type == request->msg_type) {
			handler = &agent->info->handlers[i];
			break;
		}
	}

	if (handler == NULL) {
		/* this type of message is not defined by the agent */
		LDMA_DBG("%s: DATA hdl=%llx, unknown message type %x",
		    agent->info->name, hdl, request->msg_type);
		status = LDMA_REQ_NOTSUP;
		goto do_reply;
	}

	if (handler->msg_handler == NULL) {
		/*
		 * This type of message is defined by the agent but it
		 * has no handler. That means there is no processing to
		 * do, the message is just ignored, but the request is
		 * successfully completed.
		 */
		LDMA_DBG("%s: DATA hdl=%llx, no handler",
		    agent->info->name, hdl);
		status = LDMA_REQ_COMPLETED;
		goto do_reply;
	}

	/* invoke the message handler of the agent */
	status = (*handler->msg_handler)(&agent->conn_ver, request,
	    request_dlen, &reply, &reply_dlen);

	LDMA_DBG("%s: DATA hdl=%llx, handler stat=%d reply=%p rlen=%d",
	    agent->info->name, hdl, status, (void *)reply, reply_dlen);

do_reply:
	/*
	 * If the handler has provided a reply message, we use it directly.
	 * Otherwise, we build a reply depending on the status of the request.
	 * In that case, we re-use the request buffer to build the reply
	 * message.
	 */
	if (reply == NULL) {

		reply = request;
		reply_dlen = 0;

		if (status == LDMA_REQ_COMPLETED) {
			/*
			 * The request was successful but no result message was
			 * provided so we send an empty result message.
			 */
			reply->msg_type = LDMA_MSG_RESULT;
			reply->msg_info = 0;

		} else {
			/*
			 * The request has failed but no error message was
			 * provided so we send an error message based on the
			 * request status.
			 */
			reply->msg_type = LDMA_MSG_ERROR;
			reply->msg_info =
			    (status == LDMA_REQ_NOTSUP)? LDMA_MSGERR_NOTSUP :
			    (status == LDMA_REQ_INVALID)? LDMA_MSGERR_INVALID :
			    (status == LDMA_REQ_DENIED)? LDMA_MSGERR_DENY :
			    LDMA_MSGERR_FAIL;
		}
	}

	reply_len = LDMA_MESSAGE_SIZE(reply_dlen);

	LDMA_DBG("%s: DATA hdl=%llx, reply num=%llu type=0x%x info=0x%x "
	    "dlen=%d", agent->info->name, hdl, reply->msg_num,
	    reply->msg_type, reply->msg_info, reply_dlen);

	if (ds_send_msg(hdl, reply, reply_len) != 0) {
		LDMA_ERR("agent %s has failed to send reply for request %llu",
		    agent->info->name, request->msg_num);
	}

	if (reply != request)
		free(reply);
}

/*
 * Register an agent. Return 0 if the agent was successfully registered.
 */
static int
ldma_register(ldma_agent_info_t *agent_info)
{
	ldma_agent_t	*agent;
	ds_capability_t	ds_cap;
	ds_ops_t	ds_ops;

	agent = malloc(sizeof (ldma_agent_t));
	if (agent == NULL)
		goto register_fail;

	agent->info = agent_info;
	agent->conn_hdl = 0;
	agent->conn_ver.major = 0;
	agent->conn_ver.minor = 0;

	ds_cap.svc_id = agent_info->name;
	ds_cap.vers = agent_info->vers;
	ds_cap.nvers = agent_info->nvers;

	ds_ops.ds_reg_cb = ldma_reg_cb;
	ds_ops.ds_unreg_cb = ldma_unreg_cb;
	ds_ops.ds_data_cb = ldma_data_cb;
	ds_ops.cb_arg = agent;

	if (ds_svc_reg(&ds_cap, &ds_ops) == 0) {
		LDMA_INFO("agent %s registered", agent_info->name);
		return (0);
	}

register_fail:

	LDMA_ERR("agent %s has failed to register", agent_info->name);
	free(agent);
	return (-1);
}

/*
 * Register all known agents. Return the number of agents successfully
 * registered.
 */
static int
ldma_register_agents()
{
	int count = 0;
	ldma_agent_info_t **agent_infop;

	for (agent_infop = ldma_agent_infos;
	    *agent_infop != NULL; agent_infop++) {

		if (ldma_register(*agent_infop) == 0)
			count++;
	}

	return (count);
}

/*ARGSUSED*/
static void
ldma_sigusr_handler(int sig, siginfo_t *sinfo, void *ucontext)
{
	/*
	 * The child process can send the signal before the fork()
	 * call has returned in the parent process. So daemon_pid
	 * may not be set yet, and we don't check the pid in that
	 * case.
	 */
	if (sig != SIGUSR1 || sinfo->si_code != SI_USER ||
	    (daemon_pid > 0 && sinfo->si_pid != daemon_pid))
		return;

	/*
	 * The parent process has received a USR1 signal from the child.
	 * This means that the daemon has correctly started and the parent
	 * can exit.
	 */
	exit(0);
}

static void
ldma_start(boolean_t standalone)
{
	int stat, rv;
	struct sigaction action;

	if (!standalone) {
		/*
		 * Some configuration of the daemon has to be done in the
		 * child, but we want the parent to report if the daemon
		 * has successfully started or not. So we setup a signal
		 * handler, and the child will notify the parent using the
		 * USR1 signal if the setup was successful. Otherwise the
		 * child will exit.
		 */
		action.sa_sigaction = ldma_sigusr_handler;
		action.sa_flags = SA_SIGINFO;

		if (sigemptyset(&action.sa_mask) == -1) {
			LDMA_ERR("sigemptyset error (%d)", errno);
			exit(1);
		}

		if (sigaction(SIGUSR1, &action, NULL) == -1) {
			LDMA_ERR("sigaction() error (%d)", errno);
			exit(1);
		}

		if (sigrelse(SIGUSR1) == -1) {
			LDMA_ERR("sigrelse() error (%d)", errno);
			exit(1);
		}

		if ((daemon_pid = fork()) == -1) {
			LDMA_ERR("fork() error (%d)", errno);
			exit(1);
		}

		if (daemon_pid != 0) {
			/*
			 * The parent process waits until the child exits (in
			 * case of an error) or sends a USR1 signal (if the
			 * daemon has correctly started).
			 */
			for (;;) {
				rv = waitpid(daemon_pid, &stat, 0);
				if ((rv == daemon_pid && WIFEXITED(stat)) ||
				    (rv == -1 && errno != EINTR)) {
					/* child has exited or error */
					exit(1);
				}
			}
		}

		/*
		 * Initialize child process
		 */
		if (sighold(SIGUSR1) == -1) {
			LDMA_ERR("sighold error (%d)", errno);
			exit(1);
		}

		if (sigignore(SIGUSR1) == -1) {
			LDMA_ERR("sigignore error (%d)", errno);
			exit(1);
		}

		if (setsid() == -1) {
			LDMA_ERR("setsid error (%d)", errno);
			exit(1);
		}

		if (chdir("/") == -1) {
			LDMA_ERR("chdir error (%d)", errno);
			exit(1);
		}
		(void) umask(0);

		/*
		 * Initialize file descriptors. Do not touch stderr
		 * which is initialized by SMF to point to the daemon
		 * specific log file.
		 */
		(void) close(STDIN_FILENO);
		if (open("/dev/null", O_RDWR) == -1) {
			LDMA_ERR("open /dev/null error (%d)", errno);
			exit(1);
		}
		if (dup2(STDIN_FILENO, STDOUT_FILENO) == -1) {
			LDMA_ERR("dup2 error (%d)", errno);
			exit(1);
		}
		closefrom(STDERR_FILENO + 1);

		/* initialize logging */
		openlog(cmdname, LOG_CONS | LOG_NDELAY, LOG_DAEMON);

		ldma_daemon = B_TRUE;
	}

	/*
	 * Register the agents. It would be easier to do this before
	 * daemonizing so that any start error is directly reported. But
	 * this can not be done because agents are registered using libds
	 * and this will subscribe the daemon to some sysevents which is
	 * a process based subscription. Instead we notify the parent process
	 * either by exiting, or by sending a SIGUSR1 signal.
	 */
	if (ldma_register_agents() == 0) {
		/* no agent registered */
		LDMA_ERR("Unable to register any agent");
		exit(1);
	}

	if (!standalone) {
		/* signal parent that startup was successful */
		if (kill(getppid(), SIGUSR1) == -1)
			exit(1);
	}
}

static void
ldma_usage()
{
	(void) fprintf(stderr, "usage: %s\n", cmdname);
}

int
main(int argc, char *argv[])
{
	int opt;
	boolean_t standalone = B_FALSE;

	cmdname = basename(argv[0]);

	/* disable getopt error messages */
	opterr = 0;

	while ((opt = getopt(argc, argv, "ds")) != EOF) {

		switch (opt) {
		case 'd':
			ldma_debug = B_TRUE;
			break;
		case 's':
			standalone = B_TRUE;
			break;
		default:
			ldma_usage();
			exit(1);
		}
	}

	ldma_start(standalone);

	/*
	 * Loop forever. Any incoming message will be received by libds and
	 * forwarded to the agent data callback (ldma_data_cb()) where it
	 * will be processed.
	 */
	for (;;) {
		(void) pause();
	}

	/*NOTREACHED*/
	return (0);
}
