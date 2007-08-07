/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: mipagentsnmp_appl.c
 *
 * This file contains the main SNMP routines used for
 * initialization and shutdown.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <syslog.h>

#include <impl.h>
#include <pagent.h>

#include "snmp_stub.h"
#include "mip.h"

/* GLOBAL VARIABLES */

#ifndef lint
char default_config_file[] = "/etc/snmp/conf/mipagent.reg";
char default_sec_config_file[] = "/etc/snmp/conf/mipagent.acl";
char default_error_file[] = "/var/snmp/mipagent.log";
#endif

static 	pthread_t snmpThreadId = 0;

typedef struct {
	int argc;
	char *argv;
} StartupArgs;

static void mipagent_snmp_thread(StartupArgs *args);

#define	DEFAULT_SNMP_PORT	161

extern ipaddr_t subagent_addr; /* this was set in setup.c */

extern int SSASubagentOpen(int, char *);
extern int SSARegSubagent(Agent *);
extern int SSAMain(int, char **);

/*
 * Function: register_with_master
 *
 * Arguments:	subagent_addr - Sub-Agent Address
 *
 * Description: This function will register the SNMP
 *		sub-agent with the master SNMP agent.
 *
 * Returns: int, 0 if successful
 */
static int
/* LINTED E_FUNC_ARG_UNUSED */
register_with_master(ipaddr_t subagent_addr)
{
	/* LINTED E_FUNC_VAR_UNUSED */
	Agent subagent;

	return (0);

#if 0
	/* NOTREACHED */

	agentid = SSASubagentOpen(0, "mipagent");
	(void) memset(&subagent, 0, sizeof (Agent));
	subagent.agent_id = agentid;

	/*
	 * Tell master we are ready
	 */
	subagent.agent_status = SSA_OPER_STATUS_ACTIVE;
	subagent.address.sin_family = AF_INET;
	subagent.address.sin_port = DEFAULT_SNMP_PORT;
	subagent.address.sin_addr.s_addr = subagent_addr;
	if ((SSARegSubagent(&subagent)) == 0) {
		return (-1);
	}
	return (0);
#endif
}

/*
 * Function: deregister_with_master
 *
 * Arguments:	subagent_addr - Sub-Agent Address
 *
 * Description: This function will inform the
 *		SNMP Master agent that we are
 *		going away.
 *
 * Returns: int, 0 if successful
 */
static int
/* LINTED E_FUNC_ARG_UNUSED */
deregister_with_master(ipaddr_t subagent_addr)
{
	/* LINTED E_FUNC_VAR_UNUSED */
	Agent subagent;

	return (0);
#if 0
	/* NOTREACHED */

	if (agentid) {
		(void) memset(&subagent, 0, sizeof (Agent));
		subagent.agent_id = agentid;

		/*
		 * Tell master we are going away
		 */
		subagent.agent_status = SSA_OPER_STATUS_DESTROY;
		subagent.address.sin_family = AF_INET;
		subagent.address.sin_port = DEFAULT_SNMP_PORT;
		subagent.address.sin_addr.s_addr = subagent_addr;
		if ((SSARegSubagent(&subagent)) == 0) {
			return (-1);
		}

		agentid = 0;
	}
	return (0);
#endif
}

#ifndef lint
/*
 * Function: agent_init
 *
 * Arguments:
 *
 * Description: Stub provided for the SNMP Sub-Agent
 *		initialization. We do not have anything
 *		to do here.
 *
 * Returns:
 */
void
agent_init()
{
}


/*
 * Function: agent_end
 *
 * Arguments:
 *
 * Description: Stub provided for the SNMP Sub-Agent
 *		shutdown. We do not have anything
 *		to do here.
 *
 * Returns:
 */
void
agent_end()
{
}


/*
 * Function: agent_loop
 *
 * Arguments:
 *
 * Description: The SNMP Loop function, which is
 *		provided because the sub-agent needs it.
 *
 * Returns:
 */
void
agent_loop()
{
}


/*
 * Function: agent_select_info
 *
 * Arguments:	fdset - File Descriptor set
 *		numfds - number of file descriptors
 *
 * Description: Another stub provided for the SNMP
 *		sub-agent.
 *
 * Returns:
 */
/* ARGSUSED */
void
agent_select_info(fd_set *fdset, int *numfds)
{
}


/*
 * Function: agent_select_callback
 *
 * Arguments:	fdset - File Descriptor set
 *
 * Description: Callback routine for the SNMP Sub-Agent,
 *		which we are providing as a stub.
 *
 * Returns:
 */
/* ARGSUSED */
void
agent_select_callback(fd_set *fdset)
{
}
#endif
/*
 * Function: startSNMPTaskThread
 *
 * Arguments: none
 *
 * Description: This function will start the SNMP
 *		sub-agent thread, and register with
 *		the Master SNMP thread.
 *
 * Returns: int, 0 if successful
 */
int
startSNMPTaskThread(void)
{
	StartupArgs *args;
	static char *all_args[3];
	static char arg0[] = "mipagent";
	static char arg1[] = "-d";
	static char arg2[] = "1";
	pthread_attr_t pthreadAttribute;
	int result;

	result = pthread_attr_init(&pthreadAttribute);
	if (result) {
		syslog(LOG_CRIT, "Error Initializing pthread.");
		return (-1);
	}

	args = (StartupArgs *) malloc(sizeof (StartupArgs));
	if (args == NULL) {
		syslog(LOG_CRIT, "Unable to allocate memory.");
		return (-1);
	}

	/*
	 * Call the SSAMain() with "-d 1" argument, so that it doesn't
	 * daemonize the process. "-d 1" attempts to generate debug output.
	 * When mipagent is daemonized, since the stdout is closed, this
	 * will have no effect. When mipagent is not deamonized for debugging
	 * purposes, this will generate useful debug info for SNMP.
	 */
	all_args[0] = (char *)arg0;
	all_args[1] = (char *)arg1;
	all_args[2] = (char *)arg2;

	args->argc = 3;
	args->argv = (char *)all_args;

	/*
	 * The thread is then started  It is mandatory that all
	 * applications have a slaveThread() function declared,
	 * which will be called with the TCB.
	 */
	result = pthread_create(&snmpThreadId, &pthreadAttribute,
	    (void *(*)()) mipagent_snmp_thread,
	    (void *)args);

	if (result) {
		syslog(LOG_CRIT, "pthread_create() failed.");
		free(args);
		return (-1);
	}

	/*
	 * In order for system resources the be properly cleaned up,
	 * we need to detach the thread. Otherwise, we need to wait for
	 * a pthread_join(), which we do not want.
	 */
	result = pthread_detach(snmpThreadId);

	if (result) {
		syslog(LOG_CRIT, "pthread_detach() failed.");
		free(args);
		return (-1);
	}

	return (0);

}

/*
 * Function: killSNMPTaskThread
 *
 * Arguments:
 *
 * Description: This function is used to shutdown the
 *		SNMP Sub-Agent thread.
 *
 * Returns:
 */
int
killSNMPTaskThread()
{
	int result;

	if (snmpThreadId) {
		if (deregister_with_master(subagent_addr)) {
			syslog(LOG_CRIT, "Unable to deregister with sub-agent");
		}

		/*
		 * Next we need to kill the dispatching thread.
		 */
		result = pthread_cancel(snmpThreadId);

		if (result) {
			/*
			 * Well, there's not much we can do here..
			 */
			syslog(LOG_CRIT, "Unable to kill snmp thread");
		}
	}

	return (0);
}

/*
 * Function: mipagent_snmp_thread
 *
 * Arguments:	args - Command Line Arguments
 *
 * Description: This function is the main SNMP Sub-Agent
 *		thread. The function will call SSAMain, which
 *		never returns (unless an error occured).
 *
 *		This thread will remain active until either
 *		the SNMP Sub-Agent main routines returns or
 *		the killSNMPTaskThread() function is called.
 *
 * Returns:
 */
static void
mipagent_snmp_thread(StartupArgs *args)
{
	int argc;
	int result;
	char **argv;

	/*
	 * Register ourselves as a sub-agent with the master SNMP
	 * agent.
	 */
	result = register_with_master(subagent_addr);

	if (result) {
		syslog(LOG_CRIT, "Could not register with master SNMP agent.");
		free(args);
		pthread_exit(NULL);
	}

	/*
	 * Let's do the SSAMain thingy... Note that this function should,
	 * in theory, never return. This function will interface with the
	 * SNMP Master Agent.
	 */
	argc = args->argc;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	argv = (char **)args->argv;

	SSAMain(argc, argv);

	free(args);

	if (deregister_with_master(subagent_addr)) {
		syslog(LOG_CRIT, "Unable to deregister with sub-agent");
	}

	pthread_exit(NULL);
}
