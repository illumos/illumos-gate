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

#include <sys/types.h>
#include <sys/ctfs.h>
#include <sys/contract/process.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhcpagent_ipc.h"
#include "dhcpagent_util.h"

/*
 * Strings returned by dhcp_status_hdr_string() and
 * dhcp_status_reply_to_string(). The first define is the header line, and
 * the second defines line printed underneath.
 * The spacing of fields must match.
 */
#define	DHCP_STATUS_HDR	"Interface  State         Sent  Recv  Declined  Flags\n"
#define	DHCP_STATUS_STR	"%-10s %-12s %5d %5d %9d  "

static const char *time_to_string(time_t abs_time);

/*
 * dhcp_state_to_string(): given a state, provides the state's name
 *
 *    input: DHCPSTATE: the state to get the name of
 *   output: const char *: the state's name
 */

const char *
dhcp_state_to_string(DHCPSTATE state)
{
	const char *states[] = {
		"INIT",
		"SELECTING",
		"REQUESTING",
		"PRE_BOUND",
		"BOUND",
		"RENEWING",
		"REBINDING",
		"INFORMATION",
		"INIT_REBOOT",
		"ADOPTING",
		"INFORM_SENT",
		"DECLINING",
		"RELEASING"
	};

	if (state < 0 || state >= DHCP_NSTATES)
		return ("<unknown>");

	return (states[state]);
}

static int
init_template(void)
{
	int fd;
	int err = 0;

	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		return (-1);

	/*
	 * Deliver no events, don't inherit, and allow it to be orphaned.
	 */
	err |= ct_tmpl_set_critical(fd, 0);
	err |= ct_tmpl_set_informative(fd, 0);
	err |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	err |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (err != 0 || ct_tmpl_activate(fd) != 0) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * dhcp_start_agent(): starts the agent if not already running
 *
 *   input: int: number of seconds to wait for agent to start (-1 is forever)
 *  output: int: 0 on success, -1 on failure
 */

int
dhcp_start_agent(int timeout)
{
	int			error;
	time_t			start_time = time(NULL);
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply;
	int			ctfd;
	pid_t			childpid;
	ctid_t			ct;

	/*
	 * just send a dummy request to the agent to find out if it's
	 * up.  we do this instead of directly connecting to it since
	 * we want to make sure we follow its IPC conventions
	 * (otherwise, it will log warnings to syslog).
	 */

	request = dhcp_ipc_alloc_request(DHCP_PING, "", NULL, 0,
	    DHCP_TYPE_NONE);
	if (request == NULL)
		return (-1);

	error = dhcp_ipc_make_request(request, &reply, 0);
	if (error == 0) {
		free(reply);
		free(request);
		return (0);
	}
	if (error != DHCP_IPC_E_CONNECT)
		goto fail;

	if ((ctfd = init_template()) == -1)
		goto fail;

	childpid = fork();

	(void) ct_tmpl_clear(ctfd);
	(void) close(ctfd);

	switch (childpid) {
	case -1:
		goto fail;

	case  0:
		(void) execl(DHCP_AGENT_PATH, DHCP_AGENT_PATH, (char *)0);
		_exit(EXIT_FAILURE);

	default:
		break;
	}

	/* wait for the daemon to run and then abandon the contract */
	(void) waitpid(childpid, NULL, 0);

	if (contract_latest(&ct) != -1)
		(void) contract_abandon_id(ct);

	while ((timeout != -1) && (time(NULL) - start_time < timeout)) {
		error = dhcp_ipc_make_request(request, &reply, 0);
		if (error == 0) {
			free(reply);
			free(request);
			return (0);
		} else if (error != DHCP_IPC_E_CONNECT)
			break;
		(void) sleep(1);
	}

fail:
	free(request);
	return (-1);
}

/*
 * dhcp_status_hdr_string(): Return a string suitable to use as the header
 *			     when printing DHCP_STATUS reply.
 *  output: const char *: newline terminated printable string
 */
const char *
dhcp_status_hdr_string(void)
{
	return (DHCP_STATUS_HDR);
}

/*
 * time_to_string(): Utility routine for printing time
 *
 *   input: time_t *: time_t to stringify
 *  output: const char *: printable time
 */
static const char *
time_to_string(time_t abs_time)
{
	static char time_buf[24];
	time_t tm = abs_time;

	if (tm == DHCP_PERM)
		return ("Never");

	if (strftime(time_buf, sizeof (time_buf), "%m/%d/%Y %R",
	    localtime(&tm)) == 0)
		return ("<unknown>");

	return (time_buf);
}

/*
 * dhcp_status_reply_to_string(): Return DHCP IPC reply of type DHCP_STATUS
 *				  as a printable string
 *
 *   input: dhcp_reply_t *: contains the status structure to print
 *  output: const char *: newline terminated printable string
 */
const char *
dhcp_status_reply_to_string(dhcp_ipc_reply_t *reply)
{
	static char str[1024];
	size_t reply_size;
	dhcp_status_t *status;

	status = dhcp_ipc_get_data(reply, &reply_size, NULL);
	if (reply_size < DHCP_STATUS_VER1_SIZE)
		return ("<Internal error: status msg size>\n");

	(void) snprintf(str, sizeof (str), DHCP_STATUS_STR,
	    status->if_name, dhcp_state_to_string(status->if_state),
	    status->if_sent, status->if_recv, status->if_bad_offers);

	if (status->if_dflags & DHCP_IF_PRIMARY)
		(void) strlcat(str, "[PRIMARY] ", sizeof (str));

	if (status->if_dflags & DHCP_IF_BOOTP)
		(void) strlcat(str, "[BOOTP] ", sizeof (str));

	if (status->if_dflags & DHCP_IF_FAILED)
		(void) strlcat(str, "[FAILED] ", sizeof (str));

	if (status->if_dflags & DHCP_IF_BUSY)
		(void) strlcat(str, "[BUSY] ", sizeof (str));

	if (status->if_dflags & DHCP_IF_V6)
		(void) strlcat(str, "[V6] ", sizeof (str));

	(void) strlcat(str, "\n", sizeof (str));

	switch (status->if_state) {
	case BOUND:
	case RENEWING:
	case REBINDING:
		break;
	default:
		return (str);
	}

	(void) strlcat(str, "(Began, Expires, Renew) = (", sizeof (str));
	(void) strlcat(str, time_to_string(status->if_began), sizeof (str));
	(void) strlcat(str, ", ", sizeof (str));
	(void) strlcat(str, time_to_string(status->if_lease), sizeof (str));
	(void) strlcat(str, ", ", sizeof (str));
	(void) strlcat(str, time_to_string(status->if_t1), sizeof (str));
	(void) strlcat(str, ")\n", sizeof (str));
	return (str);
}
