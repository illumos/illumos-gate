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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <dhcp_hostconf.h>
#include <dhcp_symbol.h>
#include <dhcpagent_ipc.h>
#include <dhcpmsg.h>
#include <netinet/dhcp.h>

#include "async.h"
#include "agent.h"
#include "script_handler.h"
#include "util.h"
#include "class_id.h"
#include "states.h"
#include "packet.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

iu_timer_id_t		inactivity_id;
int			class_id_len = 0;
char			*class_id;
iu_eh_t			*eh;
iu_tq_t			*tq;
pid_t			grandparent;

static boolean_t	shutdown_started = B_FALSE;
static boolean_t	do_adopt = B_FALSE;
static unsigned int	debug_level = 0;
static iu_eh_callback_t	accept_event, ipc_event;

/*
 * The ipc_cmd_allowed[] table indicates which IPC commands are allowed in
 * which states; a non-zero value indicates the command is permitted.
 *
 * START is permitted if the interface is fresh, or if we are in the process
 * of trying to obtain a lease (as a convenience to save the administrator
 * from having to do an explicit DROP).  EXTEND, RELEASE, and GET_TAG require
 * a lease to be obtained in order to make sense.  INFORM is permitted if the
 * interface is fresh or has an INFORM in progress or previously done on it --
 * otherwise a DROP or RELEASE is first required.  PING and STATUS always make
 * sense and thus are always permitted, as is DROP in order to permit the
 * administrator to always bail out.
 */
static int ipc_cmd_allowed[DHCP_NSTATES][DHCP_NIPC] = {
	/*			  D  E	P  R  S	 S  I  G */
	/*			  R  X	I  E  T	 T  N  E */
	/*			  O  T	N  L  A	 A  F  T */
	/*			  P  E	G  E  R	 T  O  _ */
	/*			  .  N  .  A  T  U  R  T */
	/*			  .  D	.  S  .  S  M  A */
	/*			  .  .  .  E  .  .  .  G */
	/* INIT		*/	{ 1, 0, 1, 0, 1, 1, 1, 0 },
	/* SELECTING	*/	{ 1, 0, 1, 0, 1, 1, 0, 0 },
	/* REQUESTING	*/	{ 1, 0, 1, 0, 1, 1, 0, 0 },
	/* BOUND	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* RENEWING	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* REBINDING	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* INFORMATION  */	{ 1, 0, 1, 0, 0, 1, 1, 1 },
	/* INIT_REBOOT  */	{ 1, 0, 1, 0, 1, 1, 0, 0 },
	/* ADOPTING	*/	{ 1, 0, 1, 0, 0, 1, 0, 0 },
	/* INFORM_SENT  */	{ 1, 0, 1, 0, 0, 1, 1, 0 }
};

int
main(int argc, char **argv)
{
	boolean_t	is_daemon  = B_TRUE;
	boolean_t	is_verbose = B_FALSE;
	int		ipc_fd;
	int		c;
	struct rlimit	rl;

	/*
	 * -l is ignored for compatibility with old agent.
	 */

	while ((c = getopt(argc, argv, "vd:l:fa")) != EOF) {

		switch (c) {

		case 'a':
			do_adopt = B_TRUE;
			grandparent = getpid();
			break;

		case 'd':
			debug_level = strtoul(optarg, NULL, 0);
			break;

		case 'f':
			is_daemon = B_FALSE;
			break;

		case 'v':
			is_verbose = B_TRUE;
			break;

		case '?':
			(void) fprintf(stderr, "usage: %s [-a] [-d n] [-f] [-v]"
			    "\n", argv[0]);
			return (EXIT_FAILURE);

		default:
			break;
		}
	}

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (geteuid() != 0) {
		dhcpmsg_init(argv[0], B_FALSE, is_verbose, debug_level);
		dhcpmsg(MSG_ERROR, "must be super-user");
		dhcpmsg_fini();
		return (EXIT_FAILURE);
	}

	if (is_daemon && daemonize() == 0) {
		dhcpmsg_init(argv[0], B_FALSE, is_verbose, debug_level);
		dhcpmsg(MSG_ERR, "cannot become daemon, exiting");
		dhcpmsg_fini();
		return (EXIT_FAILURE);
	}

	dhcpmsg_init(argv[0], is_daemon, is_verbose, debug_level);
	(void) atexit(dhcpmsg_fini);

	tq = iu_tq_create();
	eh = iu_eh_create();

	if (eh == NULL || tq == NULL) {
		errno = ENOMEM;
		dhcpmsg(MSG_ERR, "cannot create timer queue or event handler");
		return (EXIT_FAILURE);
	}

	/*
	 * ignore most signals that could be reasonably generated.
	 */

	(void) signal(SIGTERM, graceful_shutdown);
	(void) signal(SIGQUIT, graceful_shutdown);
	(void) signal(SIGPIPE, SIG_IGN);
	(void) signal(SIGUSR1, SIG_IGN);
	(void) signal(SIGUSR2, SIG_IGN);
	(void) signal(SIGINT,  SIG_IGN);
	(void) signal(SIGHUP,  SIG_IGN);
	(void) signal(SIGCHLD, SIG_IGN);

	/*
	 * upon SIGTHAW we need to refresh any non-infinite leases.
	 */

	(void) iu_eh_register_signal(eh, SIGTHAW, refresh_ifslist, NULL);

	class_id = get_class_id();
	if (class_id != NULL)
		class_id_len = strlen(class_id);
	else
		dhcpmsg(MSG_WARNING, "get_class_id failed, continuing "
		    "with no vendor class id");

	/*
	 * the inactivity timer is enabled any time there are no
	 * interfaces under DHCP control.  if DHCP_INACTIVITY_WAIT
	 * seconds transpire without an interface under DHCP control,
	 * the agent shuts down.
	 */

	inactivity_id = iu_schedule_timer(tq, DHCP_INACTIVITY_WAIT,
	    inactivity_shutdown, NULL);

	/*
	 * max out the number available descriptors, just in case..
	 */

	rl.rlim_cur = RLIM_INFINITY;
	rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		dhcpmsg(MSG_ERR, "setrlimit failed");

	/*
	 * create the ipc channel that the agent will listen for
	 * requests on, and register it with the event handler so that
	 * `accept_event' will be called back.
	 */

	switch (dhcp_ipc_init(&ipc_fd)) {

	case 0:
		break;

	case DHCP_IPC_E_BIND:
		dhcpmsg(MSG_ERROR, "dhcp_ipc_init: cannot bind to port "
		    "%i (agent already running?)", IPPORT_DHCPAGENT);
		return (EXIT_FAILURE);

	default:
		dhcpmsg(MSG_ERROR, "dhcp_ipc_init failed");
		return (EXIT_FAILURE);
	}

	if (iu_register_event(eh, ipc_fd, POLLIN, accept_event, 0) == -1) {
		dhcpmsg(MSG_ERR, "cannot register ipc fd for messages");
		return (EXIT_FAILURE);
	}

	/*
	 * if the -a (adopt) option was specified, try to adopt the
	 * kernel-managed interface before we start. Our grandparent
	 * will be waiting for us to finish this, so signal him when
	 * we're done.
	 */

	if (do_adopt) {
		int result;

		result = dhcp_adopt();

		if (grandparent != (pid_t)0) {
			dhcpmsg(MSG_DEBUG, "adoption complete, signalling "
			    "parent (%i) to exit.", grandparent);
			(void) kill(grandparent, SIGALRM);
		}

		if (result == 0)
			return (EXIT_FAILURE);
	}

	/*
	 * enter the main event loop; this is where all the real work
	 * takes place (through registering events and scheduling timers).
	 * this function only returns when the agent is shutting down.
	 */

	switch (iu_handle_events(eh, tq)) {

	case -1:
		dhcpmsg(MSG_WARNING, "iu_handle_events exited abnormally");
		break;

	case DHCP_REASON_INACTIVITY:
		dhcpmsg(MSG_INFO, "no interfaces to manage, shutting down...");
		break;

	case DHCP_REASON_TERMINATE:
		dhcpmsg(MSG_INFO, "received SIGTERM, shutting down...");
		break;

	case DHCP_REASON_SIGNAL:
		dhcpmsg(MSG_WARNING, "received unexpected signal, shutting "
		    "down...");
		break;
	}

	(void) iu_eh_unregister_signal(eh, SIGTHAW, NULL);

	iu_eh_destroy(eh);
	iu_tq_destroy(tq);

	return (EXIT_SUCCESS);
}

/*
 * drain_script(): event loop callback during shutdown
 *
 *   input: eh_t *: unused
 *	    void *: unused
 *  output: boolean_t: B_TRUE if event loop should exit; B_FALSE otherwise
 */

/* ARGSUSED */
boolean_t
drain_script(iu_eh_t *ehp, void *arg)
{
	if (shutdown_started == B_FALSE) {
		shutdown_started = B_TRUE;
		if (do_adopt == B_FALSE)	/* see 4291141 */
			nuke_ifslist(B_TRUE);
	}
	return (script_count == 0);
}

/*
 * accept_event(): accepts a new connection on the ipc socket and registers
 *		   to receive its messages with the event handler
 *
 *   input: iu_eh_t *: unused
 *	    int: the file descriptor in the iu_eh_t * the connection came in on
 *	    (other arguments unused)
 *  output: void
 */

/* ARGSUSED */
static void
accept_event(iu_eh_t *ehp, int fd, short events, iu_event_id_t id, void *arg)
{
	int	client_fd;
	int	is_priv;

	if (dhcp_ipc_accept(fd, &client_fd, &is_priv) != 0) {
		dhcpmsg(MSG_ERR, "accept_event: accept on ipc socket");
		return;
	}

	if (iu_register_event(eh, client_fd, POLLIN, ipc_event,
	    (void *)is_priv) == -1) {
		dhcpmsg(MSG_ERROR, "accept_event: cannot register ipc socket "
		    "for callback");
	}
}

/*
 * ipc_event(): processes incoming ipc requests
 *
 *   input: iu_eh_t *: unused
 *	    int: the file descriptor in the iu_eh_t * the request came in on
 *	    short: unused
 *	    iu_event_id_t: unused
 *	    void *: indicates whether the request is from a privileged client
 *  output: void
 */

/* ARGSUSED */
static void
ipc_event(iu_eh_t *ehp, int fd, short events, iu_event_id_t id, void *arg)
{
	dhcp_ipc_request_t	*request;
	struct ifslist		*ifsp, *primary_ifsp;
	int			error, is_priv = (int)arg;
	PKT_LIST 		*plp[2];
	dhcp_ipc_type_t		cmd;

	(void) iu_unregister_event(eh, id, NULL);

	if (dhcp_ipc_recv_request(fd, &request, DHCP_IPC_REQUEST_WAIT) != 0) {
		dhcpmsg(MSG_ERROR, "ipc_event: dhcp_ipc_recv_request failed");
		(void) dhcp_ipc_close(fd);
		return;
	}

	cmd = DHCP_IPC_CMD(request->message_type);
	if (cmd >= DHCP_NIPC) {
		send_error_reply(request, DHCP_IPC_E_CMD_UNKNOWN, &fd);
		return;
	}

	/* return EPERM for any of the privileged actions */

	if (!is_priv) {
		switch (cmd) {

		case DHCP_STATUS:
		case DHCP_PING:
		case DHCP_GET_TAG:
			break;

		default:
			dhcpmsg(MSG_WARNING, "ipc_event: privileged ipc "
			    "command (%i) attempted on %s", cmd,
			    request->ifname);

			send_error_reply(request, DHCP_IPC_E_PERM, &fd);
			return;
		}
	}

	/*
	 * try to locate the ifs associated with this command.  if the
	 * command is DHCP_START or DHCP_INFORM, then if there isn't
	 * an ifs already, make one (there may already be one from a
	 * previous failed attempt to START or INFORM).  otherwise,
	 * verify the interface is still valid.
	 */

	ifsp = lookup_ifs(request->ifname);

	switch (cmd) {

	case DHCP_START:			/* FALLTHRU */
	case DHCP_INFORM:
		/*
		 * it's possible that the interface already exists, but
		 * has been abandoned.  usually in those cases we should
		 * return DHCP_IPC_E_UNKIF, but that makes little sense
		 * in the case of "start" or "inform", so just ignore
		 * the abandoned interface and start over anew.
		 */

		if (ifsp != NULL && verify_ifs(ifsp) == 0)
			ifsp = NULL;

		/*
		 * as part of initializing the ifs, insert_ifs()
		 * creates a DLPI stream at ifsp->if_dlpi_fd.
		 */

		if (ifsp == NULL) {
			ifsp = insert_ifs(request->ifname, B_FALSE, &error);
			if (ifsp == NULL) {
				send_error_reply(request, error, &fd);
				return;
			}
		}
		break;

	default:
		if (ifsp == NULL) {
			if (request->ifname[0] == '\0')
				error = DHCP_IPC_E_NOPRIMARY;
			else
				error = DHCP_IPC_E_UNKIF;

			send_error_reply(request, error, &fd);
			return;
		}
		break;
	}

	if (verify_ifs(ifsp) == 0) {
		send_error_reply(request, DHCP_IPC_E_UNKIF, &fd);
		return;
	}

	if (ifsp->if_dflags & DHCP_IF_BOOTP) {
		switch (cmd) {

		case DHCP_EXTEND:
		case DHCP_RELEASE:
		case DHCP_INFORM:
			send_error_reply(request, DHCP_IPC_E_BOOTP, &fd);
			return;

		default:
			break;
		}
	}

	/*
	 * verify that the interface is in a state which will allow the
	 * command.  we do this up front so that we can return an error
	 * *before* needlessly cancelling an in-progress transaction.
	 */

	if (!ipc_cmd_allowed[ifsp->if_state][cmd]) {
		send_error_reply(request, DHCP_IPC_E_OUTSTATE, &fd);
		return;
	}

	if ((request->message_type & DHCP_PRIMARY) && is_priv) {
		if ((primary_ifsp = lookup_ifs("")) != NULL)
			primary_ifsp->if_dflags &= ~DHCP_IF_PRIMARY;
		ifsp->if_dflags |= DHCP_IF_PRIMARY;
	}

	/*
	 * current design dictates that there can be only one
	 * outstanding transaction per interface -- this simplifies
	 * the code considerably and also fits well with RFC2131.
	 * it is worth classifying the different DHCP commands into
	 * synchronous (those which we will handle now and be done
	 * with) and asynchronous (those which require transactions
	 * and will be completed at an indeterminate time in the
	 * future):
	 *
	 *    DROP: removes the agent's management of an interface.
	 *	    asynchronous as the script program may be invoked.
	 *
	 *    PING: checks to see if the agent controls an interface.
	 *	    synchronous, since no packets need to be sent
	 *	    to the DHCP server.
	 *
	 *  STATUS: returns information about the an interface.
	 *	    synchronous, since no packets need to be sent
	 *	    to the DHCP server.
	 *
	 * RELEASE: releases the agent's management of an interface
	 *	    and brings the interface down.  asynchronous as
	 *	    the script program may be invoked.
	 *
	 *  EXTEND: renews a lease.  asynchronous, since the agent
	 *	    needs to wait for an ACK, etc.
	 *
	 *   START: starts DHCP on an interface.  asynchronous since
	 *	    the agent needs to wait for OFFERs, ACKs, etc.
	 *
	 *  INFORM: obtains configuration parameters for an externally
	 *	    configured interface.  asynchronous, since the
	 *	    agent needs to wait for an ACK.
	 *
	 * notice that EXTEND, INFORM, START, DROP and RELEASE are
	 * asynchronous. notice also that asynchronous commands may
	 * occur from within the agent -- for instance, the agent
	 * will need to do implicit EXTENDs to extend the lease. in
	 * order to make the code simpler, the following rules apply
	 * for asynchronous commands:
	 *
	 * there can only be one asynchronous command at a time per
	 * interface.  the current asynchronous command is managed by
	 * the async_* api: async_start(), async_finish(),
	 * async_timeout(), async_cancel(), and async_pending().
	 * async_start() starts management of a new asynchronous
	 * command on an interface, which should only be done after
	 * async_pending() is called to check that there are no
	 * pending asynchronous commands on that interface.  when the
	 * command is completed, async_finish() should be called.  all
	 * asynchronous commands have an associated timer, which calls
	 * async_timeout() when it times out.  if async_timeout()
	 * decides that the asynchronous command should be cancelled
	 * (see below), it calls async_cancel() to attempt
	 * cancellation.
	 *
	 * asynchronous commands started by a user command have an
	 * associated ipc_action which provides the agent with
	 * information for how to get in touch with the user command
	 * when the action completes.  these ipc_action records also
	 * have an associated timeout which may be infinite.
	 * ipc_action_start() should be called when starting an
	 * asynchronous command requested by a user, which sets up the
	 * timer and keeps track of the ipc information (file
	 * descriptor, request type).  when the asynchronous command
	 * completes, ipc_action_finish() should be called to return a
	 * command status code to the user and close the ipc
	 * connection).  if the command does not complete before the
	 * timer fires, ipc_action_timeout() is called which closes
	 * the ipc connection and returns DHCP_IPC_E_TIMEOUT to the
	 * user.  note that independent of ipc_action_timeout(),
	 * ipc_action_finish() should be called.
	 *
	 * on a case-by-case basis, here is what happens (per interface):
	 *
	 *    o when an asynchronous command is requested, then
	 *	async_pending() is called to see if there is already
	 *	an asynchronous event.  if so, the command does not
	 *	proceed, and if there is an associated ipc_action,
	 *	the user command is sent DHCP_IPC_E_PEND.
	 *
	 *    o otherwise, the the transaction is started with
	 *	async_start().  if the transaction is on behalf
	 *	of a user, ipc_action_start() is called to keep
	 *	track of the ipc information and set up the
	 *	ipc_action timer.
	 *
	 *    o if the command completes normally and before a
	 *	timeout fires, then async_finish() is called.
	 *	if there was an associated ipc_action,
	 *	ipc_action_finish() is called to complete it.
	 *
	 *    o if the command fails before a timeout fires, then
	 *	async_finish() is called, and the interface is
	 *	is returned to a known state based on the command.
	 *	if there was an associated ipc_action,
	 *	ipc_action_finish() is called to complete it.
	 *
	 *    o if the ipc_action timer fires before command
	 *	completion, then DHCP_IPC_E_TIMEOUT is returned to
	 *	the user.  however, the transaction continues to
	 *	be carried out asynchronously.
	 *
	 *    o if async_timeout() fires before command completion,
	 *	then if the command was internal to the agent, it
	 *	is cancelled.  otherwise, if it was a user command,
	 *	then if the user is still waiting for the command
	 *	to complete, the command continues and async_timeout()
	 *	is rescheduled.
	 */

	switch (cmd) {

	case DHCP_DROP:					/* FALLTHRU */
	case DHCP_RELEASE:				/* FALLTHRU */
	case DHCP_EXTEND:				/* FALLTHRU */
	case DHCP_INFORM:				/* FALLTHRU */
	case DHCP_START:
		/*
		 * if shutdown request has been received, send back an error.
		 */
		if (shutdown_started) {
			send_error_reply(request, DHCP_IPC_E_OUTSTATE, &fd);
			return;
		}

		if (async_pending(ifsp)) {
			send_error_reply(request, DHCP_IPC_E_PEND, &fd);
			return;
		}

		if (ipc_action_start(ifsp, request, fd) == 0) {
			dhcpmsg(MSG_WARNING, "ipc_event: ipc_action_start "
			    "failed for %s", ifsp->if_name);
			send_error_reply(request, DHCP_IPC_E_MEMORY, &fd);
			return;
		}

		if (async_start(ifsp, cmd, B_TRUE) == 0) {
			ipc_action_finish(ifsp, DHCP_IPC_E_MEMORY);
			return;
		}
		break;

	default:
		break;
	}

	switch (cmd) {

	case DHCP_DROP:
		(void) script_start(ifsp, EVENT_DROP, dhcp_drop, NULL, NULL);
		return;

	case DHCP_EXTEND:
		(void) dhcp_extending(ifsp);
		break;

	case DHCP_GET_TAG: {
		dhcp_optnum_t	optnum;
		DHCP_OPT	*opt = NULL;
		boolean_t	did_alloc = B_FALSE;
		PKT_LIST	*ack = ifsp->if_ack;

		/*
		 * verify the request makes sense.
		 */

		if (request->data_type   != DHCP_TYPE_OPTNUM ||
		    request->data_length != sizeof (dhcp_optnum_t)) {
			send_error_reply(request, DHCP_IPC_E_PROTO, &fd);
			return;
		}

		(void) memcpy(&optnum, request->buffer, sizeof (dhcp_optnum_t));
load_option:
		switch (optnum.category) {

		case DSYM_SITE:			/* FALLTHRU */
		case DSYM_STANDARD:
			if (optnum.code <= DHCP_LAST_OPT)
				opt = ack->opts[optnum.code];
			break;

		case DSYM_VENDOR:
			/*
			 * the test against VS_OPTION_START is broken up into
			 * two tests to avoid compiler warnings under intel.
			 */

			if ((optnum.code > VS_OPTION_START ||
			    optnum.code == VS_OPTION_START) &&
			    optnum.code <= VS_OPTION_END)
				opt = ack->vs[optnum.code];
			break;

		case DSYM_FIELD:
			if (optnum.code + optnum.size > sizeof (PKT))
				break;

			/* + 2 to account for option code and length byte */
			opt = malloc(optnum.size + 2);
			if (opt == NULL) {
				send_error_reply(request, DHCP_IPC_E_MEMORY,
				    &fd);
				return;
			}

			did_alloc = B_TRUE;
			opt->len  = optnum.size;
			opt->code = optnum.code;
			(void) memcpy(&opt->value, (caddr_t)ack->pkt +
			    opt->code, opt->len);

			break;

		default:
			send_error_reply(request, DHCP_IPC_E_PROTO, &fd);
			return;
		}

		/*
		 * return the option payload, if there was one.  the "+ 2"
		 * accounts for the option code number and length byte.
		 */

		if (opt != NULL) {
			send_data_reply(request, &fd, 0, DHCP_TYPE_OPTION, opt,
			    opt->len + 2);

			if (did_alloc)
				free(opt);
			return;
		} else if (ack != ifsp->if_orig_ack) {
			/*
			 * There wasn't any definition for the option in the
			 * current ack, so now retry with the original ack if
			 * the original ack is not the current ack.
			 */
			ack = ifsp->if_orig_ack;
			goto load_option;
		}

		/*
		 * note that an "okay" response is returned either in
		 * the case of an unknown option or a known option
		 * with no payload.  this is okay (for now) since
		 * dhcpinfo checks whether an option is valid before
		 * ever performing ipc with the agent.
		 */

		send_ok_reply(request, &fd);
		return;
	}

	case DHCP_INFORM:
		dhcp_inform(ifsp);
		/* next destination: dhcp_acknak() */
		return;

	case DHCP_PING:
		if (ifsp->if_dflags & DHCP_IF_FAILED)
			send_error_reply(request, DHCP_IPC_E_FAILEDIF, &fd);
		else
			send_ok_reply(request, &fd);
		return;

	case DHCP_RELEASE:
		(void) script_start(ifsp, EVENT_RELEASE, dhcp_release,
		    "Finished with lease.", NULL);
		return;

	case DHCP_START:
		assert(ifsp->if_state == INIT);
		(void) canonize_ifs(ifsp);

		/*
		 * if we have a valid hostconf lying around, then jump
		 * into INIT_REBOOT.  if it fails, we'll end up going
		 * through the whole selecting() procedure again.
		 */

		error = read_hostconf(ifsp->if_name, plp, 2);
		if (error != -1) {
			ifsp->if_orig_ack = ifsp->if_ack = plp[0];
			if (error > 1) {
				/*
				 * Return indicated we had more than one packet
				 * second one is the original ack.  Older
				 * versions of the agent wrote only one ack
				 * to the file, we now keep both the first
				 * ack as well as the last one.
				 */
				ifsp->if_orig_ack = plp[1];
			}
			dhcp_init_reboot(ifsp);
			/* next destination: dhcp_acknak() */
			return;
		}

		/*
		 * if not debugging, wait for a few seconds before
		 * going into SELECTING.
		 */

		if (debug_level == 0) {
			if (iu_schedule_timer_ms(tq,
			    lrand48() % DHCP_SELECT_WAIT, dhcp_start, ifsp)
			    != -1) {
				hold_ifs(ifsp);
				/* next destination: dhcp_start() */
				return;
			}
		}

		dhcp_selecting(ifsp);
		/* next destination: dhcp_requesting() */
		return;

	case DHCP_STATUS: {
		dhcp_status_t	status;

		status.if_began = monosec_to_time(ifsp->if_curstart_monosec);

		if (ifsp->if_lease == DHCP_PERM) {
			status.if_t1	= DHCP_PERM;
			status.if_t2	= DHCP_PERM;
			status.if_lease	= DHCP_PERM;
		} else {
			status.if_t1	= status.if_began + ifsp->if_t1;
			status.if_t2	= status.if_began + ifsp->if_t2;
			status.if_lease	= status.if_began + ifsp->if_lease;
		}

		status.version		= DHCP_STATUS_VER;
		status.if_state		= ifsp->if_state;
		status.if_dflags	= ifsp->if_dflags;
		status.if_sent		= ifsp->if_sent;
		status.if_recv		= ifsp->if_received;
		status.if_bad_offers	= ifsp->if_bad_offers;

		(void) strlcpy(status.if_name, ifsp->if_name, IFNAMSIZ);

		send_data_reply(request, &fd, 0, DHCP_TYPE_STATUS, &status,
		    sizeof (dhcp_status_t));
		return;
	}

	default:
		return;
	}
}
