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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <dhcp_hostconf.h>
#include <dhcpagent_ipc.h>
#include <dhcpagent_util.h>
#include <dhcpmsg.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include <netinet/dhcp.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <stropts.h>
#include <fcntl.h>
#include <sys/scsi/adapters/iscsi_if.h>

#include "async.h"
#include "agent.h"
#include "script_handler.h"
#include "util.h"
#include "class_id.h"
#include "states.h"
#include "packet.h"
#include "interface.h"
#include "defaults.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

iu_timer_id_t		inactivity_id;
int			class_id_len = 0;
char			*class_id;
iu_eh_t			*eh;
iu_tq_t			*tq;
pid_t			grandparent;
int			rtsock_fd;

static boolean_t	shutdown_started = B_FALSE;
static boolean_t	do_adopt = B_FALSE;
static unsigned int	debug_level = 0;
static iu_eh_callback_t	accept_event, ipc_event, rtsock_event;
static void dhcp_smach_set_msg_reqhost(dhcp_smach_t *dsmp,
		ipc_action_t *iap);
static DHCP_OPT * dhcp_get_ack_or_state(const dhcp_smach_t *dsmp,
		const PKT_LIST *plp, uint_t codenum, boolean_t *did_alloc);

/*
 * The ipc_cmd_allowed[] table indicates which IPC commands are allowed in
 * which states; a non-zero value indicates the command is permitted.
 *
 * START is permitted if the state machine is fresh, or if we are in the
 * process of trying to obtain a lease (as a convenience to save the
 * administrator from having to do an explicit DROP).  EXTEND, RELEASE, and
 * GET_TAG require a lease to be obtained in order to make sense.  INFORM is
 * permitted if the interface is fresh or has an INFORM in progress or
 * previously done on it -- otherwise a DROP or RELEASE is first required.
 * PING and STATUS always make sense and thus are always permitted, as is DROP
 * in order to permit the administrator to always bail out.
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
	/* PRE_BOUND	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* BOUND	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* RENEWING	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* REBINDING	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* INFORMATION  */	{ 1, 0, 1, 0, 1, 1, 1, 1 },
	/* INIT_REBOOT  */	{ 1, 0, 1, 1, 1, 1, 0, 0 },
	/* ADOPTING	*/	{ 1, 0, 1, 1, 0, 1, 0, 0 },
	/* INFORM_SENT  */	{ 1, 0, 1, 0, 1, 1, 1, 0 },
	/* DECLINING	*/	{ 1, 1, 1, 1, 0, 1, 0, 1 },
	/* RELEASING	*/	{ 1, 0, 1, 0, 0, 1, 0, 1 },
};

#define	CMD_ISPRIV	0x1	/* Command requires privileges */
#define	CMD_CREATE	0x2	/* Command creates an interface */
#define	CMD_BOOTP	0x4	/* Command is valid with BOOTP */
#define	CMD_IMMED	0x8	/* Reply is immediate (no BUSY state) */

static uint_t ipc_cmd_flags[DHCP_NIPC] = {
	/* DHCP_DROP */		CMD_ISPRIV|CMD_BOOTP,
	/* DHCP_EXTEND */	CMD_ISPRIV,
	/* DHCP_PING */		CMD_BOOTP|CMD_IMMED,
	/* DHCP_RELEASE */	CMD_ISPRIV,
	/* DHCP_START */	CMD_CREATE|CMD_ISPRIV|CMD_BOOTP,
	/* DHCP_STATUS */	CMD_BOOTP|CMD_IMMED,
	/* DHCP_INFORM */	CMD_CREATE|CMD_ISPRIV,
	/* DHCP_GET_TAG */	CMD_BOOTP|CMD_IMMED
};

static boolean_t is_iscsi_active(void);

int
main(int argc, char **argv)
{
	boolean_t	is_daemon  = B_TRUE;
	boolean_t	is_verbose;
	int		ipc_fd;
	int		c;
	int		aware = RTAW_UNDER_IPMP;
	struct rlimit	rl;

	debug_level = df_get_int("", B_FALSE, DF_DEBUG_LEVEL);
	is_verbose = df_get_bool("", B_FALSE, DF_VERBOSE);

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

	/*
	 * Seed the random number generator, since we're going to need it
	 * to set transaction id's and for exponential backoff.
	 */
	srand48(gethrtime() ^ gethostid() ^ getpid());

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

	(void) iu_eh_register_signal(eh, SIGTHAW, refresh_smachs, NULL);

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

	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * Create and bind default IP sockets used to control interfaces and to
	 * catch stray packets.
	 */

	if (!dhcp_ip_default())
		return (EXIT_FAILURE);

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
	 * Create the global routing socket.  This is used for monitoring
	 * interface transitions, so that we learn about the kernel's Duplicate
	 * Address Detection status, and for inserting and removing default
	 * routes as learned from DHCP servers.  Both v4 and v6 are handed
	 * with this one socket.
	 */
	rtsock_fd = socket(PF_ROUTE, SOCK_RAW, 0);
	if (rtsock_fd == -1) {
		dhcpmsg(MSG_ERR, "cannot open routing socket");
		return (EXIT_FAILURE);
	}

	/*
	 * We're IPMP-aware and can manage IPMP test addresses, so issue
	 * RT_AWARE to get routing socket messages for interfaces under IPMP.
	 */
	if (setsockopt(rtsock_fd, SOL_ROUTE, RT_AWARE, &aware,
	    sizeof (aware)) == -1) {
		dhcpmsg(MSG_ERR, "cannot set RT_AWARE on routing socket");
		return (EXIT_FAILURE);
	}

	if (iu_register_event(eh, rtsock_fd, POLLIN, rtsock_event, 0) == -1) {
		dhcpmsg(MSG_ERR, "cannot register routing socket for messages");
		return (EXIT_FAILURE);
	}

	/*
	 * if the -a (adopt) option was specified, try to adopt the
	 * kernel-managed interface before we start.
	 */

	if (do_adopt && !dhcp_adopt())
		return (EXIT_FAILURE);

	/*
	 * For DHCPv6, we own all of the interfaces marked DHCPRUNNING.  As
	 * we're starting operation here, if there are any of those interfaces
	 * lingering around, they're strays, and need to be removed.
	 *
	 * It might be nice to save these addresses off somewhere -- for both
	 * v4 and v6 -- and use them as hints for later negotiation.
	 */
	remove_v6_strays();

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
		/*
		 * Check if the system is diskless client and/or
		 * there are active iSCSI sessions
		 *
		 * Do not drop the lease, or the system will be
		 * unable to sync(dump) through nfs/iSCSI driver
		 */
		if (!do_adopt && !is_iscsi_active()) {
			nuke_smach_list();
		}
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
 *	    iu_event_id_t: event ID
 *	    void *: indicates whether the request is from a privileged client
 *  output: void
 */

/* ARGSUSED */
static void
ipc_event(iu_eh_t *ehp, int fd, short events, iu_event_id_t id, void *arg)
{
	ipc_action_t		ia, *iap;
	dhcp_smach_t		*dsmp;
	int			error, is_priv = (int)arg;
	const char		*ifname;
	boolean_t		isv6;
	boolean_t		dsm_created = B_FALSE;

	ipc_action_init(&ia);
	error = dhcp_ipc_recv_request(fd, &ia.ia_request,
	    DHCP_IPC_REQUEST_WAIT);
	if (error != DHCP_IPC_SUCCESS) {
		if (error != DHCP_IPC_E_EOF) {
			dhcpmsg(MSG_ERROR,
			    "ipc_event: dhcp_ipc_recv_request failed: %s",
			    dhcp_ipc_strerror(error));
		} else {
			dhcpmsg(MSG_DEBUG, "ipc_event: connection closed");
		}
		if ((dsmp = lookup_smach_by_event(id)) != NULL) {
			ipc_action_finish(dsmp, error);
		} else {
			(void) iu_unregister_event(eh, id, NULL);
			(void) dhcp_ipc_close(fd);
		}
		return;
	}

	/* Fill in temporary ipc_action structure for utility functions */
	ia.ia_cmd = DHCP_IPC_CMD(ia.ia_request->message_type);
	ia.ia_fd = fd;
	ia.ia_eid = id;

	if (ia.ia_cmd >= DHCP_NIPC) {
		dhcpmsg(MSG_ERROR,
		    "ipc_event: invalid command (%s) attempted on %s",
		    dhcp_ipc_type_to_string(ia.ia_cmd), ia.ia_request->ifname);
		send_error_reply(&ia, DHCP_IPC_E_CMD_UNKNOWN);
		return;
	}

	/* return EPERM for any of the privileged actions */

	if (!is_priv && (ipc_cmd_flags[ia.ia_cmd] & CMD_ISPRIV)) {
		dhcpmsg(MSG_WARNING,
		    "ipc_event: privileged ipc command (%s) attempted on %s",
		    dhcp_ipc_type_to_string(ia.ia_cmd), ia.ia_request->ifname);
		send_error_reply(&ia, DHCP_IPC_E_PERM);
		return;
	}

	/*
	 * Try to locate the state machine associated with this command.  If
	 * the command is DHCP_START or DHCP_INFORM and there isn't a state
	 * machine already, make one (there may already be one from a previous
	 * failed attempt to START or INFORM).  Otherwise, verify the reference
	 * is still valid.
	 *
	 * The interface name may be blank.  In that case, we look up the
	 * primary interface, and the requested type (v4 or v6) doesn't matter.
	 */

	isv6 = (ia.ia_request->message_type & DHCP_V6) != 0;
	ifname = ia.ia_request->ifname;
	if (*ifname == '\0')
		dsmp = primary_smach(isv6);
	else
		dsmp = lookup_smach(ifname, isv6);

	if (dsmp != NULL) {
		/* Note that verify_smach drops a reference */
		hold_smach(dsmp);
		if (!verify_smach(dsmp))
			dsmp = NULL;
	}

	if (dsmp == NULL) {
		/*
		 * If the user asked for the primary DHCP interface by giving
		 * an empty string and there is no primary, then check if we're
		 * handling dhcpinfo.  If so, then simulate primary selection.
		 * Otherwise, report failure.
		 */
		if (ifname[0] == '\0') {
			if (ia.ia_cmd == DHCP_GET_TAG)
				dsmp = info_primary_smach(isv6);
			if (dsmp == NULL)
				error = DHCP_IPC_E_NOPRIMARY;

		/*
		 * If there's no interface, and we're starting up, then create
		 * it now, along with a state machine for it.  Note that if
		 * insert_smach fails, it discards the LIF reference.
		 */
		} else if (ipc_cmd_flags[ia.ia_cmd] & CMD_CREATE) {
			dhcp_lif_t *lif;

			lif = attach_lif(ifname, isv6, &error);
			if (lif != NULL &&
			    (dsmp = insert_smach(lif, &error)) != NULL) {
				/*
				 * Get client ID for logical interface.  (V4
				 * only, because V6 plumbs its own interfaces.)
				 */
				error = get_smach_cid(dsmp);
				if (error != DHCP_IPC_SUCCESS) {
					remove_smach(dsmp);
					dsmp = NULL;
				}
				dsm_created = (dsmp != NULL);
			}

		/*
		 * Otherwise, this is an operation on an unknown interface.
		 */
		} else {
			error = DHCP_IPC_E_UNKIF;
		}
		if (dsmp == NULL) {
			send_error_reply(&ia, error);
			return;
		}
	}

	/*
	 * If this is a request for DHCP to manage a lease on an address,
	 * ensure that IFF_DHCPRUNNING is set (we don't set this when the lif
	 * is created because the lif may have been created for INFORM).
	 */
	if (ia.ia_cmd == DHCP_START &&
	    (error = set_lif_dhcp(dsmp->dsm_lif)) != DHCP_IPC_SUCCESS) {
		if (dsm_created)
			remove_smach(dsmp);
		send_error_reply(&ia, error);
		return;
	}

	if ((dsmp->dsm_dflags & DHCP_IF_BOOTP) &&
	    !(ipc_cmd_flags[ia.ia_cmd] & CMD_BOOTP)) {
		dhcpmsg(MSG_ERROR, "command %s not valid for BOOTP on %s",
		    dhcp_ipc_type_to_string(ia.ia_cmd), dsmp->dsm_name);
		send_error_reply(&ia, DHCP_IPC_E_BOOTP);
		return;
	}

	/*
	 * verify that the state machine is in a state which will allow the
	 * command.  we do this up front so that we can return an error
	 * *before* needlessly cancelling an in-progress transaction.
	 */

	if (!check_cmd_allowed(dsmp->dsm_state, ia.ia_cmd)) {
		dhcpmsg(MSG_DEBUG,
		    "in state %s; not allowing %s command on %s",
		    dhcp_state_to_string(dsmp->dsm_state),
		    dhcp_ipc_type_to_string(ia.ia_cmd), dsmp->dsm_name);
		send_error_reply(&ia,
		    ia.ia_cmd == DHCP_START && dsmp->dsm_state != INIT ?
		    DHCP_IPC_E_RUNNING : DHCP_IPC_E_OUTSTATE);
		return;
	}

	dhcpmsg(MSG_DEBUG, "in state %s; allowing %s command on %s",
	    dhcp_state_to_string(dsmp->dsm_state),
	    dhcp_ipc_type_to_string(ia.ia_cmd), dsmp->dsm_name);

	if ((ia.ia_request->message_type & DHCP_PRIMARY) && is_priv)
		make_primary(dsmp);

	/*
	 * The current design dictates that there can be only one outstanding
	 * transaction per state machine -- this simplifies the code
	 * considerably and also fits well with RFCs 2131 and 3315.  It is
	 * worth classifying the different DHCP commands into synchronous
	 * (those which we will handle now and reply to immediately) and
	 * asynchronous (those which require transactions and will be completed
	 * at an indeterminate time in the future):
	 *
	 *    DROP: removes the agent's management of a state machine.
	 *	    asynchronous as the script program may be invoked.
	 *
	 *    PING: checks to see if the agent has a named state machine.
	 *	    synchronous, since no packets need to be sent
	 *	    to the DHCP server.
	 *
	 *  STATUS: returns information about a state machine.
	 *	    synchronous, since no packets need to be sent
	 *	    to the DHCP server.
	 *
	 * RELEASE: releases the agent's management of a state machine
	 *	    and brings the associated interfaces down.  asynchronous
	 *	    as the script program may be invoked.
	 *
	 *  EXTEND: renews a lease.  asynchronous, since the agent
	 *	    needs to wait for an ACK, etc.
	 *
	 *   START: starts DHCP on a named state machine.  asynchronous since
	 *	    the agent needs to wait for OFFERs, ACKs, etc.
	 *
	 *  INFORM: obtains configuration parameters for the system using
	 *	    externally configured interface.  asynchronous, since the
	 *	    agent needs to wait for an ACK.
	 *
	 * Notice that EXTEND, INFORM, START, DROP and RELEASE are
	 * asynchronous.  Notice also that asynchronous commands may occur from
	 * within the agent -- for instance, the agent will need to do implicit
	 * EXTENDs to extend the lease. In order to make the code simpler, the
	 * following rules apply for asynchronous commands:
	 *
	 * There can only be one asynchronous command at a time per state
	 * machine.  The current asynchronous command is managed by the async_*
	 * api: async_start(), async_finish(), and async_cancel().
	 * async_start() starts management of a new asynchronous command on an
	 * state machine, which should only be done after async_cancel() to
	 * terminate a previous command.  When the command is completed,
	 * async_finish() should be called.
	 *
	 * Asynchronous commands started by a user command have an associated
	 * ipc_action which provides the agent with information for how to get
	 * in touch with the user command when the action completes.  These
	 * ipc_action records also have an associated timeout which may be
	 * infinite.  ipc_action_start() should be called when starting an
	 * asynchronous command requested by a user, which sets up the timer
	 * and keeps track of the ipc information (file descriptor, request
	 * type).  When the asynchronous command completes, ipc_action_finish()
	 * should be called to return a command status code to the user and
	 * close the ipc connection).  If the command does not complete before
	 * the timer fires, ipc_action_timeout() is called which closes the ipc
	 * connection and returns DHCP_IPC_E_TIMEOUT to the user.  Note that
	 * independent of ipc_action_timeout(), ipc_action_finish() should be
	 * called.
	 *
	 * on a case-by-case basis, here is what happens (per state machine):
	 *
	 *    o When an asynchronous command is requested, then
	 *	async_cancel() is called to terminate any non-user
	 *	action in progress.  If there's a user action running,
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
	 *	async_finish() is called, and the state machine is
	 *	is returned to a known state based on the command.
	 *	if there was an associated ipc_action,
	 *	ipc_action_finish() is called to complete it.
	 *
	 *    o if the ipc_action timer fires before command
	 *	completion, then DHCP_IPC_E_TIMEOUT is returned to
	 *	the user.  however, the transaction continues to
	 *	be carried out asynchronously.
	 */

	if (ipc_cmd_flags[ia.ia_cmd] & CMD_IMMED) {
		/*
		 * Only immediate commands (ping, status, get_tag) need to
		 * worry about freeing ia through one of the reply functions
		 * before returning.
		 */
		iap = &ia;
	} else {
		/*
		 * if shutdown request has been received, send back an error.
		 */
		if (shutdown_started) {
			send_error_reply(&ia, DHCP_IPC_E_OUTSTATE);
			return;
		}

		if (dsmp->dsm_dflags & DHCP_IF_BUSY) {
			send_error_reply(&ia, DHCP_IPC_E_PEND);
			return;
		}

		if (!ipc_action_start(dsmp, &ia)) {
			dhcpmsg(MSG_WARNING, "ipc_event: ipc_action_start "
			    "failed for %s", dsmp->dsm_name);
			send_error_reply(&ia, DHCP_IPC_E_MEMORY);
			return;
		}

		/* Action structure consumed by above function */
		iap = &dsmp->dsm_ia;
	}

	switch (iap->ia_cmd) {

	case DHCP_DROP:
		if (dsmp->dsm_droprelease)
			break;
		dsmp->dsm_droprelease = B_TRUE;

		/*
		 * Ensure that a timer associated with the existing state
		 * doesn't pop while we're waiting for the script to complete.
		 * (If so, chaos can result -- e.g., a timer causes us to end
		 * up in dhcp_selecting() would start acquiring a new lease on
		 * dsmp while our DHCP_DROP dismantling is ongoing.)
		 */
		cancel_smach_timers(dsmp);
		(void) script_start(dsmp, isv6 ? EVENT_DROP6 : EVENT_DROP,
		    dhcp_drop, NULL, NULL);
		break;		/* not an immediate function */

	case DHCP_EXTEND:
		dhcp_smach_set_msg_reqhost(dsmp, iap);
		(void) dhcp_extending(dsmp);
		break;

	case DHCP_GET_TAG: {
		dhcp_optnum_t	optnum;
		void		*opt = NULL;
		uint_t		optlen;
		boolean_t	did_alloc = B_FALSE;
		PKT_LIST	*ack = dsmp->dsm_ack;
		int		i;

		/*
		 * verify the request makes sense.
		 */

		if (iap->ia_request->data_type   != DHCP_TYPE_OPTNUM ||
		    iap->ia_request->data_length != sizeof (dhcp_optnum_t)) {
			send_error_reply(iap, DHCP_IPC_E_PROTO);
			break;
		}

		(void) memcpy(&optnum, iap->ia_request->buffer,
		    sizeof (dhcp_optnum_t));

load_option:
		switch (optnum.category) {

		case DSYM_SITE:			/* FALLTHRU */
		case DSYM_STANDARD:
			for (i = 0; i < dsmp->dsm_pillen; i++) {
				if (dsmp->dsm_pil[i] == optnum.code)
					break;
			}
			if (i < dsmp->dsm_pillen)
				break;
			if (isv6) {
				opt = dhcpv6_pkt_option(ack, NULL, optnum.code,
				    NULL);
			} else {
				opt = dhcp_get_ack_or_state(dsmp, ack,
				    optnum.code, &did_alloc);
			}
			break;

		case DSYM_VENDOR:
			if (isv6) {
				dhcpv6_option_t *d6o;
				uint32_t ent;

				/*
				 * Look through vendor options to find our
				 * enterprise number.
				 */
				d6o = NULL;
				for (;;) {
					d6o = dhcpv6_pkt_option(ack, d6o,
					    DHCPV6_OPT_VENDOR_OPT, &optlen);
					if (d6o == NULL)
						break;
					optlen -= sizeof (*d6o);
					if (optlen < sizeof (ent))
						continue;
					(void) memcpy(&ent, d6o + 1,
					    sizeof (ent));
					if (ntohl(ent) != DHCPV6_SUN_ENT)
						continue;
					break;
				}
				if (d6o != NULL) {
					/*
					 * Now find the requested vendor option
					 * within the vendor options block.
					 */
					opt = dhcpv6_find_option(
					    (char *)(d6o + 1) + sizeof (ent),
					    optlen - sizeof (ent), NULL,
					    optnum.code, NULL);
				}
			} else {
				/*
				 * the test against VS_OPTION_START is broken
				 * up into two tests to avoid compiler warnings
				 * under intel.
				 */
				if ((optnum.code > VS_OPTION_START ||
				    optnum.code == VS_OPTION_START) &&
				    optnum.code <= VS_OPTION_END)
					opt = ack->vs[optnum.code];
			}
			break;

		case DSYM_FIELD:
			if (isv6) {
				dhcpv6_message_t *d6m =
				    (dhcpv6_message_t *)ack->pkt;
				dhcpv6_option_t *d6o;

				/* Validate the packet field the user wants */
				optlen = optnum.code + optnum.size;
				if (d6m->d6m_msg_type ==
				    DHCPV6_MSG_RELAY_FORW ||
				    d6m->d6m_msg_type ==
				    DHCPV6_MSG_RELAY_REPL) {
					if (optlen > sizeof (dhcpv6_relay_t))
						break;
				} else {
					if (optlen > sizeof (*d6m))
						break;
				}

				opt = malloc(sizeof (*d6o) + optnum.size);
				if (opt != NULL) {
					d6o = opt;
					d6o->d6o_code = htons(optnum.code);
					d6o->d6o_len = htons(optnum.size);
					(void) memcpy(d6o + 1, (caddr_t)d6m +
					    optnum.code, optnum.size);
				}
			} else {
				if (optnum.code + optnum.size > sizeof (PKT))
					break;

				opt = malloc(optnum.size + DHCP_OPT_META_LEN);
				if (opt != NULL) {
					DHCP_OPT *v4opt = opt;

					v4opt->len  = optnum.size;
					v4opt->code = optnum.code;
					(void) memcpy(v4opt->value,
					    (caddr_t)ack->pkt + optnum.code,
					    optnum.size);
				}
			}

			if (opt == NULL) {
				send_error_reply(iap, DHCP_IPC_E_MEMORY);
				return;
			}
			did_alloc = B_TRUE;
			break;

		default:
			send_error_reply(iap, DHCP_IPC_E_PROTO);
			return;
		}

		/*
		 * return the option payload, if there was one.
		 */

		if (opt != NULL) {
			if (isv6) {
				dhcpv6_option_t d6ov;

				(void) memcpy(&d6ov, opt, sizeof (d6ov));
				optlen = ntohs(d6ov.d6o_len) + sizeof (d6ov);
			} else {
				optlen = ((DHCP_OPT *)opt)->len +
				    DHCP_OPT_META_LEN;
			}
			send_data_reply(iap, 0, DHCP_TYPE_OPTION, opt, optlen);

			if (did_alloc)
				free(opt);
			break;
		} else if (ack != dsmp->dsm_orig_ack) {
			/*
			 * There wasn't any definition for the option in the
			 * current ack, so now retry with the original ack if
			 * the original ack is not the current ack.
			 */
			ack = dsmp->dsm_orig_ack;
			goto load_option;
		}

		/*
		 * note that an "okay" response is returned either in
		 * the case of an unknown option or a known option
		 * with no payload.  this is okay (for now) since
		 * dhcpinfo checks whether an option is valid before
		 * ever performing ipc with the agent.
		 */

		send_ok_reply(iap);
		break;
	}

	case DHCP_INFORM:
		dhcp_inform(dsmp);
		/* next destination: dhcp_acknak() */
		break;		/* not an immediate function */

	case DHCP_PING:
		if (dsmp->dsm_dflags & DHCP_IF_FAILED)
			send_error_reply(iap, DHCP_IPC_E_FAILEDIF);
		else
			send_ok_reply(iap);
		break;

	case DHCP_RELEASE:
		if (dsmp->dsm_droprelease)
			break;
		dsmp->dsm_droprelease = B_TRUE;
		cancel_smach_timers(dsmp); /* see comment in DHCP_DROP above */
		(void) script_start(dsmp, isv6 ? EVENT_RELEASE6 :
		    EVENT_RELEASE, dhcp_release, "Finished with lease.", NULL);
		break;		/* not an immediate function */

	case DHCP_START: {
		PKT_LIST *ack, *oack;
		PKT_LIST *plp[2];

		deprecate_leases(dsmp);
		dhcp_smach_set_msg_reqhost(dsmp, iap);

		/*
		 * if we have a valid hostconf lying around, then jump
		 * into INIT_REBOOT.  if it fails, we'll end up going
		 * through the whole selecting() procedure again.
		 */

		error = read_hostconf(dsmp->dsm_name, plp, 2, dsmp->dsm_isv6);
		ack = error > 0 ? plp[0] : NULL;
		oack = error > 1 ? plp[1] : NULL;

		/*
		 * If the allocation of the old ack fails, that's fine;
		 * continue without it.
		 */
		if (oack == NULL)
			oack = ack;

		/*
		 * As long as we've allocated something, start using it.
		 */
		if (ack != NULL) {
			dsmp->dsm_orig_ack = oack;
			dsmp->dsm_ack = ack;
			dhcp_init_reboot(dsmp);
			/* next destination: dhcp_acknak() */
			break;
		}

		/*
		 * if not debugging, wait for a few seconds before
		 * going into SELECTING.
		 */

		if (debug_level == 0 && set_start_timer(dsmp)) {
			/* next destination: dhcp_start() */
			break;
		} else {
			dhcp_selecting(dsmp);
			/* next destination: dhcp_requesting() */
			break;
		}
	}

	case DHCP_STATUS: {
		dhcp_status_t	status;
		dhcp_lease_t	*dlp;

		status.if_began = monosec_to_time(dsmp->dsm_curstart_monosec);

		/*
		 * We return information on just the first lease as being
		 * representative of the lot.  A better status mechanism is
		 * needed.
		 */
		dlp = dsmp->dsm_leases;

		if (dlp == NULL ||
		    dlp->dl_lifs->lif_expire.dt_start == DHCP_PERM) {
			status.if_t1	= DHCP_PERM;
			status.if_t2	= DHCP_PERM;
			status.if_lease	= DHCP_PERM;
		} else {
			status.if_t1	= status.if_began +
			    dlp->dl_t1.dt_start;
			status.if_t2	= status.if_began +
			    dlp->dl_t2.dt_start;
			status.if_lease	= status.if_began +
			    dlp->dl_lifs->lif_expire.dt_start;
		}

		status.version		= DHCP_STATUS_VER;
		status.if_state		= dsmp->dsm_state;
		status.if_dflags	= dsmp->dsm_dflags;
		status.if_sent		= dsmp->dsm_sent;
		status.if_recv		= dsmp->dsm_received;
		status.if_bad_offers	= dsmp->dsm_bad_offers;

		(void) strlcpy(status.if_name, dsmp->dsm_name, LIFNAMSIZ);

		send_data_reply(iap, 0, DHCP_TYPE_STATUS, &status,
		    sizeof (dhcp_status_t));
		break;
	}
	}
}

/*
 * dhcp_smach_set_msg_reqhost(): set dsm_msg_reqhost based on the message
 * content of a DHCP IPC message
 *
 *   input: dhcp_smach_t *: the state machine instance;
 *	    ipc_action_t *: the decoded DHCP IPC message;
 *  output: void
 */

static void
dhcp_smach_set_msg_reqhost(dhcp_smach_t *dsmp, ipc_action_t *iap)
{
	DHCP_OPT	*d4o;
	dhcp_symbol_t	*entry;
	char		*value;

	if (dsmp->dsm_msg_reqhost != NULL) {
		dhcpmsg(MSG_DEBUG,
		    "dhcp_smach_set_msg_reqhost: nullify former value, %s",
		    dsmp->dsm_msg_reqhost);
		free(dsmp->dsm_msg_reqhost);
		dsmp->dsm_msg_reqhost = NULL;
	}

	/*
	 * if a STANDARD/HOSTNAME was sent in the IPC request, then copy that
	 * value into the state machine data if decoding succeeds. Otherwise,
	 * log to indicate at what step the decoding stopped.
	 */

	if (dsmp->dsm_isv6) {
		dhcpmsg(MSG_DEBUG, "dhcp_smach_set_msg_reqhost: ipv6 is not"
		    " handled");
		return;
	} else if (iap->ia_request->data_type != DHCP_TYPE_OPTION) {
		dhcpmsg(MSG_DEBUG, "dhcp_smach_set_msg_reqhost: request type"
		    " %d is not DHCP_TYPE_OPTION", iap->ia_request->data_type);
		return;
	}

	if (iap->ia_request->buffer == NULL ||
	    iap->ia_request->data_length <= DHCP_OPT_META_LEN) {
		dhcpmsg(MSG_WARNING, "dhcp_smach_set_msg_reqhost:"
		    " DHCP_TYPE_OPTION ia_request buffer is NULL (0) or"
		    " short (1): %d",
		    iap->ia_request->buffer == NULL ? 0 : 1);
		return;
	}

	d4o = (DHCP_OPT *)iap->ia_request->buffer;
	if (d4o->code != CD_HOSTNAME) {
		dhcpmsg(MSG_DEBUG,
		    "dhcp_smach_set_msg_reqhost: ignoring DHCPv4"
		    " option %u", d4o->code);
		return;
	} else if (iap->ia_request->data_length - DHCP_OPT_META_LEN
	    != d4o->len) {
		dhcpmsg(MSG_WARNING, "dhcp_smach_set_msg_reqhost:"
		    " unexpected DHCP_OPT buffer length %u for CD_HOSTNAME"
		    " option length %u", iap->ia_request->data_length,
		    d4o->len);
		return;
	}

	entry = inittab_getbycode(ITAB_CAT_STANDARD, ITAB_CONS_INFO,
	    CD_HOSTNAME);
	if (entry == NULL) {
		dhcpmsg(MSG_WARNING,
		    "dhcp_smach_set_msg_reqhost: error getting"
		    " ITAB_CAT_STANDARD ITAB_CONS_INFO"
		    " CD_HOSTNAME entry");
		return;
	}

	value = inittab_decode(entry, d4o->value, d4o->len,
	    /* just_payload */ B_TRUE);
	if (value == NULL) {
		dhcpmsg(MSG_WARNING,
		    "dhcp_smach_set_msg_reqhost: error decoding"
		    " CD_HOSTNAME value from DHCP_OPT");
	} else {
		dhcpmsg(MSG_DEBUG,
		    "dhcp_smach_set_msg_reqhost: host %s", value);
		free(dsmp->dsm_msg_reqhost);
		dsmp->dsm_msg_reqhost = value;
	}
	free(entry);
}

/*
 * dhcp_get_ack_or_state(): get a v4 option from the ACK or from the state
 * machine state for certain codes that are not ACKed (e.g., CD_CLIENT_ID)
 *
 *   input: dhcp_smach_t *: the state machine instance;
 *	    PKT_LIST *: the decoded DHCP IPC message;
 *	    uint_t: the DHCP client option code;
 *	    boolean_t *: a pointer to a value that will be set to B_TRUE if
 *	        the return value must be freed (or else set to B_FALSE);
 *  output: the option if found or else NULL.
 */

static DHCP_OPT *
dhcp_get_ack_or_state(const dhcp_smach_t *dsmp, const PKT_LIST *plp,
    uint_t codenum, boolean_t *did_alloc)
{
	DHCP_OPT *opt;

	*did_alloc = B_FALSE;

	if (codenum > DHCP_LAST_OPT)
		return (NULL);

	/* check the ACK first for all codes */
	opt = plp->opts[codenum];
	if (opt != NULL)
		return (opt);

	/* check the machine state also for certain codes */
	switch (codenum) {
	case CD_CLIENT_ID:
		/*
		 * CD_CLIENT_ID is not sent in an ACK, but it's possibly
		 * available from the state machine data
		 */

		if (dsmp->dsm_cidlen > 0) {
			if ((opt = malloc(dsmp->dsm_cidlen + DHCP_OPT_META_LEN))
			    != NULL) {
				*did_alloc = B_TRUE;
				(void) encode_dhcp_opt(opt,
				    B_FALSE /* is IPv6 */, CD_CLIENT_ID,
				    dsmp->dsm_cid, dsmp->dsm_cidlen);
			}
		}
		break;
	default:
		break;
	}
	return (opt);
}

/*
 * check_rtm_addr(): determine if routing socket message matches interface
 *		     address
 *
 *   input: const struct if_msghdr *: pointer to routing socket message
 *	    int: routing socket message length
 *	    boolean_t: set to B_TRUE if IPv6
 *	    const in6_addr_t *: pointer to IP address
 *  output: boolean_t: B_TRUE if address is a match
 */

static boolean_t
check_rtm_addr(const struct ifa_msghdr *ifam, int msglen, boolean_t isv6,
    const in6_addr_t *addr)
{
	const char *cp, *lim;
	uint_t flag;
	const struct sockaddr *sa;

	if (!(ifam->ifam_addrs & RTA_IFA))
		return (B_FALSE);

	cp = (const char *)(ifam + 1);
	lim = (const char *)ifam + msglen;
	for (flag = 1; flag < RTA_IFA; flag <<= 1) {
		if (ifam->ifam_addrs & flag) {
			/* LINTED: alignment */
			sa = (const struct sockaddr *)cp;
			if ((const char *)(sa + 1) > lim)
				return (B_FALSE);
			switch (sa->sa_family) {
			case AF_INET:
				cp += sizeof (struct sockaddr_in);
				break;
			case AF_LINK:
				cp += sizeof (struct sockaddr_dl);
				break;
			case AF_INET6:
				cp += sizeof (struct sockaddr_in6);
				break;
			default:
				cp += sizeof (struct sockaddr);
				break;
			}
		}
	}
	if (isv6) {
		const struct sockaddr_in6 *sin6;

		/* LINTED: alignment */
		sin6 = (const struct sockaddr_in6 *)cp;
		if ((const char *)(sin6 + 1) > lim)
			return (B_FALSE);
		if (sin6->sin6_family != AF_INET6)
			return (B_FALSE);
		return (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, addr));
	} else {
		const struct sockaddr_in *sinp;
		ipaddr_t v4addr;

		/* LINTED: alignment */
		sinp = (const struct sockaddr_in *)cp;
		if ((const char *)(sinp + 1) > lim)
			return (B_FALSE);
		if (sinp->sin_family != AF_INET)
			return (B_FALSE);
		IN6_V4MAPPED_TO_IPADDR(addr, v4addr);
		return (sinp->sin_addr.s_addr == v4addr);
	}
}

/*
 * is_rtm_v6(): determine if routing socket message is IPv6
 *
 *   input: struct ifa_msghdr *: pointer to routing socket message
 *	    int: message length
 *  output: boolean_t
 */

static boolean_t
is_rtm_v6(const struct ifa_msghdr *ifam, int msglen)
{
	const char *cp, *lim;
	uint_t flag;
	const struct sockaddr *sa;

	cp = (const char *)(ifam + 1);
	lim = (const char *)ifam + msglen;
	for (flag = ifam->ifam_addrs; flag != 0; flag &= flag - 1) {
		/* LINTED: alignment */
		sa = (const struct sockaddr *)cp;
		if ((const char *)(sa + 1) > lim)
			return (B_FALSE);
		switch (sa->sa_family) {
		case AF_INET:
			return (B_FALSE);
		case AF_LINK:
			cp += sizeof (struct sockaddr_dl);
			break;
		case AF_INET6:
			return (B_TRUE);
		default:
			cp += sizeof (struct sockaddr);
			break;
		}
	}
	return (B_FALSE);
}

/*
 * check_lif(): check the state of a given logical interface and its DHCP
 *		lease.  We've been told by the routing socket that the
 *		corresponding ifIndex has changed.  This may mean that DAD has
 *		completed or failed.
 *
 *   input: dhcp_lif_t *: pointer to the LIF
 *	    const struct ifa_msghdr *: routing socket message
 *	    int: size of routing socket message
 *  output: boolean_t: B_TRUE if DAD has completed on this interface
 */

static boolean_t
check_lif(dhcp_lif_t *lif, const struct ifa_msghdr *ifam, int msglen)
{
	boolean_t isv6, dad_wait, unplumb;
	int fd;
	struct lifreq lifr;

	isv6 = lif->lif_pif->pif_isv6;
	fd = isv6 ? v6_sock_fd : v4_sock_fd;

	/*
	 * Get the real (64 bit) logical interface flags.  Note that the
	 * routing socket message has flags, but these are just the lower 32
	 * bits.
	 */
	unplumb = B_FALSE;
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, lif->lif_name, sizeof (lifr.lifr_name));
	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		/*
		 * Failing to retrieve flags means that the interface is gone.
		 * It hasn't failed to verify with DAD, but we still have to
		 * give up on it.
		 */
		lifr.lifr_flags = 0;
		if (errno == ENXIO) {
			lif->lif_plumbed = B_FALSE;
			dhcpmsg(MSG_INFO, "%s has been removed; abandoning",
			    lif->lif_name);
			if (!isv6)
				discard_default_routes(lif->lif_smachs);
		} else {
			dhcpmsg(MSG_ERR,
			    "unable to retrieve interface flags on %s",
			    lif->lif_name);
		}
		unplumb = B_TRUE;
	} else if (!check_rtm_addr(ifam, msglen, isv6, &lif->lif_v6addr)) {
		/*
		 * If the message is not about this logical interface,
		 * then just ignore it.
		 */
		return (B_FALSE);
	} else if (lifr.lifr_flags & IFF_DUPLICATE) {
		dhcpmsg(MSG_ERROR, "interface %s has duplicate address",
		    lif->lif_name);
		lif_mark_decline(lif, "duplicate address");
		close_ip_lif(lif);
		(void) open_ip_lif(lif, INADDR_ANY, B_TRUE);
	}

	dad_wait = lif->lif_dad_wait;
	if (dad_wait) {
		dhcpmsg(MSG_VERBOSE, "check_lif: %s has finished DAD",
		    lif->lif_name);
		lif->lif_dad_wait = B_FALSE;
	}

	if (unplumb)
		unplumb_lif(lif);

	return (dad_wait);
}

/*
 * check_main_lif(): check the state of a main logical interface for a state
 *		     machine.  This is used only for DHCPv6.
 *
 *   input: dhcp_smach_t *: pointer to the state machine
 *	    const struct ifa_msghdr *: routing socket message
 *	    int: size of routing socket message
 *  output: boolean_t: B_TRUE if LIF is ok.
 */

static boolean_t
check_main_lif(dhcp_smach_t *dsmp, const struct ifa_msghdr *ifam, int msglen)
{
	dhcp_lif_t *lif = dsmp->dsm_lif;
	struct lifreq lifr;

	/*
	 * Get the real (64 bit) logical interface flags.  Note that the
	 * routing socket message has flags, but these are just the lower 32
	 * bits.
	 */
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, lif->lif_name, sizeof (lifr.lifr_name));
	if (ioctl(v6_sock_fd, SIOCGLIFFLAGS, &lifr) == -1) {
		/*
		 * Failing to retrieve flags means that the interface is gone.
		 * Our state machine is now trash.
		 */
		if (errno == ENXIO) {
			dhcpmsg(MSG_INFO, "%s has been removed; abandoning",
			    lif->lif_name);
		} else {
			dhcpmsg(MSG_ERR,
			    "unable to retrieve interface flags on %s",
			    lif->lif_name);
		}
		return (B_FALSE);
	} else if (!check_rtm_addr(ifam, msglen, B_TRUE, &lif->lif_v6addr)) {
		/*
		 * If the message is not about this logical interface,
		 * then just ignore it.
		 */
		return (B_TRUE);
	} else if (lifr.lifr_flags & IFF_DUPLICATE) {
		dhcpmsg(MSG_ERROR, "interface %s has duplicate address",
		    lif->lif_name);
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

/*
 * process_link_up_down(): check the state of a physical interface for up/down
 *			   transitions; must go through INIT_REBOOT state if
 *			   the link flaps.
 *
 *   input: dhcp_pif_t *: pointer to the physical interface to check
 *	    const struct if_msghdr *: routing socket message
 *  output: none
 */

static void
process_link_up_down(dhcp_pif_t *pif, const struct if_msghdr *ifm)
{
	struct lifreq lifr;
	boolean_t isv6;
	int fd;

	/*
	 * If the message implies no change of flags, then we're done; no need
	 * to check further.  Note that if we have multiple state machines on a
	 * single physical interface, this test keeps us from issuing an ioctl
	 * for each one.
	 */
	if ((ifm->ifm_flags & IFF_RUNNING) && pif->pif_running ||
	    !(ifm->ifm_flags & IFF_RUNNING) && !pif->pif_running)
		return;

	/*
	 * We don't know what the real interface flags are, because the
	 * if_index number is only 16 bits; we must go ask.
	 */
	isv6 = pif->pif_isv6;
	fd = isv6 ? v6_sock_fd : v4_sock_fd;
	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, pif->pif_name, sizeof (lifr.lifr_name));

	if (ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1 ||
	    !(lifr.lifr_flags & IFF_RUNNING)) {
		/*
		 * If we've lost the interface or it has gone down, then
		 * nothing special to do; just turn off the running flag.
		 */
		pif_status(pif, B_FALSE);
	} else {
		/*
		 * Interface has come back up: go through verification process.
		 */
		pif_status(pif, B_TRUE);
	}
}

/*
 * rtsock_event(): fetches routing socket messages and updates internal
 *		   interface state based on those messages.
 *
 *   input: iu_eh_t *: unused
 *	    int: the routing socket file descriptor
 *	    (other arguments unused)
 *  output: void
 */

/* ARGSUSED */
static void
rtsock_event(iu_eh_t *ehp, int fd, short events, iu_event_id_t id, void *arg)
{
	dhcp_smach_t *dsmp, *dsmnext;
	union {
		struct ifa_msghdr ifam;
		struct if_msghdr ifm;
		char buf[1024];
	} msg;
	uint16_t ifindex;
	int msglen;
	boolean_t isv6;

	if ((msglen = read(fd, &msg, sizeof (msg))) <= 0)
		return;

	/* Note that the routing socket interface index is just 16 bits */
	if (msg.ifm.ifm_type == RTM_IFINFO) {
		ifindex = msg.ifm.ifm_index;
		isv6 = (msg.ifm.ifm_flags & IFF_IPV6) ? B_TRUE : B_FALSE;
	} else if (msg.ifam.ifam_type == RTM_DELADDR ||
	    msg.ifam.ifam_type == RTM_NEWADDR) {
		ifindex = msg.ifam.ifam_index;
		isv6 = is_rtm_v6(&msg.ifam, msglen);
	} else {
		return;
	}

	for (dsmp = lookup_smach_by_uindex(ifindex, NULL, isv6);
	    dsmp != NULL; dsmp = dsmnext) {
		DHCPSTATE oldstate;
		boolean_t lif_finished;
		boolean_t lease_removed;
		dhcp_lease_t *dlp, *dlnext;

		/*
		 * Note that script_start can call dhcp_drop directly, and
		 * that will do release_smach.
		 */
		dsmnext = lookup_smach_by_uindex(ifindex, dsmp, isv6);
		oldstate = dsmp->dsm_state;

		/*
		 * Ignore state machines that are currently processing drop or
		 * release; there is nothing more we can do for them.
		 */
		if (dsmp->dsm_droprelease)
			continue;

		/*
		 * Look for link up/down notifications.  These occur on a
		 * physical interface basis.
		 */
		if (msg.ifm.ifm_type == RTM_IFINFO) {
			process_link_up_down(dsmp->dsm_lif->lif_pif, &msg.ifm);
			continue;
		}

		/*
		 * Since we cannot trust the flags reported by the routing
		 * socket (they're just 32 bits -- and thus never include
		 * IFF_DUPLICATE), and we can't trust the ifindex (it's only 16
		 * bits and also doesn't reflect the alias in use), we get
		 * flags on all matching interfaces, and go by that.
		 */
		lif_finished = B_FALSE;
		lease_removed = B_FALSE;
		for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlnext) {
			dhcp_lif_t *lif, *lifnext;
			uint_t nlifs = dlp->dl_nlifs;

			dlnext = dlp->dl_next;
			for (lif = dlp->dl_lifs; lif != NULL && nlifs > 0;
			    lif = lifnext, nlifs--) {
				lifnext = lif->lif_next;
				if (check_lif(lif, &msg.ifam, msglen)) {
					dsmp->dsm_lif_wait--;
					lif_finished = B_TRUE;
				}
			}
			if (dlp->dl_nlifs == 0) {
				remove_lease(dlp);
				lease_removed = B_TRUE;
			}
		}

		if ((isv6 && !check_main_lif(dsmp, &msg.ifam, msglen)) ||
		    (!isv6 && !verify_lif(dsmp->dsm_lif))) {
			finished_smach(dsmp, DHCP_IPC_E_INVIF);
			continue;
		}

		/*
		 * Ignore this state machine if nothing interesting has
		 * happened.
		 */
		if (!lif_finished && dsmp->dsm_lif_down == 0 &&
		    (dsmp->dsm_leases != NULL || !lease_removed))
			continue;

		/*
		 * If we're still waiting for DAD to complete on some of the
		 * configured LIFs, then don't send a response.
		 */
		if (dsmp->dsm_lif_wait != 0) {
			dhcpmsg(MSG_VERBOSE, "rtsock_event: %s still has %d "
			    "LIFs waiting on DAD", dsmp->dsm_name,
			    dsmp->dsm_lif_wait);
			continue;
		}

		/*
		 * If we have some failed LIFs, then handle them now.  We'll
		 * remove them from the list.  Any leases that become empty are
		 * also removed as part of the decline-generation process.
		 */
		if (dsmp->dsm_lif_down != 0)
			send_declines(dsmp);

		if (dsmp->dsm_leases == NULL) {
			dsmp->dsm_bad_offers++;
			/*
			 * For DHCPv6, we'll process the restart once we're
			 * done sending Decline messages, because these are
			 * supposed to be acknowledged.  With DHCPv4, there's
			 * no acknowledgment for a DECLINE, so after sending
			 * it, we just restart right away.
			 */
			if (!dsmp->dsm_isv6) {
				dhcpmsg(MSG_VERBOSE, "rtsock_event: %s has no "
				    "LIFs left", dsmp->dsm_name);
				dhcp_restart(dsmp);
			}
		} else {
			/*
			 * If we're now up on at least some of the leases and
			 * we were waiting for that, then kick off the rest of
			 * configuration.  Lease validation and DAD are done.
			 */
			dhcpmsg(MSG_VERBOSE, "rtsock_event: all LIFs verified "
			    "on %s in %s state", dsmp->dsm_name,
			    dhcp_state_to_string(oldstate));
			if (oldstate == PRE_BOUND ||
			    oldstate == ADOPTING)
				dhcp_bound_complete(dsmp);
			if (oldstate == ADOPTING)
				dhcp_adopt_complete(dsmp);
		}
	}
}

/*
 * check_cmd_allowed(): check whether the requested command is allowed in the
 *			state specified.
 *
 *   input: DHCPSTATE: current state
 *	    dhcp_ipc_type_t: requested command
 *  output: boolean_t: B_TRUE if command is allowed in this state
 */

boolean_t
check_cmd_allowed(DHCPSTATE state, dhcp_ipc_type_t cmd)
{
	return (ipc_cmd_allowed[state][cmd] != 0);
}

static boolean_t
is_iscsi_active(void)
{
	int fd;
	int active = 0;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) != -1) {
		if (ioctl(fd, ISCSI_IS_ACTIVE, &active) != 0)
			active = 0;
		(void) close(fd);
	}

	return (active != 0);
}
