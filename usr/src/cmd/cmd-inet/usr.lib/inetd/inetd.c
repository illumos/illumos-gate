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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * NOTES: To be expanded.
 *
 * The SMF inetd.
 *
 * Below are some high level notes of the operation of the SMF inetd. The
 * notes don't go into any real detail, and the viewer of this file is
 * encouraged to look at the code and its associated comments to better
 * understand inetd's operation. This saves the potential for the code
 * and these notes diverging over time.
 *
 * Inetd's major work is done from the context of event_loop(). Within this
 * loop, inetd polls for events arriving from a number of different file
 * descriptors, representing the following event types, and initiates
 * any necessary event processing:
 * - incoming network connections/datagrams.
 * - notification of terminated processes (discovered via contract events).
 * - instance specific events originating from the SMF master restarter.
 * - stop/refresh requests from the inetd method processes (coming in on a
 *   Unix Domain socket).
 * There's also a timeout set for the poll, which is set to the nearest
 * scheduled timer in a timer queue that inetd uses to perform delayed
 * processing, such as bind retries.
 * The SIGHUP and SIGINT signals can also interrupt the poll, and will
 * result in inetd being refreshed or stopped respectively, as was the
 * behavior with the old inetd.
 *
 * Inetd implements a state machine for each instance. The states within the
 * machine are: offline, online, disabled, maintenance, uninitialized and
 * specializations of the offline state for when an instance exceeds one of
 * its DOS limits. The state of an instance can be changed as a
 * result/side-effect of one of the above events occurring, or inetd being
 * started up. The ongoing state of an instance is stored in the SMF
 * repository, as required of SMF restarters. This enables an administrator
 * to view the state of each instance, and, if inetd was to terminate
 * unexpectedly, it could use the stored state to re-commence where it left off.
 *
 * Within the state machine a number of methods are run (if provided) as part
 * of a state transition to aid/ effect a change in an instance's state. The
 * supported methods are: offline, online, disable, refresh and start. The
 * latter of these is the equivalent of the server program and its arguments
 * in the old inetd.
 *
 * Events from the SMF master restarter come in on a number of threads
 * created in the registration routine of librestart, the delegated restarter
 * library. These threads call into the restart_event_proxy() function
 * when an event arrives. To serialize the processing of instances, these events
 * are then written down a pipe to the process's main thread, which listens
 * for these events via a poll call, with the file descriptor of the other
 * end of the pipe in its read set, and processes the event appropriately.
 * When the event has been  processed (which may be delayed if the instance
 * for which the event is for is in the process of executing one of its methods
 * as part of a state transition) it writes an acknowledgement back down the
 * pipe the event was received on. The thread in restart_event_proxy() that
 * wrote the event will read the acknowledgement it was blocked upon, and will
 * then be able to return to its caller, thus implicitly acknowledging the
 * event, and allowing another event to be written down the pipe for the main
 * thread to process.
 */


#include <netdb.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <locale.h>
#include <syslog.h>
#include <libintl.h>
#include <librestart.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>
#include <tcpd.h>
#include <libscf.h>
#include <libuutil.h>
#include <stddef.h>
#include <bsm/adt_event.h>
#include <ucred.h>
#include "inetd_impl.h"

/* path to inetd's binary */
#define	INETD_PATH	"/usr/lib/inet/inetd"

/*
 * inetd's default configuration file paths. /etc/inetd/inetd.conf is set
 * be be the primary file, so it is checked before /etc/inetd.conf.
 */
#define	PRIMARY_DEFAULT_CONF_FILE	"/etc/inet/inetd.conf"
#define	SECONDARY_DEFAULT_CONF_FILE	"/etc/inetd.conf"

/* Arguments passed to this binary to request which method to execute. */
#define	START_METHOD_ARG	"start"
#define	STOP_METHOD_ARG		"stop"
#define	REFRESH_METHOD_ARG	"refresh"

/* connection backlog for unix domain socket */
#define	UDS_BACKLOG	2

/* number of retries to recv() a request on the UDS socket before giving up */
#define	UDS_RECV_RETRIES	10

/* enumeration of the different ends of a pipe */
enum pipe_end {
	PE_CONSUMER,
	PE_PRODUCER
};

typedef struct {
	internal_inst_state_t		istate;
	const char			*name;
	restarter_instance_state_t	smf_state;
	instance_method_t		method_running;
} state_info_t;


/*
 * Collection of information for each state.
 * NOTE:  This table is indexed into using the internal_inst_state_t
 * enumeration, so the ordering needs to be kept in synch.
 */
static state_info_t states[] = {
	{IIS_UNINITIALIZED, "uninitialized", RESTARTER_STATE_UNINIT,
	    IM_NONE},
	{IIS_ONLINE, "online", RESTARTER_STATE_ONLINE, IM_START},
	{IIS_IN_ONLINE_METHOD, "online_method", RESTARTER_STATE_OFFLINE,
	    IM_ONLINE},
	{IIS_OFFLINE, "offline", RESTARTER_STATE_OFFLINE, IM_NONE},
	{IIS_IN_OFFLINE_METHOD, "offline_method", RESTARTER_STATE_OFFLINE,
	    IM_OFFLINE},
	{IIS_DISABLED, "disabled", RESTARTER_STATE_DISABLED, IM_NONE},
	{IIS_IN_DISABLE_METHOD, "disabled_method", RESTARTER_STATE_OFFLINE,
	    IM_DISABLE},
	{IIS_IN_REFRESH_METHOD, "refresh_method", RESTARTER_STATE_ONLINE,
	    IM_REFRESH},
	{IIS_MAINTENANCE, "maintenance", RESTARTER_STATE_MAINT, IM_NONE},
	{IIS_OFFLINE_CONRATE, "cr_offline", RESTARTER_STATE_OFFLINE, IM_NONE},
	{IIS_OFFLINE_BIND, "bind_offline", RESTARTER_STATE_OFFLINE, IM_NONE},
	{IIS_OFFLINE_COPIES, "copies_offline", RESTARTER_STATE_OFFLINE,
	    IM_NONE},
	{IIS_DEGRADED, "degraded", RESTARTER_STATE_DEGRADED, IM_NONE},
	{IIS_NONE, "none", RESTARTER_STATE_NONE, IM_NONE}
};

/*
 * Pipe used to send events from the threads created by restarter_bind_handle()
 * to the main thread of control.
 */
static int			rst_event_pipe[] = {-1, -1};
/*
 * Used to protect the critical section of code in restarter_event_proxy() that
 * involves writing an event down the event pipe and reading an acknowledgement.
 */
static pthread_mutex_t		rst_event_pipe_mtx = PTHREAD_MUTEX_INITIALIZER;

/* handle used in communication with the master restarter */
static restarter_event_handle_t *rst_event_handle = NULL;

/* set to indicate a refresh of inetd is requested */
static boolean_t		refresh_inetd_requested = B_FALSE;

/* set by the SIGTERM handler to flag we got a SIGTERM */
static boolean_t		got_sigterm = B_FALSE;

/*
 * Timer queue used to store timers for delayed event processing, such as
 * bind retries.
 */
iu_tq_t				*timer_queue = NULL;

/*
 * fd of Unix Domain socket used to communicate stop and refresh requests
 * to the inetd start method process.
 */
static int			uds_fd = -1;

/*
 * List of inetd's currently managed instances; each containing its state,
 * and in certain states its configuration.
 */
static uu_list_pool_t		*instance_pool = NULL;
uu_list_t			*instance_list = NULL;

/* set to indicate we're being stopped */
boolean_t			inetd_stopping = B_FALSE;

/* TCP wrappers syslog globals. Consumed by libwrap. */
int				allow_severity = LOG_INFO;
int				deny_severity = LOG_WARNING;

/* path of the configuration file being monitored by check_conf_file() */
static char			*conf_file = NULL;

/* Auditing session handle */
static adt_session_data_t	*audit_handle;

/* Number of pending connections */
static size_t			tlx_pending_counter;

static void uds_fini(void);
static int uds_init(void);
static int run_method(instance_t *, instance_method_t, const proto_info_t *);
static void create_bound_fds(instance_t *);
static void destroy_bound_fds(instance_t *);
static void destroy_instance(instance_t *);
static void inetd_stop(void);
static void
exec_method(instance_t *instance, instance_method_t method, method_info_t *mi,
    struct method_context *mthd_ctxt, const proto_info_t *pi) __NORETURN;

/*
 * The following two functions are callbacks that libumem uses to determine
 * inetd's desired debugging/logging levels. The interface they consume is
 * exported by FMA and is consolidation private. The comments in the two
 * functions give the environment variable that will effectively be set to
 * their returned value, and thus whose behavior for this value, described in
 * umem_debug(3MALLOC), will be followed.
 */

const char *
_umem_debug_init(void)
{
	return ("default,verbose");	/* UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");	/* UMEM_LOGGING setting */
}

static void
log_invalid_cfg(const char *fmri)
{
	error_msg(gettext(
	    "Invalid configuration for instance %s, placing in maintenance"),
	    fmri);
}

/*
 * Returns B_TRUE if the instance is in a suitable state for inetd to stop.
 */
static boolean_t
instance_stopped(const instance_t *inst)
{
	return ((inst->cur_istate == IIS_OFFLINE) ||
	    (inst->cur_istate == IIS_MAINTENANCE) ||
	    (inst->cur_istate == IIS_DISABLED) ||
	    (inst->cur_istate == IIS_UNINITIALIZED));
}

/*
 * Updates the current and next repository states of instance 'inst'. If
 * any errors occur an error message is output.
 */
static void
update_instance_states(instance_t *inst, internal_inst_state_t new_cur_state,
    internal_inst_state_t new_next_state, restarter_error_t err)
{
	internal_inst_state_t	old_cur = inst->cur_istate;
	internal_inst_state_t	old_next = inst->next_istate;
	scf_error_t		sret;
	int			ret;

	/* update the repository/cached internal state */
	inst->cur_istate = new_cur_state;
	inst->next_istate = new_next_state;
	(void) set_single_rep_val(inst->cur_istate_rep,
	    (int64_t)new_cur_state);
	(void) set_single_rep_val(inst->next_istate_rep,
	    (int64_t)new_next_state);

	if (((sret = store_rep_vals(inst->cur_istate_rep, inst->fmri,
	    PR_NAME_CUR_INT_STATE)) != 0) ||
	    ((sret = store_rep_vals(inst->next_istate_rep, inst->fmri,
	    PR_NAME_NEXT_INT_STATE)) != 0))
		error_msg(gettext("Failed to update state of instance %s in "
		    "repository: %s"), inst->fmri, scf_strerror(sret));

	/* update the repository SMF state */
	if ((ret = restarter_set_states(rst_event_handle, inst->fmri,
	    states[old_cur].smf_state, states[new_cur_state].smf_state,
	    states[old_next].smf_state, states[new_next_state].smf_state,
	    err, 0)) != 0)
		error_msg(gettext("Failed to update state of instance %s in "
		    "repository: %s"), inst->fmri, strerror(ret));

}

void
update_state(instance_t *inst, internal_inst_state_t new_cur,
    restarter_error_t err)
{
	update_instance_states(inst, new_cur, IIS_NONE, err);
}

/*
 * Sends a refresh event to the inetd start method process and returns
 * SMF_EXIT_OK if it managed to send it. If it fails to send the request for
 * some reason it returns SMF_EXIT_ERR_OTHER.
 */
static int
refresh_method(void)
{
	uds_request_t   req = UR_REFRESH_INETD;
	int		fd;

	if ((fd = connect_to_inetd()) < 0) {
		error_msg(gettext("Failed to connect to inetd: %s"),
		    strerror(errno));
		return (SMF_EXIT_ERR_OTHER);
	}

	/* write the request and return success */
	if (safe_write(fd, &req, sizeof (req)) == -1) {
		error_msg(
		    gettext("Failed to send refresh request to inetd: %s"),
		    strerror(errno));
		(void) close(fd);
		return (SMF_EXIT_ERR_OTHER);
	}

	(void) close(fd);

	return (SMF_EXIT_OK);
}

/*
 * Sends a stop event to the inetd start method process and wait till it goes
 * away. If inetd is determined to have stopped SMF_EXIT_OK is returned, else
 * SMF_EXIT_ERR_OTHER is returned.
 */
static int
stop_method(void)
{
	uds_request_t   req = UR_STOP_INETD;
	int		fd;
	char		c;
	ssize_t		ret;

	if ((fd = connect_to_inetd()) == -1) {
		debug_msg(gettext("Failed to connect to inetd: %s"),
		    strerror(errno));
		/*
		 * Assume connect_to_inetd() failed because inetd was already
		 * stopped, and return success.
		 */
		return (SMF_EXIT_OK);
	}

	/*
	 * This is safe to do since we're fired off in a separate process
	 * than inetd and in the case we get wedged, the stop method timeout
	 * will occur and we'd be killed by our restarter.
	 */
	enable_blocking(fd);

	/* write the stop request to inetd and wait till it goes away */
	if (safe_write(fd, &req, sizeof (req)) != 0) {
		error_msg(gettext("Failed to send stop request to inetd"));
		(void) close(fd);
		return (SMF_EXIT_ERR_OTHER);
	}

	/* wait until remote end of socket is closed */
	while (((ret = recv(fd, &c, sizeof (c), 0)) != 0) && (errno == EINTR))
		;

	(void) close(fd);

	if (ret != 0) {
		error_msg(gettext("Failed to determine whether inetd stopped"));
		return (SMF_EXIT_ERR_OTHER);
	}

	return (SMF_EXIT_OK);
}


/*
 * This function is called to handle restarter events coming in from the
 * master restarter. It is registered with the master restarter via
 * restarter_bind_handle() and simply passes a pointer to the event down
 * the event pipe, which will be discovered by the poll in the event loop
 * and processed there. It waits for an acknowledgement to be written back down
 * the pipe before returning.
 * Writing a pointer to the function's 'event' parameter down the pipe will
 * be safe, as the thread in restarter_event_proxy() doesn't return until
 * the main thread has finished its processing of the passed event, thus
 * the referenced event will remain around until the function returns.
 * To impose the limit of only one event being in the pipe and processed
 * at once, a lock is taken on entry to this function and returned on exit.
 * Always returns 0.
 */
static int
restarter_event_proxy(restarter_event_t *event)
{
	boolean_t		processed;

	(void) pthread_mutex_lock(&rst_event_pipe_mtx);

	/* write the event to the main worker thread down the pipe */
	if (safe_write(rst_event_pipe[PE_PRODUCER], &event,
	    sizeof (event)) != 0)
		goto pipe_error;

	/*
	 * Wait for an acknowledgement that the event has been processed from
	 * the same pipe. In the case that inetd is stopping, any thread in
	 * this function will simply block on this read until inetd eventually
	 * exits. This will result in this function not returning success to
	 * its caller, and the event that was being processed when the
	 * function exited will be re-sent when inetd is next started.
	 */
	if (safe_read(rst_event_pipe[PE_PRODUCER], &processed,
	    sizeof (processed)) != 0)
		goto pipe_error;

	(void) pthread_mutex_unlock(&rst_event_pipe_mtx);

	return (processed ? 0 : EAGAIN);

pipe_error:
	/*
	 * Something's seriously wrong with the event pipe. Notify the
	 * worker thread by closing this end of the event pipe and pause till
	 * inetd exits.
	 */
	error_msg(gettext("Can't process restarter events: %s"),
	    strerror(errno));
	(void) close(rst_event_pipe[PE_PRODUCER]);
	for (;;)
		(void) pause();

	/* NOTREACHED */
}

/*
 * Let restarter_event_proxy() know we're finished with the event it's blocked
 * upon. The 'processed' argument denotes whether we successfully processed the
 * event.
 */
static void
ack_restarter_event(boolean_t processed)
{
	/*
	 * If safe_write returns -1 something's seriously wrong with the event
	 * pipe, so start the shutdown proceedings.
	 */
	if (safe_write(rst_event_pipe[PE_CONSUMER], &processed,
	    sizeof (processed)) == -1)
		inetd_stop();
}

/*
 * Switch the syslog identification string to 'ident'.
 */
static void
change_syslog_ident(const char *ident)
{
	closelog();
	openlog(ident, LOG_PID|LOG_CONS, LOG_DAEMON);
}

/*
 * Perform TCP wrappers checks on this instance. Due to the fact that the
 * current wrappers code used in Solaris is taken untouched from the open
 * source version, we're stuck with using the daemon name for the checks, as
 * opposed to making use of instance FMRIs. Sigh.
 * Returns B_TRUE if the check passed, else B_FALSE.
 */
static boolean_t
tcp_wrappers_ok(instance_t *instance)
{
	boolean_t		rval = B_TRUE;
	char			*daemon_name;
	basic_cfg_t		*cfg = instance->config->basic;
	struct request_info	req;

	/*
	 * Wrap the service using libwrap functions. The code below implements
	 * the functionality of tcpd. This is done only for stream,nowait
	 * services, following the convention of other vendors.  udp/dgram and
	 * stream/wait can NOT be wrapped with this libwrap, so be wary of
	 * changing the test below.
	 */
	if (cfg->do_tcp_wrappers && !cfg->iswait && !cfg->istlx) {

		daemon_name = instance->config->methods[
		    IM_START]->exec_args_we.we_wordv[0];
		if (*daemon_name == '/')
			daemon_name = strrchr(daemon_name, '/') + 1;

		/*
		 * Change the syslog message identity to the name of the
		 * daemon being wrapped, as opposed to "inetd".
		 */
		change_syslog_ident(daemon_name);

		(void) request_init(&req, RQ_DAEMON, daemon_name, RQ_FILE,
		    instance->conn_fd, NULL);
		fromhost(&req);

		if (strcasecmp(eval_hostname(req.client), paranoid) == 0) {
			syslog(deny_severity,
			    "refused connect from %s (name/address mismatch)",
			    eval_client(&req));
			if (req.sink != NULL)
				req.sink(instance->conn_fd);
			rval = B_FALSE;
		} else if (!hosts_access(&req)) {
			syslog(deny_severity,
			    "refused connect from %s (access denied)",
			    eval_client(&req));
			if (req.sink != NULL)
				req.sink(instance->conn_fd);
			rval = B_FALSE;
		} else {
			syslog(allow_severity, "connect from %s",
			    eval_client(&req));
		}

		/* Revert syslog identity back to "inetd". */
		change_syslog_ident(SYSLOG_IDENT);
	}
	return (rval);
}

/*
 * Handler registered with the timer queue code to remove an instance from
 * the connection rate offline state when it has been there for its allotted
 * time.
 */
/* ARGSUSED */
static void
conn_rate_online(iu_tq_t *tq, void *arg)
{
	instance_t *instance = arg;

	assert(instance->cur_istate == IIS_OFFLINE_CONRATE);
	instance->timer_id = -1;
	update_state(instance, IIS_OFFLINE, RERR_RESTART);
	process_offline_inst(instance);
}

/*
 * Check whether this instance in the offline state is in transition to
 * another state and do the work to continue this transition.
 */
void
process_offline_inst(instance_t *inst)
{
	if (inst->disable_req) {
		inst->disable_req = B_FALSE;
		(void) run_method(inst, IM_DISABLE, NULL);
	} else if (inst->maintenance_req) {
		inst->maintenance_req = B_FALSE;
		update_state(inst, IIS_MAINTENANCE, RERR_RESTART);
	/*
	 * If inetd is in the process of stopping, we don't want to enter
	 * any states but offline, disabled and maintenance.
	 */
	} else if (!inetd_stopping) {
		if (inst->conn_rate_exceeded) {
			basic_cfg_t *cfg = inst->config->basic;

			inst->conn_rate_exceeded = B_FALSE;
			update_state(inst, IIS_OFFLINE_CONRATE, RERR_RESTART);
			/*
			 * Schedule a timer to bring the instance out of the
			 * connection rate offline state.
			 */
			inst->timer_id = iu_schedule_timer(timer_queue,
			    cfg->conn_rate_offline, conn_rate_online,
			    inst);
			if (inst->timer_id == -1) {
				error_msg(gettext("%s unable to set timer, "
				    "won't be brought on line after %d "
				    "seconds."), inst->fmri,
				    cfg->conn_rate_offline);
			}

		} else if (copies_limit_exceeded(inst)) {
			update_state(inst, IIS_OFFLINE_COPIES, RERR_RESTART);
		}
	}
}

/*
 * Create a socket bound to the instance's configured address. If the
 * bind fails, returns -1, else the fd of the bound socket.
 */
static int
create_bound_socket(const instance_t *inst, socket_info_t *sock_info)
{
	int		fd;
	int		on = 1;
	const char	*fmri = inst->fmri;
	rpc_info_t	*rpc = sock_info->pr_info.ri;
	const char	*proto = sock_info->pr_info.proto;

	fd = socket(sock_info->local_addr.ss_family, sock_info->type,
	    sock_info->protocol);
	if (fd < 0) {
		error_msg(gettext(
		    "Socket creation failure for instance %s, proto %s: %s"),
		    fmri, proto, strerror(errno));
		return (-1);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) == -1) {
		error_msg(gettext("setsockopt SO_REUSEADDR failed for service "
		    "instance %s, proto %s: %s"), fmri, proto, strerror(errno));
		(void) close(fd);
		return (-1);
	}
	if (sock_info->pr_info.v6only) {
		/* restrict socket to IPv6 communications only */
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
		    sizeof (on)) == -1) {
			error_msg(gettext("setsockopt IPV6_V6ONLY failed for "
			    "service instance %s, proto %s: %s"), fmri, proto,
			    strerror(errno));
			(void) close(fd);
			return (-1);
		}
	}

	if (rpc != NULL)
		SS_SETPORT(sock_info->local_addr, 0);

	if (bind(fd, (struct sockaddr *)&(sock_info->local_addr),
	    SS_ADDRLEN(sock_info->local_addr)) < 0) {
		error_msg(gettext(
		    "Failed to bind to the port of service instance %s, "
		    "proto %s: %s"), fmri, proto, strerror(errno));
		(void) close(fd);
		return (-1);
	}

	/*
	 * Retrieve and store the address bound to for RPC services.
	 */
	if (rpc != NULL) {
		struct sockaddr_storage	ss;
		int			ss_size = sizeof (ss);

		if (getsockname(fd, (struct sockaddr *)&ss, &ss_size) < 0) {
			error_msg(gettext("Failed getsockname for instance %s, "
			    "proto %s: %s"), fmri, proto, strerror(errno));
			(void) close(fd);
			return (-1);
		}
		(void) memcpy(rpc->netbuf.buf, &ss,
		    sizeof (struct sockaddr_storage));
		rpc->netbuf.len = SS_ADDRLEN(ss);
		rpc->netbuf.maxlen = SS_ADDRLEN(ss);
	}

	if (sock_info->type == SOCK_STREAM) {
		int qlen = inst->config->basic->conn_backlog;

		debug_msg("Listening for service %s with backlog queue"
		    " size %d", fmri, qlen);
		(void) listen(fd, qlen);
	}

	return (fd);
}

/*
 * Handler registered with the timer queue code to retry the creation
 * of a bound fd.
 */
/* ARGSUSED */
static void
retry_bind(iu_tq_t *tq, void *arg)
{
	instance_t *instance = arg;

	switch (instance->cur_istate) {
	case IIS_OFFLINE_BIND:
	case IIS_ONLINE:
	case IIS_DEGRADED:
	case IIS_IN_ONLINE_METHOD:
	case IIS_IN_REFRESH_METHOD:
		break;
	default:
#ifndef NDEBUG
		(void) fprintf(stderr, "%s:%d: Unknown instance state %d.\n",
		    __FILE__, __LINE__, instance->cur_istate);
#endif
		abort();
	}

	instance->bind_timer_id = -1;
	create_bound_fds(instance);
}

/*
 * For each of the fds for the given instance that are bound, if 'listen' is
 * set add them to the poll set, else remove them from it. If any additions
 * fail, returns -1, else 0 on success.
 */
int
poll_bound_fds(instance_t *instance, boolean_t listen)
{
	basic_cfg_t	*cfg = instance->config->basic;
	proto_info_t	*pi;
	int		ret = 0;

	for (pi = uu_list_first(cfg->proto_list); pi != NULL;
	    pi = uu_list_next(cfg->proto_list, pi)) {
		if (pi->listen_fd != -1) {	/* fd bound */
			if (!listen) {
				clear_pollfd(pi->listen_fd);
			} else if (set_pollfd(pi->listen_fd, POLLIN) == -1) {
				ret = -1;
			}
		}
	}

	return (ret);
}

/*
 * Handle the case were we either fail to create a bound fd or we fail
 * to add a bound fd to the poll set for the given instance.
 */
static void
handle_bind_failure(instance_t *instance)
{
	basic_cfg_t *cfg = instance->config->basic;

	/*
	 * We must be being called as a result of a failed poll_bound_fds()
	 * as a bind retry is already scheduled. Just return and let it do
	 * the work.
	 */
	if (instance->bind_timer_id != -1)
		return;

	/*
	 * Check if the rebind retries limit is operative and if so,
	 * if it has been reached.
	 */
	if (((cfg->bind_fail_interval <= 0) ||		/* no retries */
	    ((cfg->bind_fail_max >= 0) &&		/* limit reached */
	    (++instance->bind_fail_count > cfg->bind_fail_max))) ||
	    ((instance->bind_timer_id = iu_schedule_timer(timer_queue,
	    cfg->bind_fail_interval, retry_bind, instance)) == -1)) {
		proto_info_t *pi;

		instance->bind_fail_count = 0;

		switch (instance->cur_istate) {
		case IIS_DEGRADED:
		case IIS_ONLINE:
			/* check if any of the fds are being poll'd upon */
			for (pi = uu_list_first(cfg->proto_list); pi != NULL;
			    pi = uu_list_next(cfg->proto_list, pi)) {
				if ((pi->listen_fd != -1) &&
				    (find_pollfd(pi->listen_fd) != NULL))
					break;
			}
			if (pi != NULL)	{	/* polling on > 0 fds */
				warn_msg(gettext("Failed to bind on "
				    "all protocols for instance %s, "
				    "transitioning to degraded"),
				    instance->fmri);
				update_state(instance, IIS_DEGRADED, RERR_NONE);
				instance->bind_retries_exceeded = B_TRUE;
				break;
			}

			destroy_bound_fds(instance);
			/*
			 * In the case we failed the 'bind' because set_pollfd()
			 * failed on all bound fds, use the offline handling.
			 */
			/* FALLTHROUGH */
		case IIS_OFFLINE:
		case IIS_OFFLINE_BIND:
			error_msg(gettext("Too many bind failures for instance "
			"%s, transitioning to maintenance"), instance->fmri);
			update_state(instance, IIS_MAINTENANCE,
			    RERR_FAULT);
			break;
		case IIS_IN_ONLINE_METHOD:
		case IIS_IN_REFRESH_METHOD:
			warn_msg(gettext("Failed to bind on all "
			    "protocols for instance %s, instance will go to "
			    "degraded"), instance->fmri);
			/*
			 * Set the retries exceeded flag so when the method
			 * completes the instance goes to the degraded state.
			 */
			instance->bind_retries_exceeded = B_TRUE;
			break;
		default:
#ifndef NDEBUG
			(void) fprintf(stderr,
			    "%s:%d: Unknown instance state %d.\n",
			    __FILE__, __LINE__, instance->cur_istate);
#endif
			abort();
		}
	} else if (instance->cur_istate == IIS_OFFLINE) {
		/*
		 * bind re-scheduled, so if we're offline reflect this in the
		 * state.
		 */
		update_state(instance, IIS_OFFLINE_BIND, RERR_NONE);
	}
}


/*
 * Check if two transport protocols for RPC conflict.
 */

boolean_t
is_rpc_proto_conflict(const char *proto0, const char *proto1) {
	if (strcmp(proto0, "tcp") == 0) {
		if (strcmp(proto1, "tcp") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "tcp6") == 0)
			return (B_TRUE);
		return (B_FALSE);
	}

	if (strcmp(proto0, "tcp6") == 0) {
		if (strcmp(proto1, "tcp") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "tcp6only") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "tcp6") == 0)
			return (B_TRUE);
		return (B_FALSE);
	}

	if (strcmp(proto0, "tcp6only") == 0) {
		if (strcmp(proto1, "tcp6only") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "tcp6") == 0)
			return (B_TRUE);
		return (B_FALSE);
	}

	if (strcmp(proto0, "udp") == 0) {
		if (strcmp(proto1, "udp") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "udp6") == 0)
			return (B_TRUE);
		return (B_FALSE);
	}

	if (strcmp(proto0, "udp6") == 0) {

		if (strcmp(proto1, "udp") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "udp6only") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "udp6") == 0)
			return (B_TRUE);
		return (B_FALSE);
	}

	if (strcmp(proto0, "udp6only") == 0) {

		if (strcmp(proto1, "udp6only") == 0)
			return (B_TRUE);
		if (strcmp(proto1, "udp6") == 0)
			return (B_TRUE);
		return (0);
	}

	/*
	 * If the protocol isn't TCP/IP or UDP/IP assume that it has its own
	 * port namepsace and that conflicts can be detected by literal string
	 * comparison.
	 */

	if (strcmp(proto0, proto1))
		return (FALSE);

	return (B_TRUE);
}


/*
 * Check if inetd thinks this RPC program number is already registered.
 *
 * An RPC protocol conflict occurs if
 * 	a) the program numbers are the same and,
 * 	b) the version numbers overlap,
 * 	c) the protocols (TCP vs UDP vs tic*) are the same.
 */

boolean_t
is_rpc_num_in_use(int rpc_n, char *proto, int lowver, int highver) {
	instance_t *i;
	basic_cfg_t *cfg;
	proto_info_t *pi;

	for (i = uu_list_first(instance_list); i != NULL;
	    i = uu_list_next(instance_list, i)) {

		if (i->cur_istate != IIS_ONLINE)
			continue;
		cfg = i->config->basic;

		for (pi = uu_list_first(cfg->proto_list); pi != NULL;
		    pi = uu_list_next(cfg->proto_list, pi)) {

			if (pi->ri == NULL)
				continue;
			if (pi->ri->prognum != rpc_n)
				continue;
			if (!is_rpc_proto_conflict(pi->proto, proto))
				continue;
			if ((lowver < pi->ri->lowver &&
			    highver < pi->ri->lowver) ||
			    (lowver > pi->ri->highver &&
			    highver > pi->ri->highver))
				continue;
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}


/*
 * Independent of the transport, for each of the entries in the instance's
 * proto list this function first attempts to create an associated network fd;
 * for RPC services these are then bound to a kernel chosen port and the
 * fd is registered with rpcbind; for non-RPC services the fds are bound
 * to the port associated with the instance's service name. On any successful
 * binds the instance is taken online. Failed binds are handled by
 * handle_bind_failure().
 */
void
create_bound_fds(instance_t *instance)
{
	basic_cfg_t	*cfg = instance->config->basic;
	boolean_t	failure = B_FALSE;
	boolean_t	success = B_FALSE;
	proto_info_t	*pi;

	/*
	 * Loop through and try and bind any unbound protos.
	 */
	for (pi = uu_list_first(cfg->proto_list); pi != NULL;
	    pi = uu_list_next(cfg->proto_list, pi)) {
		if (pi->listen_fd != -1)
			continue;
		if (cfg->istlx) {
			pi->listen_fd = create_bound_endpoint(instance,
			    (tlx_info_t *)pi);
		} else {
			/*
			 * We cast pi to a void so we can then go on to cast
			 * it to a socket_info_t without lint complaining
			 * about alignment. This is done because the x86
			 * version of lint thinks a lint suppression directive
			 * is unnecessary and flags it as such, yet the sparc
			 * version complains if it's absent.
			 */
			void *p = pi;
			pi->listen_fd = create_bound_socket(instance,
			    (socket_info_t *)p);
		}
		if (pi->listen_fd == -1) {
			failure = B_TRUE;
			continue;
		}

		if (pi->ri != NULL) {

			/*
			 * Don't register the same RPC program number twice.
			 * Doing so silently discards the old service
			 * without causing an error.
			 */
			if (is_rpc_num_in_use(pi->ri->prognum, pi->proto,
			    pi->ri->lowver, pi->ri->highver)) {
				failure = B_TRUE;
				close_net_fd(instance, pi->listen_fd);
				pi->listen_fd = -1;
				continue;
			}

			unregister_rpc_service(instance->fmri, pi->ri);
			if (register_rpc_service(instance->fmri, pi->ri) ==
			    -1) {
				close_net_fd(instance, pi->listen_fd);
				pi->listen_fd = -1;
				failure = B_TRUE;
				continue;
			}
		}

		success = B_TRUE;
	}

	switch (instance->cur_istate) {
	case IIS_OFFLINE:
	case IIS_OFFLINE_BIND:
		/*
		 * If we've managed to bind at least one proto lets run the
		 * online method, so we can start listening for it.
		 */
		if (success && run_method(instance, IM_ONLINE, NULL) == -1)
			return;	/* instance gone to maintenance */
		break;
	case IIS_ONLINE:
	case IIS_IN_REFRESH_METHOD:
		/*
		 * We're 'online', so start polling on any bound fds we're
		 * currently not.
		 */
		if (poll_bound_fds(instance, B_TRUE) != 0) {
			failure = B_TRUE;
		} else if (!failure) {
			/*
			 * We've successfully bound and poll'd upon all protos,
			 * so reset the failure count.
			 */
			instance->bind_fail_count = 0;
		}
		break;
	case IIS_IN_ONLINE_METHOD:
		/*
		 * Nothing to do here as the method completion code will start
		 * listening for any successfully bound fds.
		 */
		break;
	default:
#ifndef NDEBUG
		(void) fprintf(stderr, "%s:%d: Unknown instance state %d.\n",
		    __FILE__, __LINE__, instance->cur_istate);
#endif
		abort();
	}

	if (failure)
		handle_bind_failure(instance);
}

/*
 * Counter to create_bound_fds(), for each of the bound network fds this
 * function unregisters the instance from rpcbind if it's an RPC service,
 * stops listening for new connections for it and then closes the listening fd.
 */
static void
destroy_bound_fds(instance_t *instance)
{
	basic_cfg_t	*cfg = instance->config->basic;
	proto_info_t	*pi;

	for (pi = uu_list_first(cfg->proto_list); pi != NULL;
	    pi = uu_list_next(cfg->proto_list, pi)) {
		if (pi->listen_fd != -1) {
			if (pi->ri != NULL)
				unregister_rpc_service(instance->fmri, pi->ri);
			clear_pollfd(pi->listen_fd);
			close_net_fd(instance, pi->listen_fd);
			pi->listen_fd = -1;
		}
	}

	/* cancel any bind retries */
	if (instance->bind_timer_id != -1)
		cancel_bind_timer(instance);

	instance->bind_retries_exceeded = B_FALSE;
}

/*
 * Perform %A address expansion and return a pointer to a static string
 * array containing crafted arguments. This expansion is provided for
 * compatibility with 4.2BSD daemons, and as such we've copied the logic of
 * the legacy inetd to maintain this compatibility as much as possible. This
 * logic is a bit scatty, but it dates back at least as far as SunOS 4.x.
 */
static char **
expand_address(instance_t *inst, const proto_info_t *pi)
{
	static char	addrbuf[sizeof ("ffffffff.65536")];
	static char	*ret[3];
	instance_cfg_t	*cfg = inst->config;
	/*
	 * We cast pi to a void so we can then go on to cast it to a
	 * socket_info_t without lint complaining about alignment. This
	 * is done because the x86 version of lint thinks a lint suppression
	 * directive is unnecessary and flags it as such, yet the sparc
	 * version complains if it's absent.
	 */
	const void	*p = pi;

	/* set ret[0] to the basename of exec path */
	if ((ret[0] = strrchr(cfg->methods[IM_START]->exec_path, '/'))
	    != NULL) {
		ret[0]++;
	} else {
		ret[0] = cfg->methods[IM_START]->exec_path;
	}

	if (!cfg->basic->istlx &&
	    (((socket_info_t *)p)->type == SOCK_DGRAM)) {
		ret[1] = NULL;
	} else {
		addrbuf[0] = '\0';
		if (!cfg->basic->iswait &&
		    (inst->remote_addr.ss_family == AF_INET)) {
			struct sockaddr_in *sp;

			sp = (struct sockaddr_in *)&(inst->remote_addr);
			(void) snprintf(addrbuf, sizeof (addrbuf), "%x.%hu",
			    ntohl(sp->sin_addr.s_addr), ntohs(sp->sin_port));
		}
		ret[1] = addrbuf;
		ret[2] = NULL;
	}

	return (ret);
}

/*
 * Returns the state associated with the supplied method being run for an
 * instance.
 */
static internal_inst_state_t
get_method_state(instance_method_t method)
{
	state_info_t *sip;

	for (sip = states; sip->istate != IIS_NONE; sip++) {
		if (sip->method_running == method)
			break;
	}
	assert(sip->istate != IIS_NONE);

	return (sip->istate);
}

/*
 * Store the method's PID and CID in the repository. If the store fails
 * we ignore it and just drive on.
 */
static void
add_method_ids(instance_t *ins, pid_t pid, ctid_t cid, instance_method_t mthd)
{
	if (cid != -1)
		(void) add_remove_contract(ins, B_TRUE, cid);

	if (mthd == IM_START) {
		if (add_rep_val(ins->start_pids, (int64_t)pid) == 0) {
			(void) store_rep_vals(ins->start_pids, ins->fmri,
			    PR_NAME_START_PIDS);
		}
	} else {
		if (add_rep_val(ins->non_start_pid, (int64_t)pid) == 0) {
			(void) store_rep_vals(ins->non_start_pid, ins->fmri,
			    PR_NAME_NON_START_PID);
		}
	}
}

/*
 * Remove the method's PID and CID from the repository. If the removal
 * fails we ignore it and drive on.
 */
void
remove_method_ids(instance_t *inst, pid_t pid, ctid_t cid,
    instance_method_t mthd)
{
	if (cid != -1)
		(void) add_remove_contract(inst, B_FALSE, cid);

	if (mthd == IM_START) {
		remove_rep_val(inst->start_pids, (int64_t)pid);
		(void) store_rep_vals(inst->start_pids, inst->fmri,
		    PR_NAME_START_PIDS);
	} else {
		remove_rep_val(inst->non_start_pid, (int64_t)pid);
		(void) store_rep_vals(inst->non_start_pid, inst->fmri,
		    PR_NAME_NON_START_PID);
	}
}

static instance_t *
create_instance(const char *fmri)
{
	instance_t *ret;

	if (((ret = calloc(1, sizeof (instance_t))) == NULL) ||
	    ((ret->fmri = strdup(fmri)) == NULL))
		goto alloc_fail;

	ret->conn_fd = -1;

	ret->copies = 0;

	ret->conn_rate_count = 0;
	ret->fail_rate_count = 0;
	ret->bind_fail_count = 0;

	if (((ret->non_start_pid = create_rep_val_list()) == NULL) ||
	    ((ret->start_pids = create_rep_val_list()) == NULL) ||
	    ((ret->start_ctids = create_rep_val_list()) == NULL))
		goto alloc_fail;

	ret->cur_istate = IIS_NONE;
	ret->next_istate = IIS_NONE;

	if (((ret->cur_istate_rep = create_rep_val_list()) == NULL) ||
	    ((ret->next_istate_rep = create_rep_val_list()) == NULL))
		goto alloc_fail;

	ret->config = NULL;
	ret->new_config = NULL;

	ret->timer_id = -1;
	ret->bind_timer_id = -1;

	ret->disable_req = B_FALSE;
	ret->maintenance_req = B_FALSE;
	ret->conn_rate_exceeded = B_FALSE;
	ret->bind_retries_exceeded = B_FALSE;

	ret->pending_rst_event = RESTARTER_EVENT_TYPE_INVALID;

	return (ret);

alloc_fail:
	error_msg(strerror(errno));
	destroy_instance(ret);
	return (NULL);
}

static void
destroy_instance(instance_t *inst)
{
	if (inst == NULL)
		return;

	destroy_instance_cfg(inst->config);
	destroy_instance_cfg(inst->new_config);

	destroy_rep_val_list(inst->cur_istate_rep);
	destroy_rep_val_list(inst->next_istate_rep);

	destroy_rep_val_list(inst->start_pids);
	destroy_rep_val_list(inst->non_start_pid);
	destroy_rep_val_list(inst->start_ctids);

	free(inst->fmri);

	free(inst);
}

/*
 * Retrieves the current and next states internal states. Returns 0 on success,
 * else returns one of the following on error:
 * SCF_ERROR_NO_MEMORY if memory allocation failed.
 * SCF_ERROR_CONNECTION_BROKEN if the connection to the repository was broken.
 * SCF_ERROR_TYPE_MISMATCH if the property was of an unexpected type.
 * SCF_ERROR_NO_RESOURCES if the server doesn't have adequate resources.
 * SCF_ERROR_NO_SERVER if the server isn't running.
 */
static scf_error_t
retrieve_instance_state(instance_t *inst)
{
	scf_error_t	ret;

	/* retrieve internal states */
	if (((ret = retrieve_rep_vals(inst->cur_istate_rep, inst->fmri,
	    PR_NAME_CUR_INT_STATE)) != 0) ||
	    ((ret = retrieve_rep_vals(inst->next_istate_rep, inst->fmri,
	    PR_NAME_NEXT_INT_STATE)) != 0)) {
		if (ret != SCF_ERROR_NOT_FOUND) {
			error_msg(gettext(
			    "Failed to read state of instance %s: %s"),
			    inst->fmri, scf_strerror(scf_error()));
			return (ret);
		}

		debug_msg("instance with no previous int state - "
		    "setting state to uninitialized");

		if ((set_single_rep_val(inst->cur_istate_rep,
		    (int64_t)IIS_UNINITIALIZED) == -1) ||
		    (set_single_rep_val(inst->next_istate_rep,
		    (int64_t)IIS_NONE) == -1)) {
			return (SCF_ERROR_NO_MEMORY);
		}
	}

	/* update convenience states */
	inst->cur_istate = get_single_rep_val(inst->cur_istate_rep);
	inst->next_istate = get_single_rep_val(inst->next_istate_rep);
	return (0);
}

/*
 * Retrieve stored process ids and register each of them so we process their
 * termination.
 */
static int
retrieve_method_pids(instance_t *inst)
{
	rep_val_t	*rv;

	switch (retrieve_rep_vals(inst->start_pids, inst->fmri,
	    PR_NAME_START_PIDS)) {
	case 0:
		break;
	case SCF_ERROR_NOT_FOUND:
		return (0);
	default:
		error_msg(gettext("Failed to retrieve the start pids of "
		    "instance %s from repository: %s"), inst->fmri,
		    scf_strerror(scf_error()));
		return (-1);
	}

	rv = uu_list_first(inst->start_pids);
	while (rv != NULL) {
		if (register_method(inst, (pid_t)rv->val, (ctid_t)-1,
		    IM_START) == 0) {
			inst->copies++;
			rv = uu_list_next(inst->start_pids, rv);
		} else if (errno == ENOENT) {
			pid_t pid = (pid_t)rv->val;

			/*
			 * The process must have already terminated. Remove
			 * it from the list.
			 */
			rv = uu_list_next(inst->start_pids, rv);
			remove_rep_val(inst->start_pids, pid);
		} else {
			error_msg(gettext("Failed to listen for the completion "
			    "of %s method of instance %s"), START_METHOD_NAME,
			    inst->fmri);
			rv = uu_list_next(inst->start_pids, rv);
		}
	}

	/* synch the repository pid list to remove any terminated pids */
	(void) store_rep_vals(inst->start_pids, inst->fmri, PR_NAME_START_PIDS);

	return (0);
}

/*
 * Remove the passed instance from inetd control.
 */
static void
remove_instance(instance_t *instance)
{
	switch (instance->cur_istate) {
	case IIS_ONLINE:
	case IIS_DEGRADED:
		/* stop listening for network connections */
		destroy_bound_fds(instance);
		break;
	case IIS_OFFLINE_BIND:
		cancel_bind_timer(instance);
		break;
	case IIS_OFFLINE_CONRATE:
		cancel_inst_timer(instance);
		break;
	}

	/* stop listening for terminated methods */
	unregister_instance_methods(instance);

	uu_list_remove(instance_list, instance);
	destroy_instance(instance);
}

/*
 * Refresh the configuration of instance 'inst'. This method gets called as
 * a result of a refresh event for the instance from the master restarter, so
 * we can rely upon the instance's running snapshot having been updated from
 * its configuration snapshot.
 */
void
refresh_instance(instance_t *inst)
{
	instance_cfg_t	*cfg;

	switch (inst->cur_istate) {
	case IIS_MAINTENANCE:
	case IIS_DISABLED:
	case IIS_UNINITIALIZED:
		/*
		 * Ignore any possible changes, we'll re-read the configuration
		 * automatically when we exit these states.
		 */
		break;

	case IIS_OFFLINE_COPIES:
	case IIS_OFFLINE_BIND:
	case IIS_OFFLINE:
	case IIS_OFFLINE_CONRATE:
		destroy_instance_cfg(inst->config);
		if ((inst->config = read_instance_cfg(inst->fmri)) == NULL) {
			log_invalid_cfg(inst->fmri);
			if (inst->cur_istate == IIS_OFFLINE_BIND) {
				cancel_bind_timer(inst);
			} else if (inst->cur_istate == IIS_OFFLINE_CONRATE) {
				cancel_inst_timer(inst);
			}
			update_state(inst, IIS_MAINTENANCE, RERR_FAULT);
		} else {
			switch (inst->cur_istate) {
			case IIS_OFFLINE_BIND:
				if (copies_limit_exceeded(inst)) {
					/* Cancel scheduled bind retries. */
					cancel_bind_timer(inst);

					/*
					 * Take the instance to the copies
					 * offline state, via the offline
					 * state.
					 */
					update_state(inst, IIS_OFFLINE,
					    RERR_RESTART);
					process_offline_inst(inst);
				}
				break;

			case IIS_OFFLINE:
				process_offline_inst(inst);
				break;

			case IIS_OFFLINE_CONRATE:
				/*
				 * Since we're already in a DOS state,
				 * don't bother evaluating the copies
				 * limit. This will be evaluated when
				 * we leave this state in
				 * process_offline_inst().
				 */
				break;

			case IIS_OFFLINE_COPIES:
				/*
				 * Check if the copies limit has been increased
				 * above the current count.
				 */
				if (!copies_limit_exceeded(inst)) {
					update_state(inst, IIS_OFFLINE,
					    RERR_RESTART);
					process_offline_inst(inst);
				}
				break;

			default:
				assert(0);
			}
		}
		break;

	case IIS_DEGRADED:
	case IIS_ONLINE:
		if ((cfg = read_instance_cfg(inst->fmri)) != NULL) {
			instance_cfg_t *ocfg = inst->config;

			/*
			 * Try to avoid the overhead of taking an instance
			 * offline and back on again. We do this by limiting
			 * this behavior to two eventualities:
			 * - there needs to be a re-bind to listen on behalf
			 *   of the instance with its new configuration. This
			 *   could be because for example its service has been
			 *   associated with a different port, or because the
			 *   v6only protocol option has been newly applied to
			 *   the instance.
			 * - one or both of the start or online methods of the
			 *   instance have changed in the new configuration.
			 *   Without taking the instance offline when the
			 *   start method changed the instance may be running
			 *   with unwanted parameters (or event an unwanted
			 *   binary); and without taking the instance offline
			 *   if its online method was to change, some part of
			 *   its running environment may have changed and would
			 *   not be picked up until the instance next goes
			 *   offline for another reason.
			 */
			if ((!bind_config_equal(ocfg->basic, cfg->basic)) ||
			    !method_info_equal(ocfg->methods[IM_ONLINE],
			    cfg->methods[IM_ONLINE]) ||
			    !method_info_equal(ocfg->methods[IM_START],
			    cfg->methods[IM_START])) {
				destroy_bound_fds(inst);

				assert(inst->new_config == NULL);
				inst->new_config = cfg;

				(void) run_method(inst, IM_OFFLINE, NULL);
			} else {	/* no bind config / method changes */

				/*
				 * swap the proto list over from the old
				 * configuration to the new, so we retain
				 * our set of network fds.
				 */
				destroy_proto_list(cfg->basic);
				cfg->basic->proto_list =
				    ocfg->basic->proto_list;
				ocfg->basic->proto_list = NULL;
				destroy_instance_cfg(ocfg);
				inst->config = cfg;

				/* re-evaluate copies limits based on new cfg */
				if (copies_limit_exceeded(inst)) {
					destroy_bound_fds(inst);
					(void) run_method(inst, IM_OFFLINE,
					    NULL);
				} else {
					/*
					 * Since the instance isn't being
					 * taken offline, where we assume it
					 * would pick-up any configuration
					 * changes automatically when it goes
					 * back online, run its refresh method
					 * to allow it to pick-up any changes
					 * whilst still online.
					 */
					(void) run_method(inst, IM_REFRESH,
					    NULL);
				}
			}
		} else {
			log_invalid_cfg(inst->fmri);

			destroy_bound_fds(inst);

			inst->maintenance_req = B_TRUE;
			(void) run_method(inst, IM_OFFLINE, NULL);
		}
		break;

	default:
		debug_msg("Unhandled current state %d for instance in "
		    "refresh_instance", inst->cur_istate);
		assert(0);
	}
}

/*
 * Called by process_restarter_event() to handle a restarter event for an
 * instance.
 */
static void
handle_restarter_event(instance_t *instance, restarter_event_type_t event,
    boolean_t send_ack)
{
	switch (event) {
	case RESTARTER_EVENT_TYPE_ADD_INSTANCE:
		/*
		 * When startd restarts, it sends _ADD_INSTANCE to delegated
		 * restarters for all those services managed by them. We should
		 * acknowledge this event, as startd's graph needs to be updated
		 * about the current state of the service, when startd is
		 * restarting.
		 * update_state() is ok to be called here, as commands for
		 * instances in transition are deferred by
		 * process_restarter_event().
		 */
		update_state(instance, instance->cur_istate, RERR_NONE);
		goto done;
	case RESTARTER_EVENT_TYPE_ADMIN_REFRESH:
		refresh_instance(instance);
		goto done;
	case RESTARTER_EVENT_TYPE_ADMIN_RESTART:
		/*
		 * We've got a restart event, so if the instance is online
		 * in any way initiate taking it offline, and rely upon
		 * our restarter to send us an online event to bring
		 * it back online.
		 */
		switch (instance->cur_istate) {
		case IIS_ONLINE:
		case IIS_DEGRADED:
			destroy_bound_fds(instance);
			(void) run_method(instance, IM_OFFLINE, NULL);
		}
		goto done;
	case RESTARTER_EVENT_TYPE_REMOVE_INSTANCE:
		remove_instance(instance);
		goto done;
	case RESTARTER_EVENT_TYPE_STOP:
		switch (instance->cur_istate) {
		case IIS_OFFLINE_CONRATE:
		case IIS_OFFLINE_BIND:
		case IIS_OFFLINE_COPIES:
			/*
			 * inetd must be closing down as we wouldn't get this
			 * event in one of these states from the master
			 * restarter. Take the instance to the offline resting
			 * state.
			 */
			if (instance->cur_istate == IIS_OFFLINE_BIND) {
				cancel_bind_timer(instance);
			} else if (instance->cur_istate ==
			    IIS_OFFLINE_CONRATE) {
				cancel_inst_timer(instance);
			}
			update_state(instance, IIS_OFFLINE, RERR_RESTART);
			goto done;
		}
		break;
	}

	switch (instance->cur_istate) {
	case IIS_OFFLINE:
		switch (event) {
		case RESTARTER_EVENT_TYPE_START:
			/*
			 * Dependencies are met, let's take the service online.
			 * Only try and bind for a wait type service if
			 * no process is running on its behalf. Otherwise, just
			 * mark the service online and binding will be attempted
			 * when the process exits.
			 */
			if (!(instance->config->basic->iswait &&
			    (uu_list_first(instance->start_pids) != NULL))) {
				create_bound_fds(instance);
			} else {
				update_state(instance, IIS_ONLINE, RERR_NONE);
			}
			break;
		case RESTARTER_EVENT_TYPE_DISABLE:
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			/*
			 * The instance should be disabled, so run the
			 * instance's disabled method that will do the work
			 * to take it there.
			 */
			(void) run_method(instance, IM_DISABLE, NULL);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			/*
			 * The master restarter has requested the instance
			 * go to maintenance; since we're already offline
			 * just update the state to the maintenance state.
			 */
			update_state(instance, IIS_MAINTENANCE, RERR_RESTART);
			break;
		}
		break;

	case IIS_OFFLINE_BIND:
		switch (event) {
		case RESTARTER_EVENT_TYPE_DISABLE:
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			/*
			 * The instance should be disabled. Firstly, as for
			 * the above dependencies unmet comment, cancel
			 * the bind retry timer and update the state to
			 * offline. Then, run the disable method to do the
			 * work to take the instance from offline to
			 * disabled.
			 */
			cancel_bind_timer(instance);
			update_state(instance, IIS_OFFLINE, RERR_RESTART);
			(void) run_method(instance, IM_DISABLE, NULL);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			/*
			 * The master restarter has requested the instance
			 * be placed in the maintenance state. Cancel the
			 * outstanding retry timer, and since we're already
			 * offline, update the state to maintenance.
			 */
			cancel_bind_timer(instance);
			update_state(instance, IIS_MAINTENANCE, RERR_RESTART);
			break;
		}
		break;

	case IIS_DEGRADED:
	case IIS_ONLINE:
		switch (event) {
		case RESTARTER_EVENT_TYPE_DISABLE:
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			/*
			 * The instance needs to be disabled. Do the same work
			 * as for the dependencies unmet event below to
			 * take the instance offline.
			 */
			destroy_bound_fds(instance);
			/*
			 * Indicate that the offline method is being run
			 * as part of going to the disabled state, and to
			 * carry on this transition.
			 */
			instance->disable_req = B_TRUE;
			(void) run_method(instance, IM_OFFLINE, NULL);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			/*
			 * The master restarter has requested the instance be
			 * placed in the maintenance state. This involves
			 * firstly taking the service offline, so do the
			 * same work as for the dependencies unmet event
			 * below. We set the maintenance_req flag to
			 * indicate that when we get to the offline state
			 * we should be placed directly into the maintenance
			 * state.
			 */
			instance->maintenance_req = B_TRUE;
			/* FALLTHROUGH */
		case RESTARTER_EVENT_TYPE_STOP:
			/*
			 * Dependencies have become unmet. Close and
			 * stop listening on the instance's network file
			 * descriptor, and run the offline method to do
			 * any work required to take us to the offline state.
			 */
			destroy_bound_fds(instance);
			(void) run_method(instance, IM_OFFLINE, NULL);
		}
		break;

	case IIS_UNINITIALIZED:
		if (event == RESTARTER_EVENT_TYPE_DISABLE ||
		    event == RESTARTER_EVENT_TYPE_ADMIN_DISABLE) {
			update_state(instance, IIS_DISABLED, RERR_NONE);
			break;
		} else if (event != RESTARTER_EVENT_TYPE_ENABLE) {
			/*
			 * Ignore other events until we know whether we're
			 * enabled or not.
			 */
			break;
		}

		/*
		 * We've got an enabled event; make use of the handling in the
		 * disable case.
		 */
		/* FALLTHROUGH */

	case IIS_DISABLED:
		switch (event) {
		case RESTARTER_EVENT_TYPE_ENABLE:
			/*
			 * The instance needs enabling. Commence reading its
			 * configuration and if successful place the instance
			 * in the offline state and let process_offline_inst()
			 * take it from there.
			 */
			destroy_instance_cfg(instance->config);
			instance->config = read_instance_cfg(instance->fmri);
			if (instance->config != NULL) {
				update_state(instance, IIS_OFFLINE,
				    RERR_RESTART);
				process_offline_inst(instance);
			} else {
				log_invalid_cfg(instance->fmri);
				update_state(instance, IIS_MAINTENANCE,
				    RERR_RESTART);
			}

			break;
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			/*
			 * The master restarter has requested the instance be
			 * placed in the maintenance state, so just update its
			 * state to maintenance.
			 */
			update_state(instance, IIS_MAINTENANCE, RERR_RESTART);
			break;
		}
		break;

	case IIS_MAINTENANCE:
		switch (event) {
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF:
		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			/*
			 * The master restarter has requested that the instance
			 * be taken out of maintenance. Read its configuration,
			 * and if successful place the instance in the offline
			 * state and call process_offline_inst() to take it
			 * from there.
			 */
			destroy_instance_cfg(instance->config);
			instance->config = read_instance_cfg(instance->fmri);
			if (instance->config != NULL) {
				update_state(instance, IIS_OFFLINE,
				    RERR_RESTART);
				process_offline_inst(instance);
			} else {
				boolean_t enabled;

				/*
				 * The configuration was invalid. If the
				 * service has disabled requested, let's
				 * just place the instance in disabled even
				 * though we haven't been able to run its
				 * disable method, as the slightly incorrect
				 * state is likely to be less of an issue to
				 * an administrator than refusing to move an
				 * instance to disabled. If disable isn't
				 * requested, re-mark the service's state
				 * as maintenance, so the administrator can
				 * see the request was processed.
				 */
				if ((read_enable_merged(instance->fmri,
				    &enabled) == 0) && !enabled) {
					update_state(instance, IIS_DISABLED,
					    RERR_RESTART);
				} else {
					log_invalid_cfg(instance->fmri);
					update_state(instance, IIS_MAINTENANCE,
					    RERR_FAULT);
				}
			}
			break;
		}
		break;

	case IIS_OFFLINE_CONRATE:
		switch (event) {
		case RESTARTER_EVENT_TYPE_DISABLE:
			/*
			 * The instance wants disabling. Take the instance
			 * offline as for the dependencies unmet event above,
			 * and then from there run the disable method to do
			 * the work to take the instance to the disabled state.
			 */
			cancel_inst_timer(instance);
			update_state(instance, IIS_OFFLINE, RERR_RESTART);
			(void) run_method(instance, IM_DISABLE, NULL);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			/*
			 * The master restarter has requested the instance
			 * be taken to maintenance. Cancel the timer setup
			 * when we entered this state, and go directly to
			 * maintenance.
			 */
			cancel_inst_timer(instance);
			update_state(instance, IIS_MAINTENANCE, RERR_RESTART);
			break;
		}
		break;

	case IIS_OFFLINE_COPIES:
		switch (event) {
		case RESTARTER_EVENT_TYPE_DISABLE:
			/*
			 * The instance wants disabling. Update the state
			 * to offline, and run the disable method to do the
			 * work to take it to the disabled state.
			 */
			update_state(instance, IIS_OFFLINE, RERR_RESTART);
			(void) run_method(instance, IM_DISABLE, NULL);
			break;
		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			/*
			 * The master restarter has requested the instance be
			 * placed in maintenance. Since it's already offline
			 * simply update the state.
			 */
			update_state(instance, IIS_MAINTENANCE, RERR_RESTART);
			break;
		}
		break;

	default:
		debug_msg("handle_restarter_event: instance in an "
		    "unexpected state");
		assert(0);
	}

done:
	if (send_ack)
		ack_restarter_event(B_TRUE);
}

/*
 * Tries to read and process an event from the event pipe. If there isn't one
 * or an error occurred processing the event it returns -1. Else, if the event
 * is for an instance we're not already managing we read its state, add it to
 * our list to manage, and if appropriate read its configuration. Whether it's
 * new to us or not, we then handle the specific event.
 * Returns 0 if an event was read and processed successfully, else -1.
 */
static int
process_restarter_event(void)
{
	char			*fmri;
	size_t			fmri_size;
	restarter_event_type_t  event_type;
	instance_t		*instance;
	restarter_event_t	*event;
	ssize_t			sz;

	/*
	 * Try to read an event pointer from the event pipe.
	 */
	errno = 0;
	switch (safe_read(rst_event_pipe[PE_CONSUMER], &event,
	    sizeof (event))) {
	case 0:
		break;
	case  1:
		if (errno == EAGAIN)	/* no event to read */
			return (-1);

		/* other end of pipe closed */

		/* FALLTHROUGH */
	default:			/* unexpected read error */
		/*
		 * There's something wrong with the event pipe. Let's
		 * shutdown and be restarted.
		 */
		inetd_stop();
		return (-1);
	}

	/*
	 * Check if we're currently managing the instance which the event
	 * pertains to. If not, read its complete state and add it to our
	 * list to manage.
	 */

	fmri_size = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if ((fmri = malloc(fmri_size)) == NULL) {
		error_msg(strerror(errno));
		goto fail;
	}
	sz = restarter_event_get_instance(event, fmri, fmri_size);
	if (sz >= fmri_size)
		assert(0);

	for (instance = uu_list_first(instance_list); instance != NULL;
	    instance = uu_list_next(instance_list, instance)) {
		if (strcmp(instance->fmri, fmri) == 0)
			break;
	}

	if (instance == NULL) {
		int err;

		debug_msg("New instance to manage: %s", fmri);

		if (((instance = create_instance(fmri)) == NULL) ||
		    (retrieve_instance_state(instance) != 0) ||
		    (retrieve_method_pids(instance) != 0)) {
			destroy_instance(instance);
			free(fmri);
			goto fail;
		}

		if (((err = iterate_repository_contracts(instance, 0))
		    != 0) && (err != ENOENT)) {
			error_msg(gettext(
			    "Failed to adopt contracts of instance %s: %s"),
			    instance->fmri, strerror(err));
			destroy_instance(instance);
			free(fmri);
			goto fail;
		}

		uu_list_node_init(instance, &instance->link, instance_pool);
		(void) uu_list_insert_after(instance_list, NULL, instance);

		/*
		 * Only read configuration for instances that aren't in any of
		 * the disabled, maintenance or uninitialized states, since
		 * they'll read it on state exit.
		 */
		if ((instance->cur_istate != IIS_DISABLED) &&
		    (instance->cur_istate != IIS_MAINTENANCE) &&
		    (instance->cur_istate != IIS_UNINITIALIZED)) {
			instance->config = read_instance_cfg(instance->fmri);
			if (instance->config == NULL) {
				log_invalid_cfg(instance->fmri);
				update_state(instance, IIS_MAINTENANCE,
				    RERR_FAULT);
			}
		}
	}

	free(fmri);

	event_type = restarter_event_get_type(event);
	debug_msg("Event type: %d for instance: %s", event_type,
	    instance->fmri);

	/*
	 * If the instance is currently running a method, don't process the
	 * event now, but attach it to the instance for processing when
	 * the instance finishes its transition.
	 */
	if (INST_IN_TRANSITION(instance)) {
		debug_msg("storing event %d for instance %s", event_type,
		    instance->fmri);
		instance->pending_rst_event = event_type;
	} else {
		handle_restarter_event(instance, event_type, B_TRUE);
	}

	return (0);

fail:
	ack_restarter_event(B_FALSE);
	return (-1);
}

/*
 * Do the state machine processing associated with the termination of instance
 * 'inst''s start method.
 */
void
process_start_term(instance_t *inst)
{
	basic_cfg_t	*cfg;

	inst->copies--;

	if ((inst->cur_istate == IIS_MAINTENANCE) ||
	    (inst->cur_istate == IIS_DISABLED)) {
		/* do any further processing/checks when we exit these states */
		return;
	}

	cfg = inst->config->basic;

	if (cfg->iswait) {
		proto_info_t	*pi;

		switch (inst->cur_istate) {
		case IIS_ONLINE:
		case IIS_DEGRADED:
		case IIS_IN_REFRESH_METHOD:
			/*
			 * A wait type service's start method has exited.
			 * Check if the method was fired off in this inetd's
			 * lifetime, or a previous one; if the former,
			 * re-commence listening on the service's behalf; if
			 * the latter, mark the service offline and let bind
			 * attempts commence.
			 */
			for (pi = uu_list_first(cfg->proto_list); pi != NULL;
			    pi = uu_list_next(cfg->proto_list, pi)) {
				/*
				 * If a bound fd exists, the method was fired
				 * off during this inetd's lifetime.
				 */
				if (pi->listen_fd != -1)
					break;
			}
			if (pi != NULL) {
				if (poll_bound_fds(inst, B_TRUE) != 0)
					handle_bind_failure(inst);
			} else {
				update_state(inst, IIS_OFFLINE, RERR_RESTART);
				create_bound_fds(inst);
			}
		}
	} else {
		/*
		 * Check if a nowait service should be brought back online
		 * after exceeding its copies limit.
		 */
		if ((inst->cur_istate == IIS_OFFLINE_COPIES) &&
		    !copies_limit_exceeded(inst)) {
			update_state(inst, IIS_OFFLINE, RERR_NONE);
			process_offline_inst(inst);
		}
	}
}

/*
 * If the instance has a pending event process it and initiate the
 * acknowledgement.
 */
static void
process_pending_rst_event(instance_t *inst)
{
	if (inst->pending_rst_event != RESTARTER_EVENT_TYPE_INVALID) {
		restarter_event_type_t re;

		debug_msg("Injecting pending event %d for instance %s",
		    inst->pending_rst_event, inst->fmri);
		re = inst->pending_rst_event;
		inst->pending_rst_event = RESTARTER_EVENT_TYPE_INVALID;
		handle_restarter_event(inst, re, B_TRUE);
	}
}

/*
 * Do the state machine processing associated with the termination
 * of the specified instance's non-start method with the specified status.
 * Once the processing of the termination is done, the function also picks up
 * any processing that was blocked on the method running.
 */
void
process_non_start_term(instance_t *inst, int status)
{
	boolean_t ran_online_method = B_FALSE;

	if (status == IMRET_FAILURE) {
		error_msg(gettext("The %s method of instance %s failed, "
		    "transitioning to maintenance"),
		    methods[states[inst->cur_istate].method_running].name,
		    inst->fmri);

		if ((inst->cur_istate == IIS_IN_ONLINE_METHOD) ||
		    (inst->cur_istate == IIS_IN_REFRESH_METHOD))
			destroy_bound_fds(inst);

		update_state(inst, IIS_MAINTENANCE, RERR_FAULT);

		inst->maintenance_req = B_FALSE;
		inst->conn_rate_exceeded = B_FALSE;

		if (inst->new_config != NULL) {
			destroy_instance_cfg(inst->new_config);
			inst->new_config = NULL;
		}

		if (!inetd_stopping)
			process_pending_rst_event(inst);

		return;
	}

	/* non-failure method return */

	if (status != IMRET_SUCCESS) {
		/*
		 * An instance method never returned a supported return code.
		 * We'll assume this means the method succeeded for now whilst
		 * non-GL-cognizant methods are used - eg. pkill.
		 */
		debug_msg("The %s method of instance %s returned "
		    "non-compliant exit code: %d, assuming success",
		    methods[states[inst->cur_istate].method_running].name,
		    inst->fmri, status);
	}

	/*
	 * Update the state from the in-transition state.
	 */
	switch (inst->cur_istate) {
	case IIS_IN_ONLINE_METHOD:
		ran_online_method = B_TRUE;
		/* FALLTHROUGH */
	case IIS_IN_REFRESH_METHOD:
		/*
		 * If we've exhausted the bind retries, flag that by setting
		 * the instance's state to degraded.
		 */
		if (inst->bind_retries_exceeded) {
			update_state(inst, IIS_DEGRADED, RERR_NONE);
			break;
		}
		/* FALLTHROUGH */
	default:
		update_state(inst,
		    methods[states[inst->cur_istate].method_running].dst_state,
		    RERR_NONE);
	}

	if (inst->cur_istate == IIS_OFFLINE) {
		if (inst->new_config != NULL) {
			/*
			 * This instance was found during refresh to need
			 * taking offline because its newly read configuration
			 * was sufficiently different. Now we're offline,
			 * activate this new configuration.
			 */
			destroy_instance_cfg(inst->config);
			inst->config = inst->new_config;
			inst->new_config = NULL;
		}

		/* continue/complete any transitions that are in progress */
		process_offline_inst(inst);

	} else if (ran_online_method) {
		/*
		 * We've just successfully executed the online method. We have
		 * a set of bound network fds that were created before running
		 * this method, so now we're online start listening for
		 * connections on them.
		 */
		if (poll_bound_fds(inst, B_TRUE) != 0)
			handle_bind_failure(inst);
	}

	/*
	 * If we're now out of transition (process_offline_inst() could have
	 * fired off another method), carry out any jobs that were blocked by
	 * us being in transition.
	 */
	if (!INST_IN_TRANSITION(inst)) {
		if (inetd_stopping) {
			if (!instance_stopped(inst)) {
				/*
				 * inetd is stopping, and this instance hasn't
				 * been stopped. Inject a stop event.
				 */
				handle_restarter_event(inst,
				    RESTARTER_EVENT_TYPE_STOP, B_FALSE);
			}
		} else {
			process_pending_rst_event(inst);
		}
	}
}

/*
 * Check if configuration file specified is readable. If not return B_FALSE,
 * else return B_TRUE.
 */
static boolean_t
can_read_file(const char *path)
{
	int	ret;
	int	serrno;

	do {
		ret = access(path, R_OK);
	} while ((ret < 0) && (errno == EINTR));
	if (ret < 0) {
		if (errno != ENOENT) {
			serrno = errno;
			error_msg(gettext("Failed to access configuration "
			    "file %s for performing modification checks: %s"),
			    path, strerror(errno));
			errno = serrno;
		}
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Check whether the configuration file has changed contents since inetd
 * was last started/refreshed, and if so, log a message indicating that
 * inetconv needs to be run.
 */
static void
check_conf_file(void)
{
	char		*new_hash;
	char		*old_hash = NULL;
	scf_error_t	ret;
	const char	*file;

	if (conf_file == NULL) {
		/*
		 * No explicit config file specified, so see if one of the
		 * default two are readable, checking the primary one first
		 * followed by the secondary.
		 */
		if (can_read_file(PRIMARY_DEFAULT_CONF_FILE)) {
			file = PRIMARY_DEFAULT_CONF_FILE;
		} else if ((errno == ENOENT) &&
		    can_read_file(SECONDARY_DEFAULT_CONF_FILE)) {
			file = SECONDARY_DEFAULT_CONF_FILE;
		} else {
			return;
		}
	} else {
		file = conf_file;
		if (!can_read_file(file))
			return;
	}

	if (calculate_hash(file, &new_hash) == 0) {
		ret = retrieve_inetd_hash(&old_hash);
		if (((ret == SCF_ERROR_NONE) &&
		    (strcmp(old_hash, new_hash) != 0))) {
			/* modified config file */
			warn_msg(gettext(
			    "Configuration file %s has been modified since "
			    "inetconv was last run. \"inetconv -i %s\" must be "
			    "run to apply any changes to the SMF"), file, file);
		} else if ((ret != SCF_ERROR_NOT_FOUND) &&
		    (ret != SCF_ERROR_NONE)) {
			/* No message if hash not yet computed */
			error_msg(gettext("Failed to check whether "
			    "configuration file %s has been modified: %s"),
			    file, scf_strerror(ret));
		}
		free(old_hash);
		free(new_hash);
	} else {
		error_msg(gettext("Failed to check whether configuration file "
		    "%s has been modified: %s"), file, strerror(errno));
	}
}

/*
 * Refresh all inetd's managed instances and check the configuration file
 * for any updates since inetconv was last run, logging a message if there
 * are. We call the SMF refresh function to refresh each instance so that
 * the refresh request goes through the framework, and thus results in the
 * running snapshot of each instance being updated from the configuration
 * snapshot.
 */
static void
inetd_refresh(void)
{
	instance_t	*inst;

	refresh_debug_flag();

	/* call libscf to send refresh requests for all managed instances */
	for (inst = uu_list_first(instance_list); inst != NULL;
	    inst = uu_list_next(instance_list, inst)) {
		if (smf_refresh_instance(inst->fmri) < 0) {
			error_msg(gettext("Failed to refresh instance %s: %s"),
			    inst->fmri, scf_strerror(scf_error()));
		}
	}

	/*
	 * Log a message if the configuration file has changed since inetconv
	 * was last run.
	 */
	check_conf_file();
}

/*
 * Initiate inetd's shutdown.
 */
static void
inetd_stop(void)
{
	instance_t *inst;

	/* Block handling signals for stop and refresh */
	(void) sighold(SIGHUP);
	(void) sighold(SIGTERM);

	/* Indicate inetd is coming down */
	inetd_stopping = B_TRUE;

	/* Stop polling on restarter events. */
	clear_pollfd(rst_event_pipe[PE_CONSUMER]);

	/* Stop polling for any more stop/refresh requests. */
	clear_pollfd(uds_fd);

	/*
	 * Send a stop event to all currently unstopped instances that
	 * aren't in transition. For those that are in transition, the
	 * event will get sent when the transition completes.
	 */
	for (inst = uu_list_first(instance_list); inst != NULL;
	    inst = uu_list_next(instance_list, inst)) {
		if (!instance_stopped(inst) && !INST_IN_TRANSITION(inst))
			handle_restarter_event(inst,
			    RESTARTER_EVENT_TYPE_STOP, B_FALSE);
	}
}

/*
 * Sets up the intra-inetd-process Unix Domain Socket.
 * Returns -1 on error, else 0.
 */
static int
uds_init(void)
{
	struct sockaddr_un addr;

	if ((uds_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		error_msg("socket: %s", strerror(errno));
		return (-1);
	}

	disable_blocking(uds_fd);

	(void) unlink(INETD_UDS_PATH);  /* clean-up any stale files */

	(void) memset(&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	/* CONSTCOND */
	assert(sizeof (INETD_UDS_PATH) <= sizeof (addr.sun_path));
	(void) strlcpy(addr.sun_path, INETD_UDS_PATH, sizeof (addr.sun_path));

	if (bind(uds_fd, (struct sockaddr *)(&addr), sizeof (addr)) < 0) {
		error_msg(gettext("Failed to bind socket to %s: %s"),
		    INETD_UDS_PATH, strerror(errno));
		(void) close(uds_fd);
		return (-1);
	}

	(void) listen(uds_fd, UDS_BACKLOG);

	if ((set_pollfd(uds_fd, POLLIN)) == -1) {
		(void) close(uds_fd);
		(void) unlink(INETD_UDS_PATH);
		return (-1);
	}

	return (0);
}

static void
uds_fini(void)
{
	if (uds_fd != -1)
		(void) close(uds_fd);
	(void) unlink(INETD_UDS_PATH);
}

/*
 * Handle an incoming request on the Unix Domain Socket. Returns -1 if there
 * was an error handling the event, else 0.
 */
static int
process_uds_event(void)
{
	uds_request_t		req;
	int			fd;
	struct sockaddr_un	addr;
	socklen_t		len = sizeof (addr);
	int			ret;
	uint_t			retries = 0;
	ucred_t			*ucred = NULL;
	uid_t			euid;

	do {
		fd = accept(uds_fd, (struct sockaddr *)&addr, &len);
	} while ((fd < 0) && (errno == EINTR));
	if (fd < 0) {
		if (errno != EWOULDBLOCK)
			error_msg("accept failed: %s", strerror(errno));
		return (-1);
	}

	if (getpeerucred(fd, &ucred) == -1) {
		error_msg("getpeerucred failed: %s", strerror(errno));
		(void) close(fd);
		return (-1);
	}

	/* Check peer credentials before acting on the request */
	euid = ucred_geteuid(ucred);
	ucred_free(ucred);
	if (euid != 0 && getuid() != euid) {
		debug_msg("peer euid %u != uid %u",
		    (uint_t)euid, (uint_t)getuid());
		(void) close(fd);
		return (-1);
	}

	for (retries = 0; retries < UDS_RECV_RETRIES; retries++) {
		if (((ret = safe_read(fd, &req, sizeof (req))) != 1) ||
		    (errno != EAGAIN))
			break;

		(void) poll(NULL, 0, 100);	/* 100ms pause */
	}

	if (ret != 0) {
		error_msg(gettext("Failed read: %s"), strerror(errno));
		(void) close(fd);
		return (-1);
	}

	switch (req) {
	case UR_REFRESH_INETD:
		/* flag the request for event_loop() to process */
		refresh_inetd_requested = B_TRUE;
		(void) close(fd);
		break;
	case UR_STOP_INETD:
		inetd_stop();
		break;
	default:
		error_msg("unexpected UDS request");
		(void) close(fd);
		return (-1);
	}

	return (0);
}

/*
 * Perform checks for common exec string errors. We limit the checks to
 * whether the file exists, is a regular file, and has at least one execute
 * bit set. We leave the core security checks to exec() so as not to duplicate
 * and thus incur the associated drawbacks, but hope to catch the common
 * errors here.
 */
static boolean_t
passes_basic_exec_checks(const char *instance, const char *method,
    const char *path)
{
	struct stat	sbuf;

	/* check the file exists */
	while (stat(path, &sbuf) == -1) {
		if (errno != EINTR) {
			error_msg(gettext(
			    "Can't stat the %s method of instance %s: %s"),
			    method, instance, strerror(errno));
			return (B_FALSE);
		}
	}

	/*
	 * Check if the file is a regular file and has at least one execute
	 * bit set.
	 */
	if ((sbuf.st_mode & S_IFMT) != S_IFREG) {
		error_msg(gettext(
		    "The %s method of instance %s isn't a regular file"),
		    method, instance);
		return (B_FALSE);
	} else if ((sbuf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
		error_msg(gettext("The %s method instance %s doesn't have "
		    "any execute permissions set"), method, instance);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
exec_method(instance_t *instance, instance_method_t method, method_info_t *mi,
    struct method_context *mthd_ctxt, const proto_info_t *pi)
{
	char		**args;
	char 		**env;
	const char	*errf;
	int		serrno;
	basic_cfg_t	*cfg = instance->config->basic;

	if (method == IM_START) {
		/*
		 * If wrappers checks fail, pretend the method was exec'd and
		 * failed.
		 */
		if (!tcp_wrappers_ok(instance))
			exit(IMRET_FAILURE);
	}

	/*
	 * Revert the disposition of handled signals and ignored signals to
	 * their defaults, unblocking any blocked ones as a side effect.
	 */
	(void) sigset(SIGHUP, SIG_DFL);
	(void) sigset(SIGTERM, SIG_DFL);
	(void) sigset(SIGINT, SIG_DFL);

	/*
	 * Setup exec arguments. Do this before the fd setup below, so our
	 * logging related file fd doesn't get taken over before we call
	 * expand_address().
	 */
	if ((method == IM_START) &&
	    (strcmp(mi->exec_args_we.we_wordv[0], "%A") == 0)) {
		args = expand_address(instance, pi);
	} else {
		args = mi->exec_args_we.we_wordv;
	}

	/* Generate audit trail for start operations */
	if (method == IM_START) {
		adt_event_data_t *ae;
		struct sockaddr_storage ss;
		priv_set_t *privset;
		socklen_t sslen = sizeof (ss);

		if ((ae = adt_alloc_event(audit_handle, ADT_inetd_connect))
		    == NULL) {
			error_msg(gettext("Unable to allocate audit event for "
			    "the %s method of instance %s"),
			    methods[method].name, instance->fmri);
			exit(IMRET_FAILURE);
		}

		/*
		 * The inetd_connect audit record consists of:
		 *	Service name
		 *	Execution path
		 *	Remote address and port
		 *	Local port
		 *	Process privileges
		 */
		ae->adt_inetd_connect.service_name = cfg->svc_name;
		ae->adt_inetd_connect.cmd = mi->exec_path;

		if (instance->remote_addr.ss_family == AF_INET) {
			struct in_addr *in = SS_SINADDR(instance->remote_addr);
			ae->adt_inetd_connect.ip_adr[0] = in->s_addr;
			ae->adt_inetd_connect.ip_type = ADT_IPv4;
		} else {
			uint32_t *addr6;
			int i;

			ae->adt_inetd_connect.ip_type = ADT_IPv6;
			addr6 = (uint32_t *)SS_SINADDR(instance->remote_addr);
			for (i = 0; i < 4; ++i)
				ae->adt_inetd_connect.ip_adr[i] = addr6[i];
		}

		ae->adt_inetd_connect.ip_remote_port =
		    ntohs(SS_PORT(instance->remote_addr));

		if (getsockname(instance->conn_fd, (struct sockaddr *)&ss,
		    &sslen) == 0)
			ae->adt_inetd_connect.ip_local_port =
			    ntohs(SS_PORT(ss));

		privset = mthd_ctxt->priv_set;
		if (privset == NULL) {
			privset = priv_allocset();
			if (privset != NULL &&
			    getppriv(PRIV_EFFECTIVE, privset) != 0) {
				priv_freeset(privset);
				privset = NULL;
			}
		}

		ae->adt_inetd_connect.privileges = privset;

		(void) adt_put_event(ae, ADT_SUCCESS, ADT_SUCCESS);
		adt_free_event(ae);

		if (privset != NULL && mthd_ctxt->priv_set == NULL)
			priv_freeset(privset);
	}

	/*
	 * Set method context before the fd setup below so we can output an
	 * error message if it fails.
	 */
	if ((errno = restarter_set_method_context(mthd_ctxt, &errf)) != 0) {
		const char *msg;

		if (errno == -1) {
			if (strcmp(errf, "core_set_process_path") == 0) {
				msg = gettext("Failed to set the corefile path "
				    "for the %s method of instance %s");
			} else if (strcmp(errf, "setproject") == 0) {
				msg = gettext("Failed to assign a resource "
				    "control for the %s method of instance %s");
			} else if (strcmp(errf, "pool_set_binding") == 0) {
				msg = gettext("Failed to bind the %s method of "
				    "instance %s to a pool due to a system "
				    "error");
			} else {
				assert(0);
				abort();
			}

			error_msg(msg, methods[method].name, instance->fmri);

			exit(IMRET_FAILURE);
		}

		if (errf != NULL && strcmp(errf, "pool_set_binding") == 0) {
			switch (errno) {
			case ENOENT:
				msg = gettext("Failed to find resource pool "
				    "for the %s method of instance %s");
				break;

			case EBADF:
				msg = gettext("Failed to bind the %s method of "
				    "instance %s to a pool due to invalid "
				    "configuration");
				break;

			case EINVAL:
				msg = gettext("Failed to bind the %s method of "
				    "instance %s to a pool due to invalid "
				    "pool name");
				break;

			default:
				assert(0);
				abort();
			}

			exit(IMRET_FAILURE);
		}

		if (errf != NULL) {
			error_msg(gettext("Failed to set credentials for the "
			    "%s method of instance %s (%s: %s)"),
			    methods[method].name, instance->fmri, errf,
			    strerror(errno));
			exit(IMRET_FAILURE);
		}

		switch (errno) {
		case ENOMEM:
			msg = gettext("Failed to set credentials for the %s "
			    "method of instance %s (out of memory)");
			break;

		case ENOENT:
			msg = gettext("Failed to set credentials for the %s "
			    "method of instance %s (no passwd or shadow "
			    "entry for user)");
			break;

		default:
			assert(0);
			abort();
		}

		error_msg(msg, methods[method].name, instance->fmri);
		exit(IMRET_FAILURE);
	}

	/* let exec() free mthd_ctxt */

	/* setup standard fds */
	if (method == IM_START) {
		(void) dup2(instance->conn_fd, STDIN_FILENO);
	} else {
		(void) close(STDIN_FILENO);
		(void) open("/dev/null", O_RDONLY);
	}
	(void) dup2(STDIN_FILENO, STDOUT_FILENO);
	(void) dup2(STDIN_FILENO, STDERR_FILENO);

	closefrom(STDERR_FILENO + 1);

	method_preexec();

	env = set_smf_env(mthd_ctxt, instance, methods[method].name);

	if (env != NULL) {
		do {
			(void) execve(mi->exec_path, args, env);
		} while (errno == EINTR);
	}

	serrno = errno;
	/* start up logging again to report the error */
	msg_init();
	errno = serrno;

	error_msg(
	    gettext("Failed to exec %s method of instance %s: %s"),
	    methods[method].name, instance->fmri, strerror(errno));

	if ((method == IM_START) && (instance->config->basic->iswait)) {
		/*
		 * We couldn't exec the start method for a wait type service.
		 * Eat up data from the endpoint, so that hopefully the
		 * service's fd won't wake poll up on the next time round
		 * event_loop(). This behavior is carried over from the old
		 * inetd, and it seems somewhat arbitrary that it isn't
		 * also done in the case of fork failures; but I guess
		 * it assumes an exec failure is less likely to be the result
		 * of a resource shortage, and is thus not worth retrying.
		 */
		consume_wait_data(instance, 0);
	}

	exit(IMRET_FAILURE);
}

static restarter_error_t
get_method_error_success(instance_method_t method)
{
	switch (method) {
	case IM_OFFLINE:
		return (RERR_RESTART);
	case IM_ONLINE:
		return (RERR_RESTART);
	case IM_DISABLE:
		return (RERR_RESTART);
	case IM_REFRESH:
		return (RERR_REFRESH);
	case IM_START:
		return (RERR_RESTART);
	}
	(void) fprintf(stderr, gettext("Internal fatal error in inetd.\n"));

	abort();
	/* NOTREACHED */
}

static int
smf_kill_process(instance_t *instance, int sig)
{
	rep_val_t	*rv;
	int		ret = IMRET_SUCCESS;

	/* Carry out process assassination */
	for (rv = uu_list_first(instance->start_pids);
	    rv != NULL;
	    rv = uu_list_next(instance->start_pids, rv)) {
		if ((kill((pid_t)rv->val, sig) != 0) &&
		    (errno != ESRCH)) {
			ret = IMRET_FAILURE;
			error_msg(gettext("Unable to kill "
			    "start process (%ld) of instance %s: %s"),
			    rv->val, instance->fmri, strerror(errno));
		}
	}
	return (ret);
}

/*
 * Runs the specified method of the specified service instance.
 * If the method was never specified, we handle it the same as if the
 * method was called and returned success, carrying on any transition the
 * instance may be in the midst of.
 * If the method isn't executable in its specified profile or an error occurs
 * forking a process to run the method in the function returns -1.
 * If a method binary is successfully executed, the function switches the
 * instance's cur state to the method's associated 'run' state and the next
 * state to the methods associated next state.
 * Returns -1 if there's an error before forking, else 0.
 */
int
run_method(instance_t *instance, instance_method_t method,
    const proto_info_t *start_info)
{
	pid_t			child_pid;
	method_info_t		*mi;
	struct method_context	*mthd_ctxt = NULL;
	const char		*errstr;
	int			sig = 0;
	int			ret;
	instance_cfg_t		*cfg = instance->config;
	ctid_t			cid;
	boolean_t		trans_failure = B_TRUE;
	int			serrno;

	/*
	 * Don't bother updating the instance's state for the start method
	 * as there isn't a separate start method state.
	 */
	if (method != IM_START)
		update_instance_states(instance, get_method_state(method),
		    methods[method].dst_state,
		    get_method_error_success(method));

	if ((mi = cfg->methods[method]) == NULL) {
		/*
		 * If the absent method is IM_OFFLINE, default action needs
		 * to be taken to avoid lingering processes which can prevent
		 * the upcoming rebinding from happening.
		 */
		if ((method == IM_OFFLINE) && instance->config->basic->iswait) {
			warn_msg(gettext("inetd_offline method for instance %s "
			    "is unspecified.  Taking default action: kill."),
			    instance->fmri);
			(void) str2sig("TERM", &sig);
			ret = smf_kill_process(instance, sig);
			process_non_start_term(instance, ret);
			return (0);
		} else {
			process_non_start_term(instance, IMRET_SUCCESS);
			return (0);
		}
	}

	/* Handle special method tokens, not allowed on start */
	if (method != IM_START) {
		if (restarter_is_null_method(mi->exec_path)) {
			/* :true means nothing should be done */
			process_non_start_term(instance, IMRET_SUCCESS);
			return (0);
		}

		if ((sig = restarter_is_kill_method(mi->exec_path)) >= 0) {
			/* Carry out contract assassination */
			ret = iterate_repository_contracts(instance, sig);
			/* ENOENT means we didn't find any contracts */
			if (ret != 0 && ret != ENOENT) {
				error_msg(gettext("Failed to send signal %d "
				    "to contracts of instance %s: %s"), sig,
				    instance->fmri, strerror(ret));
				goto prefork_failure;
			} else {
				process_non_start_term(instance, IMRET_SUCCESS);
				return (0);
			}
		}

		if ((sig = restarter_is_kill_proc_method(mi->exec_path)) >= 0) {
			ret = smf_kill_process(instance, sig);
			process_non_start_term(instance, ret);
			return (0);
		}
	}

	/*
	 * Get the associated method context before the fork so we can
	 * modify the instances state if things go wrong.
	 */
	if ((mthd_ctxt = read_method_context(instance->fmri,
	    methods[method].name, mi->exec_path, &errstr)) == NULL) {
		error_msg(gettext("Failed to retrieve method context for the "
		    "%s method of instance %s: %s"), methods[method].name,
		    instance->fmri, errstr);
		goto prefork_failure;
	}

	/*
	 * Perform some basic checks before we fork to limit the possibility
	 * of exec failures, so we can modify the instance state if necessary.
	 */
	if (!passes_basic_exec_checks(instance->fmri, methods[method].name,
	    mi->exec_path)) {
		trans_failure = B_FALSE;
		goto prefork_failure;
	}

	if (contract_prefork(instance->fmri, method) == -1)
		goto prefork_failure;
	child_pid = fork();
	serrno = errno;
	contract_postfork();

	switch (child_pid) {
	case -1:
		error_msg(gettext(
		    "Unable to fork %s method of instance %s: %s"),
		    methods[method].name, instance->fmri, strerror(serrno));
		if ((serrno != EAGAIN) && (serrno != ENOMEM))
			trans_failure = B_FALSE;
		goto prefork_failure;
	case 0:				/* child */
		exec_method(instance, method, mi, mthd_ctxt, start_info);
		/* NOTREACHED */
	default:			/* parent */
		restarter_free_method_context(mthd_ctxt);
		mthd_ctxt = NULL;

		if (get_latest_contract(&cid) < 0)
			cid = -1;

		/*
		 * Register this method so its termination is noticed and
		 * the state transition this method participates in is
		 * continued.
		 */
		if (register_method(instance, child_pid, cid, method) != 0) {
			/*
			 * Since we will never find out about the termination
			 * of this method, if it's a non-start method treat
			 * is as a failure so we don't block restarter event
			 * processing on it whilst it languishes in a method
			 * running state.
			 */
			error_msg(gettext("Failed to monitor status of "
			    "%s method of instance %s"), methods[method].name,
			    instance->fmri);
			if (method != IM_START)
				process_non_start_term(instance, IMRET_FAILURE);
		}

		add_method_ids(instance, child_pid, cid, method);

		/* do tcp tracing for those nowait instances that request it */
		if ((method == IM_START) && cfg->basic->do_tcp_trace &&
		    !cfg->basic->iswait) {
			char buf[INET6_ADDRSTRLEN];

			syslog(LOG_NOTICE, "%s[%d] from %s %d",
			    cfg->basic->svc_name, child_pid,
			    inet_ntop_native(instance->remote_addr.ss_family,
			    SS_SINADDR(instance->remote_addr), buf,
			    sizeof (buf)),
			    ntohs(SS_PORT(instance->remote_addr)));
		}
	}

	return (0);

prefork_failure:
	if (mthd_ctxt != NULL) {
		restarter_free_method_context(mthd_ctxt);
		mthd_ctxt = NULL;
	}

	if (method == IM_START) {
		/*
		 * Only place a start method in maintenance if we're sure
		 * that the failure was non-transient.
		 */
		if (!trans_failure) {
			destroy_bound_fds(instance);
			update_state(instance, IIS_MAINTENANCE, RERR_FAULT);
		}
	} else {
		/* treat the failure as if the method ran and failed */
		process_non_start_term(instance, IMRET_FAILURE);
	}

	return (-1);
}

static int
pending_connections(instance_t *instance, proto_info_t *pi)
{
	if (instance->config->basic->istlx) {
		tlx_info_t *tl = (tlx_info_t *)pi;

		return (uu_list_numnodes(tl->conn_ind_queue) != 0);
	} else {
		return (0);
	}
}

static int
accept_connection(instance_t *instance, proto_info_t *pi)
{
	int		fd;
	socklen_t	size;

	if (instance->config->basic->istlx) {
		tlx_info_t *tl = (tlx_info_t *)pi;
		tlx_pending_counter = \
		    tlx_pending_counter - uu_list_numnodes(tl->conn_ind_queue);

		fd = tlx_accept(instance->fmri, (tlx_info_t *)pi,
		    &(instance->remote_addr));

		tlx_pending_counter = \
		    tlx_pending_counter + uu_list_numnodes(tl->conn_ind_queue);
	} else {
		size = sizeof (instance->remote_addr);
		fd = accept(pi->listen_fd,
		    (struct sockaddr *)&(instance->remote_addr), &size);
		if (fd < 0)
			error_msg("accept: %s", strerror(errno));
	}

	return (fd);
}

/*
 * Handle an incoming connection request for a nowait service.
 * This involves accepting the incoming connection on a new fd. Connection
 * rate checks are then performed, transitioning the service to the
 * conrate offline state if these fail. Otherwise, the service's start method
 * is run (performing TCP wrappers checks if applicable as we do), and on
 * success concurrent copies checking is done, transitioning the service to the
 * copies offline state if this fails.
 */
static void
process_nowait_request(instance_t *instance, proto_info_t *pi)
{
	basic_cfg_t		*cfg = instance->config->basic;
	int			ret;
	adt_event_data_t	*ae;
	char			buf[BUFSIZ];

	/* accept nowait service connections on a new fd */
	if ((instance->conn_fd = accept_connection(instance, pi)) == -1) {
		/*
		 * Failed accept. Return and allow the event loop to initiate
		 * another attempt later if the request is still present.
		 */
		return;
	}

	/*
	 * Limit connection rate of nowait services. If either conn_rate_max
	 * or conn_rate_offline are <= 0, no connection rate limit checking
	 * is done. If the configured rate is exceeded, the instance is taken
	 * to the connrate_offline state and a timer scheduled to try and
	 * bring the instance back online after the configured offline time.
	 */
	if ((cfg->conn_rate_max > 0) && (cfg->conn_rate_offline > 0)) {
		if (instance->conn_rate_count++ == 0) {
			instance->conn_rate_start = time(NULL);
		} else if (instance->conn_rate_count >
		    cfg->conn_rate_max) {
			time_t now = time(NULL);

			if ((now - instance->conn_rate_start) > 1) {
				instance->conn_rate_start = now;
				instance->conn_rate_count = 1;
			} else {
				/* Generate audit record */
				if ((ae = adt_alloc_event(audit_handle,
				    ADT_inetd_ratelimit)) == NULL) {
					error_msg(gettext("Unable to allocate "
					    "rate limit audit event"));
				} else {
					adt_inetd_ratelimit_t *rl =
					    &ae->adt_inetd_ratelimit;
					/*
					 * The inetd_ratelimit audit
					 * record consists of:
					 * 	Service name
					 *	Connection rate limit
					 */
					rl->service_name = cfg->svc_name;
					(void) snprintf(buf, sizeof (buf),
					    "limit=%lld", cfg->conn_rate_max);
					rl->limit = buf;
					(void) adt_put_event(ae, ADT_SUCCESS,
					    ADT_SUCCESS);
					adt_free_event(ae);
				}

				error_msg(gettext(
				    "Instance %s has exceeded its configured "
				    "connection rate, additional connections "
				    "will not be accepted for %d seconds"),
				    instance->fmri, cfg->conn_rate_offline);

				close_net_fd(instance, instance->conn_fd);
				instance->conn_fd = -1;

				destroy_bound_fds(instance);

				instance->conn_rate_count = 0;

				instance->conn_rate_exceeded = B_TRUE;
				(void) run_method(instance, IM_OFFLINE, NULL);

				return;
			}
		}
	}

	ret = run_method(instance, IM_START, pi);

	close_net_fd(instance, instance->conn_fd);
	instance->conn_fd = -1;

	if (ret == -1) /* the method wasn't forked  */
		return;

	instance->copies++;

	/*
	 * Limit concurrent connections of nowait services.
	 */
	if (copies_limit_exceeded(instance)) {
		/* Generate audit record */
		if ((ae = adt_alloc_event(audit_handle, ADT_inetd_copylimit))
		    == NULL) {
			error_msg(gettext("Unable to allocate copy limit "
			    "audit event"));
		} else {
			/*
			 * The inetd_copylimit audit record consists of:
			 *	Service name
			 * 	Copy limit
			 */
			ae->adt_inetd_copylimit.service_name = cfg->svc_name;
			(void) snprintf(buf, sizeof (buf), "limit=%lld",
			    cfg->max_copies);
			ae->adt_inetd_copylimit.limit = buf;
			(void) adt_put_event(ae, ADT_SUCCESS, ADT_SUCCESS);
			adt_free_event(ae);
		}

		warn_msg(gettext("Instance %s has reached its maximum "
		    "configured copies, no new connections will be accepted"),
		    instance->fmri);
		destroy_bound_fds(instance);
		(void) run_method(instance, IM_OFFLINE, NULL);
	}
}

/*
 * Handle an incoming request for a wait type service.
 * Failure rate checking is done first, taking the service to the maintenance
 * state if the checks fail. Following this, the service's start method is run,
 * and on success, we stop listening for new requests for this service.
 */
static void
process_wait_request(instance_t *instance, const proto_info_t *pi)
{
	basic_cfg_t		*cfg = instance->config->basic;
	int			ret;
	adt_event_data_t	*ae;
	char			buf[BUFSIZ];

	instance->conn_fd = pi->listen_fd;

	/*
	 * Detect broken servers and transition them to maintenance. If a
	 * wait type service exits without accepting the connection or
	 * consuming (reading) the datagram, that service's descriptor will
	 * select readable again, and inetd will fork another instance of
	 * the server. If either wait_fail_cnt or wait_fail_interval are <= 0,
	 * no failure rate detection is done.
	 */
	if ((cfg->wait_fail_cnt > 0) && (cfg->wait_fail_interval > 0)) {
		if (instance->fail_rate_count++ == 0) {
			instance->fail_rate_start = time(NULL);
		} else if (instance->fail_rate_count > cfg->wait_fail_cnt) {
			time_t now = time(NULL);

			if ((now - instance->fail_rate_start) >
			    cfg->wait_fail_interval) {
				instance->fail_rate_start = now;
				instance->fail_rate_count = 1;
			} else {
				/* Generate audit record */
				if ((ae = adt_alloc_event(audit_handle,
				    ADT_inetd_failrate)) == NULL) {
					error_msg(gettext("Unable to allocate "
					    "failure rate audit event"));
				} else {
					adt_inetd_failrate_t *fr =
					    &ae->adt_inetd_failrate;
					/*
					 * The inetd_failrate audit record
					 * consists of:
					 * 	Service name
					 * 	Failure rate
					 *	Interval
					 * Last two are expressed as k=v pairs
					 * in the values field.
					 */
					fr->service_name = cfg->svc_name;
					(void) snprintf(buf, sizeof (buf),
					    "limit=%lld,interval=%d",
					    cfg->wait_fail_cnt,
					    cfg->wait_fail_interval);
					fr->values = buf;
					(void) adt_put_event(ae, ADT_SUCCESS,
					    ADT_SUCCESS);
					adt_free_event(ae);
				}

				error_msg(gettext(
				    "Instance %s has exceeded its configured "
				    "failure rate, transitioning to "
				    "maintenance"), instance->fmri);
				instance->fail_rate_count = 0;

				destroy_bound_fds(instance);

				instance->maintenance_req = B_TRUE;
				(void) run_method(instance, IM_OFFLINE, NULL);
				return;
			}
		}
	}

	ret = run_method(instance, IM_START, pi);

	instance->conn_fd = -1;

	if (ret == 0) {
		/*
		 * Stop listening for connections now we've fired off the
		 * server for a wait type instance.
		 */
		(void) poll_bound_fds(instance, B_FALSE);
	}
}

/*
 * Process any networks requests for each proto for each instance.
 */
void
process_network_events(void)
{
	instance_t	*instance;

	for (instance = uu_list_first(instance_list); instance != NULL;
	    instance = uu_list_next(instance_list, instance)) {
		basic_cfg_t	*cfg;
		proto_info_t	*pi;

		/*
		 * Ignore instances in states that definitely don't have any
		 * listening fds.
		 */
		switch (instance->cur_istate) {
		case IIS_ONLINE:
		case IIS_DEGRADED:
		case IIS_IN_REFRESH_METHOD:
			break;
		default:
			continue;
		}

		cfg = instance->config->basic;

		for (pi = uu_list_first(cfg->proto_list); pi != NULL;
		    pi = uu_list_next(cfg->proto_list, pi)) {
			if (((pi->listen_fd != -1) &&
			    isset_pollfd(pi->listen_fd)) ||
			    pending_connections(instance, pi)) {
				if (cfg->iswait) {
					process_wait_request(instance, pi);
				} else {
					process_nowait_request(instance, pi);
				}
			}
		}
	}
}

/* ARGSUSED0 */
static void
sigterm_handler(int sig)
{
	got_sigterm = B_TRUE;
}

/* ARGSUSED0 */
static void
sighup_handler(int sig)
{
	refresh_inetd_requested = B_TRUE;
}

/*
 * inetd's major work loop. This function sits in poll waiting for events
 * to occur, processing them when they do. The possible events are
 * master restarter requests, expired timer queue timers, stop/refresh signal
 * requests, contract events indicating process termination, stop/refresh
 * requests originating from one of the stop/refresh inetd processes and
 * network events.
 * The loop is exited when a stop request is received and processed, and
 * all the instances have reached a suitable 'stopping' state.
 */
static void
event_loop(void)
{
	instance_t		*instance;
	int			timeout;

	for (;;) {
		int	pret = -1;

		if (tlx_pending_counter != 0)
			timeout = 0;
		else
			timeout = iu_earliest_timer(timer_queue);

		if (!got_sigterm && !refresh_inetd_requested) {
			pret = poll(poll_fds, num_pollfds, timeout);
			if ((pret == -1) && (errno != EINTR)) {
				error_msg(gettext("poll failure: %s"),
				    strerror(errno));
				continue;
			}
		}

		if (got_sigterm) {
			msg_fini();
			inetd_stop();
			got_sigterm = B_FALSE;
			goto check_if_stopped;
		}

		/*
		 * Process any stop/refresh requests from the Unix Domain
		 * Socket.
		 */
		if ((pret != -1) && isset_pollfd(uds_fd)) {
			while (process_uds_event() == 0)
				;
		}

		/*
		 * Process refresh request. We do this check after the UDS
		 * event check above, as it would be wasted processing if we
		 * started refreshing inetd based on a SIGHUP, and then were
		 * told to shut-down via a UDS event.
		 */
		if (refresh_inetd_requested) {
			refresh_inetd_requested = B_FALSE;
			if (!inetd_stopping)
				inetd_refresh();
		}

		/*
		 * We were interrupted by a signal. Don't waste any more
		 * time processing a potentially inaccurate poll return.
		 */
		if (pret == -1)
			continue;

		/*
		 * Process any instance restarter events.
		 */
		if (isset_pollfd(rst_event_pipe[PE_CONSUMER])) {
			while (process_restarter_event() == 0)
				;
		}

		/*
		 * Process any expired timers (bind retry, con-rate offline,
		 * method timeouts).
		 */
		(void) iu_expire_timers(timer_queue);

		process_terminated_methods();

		/*
		 * If inetd is stopping, check whether all our managed
		 * instances have been stopped and we can return.
		 */
		if (inetd_stopping) {
check_if_stopped:
			for (instance = uu_list_first(instance_list);
			    instance != NULL;
			    instance = uu_list_next(instance_list, instance)) {
				if (!instance_stopped(instance)) {
					debug_msg("%s not yet stopped",
					    instance->fmri);
					break;
				}
			}
			/* if all instances are stopped, return */
			if (instance == NULL)
				return;
		}

		process_network_events();
	}
}

static void
fini(void)
{
	method_fini();
	uds_fini();
	if (timer_queue != NULL)
		iu_tq_destroy(timer_queue);


	/*
	 * We don't bother to undo the restarter interface at all.
	 * Because of quirks in the interface, there is no way to
	 * disconnect from the channel and cause any new events to be
	 * queued.  However, any events which are received and not
	 * acknowledged will be re-sent when inetd restarts as long as inetd
	 * uses the same subscriber ID, which it does.
	 *
	 * By keeping the event pipe open but ignoring it, any events which
	 * occur will cause restarter_event_proxy to hang without breaking
	 * anything.
	 */

	if (instance_list != NULL) {
		void		*cookie = NULL;
		instance_t	*inst;

		while ((inst = uu_list_teardown(instance_list, &cookie)) !=
		    NULL)
			destroy_instance(inst);
		uu_list_destroy(instance_list);
	}
	if (instance_pool != NULL)
		uu_list_pool_destroy(instance_pool);
	tlx_fini();
	config_fini();
	repval_fini();
	poll_fini();

	/* Close audit session */
	(void) adt_end_session(audit_handle);
}

static int
init(void)
{
	int err;

	if (repval_init() < 0)
		goto failed;

	if (config_init() < 0)
		goto failed;

	refresh_debug_flag();

	if (tlx_init() < 0)
		goto failed;

	/* Setup instance list. */
	if ((instance_pool = uu_list_pool_create("instance_pool",
	    sizeof (instance_t), offsetof(instance_t, link), NULL,
	    UU_LIST_POOL_DEBUG)) == NULL) {
		error_msg("%s: %s",
		    gettext("Failed to create instance pool"),
		    uu_strerror(uu_error()));
		goto failed;
	}
	if ((instance_list = uu_list_create(instance_pool, NULL, 0)) == NULL) {
		error_msg("%s: %s",
		    gettext("Failed to create instance list"),
		    uu_strerror(uu_error()));
		goto failed;
	}

	/*
	 * Create event pipe to communicate events with the main event
	 * loop and add it to the event loop's fdset.
	 */
	if (pipe(rst_event_pipe) < 0) {
		error_msg("pipe: %s", strerror(errno));
		goto failed;
	}
	/*
	 * We only leave the producer end to block on reads/writes as we
	 * can't afford to block in the main thread, yet need to in
	 * the restarter event thread, so it can sit and wait for an
	 * acknowledgement to be written to the pipe.
	 */
	disable_blocking(rst_event_pipe[PE_CONSUMER]);
	if ((set_pollfd(rst_event_pipe[PE_CONSUMER], POLLIN)) == -1)
		goto failed;

	/*
	 * Register with master restarter for managed service events. This
	 * will fail, amongst other reasons, if inetd is already running.
	 */
	if ((err = restarter_bind_handle(RESTARTER_EVENT_VERSION,
	    INETD_INSTANCE_FMRI, restarter_event_proxy, 0,
	    &rst_event_handle)) != 0) {
		error_msg(gettext(
		    "Failed to register for restarter events: %s"),
		    strerror(err));
		goto failed;
	}

	if (contract_init() < 0)
		goto failed;

	if ((timer_queue = iu_tq_create()) == NULL) {
		error_msg(gettext("Failed to create timer queue."));
		goto failed;
	}

	if (uds_init() < 0)
		goto failed;

	if (method_init() < 0)
		goto failed;

	/* Initialize auditing session */
	if (adt_start_session(&audit_handle, NULL, ADT_USE_PROC_DATA) != 0) {
		error_msg(gettext("Unable to start audit session"));
	}

	/*
	 * Initialize signal dispositions/masks
	 */
	(void) sigset(SIGHUP, sighup_handler);
	(void) sigset(SIGTERM, sigterm_handler);
	(void) sigignore(SIGINT);

	return (0);

failed:
	fini();
	return (-1);
}

static int
start_method(void)
{
	int	i;
	int	pipe_fds[2];
	int	child;

	/* Create pipe for child to notify parent of initialization success. */
	if (pipe(pipe_fds) < 0) {
		error_msg("pipe: %s", strerror(errno));
		return (SMF_EXIT_ERR_OTHER);
	}

	if ((child = fork()) == -1) {
		error_msg("fork: %s", strerror(errno));
		(void) close(pipe_fds[PE_CONSUMER]);
		(void) close(pipe_fds[PE_PRODUCER]);
		return (SMF_EXIT_ERR_OTHER);
	} else if (child > 0) {			/* parent */

		/* Wait on child to return success of initialization. */
		(void) close(pipe_fds[PE_PRODUCER]);
		if ((safe_read(pipe_fds[PE_CONSUMER], &i, sizeof (i)) != 0) ||
		    (i < 0)) {
			error_msg(gettext(
			    "Initialization failed, unable to start"));
			(void) close(pipe_fds[PE_CONSUMER]);
			/*
			 * Batch all initialization errors as 'other' errors,
			 * resulting in retries being attempted.
			 */
			return (SMF_EXIT_ERR_OTHER);
		} else {
			(void) close(pipe_fds[PE_CONSUMER]);
			return (SMF_EXIT_OK);
		}
	} else {				/* child */
		/*
		 * Perform initialization and return success code down
		 * the pipe.
		 */
		(void) close(pipe_fds[PE_CONSUMER]);
		i = init();
		if ((safe_write(pipe_fds[PE_PRODUCER], &i, sizeof (i)) < 0) ||
		    (i < 0)) {
			error_msg(gettext("pipe write failure: %s"),
			    strerror(errno));
			exit(1);
		}
		(void) close(pipe_fds[PE_PRODUCER]);

		(void) setsid();

		/*
		 * Log a message if the configuration file has changed since
		 * inetconv was last run.
		 */
		check_conf_file();

		event_loop();

		fini();
		debug_msg("inetd stopped");
		msg_fini();
		exit(0);
	}
	/* NOTREACHED */
}

/*
 * When inetd is run from outside the SMF, this message is output to provide
 * the person invoking inetd with further information that will help them
 * understand how to start and stop inetd, and to achieve the other
 * behaviors achievable with the legacy inetd command line interface, if
 * it is possible.
 */
static void
legacy_usage(void)
{
	(void) fprintf(stderr,
	    "inetd is now an smf(5) managed service and can no longer be run "
	    "from the\n"
	    "command line. To enable or disable inetd refer to svcadm(1M) on\n"
	    "how to enable \"%s\", the inetd instance.\n"
	    "\n"
	    "The traditional inetd command line option mappings are:\n"
	    "\t-d : there is no supported debug output\n"
	    "\t-s : inetd is only runnable from within the SMF\n"
	    "\t-t : See inetadm(1M) on how to enable TCP tracing\n"
	    "\t-r : See inetadm(1M) on how to set a failure rate\n"
	    "\n"
	    "To specify an alternative configuration file see svccfg(1M)\n"
	    "for how to modify the \"%s/%s\" string type property of\n"
	    "the inetd instance, and modify it according to the syntax:\n"
	    "\"%s [alt_config_file] %%m\".\n"
	    "\n"
	    "For further information on inetd see inetd(1M).\n",
	    INETD_INSTANCE_FMRI, START_METHOD_ARG, SCF_PROPERTY_EXEC,
	    INETD_PATH);
}

/*
 * Usage message printed out for usage errors when running under the SMF.
 */
static void
smf_usage(const char *arg0)
{
	error_msg("Usage: %s [alt_conf_file] %s|%s|%s", arg0, START_METHOD_ARG,
	    STOP_METHOD_ARG, REFRESH_METHOD_ARG);
}

/*
 * Returns B_TRUE if we're being run from within the SMF, else B_FALSE.
 */
static boolean_t
run_through_smf(void)
{
	char *fmri;

	/*
	 * check if the instance fmri environment variable has been set by
	 * our restarter.
	 */
	return (((fmri = getenv("SMF_FMRI")) != NULL) &&
	    (strcmp(fmri, INETD_INSTANCE_FMRI) == 0));
}

int
main(int argc, char *argv[])
{
	char		*method;
	int		ret;

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	(void) setlocale(LC_ALL, "");

	if (!run_through_smf()) {
		legacy_usage();
		return (SMF_EXIT_ERR_NOSMF);
	}

	msg_init();	/* setup logging */

	(void) enable_extended_FILE_stdio(-1, -1);

	/* inetd invocation syntax is inetd [alt_conf_file] method_name */

	switch (argc) {
	case 2:
		method = argv[1];
		break;
	case 3:
		conf_file = argv[1];
		method = argv[2];
		break;
	default:
		smf_usage(argv[0]);
		return (SMF_EXIT_ERR_CONFIG);

	}

	if (strcmp(method, START_METHOD_ARG) == 0) {
		ret = start_method();
	} else if (strcmp(method, STOP_METHOD_ARG) == 0) {
		ret = stop_method();
	} else if (strcmp(method, REFRESH_METHOD_ARG) == 0) {
		ret = refresh_method();
	} else {
		smf_usage(argv[0]);
		return (SMF_EXIT_ERR_CONFIG);
	}

	return (ret);
}
