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
 * main() of idmapd(1M)
 */

#include "idmapd.h"
#include <signal.h>
#include <rpc/pmap_clnt.h> /* for pmap_unset */
#include <string.h> /* strcmp */
#include <unistd.h> /* setsid */
#include <sys/types.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <sys/resource.h> /* rlimit */
#include <syslog.h>
#include <rpcsvc/daemon_utils.h> /* DAEMON_UID and DAEMON_GID */
#include <priv_utils.h> /* privileges */
#include <locale.h>
#include <sys/systeminfo.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <zone.h>
#include <door.h>
#include <port.h>
#include <tsol/label.h>
#include <sys/resource.h>
#include <sys/sid.h>
#include <sys/idmap.h>

static void	hup_handler(int);
static void	term_handler(int);
static void	init_idmapd();
static void	fini_idmapd();

#ifndef SIG_PF
#define	SIG_PF void(*)(int)
#endif

#define	_RPCSVC_CLOSEDOWN 120

int _rpcsvcstate = _IDLE;	/* Set when a request is serviced */
int _rpcsvccount = 0;		/* Number of requests being serviced */
mutex_t _svcstate_lock;		/* lock for _rpcsvcstate, _rpcsvccount */
idmapd_state_t	_idmapdstate;

int hupped;
extern int hup_ev_port;

SVCXPRT *xprt = NULL;

static int dfd = -1;		/* our door server fildes, for unregistration */

#ifdef DEBUG
#define	RPC_SVC_FG
#endif

/*
 * This is needed for mech_krb5 -- we run as daemon, yes, but we want
 * mech_krb5 to think we're root so it can get host/nodename.fqdn
 * tickets for us so we can authenticate to AD as the machine account
 * that we are.  For more details look at the entry point in mech_krb5
 * corresponding to gss_init_sec_context().
 *
 * As a side effect of faking our effective UID to mech_krb5 we will use
 * root's default ccache (/tmp/krb5cc_0).  But if that's created by
 * another process then we won't have access to it: we run as daemon and
 * keep PRIV_FILE_DAC_READ, which is insufficient to share the ccache
 * with others.  We putenv("KRB5CCNAME=/var/run/idmap/ccache") in main()
 * to avoid this issue; see main().
 *
 * Someday we'll have gss/mech_krb5 extensions for acquiring initiator
 * creds with keytabs/raw keys, and someday we'll have extensions to
 * libsasl to specify creds/name to use on the initiator side, and
 * someday we'll have extensions to libldap to pass those through to
 * libsasl.  Until then this interposer will have to do.
 *
 * Also, we have to tell lint to shut up: it thinks app_krb5_user_uid()
 * is defined but not used.
 */
/*LINTLIBRARY*/
uid_t
app_krb5_user_uid(void)
{
	return (0);
}

/*ARGSUSED*/
static void
hup_handler(int sig) {
	hupped = 1;
	if (hup_ev_port >= 0)
		(void) port_send(hup_ev_port, 1, &sig /* any ptr will do */);
}


/*ARGSUSED*/
static void
term_handler(int sig) {
	(void) idmapdlog(LOG_INFO, "idmapd: Terminating.");
	fini_idmapd();
	_exit(0);
}

static int pipe_fd = -1;

static void
daemonize_ready(void) {
	char data = '\0';
	/*
	 * wake the parent
	 */
	(void) write(pipe_fd, &data, 1);
	(void) close(pipe_fd);
}

static int
daemonize_start(void) {
	char	data;
	int	status;
	int	devnull;
	int	filedes[2];
	pid_t	pid;

	(void) sigset(SIGPIPE, SIG_IGN);
	devnull = open("/dev/null", O_RDONLY);
	if (devnull < 0)
		return (-1);
	(void) dup2(devnull, 0);
	(void) dup2(2, 1);	/* stderr only */
	if (pipe(filedes) < 0)
		return (-1);
	if ((pid = fork1()) < 0)
		return (-1);
	if (pid != 0) {
		/*
		 * parent
		 */
		(void) close(filedes[1]);
		if (read(filedes[0], &data, 1) == 1) {
			/* presume success */
			_exit(0);
		}
		status = -1;
		(void) wait4(pid, &status, 0, NULL);
		if (WIFEXITED(status))
			_exit(WEXITSTATUS(status));
		else
			_exit(-1);
	}

	/*
	 * child
	 */
	pipe_fd = filedes[1];
	(void) close(filedes[0]);
	(void) setsid();
	(void) umask(0077);
	openlog("idmap", LOG_PID, LOG_DAEMON);
	_idmapdstate.daemon_mode = TRUE;
	return (0);
}


int
main(int argc, char **argv)
{
	int c;
#ifdef RPC_SVC_FG
	bool_t daemonize = FALSE;
#else
	bool_t daemonize = TRUE;
#endif

	while ((c = getopt(argc, argv, "d")) != EOF) {
		switch (c) {
			case 'd':
				daemonize = FALSE;
				break;
			default:
				break;
		}
	}

	/* set locale and domain for internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) idmapdlog(LOG_ERR,
		    "idmapd: idmapd runs only in the global zone");
		exit(1);
	}

	(void) mutex_init(&_svcstate_lock, USYNC_THREAD, NULL);

	if (daemonize == TRUE) {
		if (daemonize_start() < 0) {
			(void) perror("idmapd: unable to daemonize");
			exit(-1);
		}
	} else
		(void) umask(0077);

	idmap_init_tsd_key();

	init_idmapd();

	/* signal handlers that should run only after we're initialized */
	(void) sigset(SIGTERM, term_handler);
	(void) sigset(SIGHUP, hup_handler);

	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID,
	    PRIV_PROC_AUDIT, PRIV_FILE_DAC_READ,
	    (char *)NULL) == -1) {
		(void) idmapdlog(LOG_ERR, "idmapd: unable to drop privileges");
		exit(1);
	}

	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);

	if (daemonize == TRUE)
		daemonize_ready();

	/* With doors RPC this just wastes this thread, oh well */
	svc_run();
	return (0);
}

static void
init_idmapd() {
	int	error;
	int connmaxrec = IDMAP_MAX_DOOR_RPC;

	/* create directories as root and chown to daemon uid */
	if (create_directory(IDMAP_DBDIR, DAEMON_UID, DAEMON_GID) < 0)
		exit(1);
	if (create_directory(IDMAP_CACHEDIR, DAEMON_UID, DAEMON_GID) < 0)
		exit(1);

	/*
	 * Set KRB5CCNAME in the environment.  See app_krb5_user_uid()
	 * for more details.  We blow away the existing one, if there is
	 * one.
	 */
	(void) unlink(IDMAP_CACHEDIR "/ccache");
	putenv("KRB5CCNAME=" IDMAP_CACHEDIR "/ccache");

	memset(&_idmapdstate, 0, sizeof (_idmapdstate));

	if (sysinfo(SI_HOSTNAME, _idmapdstate.hostname,
			sizeof (_idmapdstate.hostname)) == -1) {
		error = errno;
		idmapdlog(LOG_ERR,
	"idmapd: unable to determine hostname, error: %d",
			error);
		exit(1);
	}

	if (init_mapping_system() < 0) {
		idmapdlog(LOG_ERR,
		"idmapd: unable to initialize mapping system");
		exit(1);
	}

	xprt = svc_door_create(idmap_prog_1, IDMAP_PROG, IDMAP_V1, connmaxrec);
	if (xprt == NULL) {
		idmapdlog(LOG_ERR,
		"idmapd: unable to create door RPC service");
		goto errout;
	}

	if (!svc_control(xprt, SVCSET_CONNMAXREC, &connmaxrec)) {
		idmapdlog(LOG_ERR,
		    "idmapd: unable to limit RPC request size");
		goto errout;
	}

	dfd = xprt->xp_fd;

	if (dfd == -1) {
		idmapdlog(LOG_ERR, "idmapd: unable to register door");
		goto errout;
	}
	if ((error = idmap_reg(dfd)) != 0) {
		idmapdlog(LOG_ERR, "idmapd: unable to register door (%s)",
				strerror(error));
		goto errout;
	}

	if ((error = allocids(_idmapdstate.new_eph_db,
			8192, &_idmapdstate.next_uid,
			8192, &_idmapdstate.next_gid)) != 0) {
		idmapdlog(LOG_ERR, "idmapd: unable to allocate ephemeral IDs "
			"(%s)", strerror(error));
		_idmapdstate.next_uid = _idmapdstate.limit_uid = SENTINEL_PID;
		_idmapdstate.next_gid = _idmapdstate.limit_gid = SENTINEL_PID;
	} else {
		_idmapdstate.limit_uid = _idmapdstate.next_uid + 8192;
		_idmapdstate.limit_gid = _idmapdstate.next_gid + 8192;
	}

	print_idmapdstate();

	return;

errout:
	fini_idmapd();
	exit(1);
}

static void
fini_idmapd() {
	idmap_unreg(dfd);
	fini_mapping_system();
	if (xprt != NULL)
		svc_destroy(xprt);
}

void
idmapdlog(int pri, const char *format, ...) {
	va_list args;

	va_start(args, format);
	if (_idmapdstate.daemon_mode == FALSE) {
		(void) vfprintf(stderr, format, args);
		(void) fprintf(stderr, "\n");
	}
	(void) vsyslog(pri, format, args);
	va_end(args);
}
