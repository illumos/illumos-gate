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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * main() of idmapd(1M)
 */

#include "idmapd.h"
#include <atomic.h>
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

static void	term_handler(int);
static void	init_idmapd();
static void	fini_idmapd();

#define	_RPCSVC_CLOSEDOWN 120

int _rpcsvcstate = _IDLE;	/* Set when a request is serviced */
int _rpcsvccount = 0;		/* Number of requests being serviced */
mutex_t _svcstate_lock;		/* lock for _rpcsvcstate, _rpcsvccount */
idmapd_state_t	_idmapdstate;

SVCXPRT *xprt = NULL;

static int dfd = -1;		/* our door server fildes, for unregistration */
static int degraded = 0;	/* whether the FMRI has been marked degraded */

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
term_handler(int sig)
{
	idmapdlog(LOG_INFO, "Terminating.");
	fini_idmapd();
	_exit(0);
}

/*ARGSUSED*/
static void
usr1_handler(int sig)
{
	bool_t saved_debug_mode = _idmapdstate.debug_mode;

	_idmapdstate.debug_mode = TRUE;
	print_idmapdstate();
	_idmapdstate.debug_mode = saved_debug_mode;
}

static int pipe_fd = -1;

static void
daemonize_ready(void)
{
	char data = '\0';
	/*
	 * wake the parent
	 */
	(void) write(pipe_fd, &data, 1);
	(void) close(pipe_fd);
}

static int
daemonize_start(void)
{
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
	return (0);
}


int
main(int argc, char **argv)
{
	int c;

	_idmapdstate.daemon_mode = TRUE;
	_idmapdstate.debug_mode = FALSE;
	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
			case 'd':
				_idmapdstate.daemon_mode = FALSE;
				break;
			default:
				fprintf(stderr, "Usage: /usr/lib/idmapd");
				return (SMF_EXIT_ERR_CONFIG);
				break;
		}
	}

	/* set locale and domain for internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (is_system_labeled() && getzoneid() != GLOBAL_ZONEID) {
		idmapdlog(LOG_ERR,
		    "with Trusted Extensions idmapd runs only in the "
		    "global zone");
		exit(1);
	}

	(void) mutex_init(&_svcstate_lock, USYNC_THREAD, NULL);

	if (_idmapdstate.daemon_mode == TRUE) {
		if (daemonize_start() < 0) {
			(void) idmapdlog(LOG_ERR, "unable to daemonize");
			exit(-1);
		}
	} else
		(void) umask(0077);

	idmap_init_tsd_key();

	init_idmapd();

	/* signal handlers that should run only after we're initialized */
	(void) sigset(SIGTERM, term_handler);
	(void) sigset(SIGUSR1, usr1_handler);
	(void) sigset(SIGHUP, idmap_cfg_hup_handler);

	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID,
	    PRIV_PROC_AUDIT, PRIV_FILE_DAC_READ,
	    (char *)NULL) == -1) {
		idmapdlog(LOG_ERR, "unable to drop privileges");
		exit(1);
	}

	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);

	if (_idmapdstate.daemon_mode == TRUE)
		daemonize_ready();

	/* With doors RPC this just wastes this thread, oh well */
	svc_run();
	return (0);
}

static void
init_idmapd()
{
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

	if (sysinfo(SI_HOSTNAME, _idmapdstate.hostname,
	    sizeof (_idmapdstate.hostname)) == -1) {
		error = errno;
		idmapdlog(LOG_ERR, "unable to determine hostname, error: %d",
		    error);
		exit(1);
	}

	if ((error = init_mapping_system()) < 0) {
		idmapdlog(LOG_ERR, "unable to initialize mapping system");
		exit(error < -2 ? SMF_EXIT_ERR_CONFIG : 1);
	}

	xprt = svc_door_create(idmap_prog_1, IDMAP_PROG, IDMAP_V1, connmaxrec);
	if (xprt == NULL) {
		idmapdlog(LOG_ERR, "unable to create door RPC service");
		goto errout;
	}

	if (!svc_control(xprt, SVCSET_CONNMAXREC, &connmaxrec)) {
		idmapdlog(LOG_ERR, "unable to limit RPC request size");
		goto errout;
	}

	dfd = xprt->xp_fd;

	if (dfd == -1) {
		idmapdlog(LOG_ERR, "unable to register door");
		goto errout;
	}
	if ((error = idmap_reg(dfd)) != 0) {
		idmapdlog(LOG_ERR, "unable to register door (%s)",
		    strerror(errno));
		goto errout;
	}

	if ((error = allocids(_idmapdstate.new_eph_db,
	    8192, &_idmapdstate.next_uid,
	    8192, &_idmapdstate.next_gid)) != 0) {
		idmapdlog(LOG_ERR, "unable to allocate ephemeral IDs (%s)",
		    strerror(errno));
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
fini_idmapd()
{
	idmap_unreg(dfd);
	fini_mapping_system();
	if (xprt != NULL)
		svc_destroy(xprt);
}

static
const char *
get_fmri(void)
{
	static char *fmri = NULL;
	static char buf[60];
	char *s;

	membar_consumer();
	s = fmri;
	if (s != NULL && *s == '\0')
		return (NULL);
	else if (s != NULL)
		return (s);

	if ((s = getenv("SMF_FMRI")) == NULL || strlen(s) >= sizeof (buf))
		buf[0] = '\0';
	else
		(void) strlcpy(buf, s, sizeof (buf));

	membar_producer();
	fmri = buf;

	return (get_fmri());
}

/*
 * Wrappers for smf_degrade/restore_instance()
 *
 * smf_restore_instance() is too heavy duty to be calling every time we
 * have a successful AD name<->SID lookup.
 */
void
degrade_svc(int poke_discovery, const char *reason)
{
	const char *fmri;

	/*
	 * If the config update thread is in a state where auto-discovery could
	 * be re-tried, then this will make it try it -- a sort of auto-refresh.
	 */
	if (poke_discovery)
		idmap_cfg_poke_updates();

	membar_consumer();
	if (degraded)
		return;

	idmapdlog(LOG_ERR, "Degraded operation (%s).  If you are running an "
	    "SMB server in workgroup mode, or if you're not running an SMB "
	    "server, then you can ignore this message", reason);

	membar_producer();
	degraded = 1;

	if ((fmri = get_fmri()) != NULL)
		(void) smf_degrade_instance(fmri, 0);
}

void
restore_svc(void)
{
	const char *fmri;

	membar_consumer();
	if (!degraded)
		return;

	if ((fmri = get_fmri()) == NULL)
		(void) smf_restore_instance(fmri);

	membar_producer();
	degraded = 0;
	idmapdlog(LOG_NOTICE, "Normal operation restored");
}

void
idmapdlog(int pri, const char *format, ...)
{
	va_list args;

	va_start(args, format);

	if (_idmapdstate.debug_mode == TRUE ||
	    _idmapdstate.daemon_mode == FALSE) {
		(void) vfprintf(stderr, format, args);
		(void) fprintf(stderr, "\n");
	}

	/*
	 * We don't want to fill up the logs with useless messages when
	 * we're degraded, but we still want to log.
	 */
	if (degraded)
		pri = LOG_DEBUG;

	(void) vsyslog(pri, format, args);
	va_end(args);
}
