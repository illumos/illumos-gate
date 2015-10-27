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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */


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
#include <pthread.h>
#include <stdarg.h>
#include <assert.h>
#include <note.h>

#define	CBUFSIZ 26	/* ctime(3c) */

static void	term_handler(int);
static void	init_idmapd();
static void	fini_idmapd();

/* The DC Locator lives inside idmap (for now). */
extern void	init_dc_locator(void);
extern void	fini_dc_locator(void);

idmapd_state_t	_idmapdstate;

SVCXPRT *xprt = NULL;

static int dfd = -1;		/* our door server fildes, for unregistration */
static boolean_t degraded = B_FALSE;


static uint32_t		num_threads = 0;
static pthread_key_t	create_threads_key;
static uint32_t		max_threads = 40;

/*
 * Server door thread start routine.
 *
 * Set a TSD value to the door thread. This enables the destructor to
 * be called when this thread exits.
 */
/*ARGSUSED*/
static void *
idmapd_door_thread_start(void *arg)
{
	static void *value = 0;

	/*
	 * Disable cancellation to avoid memory leaks from not running
	 * the thread cleanup code.
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) pthread_setspecific(create_threads_key, value);
	(void) door_return(NULL, 0, NULL, 0);

	/* make lint happy */
	return (NULL);
}

/*
 * Server door threads creation
 */
/*ARGSUSED*/
static void
idmapd_door_thread_create(door_info_t *dip)
{
	int		num;
	pthread_t	thread_id;

	if ((num = atomic_inc_32_nv(&num_threads)) > max_threads) {
		atomic_dec_32(&num_threads);
		idmapdlog(LOG_DEBUG,
		    "thread creation refused - %d threads currently active",
		    num - 1);
		return;
	}
	(void) pthread_create(&thread_id, NULL, idmapd_door_thread_start, NULL);
	idmapdlog(LOG_DEBUG,
	    "created thread ID %d - %d threads currently active",
	    thread_id, num);
}

/*
 * Server door thread cleanup
 */
/*ARGSUSED*/
static void
idmapd_door_thread_cleanup(void *arg)
{
	int num;

	num = atomic_dec_32_nv(&num_threads);
	idmapdlog(LOG_DEBUG,
	    "exiting thread ID %d - %d threads currently active",
	    pthread_self(), num);
}

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
	fini_dc_locator();
	fini_idmapd();
	_exit(0);
}

/*ARGSUSED*/
static void
usr1_handler(int sig)
{
	NOTE(ARGUNUSED(sig))
	print_idmapdstate();
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
	struct rlimit rl;

	if (rwlock_init(&_idmapdstate.rwlk_cfg, USYNC_THREAD, NULL) != 0)
		return (-1);
	if (mutex_init(&_idmapdstate.addisc_lk, USYNC_THREAD, NULL) != 0)
		return (-1);
	if (cond_init(&_idmapdstate.addisc_cv, USYNC_THREAD, NULL) != 0)
		return (-1);

	_idmapdstate.daemon_mode = TRUE;
	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
			case 'd':
				_idmapdstate.daemon_mode = FALSE;
				break;
			default:
				(void) fprintf(stderr,
				    "Usage: /usr/lib/idmapd [-d]\n");
				return (SMF_EXIT_ERR_CONFIG);
		}
	}

	/* set locale and domain for internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	idmap_set_logger(idmapdlog);
	adutils_set_logger(idmapdlog);

	if (is_system_labeled() && getzoneid() != GLOBAL_ZONEID) {
		idmapdlog(LOG_ERR,
		    "with Trusted Extensions idmapd runs only in the "
		    "global zone");
		exit(1);
	}

	/*
	 * Raise the fd limit to max
	 */
	if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
		idmapdlog(LOG_ERR, "getrlimit failed");
	} else if (rl.rlim_cur < rl.rlim_max) {
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
			idmapdlog(LOG_ERR,
			    "Unable to raise RLIMIT_NOFILE to %d",
			    rl.rlim_cur);
	}

	(void) mutex_init(&_svcstate_lock, USYNC_THREAD, NULL);

	if (_idmapdstate.daemon_mode == TRUE) {
		if (daemonize_start() < 0) {
			idmapdlog(LOG_ERR, "unable to daemonize");
			exit(-1);
		}
	} else
		(void) umask(0077);

	idmap_init_tsd_key();

	init_idmapd();
	init_dc_locator();

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
	int	connmaxrec = IDMAP_MAX_DOOR_RPC;


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
	(void) putenv("KRB5CCNAME=" IDMAP_CACHEDIR "/ccache");
	(void) putenv("MS_INTEROP=1");

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

	(void) door_server_create(idmapd_door_thread_create);
	if ((error = pthread_key_create(&create_threads_key,
	    idmapd_door_thread_cleanup)) != 0) {
		idmapdlog(LOG_ERR, "unable to create threads key (%s)",
		    strerror(error));
		goto errout;
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
	if ((error = __idmap_reg(dfd)) != 0) {
		idmapdlog(LOG_ERR, "unable to register door (%s)",
		    strerror(errno));
		goto errout;
	}

	if ((error = allocids(_idmapdstate.new_eph_db,
	    8192, &_idmapdstate.next_uid,
	    8192, &_idmapdstate.next_gid)) != 0) {
		idmapdlog(LOG_ERR, "unable to allocate ephemeral IDs (%s)",
		    strerror(errno));
		_idmapdstate.next_uid = IDMAP_SENTINEL_PID;
		_idmapdstate.limit_uid = IDMAP_SENTINEL_PID;
		_idmapdstate.next_gid = IDMAP_SENTINEL_PID;
		_idmapdstate.limit_gid = IDMAP_SENTINEL_PID;
	} else {
		_idmapdstate.limit_uid = _idmapdstate.next_uid + 8192;
		_idmapdstate.limit_gid = _idmapdstate.next_gid + 8192;
	}

	if (DBG(CONFIG, 1))
		print_idmapdstate();

	return;

errout:
	fini_idmapd();
	exit(1);
}

static void
fini_idmapd()
{
	(void) __idmap_unreg(dfd);
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

	membar_consumer();
	if (degraded)
		return;

	idmapdlog(LOG_ERR, "Degraded operation (%s).", reason);

	membar_producer();
	degraded = B_TRUE;

	if ((fmri = get_fmri()) != NULL)
		(void) smf_degrade_instance(fmri, 0);

	/*
	 * If the config update thread is in a state where auto-discovery could
	 * be re-tried, then this will make it try it -- a sort of auto-refresh.
	 */
	if (poke_discovery)
		idmap_cfg_poke_updates();
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
	degraded = B_FALSE;

	idmapdlog(LOG_NOTICE, "Normal operation restored");
}


/* printflike */
void
idmapdlog(int pri, const char *format, ...) {
	static time_t prev_ts;
	va_list args;
	char cbuf[CBUFSIZ];
	time_t ts;

	ts = time(NULL);
	if (prev_ts != ts) {
		prev_ts = ts;
		/* NB: cbuf has \n */
		(void) fprintf(stderr, "@ %s",
		    ctime_r(&ts, cbuf, sizeof (cbuf)));
	}

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	(void) fprintf(stderr, "\n");
	va_end(args);

	/*
	 * We don't want to fill up the logs with useless messages when
	 * we're degraded, but we still want to log.
	 */
	if (degraded)
		pri = LOG_DEBUG;

	va_start(args, format);
	vsyslog(pri, format, args);
	va_end(args);
}

static void
trace_str(nvlist_t *entry, char *n1, char *n2, char *str)
{
	char name[IDMAP_TRACE_NAME_MAX+1];	/* Max used is only about 11 */

	(void) strlcpy(name, n1, sizeof (name));
	if (n2 != NULL)
		(void) strlcat(name, n2, sizeof (name));

	(void) nvlist_add_string(entry, name, str);
}

static void
trace_int(nvlist_t *entry, char *n1, char *n2, int64_t i)
{
	char name[IDMAP_TRACE_NAME_MAX+1];	/* Max used is only about 11 */

	(void) strlcpy(name, n1, sizeof (name));
	if (n2 != NULL)
		(void) strlcat(name, n2, sizeof (name));

	(void) nvlist_add_int64(entry, name, i);
}

static void
trace_sid(nvlist_t *entry, char *n1, char *n2, idmap_sid *sid)
{
	char *str;

	(void) asprintf(&str, "%s-%u", sid->prefix, sid->rid);
	if (str == NULL)
		return;

	trace_str(entry, n1, n2, str);
	free(str);
}

static void
trace_id(nvlist_t *entry, char *fromto, idmap_id *id, char *name, char *domain)
{
	trace_int(entry, fromto, IDMAP_TRACE_TYPE, (int64_t)id->idtype);
	if (IS_ID_SID(*id)) {
		if (name != NULL) {
			char *str;

			(void) asprintf(&str, "%s%s%s", name,
			    domain == NULL ? "" : "@",
			    domain == NULL ? "" : domain);
			if (str != NULL) {
				trace_str(entry, fromto, IDMAP_TRACE_NAME, str);
				free(str);
			}
		}
		if (id->idmap_id_u.sid.prefix != NULL) {
			trace_sid(entry, fromto, IDMAP_TRACE_SID,
			    &id->idmap_id_u.sid);
		}
	} else if (IS_ID_POSIX(*id)) {
		if (name != NULL)
			trace_str(entry, fromto, IDMAP_TRACE_NAME, name);
		if (id->idmap_id_u.uid != IDMAP_SENTINEL_PID) {
			trace_int(entry, fromto, IDMAP_TRACE_UNIXID,
			    (int64_t)id->idmap_id_u.uid);
		}
	}
}

/*
 * Record a trace event.  TRACE() has already decided whether or not
 * tracing is required; what we do here is collect the data and send it
 * to its destination - to the trace log in the response, if
 * IDMAP_REQ_FLG_TRACE is set, and to the SMF service log, if debug/mapping
 * is greater than zero.
 */
int
trace(idmap_mapping *req, idmap_id_res *res, char *fmt, ...)
{
	va_list va;
	char *buf;
	int err;
	nvlist_t *entry;

	assert(req != NULL);
	assert(res != NULL);

	err = nvlist_alloc(&entry, NV_UNIQUE_NAME, 0);
	if (err != 0) {
		(void) fprintf(stderr, "trace nvlist_alloc(entry):  %s\n",
		    strerror(err));
		return (0);
	}

	trace_id(entry, "from", &req->id1, req->id1name, req->id1domain);
	trace_id(entry, "to", &res->id, req->id2name, req->id2domain);

	if (IDMAP_ERROR(res->retcode)) {
		trace_int(entry, IDMAP_TRACE_ERROR, NULL,
		    (int64_t)res->retcode);
	}

	va_start(va, fmt);
	(void) vasprintf(&buf, fmt, va);
	va_end(va);
	if (buf != NULL) {
		trace_str(entry, IDMAP_TRACE_MESSAGE, NULL, buf);
		free(buf);
	}

	if (DBG(MAPPING, 1))
		idmap_trace_print_1(stderr, "", entry);

	if (req->flag & IDMAP_REQ_FLG_TRACE) {
		/* Lazily allocate the trace list */
		if (res->info.trace == NULL) {
			err = nvlist_alloc(&res->info.trace, 0, 0);
			if (err != 0) {
				res->info.trace = NULL; /* just in case */
				(void) fprintf(stderr,
				    "trace nvlist_alloc(trace):  %s\n",
				    strerror(err));
				nvlist_free(entry);
				return (0);
			}
		}
		(void) nvlist_add_nvlist(res->info.trace, "", entry);
		/* Note that entry is copied, so we must still free our copy */
	}

	nvlist_free(entry);

	return (0);
}
