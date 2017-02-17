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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <assert.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <priv.h>
#include <procfs.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/corectl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include "configd.h"

/*
 * This file manages the overall startup and shutdown of configd, as well
 * as managing its door thread pool and per-thread datastructures.
 *
 * 1.  Per-thread Datastructures
 * -----------------------------
 * Each configd thread has an associated thread_info_t which contains its
 * current state.  A pointer is kept to this in TSD, keyed by thread_info_key.
 * The thread_info_ts for all threads in configd are kept on a single global
 * list, thread_list.  After creation, the state in the thread_info structure
 * is only modified by the associated thread, so no locking is needed.  A TSD
 * destructor removes the thread_info from the global list and frees it at
 * pthread_exit() time.
 *
 * Threads access their per-thread data using thread_self()
 *
 * The thread_list is protected by thread_lock, a leaf lock.
 *
 * 2. Door Thread Pool Management
 * ------------------------------
 * Whenever door_return(3door) returns from the kernel and there are no
 * other configd threads waiting for requests, libdoor automatically
 * invokes a function registered with door_server_create(), to request a new
 * door server thread.  The default function just creates a thread that calls
 * door_return(3door).  Unfortunately, since it can take a while for the new
 * thread to *get* to door_return(3door), a stream of requests can cause a
 * large number of threads to be created, even though they aren't all needed.
 *
 * In our callback, new_server_needed(), we limit ourself to two new threads
 * at a time -- this logic is handled in reserve_new_thread().  This keeps
 * us from creating an absurd number of threads in response to peaking load.
 */
static pthread_key_t	thread_info_key;
static pthread_attr_t	thread_attr;

static pthread_mutex_t	thread_lock = PTHREAD_MUTEX_INITIALIZER;
int			num_started;	/* number actually running */
int			num_servers;	/* number in-progress or running */
static uu_list_pool_t	*thread_pool;
uu_list_t		*thread_list;

static thread_info_t	main_thread_info;

static int	finished;

static pid_t	privileged_pid = 0;
static int	privileged_psinfo_fd = -1;

static int	privileged_user = 0;

static priv_set_t *privileged_privs;

static int	log_to_syslog = 0;

int		is_main_repository = 1;

int		max_repository_backups = 4;

#define	CONFIGD_MAX_FDS		262144

const char *
_umem_options_init(void)
{
	/*
	 * Like svc.startd, we set our UMEM_OPTIONS to indicate that we do not
	 * wish to have per-CPU magazines to reduce our memory footprint.  And
	 * as with svc.startd, if svc.configd is so MT-hot that this becomes a
	 * scalability problem, there are deeper issues...
	 */
	return ("nomagazines");		/* UMEM_OPTIONS setting */
}

/*
 * Thanks, Mike
 */
void
abort_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	struct sigaction act;

	(void) sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	(void) sigaction(sig, &act, NULL);

	(void) printstack(2);

	if (sip != NULL && SI_FROMUSER(sip))
		(void) pthread_kill(pthread_self(), sig);
	(void) sigfillset(&ucp->uc_sigmask);
	(void) sigdelset(&ucp->uc_sigmask, sig);
	ucp->uc_flags |= UC_SIGMASK;
	(void) setcontext(ucp);
}

/*
 * Don't want to have more than a couple thread creates outstanding
 */
static int
reserve_new_thread(void)
{
	(void) pthread_mutex_lock(&thread_lock);
	assert(num_started >= 0);
	if (num_servers > num_started + 1) {
		(void) pthread_mutex_unlock(&thread_lock);
		return (0);
	}
	++num_servers;
	(void) pthread_mutex_unlock(&thread_lock);
	return (1);
}

static void
thread_info_free(thread_info_t *ti)
{
	uu_list_node_fini(ti, &ti->ti_node, thread_pool);
	if (ti->ti_ucred != NULL)
		uu_free(ti->ti_ucred);
	uu_free(ti);
}

static void
thread_exiting(void *arg)
{
	thread_info_t *ti = arg;

	if (ti != NULL)
		log_enter(&ti->ti_log);

	(void) pthread_mutex_lock(&thread_lock);
	if (ti != NULL) {
		num_started--;
		uu_list_remove(thread_list, ti);
	}
	assert(num_servers > 0);
	--num_servers;

	if (num_servers == 0) {
		configd_critical("no door server threads\n");
		abort();
	}
	(void) pthread_mutex_unlock(&thread_lock);

	if (ti != NULL && ti != &main_thread_info)
		thread_info_free(ti);
}

void
thread_newstate(thread_info_t *ti, thread_state_t newstate)
{
	ti->ti_ucred_read = 0;			/* invalidate cached ucred */
	if (newstate != ti->ti_state) {
		ti->ti_prev_state = ti->ti_state;
		ti->ti_state = newstate;
		ti->ti_lastchange = gethrtime();
	}
}

thread_info_t *
thread_self(void)
{
	return (pthread_getspecific(thread_info_key));
}

/*
 * get_ucred() returns NULL if it was unable to get the credential
 * information.
 */
ucred_t *
get_ucred(void)
{
	thread_info_t *ti = thread_self();
	ucred_t **ret = &ti->ti_ucred;

	if (ti->ti_ucred_read)
		return (*ret);			/* cached value */

	if (door_ucred(ret) != 0)
		return (NULL);
	ti->ti_ucred_read = 1;

	return (*ret);
}

int
ucred_is_privileged(ucred_t *uc)
{
	const priv_set_t *ps;

	if ((ps = ucred_getprivset(uc, PRIV_EFFECTIVE)) != NULL) {
		if (priv_isfullset(ps))
			return (1);		/* process has all privs */

		if (privileged_privs != NULL &&
		    priv_issubset(privileged_privs, ps))
			return (1);		/* process has zone privs */
	}

	return (0);
}

/*
 * The purpose of this function is to get the audit session data for use in
 * generating SMF audit events.  We use a single audit session per client.
 *
 * get_audit_session() may return NULL.  It is legal to use a NULL pointer
 * in subsequent calls to adt_* functions.
 */
adt_session_data_t *
get_audit_session(void)
{
	thread_info_t	*ti = thread_self();

	return (ti->ti_active_client->rc_adt_session);
}

static void *
thread_start(void *arg)
{
	thread_info_t *ti = arg;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	(void) pthread_mutex_lock(&thread_lock);
	num_started++;
	(void) uu_list_insert_after(thread_list, uu_list_last(thread_list),
	    ti);
	(void) pthread_mutex_unlock(&thread_lock);
	(void) pthread_setspecific(thread_info_key, ti);

	thread_newstate(ti, TI_DOOR_RETURN);

	/*
	 * Start handling door calls
	 */
	(void) door_return(NULL, 0, NULL, 0);
	return (arg);
}

static void
new_thread_needed(door_info_t *dip)
{
	thread_info_t *ti;

	sigset_t new, old;

	assert(dip == NULL);

	if (!reserve_new_thread())
		return;

	if ((ti = uu_zalloc(sizeof (*ti))) == NULL)
		goto fail;

	uu_list_node_init(ti, &ti->ti_node, thread_pool);
	ti->ti_state = TI_CREATED;
	ti->ti_prev_state = TI_CREATED;

	if ((ti->ti_ucred = uu_zalloc(ucred_size())) == NULL)
		goto fail;

	(void) sigfillset(&new);
	(void) pthread_sigmask(SIG_SETMASK, &new, &old);
	if ((errno = pthread_create(&ti->ti_thread, &thread_attr, thread_start,
	    ti)) != 0) {
		(void) pthread_sigmask(SIG_SETMASK, &old, NULL);
		goto fail;
	}

	(void) pthread_sigmask(SIG_SETMASK, &old, NULL);
	return;

fail:
	/*
	 * Since the thread_info structure was never linked onto the
	 * thread list, thread_exiting() can't handle the cleanup.
	 */
	thread_exiting(NULL);
	if (ti != NULL)
		thread_info_free(ti);
}

int
create_connection(ucred_t *uc, repository_door_request_t *rp,
    size_t rp_size, int *out_fd)
{
	int flags;
	int privileged = 0;
	uint32_t debugflags = 0;
	psinfo_t info;

	if (privileged_pid != 0) {
		/*
		 * in privileged pid mode, we only allow connections from
		 * our original parent -- the psinfo read verifies that
		 * it is the same process which we started with.
		 */
		if (ucred_getpid(uc) != privileged_pid ||
		    read(privileged_psinfo_fd, &info, sizeof (info)) !=
		    sizeof (info))
			return (REPOSITORY_DOOR_FAIL_PERMISSION_DENIED);

		privileged = 1;			/* it gets full privileges */
	} else if (privileged_user != 0) {
		/*
		 * in privileged user mode, only one particular user is
		 * allowed to connect to us, and they can do anything.
		 */
		if (ucred_geteuid(uc) != privileged_user)
			return (REPOSITORY_DOOR_FAIL_PERMISSION_DENIED);

		privileged = 1;
	}

	/*
	 * Check that rp, of size rp_size, is large enough to
	 * contain field 'f'.  If so, write the value into *out, and return 1.
	 * Otherwise, return 0.
	 */
#define	GET_ARG(rp, rp_size, f, out)					\
	(((rp_size) >= offsetofend(repository_door_request_t, f)) ?	\
	    ((*(out) = (rp)->f), 1) : 0)

	if (!GET_ARG(rp, rp_size, rdr_flags, &flags))
		return (REPOSITORY_DOOR_FAIL_BAD_REQUEST);

#if (REPOSITORY_DOOR_FLAG_ALL != REPOSITORY_DOOR_FLAG_DEBUG)
#error Need to update flag checks
#endif

	if (flags & ~REPOSITORY_DOOR_FLAG_ALL)
		return (REPOSITORY_DOOR_FAIL_BAD_FLAG);

	if (flags & REPOSITORY_DOOR_FLAG_DEBUG)
		if (!GET_ARG(rp, rp_size, rdr_debug, &debugflags))
			return (REPOSITORY_DOOR_FAIL_BAD_REQUEST);
#undef GET_ARG

	return (create_client(ucred_getpid(uc), debugflags, privileged,
	    out_fd));
}

void
configd_vlog(int severity, const char *prefix, const char *message,
    va_list args)
{
	if (log_to_syslog)
		vsyslog(severity, message, args);
	else {
		flockfile(stderr);
		if (prefix != NULL)
			(void) fprintf(stderr, "%s", prefix);
		(void) vfprintf(stderr, message, args);
		if (message[0] == 0 || message[strlen(message) - 1] != '\n')
			(void) fprintf(stderr, "\n");
		funlockfile(stderr);
	}
}

void
configd_vcritical(const char *message, va_list args)
{
	configd_vlog(LOG_CRIT, "svc.configd: Fatal error: ", message, args);
}

void
configd_critical(const char *message, ...)
{
	va_list args;
	va_start(args, message);
	configd_vcritical(message, args);
	va_end(args);
}

void
configd_info(const char *message, ...)
{
	va_list args;
	va_start(args, message);
	configd_vlog(LOG_INFO, "svc.configd: ", message, args);
	va_end(args);
}

static void
usage(const char *prog, int ret)
{
	(void) fprintf(stderr,
	    "usage: %s [-np] [-d door_path] [-r repository_path]\n"
	    "    [-t nonpersist_repository]\n", prog);
	exit(ret);
}

/*ARGSUSED*/
static void
handler(int sig, siginfo_t *info, void *data)
{
	finished = 1;
}

static int pipe_fd = -1;

static int
daemonize_start(void)
{
	char data;
	int status;

	int filedes[2];
	pid_t pid;

	(void) close(0);
	(void) dup2(2, 1);		/* stderr only */

	if (pipe(filedes) < 0)
		return (-1);

	if ((pid = fork1()) < 0)
		return (-1);

	if (pid != 0) {
		/*
		 * parent
		 */
		struct sigaction act;

		act.sa_sigaction = SIG_DFL;
		(void) sigemptyset(&act.sa_mask);
		act.sa_flags = 0;

		(void) sigaction(SIGPIPE, &act, NULL);	/* ignore SIGPIPE */

		(void) close(filedes[1]);
		if (read(filedes[0], &data, 1) == 1) {
			/* presume success */
			_exit(CONFIGD_EXIT_OKAY);
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

	/*
	 * generic Unix setup
	 */
	(void) setsid();
	(void) umask(0077);

	return (0);
}

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

const char *
regularize_path(const char *dir, const char *base, char *tmpbuf)
{
	if (base == NULL)
		return (NULL);
	if (base[0] == '/')
		return (base);

	if (snprintf(tmpbuf, PATH_MAX, "%s/%s", dir, base) >= PATH_MAX) {
		(void) fprintf(stderr, "svc.configd: %s/%s: path too long\n",
		    dir, base);
		exit(CONFIGD_EXIT_BAD_ARGS);
	}

	return (tmpbuf);
}

int
main(int argc, char *argv[])
{
	thread_info_t *ti = &main_thread_info;

	char pidpath[sizeof ("/proc/" "/psinfo") + 10];

	struct rlimit fd_new;

	const char *endptr;
	sigset_t myset;
	int c;
	int ret;
	int fd;

	char curdir[PATH_MAX];
	char dbtmp[PATH_MAX];
	char npdbtmp[PATH_MAX];
	char doortmp[PATH_MAX];

	const char *dbpath = NULL;
	const char *npdbpath = NULL;
	const char *doorpath = REPOSITORY_DOOR_NAME;
	struct sigaction act;

	int daemonize = 1;		/* default to daemonizing */
	int have_npdb = 1;

	closefrom(3);			/* get rid of extraneous fds */

	if (getcwd(curdir, sizeof (curdir)) == NULL) {
		(void) fprintf(stderr,
		    "%s: unable to get current directory: %s\n",
		    argv[0], strerror(errno));
		exit(CONFIGD_EXIT_INIT_FAILED);
	}

	while ((c = getopt(argc, argv, "Dnpd:r:t:")) != -1) {
		switch (c) {
		case 'n':
			daemonize = 0;
			break;
		case 'd':
			doorpath = regularize_path(curdir, optarg, doortmp);
			have_npdb = 0;		/* default to no non-persist */
			break;
		case 'p':
			log_to_syslog = 0;	/* don't use syslog */

			/*
			 * If our parent exits while we're opening its /proc
			 * psinfo, we're vulnerable to a pid wrapping.  To
			 * protect against that, re-check our ppid after
			 * opening it.
			 */
			privileged_pid = getppid();
			(void) snprintf(pidpath, sizeof (pidpath),
			    "/proc/%d/psinfo", privileged_pid);
			if ((fd = open(pidpath, O_RDONLY)) < 0 ||
			    getppid() != privileged_pid) {
				(void) fprintf(stderr,
				    "%s: unable to get parent info\n", argv[0]);
				exit(CONFIGD_EXIT_BAD_ARGS);
			}
			privileged_psinfo_fd = fd;
			break;
		case 'r':
			dbpath = regularize_path(curdir, optarg, dbtmp);
			is_main_repository = 0;
			break;
		case 't':
			npdbpath = regularize_path(curdir, optarg, npdbtmp);
			is_main_repository = 0;
			break;
		default:
			usage(argv[0], CONFIGD_EXIT_BAD_ARGS);
			break;
		}
	}

	/*
	 * If we're not running as root, allow our euid full access, and
	 * everyone else no access.
	 */
	if (privileged_pid == 0 && geteuid() != 0) {
		privileged_user = geteuid();
	}

	privileged_privs = priv_str_to_set("zone", "", &endptr);
	if (endptr != NULL && privileged_privs != NULL) {
		priv_freeset(privileged_privs);
		privileged_privs = NULL;
	}

	openlog("svc.configd", LOG_PID | LOG_CONS, LOG_DAEMON);
	(void) setlogmask(LOG_UPTO(LOG_NOTICE));

	/*
	 * if a non-persist db is specified, always enable it
	 */
	if (npdbpath)
		have_npdb = 1;

	if (optind != argc)
		usage(argv[0], CONFIGD_EXIT_BAD_ARGS);

	if (daemonize) {
		if (getuid() == 0)
			(void) chdir("/");
		if (daemonize_start() < 0) {
			(void) perror("unable to daemonize");
			exit(CONFIGD_EXIT_INIT_FAILED);
		}
	}
	if (getuid() == 0)
		(void) core_set_process_path(CONFIGD_CORE,
		    strlen(CONFIGD_CORE) + 1, getpid());

	/*
	 * this should be enabled once we can drop privileges and still get
	 * a core dump.
	 */
#if 0
	/* turn off basic privileges we do not need */
	(void) priv_set(PRIV_OFF, PRIV_PERMITTED, PRIV_FILE_LINK_ANY,
	    PRIV_PROC_EXEC, PRIV_PROC_FORK, PRIV_PROC_SESSION, NULL);
#endif

	/* not that we can exec, but to be safe, shut them all off... */
	(void) priv_set(PRIV_SET, PRIV_INHERITABLE, NULL);

	(void) sigfillset(&act.sa_mask);

	/* signals to ignore */
	act.sa_sigaction = SIG_IGN;
	act.sa_flags = 0;
	(void) sigaction(SIGPIPE, &act, NULL);
	(void) sigaction(SIGALRM, &act, NULL);
	(void) sigaction(SIGUSR1, &act, NULL);
	(void) sigaction(SIGUSR2, &act, NULL);
	(void) sigaction(SIGPOLL, &act, NULL);

	/* signals to abort on */
	act.sa_sigaction = (void (*)(int, siginfo_t *, void *))&abort_handler;
	act.sa_flags = SA_SIGINFO;

	(void) sigaction(SIGABRT, &act, NULL);

	/* signals to handle */
	act.sa_sigaction = &handler;
	act.sa_flags = SA_SIGINFO;

	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);

	(void) sigemptyset(&myset);
	(void) sigaddset(&myset, SIGHUP);
	(void) sigaddset(&myset, SIGINT);
	(void) sigaddset(&myset, SIGTERM);

	if ((errno = pthread_attr_init(&thread_attr)) != 0) {
		(void) perror("initializing");
		exit(CONFIGD_EXIT_INIT_FAILED);
	}

	/*
	 * Set the hard and soft limits to CONFIGD_MAX_FDS.
	 */
	fd_new.rlim_max = fd_new.rlim_cur = CONFIGD_MAX_FDS;
	(void) setrlimit(RLIMIT_NOFILE, &fd_new);

#ifndef NATIVE_BUILD /* Allow building on snv_38 and earlier; remove later. */
	(void) enable_extended_FILE_stdio(-1, -1);
#endif

	if ((ret = backend_init(dbpath, npdbpath, have_npdb)) !=
	    CONFIGD_EXIT_OKAY)
		exit(ret);

	if (!client_init())
		exit(CONFIGD_EXIT_INIT_FAILED);

	if (!rc_node_init())
		exit(CONFIGD_EXIT_INIT_FAILED);

	(void) pthread_attr_setdetachstate(&thread_attr,
	    PTHREAD_CREATE_DETACHED);
	(void) pthread_attr_setscope(&thread_attr, PTHREAD_SCOPE_SYSTEM);

	if ((errno = pthread_key_create(&thread_info_key,
	    thread_exiting)) != 0) {
		perror("pthread_key_create");
		exit(CONFIGD_EXIT_INIT_FAILED);
	}

	if ((thread_pool = uu_list_pool_create("thread_pool",
	    sizeof (thread_info_t), offsetof(thread_info_t, ti_node),
	    NULL, UU_LIST_POOL_DEBUG)) == NULL) {
		configd_critical("uu_list_pool_create: %s\n",
		    uu_strerror(uu_error()));
		exit(CONFIGD_EXIT_INIT_FAILED);
	}

	if ((thread_list = uu_list_create(thread_pool, NULL, 0)) == NULL) {
		configd_critical("uu_list_create: %s\n",
		    uu_strerror(uu_error()));
		exit(CONFIGD_EXIT_INIT_FAILED);
	}

	(void) memset(ti, '\0', sizeof (*ti));
	uu_list_node_init(ti, &ti->ti_node, thread_pool);
	(void) uu_list_insert_before(thread_list, uu_list_first(thread_list),
	    ti);

	ti->ti_thread = pthread_self();
	ti->ti_state = TI_SIGNAL_WAIT;
	ti->ti_prev_state = TI_SIGNAL_WAIT;

	(void) pthread_setspecific(thread_info_key, ti);

	(void) door_server_create(new_thread_needed);

	if (!setup_main_door(doorpath)) {
		configd_critical("Setting up main door failed.\n");
		exit(CONFIGD_EXIT_DOOR_INIT_FAILED);
	}

	if (daemonize)
		daemonize_ready();

	(void) pthread_sigmask(SIG_BLOCK, &myset, NULL);
	while (!finished) {
		int sig = sigwait(&myset);
		if (sig > 0) {
			break;
		}
	}

	backend_fini();

	return (CONFIGD_EXIT_OKAY);
}
