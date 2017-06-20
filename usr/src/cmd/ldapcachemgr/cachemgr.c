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
 * Simple doors ldap cache daemon
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <door.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <thread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <memory.h>
#include <sys/types.h>
#include <syslog.h>
#include <locale.h>	/* LC_ALL */

#include <alloca.h>
#include <ucontext.h>
#include <stddef.h>	/* offsetof */
#include <priv.h>

#include "getxby_door.h"
#include "cachemgr.h"

static void	detachfromtty();
admin_t		current_admin;
static int	will_become_server;

static void switcher(void *cookie, char *argp, size_t arg_size,
			door_desc_t *dp, uint_t n_desc);
static void usage(char *s);
static int cachemgr_set_lf(admin_t *ptr, char *logfile);
static int client_getadmin(admin_t *ptr);
static int setadmin(ldap_call_t *ptr);
static  int client_setadmin(admin_t *ptr);
static int client_showstats(admin_t *ptr);
static int is_root(int free_uc, char *dc_str, ucred_t **uc);
int is_root_or_all_privs(char *dc_str, ucred_t **ucp);
static void admin_modify(LineBuf *config_info, ldap_call_t *in);

#ifdef SLP
int			use_slp = 0;
static unsigned int	refresh = 10800;	/* dynamic discovery interval */
#endif /* SLP */

static ldap_stat_t *
getcacheptr(char *s)
{
	static const char *caches[1] = {"ldap"};

	if (strncmp(caches[0], s, strlen(caches[0])) == 0)
		return (&current_admin.ldap_stat);

	return (NULL);
}

char *
getcacheopt(char *s)
{
	while (*s && *s != ',')
		s++;
	return ((*s == ',') ? (s + 1) : NULL);
}

/*
 *  This is here to prevent the ldap_cachemgr becomes
 *  daemonlized to early to soon during boot time.
 *  This causes problems during boot when automounter
 *  and others try to use libsldap before ldap_cachemgr
 *  finishes walking the server list.
 */
static void
sig_ok_to_exit(int signo)
{
	if (signo == SIGUSR1) {
		logit("sig_ok_to_exit(): parent exiting...\n");
		exit(0);
	} else {
		logit("sig_ok_to_exit(): invalid signal(%d) received.\n",
		    signo);
		syslog(LOG_ERR, gettext("ldap_cachemgr: "
		    "invalid signal(%d) received."), signo);
		exit(1);
	}
}
#define	LDAP_TABLES		1	/* ldap */
#define	TABLE_THREADS		10
#define	COMMON_THREADS		20
#define	CACHE_MISS_THREADS	(COMMON_THREADS + LDAP_TABLES * TABLE_THREADS)
#define	CACHE_HIT_THREADS	20
/*
 * There is only one thread handling GETSTATUSCHANGE START from main nscd
 * most of time. But it could happen that a main nscd is restarted, old main
 * nscd's handling thread is still alive when new main nscd starts and sends
 * START, or old main dies. STOP is not sent in both cases.
 * The main nscd requires 2 threads to handle START and STOP. So max number
 * of change threads is set to 4.
 */
#define	MAX_CHG_THREADS		4
#define	MAX_SERVER_THREADS	(CACHE_HIT_THREADS + CACHE_MISS_THREADS + \
				MAX_CHG_THREADS)

static sema_t common_sema;
static sema_t ldap_sema;
static thread_key_t lookup_state_key;
static int chg_threads_num = 0;
static mutex_t chg_threads_num_lock = DEFAULTMUTEX;

static void
initialize_lookup_clearance()
{
	(void) thr_keycreate(&lookup_state_key, NULL);
	(void) sema_init(&common_sema, COMMON_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&ldap_sema, TABLE_THREADS, USYNC_THREAD, 0);
}

int
get_clearance(int callnumber)
{
	sema_t	*table_sema = NULL;
	char	*tab;

	if (sema_trywait(&common_sema) == 0) {
		(void) thr_setspecific(lookup_state_key, NULL);
		return (0);
	}

	switch (callnumber) {
		case GETLDAPCONFIG:
			tab = "ldap";
			table_sema = &ldap_sema;
			break;
		default:
			logit("Internal Error: get_clearance\n");
			break;
	}

	if (sema_trywait(table_sema) == 0) {
		(void) thr_setspecific(lookup_state_key, (void*)1);
		return (0);
	}

	if (current_admin.debug_level >= DBG_CANT_FIND) {
		logit("get_clearance: throttling load for %s table\n", tab);
	}

	return (-1);
}

int
release_clearance(int callnumber)
{
	int	which;
	sema_t	*table_sema = NULL;

	(void) thr_getspecific(lookup_state_key, (void**)&which);
	if (which == 0) /* from common pool */ {
		(void) sema_post(&common_sema);
		return (0);
	}

	switch (callnumber) {
		case GETLDAPCONFIG:
			table_sema = &ldap_sema;
			break;
		default:
			logit("Internal Error: release_clearance\n");
			break;
	}
	(void) sema_post(table_sema);

	return (0);
}


static mutex_t		create_lock;
static int		num_servers = 0;
static thread_key_t	server_key;


/*
 * Bind a TSD value to a server thread. This enables the destructor to
 * be called if/when this thread exits.  This would be a programming error,
 * but better safe than sorry.
 */

/*ARGSUSED*/
static void *
server_tsd_bind(void *arg)
{
	static void	*value = 0;

	/*
	 * disable cancellation to prevent hangs when server
	 * threads disappear
	 */

	(void) thr_setspecific(server_key, value);
	(void) door_return(NULL, 0, NULL, 0);

	return (value);
}

/*
 * Server threads are created here.
 */

/*ARGSUSED*/
static void
server_create(door_info_t *dip)
{
	(void) mutex_lock(&create_lock);
	if (++num_servers > MAX_SERVER_THREADS) {
		num_servers--;
		(void) mutex_unlock(&create_lock);
		return;
	}
	(void) mutex_unlock(&create_lock);
	(void) thr_create(NULL, 0, server_tsd_bind, NULL,
	    THR_BOUND|THR_DETACHED, NULL);
}

/*
 * Server thread are destroyed here
 */

/*ARGSUSED*/
static void
server_destroy(void *arg)
{
	(void) mutex_lock(&create_lock);
	num_servers--;
	(void) mutex_unlock(&create_lock);
}

static void		client_killserver();

int
main(int argc, char ** argv)
{
	int			did;
	int			opt;
	int			errflg = 0;
	int			showstats = 0;
	int			doset = 0;
	int			dofg = 0;
	struct stat		buf;
	sigset_t		myset;
	struct sigaction	sighupaction;
	int			debug_level = 0;

	/* setup for localization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	openlog("ldap_cachemgr", LOG_PID, LOG_DAEMON);

	if (chdir(NSLDAPDIRECTORY) < 0) {
		(void) fprintf(stderr, gettext("chdir(\"%s\") failed: %s\n"),
		    NSLDAPDIRECTORY, strerror(errno));
		exit(1);
	}

	/*
	 * Correctly set file mode creation mask, so to make the new files
	 * created for door calls being readable by all.
	 */
	(void) umask(0);

	/*
	 *  Special case non-root user here -	he/she/they/it can just print
	 *					stats
	 */

	if (geteuid()) {
		if (argc != 2 || strcmp(argv[1], "-g")) {
			(void) fprintf(stderr,
			    gettext("Must be root to use any option "
			    "other than -g.\n\n"));
			usage(argv[0]);
		}

		if ((__ns_ldap_cache_ping() != NS_CACHE_SUCCESS) ||
		    (client_getadmin(&current_admin) != 0)) {
			(void) fprintf(stderr,
			    gettext("%s doesn't appear to be running.\n"),
			    argv[0]);
			exit(1);
		}
		(void) client_showstats(&current_admin);
		exit(0);
	}



	/*
	 *  Determine if there is already a daemon running
	 */

	will_become_server = (__ns_ldap_cache_ping() != NS_CACHE_SUCCESS);

	/*
	 *  load normal config file
	 */

	if (will_become_server) {
		static const ldap_stat_t defaults = {
			0,		/* stat */
			DEFAULTTTL};	/* ttl */

		current_admin.ldap_stat = defaults;
		(void) strcpy(current_admin.logfile, LOGFILE);
	} else {
		if (client_getadmin(&current_admin)) {
			(void) fprintf(stderr, gettext("Cannot contact %s "
			    "properly(?)\n"), argv[0]);
			exit(1);
		}
	}

#ifndef SLP
	while ((opt = getopt(argc, argv, "fKgl:r:d:")) != EOF) {
#else
	while ((opt = getopt(argc, argv, "fKgs:l:r:d:")) != EOF) {
#endif /* SLP */
		ldap_stat_t	*cache;

		switch (opt) {
		case 'K':
			client_killserver();
			exit(0);
			break;
		case 'g':
			showstats++;
			break;
		case 'f':
			dofg++;
			break;
		case 'r':
			doset++;
			cache = getcacheptr("ldap");
			if (!optarg) {
				errflg++;
				break;
			}
			cache->ldap_ttl = atoi(optarg);
			break;
		case 'l':
			doset++;
			(void) strlcpy(current_admin.logfile,
			    optarg, sizeof (current_admin.logfile));
			break;
		case 'd':
			doset++;
			debug_level = atoi(optarg);
			break;
#ifdef SLP
		case 's':	/* undocumented: use dynamic (SLP) config */
			use_slp = 1;
			break;
#endif /* SLP */
		default:
			errflg++;
			break;
		}
	}

	if (errflg)
		usage(argv[0]);

	/*
	 * will not show statistics if no daemon running
	 */
	if (will_become_server && showstats) {
		(void) fprintf(stderr,
		    gettext("%s doesn't appear to be running.\n"),
		    argv[0]);
		exit(1);
	}

	if (!will_become_server) {
		if (showstats) {
			(void) client_showstats(&current_admin);
		}
		if (doset) {
			current_admin.debug_level = debug_level;
			if (client_setadmin(&current_admin) < 0) {
				(void) fprintf(stderr,
				    gettext("Error during admin call\n"));
				exit(1);
			}
		}
		if (!showstats && !doset) {
			(void) fprintf(stderr,
			gettext("%s already running....use '%s "
			    "-K' to stop\n"), argv[0], argv[0]);
		}
		exit(0);
	}

	/*
	 *   daemon from here on
	 */

	if (debug_level) {
		/*
		 * we're debugging...
		 */
		if (strlen(current_admin.logfile) == 0)
			/*
			 * no specified log file
			 */
			(void) strcpy(current_admin.logfile, LOGFILE);
		(void) cachemgr_set_lf(&current_admin, current_admin.logfile);
		/*
		 * validate the range of debug level number
		 * and set the number to current_admin.debug_level
		 */
		if (cachemgr_set_dl(&current_admin, debug_level) < 0) {
				/*
				 * print error messages to the screen
				 * cachemgr_set_dl prints msgs to cachemgr.log
				 * only
				 */
				(void) fprintf(stderr,
				gettext("Incorrect Debug Level: %d\n"
				"It should be between %d and %d\n"),
				    debug_level, DBG_OFF, MAXDEBUG);
			exit(-1);
		}
	} else {
		if (strlen(current_admin.logfile) == 0)
			(void) strcpy(current_admin.logfile, "/dev/null");
		(void) cachemgr_set_lf(&current_admin, current_admin.logfile);
	}

	if (dofg == 0)
		detachfromtty(argv[0]);

	/*
	 * perform some initialization
	 */

	initialize_lookup_clearance();

	if (getldap_init() != 0)
		exit(-1);

	/*
	 * Establish our own server thread pool
	 */

	(void) door_server_create(server_create);
	if (thr_keycreate(&server_key, server_destroy) != 0) {
		logit("thr_keycreate() call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: thr_keycreate() call failed"));
		perror("thr_keycreate");
		exit(-1);
	}

	/*
	 * Create a door
	 */

	if ((did = door_create(switcher, LDAP_CACHE_DOOR_COOKIE,
	    DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
		logit("door_create() call failed\n");
		syslog(LOG_ERR, gettext(
		    "ldap_cachemgr: door_create() call failed"));
		perror("door_create");
		exit(-1);
	}

	/*
	 * bind to file system
	 */

	if (stat(LDAP_CACHE_DOOR, &buf) < 0) {
		int	newfd;

		if ((newfd = creat(LDAP_CACHE_DOOR, 0444)) < 0) {
			logit("Cannot create %s:%s\n",
			    LDAP_CACHE_DOOR,
			    strerror(errno));
			exit(1);
		}
		(void) close(newfd);
	}

	if (fattach(did, LDAP_CACHE_DOOR) < 0) {
		if ((errno != EBUSY) ||
		    (fdetach(LDAP_CACHE_DOOR) <  0) ||
		    (fattach(did, LDAP_CACHE_DOOR) < 0)) {
			logit("fattach() call failed\n");
			syslog(LOG_ERR, gettext(
			    "ldap_cachemgr: fattach() call failed"));
			perror("fattach");
			exit(2);
		}
	}

	/* catch SIGHUP revalid signals */
	sighupaction.sa_handler = getldap_revalidate;
	sighupaction.sa_flags = 0;
	(void) sigemptyset(&sighupaction.sa_mask);
	(void) sigemptyset(&myset);
	(void) sigaddset(&myset, SIGHUP);

	if (sigaction(SIGHUP, &sighupaction, NULL) < 0) {
		logit("sigaction() call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: sigaction() call failed"));
		perror("sigaction");
		exit(1);
	}

	if (thr_sigsetmask(SIG_BLOCK, &myset, NULL) < 0) {
		logit("thr_sigsetmask() call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: thr_sigsetmask() call failed"));
		perror("thr_sigsetmask");
		exit(1);
	}

	/*
	 *  kick off revalidate threads only if ttl != 0
	 */

	if (thr_create(NULL, 0, (void *(*)(void*))getldap_refresh,
	    NULL, 0, NULL) != 0) {
		logit("thr_create() call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: thr_create() call failed"));
		perror("thr_create");
		exit(1);
	}

	/*
	 *  kick off the thread which refreshes the server info
	 */

	if (thr_create(NULL, 0, (void *(*)(void*))getldap_serverInfo_refresh,
	    NULL, 0, NULL) != 0) {
		logit("thr_create() call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: thr_create() call failed"));
		perror("thr_create");
		exit(1);
	}

	/*
	 * kick off the thread which cleans up waiting threads for
	 * GETSTATUSCHANGE
	 */

	if (thr_create(NULL, 0, chg_cleanup_waiting_threads,
	    NULL, 0, NULL) != 0) {
		logit("thr_create() chg_cleanup_waiting_threads call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: thr_create() "
		    "chg_cleanup_waiting_threads call failed"));
		exit(1);
	}

#ifdef SLP
	if (use_slp) {
		/* kick off SLP discovery thread */
		if (thr_create(NULL, 0, (void *(*)(void *))discover,
		    (void *)&refresh, 0, NULL) != 0) {
			logit("thr_create() call failed\n");
			syslog(LOG_ERR, gettext("ldap_cachemgr: thr_create() "
			    "call failed"));
			perror("thr_create");
			exit(1);
		}
	}
#endif /* SLP */

	if (thr_sigsetmask(SIG_UNBLOCK, &myset, NULL) < 0) {
		logit("thr_sigsetmask() call failed\n");
		syslog(LOG_ERR,
		    gettext("ldap_cachemgr: the_sigsetmask() call failed"));
		perror("thr_sigsetmask");
		exit(1);
	}

	/*CONSTCOND*/
	while (1) {
		(void) pause();
	}
	/* NOTREACHED */
	/*LINTED E_FUNC_HAS_NO_RETURN_STMT*/
}


/*
 * Before calling the alloca() function we have to be sure that we won't get
 * beyond the stack. Since we don't know the precise layout of the stack,
 * the address of an automatic of the function gives us a rough idea, plus/minus
 * a bit. We also need a bit more of stackspace after the call to be able
 * to call further functions. Even something as simple as making a system call
 * from within this function can take ~100 Bytes of stackspace.
 */
#define	SAFETY_BUFFER 32 * 1024 /* 32KB */

static
size_t
get_data_size(LineBuf *config_info, int *err_code)
{
	size_t		configSize = sizeof (ldap_return_t);
	dataunion	*buf = NULL; /* For the 'sizeof' purpose */

	if (config_info->str != NULL &&
	    config_info->len >= sizeof (buf->data.ldap_ret.ldap_u.config)) {
		configSize = sizeof (buf->space) +
		    config_info->len -
		    sizeof (buf->data.ldap_ret.ldap_u.config);

		if (!stack_inbounds((char *)&buf -
		    (configSize + SAFETY_BUFFER))) {
			/*
			 * We do not have enough space on the stack
			 * to accomodate the whole DUAProfile
			 */
			logit("The DUAProfile is too big. There is not enough "
			    "space to process it. Ignoring it.\n");
			syslog(LOG_ERR, gettext("ldap_cachemgr: The DUAProfile "
			    "is too big. There is not enough space "
			    "to process it. Ignoring it."));

			*err_code = NS_CACHE_SERVERERROR;

			free(config_info->str);
			config_info->str = NULL;
			config_info->len = 0;
			configSize = sizeof (ldap_return_t);
		}
	}

	return (configSize);
}

/*ARGSUSED*/
static void
switcher(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
#define	GETSIZE 1000
#define	ALLOCATE 1001

	ldap_call_t	*ptr = (ldap_call_t *)argp;
	ucred_t		*uc = NULL;

	LineBuf		configInfo;
	dataunion	*buf = NULL;

	/*
	 * By default the size of  a buffer to be passed down to a client
	 * is equal to the size of the ldap_return_t structure. We need
	 * a bigger buffer in a few cases.
	 */
	size_t		configSize = sizeof (ldap_return_t);
	int		ldapErrno = 0, state, callnumber;
	struct {
		void	*begin;
		size_t	size;
		uint8_t	destroy;
	} dataSource;

	if (argp == DOOR_UNREF_DATA) {
		logit("Door Slam... invalid door param\n");
		syslog(LOG_ERR, gettext("ldap_cachemgr: Door Slam... "
		    "invalid door param"));
		(void) printf(gettext("Door Slam... invalid door param\n"));
		exit(0);
	}

	if (ptr == NULL) { /* empty door call */
		(void) door_return(NULL, 0, 0, 0); /* return the favor */
	}

	bzero(&dataSource, sizeof (dataSource));

	/*
	 * We presume that sizeof (ldap_return_t) bytes are always available
	 * on the stack
	 */
	callnumber = ptr->ldap_callnumber;

	switch (callnumber) {
		case NULLCALL:
			/*
			 * Just a 'ping'. Use the default size
			 * of the buffer and set the
			 * 'OK' error code.
			 */
			state = ALLOCATE;
			break;
		case GETLDAPCONFIG:
			/*
			 * Get the current LDAP configuration.
			 * Since this is dynamic data and its size can exceed
			 * the size of ldap_return_t, the next step will
			 * calculate how much space exactly is required.
			 */
			getldap_lookup(&configInfo, ptr);

			state = GETSIZE;
			break;
		case GETADMINCRED:
			/*
			 * Get the current Admin Credentials (DN and password).
			 * Since this is dynamic data and its size can exceed
			 * the size of ldap_return_t, the next step will
			 * calculate how much space exactly is required.
			 */
			getldap_admincred(&configInfo, ptr);

			state = GETSIZE;
			break;
		case GETLDAPSERVER:
			/*
			 * Get the root DSE for a next server in the list.
			 * Since this is dynamic data and its size can exceed
			 * the size of ldap_return_t, the next step will
			 * calculate how much space exactly is required.
			 */
			getldap_getserver(&configInfo, ptr);

			state = GETSIZE;
			break;
		case GETCACHESTAT:
			/*
			 * Get the cache stattistics.
			 * Since this is dynamic data and its size can exceed
			 * the size of ldap_return_t, the next step will
			 * calculate how much space exactly is required.
			 */
			getldap_get_cacheStat(&configInfo);

			state = GETSIZE;
			break;
		case GETADMIN:
			/*
			 * Get current configuration and statistics.
			 * The size of the statistics structure is less then
			 * sizeof (ldap_return_t). So specify the source
			 * where to take the info and proceed with the memory
			 * allocation.
			 */
			state = ALLOCATE;

			if (ldapErrno == 0) {
				dataSource.begin = &current_admin;
				dataSource.size = sizeof (current_admin);
				dataSource.destroy = 0;
			}
			break;
		case KILLSERVER:
			/*
			 * Process the request and proceed with the default
			 * buffer allocation.
			 */
			if (is_root(1, "KILLSERVER", &uc))
				exit(0);

			ldapErrno = -1;
			state = ALLOCATE;
			break;
		case SETADMIN:
			/*
			 * Process the request and proceed with the default
			 * buffer allocation.
			 */
			if (is_root(1, "SETADMIN", &uc))
				ldapErrno = setadmin(ptr);
			else
				ldapErrno = -1;

			state = ALLOCATE;
			break;
		case GETCACHE:
			/*
			 * Get the cache stattistics.
			 * Since this is dynamic data and its size can exceed
			 * the size of ldap_return_t, the next step will
			 * calculate how much space exactly is required.
			 */
			getldap_get_cacheData(&configInfo, ptr);

			state = GETSIZE;
			break;
		case SETCACHE:
			/*
			 * Process the request and proceed with the default
			 * buffer allocation.
			 */
			if (is_root(0, "SETCACHE", &uc) &&
			    is_called_from_nscd(ucred_getpid(uc))) {
				ldapErrno = getldap_set_cacheData(ptr);
				current_admin.ldap_stat.ldap_numbercalls++;
			} else
				ldapErrno = -1;

			if (uc != NULL)
				ucred_free(uc);
			state = ALLOCATE;
			break;
		case ADMINMODIFY:
			admin_modify(&configInfo, ptr);

			state = GETSIZE;
			break;
		case GETSTATUSCHANGE:
			/*
			 * Process the request and proceed with the default
			 * buffer allocation.
			 */
			(void) mutex_lock(&chg_threads_num_lock);
			chg_threads_num++;
			if (chg_threads_num > MAX_CHG_THREADS) {
				chg_threads_num--;
				(void) mutex_unlock(&chg_threads_num_lock);
				ldapErrno = CHG_EXCEED_MAX_THREADS;
				state = ALLOCATE;
				break;
			}
			(void) mutex_unlock(&chg_threads_num_lock);

			if (is_root(0, "GETSTATUSCHANGE", &uc) &&
			    is_called_from_nscd(ucred_getpid(uc))) {
				ldapErrno = chg_get_statusChange(
				    &configInfo, ptr, ucred_getpid(uc));
				state = GETSIZE;
			} else {
				ldapErrno = -1;
				state = ALLOCATE;
			}
			if (uc != NULL)
				ucred_free(uc);

			(void) mutex_lock(&chg_threads_num_lock);
			chg_threads_num--;
			(void) mutex_unlock(&chg_threads_num_lock);
			break;
		default:
			/*
			 * This means an unknown request type. Proceed with
			 * the default buffer allocation.
			 */
			logit("Unknown ldap service door call op %d\n",
			    ptr->ldap_callnumber);
			ldapErrno = -99;

			state = ALLOCATE;
			break;
	}

	switch (state) {
		case GETSIZE:
			/*
			 * This stage calculates how much data will be
			 * passed down to the client, checks if there is
			 * enough space on the stack to accommodate the data,
			 * increases the value of the configSize variable
			 * if necessary and specifies the data source.
			 * In case of any error occurred ldapErrno will be set
			 * appropriately.
			 */
			if (configInfo.str == NULL) {
				ldapErrno = -1;
			}

			configSize = get_data_size(&configInfo, &ldapErrno);

			if (ldapErrno == 0) {
				dataSource.begin = configInfo.str;
				dataSource.size = configInfo.len;
				dataSource.destroy = 1;
			}

			current_admin.ldap_stat.ldap_numbercalls++;
			/* FALLTHRU */
		case ALLOCATE:
			/*
			 * Allocate a buffer of the calculated (or default) size
			 * and proceed with populating it with data.
			 */
			buf = (dataunion *) alloca(configSize);

			/*
			 * Set a return code and, if a data source is specified,
			 * copy data from the source to the buffer.
			 */
			buf->data.ldap_ret.ldap_errno = ldapErrno;
			buf->data.ldap_ret.ldap_return_code = ldapErrno;
			buf->data.ldap_ret.ldap_bufferbytesused = configSize;

			if (dataSource.begin != NULL) {
				(void) memcpy(buf->data.ldap_ret.ldap_u.config,
				    dataSource.begin,
				    dataSource.size);
				if (dataSource.destroy) {
					free(dataSource.begin);
				}
			}

	}
	(void) door_return((char *)&buf->data,
	    buf->data.ldap_ret.ldap_bufferbytesused,
	    NULL,
	    0);
#undef	GETSIZE
#undef	ALLOCATE
}

static void
usage(char *s)
{
	(void) fprintf(stderr,
	    gettext("Usage: %s [-d debug_level] [-l logfilename]\n"), s);
	(void) fprintf(stderr, gettext("	[-K] "
	    "[-r revalidate_interval] "));
#ifndef SLP
	(void) fprintf(stderr, gettext("	[-g]\n"));
#else
	(void) fprintf(stderr, gettext("	[-g] [-s]\n"));
#endif /* SLP */
	exit(1);
}


static int	logfd = -1;

static int
cachemgr_set_lf(admin_t *ptr, char *logfile)
{
	int	newlogfd;

	/*
	 *  we don't really want to try and open the log file
	 *  /dev/null since that will fail w/ our security fixes
	 */

	if (logfile == NULL || *logfile == 0) {
		/*EMPTY*/;
	} else if (strcmp(logfile, "/dev/null") == 0) {
		(void) strcpy(current_admin.logfile, "/dev/null");
		(void) close(logfd);
		logfd = -1;
	} else {
		if ((newlogfd =
		    open(logfile, O_EXCL|O_WRONLY|O_CREAT, 0644)) < 0) {
			/*
			 * File already exists... now we need to get cute
			 * since opening a file in a world-writeable directory
			 * safely is hard = it could be a hard link or a
			 * symbolic link to a system file.
			 *
			 */
			struct stat	before;

			if (lstat(logfile, &before) < 0) {
				logit("Cannot open new logfile \"%s\": %sn",
				    logfile, strerror(errno));
				return (-1);
			}
			if (S_ISREG(before.st_mode) &&	/* no symbolic links */
			    (before.st_nlink == 1) &&	/* no hard links */
			    (before.st_uid == 0)) {	/* owned by root */
				if ((newlogfd =
				    open(logfile,
				    O_APPEND|O_WRONLY, 0644)) < 0) {
					logit("Cannot open new logfile "
					    "\"%s\": %s\n",
					    logfile, strerror(errno));
					return (-1);
				}
			} else {
				logit("Cannot use specified logfile "
				    "\"%s\": file is/has links or isn't "
				    "owned by root\n", logfile);
				return (-1);
			}
		}
		(void) strlcpy(ptr->logfile, logfile, sizeof (ptr->logfile));
		(void) close(logfd);
		logfd = newlogfd;
		logit("Starting ldap_cachemgr, logfile %s\n", logfile);
	}
	return (0);
}

/*PRINTFLIKE1*/
void
logit(char *format, ...)
{
	static mutex_t	loglock;
	struct timeval	tv;
	char		buffer[BUFSIZ];
	va_list		ap;

	va_start(ap, format);

	if (logfd >= 0) {
		int	safechars;

		(void) gettimeofday(&tv, NULL);
		(void) ctime_r(&tv.tv_sec, buffer, BUFSIZ);
		(void) snprintf(buffer+19, BUFSIZE, ".%.4ld	",
		    tv.tv_usec/100);
		safechars = sizeof (buffer) - 30;
		if (vsnprintf(buffer+25, safechars, format, ap) > safechars)
			(void) strcat(buffer, "...\n");
		(void) mutex_lock(&loglock);
		(void) write(logfd, buffer, strlen(buffer));
		(void) mutex_unlock(&loglock);
	}
	va_end(ap);
}


static int
client_getadmin(admin_t *ptr)
{
	dataunion		u;
	ldap_data_t	*dptr;
	int		ndata;
	int		adata;

	u.data.ldap_call.ldap_callnumber = GETADMIN;
	ndata = sizeof (u);
	adata = sizeof (u.data);
	dptr = &u.data;

	if (__ns_ldap_trydoorcall(&dptr, &ndata, &adata) != NS_CACHE_SUCCESS) {
		return (-1);
	}
	(void) memcpy(ptr, dptr->ldap_ret.ldap_u.buff, sizeof (*ptr));

	return (0);
}


static int
setadmin(ldap_call_t *ptr)
{
	admin_t	*new;

	new = (admin_t *)ptr->ldap_u.domainname;

	/*
	 *  global admin stuff
	 */

	if ((cachemgr_set_lf(&current_admin, new->logfile) < 0) ||
	    cachemgr_set_dl(&current_admin, new->debug_level) < 0) {
		return (-1);
	}

	if (cachemgr_set_ttl(&current_admin.ldap_stat,
	    "ldap",
	    new->ldap_stat.ldap_ttl) < 0) {
		return (-1);
	}

	return (0);
}


static void
client_killserver()
{
	dataunion		u;
	ldap_data_t		*dptr;
	int			ndata;
	int			adata;

	u.data.ldap_call.ldap_callnumber = KILLSERVER;
	ndata = sizeof (u);
	adata = sizeof (ldap_call_t);
	dptr = &u.data;

	__ns_ldap_trydoorcall(&dptr, &ndata, &adata);
}


static int
client_setadmin(admin_t *ptr)
{
	dataunion		u;
	ldap_data_t		*dptr;
	int			ndata;
	int			adata;

	u.data.ldap_call.ldap_callnumber = SETADMIN;
	(void) memcpy(u.data.ldap_call.ldap_u.domainname, ptr, sizeof (*ptr));
	ndata = sizeof (u);
	adata = sizeof (*ptr);
	dptr = &u.data;

	if (__ns_ldap_trydoorcall(&dptr, &ndata, &adata) != NS_CACHE_SUCCESS) {
		return (-1);
	}

	return (0);
}

static int
client_showstats(admin_t *ptr)
{
	dataunion	u;
	ldap_data_t	*dptr;
	int		ndata;
	int		adata;
	char		*rbuf, *sptr, *rest;

	/*
	 * print admin data
	 */
	(void) printf(gettext("\ncachemgr configuration:\n"));
	(void) printf(gettext("server debug level %10d\n"), ptr->debug_level);
	(void) printf(gettext("server log file\t\"%s\"\n"), ptr->logfile);
	(void) printf(gettext("number of calls to ldapcachemgr %10d\n"),
	    ptr->ldap_stat.ldap_numbercalls);

	/*
	 * get cache data statistics
	 */
	u.data.ldap_call.ldap_callnumber = GETCACHESTAT;
	ndata = sizeof (u);
	adata = sizeof (ldap_call_t);
	dptr = &u.data;

	if (__ns_ldap_trydoorcall(&dptr, &ndata, &adata) != NS_CACHE_SUCCESS) {
		(void) printf(
		    gettext("\nCache data statistics not available!\n"));
		return (0);
	}

	/*
	 * print cache data statistics line by line
	 */
	(void) printf(gettext("\ncachemgr cache data statistics:\n"));
	rbuf = dptr->ldap_ret.ldap_u.buff;
	sptr = strtok_r(rbuf, DOORLINESEP, &rest);
	for (;;) {
		(void) printf("%s\n", sptr);
		sptr = strtok_r(NULL, DOORLINESEP, &rest);
		if (sptr == NULL)
			break;
	}
	return (0);
}


/*
 * detach from tty
 */
static void
detachfromtty(char *pgm)
{
	int 	status;
	pid_t	pid, wret;

	(void) close(0);
	(void) close(1);
	/*
	 * Block the SIGUSR1 signal
	 * just in case that the child
	 * process may run faster than
	 * the parent process and
	 * send this signal before
	 * the signal handler is ready
	 * in the parent process.
	 * This error will cause the parent
	 * to exit with the User Signal 1
	 * exit code (144).
	 */
	(void) sighold(SIGUSR1);
	pid = fork1();
	switch (pid) {
		case (pid_t)-1:
			logit("detachfromtty(): fork1() call failed\n");
			(void) fprintf(stderr,
			    gettext("%s: fork1() call failed.\n"),
			    pgm);
			syslog(LOG_ERR,
			    gettext("ldap_cachemgr: fork1() call failed."));
			exit(1);
			break;
		case 0:
			/*
			 * child process does not
			 * need to worry about
			 * the SIGUSR1 signal
			 */
			(void) sigrelse(SIGUSR1);
			(void) close(2);
			break;
		default:
			/*
			 * Wait forever until the child process
			 * has exited, or has signalled that at
			 * least one server in the server list
			 * is up.
			 */
			if (signal(SIGUSR1, sig_ok_to_exit) == SIG_ERR) {
				logit("detachfromtty(): "
				    "can't set up signal handler to "
				    " catch SIGUSR1.\n");
				(void) fprintf(stderr,
				    gettext("%s: signal() call failed.\n"),
				    pgm);
				syslog(LOG_ERR, gettext("ldap_cachemgr: "
				    "can't set up signal handler to "
				    " catch SIGUSR1."));
				exit(1);
			}

			/*
			 * now unblock the SIGUSR1 signal
			 * to handle the pending or
			 * soon to arrive SIGUSR1 signal
			 */
			(void) sigrelse(SIGUSR1);
			wret = waitpid(pid, &status, 0);

			if (wret == -1) {
				logit("detachfromtty(): "
				    "waitpid() call failed\n");
				(void) fprintf(stderr,
				    gettext("%s: waitpid() call failed.\n"),
				    pgm);
				syslog(LOG_ERR,
				    gettext("ldap_cachemgr: waitpid() "
				    "call failed."));
				exit(1);
			}
			if (wret != pid) {
				logit("detachfromtty(): "
				    "waitpid() returned %ld when "
				    "child pid was %ld\n",
				    wret, pid);
				(void) fprintf(stderr,
				    gettext(
				    "%s: waitpid() returned %ld when "
				    "child pid was %ld.\n"),
				    pgm, wret, pid);
				syslog(LOG_ERR,
				    gettext("ldap_cachemgr: waitpid() "
				    "returned different "
				    "child pid."));
				exit(1);
			}

			/* evaluate return status */
			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0) {
					exit(0);
				}
				logit("detachfromtty(): "
				    "child failed (rc = %d).\n",
				    WEXITSTATUS(status));
				(void) fprintf(stderr,
				    gettext("%s: failed. Please see "
				    "syslog for details.\n"),
				    pgm);
				syslog(LOG_ERR,
				    gettext("ldap_cachemgr: failed "
				    "(rc = %d)."),
				    WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				logit("detachfromtty(): "
				    "child terminated by signal %d.\n",
				    WTERMSIG(status));
				(void) fprintf(stderr,
				gettext("%s: terminated by signal %d.\n"),
				    pgm, WTERMSIG(status));
				syslog(LOG_ERR,
				    gettext("ldap_cachemgr: terminated by "
				    "signal %d.\n"),
				    WTERMSIG(status));
			} else if (WCOREDUMP(status)) {
				logit("detachfromtty(): child core dumped.\n"),
				    (void) fprintf(stderr,
				    gettext("%s: core dumped.\n"),
				    pgm);
				syslog(LOG_ERR,
				    gettext("ldap_cachemgr: "
				    "core dumped.\n"));
			}

			exit(1);
	}
	(void) setsid();
	if (open("/dev/null", O_RDWR, 0) != -1) {
		(void) dup(0);
		(void) dup(0);
	}
}

/*
 * Check if the door client's euid is 0
 *
 * We could check for some privilege or re-design the interfaces that
 * lead to is_root() being called so that we rely on SMF and RBAC, but
 * we need this check only for dealing with undocumented-but-possibly-
 * used interfaces.  Anything beyond checking for euid == 0 here would
 * be overkill considering that those are undocumented interfaces.
 *
 * If free_uc is 0, the caller is responsible for freeing *ucp.
 *
 * return - 0 euid != 0
 *          1 euid == 0
 */
static int
is_root(int free_uc, char *dc_str, ucred_t **ucp)
{
	int	rc;

	if (door_ucred(ucp) != 0) {
		rc = errno;
		logit("door_ucred() call failed %s\n", strerror(rc));
		syslog(LOG_ERR, gettext("ldap_cachemgr: door_ucred() call %s "
		    "failed %s"), strerror(rc));
		return (0);
	}


	if (ucred_geteuid(*ucp) != 0) {

		if (current_admin.debug_level >= DBG_CANT_FIND)
			logit("%s call failed(cred): caller pid %ld, uid %u, "
			    "euid %u (if uid or euid is %u, it may be "
			    "unavailable)\n", dc_str, ucred_getpid(*ucp),
			    ucred_getruid(*ucp), ucred_geteuid(*ucp), -1);

		rc = 0;
	} else {

		if (current_admin.debug_level >= DBG_ALL)
			logit("received %s call from pid %ld, uid %u, euid %u "
			    "(if uid or euid is %u, it may be unavailable)\n",
			    dc_str, ucred_getpid(*ucp), ucred_getruid(*ucp),
			    ucred_geteuid(*ucp), -1);
		rc = 1;
	}

	if (free_uc)
		ucred_free(*ucp);

	return (rc);
}

/*
 * Check if pid is nscd
 *
 * Input: pid - process id of the door client that calls ldap_cachemgr
 *
 * Return: 0 - No
 *         1 - Yes
 */

int
is_called_from_nscd(pid_t pid)
{
	static mutex_t	_door_lock = DEFAULTMUTEX;
	static	int	doorfd = -1;
	int		match;
	door_info_t	my_door;

	/*
	 * the first time in we try and open and validate the door.
	 * the validations are that the door must have been
	 * created with the door cookie and
	 * that the file attached to the door is owned by root
	 * and readonly by user, group and other.  If any of these
	 * validations fail we refuse to use the door.
	 */

	(void) mutex_lock(&_door_lock);

try_again:

	if (doorfd == -1) {

		if ((doorfd = open(NAME_SERVICE_DOOR, O_RDONLY, 0))
		    == -1) {
			(void) mutex_unlock(&_door_lock);
			return (0);
		}

		if (door_info(doorfd, &my_door) == -1 ||
		    (my_door.di_attributes & DOOR_REVOKED) ||
		    my_door.di_data != (uintptr_t)NAME_SERVICE_DOOR_COOKIE) {
			/*
			 * we should close doorfd because we just opened it
			 */
			(void) close(doorfd);
			doorfd = -1;
			(void) mutex_unlock(&_door_lock);
			return (0);
		}
	} else {
		/*
		 * doorfd is cached. Double check just in case
		 * the door server is restarted or is down.
		 */
		if (door_info(doorfd, &my_door) == -1 ||
		    my_door.di_data != (uintptr_t)NAME_SERVICE_DOOR_COOKIE) {
			/*
			 * don't close it -
			 * someone else has clobbered fd
			 */
			doorfd = -1;
			goto try_again;
		}

		if (my_door.di_attributes & DOOR_REVOKED) {
			(void) close(doorfd);
			doorfd = -1;	/* try and restart connection */
			goto try_again;
		}
	}

	/*
	 * door descriptor exists and is valid
	 */
	if (pid == my_door.di_target)
		match = 1;
	else
		match = 0;

	(void) mutex_unlock(&_door_lock);

	return (match);

}

/*
 * new_attr(name, value)
 *
 * create a new LDAP attribute to be sent to the server
 */
static ns_ldap_attr_t *
new_attr(char *name, char *value)
{
	ns_ldap_attr_t *tmp;

	tmp = malloc(sizeof (*tmp));
	if (tmp != NULL) {
		tmp->attrname = name;
		tmp->attrvalue = (char **)calloc(2, sizeof (char *));
		if (tmp->attrvalue == NULL) {
			free(tmp);
			return (NULL);
		}
		tmp->attrvalue[0] = value;
		tmp->value_count = 1;
	}

	return (tmp);
}

/*
 * Convert the flatten ldap attributes in a ns_ldap_attr_t back
 * to an ns_ldap_attr_t array.
 *
 * strlist->ldap_offsets[] contains offsets to strings:
 * "dn", <dn value>, <attr 1>, <attrval 1>, ... <attr n>, <attrval n>
 * where n is (strlist->ldap_count/2 -1).
 * The output ns_ldap_attr_t array has a size of (strlist->ldap_count/2)
 * the first (strlist->ldap_count/2 -1) contains all the attribute data,
 * the last one is a NULL pointer. DN will be extracted out and pointed
 * to by *dn.
 */
static ns_ldap_attr_t **
str2attrs(ldap_strlist_t *strlist, char **dn)
{
	int		c;
	int		i;
	int		j;
	ns_ldap_attr_t	**ret;

	c = strlist->ldap_count;
	ret = calloc(c/2, sizeof (ns_ldap_attr_t *));
	if (ret == NULL)
		return (NULL);
	*dn = (char *)strlist + strlist->ldap_offsets[1];

	/*
	 * skip the first 'dn'/<dn value> pair, for all other attr type/value
	 * pairs, get pointers to the attr type (offset [i]) and attr value
	 * (offset [i+1]) and put in ns_ldap_attr_t at ret[j]
	 */
	for (i = 2, j = 0; i < c; i = i + 2, j++) {
		ret[j] = new_attr((char *)strlist + strlist->ldap_offsets[i],
		    (char *)strlist + strlist->ldap_offsets[i + 1]);
	}
	return (ret);
}

static int
get_admin_dn(ns_cred_t *credp, int *status, ns_ldap_error_t **errorp)
{
	void	**paramVal = NULL;
	int	rc;

	/* get bind DN for shadow update */
	rc = __ns_ldap_getParam(NS_LDAP_ADMIN_BINDDN_P,
	    &paramVal, errorp);
	if (rc != NS_LDAP_SUCCESS)
		return (rc);

	if (paramVal == NULL || *paramVal == NULL) {
		rc = NS_LDAP_CONFIG;
		*status = NS_CONFIG_NOTALLOW;
		if (paramVal != NULL)
			(void) __ns_ldap_freeParam(&paramVal);
		return (rc);
	}
	credp->cred.unix_cred.userID = strdup((char *)*paramVal);
	(void) __ns_ldap_freeParam(&paramVal);
	if (credp->cred.unix_cred.userID == NULL)
		return (NS_LDAP_MEMORY);

	return (NS_LDAP_SUCCESS);
}

/*
 * admin_modify() does a privileged modify within the ldap_cachemgr daemon
 * process using the admin DN/password configured with parameters
 * NS_LDAP_ADMIN_BINDDN and NS_LDAP_ADMIN_BINDPASSWD. It will only
 * be done if NS_LDAP_ENABLE_SHADOW_UPDATE is set to TRUE.
 *
 * The input ldap_call_t (*in) contains LDAP shadowAccount attributes to
 * be modified. The data is a flatten ns_ldap_attr_t arrary stored in
 * the strlist element of the input ldap_call_t.
 * The output will be in LineBuf (*config_info), an ldap_admin_mod_result_t
 * structure that contains error code, error status, and error message.
 */
static void
admin_modify(LineBuf *config_info, ldap_call_t *in)
{
	int		rc = NS_LDAP_SUCCESS;
	int		authstried = 0;
	int		shadow_enabled = 0;
	char		*dn = NULL;
	char		**certpath = NULL;
	char		**enable_shadow = NULL;
	ns_auth_t	**app;
	ns_auth_t	**authpp = NULL;
	ns_auth_t	*authp = NULL;
	ns_cred_t	*credp = NULL;
	char		buffer[MAXERROR];
	const int	rlen = offsetof(ldap_admin_mod_result_t, msg);
	int		mlen = 0;
	const int	msgmax = MAXERROR - rlen;
	int		status = 0;
	ucred_t		*uc = NULL;
	ldap_strlist_t	*strlist;
	ns_ldap_attr_t	**attrs = NULL;
	ns_ldap_error_t *error = NULL;
	ldap_admin_mod_result_t *result;

	(void) memset((char *)config_info, 0, sizeof (LineBuf));

	/* only root or an ALL privs user can do admin modify */
	if (is_root_or_all_privs("ADMINMODIFY", &uc) == 0) {
		mlen = snprintf(buffer, msgmax, "%s",
		    gettext("shadow update by a non-root and no ALL privilege "
		    "user not allowed"));
		rc = NS_LDAP_CONFIG;
		goto out;
	}

	/* check to see if shadow update is enabled */
	rc = __ns_ldap_getParam(NS_LDAP_ENABLE_SHADOW_UPDATE_P,
	    (void ***)&enable_shadow, &error);
	if (rc != NS_LDAP_SUCCESS)
		goto out;
	if (enable_shadow != NULL && *enable_shadow != NULL) {
		shadow_enabled = (*(int *)enable_shadow[0] ==
		    NS_LDAP_ENABLE_SHADOW_UPDATE_TRUE);
	}
	if (enable_shadow != NULL)
		(void) __ns_ldap_freeParam((void ***)&enable_shadow);
	if (shadow_enabled == 0) {
		rc = NS_LDAP_CONFIG;
		status = NS_CONFIG_NOTALLOW;
		mlen = snprintf(buffer, msgmax, "%s",
		    gettext("shadow update not enabled"));
		goto out;
	}

	/* convert attributes in string buffer into an ldap attribute array */
	strlist = &in->ldap_u.strlist;
	attrs = str2attrs(strlist, &dn);
	if (attrs == NULL || *attrs == NULL || dn == NULL || *dn == '\0') {
		rc = NS_LDAP_INVALID_PARAM;
		goto out;
	}

	if ((credp = (ns_cred_t *)calloc(1, sizeof (ns_cred_t))) == NULL) {
		rc = NS_LDAP_MEMORY;
		goto out;
	}

	/* get host certificate path, if one is configured */
	rc = __ns_ldap_getParam(NS_LDAP_HOST_CERTPATH_P,
	    (void ***)&certpath, &error);
	if (rc != NS_LDAP_SUCCESS)
		goto out;
	if (certpath != NULL && *certpath != NULL) {
		credp->hostcertpath = strdup(*certpath);
		if (credp->hostcertpath == NULL)
			rc = NS_LDAP_MEMORY;
	}
	if (certpath != NULL)
		(void) __ns_ldap_freeParam((void ***)&certpath);
	if (rc != NS_LDAP_SUCCESS)
		goto out;

	/* Load the service specific authentication method */
	rc = __ns_ldap_getServiceAuthMethods("passwd-cmd", &authpp,
	    &error);
	if (rc != NS_LDAP_SUCCESS) {
		if (credp->hostcertpath != NULL)
			free(credp->hostcertpath);
		goto out;
	}

	/*
	 * if authpp is null, there is no serviceAuthenticationMethod
	 * try default authenticationMethod
	 */
	if (authpp == NULL) {
		rc = __ns_ldap_getParam(NS_LDAP_AUTH_P, (void ***)&authpp,
		    &error);
		if (rc != NS_LDAP_SUCCESS)
			goto out;
	}

	/*
	 * if authpp is still null, then can not authenticate, syslog
	 * error message and return error
	 */
	if (authpp == NULL) {
		rc = NS_LDAP_CONFIG;
		mlen = snprintf(buffer, msgmax, "%s",
		    gettext("No legal LDAP authentication method configured"));
		goto out;
	}

	/*
	 * Walk the array and try all authentication methods in order except
	 * for "none".
	 */
	for (app = authpp; *app; app++) {
		authp = *app;
		if (authp->type == NS_LDAP_AUTH_NONE)
			continue;
		authstried++;
		credp->auth.type = authp->type;
		credp->auth.tlstype = authp->tlstype;
		credp->auth.saslmech = authp->saslmech;
		credp->auth.saslopt = authp->saslopt;

		/*
		 * For GSSAPI, host credential will be used. No admin
		 * DN is needed. For other authentication methods,
		 * we need to set admin.
		 */
		if (credp->auth.saslmech != NS_LDAP_SASL_GSSAPI) {
			if ((rc = get_admin_dn(credp, &status,
			    &error)) != NS_LDAP_SUCCESS) {
				if (error != NULL)
					goto out;
				if (status == NS_CONFIG_NOTALLOW) {
					mlen = snprintf(buffer, msgmax, "%s",
					    gettext("Admin bind DN not "
					    "configured"));
					goto out;
				}
			}
		}

		rc = __ns_ldap_repAttr(NS_ADMIN_SHADOW_UPDATE, dn,
		    (const ns_ldap_attr_t * const *)attrs,
		    credp, 0, &error);
		if (rc == NS_LDAP_SUCCESS)
			goto out;

		/*
		 * Other errors might need to be added to this list, for
		 * the current supported mechanisms this is sufficient.
		 */
		if (rc == NS_LDAP_INTERNAL &&
		    error->pwd_mgmt.status == NS_PASSWD_GOOD &&
		    (error->status == LDAP_INAPPROPRIATE_AUTH ||
		    error->status == LDAP_INVALID_CREDENTIALS))
			goto out;

		/*
		 * If there is error related to password policy,
		 * return it to caller.
		 */
		if (rc == NS_LDAP_INTERNAL &&
		    error->pwd_mgmt.status != NS_PASSWD_GOOD) {
			rc = NS_LDAP_CONFIG;
			status = NS_CONFIG_NOTALLOW;
			(void) __ns_ldap_freeError(&error);
			mlen = snprintf(buffer, msgmax, "%s",
			    gettext("update failed due to "
			    "password policy on server (%d)"),
			    error->pwd_mgmt.status);
			goto out;
		}

		/* we don't really care about the error, just clean it up */
		if (error)
			(void) __ns_ldap_freeError(&error);
	}
	if (authstried == 0) {
		rc = NS_LDAP_CONFIG;
		mlen = snprintf(buffer, msgmax, "%s",
		    gettext("No legal LDAP authentication method configured"));
		goto out;
	}

	rc = NS_LDAP_OP_FAILED;

out:
	if (credp != NULL)
		(void) __ns_ldap_freeCred(&credp);

	if (authpp != NULL)
		(void) __ns_ldap_freeParam((void ***)&authpp);

	if (error != NULL) {
		mlen = snprintf(buffer, msgmax, "%s", error->message);
		status = error->status;
		(void) __ns_ldap_freeError(&error);
	}

	if (attrs != NULL) {
		int i;
		for (i = 0; attrs[i]; i++) {
			free(attrs[i]->attrvalue);
			free(attrs[i]);
		}
	}

	config_info->len = rlen + mlen + 1;
	config_info->str = malloc(config_info->len);
	if (config_info->str == NULL) {
		config_info->len = 0;
		return;
	}
	result = (ldap_admin_mod_result_t *)config_info->str;
	result->ns_err = rc;
	result->status = status;
	if (mlen != 0) {
		result->msg_size = mlen + 1;
		(void) strcpy(config_info->str + rlen, buffer);
	}
}

/*
 * Check to see if the door client's euid is 0 or if it has ALL zone privilege.
 * return - 0 No or error
 *          1 Yes
 */
int
is_root_or_all_privs(char *dc_str, ucred_t **ucp)
{
	const priv_set_t *ps;	/* door client */
	priv_set_t *zs;		/* zone */
	int rc = 0;

	*ucp = NULL;

	/* no more to do if door client's euid is 0 */
	if (is_root(0, dc_str, ucp) == 1) {
		ucred_free(*ucp);
		return (1);
	}

	/* error if couldn't get the ucred_t */
	if (*ucp == NULL)
		return (0);

	if ((ps = ucred_getprivset(*ucp, PRIV_EFFECTIVE)) != NULL) {
		zs = priv_str_to_set("zone", ",", NULL);
		if (priv_isequalset(ps, zs))
			rc = 1; /* has all zone privs */
		else {
			if (current_admin.debug_level >= DBG_CANT_FIND)
				logit("%s call failed (no all zone privs): "
				    "caller pid %ld, uid %u, euid %u "
				    "(if uid or euid is %u, it may "
				    "be unavailable)\n", dc_str,
				    ucred_getpid(*ucp), ucred_getruid(*ucp),
				    ucred_geteuid(*ucp), -1);
		}
		priv_freeset(zs);
	}

	ucred_free(*ucp);
	return (rc);
}
