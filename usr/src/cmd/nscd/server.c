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

/*
 * Simple doors name server cache daemon
 */

#include <stdio.h>
#include <signal.h>
#include <sys/door.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/zone.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <thread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <memory.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <door.h>
#include "getxby_door.h"
#include "server_door.h"
#include "nscd.h"
/* Includes for filenames of databases */
#include <shadow.h>
#include <userdefs.h>
#include <netdb.h>
#include <nss_dbdefs.h>
#include <exec_attr.h>
#include <prof_attr.h>
#include <user_attr.h>
#include <ucred.h>
#include <priv.h>
#include <libscf.h>

extern int 	optind;
extern int 	opterr;
extern int 	optopt;
extern char 	*optarg;

static void switcher(void *, char *, size_t, door_desc_t *, uint_t);
static void rts_mon(void);
static void usage(char *);
static int nsc_calllen(nsc_call_t *);
static int client_getadmin(admin_t *);
static void getadmin(nsc_return_t *, int, nsc_call_t *);
static int setadmin(nsc_return_t *, int, nsc_call_t *);
static void client_killserver(void);
static int client_setadmin(admin_t *);
static void client_showstats(admin_t *);
static void detachfromtty(void);


admin_t	current_admin;
static int will_become_server;

void
nsc_reaper(char *tbl_name, hash_t *tbl, nsc_stat_t *admin_ptr,
    mutex_t *hash_lock)
{
	uint_t count;
	uint_t interval;

	while (1) {

		if (current_admin.debug_level >= DBG_ALL) {
			logit("reaper_%s: %d entries in cache\n",
			tbl_name, admin_ptr->nsc_entries);
		}
		if (admin_ptr->nsc_entries > 0) {
			count = reap_hash(tbl, admin_ptr, hash_lock,
			admin_ptr->nsc_pos_ttl);
			if (current_admin.debug_level >= DBG_ALL) {
				logit("reaper_%s: reaped %d entries\n",
				tbl_name, count);
			}
		} else {
			/*
			 * We set a minimum wait of 60 before checking again;
			 * we don't want to sleep for no time at all.
			 * We don't clamp it for the reaping itself, that is
			 * done in reap_hash, and with a different minimum.
			 */
			interval = admin_ptr->nsc_pos_ttl;
			if (interval < 60) interval = 60;
			if (current_admin.debug_level >= DBG_ALL) {
				logit(
				    "reaper_%s: Nothing to reap, sleep %d\n",
				    tbl_name, interval);
			}
			sleep(interval);
		}
	}
}

nsc_stat_t *
getcacheptr(char *s)
{
	static const char *caches[7] = {"passwd", "group", "hosts", "ipnodes",
	    "exec_attr", "prof_attr", "user_attr" };

	if (strncmp(caches[0], s, strlen(caches[0])) == 0)
		return (&current_admin.passwd);

	if (strncmp(caches[1], s, strlen(caches[1])) == 0)
		return (&current_admin.group);

	if (strncmp(caches[2], s, strlen(caches[2])) == 0)
		return (&current_admin.host);

	if (strncmp(caches[3], s, strlen(caches[3])) == 0)
		return (&current_admin.node);

	if (strncmp(caches[4], s, strlen(caches[4])) == 0)
		return (&current_admin.exec);

	if (strncmp(caches[5], s, strlen(caches[5])) == 0)
		return (&current_admin.prof);

	if (strncmp(caches[6], s, strlen(caches[6])) == 0)
		return (&current_admin.user);

	return (NULL);
}

static char *
getcacheopt(char *s)
{
	while (*s && *s != ',')
		s++;
	return ((*s == ',') ? (s + 1) : NULL);
}

/*
 *  routine to check if server is already running
 */

static int
nsc_ping(void)
{
	nsc_data_t data;
	nsc_data_t *dptr;
	int ndata;
	int adata;

	data.nsc_call.nsc_callnumber = NULLCALL;
	ndata = sizeof (data);
	adata = sizeof (data);
	dptr = &data;
	return (_nsc_trydoorcall(&dptr, &ndata, &adata));
}

static void
dozip(void)
{
	/* not much here */
}

static void
keep_open_dns_socket(void)
{
	_res.options |= RES_STAYOPEN; /* just keep this udp socket open */
}

/*
 * declaring this causes the files backend to use hashing
 * this is of course an utter hack, but provides a nice
 * quiet back door to enable this feature for only the nscd.
 */
void
__nss_use_files_hash(void)
{

}
/*
 *
 *  The allocation of resources for cache lookups is an interesting
 *  problem, and one that has caused several bugs in the beta release
 *  of 2.5.  In particular, the introduction of a thottle to prevent
 *  the creation of excessive numbers of LWPs in the case of a failed
 *  name service has led to a denial of service problem when the
 *  name service request rate exceeds the name service's ability
 *  to respond.  As a result, I'm implementing the following
 *  algorithm:
 *
 *  1) We cap the number of total threads.
 *  2) We save CACHE_THREADS of those for cache lookups only.
 *  3) We use a common pool of 2/3 of the remain threads that are used first
 *  4) We save the remainder and allocate 1/3 of it for table specific lookups
 *
 *  The intent is to prevent the failure of a single name service from
 *  causing denial of service, and to always have threads available for
 *  cached lookups.  If a request comes in and the answer isn't in the
 *  cache and we cannot get a thread, we simply return NOSERVER, forcing
 *  the client to lookup the
 *  data itself.  This will prevent the types of starvation seen
 *  at UNC due to a single threaded DNS backend, and allows the cache
 *  to eventually become filled.
 *
 */

/* 7 tables: passwd, group, hosts, ipnodes, exec_attr, prof_attr, user_attr */
#define	NSCD_TABLES		7
#define	TABLE_THREADS		10
#define	COMMON_THREADS		20
#define	CACHE_MISS_THREADS	(COMMON_THREADS + NSCD_TABLES * TABLE_THREADS)
#define	CACHE_HIT_THREADS	20
#define	MAX_SERVER_THREADS	(CACHE_HIT_THREADS + CACHE_MISS_THREADS)

static sema_t common_sema;
static sema_t passwd_sema;
static sema_t hosts_sema;
static sema_t nodes_sema;
static sema_t group_sema;
static sema_t exec_sema;
static sema_t prof_sema;
static sema_t user_sema;
static thread_key_t lookup_state_key;

static void
initialize_lookup_clearance(void)
{
	thr_keycreate(&lookup_state_key, NULL);
	(void) sema_init(&common_sema, COMMON_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&passwd_sema, TABLE_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&hosts_sema, TABLE_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&nodes_sema, TABLE_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&group_sema, TABLE_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&exec_sema, TABLE_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&prof_sema, TABLE_THREADS, USYNC_THREAD, 0);
	(void) sema_init(&user_sema, TABLE_THREADS, USYNC_THREAD, 0);
}

int
get_clearance(int callnumber)
{
	sema_t *table_sema = NULL;
	char *tab;

	if (sema_trywait(&common_sema) == 0) {
		thr_setspecific(lookup_state_key, NULL);
		return (0);
	}

	switch (MASKUPDATEBIT(callnumber)) {

	case GETPWUID:
	case GETPWNAM:
		tab = "passwd";
		table_sema = &passwd_sema;
		break;

	case GETGRNAM:
	case GETGRGID:
		tab = "group";
		table_sema = &group_sema;
		break;

	case GETHOSTBYNAME:
	case GETHOSTBYADDR:
		tab = "hosts";
		table_sema = &hosts_sema;
		break;

	case GETIPNODEBYNAME:
	case GETIPNODEBYADDR:
		tab = "ipnodes";
		table_sema = &nodes_sema;
		break;
	case GETEXECID:
		tab = "exec_attr";
		table_sema = &exec_sema;
		break;

	case GETPROFNAM:
		tab = "prof_attr";
		table_sema = &prof_sema;
		break;

	case GETUSERNAM:
		tab = "user_attr";
		table_sema = &user_sema;
		break;

	}

	if (sema_trywait(table_sema) == 0) {
		thr_setspecific(lookup_state_key, (void*)1);
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
	int which;

	sema_t *table_sema = NULL;

	thr_getspecific(lookup_state_key, (void**)&which);

	if (which == 0) /* from common pool */ {
		(void) sema_post(&common_sema);
		return (0);
	}

	switch (MASKUPDATEBIT(callnumber)) {

	case GETPWUID:
	case GETPWNAM:
		table_sema = &passwd_sema;
		break;

	case GETGRNAM:
	case GETGRGID:
		table_sema = &group_sema;
		break;

	case GETHOSTBYNAME:
	case GETHOSTBYADDR:
		table_sema = &hosts_sema;
		break;

	case GETIPNODEBYNAME:
	case GETIPNODEBYADDR:
		table_sema = &nodes_sema;
		break;

	case GETEXECID:
		table_sema = &exec_sema;
		break;

	case GETPROFNAM:
		table_sema = &prof_sema;
		break;

	case GETUSERNAM:
		table_sema = &user_sema;
		break;
	}

	(void) sema_post(table_sema);
	return (0);
}


static mutex_t		create_lock;
static int		nscd_max_servers = MAX_SERVER_THREADS;
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
	static void *value = 0;

	/* disable cancellation to avoid hangs if server threads disappear */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	thr_setspecific(server_key, value);
	door_return(NULL, 0, NULL, 0);

	/* make lint happy */
	return (NULL);
}

/*
 * Server threads are created here.
 */
/*ARGSUSED*/
static void
server_create(door_info_t *dip)
{
	(void) mutex_lock(&create_lock);
	if (++num_servers > nscd_max_servers) {
		num_servers--;
		(void) mutex_unlock(&create_lock);
		return;
	}
	(void) mutex_unlock(&create_lock);
	thr_create(NULL, 0, server_tsd_bind, NULL, THR_BOUND|THR_DETACHED,
	    NULL);
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

static char **saved_argv;
static char saved_execname[MAXPATHLEN];

static void
save_execname()
{
	const char *name = getexecname();

	saved_execname[0] = 0;

	if (name[0] != '/') { /* started w/ relative path */
		(void) getcwd(saved_execname, MAXPATHLEN);
		strlcat(saved_execname, "/", MAXPATHLEN);
	}
	strlcat(saved_execname, name, MAXPATHLEN);
}

void
main(int argc, char ** argv)
{
	int did;
	int opt;
	int errflg = 0;
	int showstats = 0;
	int doset = 0;
	int loaded_config_file = 0;
	struct stat buf;
	sigset_t myset;
	struct sigaction action;

	/*
	 *  Special case non-root user  here - he can just print stats
	 */

	if (geteuid()) {
		if (argc != 2 || strcmp(argv[1], "-g")) {
			(void) fprintf(stderr,
			    "Must be root to use any option other than "\
			    "-g.\n\n");
			usage(argv[0]);
		}

		if ((nsc_ping() != SUCCESS) ||
		    (client_getadmin(&current_admin) != 0)) {
			(void) fprintf(stderr,
			    "%s doesn't appear to be running.\n", argv[0]);
			exit(1);
		}
		client_showstats(&current_admin);
		exit(0);
	}



	/*
	 *  Determine if there is already a daemon running
	 */

	will_become_server = (nsc_ping() != SUCCESS);

	/*
	 *	process usual options
	 */

	/*
	 *  load normal config file
	 */

	if (will_become_server) {
		static const nsc_stat_t defaults = {
			0,	/* stats */
			0,	/* stats */
			0,	/* stats */
			0,	/* stats */
			0,	/* stats */
			0,	/* stats */
			0,	/* stats */
			211,	/* suggested size */
			1,	/* enabled */
			0,	/* invalidate cmd */
			600,	/* positive ttl */
			10, 	/* netative ttl */
			20,	/* keep hot */
			0,	/* old data not ok */
			1 };	/* check files */

		current_admin.passwd = defaults;
		current_admin.group  = defaults;
		current_admin.host   = defaults;
		current_admin.node   = defaults;
		current_admin.exec   = defaults;
		current_admin.prof   = defaults;
		current_admin.user   = defaults;

		current_admin.logfile[0] = '\0';

		if (access("/etc/nscd.conf", R_OK) == 0) {
			if (nscd_parse(argv[0], "/etc/nscd.conf") < 0) {
				exit(1);
			}
			loaded_config_file++;
		}
	}

	else {
		if (client_getadmin(&current_admin)) {
			(void) fprintf(stderr,
			    "Cannot contact nscd properly(?)\n");
			exit(1);
		}

		current_admin.logfile[0] = '\0';
	}

	while ((opt = getopt(argc, argv,
	    "S:Kf:c:ge:p:n:i:l:d:s:h:o:")) != EOF) {
		nsc_stat_t *cache;
		char *cacheopt;

		switch (opt) {

		case 'S':		/* undocumented feature */
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}
			if (strcmp(cacheopt, "yes") == 0)
			    cache->nsc_secure_mode = 1;
			else if (strcmp(cacheopt, "no") == 0)
			    cache->nsc_secure_mode = 0;
			else
			    errflg++;
			break;

		case 'K':		/* undocumented feature */
			client_killserver();
			exit(0);
			break;

		case 'f':
			doset++;
			loaded_config_file++;
			if (nscd_parse(argv[0], optarg) < 0) {
				exit(1);
			}
			break;

		case 'g':
			showstats++;
			break;

		case 'p':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}
			cache->nsc_pos_ttl = atoi(cacheopt);
			break;

		case 'n':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}
			cache->nsc_neg_ttl = atoi(cacheopt);
			break;

		case 'c':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}

			if (strcmp(cacheopt, "yes") == 0)
			    cache->nsc_check_files = 1;
			else if (strcmp(cacheopt, "no") == 0)
			    cache->nsc_check_files = 0;
			else
			    errflg++;
			break;


		case 'i':
			doset++;
			cache = getcacheptr(optarg);
			if (!cache) {
				errflg++;
				break;
			}
			cache->nsc_invalidate = 1;
			break;

		case 'l':
			doset++;
			(void) strlcpy(current_admin.logfile, optarg, 128);
			break;

		case 'd':

			doset++;
			current_admin.debug_level = atoi(optarg);
			break;

		case 's':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}

			cache->nsc_suggestedsize = atoi(cacheopt);

			break;

		case 'h':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}
			cache->nsc_keephot = atoi(cacheopt);
			break;

		case 'o':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}
			if (strcmp(cacheopt, "yes") == 0)
			    cache->nsc_old_data_ok = 1;
			else if (strcmp(cacheopt, "no") == 0)
			    cache->nsc_old_data_ok = 0;
			else
			    errflg++;
			break;

		case 'e':
			doset++;
			cache = getcacheptr(optarg);
			cacheopt = getcacheopt(optarg);
			if (!cache || !cacheopt) {
				errflg++;
				break;
			}
			if (strcmp(cacheopt, "yes") == 0)
			    cache->nsc_enabled = 1;
			else if (strcmp(cacheopt, "no") == 0)
			    cache->nsc_enabled = 0;
			else
			    errflg++;
			break;

		default:
			errflg++;
			break;
		}

	}

	if (errflg)
	    usage(argv[0]);

	if (!will_become_server) {

		if (showstats) {
			client_showstats(&current_admin);
		}

		if (doset) {
			if (client_setadmin(&current_admin) < 0) {
				(void) fprintf(stderr,
					"Error during admin call\n");
				exit(1);
			}
		}
		if (!showstats && !doset) {
			(void) fprintf(stderr,
				"%s already running.... no admin specified\n",
				argv[0]);
		}
		exit(0);
	}

	/*
	 *   daemon from here ou
	 */

	if (!loaded_config_file) {
		(void) fprintf(stderr,
			"No configuration file specifed and /etc/nscd.conf" \
			"not present\n");
		exit(1);
	}

	saved_argv = argv;
	save_execname();

	if (current_admin.debug_level) {
		/* we're debugging... */
		if (strlen(current_admin.logfile) == 0)
		/* no specified log file */
			(void) strcpy(current_admin.logfile, "stderr");
		else
			(void) nscd_set_lf(&current_admin,
			    current_admin.logfile);
	} else {
		if (strlen(current_admin.logfile) == 0)
			(void) strcpy(current_admin.logfile, "/dev/null");
		(void) nscd_set_lf(&current_admin, current_admin.logfile);
		detachfromtty();
	}

	/* perform some initialization */
	initialize_lookup_clearance();
	keep_open_dns_socket();
	getpw_init();
	getgr_init();
	gethost_init();
	getnode_init();
	getexec_init();
	getprof_init();
	getuser_init();

	/* Establish our own server thread pool */

	door_server_create(server_create);
	if (thr_keycreate(&server_key, server_destroy) != 0) {
		perror("thr_keycreate");
		exit(-1);
	}

	/* Create a door */

	if ((did = door_create(switcher, NAME_SERVICE_DOOR_COOKIE,
	    DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) < 0) {
		perror("door_create");
		exit(-1);
	}

	/* bind to file system */

	if (stat(NAME_SERVICE_DOOR, &buf) < 0) {
		int newfd;
		if ((newfd = creat(NAME_SERVICE_DOOR, 0444)) < 0) {
			logit("Cannot create %s:%s\n",
				NAME_SERVICE_DOOR,
				strerror(errno));
			exit(1);
		}
		(void) close(newfd);
	}

	if (fattach(did, NAME_SERVICE_DOOR) < 0) {
		if ((errno != EBUSY) ||
		    (fdetach(NAME_SERVICE_DOOR) <  0) ||
		    (fattach(did, NAME_SERVICE_DOOR) < 0)) {
			perror("door_attach");
			exit(2);
		}
	}

	action.sa_handler = dozip;
	action.sa_flags = 0;
	(void) sigemptyset(&action.sa_mask);
	(void) sigemptyset(&myset);
	(void) sigaddset(&myset, SIGHUP);

	if (sigaction(SIGHUP, &action, NULL) < 0) {
		perror("sigaction");
		exit(1);
	}

	if (thr_sigsetmask(SIG_BLOCK, &myset, NULL) < 0) {
		perror("thr_sigsetmask");
		exit(1);
	}


	/*
	 *  kick off revalidate threads
	 */

	if (thr_create(NULL, NULL,
		(void *(*)(void *))getpw_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
		(void *(*)(void *))gethost_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
		(void *(*)(void*))getnode_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
		(void *(*)(void*))getgr_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void*))getexec_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void*))getprof_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void*))getuser_revalidate, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	/*
	 *  kick off reaper threads
	 */

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getpw_uid_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getpw_nam_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getgr_uid_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getgr_nam_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}


	if (thr_create(NULL, NULL,
	    (void *(*)(void *))gethost_nam_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))gethost_addr_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getnode_nam_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getnode_addr_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getexec_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getprof_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_create(NULL, NULL,
	    (void *(*)(void *))getuser_reaper, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	/*
	 * kick off routing socket monitor thread
	 */

	if (thr_create(NULL, NULL,
		(void *(*)(void *))rts_mon, 0, 0, NULL) != 0) {
		perror("thr_create");
		exit(1);
	}

	if (thr_sigsetmask(SIG_UNBLOCK, &myset, NULL) < 0) {
		perror("thr_sigsetmask");
		exit(1);
	}

	for (;;) {
		(void) pause();
		logit("Reloading /etc/nscd.conf\n");
		nscd_parse(argv[0], "/etc/nscd.conf");
	}
}


/*ARGSUSED*/
static void
switcher(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	union {
		nsc_data_t	data;
		char		space[8192];
	} u;

	time_t now;

	static time_t last_nsswitch_check;
	static time_t last_nsswitch_modified;
	static time_t last_resolv_modified;

	static mutex_t nsswitch_lock;

	nsc_call_t *ptr = (nsc_call_t *)argp;

	if (argp == DOOR_UNREF_DATA) {
		(void) printf("Door Slam... exiting\n");
		exit(0);
	}

	if (ptr == NULL) { /* empty door call */
		(void) door_return(NULL, 0, 0, 0); /* return the favor */
	}

	now = time(NULL);

	/*
	 *  just in case check
	 */

	(void) mutex_lock(&nsswitch_lock);

	if (now - last_nsswitch_check > 10) {
		struct stat nss_buf;
		struct stat res_buf;

		last_nsswitch_check = now;

		(void) mutex_unlock(&nsswitch_lock); /* let others continue */

		/*
		 *  This code keeps us from statting resolv.conf
		 *  if it doesn't exist, yet prevents us from ignoring
		 *  it if it happens to disappear later on for a bit.
		 */

		if (last_resolv_modified >= 0) {
			if (stat("/etc/resolv.conf", &res_buf) < 0) {
				if (last_resolv_modified == 0)
				    last_resolv_modified = -1;
				else
				    res_buf.st_mtime = last_resolv_modified;
			} else if (last_resolv_modified == 0) {
			    last_resolv_modified = res_buf.st_mtime;
			}
		}

		if (stat("/etc/nsswitch.conf", &nss_buf) < 0) {

			/*EMPTY*/;

		} else if (last_nsswitch_modified == 0) {

			last_nsswitch_modified = nss_buf.st_mtime;

		} else if ((last_nsswitch_modified < nss_buf.st_mtime) ||
		    ((last_resolv_modified > 0) &&
		    (last_resolv_modified < res_buf.st_mtime))) {
			static mutex_t exit_lock;
			char *fmri;
			/*
			 * time for restart
			 */
			logit("nscd restart due to /etc/nsswitch.conf or "\
				"resolv.conf change\n");
			/*
			 * try to restart under smf
			 */
			if ((fmri = getenv("SMF_FMRI")) == NULL) {
				/* not running under smf - reexec */
				execv(saved_execname, saved_argv);
				exit(1); /* just in case */
			}

			mutex_lock(&exit_lock); /* prevent multiple restarts */
			if (smf_restart_instance(fmri) == 0)
				sleep(10); /* wait a bit */
			exit(1); /* give up waiting for resurrection */
		}

	} else
	    (void) mutex_unlock(&nsswitch_lock);

	switch (ptr->nsc_callnumber) {

	case NULLCALL:
		u.data.nsc_ret.nsc_return_code = SUCCESS;
		u.data.nsc_ret.nsc_bufferbytesused = sizeof (nsc_return_t);
		break;


	case GETPWNAM:
		*(argp + arg_size - 1) = 0; /* FALLTHROUGH */
	case GETPWUID:
		getpw_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETGRNAM:
		*(argp + arg_size - 1) = 0; /* FALLTHROUGH */
	case GETGRGID:
		getgr_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETHOSTBYNAME:
		*(argp + arg_size - 1) = 0; /* FALLTHROUGH */
	case GETHOSTBYADDR:
		gethost_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETIPNODEBYNAME:
		*(argp + arg_size - 1) = 0; /* FALLTHROUGH */
	case GETIPNODEBYADDR:
		getnode_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETEXECID:
		*(argp + arg_size - 1) = 0;
		getexec_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETPROFNAM:
		*(argp + arg_size - 1) = 0;
		getprof_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETUSERNAM:
		*(argp + arg_size - 1) = 0;
		getuser_lookup(&u.data.nsc_ret, sizeof (u), ptr, now);
		break;

	case GETADMIN:
		getadmin(&u.data.nsc_ret, sizeof (u), ptr);
		break;

	case SETADMIN:
	case KILLSERVER: {

		ucred_t *uc = NULL;
		const priv_set_t *eset;
		zoneid_t zoneid;

		if (door_ucred(&uc) != 0) {
			perror("door_ucred");
			u.data.nsc_ret.nsc_return_code = NOTFOUND;
			break;
		}

		eset = ucred_getprivset(uc, PRIV_EFFECTIVE);
		zoneid = ucred_getzoneid(uc);

		if ((zoneid != GLOBAL_ZONEID && zoneid != getzoneid()) ||
		    eset != NULL ? !priv_ismember(eset, PRIV_SYS_ADMIN) :
		    ucred_geteuid(uc) != 0) {
			logit("SETADMIN call failed(cred): caller pid %d, "
			    "uid %d, euid %d, zoneid %d\n", ucred_getpid(uc),
			    ucred_getruid(uc), ucred_geteuid(uc), zoneid);
			u.data.nsc_ret.nsc_return_code = NOTFOUND;
			ucred_free(uc);
			break;
		}

		if (ptr->nsc_callnumber == KILLSERVER) {
			logit("Nscd received KILLSERVER cmd from pid %d, "
			    "uid %d, euid %d, zoneid %d\n", ucred_getpid(uc),
			    ucred_getruid(uc), ucred_geteuid(uc), zoneid);
			exit(0);
		} else {
			if (setadmin(&u.data.nsc_ret, sizeof (u), ptr) != 0)
				logit("SETADMIN call failed\n");
		}
		ucred_free(uc);
		break;
	}

	default:
		logit("Unknown name service door call op %d\n",
		    ptr->nsc_callnumber);
		u.data.nsc_ret.nsc_return_code = -1;
		u.data.nsc_ret.nsc_bufferbytesused = sizeof (nsc_return_t);
		break;

	}
	door_return((char *)&u.data, u.data.nsc_ret.nsc_bufferbytesused,
	    NULL, 0);
}

/*
 * Monitor the routing socket.  Address lists stored in the ipnodes
 * cache are sorted based on destination address selection rules,
 * so when things change that could affect that sorting (interfaces
 * go up or down, flags change, etc.), we clear that cache so the
 * list will be re-ordered the next time the hostname is resolved.
 */
static void
rts_mon(void)
{
	int	rt_sock, rdlen;
	union {
		struct {
			struct rt_msghdr rtm;
			struct sockaddr_storage addrs[RTA_NUMBITS];
		} r;
		struct if_msghdr ifm;
		struct ifa_msghdr ifam;
	} mbuf;
	struct ifa_msghdr *ifam = &mbuf.ifam;

	rt_sock = socket(PF_ROUTE, SOCK_RAW, 0);
	if (rt_sock < 0) {
		logit("Failed to open routing socket: %s\n", strerror(errno));
		thr_exit(0);
	}

	for (;;) {
		rdlen = read(rt_sock, &mbuf, sizeof (mbuf));
		if (rdlen <= 0) {
			if (rdlen == 0 || (errno != EINTR && errno != EAGAIN)) {
				logit("routing socket read: %s\n",
				    strerror(errno));
				thr_exit(0);
			}
			continue;
		}
		if (ifam->ifam_version != RTM_VERSION) {
			logit("rx unknown version (%d) on routing socket.\n",
			    ifam->ifam_version);
			continue;
		}
		switch (ifam->ifam_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
			getnode_name_invalidate();
			break;
		case RTM_ADD:
		case RTM_DELETE:
		case RTM_CHANGE:
		case RTM_GET:
		case RTM_LOSING:
		case RTM_REDIRECT:
		case RTM_MISS:
		case RTM_LOCK:
		case RTM_OLDADD:
		case RTM_OLDDEL:
		case RTM_RESOLVE:
		case RTM_IFINFO:
			break;
		default:
			logit("rx unknown msg type (%d) on routing socket.\n",
			    ifam->ifam_type);
			break;
		}
	}
}

static void
usage(char *s)
{
	(void) fprintf(stderr,
		"Usage: %s [-d debug_level] [-l logfilename]\n", s);
	(void) fprintf(stderr,
		"	[-p cachename,positive_time_to_live]\n");
	(void) fprintf(stderr,
		"	[-n cachename,negative_time_to_live]\n");
	(void) fprintf(stderr,
		"	[-i cachename] [-s cachename,suggestedsize]\n");

	(void) fprintf(stderr,
		"	[-h cachename,keep_hot_count] "\
		"[-o cachename,\"yes\"|\"no\"]\n");

	(void) fprintf(stderr,
		"	[-e cachename,\"yes\"|\"no\"] [-g] " \
		"[-c cachename,\"yes\"|\"no\"]\n");

	(void) fprintf(stderr,
		"	[-f configfilename] \n");

	(void) fprintf(stderr,
		"\n	Supported caches: passwd, group, hosts, ipnodes\n");

	(void) fprintf(stderr,
		"         exec_attr, prof_attr, and user_attr.\n");

	exit(1);

}


static int logfd = 2;

int
nscd_set_lf(admin_t *ptr, char *s)
{
	int newlogfd;

	/*
	 *  we don't really want to try and open the log file
	 *  /dev/null since that will fail w/ our security fixes
	 */

	if (*s == 0) {
		/* ignore empty log file specs */
		/*EMPTY*/;
	} else if (s == NULL || strcmp(s, "/dev/null") == 0) {
		(void) strcpy(current_admin.logfile, "/dev/null");
		(void) close(logfd);
		logfd = -1;
	} else {
		/*
		 * In order to open this file securely, we'll try a few tricks
		 */

		if ((newlogfd = open(s, O_EXCL|O_WRONLY|O_CREAT, 0644)) < 0) {
			/*
			 * File already exists... now we need to get cute
			 * since opening a file in a world-writeable directory
			 * safely is hard = it could be a hard link or a
			 * symbolic link to a system file.
			 */
			struct stat before;

			if (lstat(s, &before) < 0) {
				logit("Cannot open new logfile \"%s\": %sn",
					s, strerror(errno));
				return (-1);
			}

			if (S_ISREG(before.st_mode) && /* no symbolic links */
				(before.st_nlink == 1) && /* no hard links */
				(before.st_uid == 0)) {   /* owned by root */
				if ((newlogfd =
				    open(s, O_APPEND|O_WRONLY, 0644)) < 0) {
					logit("Cannot open new "\
					    "logfile \"%s\": %s\n", s,
					    strerror(errno));
					return (-1);
				}
			} else {
				logit("Cannot use specified logfile \"%s\": "\
				    "file is/has links or isn't owned by "\
				    "root\n", s);
				return (-1);
			}
		}

		(void) strlcpy(ptr->logfile, s, 128);
		(void) close(logfd);
		logfd = newlogfd;
		logit("Start of new logfile %s\n", s);
	}
	return (0);
}

void
logit(char *format, ...)
{
	static mutex_t loglock;
	struct timeval tv;

#define	LOGBUFLEN	1024
	char buffer[LOGBUFLEN];

	va_list ap;
	va_start(ap, format);

	if (logfd >= 0) {
		int safechars, offset;
		if (gettimeofday(&tv, NULL) != 0 ||
		    ctime_r(&tv.tv_sec, buffer, LOGBUFLEN) == NULL) {
			(void) snprintf(buffer, LOGBUFLEN,
			    "<time conversion failed>\t");
		} else {
			/*
			 * ctime_r() includes some stuff we don't want;
			 * adjust length to overwrite " YYYY\n".
			 */
			offset = strlen(buffer) - 6;
			safechars = LOGBUFLEN - (offset - 1);
			(void) snprintf(buffer + offset, safechars, ".%.4ld\t",
			    tv.tv_usec/100);
		}
		offset = strlen(buffer);
		safechars = LOGBUFLEN - (offset - 1);
		if (vsnprintf(buffer + offset, safechars, format, ap) >
		    safechars) {
			(void) strncat(buffer, "...\n", LOGBUFLEN);
		}

		(void) mutex_lock(&loglock);
		(void) write(logfd, buffer, strlen(buffer));
		(void) mutex_unlock(&loglock);
	}

	va_end(ap);
#undef	LOGBUFLEN
}

static void
do_update(nsc_call_t *in)
{
	union {
		nsc_data_t	data;
		char		space[8192];
	} u;

	time_t now = time(NULL);

	switch (MASKUPDATEBIT(in->nsc_callnumber)) {

	case GETPWUID:
	case GETPWNAM:
		getpw_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	case GETGRNAM:
	case GETGRGID:
		getgr_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	case GETHOSTBYNAME:
	case GETHOSTBYADDR:
		gethost_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	case GETIPNODEBYNAME:
	case GETIPNODEBYADDR:
		getnode_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	case GETEXECID:
		getexec_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	case GETPROFNAM:
		getprof_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	case GETUSERNAM:
		getuser_lookup(&u.data.nsc_ret, sizeof (u), in, now);
		break;

	default:
		assert(0);
		break;
	}

	free(in);
}

int
launch_update(nsc_call_t *in)
{
	nsc_call_t *c;

	int l = nsc_calllen(in);

	in->nsc_callnumber |= UPDATEBIT;

	if ((c = malloc(l)) == NULL) {
		logit("thread create failed: %s\n", strerror(errno));
		exit(1);
	}
	(void) memcpy(c, in, l);

	if (current_admin.debug_level >= DBG_ALL) {
		logit("launching update\n");
	}

	if (thr_create(NULL,
	    NULL,
	    (void *(*)(void*))do_update,
	    c,
	    0|THR_DETACHED, NULL) != 0) {
		logit("thread create failed\n");
		exit(1);
	}

	return (0);
}

static int
nsc_calllen(nsc_call_t *in)
{
	switch (MASKUPDATEBIT(in->nsc_callnumber)) {

	case GETPWUID:
	case GETGRGID:
	case NULLCALL:
		return (sizeof (*in));

	case GETPWNAM:
	case GETGRNAM:
	case GETHOSTBYNAME:
		return (sizeof (*in) + strlen(in->nsc_u.name));
	case GETIPNODEBYNAME:
		return (sizeof (*in) + strlen(in->nsc_u.ipnode.name));

	case GETHOSTBYADDR:
	case GETIPNODEBYADDR:
		return (sizeof (*in) + in->nsc_u.addr.a_length);

	case GETEXECID:
	case GETPROFNAM:
	case GETUSERNAM:

		return (sizeof (*in) + strlen(in->nsc_u.name));
	}

	return (0);
}

static int
client_getadmin(admin_t *ptr)
{
	union {
		nsc_data_t data;
		char space[8192];
	} u;

	nsc_data_t *dptr;
	int ndata;
	int adata;

	u.data.nsc_call.nsc_callnumber = GETADMIN;
	ndata = sizeof (u);
	adata = sizeof (u.data);
	dptr = &u.data;

	if (_nsc_trydoorcall(&dptr, &ndata, &adata) != SUCCESS) {
		return (-1);
	}

	(void) memcpy(ptr, dptr->nsc_ret.nsc_u.buff, sizeof (*ptr));
	return (0);
}

/*ARGSUSED*/
static void
getadmin(nsc_return_t *out, int size, nsc_call_t *ptr)
{
	out->nsc_return_code = SUCCESS;
	out->nsc_bufferbytesused = sizeof (current_admin);
	(void) memcpy(out->nsc_u.buff, &current_admin, sizeof (current_admin));
}


static int
nscd_set_rbac(admin_t *new_admin, int invalidate)
{
	int		i;
	char		*dbname = NULL;
	nsc_stat_t	*cache = NULL;
	nsc_stat_t	*new = NULL;
	void		(*invalidate_func)(void);


	for (i = 1; i <= 3; i++) {
		/*
		 * Three of the RBAC databases are cached.
		 */
		switch (i) {
		case 1:
			dbname = NSS_DBNAM_EXECATTR;
			cache = &current_admin.exec;
			new = &new_admin->exec;
			invalidate_func = getexec_invalidate;
			break;
		case 2:
			dbname = NSS_DBNAM_PROFATTR;
			cache = &current_admin.prof;
			new = &new_admin->prof;
			invalidate_func = getprof_invalidate;
			break;
		case 3:
			dbname = NSS_DBNAM_USERATTR;
			cache = &current_admin.user;
			new = &new_admin->user;
			invalidate_func = getuser_invalidate;
			break;
		default:
			break;
		}

		if (invalidate) {
			if (new->nsc_invalidate) {
				logit("Invalidating %s cache\n", dbname);
				(*invalidate_func)();
			}
		} else {
			if (nscd_set_ttl_positive(cache, dbname,
			    new->nsc_pos_ttl) < 0 ||
			    nscd_set_ttl_negative(cache, dbname,
			    new->nsc_neg_ttl) < 0 ||
			    nscd_set_khc(cache, dbname, new->nsc_keephot) < 0 ||
			    nscd_set_odo(cache, dbname,
			    new->nsc_old_data_ok) < 0 ||
			    nscd_set_ec(cache, dbname, new->nsc_enabled) < 0 ||
			    nscd_set_ss(cache, dbname,
			    new->nsc_suggestedsize) < 0)
				return (-1);
		}
	}

	return (0);
}

/*ARGSUSED*/
static int
setadmin(nsc_return_t *out, int size, nsc_call_t *ptr)
{
	admin_t *new;

	out->nsc_return_code = SUCCESS;
	out->nsc_bufferbytesused = sizeof (nsc_return_t);

	new = (admin_t *)ptr->nsc_u.name;


	/*
	 *  global admin stuff
	 */

	if ((nscd_set_lf(&current_admin, new->logfile) < 0) ||
	    nscd_set_dl(&current_admin, new->debug_level) < 0) {
		out->nsc_return_code = NOTFOUND;
		return (-1);
	}

	/*
	 * per cache items
	 */

	if (new->passwd.nsc_invalidate) {
		logit("Invalidating passwd cache\n");
		getpw_invalidate();
	}

	if (new->group.nsc_invalidate) {
		logit("Invalidating group cache\n");
		getgr_invalidate();
	}

	if (new->host.nsc_invalidate) {
		logit("Invalidating host cache\n");
		gethost_invalidate();
	}

	if (new->node.nsc_invalidate) {
		logit("Invalidating ipnodes cache\n");
		getnode_invalidate();
	}

	(void) nscd_set_rbac(new, 1);		/* invalidate rbac cache */

	if (nscd_set_ttl_positive(&current_admin.passwd,
			"passwd",
			new->passwd.nsc_pos_ttl) < 0		||
	    nscd_set_ttl_negative(&current_admin.passwd,
			"passwd",
			new->passwd.nsc_neg_ttl) < 0		||
	    nscd_set_khc(&current_admin.passwd,
			"passwd",
			new->passwd.nsc_keephot) < 0		||
	    nscd_set_odo(&current_admin.passwd,
			"passwd",
			new->passwd.nsc_old_data_ok) < 0	||
	    nscd_set_ec(&current_admin.passwd,
			"passwd",
			new->passwd.nsc_enabled) < 0		||
	    nscd_set_ss(&current_admin.passwd,
			"passwd",
			new->passwd.nsc_suggestedsize) < 0	   ||

	    nscd_set_ttl_positive(&current_admin.group,
			"group",
			new->group.nsc_pos_ttl) < 0		||
	    nscd_set_ttl_negative(&current_admin.group,
			"group",
			new->group.nsc_neg_ttl) < 0		||
	    nscd_set_khc(&current_admin.group,
			"group",
			new->group.nsc_keephot) < 0		||
	    nscd_set_odo(&current_admin.group,
			"group",
			new->group.nsc_old_data_ok) < 0		||
	    nscd_set_ec(&current_admin.group,
			"group",
			new->group.nsc_enabled) < 0		||
	    nscd_set_ss(&current_admin.group,
			"group",
			new->group.nsc_suggestedsize) < 0	||

	    nscd_set_ttl_positive(&current_admin.node,
			"ipnodes",
			new->node.nsc_pos_ttl) < 0		||
	    nscd_set_ttl_negative(&current_admin.node,
			"ipnodes",
			new->node.nsc_neg_ttl) < 0		||
	    nscd_set_khc(&current_admin.node,
			"ipnodes",
			new->node.nsc_keephot) < 0		||
	    nscd_set_odo(&current_admin.node,
			"ipnodes",
			new->node.nsc_old_data_ok) < 0		||
	    nscd_set_ec(&current_admin.node,
			"ipnodes",
			new->node.nsc_enabled) < 0		||
	    nscd_set_ss(&current_admin.node,
			"ipnodes",
			new->node.nsc_suggestedsize) < 0	||

	    nscd_set_ttl_positive(&current_admin.host,
			"hosts",
			new->host.nsc_pos_ttl) < 0		||
	    nscd_set_ttl_negative(&current_admin.host,
			"hosts",
			new->host.nsc_neg_ttl) < 0		||
	    nscd_set_khc(&current_admin.host,
			"hosts",
			new->host.nsc_keephot) < 0		||
	    nscd_set_odo(&current_admin.host,
			"hosts",
			new->host.nsc_old_data_ok) < 0		||
	    nscd_set_ec(&current_admin.host,
			"hosts",
			new->host.nsc_enabled) < 0		||
	    nscd_set_ss(&current_admin.host,
			"hosts",
			new->host.nsc_suggestedsize) < 0	||
	    nscd_set_rbac(new, 0) < 0) {
		out->nsc_return_code = NOTFOUND;
		return (-1);
	}
	out->nsc_return_code = SUCCESS;
	return (0);
}

void
client_killserver(void)
{
	union {
		nsc_data_t data;
		char space[8192];
	} u;

	nsc_data_t *dptr;
	int ndata;
	int adata;

	u.data.nsc_call.nsc_callnumber = KILLSERVER;

	ndata = sizeof (u);
	adata = sizeof (nsc_call_t);

	dptr = &u.data;

	_nsc_trydoorcall(&dptr, &ndata, &adata);
}


static int
client_setadmin(admin_t *ptr)
{
	union {
		nsc_data_t data;
		char space[8192];
	} u;

	nsc_data_t *dptr;
	int ndata;
	int adata;

	u.data.nsc_call.nsc_callnumber = SETADMIN;

	(void) memcpy(u.data.nsc_call.nsc_u.name, ptr, sizeof (*ptr));

	ndata = sizeof (u);
	adata = sizeof (*ptr);

	dptr = &u.data;

	if (_nsc_trydoorcall(&dptr, &ndata, &adata) != SUCCESS) {
		return (-1);
	}

	return (0);
}

static void
dump_stat(nsc_stat_t *ptr)
{
	double hitrate;
	(void) printf("%10s  cache is enabled\n",
	    (ptr->nsc_enabled?"Yes":"No"));
	(void) printf("%10d  cache hits on positive entries\n",
	    ptr->nsc_pos_cache_hits);
	(void) printf("%10d  cache hits on negative entries\n",
	    ptr->nsc_neg_cache_hits);
	(void) printf("%10d  cache misses on positive entries\n",
	    ptr->nsc_pos_cache_misses);
	(void) printf("%10d  cache misses on negative entries\n",
	    ptr->nsc_neg_cache_misses);
	hitrate = ptr->nsc_pos_cache_misses + ptr->nsc_neg_cache_misses +
	    ptr->nsc_pos_cache_hits + ptr->nsc_neg_cache_hits;

	if (hitrate > 0.0)
		hitrate = (100.0 * ((double)ptr->nsc_pos_cache_hits +
		    (double)ptr->nsc_neg_cache_hits))/hitrate;

	(void) printf("%10.1f%% cache hit rate\n",  hitrate);
	(void) printf("%10d  queries deferred\n", ptr->nsc_throttle_count);
	(void) printf("%10d  total entries\n", ptr->nsc_entries);
	(void) printf("%10d  complete cache invalidations\n",
	    ptr->nsc_invalidate_count);
	(void) printf("%10d  suggested size\n", ptr->nsc_suggestedsize);
	(void) printf("%10d  seconds time to live for positive entries\n",
	    ptr->nsc_pos_ttl);
	(void) printf("%10d  seconds time to live for negative entries\n",
	    ptr->nsc_neg_ttl);
	(void) printf("%10d  most active entries to be kept valid\n",
	    ptr->nsc_keephot);
	(void) printf("%10s  check /etc/{passwd, group, hosts, inet/ipnodes} "
	    "file for changes\n",
	    (ptr->nsc_check_files?"Yes":"No"));

	(void) printf("%10s  use possibly stale data rather than waiting for "
	    "refresh\n",
	    (ptr->nsc_old_data_ok?"Yes":"No"));
}

static void
client_showstats(admin_t *ptr)
{

	(void) printf("nscd configuration:\n\n");
	(void) printf("%10d  server debug level\n", ptr->debug_level);
	(void) printf("\"%s\"  is server log file\n", ptr->logfile);

	(void) printf("\npasswd cache:\n\n");
	dump_stat(&(ptr->passwd));
	(void) printf("\ngroup cache:\n\n");
	dump_stat(&(ptr->group));
	(void) printf("\nhosts cache:\n\n");
	dump_stat(&(ptr->host));
	(void) printf("\nipnodes cache:\n\n");
	dump_stat(&(ptr->node));
	(void) printf("\nexec_attr cache:\n\n");
	dump_stat(&(ptr->exec));
	(void) printf("\nprof_attr cache:\n\n");
	dump_stat(&(ptr->prof));
	(void) printf("\nuser_attr cache:\n\n");
	dump_stat(&(ptr->user));
}



/*
 * detach from tty
 */
static void
detachfromtty(void)
{
	if (logfd > 0) {
		int i;
		for (i = 0; i < logfd; i++)
			(void) close(i);
		closefrom(logfd+1);
	} else
		closefrom(0);

	(void) chdir("/");

	switch (fork1()) {
	case (pid_t)-1:
		exit(1);
		break;
	case 0:
		break;
	default:
		exit(0);
	}
	(void) setsid();
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup(0);
	(void) dup(0);
}
