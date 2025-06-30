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
 * Copyright 2025 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <libscf.h>
#ifdef DEBUG
#include <time.h>
#endif
#include <signal.h>
#include <semaphore.h>
#include <sys/wait.h>

#include "isns_server.h"
#include "isns_dseng.h"
#include "isns_msgq.h"
#include "isns_log.h"
#include "isns_cfg.h"
#include "isns_utils.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_dd.h"
#include "isns_scn.h"
#include "isns_sched.h"
#include "isns_esi.h"
#include "isns_mgmt.h"

/*
 * iSNS Server administrative settings.
 */
uint8_t daemonlize = 0;
int dbg_level = 7;
uint64_t esi_threshold;
uint8_t mgmt_scn;
ctrl_node_t *control_nodes = NULL;
pthread_mutex_t ctrl_node_mtx = PTHREAD_MUTEX_INITIALIZER;
char data_store[MAXPATHLEN];


/* semaphore for handling exit */
static sem_t	isns_child_sem;
static int	isns_child_smf_exit_code;
static pid_t	isns_child_pid;

#if !defined(SMF_EXIT_ERR_OTHER)
#define	SMF_EXIT_ERR_OTHER	-1
#endif

/*
 * Globals for singal handling.  time_to_exit is set by sig_handle()
 * when set the main thread(daemon) and othere threads should exit.
 *
 * semaphone is used to make sure all threads that are created
 * by isns_port_watcher and esi.
 */
boolean_t time_to_exit = B_FALSE;
static uint32_t thr_ref_count;
static pthread_mutex_t thr_count_mtx = PTHREAD_MUTEX_INITIALIZER;
#define	MAX_RETRY_COUNT	10 /* for checking remaining threads before exit. */

/*
 * Door creation flag.
 */
boolean_t door_created = B_FALSE;

/*
 * global system message queue
 */
msg_queue_t *sys_q = NULL;
msg_queue_t *scn_q = NULL;

#ifdef DEBUG
extern void *cli_test(void *argv);
extern int dump_db(void);
#endif

extern void sigalrm(int);

/*
 * sigusr2_handler -- SIGUSR2 Handler
 * sigusr2 is exepected only when child is running okay.
 */
/* ARGSUSED */
static void
sigusr2_handler(
	int	sig
)
{
	/* post okay status. */
	isnslog(LOG_DEBUG, "sigusr2_handler",
	    "SIGUSR@ is received.  Parent is existing...");
	isns_child_smf_exit_code = SMF_EXIT_OK;

	(void) sem_post(&isns_child_sem);
}

/*
 * sigchld_handler -- SIGCHLD Handler
 * sigchld is exepected only when there is an error.
 */
/* ARGSUSED */
static void
sigchld_handler(
	int	sig
)
{
	int	status;
	pid_t	ret_pid;

	/* This is the default code. */
	isns_child_smf_exit_code = SMF_EXIT_ERR_OTHER;

	ret_pid = waitpid(isns_child_pid, &status, WNOHANG);

	if (ret_pid == isns_child_pid) {
		if (WIFEXITED(status)) {
			isns_child_smf_exit_code = WEXITSTATUS(status);
		}
	}
	(void) sem_post(&isns_child_sem);
}

/* ARGSUSED */
static void
sighup_handler(
	int	sig
)
{

	isnslog(LOG_DEBUG, "sighup_handle",
	    "SIGHUP is received.  Reloading config...");
	(void) queue_msg_set(sys_q, CONFIG_RELOAD, NULL);
}

/* ARGSUSED */
static void
sigexit_handler(
	int	sig
)
{
	isnslog(LOG_DEBUG, "sigexit_handler",
	    "Signal: %d received and sending server exit.", sig);
	shutdown_server();
}

void
inc_thr_count(
)
{
	(void) pthread_mutex_lock(&thr_count_mtx);

	isnslog(LOG_DEBUG, "inc_thr_count",
	    "increase thread reference count(%d).", thr_ref_count);

	thr_ref_count++;

	(void) pthread_mutex_unlock(&thr_count_mtx);
}

void
dec_thr_count(
)
{
	(void) pthread_mutex_lock(&thr_count_mtx);

	isnslog(LOG_DEBUG, "dec_thr_count",
	    "decrease thread reference count(%d).", thr_ref_count);

	thr_ref_count--;

	(void) pthread_mutex_unlock(&thr_count_mtx);
}

uint32_t
get_thr_count(
)
{
	uint32_t ref;

	(void) pthread_mutex_lock(&thr_count_mtx);

	ref = thr_ref_count;

	(void) pthread_mutex_unlock(&thr_count_mtx);

	isnslog(LOG_DEBUG, "get_thr_count",
	    "checking thread reference count %d.", ref);

	return (ref);
}

void
shutdown_server(
)
{
	isnslog(LOG_DEBUG, "shutdown", "raise exit flag.");
	time_to_exit = B_TRUE;
	(void) queue_msg_set(sys_q, SERVER_EXIT, NULL);
}

int
main(
	/* LINTED E_FUNC_ARG_UNUSED */
	int	argc,
	/* LINTED E_FUNC_ARG_UNUSED */
	char	*argv[]
)
{
	int opt_i = 0;
	pthread_t port_tid, esi_tid, scn_tid;
	uint32_t thr_cnt;
	int i;

#ifdef DEBUG
	time_t t;
	clock_t c;
#endif

#ifdef DEBUG
	if (getopt(argc, argv, "i") == 'i') {
		opt_i = 1; /* interactive mode */
	}
#endif

	/* set locale */
	openlog(ISNS_DAEMON_SYSLOG_PP, LOG_PID | LOG_CONS, LOG_DAEMON);

	/* load administative settings. pick up data location. */
	if (load_config(B_TRUE) != 0) {
		isnslog(LOG_ERR, "main", "administrative settings load error.");
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* A signal handler is set for SIGCHLD. */
	(void) signal(SIGCHLD, sigchld_handler);
	(void) signal(SIGUSR2, sigusr2_handler);
	(void) sigset(SIGALRM, sigalrm);

#ifdef DEBUG
	printf("start daemon\n");
#endif
	if (opt_i == 0 || daemonlize) {
		isnslog(LOG_DEBUG, "main", "now forking... pid %d", getpid());
		daemonlize = 1;
		/* daemonlize */
		isns_child_pid = fork();
		if (isns_child_pid < 0) {
			/*
			 * cannot fork(), terminate the server.
			 */
			exit(SMF_EXIT_ERR_CONFIG);
		}
		if (isns_child_pid > 0) {
			/*
			 * terminate parent.
			 */
			(void) sem_wait(&isns_child_sem);
			(void) sem_destroy(&isns_child_sem);
			isnslog(LOG_DEBUG, "main", "exiting with %d",
				isns_child_smf_exit_code);
			exit(isns_child_smf_exit_code);
		}

		/*
		 * redirect stdout, and stderr to /dev/null.
		 */
		i = open("/dev/null", O_RDWR);
		(void) dup2(i, 1);
		(void) dup2(i, 2);
	} /* end of daemonlize */

#ifdef DEBUG
	printf("calling cache init\n");
#endif
	/* initialize object hash table */
	if (cache_init() != 0) {
		isnslog(LOG_ERR, "main",
		    "object hash table initialization error.");
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* initialize event list */
	if (el_init(10, 60, 6) != 0) {
		isnslog(LOG_ERR, "main",
		"ESI event list initialization error.");
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* initialize iSNS database */
	if (init_data() != 0) {
		isnslog(LOG_ERR, "main",
		    "internal database initialization error");
		exit(SMF_EXIT_ERR_OTHER);
	}

#ifdef DEBUG
	printf("calling load_data\n");
	t = time(NULL);
	c = clock();
#endif

	if (load_data() != 0) {
		isnslog(LOG_ERR, "main", "loading data store failed");
		exit(SMF_EXIT_ERR_OTHER);
	}

#ifdef DEBUG
	t = time(NULL) - t;
	c = clock() - c;
	printf("time %d clock %.4lf -loading data\n",
	    t, c / (double)CLOCKS_PER_SEC);
#endif

#ifdef DEBUG
	printf("sys queue creating...\n");
#endif
	/* create a message queue for system control */
	sys_q = queue_calloc();
	if (!sys_q) {
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* create a message queue for scn thread */
	scn_q = queue_calloc();
	if (!scn_q) {
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* create scn thread */
	/* Check for Default DD/DD-set existence and */
	/* create them if they are not there. */
	if (verify_ddd() != 0) {
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* setup and verify the portal(s) for scn(s) */
	/* after scn registry is loaded from data store. */
	if (verify_scn_portal() != 0) {
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* setup and verify the portal(s) for esi(s) */
	/* after esi list is loaded from data store. */
	if (verify_esi_portal() != 0) {
		exit(SMF_EXIT_ERR_OTHER);
	}

#ifdef DEBUG
	printf("scn queue creating...\n");
#endif

	(void) sigset(SIGHUP, sighup_handler);
	(void) sigset(SIGINT, sigexit_handler);
	(void) sigset(SIGTERM, sigexit_handler);
	(void) sigset(SIGQUIT, sigexit_handler);

	/* create scn thread */
	if (pthread_create(&scn_tid, NULL, scn_proc, NULL) != 0) {
		isnslog(LOG_ERR, "main", "SCN thread creating error.");
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* setup a door for management interface */
	if (setup_mgmt_door(sys_q) != 0) {
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* create server port watcher */
	if (pthread_create(&port_tid, NULL,
	    isns_port_watcher, (void *)sys_q) != 0) {
		isnslog(LOG_ERR, "main", "iSNS port thread creating error.");
		exit(SMF_EXIT_ERR_OTHER);
	}

	/* create entity status inquiry thread */
	if (pthread_create(&esi_tid, NULL,
	    esi_proc, NULL) != 0) {
		isnslog(LOG_ERR, "main", "ESI thread creating error.");
		exit(SMF_EXIT_ERR_OTHER);
	}

#ifdef DEBUG
	if (!daemonlize) {
		pthread_t tid;
		(void) pthread_create(&tid,
		    NULL,
		    cli_test,
		    (void *)sys_q);
	}
#endif
	if (opt_i == 0 || daemonlize) {
		isnslog(LOG_DEBUG, "main", "issuing SIGUSR2.. parent pid %d",
		    getppid());
		(void) kill(getppid(), SIGUSR2);
	}

	/* pause */
	for (;;) {
		msg_text_t *msg = queue_msg_get(sys_q);
		switch (msg->id) {
			case DATA_ADD:
			case DATA_UPDATE:
			case DATA_DELETE:
			case DATA_DELETE_ASSOC:
			case DATA_COMMIT:
			case DATA_RETREAT:
				break;
			case REG_EXP:
				/* registration expiring */
				reg_expiring(msg->data);
				break;
			case DEAD_PORTAL:
				portal_dies((uint32_t)msg->data);
				break;
			case SERVER_EXIT:
				/* graceful exit. */
				(void) queue_msg_free(msg);
				isnslog(LOG_DEBUG, "main",
				    "wake up ESI and stop it.");
				(void) get_stopwatch(1);
				isnslog(LOG_DEBUG, "main",
				    "sending SCN stop msg.");
				(void) queue_msg_set(scn_q, SCN_STOP, NULL);
				if (door_created) {
					isnslog(LOG_DEBUG, "main",
					    "closing the door.");
					(void) fdetach(ISNS_DOOR_NAME);
				}
				(void) pthread_join(esi_tid, NULL);
				isnslog(LOG_DEBUG, "main",
				    "esi thread %d exited.", esi_tid);
				(void) pthread_join(port_tid, NULL);
				isnslog(LOG_DEBUG, "main",
				    "port watcher thread %d exited.", port_tid);
				(void) pthread_join(scn_tid, NULL);
				isnslog(LOG_DEBUG, "main",
				    "scn thread %d exited.", scn_tid);

				/* now check any remaining threads. */
				i = 0;
				do {
					thr_cnt = get_thr_count();
					if (thr_cnt == 0) {
						isnslog(LOG_DEBUG, "main",
						    "main thread %d is done.",
						    pthread_self());
						exit(1);
					} else {
						(void) sleep(1);
						i++;
					}
				} while (MAX_RETRY_COUNT > i);
				isnslog(LOG_DEBUG, "main",
				    "main thread %d existing ...",
				    pthread_self());
				exit(1);
				break;
			case CONFIG_RELOAD:
				/* load config again. don't pick data store. */
				(void) load_config(B_FALSE);
				break;
			case SYS_QUIT_OK:
				(void) queue_msg_free(msg);
				exit(0);
			default:
				break;
		}
		(void) queue_msg_free(msg);
	}

	/* LINTED E_STMT_NOT_REACHED */
	return (0);
}
