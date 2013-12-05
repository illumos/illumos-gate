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
 *	syseventd - The system event daemon
 *
 *		This daemon dispatches event buffers received from the
 *		kernel to all interested SLM clients.  SLMs in turn
 *		deliver the buffers to their particular application
 *		clients.
 */
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <synch.h>
#include <syslog.h>
#include <thread.h>
#include <libsysevent.h>
#include <limits.h>
#include <locale.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/wait.h>

#include "sysevent_signal.h"
#include "syseventd.h"
#include "message.h"

extern int insert_client(void *client, int client_type, int retry_limit);
extern void delete_client(int id);
extern void initialize_client_tbl(void);

extern struct sysevent_client *sysevent_client_tbl[];
extern mutex_t client_tbl_lock;

#define	DEBUG_LEVEL_FORK	9	/* will run in background at all */
					/* levels less than DEBUG_LEVEL_FORK */

int debug_level = 0;
char *root_dir = "";			/* Relative root for lock and door */

/* Maximum number of outstanding events dispatched */
#define	SE_EVENT_DISPATCH_CNT	100

static int upcall_door;			/* Kernel event door */
static int door_upcall_retval;		/* Kernel event posting return value */
static int fini_pending = 0;		/* fini pending flag */
static int deliver_buf = 0;		/* Current event buffer from kernel */
static int dispatch_buf = 0;		/* Current event buffer dispatched */
static sysevent_t **eventbuf; 		/* Global array of event buffers */
static struct ev_completion *event_compq;	/* Event completion queue */
static mutex_t ev_comp_lock;		/* Event completion queue lock */
static mutex_t err_mutex;		/* error logging lock */
static mutex_t door_lock;		/* sync door return access */
static rwlock_t mod_unload_lock;		/* sync module unloading */

/* declarations and definitions for avoiding multiple daemons running */
#define	DAEMON_LOCK_FILE "/var/run/syseventd.lock"
char local_lock_file[PATH_MAX + 1];
static int hold_daemon_lock;
static int daemon_lock_fd;

/*
 * sema_eventbuf - guards against the global buffer eventbuf
 *	being written to before it has been dispatched to clients
 *
 * sema_dispatch - synchronizes between the kernel uploading thread
 *	(producer) and the userland dispatch_message thread (consumer).
 *
 * sema_resource - throttles outstanding event consumption.
 *
 * event_comp_cv - synchronizes threads waiting for the event completion queue
 *			to empty or become active.
 */
static sema_t sema_eventbuf, sema_dispatch, sema_resource;
static cond_t event_comp_cv;

/* Self-tuning concurrency level */
#define	MIN_CONCURRENCY_LEVEL	4
static int concurrency_level = MIN_CONCURRENCY_LEVEL;


/* SLM defines */
#define	MODULE_SUFFIX	".so"
#define	EVENT_FINI	"slm_fini"
#define	EVENT_INIT	"slm_init"

#define	SE_TIMEOUT	60	/* Client dispatch timeout (seconds) */

/* syslog message related */
static int logflag = 0;
static char *prog;

/* function prototypes */
static void door_upcall(void *cookie, char *args, size_t alen, door_desc_t *ddp,
	uint_t ndid);
static void dispatch_message(void);
static int dispatch(void);
static void event_completion_thr(void);
static void usage(void);

static void syseventd_init(void);
static void syseventd_fini(int sig);

static pid_t enter_daemon_lock(void);
static void exit_daemon_lock(void);

static void
usage() {
	(void) fprintf(stderr, "usage: syseventd [-d <debug_level>] "
	    "[-r <root_dir>]\n");
	(void) fprintf(stderr, "higher debug levels get progressively ");
	(void) fprintf(stderr, "more detailed debug information.\n");
	(void) fprintf(stderr, "syseventd will run in background if ");
	(void) fprintf(stderr, "run with a debug_level less than %d.\n",
	    DEBUG_LEVEL_FORK);
	exit(2);
}


/* common exit function which ensures releasing locks */
void
syseventd_exit(int status)
{
	syseventd_print(1, "exit status = %d\n", status);

	if (hold_daemon_lock) {
		exit_daemon_lock();
	}

	exit(status);
}


/*
 * hup_handler - SIGHUP handler.  SIGHUP is used to force a reload of
 *		 all SLMs.  During fini, events are drained from all
 *		 client event queues.  The events that have been consumed
 *		 by all clients are freed from the kernel event queue.
 *
 *		 Events that have not yet been delivered to all clients
 *		 are not freed and will be replayed after all SLMs have
 *		 been (re)loaded.
 *
 *		 After all client event queues have been drained, each
 *		 SLM client is unloaded.  The init phase will (re)load
 *		 each SLM and initiate event replay and delivery from
 *		 the kernel.
 *
 */
/*ARGSUSED*/
static void
hup_handler(int sig)
{
	syseventd_err_print(SIGHUP_CAUGHT);
	(void) fflush(0);
	syseventd_fini(sig);
	syseventd_init();
	syseventd_err_print(DAEMON_RESTARTED);
	(void) fflush(0);
}

/*
 * Fault handler for other signals caught
 */
/*ARGSUSED*/
static void
flt_handler(int sig)
{
	char signame[SIG2STR_MAX];

	if (sig2str(sig, signame) == -1) {
		syseventd_err_print(UNKNOWN_SIGNAL_CAUGHT, sig);
	}

	(void) se_signal_sethandler(sig, SIG_DFL, NULL);

	switch (sig) {
		case SIGINT:
		case SIGSTOP:
		case SIGTERM:
			/* Close kernel door */
			(void) door_revoke(upcall_door);

			/* Gracefully exit current event delivery threads */
			syseventd_fini(sig);

			(void) fflush(0);
			(void) se_signal_unblockall();
			syseventd_exit(1);
			/*NOTREACHED*/
		case SIGCLD:
		case SIGPWR:
		case SIGWINCH:
		case SIGURG:
		case SIGCONT:
		case SIGWAITING:
		case SIGLWP:
		case SIGFREEZE:
		case SIGTHAW:
		case SIGCANCEL:
		case SIGXRES:
		case SIGJVM1:
		case SIGJVM2:
		case SIGINFO:
			/* No need to abort */
			break;
		default:
			syseventd_err_print(FATAL_ERROR);
			abort();

	}
}

/*
 * Daemon parent process only.
 * Child process signal to indicate successful daemon initialization.
 * This is the normal and expected exit path of the daemon parent.
 */
/*ARGSUSED*/
static void
sigusr1(int sig)
{
	syseventd_exit(0);
}

static void
sigwait_thr()
{
	int	sig;
	int	err;
	sigset_t signal_set;

	for (;;) {
		syseventd_print(3, "sigwait thread waiting for signal\n");
		(void) sigfillset(&signal_set);
		err = sigwait(&signal_set, &sig);
		if (err) {
			syseventd_exit(2);
		}

		/*
		 * Block all signals until the signal handler completes
		 */
		if (sig == SIGHUP) {
			hup_handler(sig);
		} else {
			flt_handler(sig);
		}
	}
	/* NOTREACHED */
}

static void
set_root_dir(char *dir)
{
	root_dir = malloc(strlen(dir) + 1);
	if (root_dir == NULL) {
		syseventd_err_print(INIT_ROOT_DIR_ERR, strerror(errno));
		syseventd_exit(2);
	}
	(void) strcpy(root_dir, dir);
}

int
main(int argc, char **argv)
{
	int i, c;
	int fd;
	pid_t pid;
	int has_forked = 0;
	extern char *optarg;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getuid() != 0) {
		(void) fprintf(stderr, "Must be root to run syseventd\n");
		syseventd_exit(1);
	}

	if (argc > 5) {
		usage();
	}

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}

	while ((c = getopt(argc, argv, "d:r:")) != EOF) {
		switch (c) {
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 'r':
			/*
			 * Private flag for suninstall to run
			 * daemon during install.
			 */
			set_root_dir(optarg);
			break;
		case '?':
		default:
			usage();
		}
	}

	/* demonize ourselves */
	if (debug_level < DEBUG_LEVEL_FORK) {

		sigset_t mask;

		(void) sigset(SIGUSR1, sigusr1);

		(void) sigemptyset(&mask);
		(void) sigaddset(&mask, SIGUSR1);
		(void) sigprocmask(SIG_BLOCK, &mask, NULL);

		if ((pid = fork()) == (pid_t)-1) {
			(void) fprintf(stderr,
			    "syseventd: fork failed - %s\n", strerror(errno));
			syseventd_exit(1);
		}

		if (pid != 0) {
			/*
			 * parent
			 * handshake with the daemon so that dependents
			 * of the syseventd service don't start up until
			 * the service is actually functional
			 */
			int status;
			(void) sigprocmask(SIG_UNBLOCK, &mask, NULL);

			if (waitpid(pid, &status, 0) != pid) {
				/*
				 * child process signal indicating
				 * successful daemon initialization
				 */
				syseventd_exit(0);
			}
			/* child exited implying unsuccessful startup */
			syseventd_exit(1);
		}

		/* child */

		has_forked = 1;
		(void) sigset(SIGUSR1, SIG_DFL);
		(void) sigprocmask(SIG_UNBLOCK, &mask, NULL);

		(void) chdir("/");
		(void) setsid();
		if (debug_level <= 1) {
			closefrom(0);
			fd = open("/dev/null", 0);
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			logflag = 1;
		}
	}

	openlog("syseventd", LOG_PID, LOG_DAEMON);

	(void) mutex_init(&err_mutex, USYNC_THREAD, NULL);

	syseventd_print(8,
	    "syseventd started, debug level = %d\n", debug_level);

	/* only one instance of syseventd can run at a time */
	if ((pid = enter_daemon_lock()) != getpid()) {
		syseventd_print(1,
		    "event daemon pid %ld already running\n", pid);
		exit(3);
	}

	/* initialize semaphores and eventbuf */
	(void) sema_init(&sema_eventbuf, SE_EVENT_DISPATCH_CNT,
	    USYNC_THREAD, NULL);
	(void) sema_init(&sema_dispatch, 0, USYNC_THREAD, NULL);
	(void) sema_init(&sema_resource, SE_EVENT_DISPATCH_CNT,
	    USYNC_THREAD, NULL);
	(void) cond_init(&event_comp_cv, USYNC_THREAD, NULL);
	eventbuf = (sysevent_t **)calloc(SE_EVENT_DISPATCH_CNT,
	    sizeof (sysevent_t *));
	if (eventbuf == NULL) {
		syseventd_print(1, "Unable to allocate event buffer array\n");
		exit(2);
	}
	for (i = 0; i < SE_EVENT_DISPATCH_CNT; ++i) {
		eventbuf[i] = malloc(LOGEVENT_BUFSIZE);
		if (eventbuf[i] == NULL) {
			syseventd_print(1, "Unable to allocate event "
			    "buffers\n");
			exit(2);
		}
	}

	(void) mutex_init(&client_tbl_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&ev_comp_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&door_lock, USYNC_THREAD, NULL);
	(void) rwlock_init(&mod_unload_lock, USYNC_THREAD, NULL);

	event_compq = NULL;

	syseventd_print(8, "start the message thread running\n");

	/*
	 * Block all signals to all threads include the main thread.
	 * The sigwait_thr thread will process any signals and initiate
	 * a graceful recovery if possible.
	 */
	if (se_signal_blockall() < 0) {
		syseventd_err_print(INIT_SIG_BLOCK_ERR);
		syseventd_exit(2);
	}

	if (thr_create(NULL, NULL, (void *(*)(void *))dispatch_message,
	    (void *)0, 0, NULL) < 0) {
		syseventd_err_print(INIT_THR_CREATE_ERR, strerror(errno));
		syseventd_exit(2);
	}
	if (thr_create(NULL, NULL,
	    (void *(*)(void *))event_completion_thr, NULL,
	    THR_BOUND, NULL) != 0) {
		syseventd_err_print(INIT_THR_CREATE_ERR, strerror(errno));
		syseventd_exit(2);
	}
	/* Create signal catching thread */
	if (thr_create(NULL, NULL, (void *(*)(void *))sigwait_thr,
	    NULL, 0, NULL) < 0) {
		syseventd_err_print(INIT_THR_CREATE_ERR, strerror(errno));
		syseventd_exit(2);
	}

	setbuf(stdout, (char *)NULL);

	/* Initialize and load SLM clients */
	initialize_client_tbl();
	syseventd_init();

	/* signal parent to indicate successful daemon initialization */
	if (has_forked) {
		if (kill(getppid(), SIGUSR1) != 0) {
			syseventd_err_print(
			    "signal to the parent failed - %s\n",
			    strerror(errno));
			syseventd_exit(2);
		}
	}

	syseventd_print(8, "Pausing\n");

	for (;;) {
		(void) pause();
	}
	/* NOTREACHED */
	return (0);
}

/*
 * door_upcall - called from the kernel via kernel sysevent door
 *		to upload event(s).
 *
 *		This routine should never block.  If resources are
 *		not available to immediately accept the event buffer
 *		EAGAIN is returned to the kernel.
 *
 *		Once resources are available, the kernel is notified
 *		via a modctl interface to resume event delivery to
 *		syseventd.
 *
 */
/*ARGSUSED*/
static void
door_upcall(void *cookie, char *args, size_t alen,
    door_desc_t *ddp, uint_t ndid)
{
	sysevent_t *ev;
	int rval;


	(void) mutex_lock(&door_lock);
	if (args == NULL) {
		rval = EINVAL;
	} else if (sema_trywait(&sema_eventbuf)) {
		ev = (sysevent_t *)
		    &((log_event_upcall_arg_t *)(void *)args)->buf;
		syseventd_print(2, "door_upcall: busy event %llx "
		    "retry\n", sysevent_get_seq(ev));
		rval = door_upcall_retval = EAGAIN;
	} else {
		/*
		 * Copy received message to local buffer.
		 */
		size_t size;
		ev = (sysevent_t *)
		    &((log_event_upcall_arg_t *)(void *)args)->buf;

		syseventd_print(2, "door_upcall: event %llx in eventbuf %d\n",
		    sysevent_get_seq(ev), deliver_buf);
		size = sysevent_get_size(ev) > LOGEVENT_BUFSIZE ?
		    LOGEVENT_BUFSIZE : sysevent_get_size(ev);
		(void) bcopy(ev, eventbuf[deliver_buf], size);
		deliver_buf = (deliver_buf + 1) % SE_EVENT_DISPATCH_CNT;
		rval = 0;
		(void) sema_post(&sema_dispatch);
	}

	(void) mutex_unlock(&door_lock);

	/*
	 * Filling in return values for door_return
	 */
	(void) door_return((void *)&rval, sizeof (rval), NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * dispatch_message - dispatch message thread
 *			This thread spins until an event buffer is delivered
 *			delivered from the kernel.
 *
 *			It will wait to dispatch an event to any clients
 *			until adequate resources are available to process
 *			the event buffer.
 */
static void
dispatch_message(void)
{
	int error;

	for (;;) {
		syseventd_print(3, "dispatch_message: thread started\n");
		/*
		 * Spin till a message comes
		 */
		while (sema_wait(&sema_dispatch) != 0) {
			syseventd_print(1,
			    "dispatch_message: sema_wait failed\n");
			(void) sleep(1);
		}

		syseventd_print(3, "dispatch_message: sema_dispatch\n");

		/*
		 * Wait for available resources
		 */
		while (sema_wait(&sema_resource) != 0) {
			syseventd_print(1, "dispatch_message: sema_wait "
			    "failed\n");
			(void) sleep(1);
		}

		syseventd_print(2, "dispatch_message: eventbuf %d\n",
		    dispatch_buf);

		/*
		 * Client dispatch
		 */
		do {
			error = dispatch();
		} while (error == EAGAIN);

		syseventd_print(2, "eventbuf %d dispatched\n", dispatch_buf);
		dispatch_buf = (dispatch_buf + 1) % SE_EVENT_DISPATCH_CNT;

		/*
		 * kernel received a busy signal -
		 * kickstart the kernel delivery thread
		 * door_lock blocks the kernel so we hold it for the
		 * shortest time possible.
		 */
		(void) mutex_lock(&door_lock);
		if (door_upcall_retval == EAGAIN && !fini_pending) {
			syseventd_print(3, "dispatch_message: retrigger "
			    "door_upcall_retval = %d\n",
			    door_upcall_retval);
			(void) modctl(MODEVENTS, (uintptr_t)MODEVENTS_FLUSH,
			    NULL, NULL, NULL, 0);
			door_upcall_retval = 0;
		}
		(void) mutex_unlock(&door_lock);
	}
	/* NOTREACHED */
}

/*
 * drain_eventq - Called to drain all pending events from the client's
 *		event queue.
 */
static void
drain_eventq(struct sysevent_client *scp, int status)
{
	struct event_dispatch_pkg *d_pkg;
	struct event_dispatchq *eventq, *eventq_next;

	syseventd_print(3, "Draining eventq for client %d\n",
	    scp->client_num);

	eventq = scp->eventq;
	while (eventq) {
		/*
		 * Mark all dispatched events as completed, but indicate the
		 * error status
		 */
		d_pkg = eventq->d_pkg;

		syseventd_print(4, "drain event 0X%llx for client %d\n",
		    sysevent_get_seq(d_pkg->ev), scp->client_num);

		if (d_pkg->completion_state == SE_NOT_DISPATCHED) {
			d_pkg->completion_status = status;
			d_pkg->completion_state = SE_COMPLETE;
			(void) sema_post(d_pkg->completion_sema);
		}

		eventq_next = eventq->next;
		free(eventq);
		eventq = eventq_next;
		scp->eventq = eventq;
	}
}

/*
 * client_deliver_event_thr - Client delivery thread
 *				This thread will process any events on this
 *				client's eventq.
 */
static void
client_deliver_event_thr(void *arg)
{
	int flag, error, i;
	sysevent_t *ev;
	hrtime_t now;
	module_t *mod;
	struct event_dispatchq *eventq;
	struct sysevent_client *scp;
	struct event_dispatch_pkg *d_pkg;

	scp = (struct sysevent_client *)arg;
	mod = (module_t *)scp->client_data;

	(void) mutex_lock(&scp->client_lock);
	for (;;) {
		while (scp->eventq == NULL) {

			/*
			 * Client has been suspended or unloaded, go no further.
			 */
			if (fini_pending) {
				scp->client_flags &= ~SE_CLIENT_THR_RUNNING;
				syseventd_print(3, "Client %d delivery thread "
				    "exiting flags: 0X%x\n",
				    scp->client_num, scp->client_flags);
				(void) mutex_unlock(&scp->client_lock);
				return;
			}

			(void) cond_wait(&scp->client_cv, &scp->client_lock);

		}

		/*
		 * Process events from the head of the eventq, eventq is locked
		 * going into the processing.
		 */
		eventq = scp->eventq;
		while (eventq != NULL) {
			d_pkg = eventq->d_pkg;
			d_pkg->completion_state = SE_OUTSTANDING;
			scp->eventq = eventq->next;
			free(eventq);
			(void) mutex_unlock(&scp->client_lock);


			flag = error = 0;
			ev = d_pkg->ev;

			syseventd_print(3, "Start delivery for client %d "
			    "with retry count %d\n",
			    scp->client_num, d_pkg->retry_count);

			/*
			 * Retry limit has been reached by this client, indicate
			 * that no further retries are allowed
			 */
			for (i = 0; i <= scp->retry_limit; ++i) {
				if (i == scp->retry_limit)
					flag = SE_NO_RETRY;

				/* Start the clock for the event delivery */
				d_pkg->start_time = gethrtime();

				syseventd_print(9, "Deliver to module client "
				    "%s\n", mod->name);

				error = mod->deliver_event(ev, flag);

				/* Can not allow another retry */
				if (i == scp->retry_limit)
					error = 0;

				/* Stop the clock */
				now = gethrtime();

				/*
				 * Suspend event processing and drain the
				 * event q for latent clients
				 */
				if (now - d_pkg->start_time >
				    ((hrtime_t)SE_TIMEOUT * NANOSEC)) {
					syseventd_print(1, "Unresponsive "
					    "client %d: Draining eventq and "
					    "suspending event delivery\n",
					    scp->client_num);
					(void) mutex_lock(&scp->client_lock);
					scp->client_flags &=
					    ~SE_CLIENT_THR_RUNNING;
					scp->client_flags |=
					    SE_CLIENT_SUSPENDED;

					/* Cleanup current event */
					d_pkg->completion_status = EFAULT;
					d_pkg->completion_state = SE_COMPLETE;
					(void) sema_post(
					    d_pkg->completion_sema);

					/*
					 * Drain the remaining events from the
					 * queue.
					 */
					drain_eventq(scp, EINVAL);
					(void) mutex_unlock(&scp->client_lock);
					return;
				}

				/* Event delivery retry requested */
				if (fini_pending || error != EAGAIN) {
					break;
				} else {
					(void) sleep(SE_RETRY_TIME);
				}
			}

			(void) mutex_lock(&scp->client_lock);
			d_pkg->completion_status = error;
			d_pkg->completion_state = SE_COMPLETE;
			(void) sema_post(d_pkg->completion_sema);
			syseventd_print(3, "Completed delivery with "
			    "error %d\n", error);
			eventq = scp->eventq;
		}

		syseventd_print(3, "No more events to process for client %d\n",
		    scp->client_num);

		/* Return if this was a synchronous delivery */
		if (!SE_CLIENT_IS_THR_RUNNING(scp)) {
			(void) mutex_unlock(&scp->client_lock);
			return;
		}

	}
}

/*
 * client_deliver_event - Client specific event delivery
 *			This routine will allocate and initialize the
 *			neccessary per-client dispatch data.
 *
 *			If the eventq is not empty, it may be assumed that
 *			a delivery thread exists for this client and the
 *			dispatch data is appended to the eventq.
 *
 *			The dispatch package is freed by the event completion
 *			thread (event_completion_thr) and the eventq entry
 *			is freed by the event delivery thread.
 */
static struct event_dispatch_pkg *
client_deliver_event(struct sysevent_client *scp, sysevent_t *ev,
	sema_t *completion_sema)
{
	size_t ev_sz = sysevent_get_size(ev);
	struct event_dispatchq *newq, *tmp;
	struct event_dispatch_pkg *d_pkg;

	syseventd_print(3, "client_deliver_event: id 0x%llx size %d\n",
	    (longlong_t)sysevent_get_seq(ev), ev_sz);
	if (debug_level == 9) {
		se_print(stdout, ev);
	}

	/*
	 * Check for suspended client
	 */
	(void) mutex_lock(&scp->client_lock);
	if (SE_CLIENT_IS_SUSPENDED(scp) || !SE_CLIENT_IS_THR_RUNNING(scp)) {
		(void) mutex_unlock(&scp->client_lock);
		return (NULL);
	}

	/*
	 * Allocate a new dispatch package and eventq entry
	 */
	newq = (struct event_dispatchq *)malloc(
	    sizeof (struct event_dispatchq));
	if (newq == NULL) {
		(void) mutex_unlock(&scp->client_lock);
		return (NULL);
	}

	d_pkg = (struct event_dispatch_pkg *)malloc(
	    sizeof (struct event_dispatch_pkg));
	if (d_pkg == NULL) {
		free(newq);
		(void) mutex_unlock(&scp->client_lock);
		return (NULL);
	}

	/* Initialize the dispatch package */
	d_pkg->scp = scp;
	d_pkg->retry_count = 0;
	d_pkg->completion_status = 0;
	d_pkg->completion_state = SE_NOT_DISPATCHED;
	d_pkg->completion_sema = completion_sema;
	d_pkg->ev = ev;
	newq->d_pkg = d_pkg;
	newq->next = NULL;

	if (scp->eventq != NULL) {

		/* Add entry to the end of the eventq */
		tmp = scp->eventq;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = newq;
	} else {
		/* event queue empty, wakeup delivery thread */
		scp->eventq = newq;
		(void) cond_signal(&scp->client_cv);
	}
	(void) mutex_unlock(&scp->client_lock);

	return (d_pkg);
}

/*
 * event_completion_thr - Event completion thread.  This thread routine
 *			waits for all client delivery thread to complete
 *			delivery of a particular event.
 */
static void
event_completion_thr()
{
	int ret, i, client_count, ok_to_free;
	sysevent_id_t eid;
	struct sysevent_client *scp;
	struct ev_completion *ev_comp;
	struct event_dispatchq *dispatchq;
	struct event_dispatch_pkg *d_pkg;

	(void) mutex_lock(&ev_comp_lock);
	for (;;) {
		while (event_compq == NULL) {
			(void) cond_wait(&event_comp_cv, &ev_comp_lock);
		}

		/*
		 * Process event completions from the head of the
		 * completion queue
		 */
		ev_comp = event_compq;
		while (ev_comp) {
			(void) mutex_unlock(&ev_comp_lock);
			eid.eid_seq = sysevent_get_seq(ev_comp->ev);
			sysevent_get_time(ev_comp->ev, &eid.eid_ts);
			client_count = ev_comp->client_count;
			ok_to_free = 1;

			syseventd_print(3, "Wait for event completion of "
			    "event 0X%llx on %d clients\n",
			    eid.eid_seq, client_count);

			while (client_count) {
				syseventd_print(9, "Waiting for %d clients on "
				    "event id 0X%llx\n", client_count,
				    eid.eid_seq);

				(void) sema_wait(&ev_comp->client_sema);
				--client_count;
			}

			syseventd_print(3, "Cleaning up clients for event "
			    "0X%llx\n", eid.eid_seq);
			dispatchq = ev_comp->dispatch_list;
			while (dispatchq != NULL) {
				d_pkg = dispatchq->d_pkg;
				scp = d_pkg->scp;

				if (d_pkg->completion_status == EAGAIN)
					ok_to_free = 0;

				syseventd_print(4, "Delivery of 0X%llx "
				    "complete for client %d retry count %d "
				    "status %d\n", eid.eid_seq,
				    scp->client_num,
				    d_pkg->retry_count,
				    d_pkg->completion_status);

				free(d_pkg);
				ev_comp->dispatch_list = dispatchq->next;
				free(dispatchq);
				dispatchq = ev_comp->dispatch_list;
			}

			if (ok_to_free) {
				for (i = 0; i < MAX_MODCTL_RETRY; ++i) {
					if ((ret = modctl(MODEVENTS,
					    (uintptr_t)MODEVENTS_FREEDATA,
					    (uintptr_t)&eid, NULL,
					    NULL, 0)) != 0) {
						syseventd_print(1, "attempting "
						    "to free event 0X%llx\n",
						    eid.eid_seq);

						/*
						 * Kernel may need time to
						 * move this event buffer to
						 * the sysevent sent queue
						 */
						(void) sleep(1);
					} else {
						break;
					}
				}
				if (ret) {
					syseventd_print(1, "Unable to free "
					    "event 0X%llx from the "
					    "kernel\n", eid.eid_seq);
				}
			} else {
				syseventd_print(1, "Not freeing event 0X%llx\n",
				    eid.eid_seq);
			}

			syseventd_print(2, "Event delivery complete for id "
			    "0X%llx\n", eid.eid_seq);

			(void) mutex_lock(&ev_comp_lock);
			event_compq = ev_comp->next;
			free(ev_comp->ev);
			free(ev_comp);
			ev_comp = event_compq;
			(void) sema_post(&sema_resource);
		}

		/*
		 * Event completion queue is empty, signal possible unload
		 * operation
		 */
		(void) cond_signal(&event_comp_cv);

		syseventd_print(3, "No more events\n");
	}
}

/*
 * dispatch - Dispatch the current event buffer to all valid SLM clients.
 */
static int
dispatch(void)
{
	int ev_sz, i, client_count = 0;
	sysevent_t *new_ev;
	sysevent_id_t eid;
	struct ev_completion *ev_comp, *tmp;
	struct event_dispatchq *dispatchq, *client_list;
	struct event_dispatch_pkg *d_pkg;

	/* Check for module unload operation */
	if (rw_tryrdlock(&mod_unload_lock) != 0) {
		syseventd_print(2, "unload in progress abort delivery\n");
		(void) sema_post(&sema_eventbuf);
		(void) sema_post(&sema_resource);
		return (0);
	}

	syseventd_print(3, "deliver dispatch buffer %d", dispatch_buf);
	eid.eid_seq = sysevent_get_seq(eventbuf[dispatch_buf]);
	sysevent_get_time(eventbuf[dispatch_buf], &eid.eid_ts);
	syseventd_print(3, "deliver msg id: 0x%llx\n", eid.eid_seq);

	/*
	 * ev_comp is used to hold event completion data.  It is freed
	 * by the event completion thread (event_completion_thr).
	 */
	ev_comp = (struct ev_completion *)
	    malloc(sizeof (struct ev_completion));
	if (ev_comp == NULL) {
		(void) rw_unlock(&mod_unload_lock);
		syseventd_print(1, "Can not allocate event completion buffer "
		    "for event id 0X%llx\n", eid.eid_seq);
		return (EAGAIN);
	}
	ev_comp->dispatch_list = NULL;
	ev_comp->next = NULL;
	(void) sema_init(&ev_comp->client_sema, 0, USYNC_THREAD, NULL);

	ev_sz = sysevent_get_size(eventbuf[dispatch_buf]);
	new_ev = calloc(1, ev_sz);
	if (new_ev == NULL) {
		free(ev_comp);
		(void) rw_unlock(&mod_unload_lock);
		syseventd_print(1, "Can not allocate new event buffer "
		"for event id 0X%llx\n", eid.eid_seq);
		return (EAGAIN);
	}


	/*
	 * For long messages, copy additional data from kernel
	 */
	if (ev_sz > LOGEVENT_BUFSIZE) {
		int ret = 0;

		/* Ok to release eventbuf for next event buffer from kernel */
		(void) sema_post(&sema_eventbuf);

		for (i = 0; i < MAX_MODCTL_RETRY; ++i) {
			if ((ret = modctl(MODEVENTS,
			    (uintptr_t)MODEVENTS_GETDATA,
			    (uintptr_t)&eid,
			    (uintptr_t)ev_sz,
			    (uintptr_t)new_ev, 0))
			    == 0)
				break;
			else
				(void) sleep(1);
		}
		if (ret) {
			syseventd_print(1, "GET_DATA failed for 0X%llx:%llx\n",
			    eid.eid_ts, eid.eid_seq);
			free(new_ev);
			free(ev_comp);
			(void) rw_unlock(&mod_unload_lock);
			return (EAGAIN);
		}
	} else {
		(void) bcopy(eventbuf[dispatch_buf], new_ev, ev_sz);
		/* Ok to release eventbuf for next event buffer from kernel */
		(void) sema_post(&sema_eventbuf);
	}


	/*
	 * Deliver a copy of eventbuf to clients so
	 * eventbuf can be used for the next message
	 */
	for (i = 0; i < MAX_SLM; ++i) {

		/* Don't bother for suspended or unloaded clients */
		if (!SE_CLIENT_IS_LOADED(sysevent_client_tbl[i]) ||
		    SE_CLIENT_IS_SUSPENDED(sysevent_client_tbl[i]))
			continue;

		/*
		 * Allocate event dispatch queue entry.  All queue entries
		 * are freed by the event completion thread as client
		 * delivery completes.
		 */
		dispatchq = (struct event_dispatchq *)malloc(
		    sizeof (struct event_dispatchq));
		if (dispatchq == NULL) {
			syseventd_print(1, "Can not allocate dispatch q "
			"for event id 0X%llx client %d\n", eid.eid_seq, i);
			continue;
		}
		dispatchq->next = NULL;

		/* Initiate client delivery */
		d_pkg = client_deliver_event(sysevent_client_tbl[i],
		    new_ev, &ev_comp->client_sema);
		if (d_pkg == NULL) {
			syseventd_print(1, "Can not allocate dispatch "
			    "package for event id 0X%llx client %d\n",
			    eid.eid_seq, i);
			free(dispatchq);
			continue;
		}
		dispatchq->d_pkg = d_pkg;
		++client_count;

		if (ev_comp->dispatch_list == NULL) {
			ev_comp->dispatch_list = dispatchq;
			client_list = dispatchq;
		} else {
			client_list->next = dispatchq;
			client_list = client_list->next;
		}
	}

	ev_comp->client_count = client_count;
	ev_comp->ev = new_ev;

	(void) mutex_lock(&ev_comp_lock);

	if (event_compq == NULL) {
		syseventd_print(3, "Wakeup event completion thread for "
		    "id 0X%llx\n", eid.eid_seq);
		event_compq = ev_comp;
		(void) cond_signal(&event_comp_cv);
	} else {

		/* Add entry to the end of the event completion queue */
		tmp = event_compq;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = ev_comp;
		syseventd_print(3, "event added to completion queue for "
		    "id 0X%llx\n", eid.eid_seq);
	}
	(void) mutex_unlock(&ev_comp_lock);
	(void) rw_unlock(&mod_unload_lock);

	return (0);
}

#define	MODULE_DIR_HW	"/usr/platform/%s/lib/sysevent/modules/"
#define	MODULE_DIR_GEN	"/usr/lib/sysevent/modules/"
#define	MOD_DIR_NUM	3
static char dirname[MOD_DIR_NUM][MAXPATHLEN];

static char *
dir_num2name(int dirnum)
{
	char infobuf[MAXPATHLEN];

	if (dirnum >= MOD_DIR_NUM)
		return (NULL);

	if (dirname[0][0] == '\0') {
		if (sysinfo(SI_PLATFORM, infobuf, MAXPATHLEN) == -1) {
			syseventd_print(1, "dir_num2name: "
			    "sysinfo error %s\n", strerror(errno));
			return (NULL);
		} else if (snprintf(dirname[0], sizeof (dirname[0]),
		    MODULE_DIR_HW, infobuf) >= sizeof (dirname[0])) {
			syseventd_print(1, "dir_num2name: "
			    "platform name too long: %s\n",
			    infobuf);
			return (NULL);
		}
		if (sysinfo(SI_MACHINE, infobuf, MAXPATHLEN) == -1) {
			syseventd_print(1, "dir_num2name: "
			    "sysinfo error %s\n", strerror(errno));
			return (NULL);
		} else if (snprintf(dirname[1], sizeof (dirname[1]),
		    MODULE_DIR_HW, infobuf) >= sizeof (dirname[1])) {
			syseventd_print(1, "dir_num2name: "
			    "machine name too long: %s\n",
			    infobuf);
			return (NULL);
		}
		(void) strcpy(dirname[2], MODULE_DIR_GEN);
	}

	return (dirname[dirnum]);
}


/*
 * load_modules - Load modules found in the common syseventd module directories
 *		Modules that do not provide valid interfaces are rejected.
 */
static void
load_modules(char *dirname)
{
	int client_id;
	DIR *mod_dir;
	module_t *mod;
	struct dirent *entp;
	struct slm_mod_ops *mod_ops;
	struct sysevent_client *scp;

	if (dirname == NULL)
		return;

	/* Return silently if module directory does not exist */
	if ((mod_dir = opendir(dirname)) == NULL) {
		syseventd_print(1, "Unable to open module directory %s: %s\n",
		    dirname, strerror(errno));
		return;
	}

	syseventd_print(3, "loading modules from %s\n", dirname);

	/*
	 * Go through directory, looking for files ending with .so
	 */
	while ((entp = readdir(mod_dir)) != NULL) {
		void *dlh, *f;
		char *tmp, modpath[MAXPATHLEN];

		if (((tmp = strstr(entp->d_name, MODULE_SUFFIX)) == NULL) ||
		    (tmp[strlen(MODULE_SUFFIX)] != '\0')) {
			continue;
		}

		if (snprintf(modpath, sizeof (modpath), "%s%s",
		    dirname, entp->d_name) >= sizeof (modpath)) {
			syseventd_err_print(INIT_PATH_ERR, modpath);
			continue;
		}
		if ((dlh = dlopen(modpath, RTLD_LAZY)) == NULL) {
			syseventd_err_print(LOAD_MOD_DLOPEN_ERR,
			    modpath, dlerror());
			continue;
		} else if ((f = dlsym(dlh, EVENT_INIT)) == NULL) {
			syseventd_err_print(LOAD_MOD_NO_INIT,
			    modpath, dlerror());
			(void) dlclose(dlh);
			continue;
		}

		mod = malloc(sizeof (*mod));
		if (mod == NULL) {
			syseventd_err_print(LOAD_MOD_ALLOC_ERR, "mod",
			    strerror(errno));
			(void) dlclose(dlh);
			continue;
		}

		mod->name = strdup(entp->d_name);
		if (mod->name == NULL) {
			syseventd_err_print(LOAD_MOD_ALLOC_ERR, "mod->name",
			    strerror(errno));
			(void) dlclose(dlh);
			free(mod);
			continue;
		}

		mod->dlhandle = dlh;
		mod->event_mod_init = (struct slm_mod_ops *(*)())f;

		/* load in other module functions */
		mod->event_mod_fini = (void (*)())dlsym(dlh, EVENT_FINI);
		if (mod->event_mod_fini == NULL) {
			syseventd_err_print(LOAD_MOD_DLSYM_ERR, mod->name,
			    dlerror());
			free(mod->name);
			free(mod);
			(void) dlclose(dlh);
			continue;
		}

		/* Call module init routine */
		if ((mod_ops = mod->event_mod_init()) == NULL) {
			syseventd_err_print(LOAD_MOD_EINVAL, mod->name);
			free(mod->name);
			free(mod);
			(void) dlclose(dlh);
			continue;
		}
		if (mod_ops->major_version != SE_MAJOR_VERSION) {
			syseventd_err_print(LOAD_MOD_VERSION_MISMATCH,
			    mod->name, SE_MAJOR_VERSION,
			    mod_ops->major_version);
			mod->event_mod_fini();
			free(mod->name);
			free(mod);
			(void) dlclose(dlh);
			continue;
		}

		mod->deliver_event = mod_ops->deliver_event;
		/* Add module entry to client list */
		if ((client_id = insert_client((void *)mod, SLM_CLIENT,
		    (mod_ops->retry_limit <= SE_MAX_RETRY_LIMIT ?
		    mod_ops->retry_limit : SE_MAX_RETRY_LIMIT))) < 0) {
			syseventd_err_print(LOAD_MOD_ALLOC_ERR, "insert_client",
			    strerror(errno));
			mod->event_mod_fini();
			free(mod->name);
			free(mod);
			(void) dlclose(dlh);
			continue;
		}

		scp = sysevent_client_tbl[client_id];
		++concurrency_level;
		(void) thr_setconcurrency(concurrency_level);
		if (thr_create(NULL, 0,
		    (void *(*)(void *))client_deliver_event_thr,
		    (void *)scp, THR_BOUND, &scp->tid) != 0) {

			syseventd_err_print(LOAD_MOD_ALLOC_ERR, "insert_client",
			    strerror(errno));
			mod->event_mod_fini();
			free(mod->name);
			free(mod);
			(void) dlclose(dlh);
			continue;
		}
		scp->client_flags |= SE_CLIENT_THR_RUNNING;

		syseventd_print(3, "loaded module %s\n", entp->d_name);
	}

	(void) closedir(mod_dir);
	syseventd_print(3, "modules loaded\n");
}

/*
 * unload_modules - modules are unloaded prior to graceful shutdown or
 *			before restarting the daemon upon receipt of
 *			SIGHUP.
 */
static void
unload_modules(int sig)
{
	int			i, count, done;
	module_t		*mod;
	struct sysevent_client	*scp;

	/*
	 * unload modules that are ready, skip those that have not
	 * drained their event queues.
	 */
	count = done = 0;
	while (done < MAX_SLM) {
		/* Don't wait indefinitely for unresponsive clients */
		if (sig != SIGHUP && count > SE_TIMEOUT) {
			break;
		}

		done = 0;

		/* Shutdown clients */
		for (i = 0; i < MAX_SLM; ++i) {
			scp = sysevent_client_tbl[i];
			if (mutex_trylock(&scp->client_lock) == 0) {
				if (scp->client_type != SLM_CLIENT ||
				    scp->client_data == NULL) {
					(void) mutex_unlock(&scp->client_lock);
					done++;
					continue;
				}
			} else {
				syseventd_print(3, "Skipping unload of "
				    "client %d: client locked\n",
				    scp->client_num);
				continue;
			}

			/*
			 * Drain the eventq and wait for delivery thread to
			 * cleanly exit
			 */
			drain_eventq(scp, EAGAIN);
			(void) cond_signal(&scp->client_cv);
			(void) mutex_unlock(&scp->client_lock);
			(void) thr_join(scp->tid, NULL, NULL);

			/*
			 * It is now safe to unload the module
			 */
			mod = (module_t *)scp->client_data;
			syseventd_print(2, "Unload %s\n", mod->name);
			mod->event_mod_fini();
			(void) dlclose(mod->dlhandle);
			free(mod->name);
			(void) mutex_lock(&client_tbl_lock);
			delete_client(i);
			(void) mutex_unlock(&client_tbl_lock);
			++done;

		}
		++count;
		(void) sleep(1);
	}

	/*
	 * Wait for event completions
	 */
	syseventd_print(2, "waiting for event completions\n");
	(void) mutex_lock(&ev_comp_lock);
	while (event_compq != NULL) {
		(void) cond_wait(&event_comp_cv, &ev_comp_lock);
	}
	(void) mutex_unlock(&ev_comp_lock);
}

/*
 * syseventd_init - Called at daemon (re)start-up time to load modules
 *			and kickstart the kernel delivery engine.
 */
static void
syseventd_init()
{
	int i, fd;
	char local_door_file[PATH_MAX + 1];

	fini_pending = 0;

	concurrency_level = MIN_CONCURRENCY_LEVEL;
	(void) thr_setconcurrency(concurrency_level);

	/*
	 * Load client modules for event delivering
	 */
	for (i = 0; i < MOD_DIR_NUM; ++i) {
		load_modules(dir_num2name(i));
	}

	/*
	 * Create kernel delivery door service
	 */
	syseventd_print(8, "Create a door for kernel upcalls\n");
	if (snprintf(local_door_file, sizeof (local_door_file), "%s%s",
	    root_dir, LOGEVENT_DOOR_UPCALL) >= sizeof (local_door_file)) {
		syseventd_err_print(INIT_PATH_ERR, local_door_file);
		syseventd_exit(5);
	}

	/*
	 * Remove door file for robustness.
	 */
	if (unlink(local_door_file) != 0)
		syseventd_print(8, "Unlink of %s failed.\n", local_door_file);

	fd = open(local_door_file, O_CREAT|O_RDWR, S_IREAD|S_IWRITE);
	if ((fd == -1) && (errno != EEXIST)) {
		syseventd_err_print(INIT_OPEN_DOOR_ERR, strerror(errno));
		syseventd_exit(5);
	}
	(void) close(fd);

	upcall_door = door_create(door_upcall, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (upcall_door == -1) {
		syseventd_err_print(INIT_CREATE_DOOR_ERR, strerror(errno));
		syseventd_exit(5);
	}

	(void) fdetach(local_door_file);
retry:
	if (fattach(upcall_door, local_door_file) != 0) {
		if (errno == EBUSY)
			goto retry;
		syseventd_err_print(INIT_FATTACH_ERR, strerror(errno));
		(void) door_revoke(upcall_door);
		syseventd_exit(5);
	}

	/*
	 * Tell kernel the door name and start delivery
	 */
	syseventd_print(2,
	    "local_door_file = %s\n", local_door_file);
	if (modctl(MODEVENTS,
	    (uintptr_t)MODEVENTS_SET_DOOR_UPCALL_FILENAME,
	    (uintptr_t)local_door_file, NULL, NULL, 0) < 0) {
		syseventd_err_print(INIT_DOOR_NAME_ERR, strerror(errno));
		syseventd_exit(6);
	}

	door_upcall_retval = 0;

	if (modctl(MODEVENTS, (uintptr_t)MODEVENTS_FLUSH, NULL, NULL, NULL, 0)
	    < 0) {
		syseventd_err_print(KERNEL_REPLAY_ERR, strerror(errno));
		syseventd_exit(7);
	}
}

/*
 * syseventd_fini - shut down daemon, but do not exit
 */
static void
syseventd_fini(int sig)
{
	/*
	 * Indicate that event queues should be drained and no
	 * additional events be accepted
	 */
	fini_pending = 1;

	/* Close the kernel event door to halt delivery */
	(void) door_revoke(upcall_door);

	syseventd_print(1, "Unloading modules\n");
	(void) rw_wrlock(&mod_unload_lock);
	unload_modules(sig);
	(void) rw_unlock(&mod_unload_lock);

}

/*
 * enter_daemon_lock - lock the daemon file lock
 *
 * Use an advisory lock to ensure that only one daemon process is active
 * in the system at any point in time.	If the lock is held by another
 * process, do not block but return the pid owner of the lock to the
 * caller immediately.	The lock is cleared if the holding daemon process
 * exits for any reason even if the lock file remains, so the daemon can
 * be restarted if necessary.  The lock file is DAEMON_LOCK_FILE.
 */
static pid_t
enter_daemon_lock(void)
{
	struct flock	lock;

	syseventd_print(8, "enter_daemon_lock: lock file = %s\n",
	    DAEMON_LOCK_FILE);

	if (snprintf(local_lock_file, sizeof (local_lock_file), "%s%s",
	    root_dir, DAEMON_LOCK_FILE) >= sizeof (local_lock_file)) {
		syseventd_err_print(INIT_PATH_ERR, local_lock_file);
		syseventd_exit(8);
	}
	daemon_lock_fd = open(local_lock_file, O_CREAT|O_RDWR, 0644);
	if (daemon_lock_fd < 0) {
		syseventd_err_print(INIT_LOCK_OPEN_ERR,
		    local_lock_file, strerror(errno));
		syseventd_exit(8);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {
		if (fcntl(daemon_lock_fd, F_GETLK, &lock) == -1) {
			syseventd_err_print(INIT_LOCK_ERR,
			    local_lock_file, strerror(errno));
			exit(2);
		}
		return (lock.l_pid);
	}
	hold_daemon_lock = 1;

	return (getpid());
}

/*
 * exit_daemon_lock - release the daemon file lock
 */
static void
exit_daemon_lock(void)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(daemon_lock_fd, F_SETLK, &lock) == -1) {
		syseventd_err_print(INIT_UNLOCK_ERR,
		    local_lock_file, strerror(errno));
	}

	if (close(daemon_lock_fd) == -1) {
		syseventd_err_print(INIT_LOCK_CLOSE_ERR,
		    local_lock_file, strerror(errno));
		exit(-1);
	}
}

/*
 * syseventd_err_print - print error messages to the terminal if not
 *			yet daemonized or to syslog.
 */
/*PRINTFLIKE1*/
void
syseventd_err_print(char *message, ...)
{
	va_list ap;

	(void) mutex_lock(&err_mutex);
	va_start(ap, message);

	if (logflag) {
		(void) vsyslog(LOG_ERR, message, ap);
	} else {
		(void) fprintf(stderr, "%s: ", prog);
		(void) vfprintf(stderr, message, ap);
	}
	va_end(ap);
	(void) mutex_unlock(&err_mutex);
}

/*
 * syseventd_print -  print messages to the terminal or to syslog
 *			the following levels are implemented:
 *
 * 1 - transient errors that does not affect normal program flow
 * 2 - upcall/dispatch interaction
 * 3 - program flow trace as each message goes through the daemon
 * 8 - all the nit-gritty details of startup and shutdown
 * 9 - very verbose event flow tracing (no daemonization of syseventd)
 *
 */
/*PRINTFLIKE2*/
void
syseventd_print(int level, char *message, ...)
{
	va_list ap;
	static int newline = 1;

	if (level > debug_level) {
		return;
	}

	(void) mutex_lock(&err_mutex);
	va_start(ap, message);
	if (logflag) {
		(void) syslog(LOG_DEBUG, "%s[%ld]: ",
		    prog, getpid());
		(void) vsyslog(LOG_DEBUG, message, ap);
	} else {
		if (newline) {
			(void) fprintf(stdout, "%s[%ld]: ",
			    prog, getpid());
			(void) vfprintf(stdout, message, ap);
		} else {
			(void) vfprintf(stdout, message, ap);
		}
	}
	if (message[strlen(message)-1] == '\n') {
		newline = 1;
	} else {
		newline = 0;
	}
	va_end(ap);
	(void) mutex_unlock(&err_mutex);
}
