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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <sys/time.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include "rdimpl.h"
#include "rdprot.h"
#include "rdutil.h"
#include "rdlist.h"
#include "rdfile.h"

#define	RDS_VERSION		"RDS Version 1.0\n"
#define	TIMEOUT_MSG		"Timeout"
#define	NOTREADY_RESPONSE	"BUSY"

#define	DEFAULT_SCAN_INTERVAL	1000   /* milliseconds */
#define	MAXIMAL_SCAN_INTERVAL	30000  /* milliseconds */
#define	DEFAULT_CMD_TIMEOUT	2000   /* milliseconds */

extern list_t	users;		/* list of users */
extern list_t	projects;	/* list of projects */
extern list_t	sys;		/* list with one sys entry */
extern list_t	processes;	/* list of processes */
extern list_t	lwps;		/* list of lwps */
extern char	errmsg[];	/* global message buffer */

static char	greeting[] =		\
	"Resource Data Server\n"	\
	"Copyright 2001 SMI.\n"		\
	"Version 1.0\n";

/* ms timeout between successive cmds */
static int	timeout = DEFAULT_CMD_TIMEOUT;

/* ms interval between successive scans */
static int	interval = DEFAULT_SCAN_INTERVAL;

/* global signal flag */
static int	sigterm = 0;

/* print all cmd data on stdout in server mode flag */
static int	Po = 0;

/* count of scans performed in server mode */
static long	scans_done = 0;

/* name of rds logging file */
static char		*log_file = NULL;

/* enable microstate accounting flag */
int		mo = 0;

/* name of stored data file */
char		*ltdb_file = NULL;


/* mutex lock for data lists */
pthread_mutex_t listLock = PTHREAD_MUTEX_INITIALIZER;

/* mutex lock for log */
pthread_mutex_t logLock = PTHREAD_MUTEX_INITIALIZER;

/* identifiers for the various threads */
static pthread_t scanner = 0;
static pthread_t server = 0;
static pthread_t master = 0;


/*
 * Clean up calling thread's state.
 */
static void
thread_cleanup()
{
	pthread_t this = pthread_self();

	if (pthread_equal(this, server)) {

		/* shut down the command protocol */
		(void) fprintf(stderr,
			"cleanup_state: server thread shutdown\n");
		log_msg("server thread shutdown init\n");
		wr_error(errmsg);
		log_msg("server thread shutdown complete\n");

	} else if (pthread_equal(this, scanner)) {

		/* shut down the scanner */
		(void) fprintf(stderr,
			"cleanup_state: scanner thread shutdown\n");
		log_msg("scanner thread shutdown init\n");

		log_msg("Waiting for server thread %d join from %d\n",
		    (int)server, (int)this);

		if (pthread_join(server, NULL) != 0) {
			int e = errno;

			perror("server join (cleanup)");
			log_msg("server join (cleanup) failed with %d\n", e);
		}

		log_msg("Server thread joined %d.\n", (int)this);

		monitor_stop();
		log_msg("scanner thread shutdown complete\n");

	} else if (pthread_equal(this, master)) {

		(void) fprintf(stderr,
			"cleanup_state: master thread shutdown\n");
		log_msg("master thread shutdown\n");

	} else {

		(void) fprintf(stderr,
		    "cleanup_state: unknown thread id %d\n", (int)this);
		log_msg("unknown thread %d shutdown\n", (int)this);

	}
}


/*
 * Called by any of the threads, this should set state
 * that the other threads will pick up so they will (eventually)
 * shut themselves down cleanly, then call pthread_exit
 * to properly shut down the calling thread.
 * The calling thread will exit with its code set to 1.
 */
static void
generic_exit(char *msg, int status)
{
	char wb[256];

	/* cannot be on the stack since thread terminates with pthread_exit */
	static int retcode = 0;

	retcode = status;

	/* worker-specific cleanup */
	thread_cleanup();

	/* announce the calling thread's demise */
	(void) snprintf(wb, sizeof (wb) - 2, "(%d) %s",
			(int)pthread_self(), msg);
	log_msg(wb);
	(void) fprintf(stderr, "%s", wb);

	/* everybody checks this periodically */
	sigterm = 1;

	log_msg("calling thread_exit() from %d\n", (int)pthread_self());

	/* return status as the calling thread's exit code */
	pthread_exit(&retcode);

}


/*
 * Called by any of the threads, this should set state
 * that the other threads will pick up so they will (eventually)
 * shut themselves down cleanly, then call pthread_exit
 * to properly shut down the calling thread.
 * The calling thread will exit with its code set to 1.
 */
void
err_exit()
{
	generic_exit(errmsg, 1);
}


/*
 * Called by any of the threads, this should set state
 * that the other threads will pick up so they will (eventually)
 * shut themselves down cleanly, then call pthread_exit
 * to properly shut down the calling thread.
 * The calling thread will exit with its code set to 0.
 */
static void
ok_exit()
{
	generic_exit("Normal exit.\n", 0);
}


static void
usage()
{
	(void) printf("rds [ options ]\n" \
	    "-u\t\t- print stats for all users\n" \
	    "-U<uid>\t\t- print stats for <uid>\n" \
	    "-j\t\t- print stats for all projects\n" \
	    "-J<projid>\t- print stats for <projid>\n" \
	    "-p\t\t- print stats for all processes\n" \
	    "-P <pid>\t- print stats for <pid>\n" \
	    "-m\t\t- enable microstate accounting\n" \
	    "-a\t\t- run in server mode\n" \
	    "-t<time>\t- set command timeout to <time>\n" \
	    "-i<interval>\t- set interval between scans to <time>\n" \
	    "-f<file>\t- use <file> to save/restore state\n" \
	    "-d\t\t- in server mode print stats on stdout\n" \
	    "-L<file>|stderr - write log messages into <file> or stderr\n" \
	    "-v\t\t- print rds version\n");
}


/*
 * Initiate the rds command protocol from the server side.
 * Emits the header and version strings.
 */
static void
start_protocol()
{
	/* emit version and header strings */
	if (wr_string(greeting) != 0)
		err_exit();
	if (wr_phead() != 0)
		err_exit();
}


/*
 * Emit the "not ready" message and a prompt.
 */
static void
notready()
{
	(void) wr_string(NOTREADY_RESPONSE);
	(void) wr_string("\n");
	(void) wr_prompt(PROMPT_OK);
}


/*
 * process_cmds() implements the rds server running in threaded mode.
 *
 * It assumes that the /proc scanner is running in another thread and
 * guarding access to critical sections.
 *
 * This function writes version and header to the output stream and waits
 * for commands on the input stream.
 *
 * Each received command may block on a mutex while the scanner thread is
 * updating.
 *
 * If the timeout expires without receiving a command, it will write an
 * error message and terminate.	 A received command resets the timeout.
 *
 * Each command is acknowledged with a prompt.
 */

/*ARGSUSED*/
static void *
process_cmds(void *p)
{
	fd_set	readfs;
	struct	timeval timev;
	int	interval_cnt = timeout / interval;
	int	ret;
	char	*cmd;
	hrtime_t t1, t2, wt1, wt2;
	double	d;
	int 	cmd_is_noop;

	/* start the protocol so the client knows we're alive */
	start_protocol();

	/* establish timeout value */
	timev.tv_sec = interval / 1000;
	timev.tv_usec = (interval - (timev.tv_sec * 1000)) * 1000;

	/* initialize stdin object */
	(void) FD_ZERO(&readfs);
	FD_SET(STDIN_FILENO, &readfs);

	/* emit initial prompt */
	(void) wr_prompt(PROMPT_OK);

	while (interval_cnt > 0) {

		/* time to shut down, exit gracefully */
		if (sigterm == 1) {
			break;		/* ok_exit(); */
		}

		/* check for stdin status */
		FD_SET(STDIN_FILENO, &readfs);

		/* block on stdin, max timeout */
		if ((ret = select(1, &readfs, NULL, NULL, &timev)) == 0) {

			/* timed out waiting for a command */
			--interval_cnt;
			continue;
		}

		/* if interrupted system call then exit gracefully */
		if (ret == -1 && errno == EINTR) {
			log_msg("select() interrupted\n");
			ok_exit();
		}

		/* weird error condition */
		if (ret != 1) {
			perror("RDS Select error");
			log_msg("select() error = %d\n", errno);
			continue;
		}

		/* process whatever is waiting on stdin */
		if (FD_ISSET(STDIN_FILENO, &readfs)) {

			cmd_is_noop = 0;

			/* try to parse out a valid command */
			if ((cmd = r_cmd()) == NULL) {
				err_exit();
			}
			log_msg("received '%s' command\n", cmd);
			t1 = gethrtime();

			/* handle the various commands */
			if (strcmp(cmd, CMD_EXIT) == 0) {

				/* exit now */
				(void) wr_prompt(PROMPT_OK);
				ok_exit();

			} else if (strcmp(cmd, CRETURN) == 0) {

				/* null command */
				(void) wr_prompt(PROMPT_OK);
				++cmd_is_noop;

			} else if (strcmp(cmd, CMD_ALIVE) == 0) {

				/* keepalive, another null command */
				(void) wr_prompt(PROMPT_OK);
				++cmd_is_noop;

			} else if (strcmp(cmd, CMD_GETALL) == 0) {

				/* get all project/user data */

				/*
				 * If the first scan has not yet
				 * completed, notify the requester and
				 * wait for a new command.  The
				 * command timeout counter is
				 * suspended until the next command
				 * arrives.
				 */
				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				wt1 = gethrtime();

				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					wt2 = gethrtime();
					d = (double)
					    (wt2 - wt1) / 1000000000.0;
					log_msg("Server lock wait"
					    " was %1.5f sec\n", d);

					if (wr_lshead(5) != 0)
						err_exit();

					if (list_write(L_AC_USR, Po) == -1)
						break;
					if (list_write(L_USR_SI, Po) == -1)
						break;
					if (list_write(L_AC_PRJ, Po) == -1)
						break;
					if (list_write(L_PRJ_SI, Po) == -1)
						break;
					if (list_write(L_SYSTEM, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock" \
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock failed" \
					    "with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else if (strcmp(cmd, CMD_GETPL) == 0) {

				/* get all process data (deprecated?) */

				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					if (wr_lshead(1) != 0)
						err_exit();

					if (list_write(L_PRC_SI, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock"\
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock"\
					    "failed with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else if (strcmp(cmd, CMD_GETUL) == 0) {

				/* get the active user list */

				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					if (wr_lshead(1) != 0)
						err_exit();


					if (list_write(L_USR_SI, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock"\
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock" \
					    "failed with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else if (strcmp(cmd, CMD_GETAUL) == 0) {

				/* get data for a particular user */

				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					if (wr_lshead(1) != 0)
						err_exit();

					if (list_write(L_AC_USR, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock" \
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock" \
					    "failed with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else if (strcmp(cmd, CMD_GETJL) == 0) {

				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					if (wr_lshead(1) != 0)
						err_exit();

					/* grab the mutex here */

					if (list_write(L_PRJ_SI, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock" \
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock" \
					    "failed with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else if (strcmp(cmd, CMD_GETAJL) == 0) {

				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					if (wr_lshead(1) != 0)
						err_exit();

					if (list_write(L_AC_PRJ, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock" \
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock" \
					    "failed with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else if (strcmp(cmd, CMD_GETASL) == 0) {

				if (scans_done == 0) {
					notready();
					continue;
				}

				/* grab the mutex */
				if ((ret = pthread_mutex_lock(
					&listLock)) == 0) {

					if (wr_lshead(1) != 0)
						err_exit();

					if (list_write(L_SYSTEM, Po) == -1)
						break;

					/* release the mutex */
					if ((ret = pthread_mutex_unlock(
						&listLock)) != 0) {
						log_msg("pthread_mutex_unlock"
						    "failed with %d\n", ret);
					}

				} else {
					log_msg("pthread_mutex_lock"
					    "failed with %d\n", ret);
				}

				(void) wr_prompt(PROMPT_OK);

			} else {

				/* bad command */
				(void) wr_prompt(PROMPT_WHAT);
				format_err("RDS protocol error:"
				    "unknown command");
				++cmd_is_noop;

			}

			if (!cmd_is_noop) {
				t2 = gethrtime();
				d = (double)(t2 - t1) / 1000000000.0;
				log_msg("Command took %2.3f sec"
				    " (%ld scans done)\n",
				    d, scans_done);
			}

			/* reset the interval counter for timeout */
			interval_cnt = timeout / interval;

			continue;
		}

		/* timed out, one less interval to wait */
		--interval_cnt;
	}

	/* timed out, print message */
	if (interval_cnt == 0) {
		format_err("%s %d sec. left", TIMEOUT_MSG, timeout / 1000);
		err_exit();
	}

	/* clean exit */
	log_msg("process_cmds exits\n");
	ok_exit();			/* calls pthread_exit() */

	return (NULL);
}


/*
 * The thread procedure for the /proc scanner.
 * Does a full scan of /proc, then sleeps for a specified time.
 *
 * The specified time ('interval') is adjusted according to
 * the average of the last three scan times.
 * The sleep time is increase if the average scan duration time
 * exceeds a threshold. The threshold is set to 50% of the current
 * sleep time.
 * The sleep time is decreased in a similar way.
 *
 * The update of the project and user lists is guarded by aggregate_list_mutex.
 * The update of the process list is guarded by process_list_mutex.
 */

/*ARGSUSED*/
static void *
scanprocfs(void *p)
{
	hrtime_t t1;

	double d0; /* duration of the for last scan */
	double d1; /* duration of the last scan */
	double d2; /* duration of current scan */
	double ad; /* average duration of the last three scans */
	double threshold_up; /* threshold for increasing scan duration */
	double threshold_down; /* threshold for decreasing scan duration */
	double thf =  0.5; /* */
	int new_interval = interval;
	int time_to_sleep;

	threshold_up = new_interval * thf;
	threshold_down = 0;
	d0 = d1 = d2 = ad = 0;


	while (sigterm != 1) {
		t1 = gethrtime();

		if (monitor_update() != 0)
			err_exit();

		++scans_done;

		/* make sure we're sleeping a reasonable amount of time */
		d0 = d1; d1 = d2;
		d2 = (gethrtime() - t1) / 1000000.0;
		ad = (d0 + d1 + d2) / 3.0;

		if (threshold_up < ad) {
			/* increase the new_interval in 1000 ms steps	*/
			new_interval += (int)((ad - threshold_up) / thf);
			if (new_interval > MAXIMAL_SCAN_INTERVAL)
				new_interval = MAXIMAL_SCAN_INTERVAL;
			if ((new_interval % 1000) > 500)
				new_interval += 500;
			new_interval = (new_interval / 1000) * 1000;
			/* pull up the thresholds */
			threshold_down = threshold_up;
			threshold_up = new_interval * thf;
		}

		if (threshold_down > ad) {
			/* decrease the new_interval in 1000 ms steps	*/
			new_interval -= (int)((threshold_down - ad) / thf);
			if ((new_interval % 1000) > 500)
				new_interval += 500;
			new_interval = (new_interval / 1000) * 1000;
			/* pull down the thresholds */
			if (new_interval < interval) {
				/* just as at the beginning	*/
				new_interval = interval;
				threshold_down = 0;
				threshold_up = new_interval * thf;
			} else {
				threshold_up = threshold_down;
				threshold_down = new_interval * thf;
			}
		}

		log_msg("scan %.0f ms, ad %.0f ms, thold_up %.0f ms,"
		    " thold_down %.0f ms, interval %d ms\n",
		    d2, ad, threshold_up, threshold_down, new_interval);
		log_msg("%d files open\n", fd_count());

		time_to_sleep = new_interval;
		while (time_to_sleep > 0) {
			napms(1000);
			time_to_sleep -= 1000;
			if (sigterm == 1)
				break;
		}
	}

	log_msg("scanprocfs exits\n");
	ok_exit();

	return (NULL);
}

static void
sig_rds(int sig)
{
	log_msg("caught signal #%d\n", sig);
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		sigterm = 1;
		break;
	}
}


/*
 * Run the command processor, with the /proc scanner and rds command processor
 * in separate threads.
 *
 * Initializes the mutex as a side effect.
 *
 * Returns on exit of the command process or as a result of a signal.
 */
static void
runserver()
{
	int rv;

	/* keep track of main()'s thread */
	master = pthread_self();
	log_msg("master thread = %d\n", (int)master);

	/* initialize the mutexes for later use */
	rv = pthread_mutex_init(&listLock, NULL);
	if (rv != 0) {
		(void) sprintf(errmsg, "Mutex init failed with %d", rv);
		err_exit();
	}

	rv = pthread_mutex_init(&listLock, NULL);
	if (rv != 0) {
		(void) sprintf(errmsg, "Mutex init failed with %d", rv);
		err_exit();
	}

	log_msg("pthread_mutex_init returns %d\n", rv);

	/* launch the command processor in its thread */
	rv = pthread_create(&server, NULL, process_cmds, NULL);
	if (rv != 0) {
		(void) sprintf(errmsg,
		    "Server thread create failed with %d", rv);
		err_exit();

	}
	log_msg("Server pthread_create = %d returns %d\n",
	    (int)server, rv);


	/* launch the scanner in its thread */
	rv = pthread_create(&scanner, NULL, scanprocfs, NULL);
	if (rv != 0) {
		(void) sprintf(errmsg,
		    "Scanner thread create failed with %d", rv);
		err_exit();
	}
	log_msg("Scanner pthread_create = %d returns %d\n",
	    (int)scanner, rv);


	/* nothing much else to do here */
	while (sigterm != 1)
		(void) sleep(1);

	/* wait for the scanner & server threads to shut down */
	log_msg("Waiting for scanner thread %d join from %d\n",
	    (int)scanner, (int)pthread_self());
	if (pthread_join(scanner, NULL) != 0) {
		int e = errno;
		perror("scanner join");
		log_msg("scanner join failed with %d\n", e);
	}
	log_msg("Scanner thread joined.\n");

	/* finish cleaning up global state */
	(void) pthread_mutex_destroy(&listLock);

	log_msg("Global cleanup completed.\n");
}


int
main(int argc, char *argv[])
{
	int i,	uo = 0, jo = 0, po = 0, do_server_mode = 0,
	    selected = 0;
	int	lo_arg = 1;
	int	uid = -1, pid = -1, jid = -1;
	int	rv;

	/* parse args */
	while ((i = getopt(argc, argv, "uU:jJ:pP:mat:i:l:f:dvL:")) != EOF)
		switch (i) {
		case 'U':
			uid = atoi(optarg);
			uo = 1; selected = 1;
			break;
		case 'u':
			uo = 1; selected = 1;
			break;
		case 'J':
			jid = atoi(optarg);
			jo = 1; selected = 1;
			break;
		case 'j':
			jo = 1; selected = 1;
			break;
		case 'P':
			pid = atoi(optarg);
			po = 1; selected = 1;
			break;
		case 'p':
			po = 1; selected = 1;
			break;
		case 'a':
			do_server_mode = 1;
			break;
		case 'l':
			if ((lo_arg = atoi(optarg)) == 0) {
				usage();
				exit(1);
			}
			break;
		case 'd':
			Po = 1;
			break;
		case 't':
			if ((timeout  = atoi(optarg)) < 1000) {
				usage();
				exit(1);
			}
			break;
		case 'i':
			if ((interval  = atoi(optarg)) < 100) {
				usage();
				exit(1);
			}
			break;
		case 'f':
			ltdb_file = optarg;
			break;
		case 'L':
			log_file = optarg;
			break;
		case 'm':
			mo = 1;
			break;
		case 'v': (void) printf(RDS_VERSION);
			exit(1);
			break;
		case '?':
			usage();
			exit(1);
		default:
			usage();
			exit(1);
		}


	/* set handlers */
	(void) signal(SIGINT, sig_rds);
	(void) signal(SIGTERM, sig_rds);
	(void) sigignore(SIGPIPE);

	(void) enable_extended_FILE_stdio(-1, -1);

	/* initialize the log mutex */
	rv = pthread_mutex_init(&logLock, NULL);
	if (rv != 0) {
		(void) sprintf(errmsg, "Mutex init failed with %d", rv);
		err_exit();
	}

	if (log_file != NULL)
		log_open(log_file);

	if (do_server_mode == 1) {

		/*
		 * Initialize list data structures, possibly
		 * reading saved data.
		 *
		 * As a side effect this messes with the protocol
		 * state since the list reader pretends it's reading
		 * the protocol.
		 *
		 * A problem here is that we cannot start the server
		 * thread until this has completed because it will try to
		 * use the same state hidden inside the protocol code.
		 *
		 * The consequence is that this may occupy the main
		 * thread for an arbitrarily long time *before* the server
		 * thread is started and the app becomes able to respond
		 * to commands.
		 */
		if (monitor_start() != 0)
			err_exit();

		/* Open pipes in and out for the command protocol */
		if (open_prot(STDOUT_FILENO, "w") == -1) {
			err_exit();
		}
		if (open_prot(STDIN_FILENO, "r") == -1) {
			err_exit();
		}

		/* Waits for the child threads to end */
		runserver();

		/* Close command I/O pipes */
		close_prot();

	} else {

		if (monitor_start() != 0)
			err_exit();

		for (i = 0; i < lo_arg; i ++) {
			if (sigterm == 1)
				break;
			if (monitor_update()  != 0)
				err_exit();
			if (selected == 0 || uo == 1) {
				list_print(&users, uid);
			}
			if (selected == 0 || jo == 1) {
				list_print(&projects, jid);
			}
			if (selected == 0 || po == 1) {
				list_print(&processes, pid);
			}
			if (i < lo_arg - 1)
				napms(interval);
		}
	}

	/* clean up the log stuff at the very end */
	log_close();
	(void) pthread_mutex_destroy(&logLock);

	return (0);
}
