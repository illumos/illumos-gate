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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Postprocessor for NFS server logging.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <deflt.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <syslog.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <rpc/clnt_stat.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfs_log.h>
#include "fhtab.h"
#include "nfslogd.h"
#include "buffer_list.h"
#include "../lib/nfslog_config.h"
#include "../lib/nfslogtab.h"

enum pidfile_operation {
	PID_STARTUP, PID_SHUTDOWN
};

static int nfslogtab_deactivate_after_boot(void);
static int
	nfslogtab_remove(struct buffer_ent **, struct buffer_ent **, boolean_t);
static int cycle_logs(nfsl_config_t *, int);
static void enable_logcycling(void);
static int process_pidfile(enum pidfile_operation);
static void short_cleanup(void);
static void full_cleanup(void);
static void transactions_timeout(nfsl_config_t *);
static void close_all_translogs(nfsl_config_t *);
int cycle_log(char *, int);
static boolean_t is_cycle_needed(char *, void **, boolean_t, int *);

/*
 * Configuration information.
 */

int debug = 0;
boolean_t test = B_FALSE;
time_t mapping_update_interval = MAPPING_UPDATE_INTERVAL;
/* prune_timeout measures how old a database entry must be to be pruned */
time_t prune_timeout = (SECSPERHOUR * 7 * 24);
int max_logs_preserve = MAX_LOGS_PRESERVE;
uint_t idle_time = IDLE_TIME;
static mode_t Umask = NFSLOG_UMASK;
static long cycle_frequency = CYCLE_FREQUENCY;
/* prune_frequency measures how often should prune_dbs be called */
static long prune_frequency = (SECSPERHOUR * 24);
static int min_size = MIN_PROCESSING_SIZE;
static volatile bool_t need2cycle = FALSE;
static volatile bool_t need2prune = FALSE;
boolean_t keep_running = B_TRUE;
boolean_t quick_cleaning = B_FALSE;

/*ARGSUSED*/
int
main(int argc, char **argv)
{
	struct rlimit rl;
	int error = 0;
	char *defp;
	pid_t pid;

	timestruc_t logtab_update;
	time_t process_start, last_prune = time(0);
	time_t last_cycle = time(0);	/* last time logs were cycled */
	int processed, buffers_processed;
	struct buffer_ent *buffer_list = NULL, *bep, *next;
	nfsl_config_t *config_list = NULL;
	char	*fhtable_to_prune = NULL;

	/*
	 * Check to make sure user is root.
	 */
	if (geteuid() != 0) {
		(void) fprintf(stderr, gettext("%s must be run as root\n"),
			argv[0]);
		exit(1);
	}

	/*
	 * Read defaults file.
	 */
	if (defopen(NFSLOG_OPTIONS_FILE) == 0) {
		if ((defp = defread("DEBUG=")) != NULL) {
			debug = atoi(defp);
			if (debug > 0)
				(void) printf("debug=%d\n", debug);
		}
		if ((defp = defread("TEST=")) != NULL) {
			if (strcmp(defp, "TRUE") == 0)
				test = B_TRUE;
			if (debug > 0) {
				if (test)
					(void) printf("test=TRUE\n");
				else
					(void) printf("test=FALSE\n");
			}
		}
		/*
		 * Set Umask for log and fhtable creation.
		 */
		if ((defp = defread("UMASK=")) != NULL) {
			if (sscanf(defp, "%lo", &Umask) != 1)
				Umask = NFSLOG_UMASK;
		}
		/*
		 * Minimum size buffer should reach before processing.
		 */
		if ((defp = defread("MIN_PROCESSING_SIZE=")) != NULL) {
			min_size = atoi(defp);
			if (debug > 0)
				(void) printf("min_size=%d\n", min_size);
		}
		/*
		 * Number of seconds the daemon should
		 * sleep waiting for more work.
		 */
		if ((defp = defread("IDLE_TIME=")) != NULL) {
			idle_time = (uint_t)atoi(defp);
			if (debug > 0)
				(void) printf("idle_time=%d\n", idle_time);
		}
		/*
		 * Maximum number of logs to preserve.
		 */
		if ((defp = defread("MAX_LOGS_PRESERVE=")) != NULL) {
			max_logs_preserve = atoi(defp);
			if (debug > 0) {
				(void) printf("max_logs_preserve=%d\n",
					max_logs_preserve);
			}
		}
		/*
		 * Frequency of atime updates.
		 */
		if ((defp = defread("MAPPING_UPDATE_INTERVAL=")) != NULL) {
			mapping_update_interval = atoi(defp);
			if (debug > 0) {
				(void) printf("mapping_update_interval=%ld\n",
					mapping_update_interval);
			}
		}
		/*
		 * Time to remove entries
		 */
		if ((defp = defread("PRUNE_TIMEOUT=")) != NULL) {
			/*
			 * Prune timeout is in hours but we want
			 * deal with the time in seconds internally.
			 */
			prune_timeout = atoi(defp);
			prune_timeout *= SECSPERHOUR;
			if (prune_timeout < prune_frequency)
				prune_frequency = prune_timeout;
			if (debug > 0) {
				(void) printf("prune_timeout=%ld\n",
					prune_timeout);
			}
		}
		/*
		 * fhtable to prune when start (for debug/test purposes)
		 */
		if ((defp = defread("PRUNE_FHTABLE=")) != NULL) {
			/*
			 * Specify full pathname of fhtable to prune before
			 * any processing is to be done
			 */
			if (fhtable_to_prune = malloc(strlen(defp) + 1)) {
				(void) strcpy(fhtable_to_prune, defp);
				if (debug > 0) {
					(void) printf("fhtable to prune=%s\n",
							fhtable_to_prune);
				}
			} else {
				syslog(LOG_ERR, gettext(
					"malloc fhtable_to_prune error %s\n"),
					strerror(errno));
			}
		}
		/*
		 * Log cycle frequency.
		 */
		if ((defp = defread("CYCLE_FREQUENCY=")) != NULL) {
			cycle_frequency = atol(defp);
			if (debug > 0) {
				(void) printf("cycle_frequency=%ld\n",
					cycle_frequency);
			}
		}
		/*
		 * defopen of NULL closes the open defaults file.
		 */
		(void) defopen((char *)NULL);
	}

	if (Umask > ((mode_t)0777))
		Umask = NFSLOG_UMASK;
	(void) umask(Umask);

	if (getrlimit(RLIMIT_FSIZE, &rl) < 0) {
		error = errno;
		(void) fprintf(stderr, gettext(
			"getrlimit failed error is %d - %s\n"),
			error, strerror(error));
		exit(1);
	}
	if (min_size < 0 || min_size > rl.rlim_cur) {
		(void) fprintf(stderr, gettext(
			"MIN_PROCESSING_SIZE out of range, should be >= 0 and "
			"< %d. Check %s.\n"), rl.rlim_cur, NFSLOG_OPTIONS_FILE);
		exit(1);
	}
	if (idle_time > INT_MAX) {
		(void) fprintf(stderr, gettext(
			"IDLE_TIME out of range, should be >= 0 and "
			"< %d. Check %s.\n"), INT_MAX, NFSLOG_OPTIONS_FILE);
		exit(1);
	}
	if (max_logs_preserve < 0 || max_logs_preserve > INT_MAX) {
		(void) fprintf(stderr, gettext(
			"MAX_LOGS_PRESERVE out of range, should be >= 0 and "
			"< %d. Check %s.\n"), INT_MAX, NFSLOG_OPTIONS_FILE);
		exit(1);
	}
	if (mapping_update_interval < 0|| mapping_update_interval > INT_MAX) {
		(void) fprintf(stderr, gettext(
			"MAPPING_UPDATE_INTERVAL out of range, "
			"should be >= 0 and "
			"< %d. Check %s.\n"), INT_MAX, NFSLOG_OPTIONS_FILE);
		exit(1);
	}
	if (cycle_frequency < 0 || cycle_frequency > INT_MAX) {
		(void) fprintf(stderr, gettext(
			"CYCLE_FREQUENCY out of range, should be >= 0 and "
			"< %d. Check %s.\n"), INT_MAX, NFSLOG_OPTIONS_FILE);
		exit(1);
	}
	/* get value in seconds */
	cycle_frequency = cycle_frequency * 60 * 60;

	/*
	 * If we dump core, it will be /core
	 */
	if (chdir("/") < 0)
		(void) fprintf(stderr, gettext("chdir /: %s"), strerror(errno));

	/*
	 * Config errors to stderr
	 */
	nfsl_errs_to_syslog = B_FALSE;

#ifndef DEBUG
	pid = fork();
	if (pid == -1) {
		(void) fprintf(stderr, gettext("%s: fork failure\n"),
			argv[0]);
		exit(1);
	}
	if (pid != 0)
		exit(0);
	/*
	 * Config errors to syslog
	 */
	nfsl_errs_to_syslog = B_TRUE;
#endif /* DEBUG */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Check to see if nfslogd is already running.
	 */
	if (process_pidfile(PID_STARTUP) != 0) {
		exit(1);
	}

	(void) sigset(SIGUSR1, (void (*)(int))enable_logcycling);
	(void) sigset(SIGHUP, (void (*)(int))full_cleanup);
	(void) sigset(SIGTERM, (void(*)(int))short_cleanup);

#ifndef DEBUG
	/*
	 * Close existing file descriptors, open "/dev/null" as
	 * standard input, output, and error, and detach from
	 * controlling terminal.
	 */
	if (!debug && !test) {
		closefrom(0);
		(void) open("/dev/null", O_RDONLY);
		(void) open("/dev/null", O_WRONLY);
		(void) dup(1);
	}
	(void) setsid();
#endif /* DEBUG */

	openlog(argv[0], LOG_PID, LOG_DAEMON);

	public_fh.fh_len = NFS_FHMAXDATA;
	public_fh.fh_xlen = NFS_FHMAXDATA;

	/*
	 * Call once at startup to handle the nfslogtab
	 */
	if (nfslogtab_deactivate_after_boot() == -1)
		exit(1);

	/*
	 * Get a list of buffers that need to be processed.
	 */
	if (error = getbuffer_list(&buffer_list, &logtab_update)) {
		syslog(LOG_ERR, gettext("Could not read %s: %s"),
			NFSLOGTAB, strerror(error));
		goto done;
	}

	/*
	 * Get the configuration list.
	 */
	if (error = nfsl_getconfig_list(&config_list)) {
		syslog(LOG_ERR, gettext(
			"Could not obtain configuration list: %s"),
			strerror(error));
		goto done;
	}

	/*
	 * loop to process the work being generated by the NFS server
	 */
	while (keep_running) {
		buffers_processed = 0;
		(void) checkbuffer_list(&buffer_list, &logtab_update);

		while (buffer_list == NULL) {
			/*
			 * Nothing to do
			 */
			(void) sleep(idle_time);

			if (!keep_running) {
				/*
				 * We have been interrupted and asked to
				 * flush our transactions and exit.
				 */
				close_all_translogs(config_list);
				goto done;
			}
			(void) checkbuffer_list(&buffer_list, &logtab_update);
		}

		process_start = time(0);

		if (error = nfsl_checkconfig_list(&config_list, NULL)) {
			syslog(LOG_ERR, gettext(
				"Could not update configuration list: %s"),
				strerror(error));
			nfsl_freeconfig_list(&config_list);
			goto done;
		}

		if (difftime(time(0), last_cycle) > cycle_frequency)
			need2cycle = TRUE;
		if (need2cycle) {
			error = cycle_logs(config_list, max_logs_preserve);
			if (error) {
				syslog(LOG_WARNING, gettext(
				    "One or more logfiles couldn't be cycled, "
				    "continuing regular processing"));
			}
			need2cycle = FALSE;
			last_cycle = time(0);
		}
		if (difftime(time(0), last_prune) > prune_frequency)
			need2prune = TRUE;
		if (need2prune || fhtable_to_prune) {
			error = prune_dbs(fhtable_to_prune);
			if (error) {
				syslog(LOG_WARNING, gettext(
				    "Error in cleaning database files"));
			}
			need2prune = FALSE;
			last_prune = time(0);
			/* After the first time, use the normal procedure */
			free(fhtable_to_prune);
			fhtable_to_prune = NULL;
		}

		for (bep = buffer_list; bep != NULL; bep = next) {
			next = bep->be_next;
			processed = 0;
			error = process_buffer(bep, &config_list,
				min_size, idle_time, &processed);
			if (error == 0 && processed) {
				if (bep->be_error) {
					syslog(LOG_ERR, gettext(
						"Buffer file '%s' "
						"processed successfully."),
						bep->be_name);
				}
				error =
				nfslogtab_remove(&buffer_list, &bep, B_FALSE);
			} else if (error == ENOENT) {
				syslog(LOG_ERR, gettext("Removed entry"
					"\t\"%s\t%s\t%d\" from %s"),
					bep->be_name,
					bep->be_sharepnt->se_name,
					bep->be_sharepnt->se_state,
					NFSLOGTAB);
				error =
				nfslogtab_remove(&buffer_list, &bep, B_TRUE);
			} else if (error && error != bep->be_error) {
				/*
				 * An error different from what we've reported
				 * before occured.
				 */
				syslog(LOG_ERR, gettext(
					"Cannot process buffer file '%s' - "
					"will retry on every iteration."),
					bep->be_name);
			}

			if (bep != NULL)
				bep->be_error = error;
			buffers_processed += processed;
		}

		transactions_timeout(config_list);

		if (keep_running) {
			uint_t process_time;

			/*
			 * Sleep idle_time minus however long it took us
			 * to process the buffers.
			 */
			process_time =
				(uint_t)(difftime(time(0), process_start));
			if (process_time < idle_time)
				(void) sleep(idle_time - process_time);
		}
	}

done:
	/*
	 * Make sure to clean house before we exit
	 */
	close_all_translogs(config_list);
	free_buffer_list(&buffer_list);
	nfsl_freeconfig_list(&config_list);

	(void) process_pidfile(PID_SHUTDOWN);

	return (error);
}

static void
short_cleanup(void)
{
	if (debug) {
		(void) fprintf(stderr,
			"SIGTERM received, setting state to terminate...\n");
	}
	quick_cleaning = B_TRUE;
	keep_running = B_FALSE;
}

static void
full_cleanup(void)
{
	if (debug) {
		(void) fprintf(stderr,
			"SIGHUP received, setting state to shutdown...\n");
	}
	quick_cleaning = keep_running = B_FALSE;
}

/*
 * Removes nfslogtab entries matching the specified buffer_ent,
 * if 'inactive_only' is set, then only inactive entries are removed.
 * The buffer_list and sharepoint list entries are removed appropriately.
 * Returns 0 on success, error otherwise.
 */
static int
nfslogtab_remove(
	struct buffer_ent **buffer_list,
	struct buffer_ent **bep,
	boolean_t allstates)
{
	FILE *fd;
	int error = 0;
	struct sharepnt_ent *sep, *next;

	fd = fopen(NFSLOGTAB, "r+");
	rewind(fd);
	if (fd == NULL) {
		error = errno;
		syslog(LOG_ERR, gettext("%s - %s\n"), NFSLOGTAB,
			strerror(error));
		return (error);
	}

	if (lockf(fileno(fd), F_LOCK, 0L) < 0) {
		error = errno;
		syslog(LOG_ERR, gettext("cannot lock %s - %s\n"), NFSLOGTAB,
			strerror(error));
		(void) fclose(fd);
		return (error);
	}

	for (sep = (*bep)->be_sharepnt; sep != NULL; sep = next) {
		next = sep->se_next;
		if (!allstates && sep->se_state == LES_ACTIVE)
			continue;
		if (error = logtab_rement(fd, (*bep)->be_name, sep->se_name,
					NULL, sep->se_state)) {
			syslog(LOG_ERR, gettext("cannot update %s\n"),
				NFSLOGTAB);
			error = EIO;
			goto errout;
		}
		remove_sharepnt_ent(&((*bep)->be_sharepnt), sep);
	}

	if ((*bep)->be_sharepnt == NULL) {
		/*
		 * All sharepoints were removed from NFSLOGTAB.
		 * Remove this buffer from our list.
		 */
		remove_buffer_ent(buffer_list, *bep);
		*bep = NULL;
	}

errout: (void) fclose(fd);

	return (error);
}

/*
 * Deactivates entries if nfslogtab is older than the boot time.
 */
static int
nfslogtab_deactivate_after_boot(void)
{
	FILE *fd;
	int error = 0;

	fd = fopen(NFSLOGTAB, "r+");
	if (fd == NULL) {
		error = errno;
		if (error != ENOENT) {
			syslog(LOG_ERR, gettext("%s: %s\n"), NFSLOGTAB,
				strerror(error));
			return (-1);
		}
		return (0);
	}

	if (lockf(fileno(fd), F_LOCK, 0L) < 0) {
		error = errno;
		syslog(LOG_ERR, gettext("cannot lock %s: %s\n"),
			NFSLOGTAB, strerror(error));
		(void) fclose(fd);
		return (-1);
	}

	if (logtab_deactivate_after_boot(fd) == -1) {
		syslog(LOG_ERR, gettext(
			"Cannot deactivate all entries in %s\n"), NFSLOGTAB);
		(void) fclose(fd);
		return (-1);
	}

	(void) fclose(fd);
	return (0);
}

/*
 * Enables the log file cycling flag.
 */
static void
enable_logcycling(void)
{
	need2cycle = TRUE;
}

/*
 * Cycle all log files that have been active since the last cycling.
 * This means it's not simply listed in the configuration file, but
 * there's information associated with it.
 */
static int
cycle_logs(nfsl_config_t *listp, int max_logs_preserve)
{
	nfsl_config_t *clp;
	void *processed_list = NULL;
	int error = 0, total_errors = 0;

	for (clp = listp; clp != NULL; clp = clp->nc_next) {
		error = 0;

		/*
		 * Process transpath log.
		 */
		if (clp->nc_logpath) {
			if (is_cycle_needed(clp->nc_logpath, &processed_list,
			    B_FALSE, &error)) {
				if (clp->nc_transcookie != NULL) {
					nfslog_close_transactions(
						&clp->nc_transcookie);
					assert(clp->nc_transcookie == NULL);
				}
				error = cycle_log(clp->nc_logpath,
					max_logs_preserve);
			} else if (error)
				goto errout;
		}
		total_errors += error;

		/*
		 * Process elfpath log.
		 */
		if (clp->nc_rpclogpath) {
			if (is_cycle_needed(clp->nc_rpclogpath, &processed_list,
			    B_FALSE, &error)) {
				error = cycle_log(clp->nc_rpclogpath,
					max_logs_preserve);
			} else if (error)
				goto errout;
		}
		total_errors += error;
	}

errout:
	/*
	 * Free the list of processed entries.
	 */
	(void) is_cycle_needed(NULL, &processed_list, B_TRUE, &error);

	return (total_errors);
}

/*
 * Returns TRUE if this log has not yet been cycled, FALSE otherwise.
 * '*head' points to the list of entries that have been processed.
 * If this is a new entry, it gets inserted at the beginning of the
 * list, and returns TRUE.
 *
 * The list is freed if 'need2free' is set, and returns FALSE.
 * Sets 'error' on failure, and returns FALSE.
 */
static boolean_t
is_cycle_needed(char *path, void **list, boolean_t need2free, int *error)
{
	struct list {
		char *log;
		struct list *next;
	} *head, *next, *p;

	head = (struct list *)(*list);
	if (need2free) {
		/*
		 * Free the list and return
		 */
		for (p = head; p != NULL; p = next) {
			next = p->next;
			free(p);
		}
		head = NULL;
		return (B_FALSE);
	}

	assert(path != NULL);
	*error = 0;
	for (p = head; p != NULL; p = p->next) {
		/*
		 * Have we seen this before?
		 */
		if (strcmp(p->log, path) == 0)
			return (B_FALSE);
	}

	/*
	 * Add it to the list
	 */
	if ((p = (struct list *)malloc(sizeof (*p))) == NULL) {
		*error = ENOMEM;
		syslog(LOG_ERR, gettext("Cannot allocate memory."));
		return (B_FALSE);
	}
	p->log = path;
	p->next = head;
	head = p;

	return (B_TRUE);
}

/*
 * cycle given log file.
 */
int
cycle_log(char *filename, int max_logs_preserve)
{
	int i;
	char *file_1;
	char *file_2;
	int error = 0;
	struct stat st;

	if (max_logs_preserve == 0)
		return (0);

	if (stat(filename, &st) == -1) {
		if (errno == ENOENT) {
			/*
			 * Nothing to cycle.
			 */
			return (0);
		}
		return (errno);
	}
	file_1 = (char *)malloc(PATH_MAX);
	file_2 = (char *)malloc(PATH_MAX);
	for (i = max_logs_preserve - 2; i >= 0; i--) {
		(void) sprintf(file_1, "%s.%d", filename, i);
		(void) sprintf(file_2, "%s.%d", filename, (i + 1));
		if (rename(file_1, file_2) == -1) {
			error = errno;
			if (error != ENOENT) {
				syslog(LOG_ERR, gettext(
				    "cycle_log: can not rename %s to %s: %s"),
				    file_1, file_2, strerror(error));
				goto out;
			}
		}
	}
	(void) sprintf(file_1, "%s.0", filename);
	if (rename(filename, file_1) == -1) {
		error = errno;
		if (error != ENOENT) {
			syslog(LOG_ERR, gettext(
				"cycle_log: can not rename %s to %s: %s"),
				filename, file_1, strerror(error));
			goto out;
		}
	}
	error = 0;

out:	free(file_1);
	free(file_2);

	return (error);
}

/*
 * If operation = PID_STARTUP then checks the nfslogd.pid file, it is opened
 * if it exists, read and the pid is checked for an active process. If no
 * active process is found, the pid of this process is written to the file,
 * and 0 is returned, otherwise non-zero error is returned.
 *
 * If operation = PID_SHUTDOWN then removes the nfslogd.pid file and 0 is
 * returned.
 */
static int
process_pidfile(enum pidfile_operation op)
{
	int fd, read_count;
	int error = 0;
	pid_t pid, mypid;
	char *PidFile = NFSLOGD_PIDFILE;
	int open_flags;

	if (op == PID_STARTUP)
		open_flags = O_RDWR | O_CREAT;
	else {
		assert(op == PID_SHUTDOWN);
		open_flags = O_RDWR;
	}

	if ((fd = open(PidFile, open_flags, 0600)) < 0) {
		error = errno;
		if (error == ENOENT && op == PID_SHUTDOWN) {
			/*
			 * We were going to remove it anyway
			 */
			error = 0;
			goto out;
		}
		(void) fprintf(stderr, gettext(
			"cannot open or create pid file %s\n"), PidFile);
		goto out;
	}
	if (lockf(fd, F_LOCK, 0) < 0) {
		error = errno;
		(void) fprintf(stderr, gettext(
			"Cannot lock %s - %s\n"), PidFile,
			strerror(error));
		goto out;
	}
	if ((read_count = read(fd, &pid, sizeof (pid))) < 0) {
		error = errno;
		(void) fprintf(stderr, gettext(
			"Can not read from file %s - %s\n"), PidFile,
			strerror(error));
	}

	mypid = getpid();
	if (op == PID_STARTUP) {
		if (read_count > 0) {
			if (kill(pid, 0) == 0) {
				error = EEXIST;
				(void) fprintf(stderr, gettext(
					"Terminated - nfslogd(%ld) already "
					"running.\n"), pid);
				goto out;
			} else if (errno != ESRCH) {
				error = errno;
				(void) fprintf(stderr, gettext(
					"Unexpected error returned %s\n"),
					strerror(error));
				goto out;
			}
		}
		pid = mypid;
		/*
		 * rewind the file to overwrite old pid
		 */
		(void) lseek(fd, 0, SEEK_SET);
		if (write(fd, &mypid, sizeof (mypid)) < 0) {
			error = errno;
			(void) fprintf(stderr, gettext(
				"Cannot update %s: %s\n"),
				PidFile, strerror(error));
		}
	} else {
		assert(pid == mypid);
		if (unlink(PidFile)) {
			error = errno;
			syslog(LOG_ERR, gettext("Cannot remove %s: %s"),
				strerror(error));
		}
	}
out:
	if (fd >= 0)
		(void) close(fd);
	return (error);
}

/*
 * Forces a timeout on all open transactions.
 */
static void
transactions_timeout(nfsl_config_t *clp)
{
	for (; clp != NULL; clp = clp->nc_next) {
		if (clp->nc_transcookie != NULL) {
			nfslog_process_trans_timeout(
			    (struct nfslog_trans_file *)clp->nc_transcookie,
			    FALSE);
		}
	}
}

/*
 * Closes all transaction logs causing outstanding transactions
 * to be flushed to their respective log.
 */
static void
close_all_translogs(nfsl_config_t *clp)
{
	for (; clp != NULL; clp = clp->nc_next) {
		if (clp->nc_transcookie != NULL) {
			nfslog_close_transactions(&clp->nc_transcookie);
			assert(clp->nc_transcookie == NULL);
		}
	}
}
