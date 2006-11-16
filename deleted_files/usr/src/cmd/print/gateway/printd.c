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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/systeminfo.h>
#include <sys/param.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <termios.h>
#include <libintl.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>

#include <ns.h>
#include <network.h>
#include <misc.h>
#include <list.h>
#include <job.h>

static int connection_failed = 0;

/*
 *	 lpr/lp
 *	This program will submit print jobs to a spooler using the BSD
 *	printing protcol as defined in RFC1179, plus some extension for
 *	support of additional lp functionality.
 */

#define	SEND_RETRY	-1
#define	SEND_ABORT	-2

/*ARGSUSED*/
static void sigpipe_handler(int i)
{
	syslog(LOG_ERR, "Warning: Received SIGPIPE; continuing");
	(void) signal(SIGPIPE, sigpipe_handler);
}

static int
sendfile(jobfile_t *file, int nd, int type)
{
	int rc = -1;

	syslog(LOG_DEBUG, "sendfile(%s, %d, %d)",
		((file != NULL) ? file->jf_spl_path : "NULL"), nd, type);
	if (file && file->jf_spl_path) {
		rc = net_send_file(nd, file->jf_spl_path, file->jf_data,
				file->jf_size, type);
	}
	return (rc);
}


/*
 *  send_job() sends a job to a remote print server.
 */
static int
send_job(job_t *job)
{
	int	lockfd,
		lock_size,
		nd,
		tmp,
		rc = 0;
	struct passwd *p = NULL;
	char	buf[BUFSIZ];

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): called", job->job_printer,
		job->job_server, job->job_id);
	if ((lockfd = get_lock(job->job_cf->jf_src_path, 0)) < 0) {
		(void) close(lockfd);
		return (SEND_RETRY);
	}

	/* is job complete ? */

	lock_size = file_size(job->job_cf->jf_src_path);
	(void) sprintf(buf, "%ld\n", getpid());	/* add pid to lock file */
	(void) lseek(lockfd, 0, SEEK_END);
	(void) write(lockfd, buf, strlen(buf));

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): have lock", job->job_printer,
		job->job_server, job->job_id);
	connection_failed = 0;
	if ((nd = net_open(job->job_server, 5)) < 0) {
		connection_failed = 1;
		if ((nd != NETWORK_ERROR_UNKNOWN) && (nd != NETWORK_ERROR_PORT))
			job_destroy(job);
		else
			(void) ftruncate(lockfd, lock_size);
		(void) close(lockfd);
		return ((nd == NETWORK_ERROR_UNKNOWN) ||
			(nd == NETWORK_ERROR_PORT) ? SEND_RETRY : SEND_ABORT);
	}

	if (net_send_message(nd, "%c%s\n", XFER_REQUEST, job->job_printer)
	    != 0) {
		(void) net_close(nd);
		syslog(LOG_WARNING,
			"send_job failed job %d (%s@%s) check status\n",
			job->job_id, job->job_printer, job->job_server);
		(void) ftruncate(lockfd, lock_size);
		(void) close(lockfd);
		return (SEND_RETRY);
	}

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): send data", job->job_printer,
		job->job_server, job->job_id);

	if ((p = getpwnam(job->job_user)) != NULL) {
		/*
		 * attempt to become the job owner: uid, euid, gid, and
		 * supplementary groups while we try to send the job data.
		 * The real uid is changed with setreuid() separately from
		 * changing the effective uid so that we retain the saved
		 * uid to elevate privilege later.  Combining these changes
		 * would result in a change to the saved uid also and a loss
		 * of the ability to elevate privilege later.
		 */
		(void) setuid(0);
		(void) initgroups(job->job_user, p->pw_gid);
		(void) setgid(p->pw_gid);
		(void) setreuid(p->pw_uid, -1);
		(void) seteuid(p->pw_uid);
	}

	for (tmp = 0; job->job_df_list[tmp] != NULL; tmp++)
		if ((rc = sendfile(job->job_df_list[tmp], nd, XFER_DATA)) < 0)
			break; /* there was an error, quit now */
	tmp = errno;
	if (p != NULL) {
		/*
		 * lose the supplemental groups and elevate our effective
		 * uid to root so that we can destroy jobs and/or become
		 * other job owners later on.
		 */
		(void) seteuid(0);
		(void) initgroups("root", 1);
	}
	errno = tmp;

	if (rc < 0) {
		if (errno == ENOENT) {
			(void) net_close(nd);
			job_destroy(job);
			(void) close(lockfd);
			return (SEND_ABORT);
		} else if (errno == EACCES) {
			/* probably trying to circumvent file security */
			(void) net_close(nd);
			job_destroy(job);
			(void) close(lockfd);
			return (SEND_ABORT);
		} else {
			(void) net_close(nd);
			(void) ftruncate(lockfd, lock_size);
			(void) close(lockfd);
			return (SEND_RETRY);
		}
	}

	if (sendfile(job->job_cf, nd, XFER_CONTROL) < 0) {
		(void) net_send_message(nd, "%c\n", XFER_CLEANUP);
		(void) net_close(nd);
		(void) ftruncate(lockfd, lock_size);
		(void) close(lockfd);
		return (SEND_RETRY);
	}

	syslog(LOG_DEBUG, "send_job(%s, %s, %d): complete", job->job_printer,
		job->job_server, job->job_id);
	(void) net_close(nd);
	job_destroy(job);
	(void) close(lockfd);
	return (0);
}


/*
 *  xfer_daemon() attempts to start up a daemon for transfering jobs to a remote
 *	print server.  The daemon runs if it can get the master lock, and it
 *	runs until there are no jobs waiting for transfer.
 */
static void
xfer_daemon()
{
	job_t **list = NULL;
	int i,
	    rc;



	closelog();
	closefrom(0);

	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);

	(void) setuid(0);
	(void) setsid();
	openlog("printd", LOG_PID, LOG_LPR);
	if (fork() != 0)
		exit(0);

	if ((i = get_lock(MASTER_LOCK, 1)) < 0)
		exit(0);

	(void) chdir(SPOOL_DIR);
	while ((list = job_list_append(NULL, NULL, NULL, SPOOL_DIR)) != NULL) {
		job_t **tmp;

		syslog(LOG_DEBUG, "got the queue...");
		for (tmp = list; *tmp != NULL; tmp++) {
		/*
		 * Bugid: 4133175 printd dies when data is removed or
		 * permissions are changed.  Memory is freed twice.
		 * Fix: Do not process anything else in the list
		 * if the return code is SEND_ABORT as the memory
		 * has already been freed by job_destroy().
		 */
			rc = send_job(*tmp);
			if ((rc != 0) && (rc != SEND_ABORT)) {
				char *s = strdup((*tmp)->job_server);
				char *p = strdup((*tmp)->job_printer);

			if (rc != SEND_ABORT) /* already free */
				job_free(*tmp);

				for (tmp++; ((*tmp != NULL) &&
					(strcmp(s, (*tmp)->job_server) == 0));
					tmp++)
					if ((connection_failed == 0) &&
					    (strcmp(p,
						    (*tmp)->job_printer) == 0))
						job_free(*tmp);
					else
						break;
				tmp--;
				free(s);
				free(p);
			}
		}
		free(list);

		/* look for more work to do before we sleep */
		if ((list = job_list_append(NULL, NULL, NULL,
				SPOOL_DIR)) != NULL) {
			(void) list_iterate((void **)list, (VFUNC_T)job_free);
			free(list);
			(void) sleep(60);
		}
	}
	syslog(LOG_DEBUG, "daemon exiting...");
}

int
main(int ac, char *av[])
{
	ns_bsd_addr_t *binding = NULL;
	int	numFiles = 0,
		queueStdin = 0,
		exit_code = 0;
	char	*program,
		*user,
		hostname[128],
		buf[BUFSIZ];
	job_t *job;

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((program = strrchr(av[0], '/')) == NULL)
		program = av[0];
	else
		program++;

	openlog(program, LOG_PID, LOG_LPR);

	/*
	 * Bugid: 4013980 Application changed fd 1 to a pipe that has
	 * no reader; we write to stdout and catch a sigpipe and exit.
	 * Fix: catch signal, complain to syslog, and continue.
	 */
	(void) signal(SIGPIPE, sigpipe_handler);

	if (check_client_spool(NULL) < 0) {
		(void) fprintf(stderr,
			gettext("couldn't validate local spool area (%s)\n"),
			SPOOL_DIR);
		return (-1);
	}

	xfer_daemon();

	exit(0);
}
