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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * private interfaces for auditd plugins and auditd.
 */

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <wait.h>
#include "audit_plugin.h"

static char	auditwarn[] = "/etc/security/audit_warn";
static pthread_mutex_t	syslog_lock;

static void
init_syslog_mutex()
{
	(void) pthread_mutex_init(&syslog_lock, NULL);
}

/*
 * audit_syslog() -- generate syslog messages from threads that use
 * different severity, facility code, and application names.
 *
 * syslog(3C) is thread safe, but the set openlog() / syslog() /
 * closelog() is not.
 *
 * Assumption:  the app_name and facility code are paired, i.e.,
 * if the facility code for this call is the same as for the
 * the previous, the app_name hasn't changed.
 */
void
__audit_syslog(const char *app_name, int flags, int facility, int severity,
    const char *message)
{
	static pthread_once_t	once_control = PTHREAD_ONCE_INIT;
	static int		logopen = 0;
	static int		prev_facility = -1;

	(void) pthread_once(&once_control, init_syslog_mutex);

	(void) pthread_mutex_lock(&syslog_lock);
	if (prev_facility != facility) {
		if (logopen)
			closelog();
		openlog(app_name, flags, facility);
		syslog(severity, "%s", message);
		(void) pthread_mutex_unlock(&syslog_lock);
	} else {
		syslog(severity, "%s", message);
		(void) pthread_mutex_unlock(&syslog_lock);
	}
}

/*
 * __audit_dowarn - invoke the shell script auditwarn to notify the
 *	adminstrator about a given problem.
 * parameters -
 *	option - what the problem is
 *	text - when used with options soft and hard: which file was being
 *		   used when the filesystem filled up
 *	       when used with the plugin option:  error detail
 *	count - used with various options: how many times auditwarn has
 *		been called for this problem since it was last cleared.
 */
void
__audit_dowarn(char *option, char *text, int count)
{
	pid_t		pid;
	int		st;
	char		countstr[5];
	char		warnstring[80];
	char		empty[1] = "";

	if ((pid = fork1()) == -1) {
		__audit_syslog("auditd", LOG_PID | LOG_ODELAY | LOG_CONS,
		    LOG_DAEMON, LOG_ALERT, gettext("audit_warn fork failed\n"));
		return;
	}
	if (pid != 0) {
		(void) waitpid(pid, &st, 0);
		return;
	}
	(void) snprintf(countstr, 5, "%d", count);
	if (text == NULL)
		text = empty;

	if (strcmp(option, "soft") == 0 || strcmp(option, "hard") == 0)
		(void) execl(auditwarn, auditwarn, option, text, 0);

	else if (strcmp(option, "allhard") == 0)
		(void) execl(auditwarn, auditwarn, option, countstr, 0);
	else if (strcmp(option, "plugin") == 0)
		(void) execl(auditwarn, auditwarn, option, text, countstr, 0);
	else
		(void) execl(auditwarn, auditwarn, option, 0);
	/*
	 * (execl failed)
	 */
	if (strcmp(option, "soft") == 0)
		(void) snprintf(warnstring, 80,
		    gettext("soft limit in %s.\n"), text);
	else if (strcmp(option, "hard") == 0)
		(void) snprintf(warnstring, 80,
		    gettext("hard limit in %s.\n"), text);
	else if (strcmp(option, "allhard") == 0)
		(void) sprintf(warnstring,
		    gettext("All audit filesystems are full.\n"));
	else
		(void) snprintf(warnstring, 80,
		    gettext("error %s.\n"), option);

	__audit_syslog("auditd", LOG_PID | LOG_ODELAY | LOG_CONS, LOG_AUTH,
	    LOG_ALERT, (const char *)warnstring);

	exit(1);
}

/*
 * __audit_dowarn2 - invoke the shell script auditwarn to notify the
 *	adminstrator about a given problem.
 * parameters -
 *	option - what the problem is
 *	name - entity reporting the problem (ie, plugin name)
 *	error - error string
 *	text - when used with options soft and hard: which file was being
 *		   used when the filesystem filled up
 *	       when used with the plugin option:  error detail
 *	count - used with various options: how many times auditwarn has
 *		been called for this problem since it was last cleared.
 */
void
__audit_dowarn2(char *option, char *name, char *error, char *text, int count)
{
	pid_t		pid;
	int		st;
	char		countstr[5];
	char		warnstring[80];
	char		empty[4] = "...";
	char		none[3] = "--";

	if ((pid = fork()) == -1) {
		__audit_syslog("auditd", LOG_PID | LOG_ODELAY | LOG_CONS,
		    LOG_DAEMON, LOG_ALERT, gettext("audit_warn fork failed\n"));
		return;
	}
	if (pid != 0) {
		(void) waitpid(pid, &st, 0);
		return;
	}
	(void) snprintf(countstr, 5, "%d", count);
	if ((text == NULL) || (*text == '\0'))
		text = empty;
	if ((name == NULL) || (*name == '\0'))
		name = none;

	(void) execl(auditwarn, auditwarn, option, name, error, text,
	    countstr, 0);

	/*
	 * (execl failed)
	 */
	(void) snprintf(warnstring, 80,
	    gettext("%s plugin error: %s\n"), name, text);

	__audit_syslog("auditd", LOG_PID | LOG_ODELAY | LOG_CONS, LOG_AUTH,
	    LOG_ALERT, (const char *)warnstring);

	exit(1);
}

/*
 * logpost - post the new audit log file name.
 *
 *	Entry	name = active audit.log file name
 *			NULL, if checking writability (auditd),
 *			changing audit log files, error, or exiting (binfile).
 *
 *	Exit	0 = success
 *		1 = system error -- errno
 *		    audit_warn called with the specific error
 *
 */
int
__logpost(char *name)
{
	int lerrno;

	if (unlink(BINFILE_FILE) != 0 &&
	    errno != ENOENT) {

		lerrno = errno;
		__audit_dowarn("tmpfile", strerror(errno), 0);
		errno = lerrno;
		return (1);
	}
	if (name == NULL || *name == '\0') {
		/* audit_binfile not active, no file pointer */
		return (0);
	}
	if (symlink(name, BINFILE_FILE) != 0) {

		lerrno = errno;
		__audit_dowarn("tmpfile", strerror(errno), 0);
		errno = lerrno;
		return (1);
	}

	return (0);
}

/*
 * debug use - open a file for auditd and its plugins for debug
 */
FILE *
__auditd_debug_file_open() {
	static FILE	*fp = NULL;

	if (fp != NULL)
		return (fp);
	if ((fp = fopen("/var/audit/dump", "aF")) == NULL)
		(void) fprintf(stderr, "failed to open debug file:  %s\n",
		    strerror(errno));

	return (fp);
}
